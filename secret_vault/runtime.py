"""Hook callbacks and the /secret command. Every Hermes hook used here exists in
hermes_cli/plugins.py VALID_HOOKS (v0.23): pre_gateway_dispatch, pre_tool_call,
transform_tool_result, transform_terminal_output, transform_llm_output."""
from __future__ import annotations

import logging
import threading
import time
from typing import Any, Callable

from . import detect
from .vault import Vault

log = logging.getLogger("secret_vault")

PENDING_TTL_S = 120


class SecretVaultRuntime:
    def __init__(self, vault_factory: Callable[[], Vault] = Vault, get_config=None) -> None:
        self._vault_factory = vault_factory
        self._vault: Vault | None = None
        self._get_config = get_config or (lambda key, default=None: default)
        self._pending: dict[tuple, tuple[str, float]] = {}
        self._lock = threading.Lock()

    # -- helpers ---------------------------------------------------------------------------------
    @property
    def vault(self) -> Vault:
        if self._vault is None:
            self._vault = self._vault_factory()
        return self._vault

    def _cfg(self, key: str, default):
        try:
            v = self._get_config(key, default)
        except Exception:
            v = default
        return default if v is None else v

    @staticmethod
    def _source_key(source: Any) -> tuple:
        plat = getattr(source, "platform", None)
        plat = getattr(plat, "value", plat)
        return (str(plat or ""), str(getattr(source, "chat_id", "") or ""),
                str(getattr(source, "user_id", "") or ""))

    def scrub_text(self, text: str) -> str:
        """Detect secrets in *text*, store them, return text with placeholders. Known vault
        values are replaced too, even if no pattern matches them."""
        if not isinstance(text, str) or not text:
            return text
        text = detect.redact(text, self.vault.items())
        findings = detect.find_secrets(
            text, entropy_threshold=float(self._cfg("entropy_threshold", 4.0)),
            generic=bool(self._cfg("detect_generic", True)))
        if not findings:
            return text
        names = []
        for f in findings:
            name = self.vault.name_for_value(f.value) or detect.auto_name(f.kind, f.value)
            if self.vault.get(name) != f.value:
                self.vault.set(name, f.value)
            names.append(name)
        log.info("secret-vault: replaced %d secret(s) with placeholders", len(findings))
        return detect.substitute(text, findings, names)

    # -- hooks -----------------------------------------------------------------------------------
    def on_pre_gateway_dispatch(self, event: Any = None, **_: Any):
        text = getattr(event, "text", None)
        if not isinstance(text, str) or not text:
            return None
        key = self._source_key(getattr(event, "source", None))
        stripped = text.strip()
        with self._lock:
            pending = self._pending.pop(key, None)
        if pending and not stripped.startswith("/"):
            name, ts = pending
            if time.time() - ts <= PENDING_TTL_S:
                self.vault.set(name, stripped)
                # Dropped: the value never reaches the agent, the transcript or the model.
                return {"action": "skip", "reason": "secret-vault captured a value"}
        parts = stripped.split()
        if len(parts) >= 3 and parts[0].lower() == "/secret" and parts[1].lower() == "set":
            with self._lock:
                self._pending[key] = (parts[2], time.time())
            if len(parts) > 3:  # value typed inline: store it, keep it out of the command text
                self.vault.set(parts[2], " ".join(parts[3:]))
                with self._lock:
                    self._pending.pop(key, None)
                return {"action": "rewrite", "text": f"/secret set {parts[2]} --stored-inline"}
            return None
        new = self.scrub_text(text)
        if new != text:
            return {"action": "rewrite", "text": new}
        return None

    def on_pre_tool_call(self, tool_name: str = "", args: Any = None, **_: Any):
        if not isinstance(args, dict) or not detect.contains_placeholder(args):
            return None
        resolved = detect.resolve(args, self.vault.get)
        if resolved == args:
            return None
        return {"action": "modify", "args": resolved}

    def _redact_result(self, value: Any):
        if not isinstance(value, str):
            return None
        secrets = self.vault.items()
        new = detect.redact(value, secrets)
        if bool(self._cfg("redact_detected_in_output", True)):
            for f in reversed(detect.find_secrets(new, generic=False)):
                name = self.vault.name_for_value(f.value) or detect.auto_name(f.kind, f.value)
                if self.vault.get(name) != f.value:
                    self.vault.set(name, f.value)
                new = new[:f.start] + detect.placeholder(name) + new[f.end:]
        return new if new != value else None

    def on_transform_tool_result(self, tool_name: str = "", args: Any = None, result: Any = None, **_: Any):
        return self._redact_result(result)

    def on_transform_terminal_output(self, command: str = "", output: Any = None, **_: Any):
        return self._redact_result(output)

    def on_transform_llm_output(self, response_text: Any = None, **_: Any):
        if not isinstance(response_text, str):
            return None
        new = detect.redact(response_text, self.vault.items())
        return new if new != response_text else None

    # -- /secret -----------------------------------------------------------------------------------
    def handle_command(self, raw_args: str = "", source: Any = None, **_: Any) -> str:
        parts = (raw_args or "").split()
        if not parts:
            return self._usage()
        sub = parts[0].lower()
        name = parts[1] if len(parts) > 1 else ""
        if sub == "list":
            names = self.vault.names()
            backend = getattr(self.vault.backend, "name", "?")
            head = f"secret-vault ({backend}): {len(names)} secret(s)"
            return head + ("\n" + "\n".join(f"- {n}" for n in names) if names else "")
        if sub in ("rm", "remove", "delete"):
            if not name:
                return "usage: /secret rm <name>"
            return f"removed {name}" if self.vault.remove(name) else f"no secret named {name}"
        if sub in ("show-placeholder", "placeholder"):
            if not name:
                return "usage: /secret show-placeholder <name>"
            if self.vault.get(name) is None:
                return f"no secret named {name}"
            return detect.placeholder(name)
        if sub == "set":
            if not detect.NAME_RE.match(name or ""):
                return "usage: /secret set <name>  (name: A-Z a-z 0-9 _ . -)"
            if "--stored-inline" in parts[2:]:
                return (f"stored {name}. The value was typed inline; delete that chat message on the "
                        f"platform. Use {detect.placeholder(name)} in requests.")
            if source is None:
                return ("/secret set <name> captures the next message on gateway platforms only. "
                        "In the CLI this build cannot read a hidden value; see README.")
            with self._lock:
                self._pending.setdefault(self._source_key(source), (name, time.time()))
            return (f"Send the value for '{name}' as your next message (within {PENDING_TTL_S}s). "
                    "It will not be shown to the model or echoed back. Delete it from the chat afterwards.")
        return self._usage()

    @staticmethod
    def _usage() -> str:
        return ("usage: /secret set <name> | /secret list | /secret rm <name> | "
                "/secret show-placeholder <name>")


def register(ctx) -> SecretVaultRuntime:
    rt = SecretVaultRuntime(get_config=getattr(ctx, "get_config", None))
    ctx.register_hook("pre_gateway_dispatch", rt.on_pre_gateway_dispatch)
    ctx.register_hook("pre_tool_call", rt.on_pre_tool_call)
    ctx.register_hook("transform_tool_result", rt.on_transform_tool_result)
    ctx.register_hook("transform_terminal_output", rt.on_transform_terminal_output)
    ctx.register_hook("transform_llm_output", rt.on_transform_llm_output)
    ctx.register_command("secret", handler=rt.handle_command,
                         description="Manage secret-vault placeholders (values are never echoed).",
                         args_hint="set|list|rm|show-placeholder <name>")
    return rt
