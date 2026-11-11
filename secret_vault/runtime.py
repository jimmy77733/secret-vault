"""Hook callbacks and the /secret command.

Hermes hooks used here (VALID_HOOKS, v0.23+):
``pre_gateway_dispatch`` (rewrite only, before auth), ``post_gateway_admission``
(after authorization / pairing), ``pre_tool_call``, ``transform_tool_result``,
``transform_terminal_output``, ``transform_llm_output``.

``/secret`` and next-message value capture run in ``post_gateway_admission`` so
unpaired / unauthorized senders cannot list, delete, or overwrite the vault.
Inbound detection in ``pre_gateway_dispatch`` only rewrites the text to
placeholders; vault writes are deferred until the same message is admitted.
Replies use the public ``{"action": "handled", "reply": text}`` return value
(no private gateway delivery methods).
"""
from __future__ import annotations

import logging
import threading
import time
from typing import Any, Callable

from . import detect
from . import vault as vault_mod
from .vault import Vault

log = logging.getLogger("secret_vault")

PENDING_TTL_S = 120


class SecretVaultRuntime:
    def __init__(self, vault_factory: Callable[[], Vault] = Vault, get_config=None) -> None:
        self._vault_factory = vault_factory
        self._vaults: dict[str, Vault] = {}
        self._get_config = get_config or (lambda key, default=None: default)
        # /secret set <name> awaits the next message from the same source.
        self._pending: dict[tuple, tuple[str, float]] = {}
        # Findings stashed by pre_gateway_dispatch until post_gateway_admission.
        self._pending_store: dict[tuple, tuple[list[tuple[str, str]], float]] = {}
        self._lock = threading.Lock()

    # -- helpers ---------------------------------------------------------------------------------
    @staticmethod
    def _vault_cache_key() -> str:
        return str(vault_mod.hermes_home().resolve())

    @property
    def vault(self) -> Vault:
        """Resolve the vault for the current Hermes home; cache keyed by that path.

        A gateway serving several profiles must not reuse the first profile's
        vault. Tests may inject a factory that ignores the home path.
        """
        key = self._vault_cache_key()
        with self._lock:
            vault = self._vaults.get(key)
            if vault is None:
                vault = self._vault_factory()
                self._vaults[key] = vault
            return vault

    def _cfg(self, key: str, default):
        try:
            v = self._get_config(key, default)
        except Exception:
            v = default
        return default if v is None else v

    @staticmethod
    def _source_key(source: Any) -> tuple:
        if isinstance(source, dict):
            plat = source.get("platform") or ""
            return (str(plat), str(source.get("chat_id") or ""), str(source.get("user_id") or ""))
        plat = getattr(source, "platform", None)
        plat = getattr(plat, "value", plat)
        return (str(plat or ""), str(getattr(source, "chat_id", "") or ""),
                str(getattr(source, "user_id", "") or ""))

    @staticmethod
    def _message_id(event: Any = None, message_id: Any = None) -> str:
        if message_id not in (None, ""):
            return str(message_id)
        mid = getattr(event, "message_id", None) if event is not None else None
        return str(mid or "")

    def _store_key(self, source: Any, message_id: str, text: str) -> tuple:
        return (self._source_key(source), message_id, text)

    def _stash_findings(self, source: Any, message_id: str, rewritten: str,
                        findings: list[tuple[str, str]]) -> None:
        if not findings:
            return
        key = self._store_key(source, message_id, rewritten)
        with self._lock:
            self._pending_store[key] = (findings, time.time())

    def _commit_pending_store(self, source: Any, message_id: str, text: str) -> None:
        now = time.time()
        key = self._store_key(source, message_id, text)
        with self._lock:
            item = self._pending_store.pop(key, None)
            # Drop expired stashes so unadmitted messages do not linger.
            expired = [k for k, (_, ts) in self._pending_store.items() if now - ts > PENDING_TTL_S]
            for k in expired:
                self._pending_store.pop(k, None)
        if item is None:
            return
        findings, ts = item
        if now - ts > PENDING_TTL_S:
            return
        for name, value in findings:
            if self.vault.get(name) != value:
                self.vault.set(name, value)

    def _rewrite_without_store(self, text: str) -> tuple[str, list[tuple[str, str]]]:
        """Replace secrets with placeholders; return (new_text, unsaved (name, value) pairs).

        Known vault values are redacted (read-only). Newly detected values are
        not written until the sender is admitted.
        """
        if not isinstance(text, str) or not text:
            return text, []
        redacted = detect.redact(text, self.vault.items())
        findings = detect.find_secrets(
            redacted, entropy_threshold=float(self._cfg("entropy_threshold", 4.0)),
            generic=bool(self._cfg("detect_generic", True)))
        if not findings:
            return redacted, []
        pending: list[tuple[str, str]] = []
        names: list[str] = []
        for f in findings:
            name = self.vault.name_for_value(f.value) or detect.auto_name(f.kind, f.value)
            if self.vault.get(name) != f.value:
                pending.append((name, f.value))
            names.append(name)
        log.info("secret-vault: replaced %d secret(s) with placeholders (store deferred)", len(findings))
        return detect.substitute(redacted, findings, names), pending

    def scrub_text(self, text: str) -> str:
        """Detect secrets in *text*, store them, return text with placeholders.

        Used for already-authorized surfaces (tool / model output). Inbound
        gateway messages must use ``_rewrite_without_store`` instead.
        """
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

    def _handled(self, reply: str) -> dict[str, str]:
        return {"action": "handled", "reply": reply}

    # -- hooks -----------------------------------------------------------------------------------
    def on_pre_gateway_dispatch(self, event: Any = None, gateway: Any = None, **_: Any):
        """Rewrite inbound text to placeholders only. Do not handle /secret or write the vault."""
        text = getattr(event, "text", None)
        if not isinstance(text, str) or not text:
            return None
        # Leave /secret (and a pending next-message value) for post_gateway_admission.
        stripped = text.strip()
        parts = stripped.split()
        if parts and parts[0].lower() == "/secret":
            return None
        source = getattr(event, "source", None)
        key = self._source_key(source)
        with self._lock:
            awaiting = key in self._pending
        if awaiting and not stripped.startswith("/"):
            return None
        new, pending = self._rewrite_without_store(text)
        if new != text:
            self._stash_findings(source, self._message_id(event), new, pending)
            return {"action": "rewrite", "text": new}
        return None

    def on_post_gateway_admission(
        self, text: str = "", source: Any = None, session_key: str = "",
        message_id: Any = None, platform: str = "", **_: Any,
    ):
        """After auth: commit deferred stores, handle /secret and next-message capture."""
        if not isinstance(text, str) or not text:
            return None
        mid = self._message_id(message_id=message_id)
        self._commit_pending_store(source, mid, text)

        stripped = text.strip()
        key = self._source_key(source)
        with self._lock:
            pending = self._pending.pop(key, None)
        if pending and not stripped.startswith("/"):
            name, ts = pending
            if time.time() - ts <= PENDING_TTL_S:
                self.vault.set(name, stripped)
                reply = (f"stored {name}. Delete that chat message on the platform. "
                         f"Use {detect.placeholder(name)} in requests.")
                return self._handled(reply)
            # Expired pending: fall through as a normal message.

        parts = stripped.split()
        if parts and parts[0].lower() == "/secret":
            raw_args = stripped.split(None, 1)[1] if len(parts) > 1 else ""
            arg_parts = raw_args.split()
            if (len(arg_parts) >= 2 and arg_parts[0].lower() == "set"
                    and "--stored-inline" not in arg_parts[1:]
                    and detect.NAME_RE.match(arg_parts[1] or "")):
                name = arg_parts[1]
                if len(arg_parts) > 2:
                    self.vault.set(name, " ".join(arg_parts[2:]))
                    reply = (f"stored {name}. The value was typed inline; delete that chat "
                             f"message on the platform. Use {detect.placeholder(name)} in requests.")
                    return self._handled(reply)
                with self._lock:
                    self._pending[key] = (name, time.time())
                reply = self.handle_command(f"set {name}", source=source)
                return self._handled(reply)
            reply = self.handle_command(raw_args, source=source)
            return self._handled(reply)
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
    ctx.register_hook("post_gateway_admission", rt.on_post_gateway_admission)
    ctx.register_hook("pre_tool_call", rt.on_pre_tool_call)
    ctx.register_hook("transform_tool_result", rt.on_transform_tool_result)
    ctx.register_hook("transform_terminal_output", rt.on_transform_terminal_output)
    ctx.register_hook("transform_llm_output", rt.on_transform_llm_output)
    ctx.register_command("secret", handler=rt.handle_command,
                         description="Manage secret-vault placeholders (values are never echoed).",
                         args_hint="set|list|rm|show-placeholder <name>")
    return rt
