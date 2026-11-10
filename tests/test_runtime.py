from types import SimpleNamespace

from secret_vault.runtime import SecretVaultRuntime, register

OPENAI = "sk-proj-" + "Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy4z"


def ev(text, chat="c1", user="u1"):
    return SimpleNamespace(text=text, source=SimpleNamespace(platform=SimpleNamespace(value="telegram"),
                                                             chat_id=chat, user_id=user))


def rt_for(vault):
    return SecretVaultRuntime(vault_factory=lambda: vault)


def test_inbound_rewrite_then_tool_resolve_then_redact(vault):
    rt = rt_for(vault)
    r = rt.on_pre_gateway_dispatch(ev(f"call the api with {OPENAI}"))
    assert r["action"] == "rewrite" and OPENAI not in r["text"]
    ph = r["text"].split("with ")[1]
    assert ph.startswith("{{SECRET:openai_")
    m = rt.on_pre_tool_call("terminal", {"command": f"curl -H 'Authorization: Bearer {ph}'"})
    assert m == {"action": "modify", "args": {"command": f"curl -H 'Authorization: Bearer {OPENAI}'"}}
    assert rt.on_transform_tool_result("terminal", {}, f"echo {OPENAI}") == f"echo {ph}"
    assert rt.on_transform_terminal_output("x", f"{OPENAI}\n") == f"{ph}\n"
    assert rt.on_transform_llm_output(response_text=f"key {OPENAI}") == f"key {ph}"


def test_no_change_returns_none(vault):
    rt = rt_for(vault)
    assert rt.on_pre_gateway_dispatch(ev("hello there")) is None
    assert rt.on_pre_tool_call("t", {"a": "b"}) is None
    assert rt.on_transform_tool_result("t", {}, "clean output") is None
    assert rt.on_transform_tool_result("t", {}, {"not": "a string"}) is None


def test_set_via_next_message(vault):
    rt = rt_for(vault)
    r = rt.on_pre_gateway_dispatch(ev("/secret set mykey"))
    assert r == {"action": "skip", "reason": "secret-vault awaiting next-message value"}
    r = rt.on_pre_gateway_dispatch(ev("super-secret-value-123"))
    assert r["action"] == "skip"
    assert vault.get("mykey") == "super-secret-value-123"
    # other chats are not captured
    rt.on_pre_gateway_dispatch(ev("/secret set k2", chat="c1"))
    assert rt.on_pre_gateway_dispatch(ev("normal text", chat="c2")) is None
    assert vault.get("k2") is None


def test_set_inline_value_skipped_not_forwarded(vault):
    rt = rt_for(vault)
    r = rt.on_pre_gateway_dispatch(ev("/secret set tok abc-123-xyz"))
    assert r["action"] == "skip"
    assert r["reason"] == "secret-vault stored inline"
    assert vault.get("tok") == "abc-123-xyz"


def test_list_rm_show(vault):
    rt = rt_for(vault)
    vault.set("alpha", "value-alpha-1")
    out = rt.handle_command("list")
    assert "alpha" in out and "value-alpha-1" not in out
    assert rt.handle_command("show-placeholder alpha") == "{{SECRET:alpha}}"
    assert "no secret" in rt.handle_command("show-placeholder nope")
    assert rt.handle_command("rm alpha") == "removed alpha"
    assert "usage" in rt.handle_command("")


def test_secret_commands_skip_even_when_agent_would_be_busy(vault):
    """Simulate Hermes busy path: /secret must be consumed at pre_gateway_dispatch
    so it never reaches interrupt / the model. Gateway reply is best-effort."""
    rt = rt_for(vault)
    vault.set("demo", "demo-value-xyz")
    sent = []

    class _Adapter:
        async def send(self, chat_id, text, metadata=None):
            sent.append((chat_id, text))

    class _Gateway:
        def _delivery_adapter_for(self, source):
            return _Adapter()

    gw = _Gateway()
    import asyncio

    async def _run():
        r_rm = rt.on_pre_gateway_dispatch(ev("/secret rm demo"), gateway=gw)
        assert r_rm == {"action": "skip", "reason": "secret-vault handled /secret"}
        assert vault.get("demo") is None
        r_list = rt.on_pre_gateway_dispatch(ev("/secret list"), gateway=gw)
        assert r_list["action"] == "skip"
        await asyncio.sleep(0)  # let create_task reply coroutines run
        assert any("0 secret" in t for _, t in sent)
        assert any("removed demo" in t for _, t in sent)

    asyncio.run(_run())

def test_known_value_redacted_inbound_even_without_pattern(vault):
    rt = rt_for(vault)
    vault.set("pw", "hunter2-correct-horse")
    r = rt.on_pre_gateway_dispatch(ev("my password is hunter2-correct-horse"))
    assert r["text"] == "my password is {{SECRET:pw}}"


def test_register_uses_real_hook_names():
    import pathlib
    import re
    calls = {"hooks": [], "cmds": []}
    ctx = SimpleNamespace(get_config=lambda k, d=None: d,
                          register_hook=lambda n, cb, **k: calls["hooks"].append(n),
                          register_command=lambda n, handler, **k: calls["cmds"].append(n))
    register(ctx)
    assert calls["cmds"] == ["secret"]
    manifest = pathlib.Path(__file__).resolve().parents[1] / "plugin.yaml"
    declared = re.search(r"provides_hooks: \[(.*)\]", manifest.read_text()).group(1)
    assert sorted(calls["hooks"]) == sorted(x.strip() for x in declared.split(","))
