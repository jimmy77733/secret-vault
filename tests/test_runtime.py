from types import SimpleNamespace

from secret_vault.runtime import SecretVaultRuntime, register

OPENAI = "sk-proj-" + "Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy4z"


def ev(text, chat="c1", user="u1", message_id="m1"):
    return SimpleNamespace(text=text, message_id=message_id,
                           source=SimpleNamespace(platform=SimpleNamespace(value="telegram"),
                                                  chat_id=chat, user_id=user))


def src(chat="c1", user="u1"):
    return {"platform": "telegram", "chat_id": chat, "user_id": user}


def rt_for(vault):
    return SecretVaultRuntime(vault_factory=lambda: vault)


def test_inbound_rewrite_does_not_store_until_admission(vault):
    rt = rt_for(vault)
    r = rt.on_pre_gateway_dispatch(ev(f"call the api with {OPENAI}", message_id="mid-1"))
    assert r["action"] == "rewrite" and OPENAI not in r["text"]
    assert vault.names() == []
    # Not admitted: nothing is stored.
    assert vault.names() == []
    assert rt.on_post_gateway_admission(text=r["text"], source=src(), message_id="mid-1") is None
    assert vault.name_for_value(OPENAI) is not None
    assert vault.get(vault.name_for_value(OPENAI)) == OPENAI


def test_inbound_rewrite_then_tool_resolve_then_redact(vault):
    rt = rt_for(vault)
    r = rt.on_pre_gateway_dispatch(ev(f"call the api with {OPENAI}", message_id="mid-2"))
    assert r["action"] == "rewrite" and OPENAI not in r["text"]
    ph = r["text"].split("with ")[1]
    assert ph.startswith("{{SECRET:openai_")
    assert rt.on_post_gateway_admission(text=r["text"], source=src(), message_id="mid-2") is None
    m = rt.on_pre_tool_call("terminal", {"command": f"curl -H 'Authorization: Bearer {ph}'"})
    assert m == {"action": "modify", "args": {"command": f"curl -H 'Authorization: Bearer {OPENAI}'"}}
    assert rt.on_transform_tool_result("terminal", {}, f"echo {OPENAI}") == f"echo {ph}"
    assert rt.on_transform_terminal_output("x", f"{OPENAI}\n") == f"{ph}\n"
    assert rt.on_transform_llm_output(response_text=f"key {OPENAI}") == f"key {ph}"


def test_no_change_returns_none(vault):
    rt = rt_for(vault)
    assert rt.on_pre_gateway_dispatch(ev("hello there")) is None
    assert rt.on_post_gateway_admission(text="hello there", source=src()) is None
    assert rt.on_pre_tool_call("t", {"a": "b"}) is None
    assert rt.on_transform_tool_result("t", {}, "clean output") is None
    assert rt.on_transform_tool_result("t", {}, {"not": "a string"}) is None


def test_set_via_next_message(vault):
    rt = rt_for(vault)
    r = rt.on_post_gateway_admission(text="/secret set mykey", source=src())
    assert r["action"] == "handled"
    assert "mykey" in r["reply"]
    r = rt.on_post_gateway_admission(text="super-secret-value-123", source=src())
    assert r["action"] == "handled"
    assert vault.get("mykey") == "super-secret-value-123"
    # other chats are not captured
    rt.on_post_gateway_admission(text="/secret set k2", source=src(chat="c1"))
    assert rt.on_post_gateway_admission(text="normal text", source=src(chat="c2")) is None
    assert vault.get("k2") is None


def test_set_inline_value_handled_not_forwarded(vault):
    rt = rt_for(vault)
    r = rt.on_post_gateway_admission(text="/secret set tok abc-123-xyz", source=src())
    assert r["action"] == "handled"
    assert "stored tok" in r["reply"]
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


def test_secret_commands_handled_after_admission(vault):
    """ /secret is consumed at post_gateway_admission and replies via the public
    handled/reply contract — no private gateway delivery adapter. """
    rt = rt_for(vault)
    vault.set("demo", "demo-value-xyz")
    r_rm = rt.on_post_gateway_admission(text="/secret rm demo", source=src())
    assert r_rm == {"action": "handled", "reply": "removed demo"}
    assert vault.get("demo") is None
    r_list = rt.on_post_gateway_admission(text="/secret list", source=src())
    assert r_list["action"] == "handled"
    assert "0 secret" in r_list["reply"]
    # pre_gateway_dispatch must not handle /secret (auth has not run yet)
    assert rt.on_pre_gateway_dispatch(ev("/secret list")) is None


def test_known_value_redacted_inbound_even_without_pattern(vault):
    rt = rt_for(vault)
    vault.set("pw", "hunter2-correct-horse")
    r = rt.on_pre_gateway_dispatch(ev("my password is hunter2-correct-horse"))
    assert r["text"] == "my password is {{SECRET:pw}}"


def test_runtime_vault_keyed_by_home(tmp_path, monkeypatch):
    from secret_vault import vault as vault_mod
    a, b = tmp_path / "A", tmp_path / "B"
    a.mkdir()
    b.mkdir()
    current = {"h": a}

    def fake_home():
        return current["h"]

    monkeypatch.setattr(vault_mod, "hermes_home", fake_home)
    rt = SecretVaultRuntime()
    current["h"] = a
    v1 = rt.vault
    v1.set("k", "val-a-home")
    current["h"] = b
    v2 = rt.vault
    assert v1 is not v2
    assert v2.get("k") is None
    v2.set("k", "val-b-home")
    current["h"] = a
    assert rt.vault is v1 and rt.vault.get("k") == "val-a-home"
    current["h"] = b
    assert rt.vault.get("k") == "val-b-home"


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
    assert "post_gateway_admission" in calls["hooks"]
    assert "pre_gateway_dispatch" in calls["hooks"]
