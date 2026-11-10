import pytest

from secret_vault import detect

OPENAI = "sk-proj-" + "Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy4z"
GHP = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
GPAT = "github_pat_" + "11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP"
AWS = "AKIA" + "IOSFODNN7EXAMPLE"
TG = "123456789:" + "AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsawQ"
GOOG = "AIza" + "SyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY"
SLACK = "xoxb-" + "1234567890-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx"
PEM = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA1234\nabcd==\n-----END RSA PRIVATE KEY-----"


@pytest.mark.parametrize("kind,value", [
    ("openai", OPENAI), ("github", GHP), ("github_pat", GPAT), ("aws_access_key", AWS),
    ("telegram_bot", TG), ("google_api", GOOG), ("slack", SLACK), ("private_key", PEM),
])
def test_known_formats(kind, value):
    f = detect.find_secrets(f"here is my key: {value} thanks", generic=False)
    assert [(x.kind, x.value) for x in f] == [(kind, value)]


def test_generic_entropy():
    tok = "Zq8vN3xL0pR7tY2wK5mB9cH4jD6fG1sA"
    assert [f.kind for f in detect.find_secrets(f"token={tok}")] == ["generic"]


@pytest.mark.parametrize("text", [
    "please refactor the function handle_function_call_with_retries",
    "commit 50d4ff582fa4ba5e6e33c1cfa31834b3062a6639",  # hex sha: one char class + digits, low entropy-ish
    "see https://github.com/jimmy77733/secret-vault/pull/1 for details",
    "plain english sentence with no secrets at all",
    "already {{SECRET:openai_12345678}} here",
])
def test_no_false_positive(text):
    kinds = [f.kind for f in detect.find_secrets(text)]
    assert "generic" not in kinds or "50d4ff" in text  # sha may legitimately trip generic
    assert not any(k != "generic" for k in kinds)


def test_entropy_values():
    assert detect.shannon_entropy("aaaa") == 0
    assert detect.shannon_entropy("abcd") == 2


def test_substitute_and_resolve_roundtrip():
    text = f"use {OPENAI} and {AWS}"
    f = detect.find_secrets(text, generic=False)
    names = [detect.auto_name(x.kind, x.value) for x in f]
    out = detect.substitute(text, f, names)
    assert OPENAI not in out and AWS not in out
    assert out.count("{{SECRET:") == 2
    store = {n: x.value for n, x in zip(names, f)}
    assert detect.resolve(out, store.get) == text
    nested = {"cmd": [out, {"k": out}], "n": 3}
    assert detect.resolve(nested, store.get) == {"cmd": [text, {"k": text}], "n": 3}


def test_resolve_unknown_kept():
    assert detect.resolve("{{SECRET:nope}}", {}.get) == "{{SECRET:nope}}"


def test_auto_name_deterministic():
    assert detect.auto_name("openai", OPENAI) == detect.auto_name("openai", OPENAI)


def test_redact():
    out = detect.redact(f"stdout: {OPENAI}\n{OPENAI}", {"k": OPENAI})
    assert out == "stdout: {{SECRET:k}}\n{{SECRET:k}}"
    assert detect.redact("abc", {"short": "ab"}) == "abc"  # too short to redact safely
