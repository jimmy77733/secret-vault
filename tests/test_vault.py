import os
import sys

import pytest

from secret_vault.backends import BackendError, FileKeyBackend
from secret_vault.vault import Vault


def test_roundtrip_and_persistence(vault):
    vault.set("gh", "ghp_secretvalue123")
    assert vault.get("gh") == "ghp_secretvalue123"
    again = Vault(vault.dir, backend=FileKeyBackend(vault.dir / "dev-only.key"))
    assert again.names() == ["gh"]
    assert again.get("gh") == "ghp_secretvalue123"


def test_file_is_encrypted(vault):
    vault.set("x", "plaintext-should-not-appear")
    assert b"plaintext-should-not-appear" not in vault.path.read_bytes()


def test_remove(vault):
    vault.set("a", "value-a-123")
    assert vault.remove("a") is True
    assert vault.remove("a") is False
    assert vault.names() == []


def test_bad_name(vault):
    with pytest.raises(ValueError):
        vault.set("bad name", "v")


def test_tamper_detected(vault):
    vault.set("a", "value-a-123")
    blob = bytearray(vault.path.read_bytes())
    blob[-1] ^= 1
    vault.path.write_bytes(bytes(blob))
    with pytest.raises(BackendError):
        Vault(vault.dir, backend=FileKeyBackend(vault.dir / "dev-only.key")).names()


def test_wrong_key(tmp_path, vault):
    vault.set("a", "value-a-123")
    other = FileKeyBackend(tmp_path / "other.key")
    with pytest.raises(BackendError):
        other.decrypt(vault.path.read_bytes())


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")
def test_key_perms(vault):
    assert oct(os.stat(vault.dir / "dev-only.key").st_mode & 0o777) == "0o600"
    vault.set("a", "value-a-123")
    assert oct(os.stat(vault.path).st_mode & 0o777) == "0o600"


@pytest.mark.skipif(sys.platform != "win32", reason="DPAPI is Windows-only")
def test_dpapi_roundtrip(tmp_path):
    from secret_vault.backends import DpapiBackend
    b = DpapiBackend()
    blob = b.encrypt(b"hello dpapi")
    assert blob != b"hello dpapi" and b"hello dpapi" not in blob
    assert b.decrypt(blob) == b"hello dpapi"
    v = Vault(tmp_path / "sv", backend=b)
    v.set("k", "dpapi-value-1")
    assert Vault(tmp_path / "sv", backend=DpapiBackend()).get("k") == "dpapi-value-1"


@pytest.mark.skipif(sys.platform == "win32", reason="non-Windows check")
def test_dpapi_unavailable_off_windows():
    from secret_vault.backends import DpapiBackend
    with pytest.raises(BackendError):
        DpapiBackend()
