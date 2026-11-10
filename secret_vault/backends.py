"""Vault encryption backends.

* ``DpapiBackend`` - Windows DPAPI (CryptProtectData / CryptUnprotectData, CurrentUser scope) via
  ctypes. This is the only backend intended for real use.
* ``FileKeyBackend`` - DEV/TEST ONLY fallback for non-Windows. A random key lives next to the vault
  in a 0600 file and is XOR-streamed with HMAC-SHA256 (stdlib only). Anyone who can read the key
  file can read the vault, so it is NOT equivalent to DPAPI.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import sys
from pathlib import Path


class BackendError(RuntimeError):
    pass


class DpapiBackend:
    name = "dpapi"
    secure = True
    _ENTROPY = b"hermes-secret-vault/v1"

    def __init__(self) -> None:
        if sys.platform != "win32":
            raise BackendError("DPAPI is only available on Windows")
        import ctypes
        from ctypes import wintypes

        class DATA_BLOB(ctypes.Structure):
            _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

        self._ct = ctypes
        self._BLOB = DATA_BLOB
        self._crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
        self._kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        for fn in (self._crypt32.CryptProtectData, self._crypt32.CryptUnprotectData):
            fn.restype = wintypes.BOOL
        self._kernel32.LocalFree.argtypes = [ctypes.c_void_p]
        self._kernel32.LocalFree.restype = ctypes.c_void_p

    def _blob(self, data: bytes):
        buf = self._ct.create_string_buffer(data, len(data))
        return self._BLOB(len(data), self._ct.cast(buf, self._ct.POINTER(self._ct.c_char))), buf

    def _call(self, fn, data: bytes) -> bytes:
        ct = self._ct
        inp, _keep = self._blob(data)
        ent, _keep2 = self._blob(self._ENTROPY)
        out = self._BLOB()
        CRYPTPROTECT_UI_FORBIDDEN = 0x1
        ok = fn(ct.byref(inp), None, ct.byref(ent), None, None, CRYPTPROTECT_UI_FORBIDDEN, ct.byref(out))
        if not ok:
            raise BackendError(f"DPAPI call failed (winerror {ct.get_last_error()})")
        try:
            return ct.string_at(out.pbData, out.cbData)
        finally:
            self._kernel32.LocalFree(ct.cast(out.pbData, ct.c_void_p))

    def encrypt(self, plaintext: bytes) -> bytes:
        ct = self._ct
        inp, _k = self._blob(plaintext)
        ent, _k2 = self._blob(self._ENTROPY)
        out = self._BLOB()
        ok = self._crypt32.CryptProtectData(ct.byref(inp), ct.c_wchar_p("secret-vault"), ct.byref(ent),
                                            None, None, 0x1, ct.byref(out))
        if not ok:
            raise BackendError(f"CryptProtectData failed (winerror {ct.get_last_error()})")
        try:
            return ct.string_at(out.pbData, out.cbData)
        finally:
            self._kernel32.LocalFree(ct.cast(out.pbData, ct.c_void_p))

    def decrypt(self, blob: bytes) -> bytes:
        return self._call(self._crypt32.CryptUnprotectData, blob)


class FileKeyBackend:
    """DEV/TEST ONLY. Not secure-equivalent to DPAPI (see module docstring)."""
    name = "filekey-dev"
    secure = False
    _MAGIC = b"SVFK1"

    def __init__(self, key_path: Path) -> None:
        self.key_path = Path(key_path)
        if self.key_path.exists():
            self._key = self.key_path.read_bytes()
        else:
            self.key_path.parent.mkdir(parents=True, exist_ok=True)
            self._key = os.urandom(32)
            fd = os.open(str(self.key_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(self._key)
        if len(self._key) != 32:
            raise BackendError("dev key file is corrupt")

    def _stream(self, nonce: bytes, n: int) -> bytes:
        out, ctr = bytearray(), 0
        while len(out) < n:
            out += hmac.new(self._key, nonce + ctr.to_bytes(8, "big"), hashlib.sha256).digest()
            ctr += 1
        return bytes(out[:n])

    def encrypt(self, plaintext: bytes) -> bytes:
        nonce = os.urandom(16)
        ct = bytes(a ^ b for a, b in zip(plaintext, self._stream(nonce, len(plaintext))))
        tag = hmac.new(self._key, self._MAGIC + nonce + ct, hashlib.sha256).digest()
        return self._MAGIC + nonce + tag + ct

    def decrypt(self, blob: bytes) -> bytes:
        if not blob.startswith(self._MAGIC):
            raise BackendError("not a filekey-dev vault")
        nonce, tag, ct = blob[5:21], blob[21:53], blob[53:]
        if not hmac.compare_digest(tag, hmac.new(self._key, self._MAGIC + nonce + ct, hashlib.sha256).digest()):
            raise BackendError("vault integrity check failed")
        return bytes(a ^ b for a, b in zip(ct, self._stream(nonce, len(ct))))


def default_backend(vault_dir: Path):
    if sys.platform == "win32":
        return DpapiBackend()
    return FileKeyBackend(Path(vault_dir) / "dev-only.key")
