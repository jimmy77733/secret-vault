"""Per-profile encrypted name->value store at ``<hermes_home>/secret-vault/vault.bin``."""
from __future__ import annotations

import json
import os
import threading
from pathlib import Path

from .backends import default_backend
from .detect import NAME_RE


def hermes_home() -> Path:
    try:
        from hermes_constants import get_hermes_home  # Hermes' own resolver (profile-aware)
        return Path(get_hermes_home())
    except Exception:
        return Path(os.environ.get("HERMES_HOME") or Path.home() / ".hermes")


class Vault:
    def __init__(self, directory: Path | None = None, backend=None) -> None:
        self.dir = Path(directory) if directory else hermes_home() / "secret-vault"
        self.path = self.dir / "vault.bin"
        self.dir.mkdir(parents=True, exist_ok=True)
        self.backend = backend or default_backend(self.dir)
        self._lock = threading.RLock()
        self._cache: dict[str, str] | None = None

    def _load(self) -> dict[str, str]:
        if self._cache is None:
            if self.path.exists():
                self._cache = json.loads(self.backend.decrypt(self.path.read_bytes()).decode("utf-8"))
            else:
                self._cache = {}
        return self._cache

    def _save(self) -> None:
        data = self.backend.encrypt(json.dumps(self._cache or {}).encode("utf-8"))
        tmp = self.path.with_suffix(".tmp")
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.replace(tmp, self.path)

    def set(self, name: str, value: str) -> None:
        if not NAME_RE.match(name or ""):
            raise ValueError("name must be 1-64 chars of A-Z a-z 0-9 _ . -")
        if not value:
            raise ValueError("empty value")
        with self._lock:
            self._load()[name] = value
            self._save()

    def get(self, name: str) -> str | None:
        with self._lock:
            return self._load().get(name)

    def remove(self, name: str) -> bool:
        with self._lock:
            d = self._load()
            if name not in d:
                return False
            del d[name]
            self._save()
            return True

    def names(self) -> list[str]:
        with self._lock:
            return sorted(self._load())

    def items(self) -> dict[str, str]:
        with self._lock:
            return dict(self._load())

    def name_for_value(self, value: str) -> str | None:
        with self._lock:
            for k, v in self._load().items():
                if v == value:
                    return k
        return None
