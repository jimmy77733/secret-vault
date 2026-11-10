import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from secret_vault.backends import FileKeyBackend  # noqa: E402
from secret_vault.vault import Vault  # noqa: E402


@pytest.fixture
def vault(tmp_path):
    d = tmp_path / "secret-vault"
    return Vault(d, backend=FileKeyBackend(d / "dev-only.key"))
