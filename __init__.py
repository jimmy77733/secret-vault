"""secret-vault: keep secrets out of the model's context in Hermes Agent."""
from __future__ import annotations

RUNTIME = None


def register(ctx) -> None:
    # Imported lazily: pytest imports this file bare when it collects the repo.
    from .secret_vault.runtime import register as _register

    global RUNTIME
    RUNTIME = _register(ctx)
