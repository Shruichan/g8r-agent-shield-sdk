"""
Single source of truth for the SDK version.

Derived at import time from the installed distribution metadata so a
bumped pyproject.toml can never drift from a stale literal in source.
The ``_FALLBACK_VERSION`` handles the in-tree dev case where the
distribution metadata hasn't been installed (`pip install -e .` not yet
run); it is kept in lock-step with ``pyproject.toml``'s ``version`` so a
checkout that hasn't been installed still reports the true release rather
than a placeholder. Both SDKs (Python + TypeScript) ship this exact
version so a CI version-equality check can assert canonical parity.

This module exists as a standalone import target so both ``__init__.py``
and ``shield.py`` can pull ``__version__`` from one place without the
circular-init problem of one of them needing to import from a
partially-initialized package namespace.
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version

# Keep in sync with `version` in pyproject.toml. This is the canonical
# synchronized parity release shared with the TypeScript SDK.
_FALLBACK_VERSION = "0.6.0"

try:
    __version__: str = _pkg_version("g8r-shield")
except PackageNotFoundError:  # pragma: no cover — only hit in editable trees pre-install
    __version__ = _FALLBACK_VERSION

__all__ = ["__version__"]
