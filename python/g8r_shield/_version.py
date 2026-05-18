"""
Single source of truth for the SDK version.

Derived at import time from the installed distribution metadata so a
bumped pyproject.toml can never drift from a stale literal in source.
The fallback handles the in-tree dev case where the distribution
metadata hasn't been installed (`pip install -e .` not yet run).

This module exists as a standalone import target so both ``__init__.py``
and ``shield.py`` can pull ``__version__`` from one place without the
circular-init problem of one of them needing to import from a
partially-initialized package namespace.
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version

try:
    __version__: str = _pkg_version("g8r-shield")
except PackageNotFoundError:  # pragma: no cover — only hit in editable trees pre-install
    __version__ = "0.0.0+unknown"

__all__ = ["__version__"]
