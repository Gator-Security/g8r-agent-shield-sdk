"""Guard: the ADK plugin's own tests must actually RUN in CI.

tests/test_adk_plugin.py opens with ``pytest.importorskip("google.adk")`` — correct for a local
dev who has not installed the optional extra, and silently catastrophic in CI. Installing
``.[dev]`` instead of ``.[dev,adk]`` makes all 11 of those tests skip, and the job still reports
green: a passing check that proves nothing whatsoever about the plugin. That is exactly what
happened, and it is invisible in the run summary unless someone reads the skip count.

This file deliberately does NOT importorskip, so it fails rather than skips. It must stay that
way for the guard to mean anything.
"""

from __future__ import annotations

import importlib.util
import os

import pytest

# GitHub Actions (and most CI systems) set CI=true. Locally it is unset, so a developer without
# the optional extra still gets a clean run — the extra is genuinely optional for them.
IN_CI = os.environ.get("CI", "").lower() in {"1", "true", "yes"}


@pytest.mark.skipif(not IN_CI, reason="local dev may legitimately lack the optional adk extra")
def test_adk_extra_is_installed_in_ci() -> None:
    assert importlib.util.find_spec("google.adk") is not None, (
        "google-adk is not installed, so every test in tests/test_adk_plugin.py is SKIPPING and "
        "the ShieldPlugin has zero CI coverage. Install the extra in the workflow: "
        'pip install -e ".[dev,adk]"'
    )


@pytest.mark.skipif(not IN_CI, reason="local dev may legitimately lack the optional adk extra")
def test_the_plugin_module_imports_under_ci() -> None:
    """find_spec proves the dependency resolves; this proves OUR module actually loads against it.

    A major-version bump in google-adk that moved BasePlugin would satisfy the check above and
    still break the plugin at import time.
    """
    from g8r_shield.adk import ShieldPlugin

    assert issubclass(ShieldPlugin, __import__("google.adk.plugins.base_plugin",
                                               fromlist=["BasePlugin"]).BasePlugin), (
        "ShieldPlugin no longer subclasses the installed google-adk BasePlugin — the ADK plugin "
        "API has moved and the plugin will not register"
    )
