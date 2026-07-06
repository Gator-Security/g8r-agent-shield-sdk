"""
G8R Agent Shield — Python SDK

Thin REST wrapper around the G8R Shield policy engine.
Gate every LLM call through enterprise AI governance before it executes.

Usage:
    from g8r_shield import AgentShield, ShieldBlockedError

    shield = AgentShield(
        tenant_id="demo-tenant",
        console_url="https://your-console.railway.app",
        api_key="sk-shield-your-key",
        department="Legal",
        user_id="usr_001",
        ai_model="anthropic.claude-3-5-sonnet-20241022-v2:0",
        agent_id="my-agent",
    )

    # Gate an LLM call — only executed if policy allows
    result = shield.wrap(lambda: my_llm_call(prompt), prompt)

    # Pre-flight check without executing
    decision = shield.check("Does this prompt violate policy?")
"""

from __future__ import annotations

import structlog

# `__version__` lives in `_version.py` (not here) so `shield.py` can import
# it directly without traversing this package's partially-initialized
# namespace at module-load time. Re-exported below for the
# `g8r_shield.__version__` public API.
from ._version import __version__

# Configure structlog once at module import so consumers get structured JSON
# log output with timestamp + level out of the box. Audit logging requires
# explicit, structured context on every operational log line.
structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.add_log_level,
        structlog.processors.JSONRenderer(),
    ],
    wrapper_class=structlog.make_filtering_bound_logger(20),  # INFO
)

# Public type re-exports. Placed after structlog.configure so that any module
# importing AgentShield gets the configured logger, not the unconfigured
# default — and after the `__version__` import so shield.py's User-Agent
# header has a value to derive from.
from .shield import (  # noqa: E402 — intentionally after structlog.configure
    AgentShield,
    ComplianceMapping,
    PolicyDecision,
    ShieldBlockedError,
    ShieldConsoleError,
    ShieldLogEntry,
)


def get_logger(**bindings: object) -> structlog.stdlib.BoundLogger:
    """Return a structlog logger bound to the g8r_shield namespace.

    Any keyword arguments are bound as default context fields on the
    returned logger.
    """
    logger: structlog.stdlib.BoundLogger = structlog.get_logger("g8r_shield").bind(**bindings)
    return logger


__all__ = [
    "AgentShield",
    "ComplianceMapping",
    "PolicyDecision",
    "ShieldBlockedError",
    "ShieldConsoleError",
    "ShieldLogEntry",
    "__version__",
    "get_logger",
]
