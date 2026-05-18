"""
Pytest configuration for the g8r-shield Python SDK.

Run from python-sdk/:
    pip install -e ".[dev]"
    pytest -v

Tests use:
    - pytest       — test runner
    - pytest-mock  — `mocker` fixture for monkeypatching
    - responses    — HTTP mocking for `requests`
"""

from __future__ import annotations

import pytest

from g8r_shield import AgentShield

CONSOLE_URL = "https://test.example.com"
CHECK_URL = f"{CONSOLE_URL}/api/sdk/v1/check"
LOG_URL = f"{CONSOLE_URL}/api/sdk/v1/log"


@pytest.fixture
def shield() -> AgentShield:
    """Default-configured AgentShield instance for tests."""
    return AgentShield(
        tenant_id="tenant-test",
        console_url=CONSOLE_URL,
        api_key="sk-shield-test-key",
        department="Engineering",
        user_id="usr_TEST_001",
        employee_name="Test User",
        ai_model="test-model",
        agent_id="test-agent",
    )


@pytest.fixture
def strict_shield() -> AgentShield:
    """AgentShield with `block_on_escalated=True` for strict-mode tests."""
    return AgentShield(
        tenant_id="tenant-strict",
        console_url=CONSOLE_URL,
        api_key="sk-shield-test-key",
        department="Legal",
        user_id="usr_LEG_001",
        ai_model="test-model",
        block_on_escalated=True,
    )


# ── Response body factories ──────────────────────────────────────────────────
# Helpers for building API response payloads in the shape /api/sdk/v1/check returns.


def allowed_response() -> dict:
    return {
        "decision": "allowed",
        "reason": "No policy violations detected.",
        "violatedRule": None,
        "requiresApproval": False,
        "sessionRevoked": False,
        "complianceMappings": [
            {
                "regulation": "NIST AI RMF",
                "controlId": "GOVERN 1.1",
                "controlName": "AI Governance",
                "description": "Legal and regulatory requirements are documented.",
            }
        ],
    }


def blocked_response(rule_name: str = "PII Protection Guard") -> dict:
    return {
        "decision": "blocked",
        "reason": "PII detected in prompt.",
        "violatedRule": rule_name,
        "requiresApproval": False,
        "sessionRevoked": False,
        "complianceMappings": [
            {
                "regulation": "GDPR",
                "controlId": "GDPR Art. 5(1)(f)",
                "controlName": "Integrity & Confidentiality",
                "description": "Personal data must be processed securely.",
            }
        ],
    }


def kill_switch_response() -> dict:
    return {
        "decision": "blocked",
        "reason": "Partner compensation data is restricted.",
        "violatedRule": "Unauthorized Partner Data Access",
        "requiresApproval": False,
        "sessionRevoked": True,
        "complianceMappings": [
            {
                "regulation": "NIST AI RMF",
                "controlId": "GOVERN 1.1",
                "controlName": "AI Governance",
                "description": "Legal and regulatory requirements are documented.",
            }
        ],
    }


def escalated_response() -> dict:
    return {
        "decision": "escalated",
        "reason": "Destructive operation requires approval.",
        "violatedRule": "Destructive Action Escalation",
        "requiresApproval": True,
        "sessionRevoked": False,
        "complianceMappings": [
            {
                "regulation": "NIST AI RMF",
                "controlId": "MANAGE 4.1",
                "controlName": "Human Oversight",
                "description": "High-risk actions require human-in-the-loop review.",
            }
        ],
    }


def log_response() -> dict:
    return {
        "id": "log-entry-uuid-stub",
        "decision": "allowed",
        "timestamp": "2026-05-08T00:00:00Z",
    }
