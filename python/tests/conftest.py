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
PEP_URL = "https://pep.test.example"
CHECK_URL = f"{CONSOLE_URL}/api/sdk/v1/check"
LOG_URL = f"{CONSOLE_URL}/api/sdk/v1/log"
DECIDE_URL = f"{PEP_URL}/decide"


@pytest.fixture
def shield() -> AgentShield:
    """Default-configured AgentShield instance for tests."""
    return AgentShield(
        tenant_id="tenant-test",
        pep_url=PEP_URL,
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
        pep_url=PEP_URL,
        console_url=CONSOLE_URL,
        api_key="sk-shield-test-key",
        department="Legal",
        user_id="usr_LEG_001",
        ai_model="test-model",
        block_on_escalated=True,
    )


# ── Response body factories ──────────────────────────────────────────────────
# Helpers for building API response payloads in the shape /api/sdk/v1/check returns.


def pep_decide_response(
    outcome: str = "ALLOW",
    *,
    reason_code: str = "ALLOW",
    explanation: str = "No policy violations detected.",
    matched_rule_ids: list | None = None,
) -> dict:
    """PEP POST /decide body (DecisionOnlyResponse)."""
    return {
        "decision": {
            "outcome": outcome,
            "reason_code": reason_code,
            "explanation": explanation,
            "matched_rule_ids": matched_rule_ids or [],
        },
        "audit_event_id": "aud_test",
    }


def pep_allowed_response() -> dict:
    return pep_decide_response("ALLOW")


def pep_blocked_response(rule_name: str = "PII Protection Guard") -> dict:
    return pep_decide_response(
        "DENY",
        reason_code="PII",
        explanation="PII detected in prompt.",
        matched_rule_ids=[rule_name],
    )


def pep_escalated_response() -> dict:
    return pep_decide_response(
        "REQUIRE_APPROVAL",
        reason_code="REQUIRE_APPROVAL",
        explanation="Destructive operation requires approval.",
    )


def pep_kill_switch_response() -> dict:
    return pep_decide_response(
        "DENY",
        reason_code="KILL_SWITCH",
        explanation="Kill switch engaged.",
    )


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
        "violatedRule": "Sensitive Data Egress",
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


def pending_registration_response() -> dict:
    """v2 trust-on-first-use, server in block mode: the agent's registration
    sits in the Console Approvals queue, so calls come back blocked WITH
    requiresApproval — the conjunction that IS the pending signal."""
    return {
        "decision": "blocked",
        "reason": "Agent registration pending approval in the Approvals queue.",
        "violatedRule": None,
        "requiresApproval": True,
        "sessionRevoked": False,
        "complianceMappings": [],
    }


def denied_registration_response() -> dict:
    """v2 admin-DENIED agent: blocked withOUT requiresApproval (both server
    modes) — must NOT read as pending."""
    return {
        "decision": "blocked",
        "reason": "agent registration denied",
        "violatedRule": None,
        "requiresApproval": False,
        "sessionRevoked": False,
        "complianceMappings": [],
    }


def log_response() -> dict:
    return {
        "id": "log-entry-uuid-stub",
        "decision": "allowed",
        "timestamp": "2026-05-08T00:00:00Z",
    }
