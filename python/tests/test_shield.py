"""
Tests for g8r_shield.shield.

Covers:
- Construction & defaults (env-var fallback, api-key warning, slots, repr)
- check()  — return shape, audit logging by default, log=False opt-out
- wrap()   — allowed/blocked/escalated dispatch, sessionRevoked propagation,
             block_on_escalated strict mode, audit log called pre-enforcement,
             log failures swallowed
- _evaluate retry — single retry on ConnectionError/Timeout, no retry on 4xx
- Value object immutability — frozen=True on dataclasses
- Payload shape — User-Agent header, employee_name fallback to user_id,
                  compliance mappings serialization
"""

from __future__ import annotations

import json
from dataclasses import FrozenInstanceError

import pytest
import requests
import responses
from structlog.testing import capture_logs

from g8r_shield import (
    AgentShield,
    ComplianceMapping,
    PolicyDecision,
    ShieldBlockedError,
    ShieldConsoleError,
    ShieldLogEntry,
)

from .conftest import (
    CHECK_URL,
    CONSOLE_URL,
    LOG_URL,
    allowed_response,
    blocked_response,
    escalated_response,
    kill_switch_response,
    log_response,
)

# ════════════════════════════════════════════════════════════════════════════
# Construction
# ════════════════════════════════════════════════════════════════════════════


class TestConstruction:
    def test_defaults_applied(self):
        s = AgentShield(tenant_id="t1", console_url="http://x", api_key="k")
        assert s._department == "General"
        assert s._user_id == "unknown"
        assert s._ai_model == "unknown"
        assert s._agent_id == "sdk-client"
        assert s._timeout == 10.0
        assert s._block_on_escalated is False

    def test_console_url_env_fallback(self, monkeypatch):
        monkeypatch.setenv("G8R_CONSOLE_URL", "https://env.example.com/")
        monkeypatch.setenv("G8R_API_KEY", "env-key")
        s = AgentShield(tenant_id="t1")
        # Trailing slash should be stripped.
        assert s._console_url == "https://env.example.com"
        assert s._api_key == "env-key"

    def test_explicit_args_override_env(self, monkeypatch):
        monkeypatch.setenv("G8R_CONSOLE_URL", "https://env.example.com")
        monkeypatch.setenv("G8R_API_KEY", "env-key")
        s = AgentShield(
            tenant_id="t1",
            console_url="https://explicit.example.com",
            api_key="explicit-key",
        )
        assert s._console_url == "https://explicit.example.com"
        assert s._api_key == "explicit-key"

    def test_raises_when_no_api_key(self, monkeypatch):
        monkeypatch.delenv("G8R_API_KEY", raising=False)
        with pytest.raises(ValueError, match="G8R API key is required"):
            AgentShield(tenant_id="t1", console_url="http://x")

    def test_raises_when_no_tenant_id(self):
        """Empty tenant_id must fail-fast at construction."""
        with pytest.raises(ValueError, match="tenant_id is required"):
            AgentShield(tenant_id="", console_url="http://x", api_key="k")

    def test_raises_when_no_console_url(self, monkeypatch):
        # Fail-closed: no implicit localhost default. A misconfigured agent
        # must not silently POST prompts + API keys to 127.0.0.1.
        monkeypatch.delenv("G8R_CONSOLE_URL", raising=False)
        with pytest.raises(ValueError, match="console_url is required"):
            AgentShield(tenant_id="t1", api_key="k")

    def test_timeout_accepts_float(self):
        s = AgentShield(tenant_id="t1", console_url="http://x", api_key="k", timeout=2.5)
        assert s._timeout == 2.5

    def test_slots_blocks_ad_hoc_attributes(self, shield):
        with pytest.raises(AttributeError):
            shield.new_attr = "should fail"  # type: ignore[attr-defined]

    def test_slots_declared_with_expected_fields(self):
        assert set(AgentShield.__slots__) == {
            "_console_url",
            "_api_key",
            "_tenant_id",
            "_department",
            "_user_id",
            "_employee_name",
            "_ai_model",
            "_agent_id",
            "_timeout",
            "_block_on_escalated",
        }


# ════════════════════════════════════════════════════════════════════════════
# __repr__
# ════════════════════════════════════════════════════════════════════════════


class TestRepr:
    def test_repr_includes_safe_fields(self, shield):
        out = repr(shield)
        assert "AgentShield" in out
        assert CONSOLE_URL in out
        assert "test-agent" in out
        assert "Engineering" in out

    def test_repr_omits_api_key(self, shield):
        # The fixture's api_key is sk-shield-test-key. Must NOT appear in repr.
        assert "sk-shield-test-key" not in repr(shield)
        assert "api_key" not in repr(shield)


# ════════════════════════════════════════════════════════════════════════════
# check()
# ════════════════════════════════════════════════════════════════════════════


class TestCheck:
    @responses.activate
    def test_returns_policy_decision_on_allowed(self, shield):
        responses.add(responses.POST, CHECK_URL, json=allowed_response(), status=200)
        responses.add(responses.POST, LOG_URL, json=log_response(), status=200)

        decision = shield.check("Safe prompt")

        assert isinstance(decision, PolicyDecision)
        assert decision.decision == "allowed"
        assert decision.violated_rule is None
        assert decision.session_revoked is False

    @responses.activate
    def test_parses_blocked_with_session_revoked(self, shield):
        responses.add(responses.POST, CHECK_URL, json=kill_switch_response(), status=200)
        responses.add(responses.POST, LOG_URL, json=log_response(), status=200)

        decision = shield.check("Pull partner compensation report")

        assert decision.decision == "blocked"
        assert decision.session_revoked is True
        assert decision.violated_rule == "Unauthorized Partner Data Access"

    @responses.activate
    def test_logs_by_default(self, shield):
        """check() with default log=True hits both /check and /log."""
        responses.add(responses.POST, CHECK_URL, json=allowed_response(), status=200)
        responses.add(responses.POST, LOG_URL, json=log_response(), status=200)

        shield.check("Safe prompt")

        assert len(responses.calls) == 2
        assert responses.calls[0].request.url == CHECK_URL
        assert responses.calls[1].request.url == LOG_URL

    @responses.activate
    def test_log_false_skips_audit(self, shield):
        """check(prompt, log=False) hits /check but NOT /log."""
        responses.add(responses.POST, CHECK_URL, json=allowed_response(), status=200)

        shield.check("Safe prompt", log=False)

        assert len(responses.calls) == 1
        assert responses.calls[0].request.url == CHECK_URL

    @responses.activate
    def test_compliance_mappings_parsed(self, shield):
        responses.add(responses.POST, CHECK_URL, json=blocked_response(), status=200)
        responses.add(responses.POST, LOG_URL, json=log_response(), status=200)

        decision = shield.check("test prompt")

        assert len(decision.compliance_mappings) == 1
        m = decision.compliance_mappings[0]
        assert m.regulation == "GDPR"
        assert m.control_id == "GDPR Art. 5(1)(f)"
        assert m.description.startswith("Personal data")

    @responses.activate
    def test_does_not_raise_on_blocked(self, shield):
        """check() returns the decision; does NOT raise. Caller decides."""
        responses.add(responses.POST, CHECK_URL, json=blocked_response(), status=200)
        responses.add(responses.POST, LOG_URL, json=log_response(), status=200)

        decision = shield.check("blocked prompt", log=False)

        assert decision.decision == "blocked"  # no raise


# ════════════════════════════════════════════════════════════════════════════
# wrap()
# ════════════════════════════════════════════════════════════════════════════


class TestWrap:
    @responses.activate
    def test_allowed_calls_factory_and_returns_result(self, shield):
        responses.add(responses.POST, CHECK_URL, json=allowed_response(), status=200)
        responses.add(responses.POST, LOG_URL, json=log_response(), status=200)

        result = shield.wrap(lambda: "factory-result", "safe prompt")

        assert result == "factory-result"

    @responses.activate
    def test_blocked_raises_shield_blocked_error(self, shield):
        responses.add(responses.POST, CHECK_URL, json=blocked_response(), status=200)
        responses.add(responses.POST, LOG_URL, json=log_response(), status=200)

        with pytest.raises(ShieldBlockedError) as exc_info:
            shield.wrap(lambda: "never returned", "bad prompt")

        assert exc_info.value.violated_rule == "PII Protection Guard"
        assert exc_info.value.session_revoked is False

    @responses.activate
    def test_blocked_factory_never_called(self, shield, mocker):
        responses.add(responses.POST, CHECK_URL, json=blocked_response(), status=200)
        responses.add(responses.POST, LOG_URL, json=log_response(), status=200)

        factory = mocker.Mock(return_value="never")
        with pytest.raises(ShieldBlockedError):
            shield.wrap(factory, "bad prompt")

        factory.assert_not_called()

    @responses.activate
    def test_kill_switch_propagates_session_revoked_on_error(self, shield):
        responses.add(responses.POST, CHECK_URL, json=kill_switch_response(), status=200)
        responses.add(responses.POST, LOG_URL, json=log_response(), status=200)

        with capture_logs() as logs, pytest.raises(ShieldBlockedError) as exc_info:
            shield.wrap(lambda: None, "Pull partner compensation")

        assert exc_info.value.session_revoked is True
        kill_logs = [e for e in logs if e.get("event") == "session_revoked"]
        assert len(kill_logs) == 1
        assert kill_logs[0]["agent_id"] == shield._agent_id
        assert kill_logs[0]["log_level"] == "warning"

    @responses.activate
    def test_escalated_default_warns_and_proceeds(self, shield, mocker):
        """Default config: escalated → emit structured warning + invoke factory."""
        responses.add(responses.POST, CHECK_URL, json=escalated_response(), status=200)
        responses.add(responses.POST, LOG_URL, json=log_response(), status=200)

        factory = mocker.Mock(return_value="approved-result")
        with capture_logs() as logs:
            result = shield.wrap(factory, "DROP TABLE users")

        assert result == "approved-result"
        factory.assert_called_once()
        esc_logs = [e for e in logs if e.get("event") == "action_escalated"]
        assert len(esc_logs) == 1
        assert esc_logs[0]["agent_id"] == shield._agent_id
        assert esc_logs[0]["log_level"] == "warning"
        assert "Destructive operation" in esc_logs[0]["reason"]

    @responses.activate
    def test_escalated_with_block_on_escalated_raises(self, strict_shield, mocker):
        """Strict config: escalated → raise instead of proceeding."""
        responses.add(responses.POST, CHECK_URL, json=escalated_response(), status=200)
        responses.add(responses.POST, LOG_URL, json=log_response(), status=200)

        factory = mocker.Mock()
        with pytest.raises(ShieldBlockedError) as exc_info:
            strict_shield.wrap(factory, "DROP TABLE users")

        assert exc_info.value.decision == "escalated"
        factory.assert_not_called()

    @responses.activate
    def test_log_called_before_enforcement(self, shield, mocker):
        """Audit log fires BEFORE the block — blocked decisions are still recorded."""
        responses.add(responses.POST, CHECK_URL, json=blocked_response(), status=200)
        responses.add(responses.POST, LOG_URL, json=log_response(), status=200)

        with pytest.raises(ShieldBlockedError):
            shield.wrap(lambda: None, "bad prompt")

        # Two calls: /check then /log. Order matters — log must precede the raise.
        assert len(responses.calls) == 2
        assert responses.calls[0].request.url == CHECK_URL
        assert responses.calls[1].request.url == LOG_URL

    @responses.activate
    def test_log_exception_swallowed(self, shield, mocker):
        """_log raising arbitrary Exception must not interrupt the decision path."""
        responses.add(responses.POST, CHECK_URL, json=allowed_response(), status=200)
        # Make the log endpoint return invalid JSON, triggering ValueError on parse.
        responses.add(responses.POST, LOG_URL, body="not-json-at-all", status=200)

        # Factory should still run; ValueError from _log is swallowed via the
        # broad `except Exception` (issue #1 from the SDK review).
        with capture_logs() as logs:
            result = shield.wrap(lambda: "ok", "safe prompt")

        assert result == "ok"
        fail_logs = [e for e in logs if e.get("event") == "log_failed"]
        assert len(fail_logs) == 1
        assert fail_logs[0]["agent_id"] == shield._agent_id
        assert fail_logs[0]["log_level"] == "error"
        assert "error" in fail_logs[0]

    @responses.activate
    def test_log_http_error_swallowed(self, shield):
        """_log getting a 500 must not interrupt the decision path either."""
        responses.add(responses.POST, CHECK_URL, json=allowed_response(), status=200)
        responses.add(responses.POST, LOG_URL, json={"error": "boom"}, status=500)

        with capture_logs() as logs:
            result = shield.wrap(lambda: "ok", "safe prompt")

        assert result == "ok"
        fail_logs = [e for e in logs if e.get("event") == "log_failed"]
        assert len(fail_logs) == 1
        assert fail_logs[0]["log_level"] == "error"


# ════════════════════════════════════════════════════════════════════════════
# Retry on transient network errors
# ════════════════════════════════════════════════════════════════════════════


class TestRetry:
    @responses.activate
    def test_retries_once_on_connection_error(self, shield, mocker):
        """First call raises ConnectionError; second succeeds."""
        mocker.patch("g8r_shield.shield.time.sleep")  # don't actually sleep
        responses.add(
            responses.POST,
            CHECK_URL,
            body=requests.exceptions.ConnectionError("simulated transient"),
        )
        responses.add(responses.POST, CHECK_URL, json=allowed_response(), status=200)

        decision = shield.check("test", log=False)

        assert decision.decision == "allowed"
        assert len(responses.calls) == 2  # one retry consumed

    @responses.activate
    def test_retries_once_on_timeout(self, shield, mocker):
        mocker.patch("g8r_shield.shield.time.sleep")
        responses.add(
            responses.POST,
            CHECK_URL,
            body=requests.exceptions.Timeout("simulated timeout"),
        )
        responses.add(responses.POST, CHECK_URL, json=allowed_response(), status=200)

        decision = shield.check("test", log=False)

        assert decision.decision == "allowed"
        assert len(responses.calls) == 2

    @responses.activate
    def test_raises_after_second_failure(self, shield, mocker):
        """Both attempts fail → RuntimeError, no third attempt."""
        mocker.patch("g8r_shield.shield.time.sleep")
        responses.add(
            responses.POST,
            CHECK_URL,
            body=requests.exceptions.ConnectionError("simulated"),
        )
        responses.add(
            responses.POST,
            CHECK_URL,
            body=requests.exceptions.ConnectionError("simulated again"),
        )

        with pytest.raises(RuntimeError, match="after retry"):
            shield.check("test", log=False)

        assert len(responses.calls) == 2

    @responses.activate
    def test_no_retry_on_http_4xx(self, shield, mocker):
        """4xx is a client error; retrying just doubles latency. Surface immediately."""
        sleep_spy = mocker.patch("g8r_shield.shield.time.sleep")
        responses.add(responses.POST, CHECK_URL, json={"error": "unauthorized"}, status=401)

        with pytest.raises(RuntimeError, match="HTTP 401"):
            shield.check("test", log=False)

        assert len(responses.calls) == 1
        sleep_spy.assert_not_called()

    @responses.activate
    def test_no_retry_on_http_5xx(self, shield, mocker):
        """5xx is a server error. Current policy: surface immediately (no retry)."""
        sleep_spy = mocker.patch("g8r_shield.shield.time.sleep")
        responses.add(responses.POST, CHECK_URL, json={"error": "boom"}, status=500)

        with pytest.raises(RuntimeError, match="HTTP 500"):
            shield.check("test", log=False)

        assert len(responses.calls) == 1
        sleep_spy.assert_not_called()


# ════════════════════════════════════════════════════════════════════════════
# ShieldConsoleError — typed HTTP exception (security audit M1)
# ════════════════════════════════════════════════════════════════════════════


class TestShieldConsoleError:
    """The HTTP error path raises a typed ShieldConsoleError so host
    frameworks that surface exception messages don't leak the raw
    server response body."""

    @responses.activate
    def test_raises_typed_exception_with_status_and_detail(self, shield):
        secret_payload = "Internal stack trace: AccessDenied at line 42 (token=AKIA...)"
        responses.add(responses.POST, CHECK_URL, body=secret_payload, status=403)

        with pytest.raises(ShieldConsoleError) as exc_info:
            shield.check("test", log=False)

        assert exc_info.value.status_code == 403
        assert exc_info.value.detail == secret_payload

    @responses.activate
    def test_str_does_not_leak_response_body(self, shield):
        """str(exc) must NOT contain the raw response body — that's the
        attack surface that frameworks surface to end users by default."""
        secret_payload = "leaky-token-9f8e7d6c-not-for-end-users"
        responses.add(responses.POST, CHECK_URL, body=secret_payload, status=500)

        with pytest.raises(ShieldConsoleError) as exc_info:
            shield.check("test", log=False)

        rendered = str(exc_info.value)
        assert secret_payload not in rendered
        assert "HTTP 500" in rendered

    @responses.activate
    def test_backward_compatible_with_runtimeerror_catchers(self, shield):
        """Existing `except RuntimeError:` catch-alls must continue to fire."""
        responses.add(responses.POST, CHECK_URL, body="err", status=401)

        with pytest.raises(RuntimeError):
            shield.check("test", log=False)

    def test_constructor_accepts_status_code_only(self):
        """Detail is optional; constructing with just a status code is valid."""
        exc = ShieldConsoleError(503)
        assert exc.status_code == 503
        assert exc.detail == ""
        assert "HTTP 503" in str(exc)

    def test_is_subclass_of_runtimeerror(self):
        """Inheritance contract: existing RuntimeError catches must still trip."""
        assert issubclass(ShieldConsoleError, RuntimeError)


# ════════════════════════════════════════════════════════════════════════════
# Value-object immutability (frozen dataclasses)
# ════════════════════════════════════════════════════════════════════════════


class TestValueObjectImmutability:
    def test_compliance_mapping_frozen(self):
        m = ComplianceMapping(
            regulation="GDPR", control_id="Art. 5", control_name="x", description="y"
        )
        with pytest.raises(FrozenInstanceError):
            m.regulation = "changed"  # type: ignore[misc]

    def test_policy_decision_frozen(self):
        d = PolicyDecision(
            decision="allowed",
            reason="ok",
            violated_rule=None,
            requires_approval=False,
            session_revoked=False,
        )
        with pytest.raises(FrozenInstanceError):
            d.decision = "blocked"  # type: ignore[misc]

    def test_shield_log_entry_frozen(self):
        e = ShieldLogEntry(id="x", decision="allowed", timestamp="2026-05-08T00:00:00Z")
        with pytest.raises(FrozenInstanceError):
            e.id = "changed"  # type: ignore[misc]


# ════════════════════════════════════════════════════════════════════════════
# Payload shape — headers, employee_name fallback, mappings serialization
# ════════════════════════════════════════════════════════════════════════════


class TestPayloadShape:
    @responses.activate
    def test_user_agent_header_on_check(self, shield):
        responses.add(responses.POST, CHECK_URL, json=allowed_response(), status=200)

        shield.check("test", log=False)

        assert responses.calls[0].request.headers["User-Agent"].startswith("g8r-shield-python/")

    @responses.activate
    def test_user_agent_header_on_log(self, shield):
        responses.add(responses.POST, CHECK_URL, json=allowed_response(), status=200)
        responses.add(responses.POST, LOG_URL, json=log_response(), status=200)

        shield.check("test")

        assert responses.calls[1].request.headers["User-Agent"].startswith("g8r-shield-python/")

    @responses.activate
    def test_bearer_auth_header(self, shield):
        responses.add(responses.POST, CHECK_URL, json=allowed_response(), status=200)

        shield.check("test", log=False)

        assert responses.calls[0].request.headers["Authorization"] == "Bearer sk-shield-test-key"

    @responses.activate
    def test_employee_name_falls_back_to_user_id_in_log_payload(self):
        """When employee_name is None, log payload uses user_id."""

        s = AgentShield(
            tenant_id="tenant-test",
            console_url=CONSOLE_URL,
            api_key="sk-test",
            user_id="usr_999",
            employee_name=None,  # explicit None
        )
        responses.add(responses.POST, CHECK_URL, json=allowed_response(), status=200)
        responses.add(responses.POST, LOG_URL, json=log_response(), status=200)

        s.check("test")

        body = json.loads(responses.calls[1].request.body)
        assert body["employeeName"] == "usr_999"

    @responses.activate
    def test_employee_name_used_when_set_in_log_payload(self, shield):

        responses.add(responses.POST, CHECK_URL, json=allowed_response(), status=200)
        responses.add(responses.POST, LOG_URL, json=log_response(), status=200)

        shield.check("test")

        log_body = responses.calls[1].request.body
        body = json.loads(log_body)
        assert body["employeeName"] == "Test User"

    @responses.activate
    def test_compliance_mappings_serialized_in_log_payload(self, shield):

        responses.add(responses.POST, CHECK_URL, json=blocked_response(), status=200)
        responses.add(responses.POST, LOG_URL, json=log_response(), status=200)

        shield.check("test")

        log_body = json.loads(responses.calls[1].request.body)
        assert len(log_body["complianceMappings"]) == 1
        m = log_body["complianceMappings"][0]
        assert m["regulation"] == "GDPR"
        assert m["controlId"] == "GDPR Art. 5(1)(f)"
        assert m["controlName"] == "Integrity & Confidentiality"
        assert "description" in m

    @responses.activate
    def test_check_payload_includes_employee_name_when_set(self, shield):

        responses.add(responses.POST, CHECK_URL, json=allowed_response(), status=200)

        shield.check("test", log=False)

        body = json.loads(responses.calls[0].request.body)
        assert body["employeeName"] == "Test User"

    @responses.activate
    def test_check_payload_omits_employee_name_when_none(self):

        s = AgentShield(
            tenant_id="tenant-test",
            console_url=CONSOLE_URL,
            api_key="sk-test",
            user_id="usr_x",
            employee_name=None,
        )
        responses.add(responses.POST, CHECK_URL, json=allowed_response(), status=200)

        s.check("test", log=False)

        body = json.loads(responses.calls[0].request.body)
        # The check payload OMITS employeeName when None (vs. log payload which
        # falls back to user_id). Documented behavior.
        assert "employeeName" not in body

    @responses.activate
    def test_outbound_payload_includes_tenant_and_request_id(self, shield):
        """Both /check and /log payloads must carry tenantId and a UUID requestId.

        Closes governance gap G1: every outbound request from the SDK is
        attributable to a tenant and traceable via request_id end-to-end.
        """
        import uuid as _uuid

        responses.add(responses.POST, CHECK_URL, json=allowed_response(), status=200)
        responses.add(responses.POST, LOG_URL, json=log_response(), status=200)

        shield.check("safe prompt")

        check_body = json.loads(responses.calls[0].request.body)
        log_body = json.loads(responses.calls[1].request.body)

        # tenantId is the constant from the fixture; requestId is fresh per call.
        assert check_body["tenantId"] == "tenant-test"
        assert log_body["tenantId"] == "tenant-test"

        assert "requestId" in check_body
        assert "requestId" in log_body
        # Verify UUID4 shape — _uuid.UUID() raises ValueError on a malformed string.
        _uuid.UUID(check_body["requestId"])
        _uuid.UUID(log_body["requestId"])
        # When check() is called standalone (not via wrap), /check and /log
        # generate independent request_ids — each public-method entry point
        # mints its own correlation id.
        assert check_body["requestId"] != log_body["requestId"]

    @responses.activate
    def test_c2_wrap_uses_single_request_id_for_check_and_log(self, shield):
        """C2: wrap() emits the same request_id to /check and /log.

        End-to-end correlation requires that a single shield.wrap() invocation
        produces ONE request_id, threaded through both the policy evaluation
        and the audit log. Before this fix, _evaluate and _log each minted
        their own uuid4 so the two server-side log lines could not be joined.
        """
        responses.add(responses.POST, CHECK_URL, json=allowed_response(), status=200)
        responses.add(responses.POST, LOG_URL, json=log_response(), status=200)

        shield.wrap(lambda: "ok", "prompt")

        assert len(responses.calls) == 2
        check_body = json.loads(responses.calls[0].request.body)
        log_body = json.loads(responses.calls[1].request.body)

        assert "requestId" in check_body
        assert "requestId" in log_body
        assert check_body["requestId"] == log_body["requestId"]  # SAME id


# ════════════════════════════════════════════════════════════════════════════
# Default-on-malformed-response (fail-closed)
# ════════════════════════════════════════════════════════════════════════════


class TestFailClosed:
    @responses.activate
    def test_missing_decision_field_defaults_to_blocked(self, shield):
        """If the server response is missing `decision`, we default to blocked."""
        # Response with no `decision` field at all — server bug / proxy mangling.
        responses.add(responses.POST, CHECK_URL, json={}, status=200)
        responses.add(responses.POST, LOG_URL, json=log_response(), status=200)

        decision = shield.check("test", log=False)

        assert decision.decision == "blocked"  # fail-closed
