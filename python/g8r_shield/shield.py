"""
Core AgentShield class — wraps the G8R Console REST API.
"""

from __future__ import annotations

import os
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, TypeVar

import structlog

from ._version import __version__ as _SDK_VERSION
from .redaction import redact_sensitive_data

try:
    import requests

    _HAS_REQUESTS = True
except ImportError:
    # Import succeeds without `requests` installed; AgentShield.__init__ raises
    # ImportError if instantiated. This lets dependent code import the types
    # (ComplianceMapping, PolicyDecision) without requiring `requests`.
    _HAS_REQUESTS = False

T = TypeVar("T")

# Module-level structured logger. Named `_LOGGER` to avoid colliding with the
# `_log` instance method on AgentShield.
_LOGGER: structlog.stdlib.BoundLogger = structlog.get_logger("g8r_shield")

# Identifies this SDK to the server in the User-Agent header. Lets the
# Console distinguish Python vs. TypeScript callers without polluting
# customer-controlled fields like agent_id. Derived from the installed
# distribution metadata (via `_version.py`) so it can't drift from
# pyproject.toml.
_SDK_USER_AGENT = f"g8r-shield-python/{_SDK_VERSION}"

# Single-retry backoff for transient network errors in _evaluate. Kept short
# so it doesn't add user-visible latency on the happy path or on hard failures.
_RETRY_BACKOFF_SECONDS = 0.5


@dataclass(frozen=True)
class ComplianceMapping:
    regulation: str
    control_id: str
    control_name: str
    description: str = ""


@dataclass(frozen=True)
class PolicyDecision:
    decision: str  # 'allowed' | 'blocked' | 'escalated'
    reason: str
    violated_rule: str | None
    requires_approval: bool
    session_revoked: bool
    compliance_mappings: list[ComplianceMapping] = field(default_factory=list)
    # Sensitive tokens stripped from the prompt by the local-first redaction
    # layer before it reached the gateway. Empty when the prompt was clean.
    # Parity with the TypeScript SDK's `PolicyCheckResult.redactedTokens`.
    redacted_tokens: list[str] = field(default_factory=list)

    @property
    def is_pending_registration(self) -> bool:
        """Whether this decision means "agent awaiting admin approval".

        v2 Consoles register agents trust-on-first-use: the FIRST call from
        an unknown ``agent_id`` auto-creates a pending registration in the
        Console's Approvals queue. What the SDK observes next depends on the
        server's pending-agent mode:

        * **flag** (the server default) — calls from the pending agent
          evaluate normally under policy while admins approve in the
          background. The caller sees ordinary decisions; this property
          stays False.
        * **block** — calls from the pending agent return ``blocked`` with
          ``requires_approval`` set until an admin approves it. On this
          path ``wrap()`` raises :class:`ShieldBlockedError`, which carries
          the same ``decision`` / ``requires_approval`` pair (and mirrors
          this property), so integrators can distinguish "awaiting admin
          approval in the Approvals queue" from "policy blocked".

        On v2, ``decision == "blocked"`` together with ``requires_approval``
        occurs ONLY for a pending registration in block mode — that
        conjunction IS the pending signal. An admin-DENIED agent comes back
        as ``blocked`` withOUT ``requires_approval``, so it correctly reads
        False here. Branch on this property, never on the human-readable
        ``reason`` string.
        """
        return self.decision == "blocked" and self.requires_approval


@dataclass(frozen=True)
class ShieldLogEntry:
    id: str
    decision: str
    timestamp: str


class ShieldBlockedError(Exception):
    """Raised when the G8R policy engine blocks or escalates a request."""

    def __init__(self, decision: PolicyDecision) -> None:
        super().__init__(decision.reason)
        self.decision = decision.decision
        self.reason = decision.reason
        self.violated_rule = decision.violated_rule
        # Carried so handlers can evaluate the v2 pending-registration signal
        # (blocked + requires_approval) without re-fetching the decision —
        # see `is_pending_registration` below.
        self.requires_approval = decision.requires_approval
        self.session_revoked = decision.session_revoked
        self.compliance_mappings = decision.compliance_mappings

    @property
    def is_pending_registration(self) -> bool:
        """Mirror of :attr:`PolicyDecision.is_pending_registration`.

        True when this block means "agent awaiting admin approval in the
        Console's Approvals queue" (v2 trust-on-first-use registration,
        server in block mode) rather than a policy rejection. See the
        :class:`PolicyDecision` property for the full contract.
        """
        return self.decision == "blocked" and self.requires_approval


class ShieldConsoleError(RuntimeError):
    """Raised when the G8R Console returns a non-2xx HTTP response.

    The default string representation is intentionally generic — only the
    status code and a fixed message are exposed via ``str(exc)``. The raw
    response body is preserved on ``.detail`` for callers that explicitly
    opt into inspecting it (e.g. debug logging, error reporting tooling).

    This guards against unintentional disclosure when host frameworks
    surface exception messages to end users (Flask/FastAPI default error
    pages, Django DEBUG mode, generic 500 responses, etc.). A regression
    that lands an internal stack trace, a Cognito error payload, or a
    PII-shaped detail on the server side will not leak through the
    exception message.

    Inherits from :class:`RuntimeError` so existing ``except RuntimeError``
    catch-alls continue to handle the case without change.
    """

    def __init__(self, status_code: int | str, detail: str = "") -> None:
        super().__init__(f"[G8R Shield] Console returned HTTP {status_code}")
        self.status_code = status_code
        self.detail = detail


class ShieldConnectionError(RuntimeError):
    """Raised when the G8R Console is unreachable after the single retry.

    Distinguishes "couldn't reach the server" (connection refused, DNS
    failure, or timeout, even after one retry) from "the server said no"
    (:class:`ShieldConsoleError`). Callers that want to fail open on a
    transient network partition but fail closed on an explicit policy
    rejection can branch on the exception type.

    The message names the ``console_url`` and that a retry was attempted,
    but — unlike :class:`ShieldConsoleError` — there is no response body to
    carry, because the request never completed.

    Inherits from :class:`RuntimeError` so existing ``except RuntimeError``
    catch-alls continue to handle the case without change.
    """


class AgentShield:
    """
    Gate AI agent actions through the G8R policy engine.

    Every call to ``wrap()`` will:

    1. POST the prompt to ``/api/sdk/v1/check`` for policy evaluation.
    2. Record the interaction in the audit trail via ``/api/sdk/v1/log``.
    3. Raise ``ShieldBlockedError`` if blocked (or if escalated and
       ``block_on_escalated=True``).
    4. Execute the factory callable and return its result if allowed
       (or if escalated and ``block_on_escalated=False``, the default).

    Instances are configured once at construction and are intended to be
    shared across threads / agent loops. All fields are write-once (enforced
    by ``__slots__``); the instance contains no mutable state.

    Args:
        tenant_id: The one hard-required field — identifies the tenant in the
            multi-tenant plane. Must be a non-empty string. No env fallback:
            tenant is call-site identity, not deployment config.
        console_url: Base URL of your deployed G8R Console. Required in effect,
            but resolved from this argument OR the ``G8R_CONSOLE_URL`` env var;
            construction fails if neither is set. Never defaults to localhost.
        api_key: Bearer token for the SDK check/log endpoints — the STATIC
            credential path (deployment shared secret). Required in effect
            unless ``credential_provider`` is supplied; resolved from this
            argument OR the ``G8R_API_KEY`` env var; construction fails if
            neither yields a non-empty value. Mutually exclusive with
            ``credential_provider``.
        credential_provider: Zero-argument callable returning the Bearer
            credential — the DYNAMIC path for short-lived tokens (e.g. an
            OIDC JWT minted via AWS workload identity). Invoked fresh for
            EVERY request (both ``/check`` and ``/log``) so a token that
            expires mid-session never goes stale inside a long-lived
            AgentShield instance. Mutually exclusive with an explicit
            ``api_key`` (``ValueError`` if both are passed); when supplied,
            the ``G8R_API_KEY`` env var is ignored. Provider failures raise
            ``ShieldConnectionError`` on the check path — fail closed, the
            wrapped LLM call never executes. The returned value is never
            logged.
        department: Functional department (e.g. 'Legal', 'Finance').
        user_id: Identifier of the end-user initiating the action.
        employee_name: Human-readable name for audit trail.
        ai_model: Model identifier (e.g. 'anthropic.claude-3-5-sonnet-20241022-v2:0').
        agent_id: Logical agent identifier registered in the G8R console.
        timeout: HTTP request timeout in seconds (default: 10.0).
        block_on_escalated: When True, ``wrap()`` raises ``ShieldBlockedError`` on
            escalated decisions instead of proceeding with a warning. Default
            False — matches the TypeScript SDK contract where escalated actions
            proceed pending out-of-band human review. Set True for stricter
            deployments (e.g. regulated-industry tenants) that prefer fail-closed.
    """

    __slots__ = (
        "_console_url",
        "_api_key",
        "_credential_provider",
        "_tenant_id",
        "_department",
        "_user_id",
        "_employee_name",
        "_ai_model",
        "_agent_id",
        "_timeout",
        "_block_on_escalated",
    )

    def __init__(
        self,
        *,
        tenant_id: str,
        console_url: str | None = None,
        api_key: str | None = None,
        department: str = "General",
        user_id: str = "unknown",
        employee_name: str | None = None,
        ai_model: str = "unknown",
        agent_id: str = "sdk-client",
        timeout: float = 10.0,
        block_on_escalated: bool = False,
        credential_provider: Callable[[], str] | None = None,
    ) -> None:
        if not _HAS_REQUESTS:
            raise ImportError(
                "g8r-shield requires 'requests'. Install it with: pip install requests"
            )

        if not tenant_id:
            raise ValueError("tenant_id is required")

        resolved_url = console_url or os.environ.get("G8R_CONSOLE_URL")
        if not resolved_url:
            raise ValueError(
                "console_url is required. Pass console_url=... or set the G8R_CONSOLE_URL env var. "
                "An SDK that ships customer prompts and API keys must never default to localhost — "
                "a misconfigured agent would silently exfiltrate to whatever happens to be bound on "
                "127.0.0.1 in the runtime environment."
            )
        self._console_url = resolved_url.rstrip("/")

        if credential_provider is not None and api_key is not None:
            # Two explicit credential sources is a config bug, not a
            # preference to guess at. Fail fast rather than silently
            # picking one and leaving the other dead.
            raise ValueError(
                "api_key and credential_provider are mutually exclusive. "
                "Pass the static shared secret OR a provider callable, not both."
            )
        self._credential_provider = credential_provider
        if credential_provider is not None:
            # Dynamic path: the provider is the sole credential source. The
            # G8R_API_KEY env var is deliberately NOT consulted — a stale
            # secret left in the deployment environment must never shadow
            # the short-lived tokens the caller opted into.
            self._api_key = ""
        else:
            self._api_key = api_key or os.environ.get("G8R_API_KEY") or ""
            if not self._api_key:
                raise ValueError(
                    "G8R API key is required. Pass api_key=... or set the G8R_API_KEY env var."
                )

        self._tenant_id = tenant_id
        self._department = department
        self._user_id = user_id
        self._employee_name = employee_name
        self._ai_model = ai_model
        self._agent_id = agent_id
        self._timeout = timeout
        self._block_on_escalated = block_on_escalated

    def __repr__(self) -> str:
        # Deliberately omits api_key — never expose it in logs or repr output.
        # tenant_id is not secret; include it for operational clarity.
        return (
            f"AgentShield(console_url={self._console_url!r}, "
            f"tenant_id={self._tenant_id!r}, "
            f"agent_id={self._agent_id!r}, department={self._department!r})"
        )

    # ── Public API ────────────────────────────────────────────────────────────

    def check(
        self,
        prompt: str,
        *,
        request_id: str | None = None,
        log: bool = True,
    ) -> PolicyDecision:
        """
        Evaluate a prompt against the policy engine without executing anything.

        Returns a :class:`PolicyDecision`. Does NOT raise on blocked/escalated —
        use the returned decision to decide what to do next.

        Args:
            prompt: The raw prompt or action string to evaluate.
            request_id: Explicit correlation id to stamp on this evaluation.
                When ``None`` (the default), a fresh uuid4 is minted per call.
                When provided, it is used verbatim on ``/check`` and — if
                ``log`` is True — the SAME id is threaded to ``/log`` so the
                policy decision and the audit line join end-to-end. ``wrap()``
                passes its own id here to correlate the whole invocation.
            log: Whether to record this evaluation in the audit trail. Default
                True so that direct ``check()`` calls don't create blind spots
                in the Console audit record. Pass ``log=False`` if you intend
                to follow up with ``wrap()`` for the same prompt — ``wrap()``
                logs internally and duplicate entries would result.

        Note: when called standalone with ``request_id=None``, each internal
        call (``_evaluate`` and ``_log``) mints its own id. Pass an explicit
        ``request_id`` (or use ``wrap()``) for single-id end-to-end
        correlation across check and log.
        """
        # Mint one id up front (when the caller didn't supply one) so the same
        # value stamps both /check and /log — otherwise _evaluate and _log each
        # mint their own and the two server-side lines can't be joined.
        if request_id is None:
            request_id = str(uuid.uuid4())
        decision = self._evaluate(prompt, request_id=request_id)
        if log:
            self._log(prompt, decision, request_id=request_id)
        return decision

    def wrap(self, factory: Callable[[], T], prompt: str) -> T:
        """
        Evaluate ``prompt`` through the policy engine, then call ``factory`` if allowed.

        Args:
            factory: Zero-argument callable that performs the LLM/agent action.
            prompt: The raw prompt or action string to evaluate.

        Returns:
            Whatever ``factory()`` returns.

        Raises:
            ShieldBlockedError: If the policy engine blocks the request. Escalated
                requests proceed (with a warning) by default, mirroring the
                TypeScript SDK contract. Set ``block_on_escalated=True`` at
                construction time to raise on escalated instead.
        """
        # Generate a single request_id for this wrap() invocation and thread
        # it through both the policy check and the audit log so the two
        # server-side log lines can be joined end-to-end under a single
        # correlation id. Without this, each internal call mints its own uuid4
        # and the policy→action linkage is lost.
        request_id = str(uuid.uuid4())

        # Reuse the PUBLIC check() path with logging suppressed. Suppressing the
        # log here (rather than letting check() log) avoids a duplicate audit
        # entry — wrap() writes exactly one /log line, explicitly, below. This
        # keeps a single call graph (check → log) for both check() and wrap().
        decision = self.check(prompt, request_id=request_id, log=False)

        # Audit-log the attempt regardless of decision so it appears in the
        # Console audit trail. Done before enforcement so blocked decisions
        # are recorded even if downstream code never sees them.
        self._log(prompt, decision, request_id=request_id)

        if decision.decision == "allowed":
            return factory()

        if decision.decision == "blocked":
            if decision.session_revoked:
                _LOGGER.warning(
                    "session_revoked",
                    tenant_id=self._tenant_id,
                    agent_id=self._agent_id,
                    reason=decision.reason,
                )
            raise ShieldBlockedError(decision)

        if decision.decision == "escalated":
            if self._block_on_escalated:
                # Strict mode — treat escalated like blocked. Caller opted in
                # at construction time.
                raise ShieldBlockedError(decision)
            _LOGGER.warning(
                "action_escalated",
                tenant_id=self._tenant_id,
                agent_id=self._agent_id,
                reason=decision.reason,
            )
            return factory()

        # Exhaustive switch: any decision value we don't recognise fails CLOSED
        # rather than silently proceeding to factory(). Mirrors the TypeScript
        # SDK's ts-pattern `.exhaustive()`. A future 4th decision value surfaces
        # here loudly instead of being treated as "allowed" by omission.
        raise ShieldBlockedError(
            PolicyDecision(
                decision=decision.decision,
                reason=(
                    f"[G8R Shield] Unrecognised policy decision "
                    f"{decision.decision!r}; failing closed."
                ),
                violated_rule=decision.violated_rule,
                requires_approval=decision.requires_approval,
                session_revoked=decision.session_revoked,
                compliance_mappings=decision.compliance_mappings,
                redacted_tokens=decision.redacted_tokens,
            )
        )

    # ── Internal ──────────────────────────────────────────────────────────────

    def _bearer_credential(self) -> str:
        """Resolve the Bearer value for ONE outbound request.

        Static path: the api_key resolved at construction. Dynamic path: the
        credential_provider is invoked fresh on every call — never cached —
        so short-lived tokens (OIDC JWTs from AWS workload identity) stay
        valid across a long-lived AgentShield instance.

        A provider failure is wrapped in :class:`ShieldConnectionError`
        rather than surfaced raw: like a connection failure, the request
        never completed and there is no server response to carry — and on
        the check path the caller fails CLOSED (the wrapped LLM call never
        runs) instead of proceeding unevaluated. The provider's exception is
        chained as ``__cause__``; its message is deliberately kept out of
        ours, and the returned credential is never logged.
        """
        if self._credential_provider is None:
            return self._api_key
        try:
            return self._credential_provider()
        except Exception as exc:
            raise ShieldConnectionError(
                "[G8R Shield] credential_provider raised while resolving the "
                "Bearer credential; failing closed. See __cause__ for the "
                "underlying error."
            ) from exc

    def _evaluate(self, prompt: str, request_id: str | None = None) -> PolicyDecision:
        # `request_id` is generated per-call by default. `wrap()` passes its
        # own value so /check and /log share a single correlation id.
        if request_id is None:
            request_id = str(uuid.uuid4())
        # Local-first redaction (local-first VPC layer): strip signing keys,
        # custodial ids, and high-entropy material BEFORE the prompt leaves
        # the process — the gateway only ever sees the redacted form. Parity
        # with the TypeScript SDK's check() path.
        redaction = redact_sensitive_data(prompt)
        url = f"{self._console_url}/api/sdk/v1/check"
        # Annotated as `dict[str, str | bytes]` — `requests.post`'s
        # `headers` parameter is typed as `MutableMapping[str, str | bytes]`
        # under mypy 2.1+ with the latest `types-requests` stubs.
        # `dict[str, str]` is NOT assignable to that (MutableMapping is
        # invariant in value type), so we declare the literal at the
        # widened type. Pre-existing fix surfaced when CI bumped mypy
        # from 1.19 → 2.1.0 and requests stubs from 2.32 → 2.34.
        #
        # The credential is resolved once per REQUEST (before the retry
        # loop): the retry re-sends the same request, and a provider
        # failure is a local credential problem — retrying the provider
        # here would just mask misconfiguration. _bearer_credential
        # raises ShieldConnectionError itself on provider failure, so
        # the check path fails closed before anything goes on the wire.
        headers: dict[str, str | bytes] = {
            "Authorization": f"Bearer {self._bearer_credential()}",
            "Content-Type": "application/json",
            "User-Agent": _SDK_USER_AGENT,
        }
        # NOTE: employeeName is deliberately NOT sent on /check. It is an
        # audit-trail label that belongs only on /log (where it falls back to
        # user_id). Keeping it off /check matches the TypeScript SDK, which
        # never sent it, so both SDKs put the same field set on the wire.
        payload: dict[str, Any] = {
            "input": redaction.redacted,
            "tenantId": self._tenant_id,
            "requestId": request_id,
            "department": self._department,
            "userId": self._user_id,
            "aiModel": self._ai_model,
            "agentId": self._agent_id,
        }

        # Single retry on transient network failures. Hard failures (4xx HTTP
        # responses, including 401/403) are surfaced immediately — retrying
        # those is just doubling the user-visible latency.
        response = None
        last_exc: Exception | None = None
        for attempt in range(2):
            try:
                response = requests.post(url, json=payload, headers=headers, timeout=self._timeout)
                response.raise_for_status()
                break
            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as exc:
                last_exc = exc
                if attempt == 0:
                    time.sleep(_RETRY_BACKOFF_SECONDS)
                    continue
                # Named type so callers can tell "couldn't reach the server"
                # apart from "the server said no" (ShieldConsoleError).
                # Subclasses RuntimeError, so existing catch-alls still fire.
                raise ShieldConnectionError(
                    f"[G8R Shield] Could not connect to console at {self._console_url} "
                    f"after retry. Is the console running?"
                ) from exc
            except requests.exceptions.HTTPError as exc:
                # `response` is bound when raise_for_status fires. The raw
                # body is preserved on `.detail` for opt-in inspection but
                # is NOT included in `str(exc)` — host frameworks that
                # surface exception messages to end users would otherwise
                # echo internal error detail (stack traces, auth payloads,
                # PII shapes from upstream services). See
                # `ShieldConsoleError` for the threat-model rationale.
                status = response.status_code if response is not None else "?"
                body = response.text if response is not None else ""
                raise ShieldConsoleError(status, body) from exc

        # Defensive: should never reach here without `response` bound, but
        # appease the type checker for the case where the loop body changes.
        if response is None:
            raise ShieldConnectionError(
                f"[G8R Shield] Could not connect to console at {self._console_url}"
            ) from last_exc

        data = response.json()
        mappings = [
            ComplianceMapping(
                regulation=m.get("regulation", ""),
                control_id=m.get("controlId", ""),
                control_name=m.get("controlName", ""),
                description=m.get("description", ""),
            )
            for m in data.get("complianceMappings", [])
        ]
        return PolicyDecision(
            decision=data.get("decision", "blocked"),
            reason=data.get("reason", ""),
            violated_rule=data.get("violatedRule"),
            requires_approval=data.get("requiresApproval", False),
            session_revoked=data.get("sessionRevoked", False),
            compliance_mappings=mappings,
            redacted_tokens=redaction.tokens_replaced,
        )

    def _log(
        self,
        prompt: str,
        decision: PolicyDecision,
        *,
        request_id: str | None = None,
    ) -> ShieldLogEntry | None:
        """
        POST the interaction to ``/api/sdk/v1/log`` so it lands in the Console
        audit trail. Failures are warned, not raised — a logging outage must
        never break the user's LLM call or mask the decision path.

        ``request_id`` is generated per-call by default. ``wrap()`` passes
        its own value so /check and /log share a single correlation id.
        """
        if request_id is None:
            request_id = str(uuid.uuid4())
        url = f"{self._console_url}/api/sdk/v1/log"
        # Redact before the audit-log POST too: the raw prompt with secrets
        # must never leave the process via ANY endpoint — /check or /log.
        payload: dict[str, Any] = {
            "input": redact_sensitive_data(prompt).redacted,
            "tenantId": self._tenant_id,
            "requestId": request_id,
            "userId": self._user_id,
            "department": self._department,
            "aiModel": self._ai_model,
            "agentId": self._agent_id,
            "employeeName": self._employee_name or self._user_id,
            "decision": decision.decision,
            "reason": decision.reason,
            "violatedRule": decision.violated_rule,
            "requiresApproval": decision.requires_approval,
            "complianceMappings": [
                {
                    "regulation": m.regulation,
                    "controlId": m.control_id,
                    "controlName": m.control_name,
                    "description": m.description,
                }
                for m in decision.compliance_mappings
            ],
        }

        try:
            # Header construction lives INSIDE the try: resolving the
            # credential can raise (a credential_provider failure surfaces
            # as ShieldConnectionError), and on the audit-log path that is
            # a logging failure like any other — warned below, never
            # raised. See `_evaluate` for the rationale on the
            # `dict[str, str | bytes]` annotation.
            headers: dict[str, str | bytes] = {
                "Authorization": f"Bearer {self._bearer_credential()}",
                "Content-Type": "application/json",
                "User-Agent": _SDK_USER_AGENT,
            }
            response = requests.post(url, json=payload, headers=headers, timeout=self._timeout)
            response.raise_for_status()
            data = response.json()
        except Exception as exc:
            # Catch broadly — JSONDecodeError, unexpected requests internals,
            # anything. Logging must never interrupt the decision path.
            # (Exception, not BaseException, so KeyboardInterrupt / SystemExit
            # still propagate cleanly.)
            _LOGGER.error(
                "log_failed",
                tenant_id=self._tenant_id,
                request_id=request_id,
                agent_id=self._agent_id,
                error=str(exc),
            )
            return None

        return ShieldLogEntry(
            id=data.get("id", ""),
            decision=data.get("decision", ""),
            timestamp=data.get("timestamp", ""),
        )
