# SDK reference

Public client contract for the two packages in this repository:

| Language   | Package                          | Published version on `main` |
| ---------- | -------------------------------- | --------------------------- |
| TypeScript | `@g8r-security/agent-shield-sdk` | `0.4.0`                     |
| Python     | `g8r-shield`                     | `0.4.0`                     |

This page documents the **shipped** constructors, methods, decision objects, and
wire endpoints as they appear in the published client source on `main`. It does
not invent endpoints.

Decision-path versions (`/api/sdk/v1/check` today vs intended PEP `/proxy`) are
specified in [wrap / check / PEP one-hop](./wrap-check-pep-one-hop.md).

Language-specific walkthroughs: [TypeScript README](../js/README.md),
[Python README](../python/README.md).

## Install

```bash
npm install @g8r-security/agent-shield-sdk
```

```bash
pip install g8r-shield
```

Python extras published in this repo: `g8r-shield[bedrock]`, `g8r-shield[adk]`.
Requires Python 3.10+. The TypeScript package requires Node 18+.

## Construct `AgentShield`

`tenantId` / `tenant_id` is the only hard-required constructor field. The
Console base URL and the bearer credential are required in effect: pass them, or
resolve them from `G8R_CONSOLE_URL` and `G8R_API_KEY`. If either is unresolved,
the constructor throws. It does not default the Console URL to localhost.

`apiKey` / `api_key` and `credentialProvider` / `credential_provider` are
mutually exclusive. A provider is invoked fresh on every outbound request. When
a provider is set, `G8R_API_KEY` is not read.

```ts
import { AgentShield, tenantId } from '@g8r-security/agent-shield-sdk';

const shield = new AgentShield({
  tenantId: tenantId('your-tenant'),
  consoleUrl: process.env.G8R_CONSOLE_URL,
  apiKey: process.env.G8R_API_KEY,
  // credentialProvider: () => mintWorkloadJwt(),
  department: 'Finance',
  userId: 'usr_001',
  aiModel: 'gpt-4o',
  agentId: 'sdk-client',
});
```

```python
from g8r_shield import AgentShield

shield = AgentShield(
    tenant_id="your-tenant",
    console_url=None,  # or set G8R_CONSOLE_URL
    api_key=None,      # or set G8R_API_KEY
    # credential_provider=fetch_workload_jwt,
    department="Finance",
    user_id="usr_001",
    ai_model="gpt-4o",
    agent_id="sdk-client",
)
```

### Constructor fields (both languages)

| TypeScript            | Python                 | Required                         | Default        | Role |
| --------------------- | ---------------------- | -------------------------------- | -------------- | ---- |
| `tenantId`            | `tenant_id`            | yes                              | —              | Tenant identity. TypeScript: `tenantId()` branded helper, charset `[a-z0-9-]`, 1–64 chars. |
| `consoleUrl`          | `console_url`          | yes in effect (`G8R_CONSOLE_URL`) | —             | Console base URL. Trailing slashes stripped. |
| `apiKey`              | `api_key`              | yes in effect unless provider (`G8R_API_KEY`) | — | Static bearer credential. Never logged or included in `toString()` / `repr()`. |
| `credentialProvider`  | `credential_provider`  | no                               | unset          | Per-request bearer callback. Mutually exclusive with the static key. |
| `department`          | `department`           | no                               | `"General"`    | Attribution on the wire. |
| `userId`              | `user_id`              | no                               | `"unknown"`    | Attribution on the wire. |
| `aiModel`             | `ai_model`             | no                               | `"unknown"`    | Attribution on the wire. |
| `agentId`             | `agent_id`             | no                               | `"sdk-client"` | Agent identity on `/check` and `/log`. |
| `sessionId`           | `session_id`           | no                               | unset          | Per-instance default session. See [Lineage](#lineage). |
| `employeeName`        | `employee_name`        | no                               | unset          | Audit-trail label on `/log` only (falls back to user id). Not sent on the decision hop. |
| `timeout`             | `timeout`              | no                               | `10` seconds   | HTTP timeout for the decision hop and `/log`. |
| `blockOnEscalated`    | `block_on_escalated`   | no                               | `false`        | When true, `wrap()` throws on `escalated` as well as `blocked`. |

Intended `0.5.0` adds `pepUrl` / `pep_url` (`G8R_PEP_URL`). That field is **not**
on the published `0.4.0` constructor. See
[wrap / check / PEP one-hop](./wrap-check-pep-one-hop.md).

## `wrap(factory, prompt)`

Primary integration. One governed action:

1. Local-first redaction of `prompt`.
2. One policy decision hop (see the [one-hop page](./wrap-check-pep-one-hop.md)).
3. One audit POST to `/api/sdk/v1/log` (not a decision).
4. Invoke `factory` only when the decision is `allowed`, or `escalated` while
   `blockOnEscalated` / `block_on_escalated` is false.

`factory` is a zero-argument callable. It is not invoked on `blocked`. On an
unrecognized decision value, both clients refuse to invoke `factory`.

TypeScript `wrap()` is async. Python `wrap()` is synchronous.

```ts
const result = await shield.wrap(
  () => model.complete(prompt),
  prompt,
);
```

```python
result = shield.wrap(lambda: model.complete(prompt), prompt)
```

A single `requestId` is minted for the invocation and sent on both the decision
hop and `/log`.

## `check(prompt, …)`

Point evaluation. Returns the decision. Does **not** invoke an LLM factory.
Does **not** throw on `blocked` or `escalated`.

By default `check()` also POSTs `/api/sdk/v1/log` with the same `requestId`
(self-auditing). Pass `log: false` / `log=False` when you will immediately call
`wrap()` for the same prompt — `wrap()` logs once itself. That option only
suppresses the extra audit POST; it does **not** skip the decision hop.

```ts
const result = await shield.check(prompt);
// result.decision → 'allowed' | 'blocked' | 'escalated'

await shield.check(prompt, {
  requestId: newRequestId(),
  log: false,
});
```

```python
decision = shield.check(prompt)
# decision.decision → "allowed" | "blocked" | "escalated"

shield.check(prompt, request_id=request_id, log=False)
```

`check()` reports ambient lineage; it does not mint a session and does not open
a nested agent scope. A standalone `check()` with no configured / ambient
session omits `sessionId` and `parentAgents`.

## `run(…)` and Python `child(…)`

`run` groups calls under one `sessionId` without adding an agent hop.

```ts
await shield.run(async () => {
  await shield.wrap(() => turnOne(), promptOne);
  await shield.wrap(() => turnTwo(), promptTwo);
}, { sessionId: 'conversation-abc' });
```

```python
with shield.run() as session_id:
    shield.check("step one")
    shield.wrap(lambda: call_model(prompt), prompt)
```

Python also publishes `shield.child(agent_id=...)` to append a parent hop when
nesting happens outside a wrapped factory. TypeScript has no `child()`; nesting
`wrap()` inside another `wrap()` factory is the published way to extend the
chain.

## Decision object

| TypeScript (`PolicyCheckResult`) | Python (`PolicyDecision`) | Notes |
| -------------------------------- | ------------------------- | ----- |
| `decision`                       | `decision`                | `'allowed'` \| `'blocked'` \| `'escalated'` |
| `reason`                         | `reason`                  | Human-readable. Do not parse. |
| `violatedRule`                   | `violated_rule`           | Rule name, or null. |
| `requiresApproval`               | `requires_approval`       | From the decision hop body. |
| `isPendingRegistration`          | `is_pending_registration` | Derived client-side: `blocked` **and** `requiresApproval`. Not a wire field. |
| `sessionRevoked`                 | `session_revoked`         | Present when a kill-switch decision sets it. |
| `complianceMappings`             | `compliance_mappings`     | `{ regulation, controlId, controlName, description }` (`control_id` / `control_name` in Python). |
| `redactedTokens`                 | `redacted_tokens`         | Tokens stripped locally before the hop. Omitted / empty when none. |

On a Console that registers unknown `agentId` values on first use:

- pending + server `flag` mode: ordinary policy decisions; the pending flag is unset
- pending + server `block` mode: `blocked` with `requiresApproval: true`
- admin-denied: `blocked` with `requiresApproval: false`

## Errors

| Error                   | When |
| ----------------------- | ---- |
| `ShieldBlockedError`    | `wrap()` on `blocked`, or on `escalated` when the instance is configured to block escalations. |
| `ShieldConsoleError`    | Non-2xx from the decision hop. Message exposes only the status code. Raw body is on `.detail` for opt-in inspection. |
| `ShieldConnectionError` | Decision hop unreachable after one retry, or the credential provider rejected before a request was sent. |

`check()` returns blocked/escalated decisions; it does not throw
`ShieldBlockedError`. Logging failures on `/api/sdk/v1/log` are swallowed so an
audit outage does not replace the decision.

`ShieldBlockedError` also carries `isPendingRegistration` /
`is_pending_registration` (same client-side conjunction as the decision object).

## Redaction

Both clients redact **before** the prompt leaves the process, on the decision
hop and on `/log`. Redaction is best-effort pattern and entropy matching, not a
completeness guarantee.

TypeScript exports `redactSensitiveData` from the package root. Python publishes
`g8r_shield.redaction.redact_sensitive_data`.

Shared labels in both clients: `BIP32_KEY`, `WIF_KEY`, `HEX_KEY`, `PEM_KEY`,
`CUSTODIAL_ID`, `CUST_ID`, `WALLET_ID`, `VAULT_ID`, `HIGH_ENTROPY` (Shannon
entropy ≥ 4.5 bits/char and length ≥ 32).

TypeScript additionally labels `CARD`, `SSN`, `EMAIL`, and `PHONE`. Those four
labels are not in the published Python redaction module.

## Lineage

Optional additive fields on both the decision hop and `/log`:

| Field          | Meaning |
| -------------- | ------- |
| `sessionId`    | Stable id for one logical run. Omitted when none is configured or ambient. |
| `parentAgents` | Ancestor `agentId` values, root-first, immediate parent last. Omitted when empty. |

Lineage is advisory and self-asserted. Clients send it; they do not use it to
decide. `wrap()` extends the ambient chain around `factory` so nested `wrap()` /
`check()` calls inherit the session and this agent as parent.

## Shipped wire endpoints (`0.4.0`)

Verified against `js/src/index.ts` and `python/g8r_shield/shield.py` on `main`:

| Method | Path | Role in `0.4.0` |
| ------ | ---- | --------------- |
| `POST` | `{consoleUrl}/api/sdk/v1/check` | Policy decision for `check()` and `wrap()`. |
| `POST` | `{consoleUrl}/api/sdk/v1/log`   | Audit record. Not a decision. |

Both send `Authorization: Bearer <credential>`, `Content-Type: application/json`,
and `User-Agent: g8r-shield-typescript/<version>` or
`g8r-shield-python/<version>`.

Decision-hop JSON body (camelCase in both languages): `input` (redacted),
`tenantId`, `requestId`, `department`, `userId`, `aiModel`, `agentId`, plus
`sessionId` / `parentAgents` when present. `employeeName` is not sent on the
decision hop.

`/log` adds `employeeName`, `decision`, `reason`, `violatedRule`,
`requiresApproval`, and `complianceMappings`.

A transient connection/timeout on the decision hop is retried once (500 ms
backoff), then surfaced as `ShieldConnectionError`. Non-2xx is not retried.

The intended `0.5.0` decision path replaces `/api/sdk/v1/check` with PEP
`/proxy`. That replacement is **not** in published `0.4.0`. See
[wrap / check / PEP one-hop](./wrap-check-pep-one-hop.md).

## Auth pairing

The Console accepts the deployment shared secret or a verified OIDC JWT in the
same `Authorization: Bearer` header. With a verified JWT, the token’s tenant
claim is authoritative over the body’s `tenantId`; a mismatch is HTTP `403`. A
bad or missing credential is HTTP `401`.

Console-side pairing variables are listed in the [root README](../README.md).

## Other published helpers

| Export | Language | Role |
| ------ | -------- | ---- |
| `VERSION` | TypeScript | `'0.4.0'` |
| `__version__` | Python | `'0.4.0'` (from package metadata, fallback `0.4.0`) |
| `tenantId`, `newRequestId`, `newSessionId` | TypeScript | Id helpers. `RequestId` / `TenantId` are branded string types. |
| `get_logger(**bindings)` | Python | `structlog` logger bound to `g8r_shield`. |
| `g8r_shield.adk.ShieldPlugin` | Python (`g8r-shield[adk]`) | Governs a Google ADK `Runner` tree through the same `AgentShield` instance. |
