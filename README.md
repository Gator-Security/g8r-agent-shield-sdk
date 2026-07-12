# G8R Agent Shield SDK

Client SDKs for **G8R Agent Shield** — an enterprise AI-governance control
plane. Wrap your LLM and agent calls with deterministic policy enforcement,
local-first sensitive-data redaction, and a tamper-evident audit trail.

This repository holds two SDKs with an aligned wire contract and semantics:

| SDK        | Path                     | Package                          |
| ---------- | ------------------------ | -------------------------------- |
| TypeScript | [`js/`](./js)            | `@g8r-security/agent-shield-sdk` (npm)    |
| Python     | [`python/`](./python)    | `g8r-shield` (PyPI)              |

> **Note:** The TS/Python constructor surfaces are aligned — `tenantId` is the
> only hard-required field in both; `consoleUrl` / `apiKey` resolve from the
> `G8R_CONSOLE_URL` / `G8R_API_KEY` environment variables when not passed
> directly; everything else defaults. The wire contract and pipeline semantics
> are likewise aligned, and v2 Console support (workload-identity credentials,
> agent registration) lands in both SDKs together.

## What it does

Every `check()` / `wrap()` call:

1. Redacts recognized signing keys, custodial IDs, common PII (card numbers,
   SSNs, emails, phone numbers), and high-entropy secrets from the prompt
   **before** it leaves the process (best-effort, local-first redaction — see
   the caveat below). The same redaction is applied to the audit-log payload.
2. Evaluates the prompt against your deployed G8R Console's policy engine.
3. Records the (redacted) interaction in the audit trail.
4. Blocks, escalates, or allows the action per the policy decision.

## Quick start

### TypeScript

```ts
import { AgentShield, tenantId } from '@g8r-security/agent-shield-sdk';

const shield = new AgentShield({
  consoleUrl: 'https://shield.yourcompany.com',
  apiKey: 'sk-shield-...',
  tenantId: tenantId('your-tenant'),
  department: 'Finance',
  userId: 'usr_001',
  aiModel: 'gpt-4o',
});

const result = await shield.wrap(
  () => openai.chat.completions.create({ /* ... */ }),
  'Summarize Q1 earnings',
);
```

Full TypeScript API: [`js/README.md`](./js/README.md).

### Python

```python
from g8r_shield import AgentShield

shield = AgentShield(
    tenant_id="your-tenant",
    console_url="https://shield.yourcompany.com",
    api_key="sk-shield-...",
)

result = shield.wrap(lambda: call_your_llm(prompt), prompt)
```

Full Python API: [`python/README.md`](./python/README.md).

## Connecting to a self-hosted v2 Console

The v2 Console keeps the same SDK wire contract — the SDKs still call
`POST /api/sdk/v1/check` and `POST /api/sdk/v1/log` with an
`Authorization: Bearer <credential>` header. What v2 adds is a second way to
authenticate that credential, plus first-class agent registration.

### Console-side configuration

Set these in your Console deployment's server-side environment:

| Variable                    | Purpose                                                            |
| --------------------------- | ------------------------------------------------------------------ |
| `GF_SDK_SHARED_SECRET`      | Deployment shared secret — SDK calls presenting this value as the bearer credential are accepted |
| `GF_SDK_OIDC_ISSUER`        | OIDC issuer whose workload-identity JWTs the Console accepts (e.g. AWS workload identity) |
| `GF_SDK_OIDC_JWKS_URL`      | JWKS endpoint the Console uses to verify JWT signatures            |
| `GF_SDK_OIDC_AUDIENCE`      | Audience claim a JWT must carry to be accepted                     |
| `GF_SDK_ALLOWED_TENANTS`    | Optional — restrict which tenant ids the deployment will serve     |
| `GF_SDK_PENDING_AGENT_MODE` | `flag` (default) or `block` — how calls from not-yet-approved agents are handled (see [Agent registration](#agent-registration)) |

Configure the shared secret, the OIDC trio, or both — a call authenticates if
either credential form verifies.

### SDK-side pairing

- **Shared secret** — set `G8R_API_KEY` (or pass `apiKey` / `api_key`) to the
  value of `GF_SDK_SHARED_SECRET`.
- **Workload identity** — supply a short-lived OIDC JWT via the SDKs'
  credential-provider option instead of a static key; see the
  [TypeScript](./js/README.md) and [Python](./python/README.md) READMEs for
  the exact surface. When the Console verifies a JWT, the token's tenant claim
  is authoritative — it overrides the `tenantId` sent in the request body, and
  a mismatch is rejected.

The Console answers `401` for a bad or missing credential and `403` for a
tenant mismatch.

### Agent registration

The first call from an `agentId` the Console has not seen before automatically
creates a **pending registration** in the Console's Approvals queue. What
happens while the registration is pending depends on
`GF_SDK_PENDING_AGENT_MODE`:

- **`flag` (default)** — calls from the pending agent evaluate normally under
  your policy set; Console admins are alerted to review the registration.
- **`block`** — calls from the pending agent return `decision: "blocked"` with
  `requiresApproval: true` (the reason points at the Approvals queue) until an
  admin approves it.

An agent an admin has **denied** stays blocked in both modes:
`decision: "blocked"` with `requiresApproval: false`.

> **Detecting the pending state.** On a v2 Console, `decision == "blocked"`
> together with `requiresApproval == true` (`requires_approval` in Python)
> occurs **only** for a pending registration under `block` mode — treat that
> conjunction as the pending signal. Do not branch on `reason` strings; they
> are human-readable copy and may change.

## License

Apache-2.0 — see [LICENSE](./LICENSE).
