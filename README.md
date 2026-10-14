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
> only hard-required identity field in both. `consoleUrl` resolves from
> `G8R_CONSOLE_URL` when not passed directly. The bearer credential is
> per tenant or per agent, supplied at runtime (`apiKey` / `credentialFile` /
> `credentialEnv`, or `G8R_TENANT_CREDENTIAL` / `G8R_TENANT_CREDENTIAL_FILE`).
> There is no shared or default SDK secret. The client refuses to start
> without a credential, and it never logs the value.

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
  pepUrl: 'https://pep.yourcompany.com',
  consoleUrl: 'https://shield.yourcompany.com',
  credentialFile: '/run/secrets/g8r-tenant-credential',
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
    pep_url="https://pep.yourcompany.com",
    console_url="https://shield.yourcompany.com",
    credential_file="/run/secrets/g8r-tenant-credential",
)

result = shield.wrap(lambda: call_your_llm(prompt), prompt)
```

Full Python API: [`python/README.md`](./python/README.md).

## Connecting to a self-hosted v2 Console

v0.5.0 `wrap()` hops PEP `POST /decide` (`pepUrl` / `G8R_PEP_URL` required; no
console fallback, no localhost). `check()` still POSTs Console
`/api/sdk/v1/check` (the documented gap). `/log` remains the audit adjunct.
What v2 adds is workload-identity authentication for that credential, plus
first-class agent registration.

### Per-tenant credential

Each `AgentShield` client presents its own tenant or agent credential. The
SDK will not start with a missing credential, and it will not fall back to a
deployment-wide or hard-coded secret. Supply the credential at runtime, for
example a file fetched from 1Password or the broker:

- **File** — `credentialFile` / `credential_file`, or
  `G8R_TENANT_CREDENTIAL_FILE` when this process serves one tenant.
- **Env var** — `credentialEnv` / `credential_env` naming the variable that
  holds this client's credential, or `G8R_TENANT_CREDENTIAL` for the
  one-tenant process case.
- **Already fetched** — pass `apiKey` / `api_key` for this client only.
- **Short-lived token** — `credentialProvider` / `credential_provider`,
  awaited fresh on every request.

Two clients in one process pass different files or env var names; they do not
share a credential. The value is sent only as `Authorization: Bearer` and is
never logged. See the [TypeScript](./js/README.md) and
[Python](./python/README.md) READMEs.

## Upgrading to 0.7.0

0.7.0 is a breaking release. The full migration note is in
[CHANGELOG.md](./CHANGELOG.md).

- Each client needs its own runtime credential. There is no shared or default
  secret, and the old deployment-wide variable is not read.
- `consoleUrl` / `console_url` and `pepUrl` / `pep_url` must be `https`.
  Loopback is refused on both. For local development only, set
  `G8R_ALLOW_INSECURE_LOCALHOST=1` to permit `http://localhost`,
  `http://127.0.0.1`, and `http://[::1]` (and https on those hosts). The
  override does not allow plaintext to any other host.
- A blank or whitespace-only tenant id is rejected.

### Console-side configuration

Set these in your Console deployment's server-side environment:

| Variable                    | Purpose                                                            |
| --------------------------- | ------------------------------------------------------------------ |
| `GF_SDK_OIDC_ISSUER`        | OIDC issuer whose workload-identity JWTs the Console accepts (e.g. AWS workload identity) |
| `GF_SDK_OIDC_JWKS_URL`      | JWKS endpoint the Console uses to verify JWT signatures            |
| `GF_SDK_OIDC_AUDIENCE`      | Audience claim a JWT must carry to be accepted                     |
| `GF_SDK_ALLOWED_TENANTS`    | Optional — restrict which tenant ids the deployment will serve     |
| `GF_SDK_PENDING_AGENT_MODE` | `flag` (default) or `block` — how calls from not-yet-approved agents are handled (see [Agent registration](#agent-registration)) |

When the Console verifies a JWT, the token's tenant claim is authoritative —
it overrides the `tenantId` sent in the request body, and a mismatch is
rejected. The Console answers `401` for a bad or missing credential and `403`
for a tenant mismatch.

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
