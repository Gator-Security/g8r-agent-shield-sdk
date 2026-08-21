# wrap / check / PEP one-hop

This page is the public decision-path contract for TypeScript
(`@g8r-security/agent-shield-sdk`) and Python (`g8r-shield`). Method shapes are
in the [SDK reference](./sdk-reference.md). Endpoints below are taken from this
repository’s client source — nothing else is implied.

## Required property

**One governed action = local redaction + one PEP `/proxy` hop, and exactly one
PDP decision at that PEP.**

`wrap()` must not call `POST /api/sdk/v1/check` **and** PEP decide for the same
action. The audit POST is not a decision.

```
prompt
  │
  ├─ 1. redact locally (in-process; best-effort)
  │
  ├─ 2. ONE hop — PEP POST /proxy  →  exactly one PDP decision
  │
  ├─ 3. POST /api/sdk/v1/log       →  audit only (no decision)
  │
  └─ 4. invoke factory             →  only after allowed
                                      (or escalated, unless configured to block)
```

`check()` is the same decision hop without invoking a factory. It is also
exactly one PDP decision. Do not pair `check()` and `wrap()` on the same prompt
if you need a single decision — each call performs its own hop.
`{ log: false }` / `log=False` only suppresses a second `/log`; it does not
remove the decision hop from a following `wrap()`.

## What is shipped vs what is intended

Verified against `js/src/index.ts` and `python/g8r_shield/shield.py` on `main`
(package version **`0.4.0`**):

| Step | Shipped `0.4.0` | Intended `0.5.0` one-hop |
| ---- | ---------------- | ------------------------ |
| Local redact | Yes, before any POST | Same |
| Decision hop | `POST {consoleUrl}/api/sdk/v1/check` | `POST {pepUrl}/proxy` |
| Audit hop | `POST {consoleUrl}/api/sdk/v1/log` | Same path; still not a decision |
| Second decide | `wrap()` does **not** call a second decision endpoint in `0.4.0` | `wrap()` must **not** also call `/api/sdk/v1/check` |

**`0.4.0` still talks to `/api/sdk/v1/check`.** That is the published decision
endpoint today. PEP `/proxy`, `pepUrl` / `pep_url`, and `G8R_PEP_URL` are **not**
in the published `0.4.0` client.

The intended replacement — one PEP `/proxy` hop, no `/api/sdk/v1/check` on
`wrap()` / `check()` — is the implementation in
[pull request #14](https://github.com/Gator-Security/g8r-agent-shield-sdk/pull/14)
(draft, not merged, not a shipped release). This page does not treat that PR as
published API.

## TypeScript

### Shipped `0.4.0`

`wrap()` and `check()` call private `evaluate()`, which POSTs the redacted
prompt to `{consoleUrl}/api/sdk/v1/check`. `wrap()` does not go through the
public `check()` method; it still performs **one** `/check` and then one
`/log`.

```ts
import { AgentShield, tenantId } from '@g8r-security/agent-shield-sdk';

const shield = new AgentShield({
  tenantId: tenantId('your-tenant'),
  consoleUrl: process.env.G8R_CONSOLE_URL,
  apiKey: process.env.G8R_API_KEY,
});

// One decision hop (/api/sdk/v1/check) + one /log, then factory if allowed.
const result = await shield.wrap(() => model.complete(prompt), prompt);

// Same decision hop; no factory. Default also POSTs /log.
const decision = await shield.check(prompt);
```

`0.4.0` has no `pepUrl` field and does not POST `/proxy`.

### Intended `0.5.0` (PR #14 — not shipped)

Constructor grows `pepUrl`, resolved from the argument or `G8R_PEP_URL`.
`evaluate()` POSTs `{pepUrl}/proxy` instead of `{consoleUrl}/api/sdk/v1/check`.
`wrap()` still does one `evaluate()` and one `/log`. Tests on that branch assert
the fetched URLs include `/proxy` and do **not** include `/api/sdk/v1/check`.

If `pepUrl` / `G8R_PEP_URL` is unset, that branch falls back to `consoleUrl` and
still POSTs `/proxy` on that base (it does not restore `/api/sdk/v1/check`).
Prefer an explicit PEP base URL.

Intended decision-hop headers on that branch, in addition to
`Authorization: Bearer …`, `Content-Type: application/json`, and
`User-Agent: g8r-shield-typescript/<version>`:

- `X-GF-Tenant-ID` — constructor `tenantId`
- `X-GF-Agent-ID` — constructor `agentId`

JSON body fields stay the shipped camelCase set (`input`, `tenantId`,
`requestId`, `department`, `userId`, `aiModel`, `agentId`, plus lineage when
present). This page does not add paths beyond `/proxy` and `/api/sdk/v1/log`.

## Python

### Shipped `0.4.0`

`check()` calls `_evaluate()`, which POSTs `{console_url}/api/sdk/v1/check`.
`wrap()` calls `check(..., log=False)` and then `_log()` — still **one**
`/check` and one `/log`, not two decisions.

```python
from g8r_shield import AgentShield

shield = AgentShield(
    tenant_id="your-tenant",
    console_url=None,  # G8R_CONSOLE_URL
    api_key=None,      # G8R_API_KEY
)

result = shield.wrap(lambda: model.complete(prompt), prompt)
decision = shield.check(prompt)
```

`0.4.0` has no `pep_url` argument and does not POST `/proxy`.

### Intended `0.5.0` (PR #14 — not shipped)

Constructor grows `pep_url`, resolved from the argument or `G8R_PEP_URL`.
`_evaluate()` POSTs `{pep_url}/proxy` instead of
`{console_url}/api/sdk/v1/check`. `wrap()` still uses one `_evaluate()` (via
`check(..., log=False)`) and one `_log()`.

Unset `pep_url` / `G8R_PEP_URL` falls back to `console_url` and still POSTs
`/proxy`. Prefer an explicit PEP base URL.

Intended extra headers match TypeScript: `X-GF-Tenant-ID`, `X-GF-Agent-ID`,
plus `User-Agent: g8r-shield-python/<version>`.

## What is not a decision

| Call | Decision? |
| ---- | --------- |
| Local redaction | No. Prepares `input` before the hop. |
| PEP `POST /proxy` (intended `0.5.0`) | **Yes — the one PDP decision.** |
| `POST /api/sdk/v1/check` (shipped `0.4.0`) | Yes, in `0.4.0` only. Not part of the intended one-hop path. |
| `POST /api/sdk/v1/log` | No. Audit adjunct. |
| Invoking `factory` | No. Runs only after the decision allows it. |

`/log` failures are swallowed in both clients so an audit outage does not
replace the decision.

## Enforcement after the hop

Same in both languages, shipped and intended:

| Decision    | `wrap()` |
| ----------- | -------- |
| `allowed`   | Invoke `factory`. |
| `blocked`   | Throw `ShieldBlockedError`. `factory` is not called. |
| `escalated` | Invoke `factory` unless `blockOnEscalated` / `block_on_escalated` is true, in which case throw `ShieldBlockedError`. |

Unrecognized decision values do not invoke `factory`.

## Do not invent

Partners call only the endpoints in this repository’s client source:

- Shipped: `/api/sdk/v1/check`, `/api/sdk/v1/log`
- Intended `0.5.0` (PR #14): `/proxy`, `/api/sdk/v1/log`

There is no second decide URL on `wrap()`, no client path that combines
`/api/sdk/v1/check` with PEP `/proxy`, and no additional decision routes
documented here.
