# wrap / check / PEP one-hop

Public SDK page for TypeScript (`@g8r-security/agent-shield-sdk`) and Python
(`g8r-shield`). Endpoints below are the ones these clients call — nothing else
is implied.

## Required property

**One governed action = local redaction + one PEP `/proxy` hop, and exactly one
PDP decision at that PEP.**

`wrap()` must not call `POST /api/sdk/v1/check` **and** PEP decide for the same
action. `POST /api/sdk/v1/log` is audit only. It is not a decision.

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

`check()` is the same decision hop without invoking a factory. Do not pair
`check()` and `wrap()` on the same prompt if you need a single decision — each
call performs its own hop. `{ log: false }` / `log=False` only suppresses a
second `/log`.

## wrap()

Primary governed action. Redact locally, one decision hop, one `/log`, then
invoke `factory` only when allowed (or escalated, unless configured to block).

<CodeGroup>

```typescript TypeScript
import { AgentShield, tenantId } from '@g8r-security/agent-shield-sdk';

const shield = new AgentShield({
  tenantId: tenantId('your-tenant'),
  consoleUrl: process.env.G8R_CONSOLE_URL,
  apiKey: process.env.G8R_API_KEY,
});

const result = await shield.wrap(() => model.complete(prompt), prompt);
```

```python Python
from g8r_shield import AgentShield

shield = AgentShield(
    tenant_id="your-tenant",
    console_url=None,  # G8R_CONSOLE_URL
    api_key=None,      # G8R_API_KEY
)

result = shield.wrap(lambda: model.complete(prompt), prompt)
```

</CodeGroup>

## check()

Point evaluation. Same decision hop. No factory. Does not throw on `blocked` or
`escalated`. Default also POSTs `/log` with the same `requestId`.

<CodeGroup>

```typescript TypeScript
const decision = await shield.check(prompt);
// decision.decision → 'allowed' | 'blocked' | 'escalated'

await shield.check(prompt, { log: false });
```

```python Python
decision = shield.check(prompt)
# decision.decision → "allowed" | "blocked" | "escalated"

shield.check(prompt, log=False)
```

</CodeGroup>

## Shipped `0.4.0` vs intended `0.5.0`

Verified against the published clients on `main` (package version **`0.4.0`**):

| Step | Shipped `0.4.0` | Intended `0.5.0` one-hop |
| ---- | ---------------- | ------------------------ |
| Local redact | Yes, before any POST | Same |
| Decision hop | `POST {consoleUrl}/api/sdk/v1/check` | `POST {pepUrl}/proxy` |
| Audit hop | `POST {consoleUrl}/api/sdk/v1/log` | Same path; still not a decision |
| Second decide | `wrap()` performs one decision hop | `wrap()` must **not** also call `/api/sdk/v1/check` |

**`0.4.0` still talks to `/api/sdk/v1/check`.** That is the published decision
endpoint today. PEP `/proxy`, `pepUrl` / `pep_url`, and `G8R_PEP_URL` are **not**
in the published `0.4.0` client.

The intended replacement — one PEP `/proxy` hop, no `/api/sdk/v1/check` on
`wrap()` / `check()` — is the implementation in
[pull request #14](https://github.com/Gator-Security/g8r-agent-shield-sdk/pull/14)
(draft, not merged, not a shipped release).

Intended `0.5.0` constructor (not shipped):

<CodeGroup>

```typescript TypeScript
const shield = new AgentShield({
  tenantId: tenantId('your-tenant'),
  pepUrl: process.env.G8R_PEP_URL,
  consoleUrl: process.env.G8R_CONSOLE_URL,
  apiKey: process.env.G8R_API_KEY,
});
```

```python Python
shield = AgentShield(
    tenant_id="your-tenant",
    pep_url=None,      # G8R_PEP_URL
    console_url=None,  # G8R_CONSOLE_URL
    api_key=None,      # G8R_API_KEY
)
```

</CodeGroup>

## What is not a decision

| Call | Decision? |
| ---- | --------- |
| Local redaction | No |
| PEP `POST /proxy` (intended `0.5.0`) | **Yes — the one PDP decision** |
| `POST /api/sdk/v1/check` (shipped `0.4.0`) | Yes, in `0.4.0` only. Not part of the intended one-hop path |
| `POST /api/sdk/v1/log` | No. Audit only |
| Invoking `factory` | No. Runs only after the decision allows it |

## After the hop

| Decision    | `wrap()` |
| ----------- | -------- |
| `allowed`   | Invoke `factory` |
| `blocked`   | Throw `ShieldBlockedError`. `factory` is not called |
| `escalated` | Invoke `factory` unless `blockOnEscalated` / `block_on_escalated` is true |

Partners call only these client paths:

- Shipped `0.4.0`: `/api/sdk/v1/check`, `/api/sdk/v1/log`
- Intended `0.5.0` (PR #14): `/proxy`, `/api/sdk/v1/log`
