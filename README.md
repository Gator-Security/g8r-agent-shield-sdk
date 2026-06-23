# G8R Agent Shield SDK

Client SDKs for **G8R Agent Shield** — an enterprise AI-governance control
plane. Wrap your LLM and agent calls with deterministic policy enforcement,
local-first sensitive-data redaction, and a tamper-evident audit trail.

This repository holds two SDKs that maintain a deliberate surface parity:

| SDK        | Path                     | Package                          |
| ---------- | ------------------------ | -------------------------------- |
| TypeScript | [`js/`](./js)            | `@g8r-security/agent-shield-sdk` (npm)    |
| Python     | [`python/`](./python)    | `g8r-shield` (PyPI)              |

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

## License

Apache-2.0 — see [LICENSE](./LICENSE).
