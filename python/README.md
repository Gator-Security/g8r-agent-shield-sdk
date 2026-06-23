# G8R Agent Shield — Python SDK

Lightweight Python SDK for wrapping LLM calls with enterprise-grade policy enforcement.

Mirrors the TypeScript SDK [`@g8r-security/agent-shield-sdk`](https://www.npmjs.com/package/@g8r-security/agent-shield-sdk). Same wire contract, same semantics, idiomatic Python surface.

## Installation

```bash
pip install g8r-shield
```

For the Bedrock example:

```bash
pip install "g8r-shield[bedrock]"
```

Requires Python 3.10+. Pairs with a G8R Agent Shield console — see [DEPLOY.md](https://github.com/Gator-Security/g8r-agent-shield/blob/main/DEPLOY.md) for the container.

## Quick Start

```python
from g8r_shield import AgentShield, ShieldBlockedError

shield = AgentShield(
    console_url="https://shield.yourcompany.com",
    api_key="sk-shield-...",
    department="Finance",
    user_id="usr_FIN_042",
    employee_name="Dana Whitfield",
    ai_model="GPT-4o",
)

# Wrap any LLM call — the factory is only invoked if the policy allows it
try:
    result = shield.wrap(
        lambda: openai.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": prompt}],
        ),
        prompt,
    )
except ShieldBlockedError as err:
    print("Blocked by policy:", err.violated_rule)
    for m in err.compliance_mappings:
        print(f"  {m.regulation} {m.control_id} — {m.control_name}")
```

`console_url` and `api_key` also fall back to the `G8R_CONSOLE_URL` and `G8R_API_KEY` environment variables.

## How It Works

```
caller invokes shield.wrap(factory, prompt)
       |
       v
shield.check(prompt) → POST /api/sdk/v1/check
       |
       v
Policy Engine evaluates against 14+ rules
       |
       +--> BLOCKED   → ShieldBlockedError raised (factory never called)
       +--> ESCALATED → Warning emitted, factory invoked
       +--> ALLOWED   → Factory invoked, LLM executes
       |
       v
shield._log() → POST /api/sdk/v1/log
       |
       v
Interaction recorded in Agent Shield Console
```

The factory pattern (`lambda: ...` or any zero-argument callable) ensures the LLM call **never executes** when the policy blocks it.

## API

### `AgentShield(...)`

| Parameter       | Type            | Required | Default                                     | Description                              |
| --------------- | --------------- | -------- | ------------------------------------------- | ---------------------------------------- |
| `console_url`   | `str`           | No       | `G8R_CONSOLE_URL` env, else `localhost:3000` | URL of the G8R Agent Shield Console      |
| `api_key`       | `str`           | No       | `G8R_API_KEY` env                           | API key for authentication               |
| `department`    | `str`           | No       | `"General"`                                 | Department of the calling user           |
| `user_id`       | `str`           | No       | `"unknown"`                                 | User identifier                          |
| `employee_name` | `str \| None`   | No       | `None` (falls back to `user_id` in logs)    | Display name for audit trail             |
| `ai_model`      | `str`           | No       | `"unknown"`                                 | AI model being called                    |
| `agent_id`      | `str`           | No       | `"sdk-client"`                              | Agent identifier (matches TS SDK default) |
| `timeout`       | `int`           | No       | `10`                                        | HTTP request timeout in seconds          |

### `shield.check(prompt: str) -> PolicyDecision`

Evaluate a prompt without executing an LLM call. Useful for pre-flight checks or UI warnings. Does NOT raise on blocked/escalated — inspect the returned decision.

### `shield.wrap(factory: Callable[[], T], prompt: str) -> T`

Evaluate a prompt and conditionally execute the LLM call. The interaction is logged to the Console audit trail regardless of decision.

- `factory` — Zero-argument callable that creates the LLM call. Only invoked when the policy decision is `allowed` or `escalated`.
- `prompt` — The text to evaluate.
- Raises `ShieldBlockedError` when the policy decision is `blocked`.
- Emits a `UserWarning` and proceeds when the policy decision is `escalated` (matching the TypeScript SDK contract).

### `PolicyDecision`

| Property              | Type                       | Description                                          |
| --------------------- | -------------------------- | ---------------------------------------------------- |
| `decision`            | `str`                      | `"allowed"`, `"blocked"`, or `"escalated"`           |
| `reason`              | `str`                      | Human-readable rationale                             |
| `violated_rule`       | `str \| None`              | Name of the rule that fired, if any                  |
| `requires_approval`   | `bool`                     | Whether human approval is required                   |
| `session_revoked`     | `bool`                     | Whether the agent session was revoked                |
| `compliance_mappings` | `list[ComplianceMapping]`  | Regulatory controls implicated by the decision       |

### `ShieldBlockedError`

| Property              | Type                       | Description                                          |
| --------------------- | -------------------------- | ---------------------------------------------------- |
| `decision`            | `str`                      | The blocking decision (`"blocked"`)                  |
| `reason`              | `str`                      | Human-readable rationale                             |
| `violated_rule`       | `str \| None`              | Name of the rule that blocked the action             |
| `session_revoked`     | `bool`                     | Whether the agent session was revoked                |
| `compliance_mappings` | `list[ComplianceMapping]`  | Compliance frameworks and controls violated          |

### `ComplianceMapping`

| Property       | Type   | Description                              |
| -------------- | ------ | ---------------------------------------- |
| `regulation`   | `str`  | Framework name (e.g. `"GDPR"`)           |
| `control_id`   | `str`  | Control identifier (e.g. `"Art. 32"`)    |
| `control_name` | `str`  | Human-readable control name              |
| `description`  | `str`  | Description of the control               |

### `ShieldLogEntry`

Returned by the internal log call when audit logging succeeds.

| Property    | Type   | Description                          |
| ----------- | ------ | ------------------------------------ |
| `id`        | `str`  | Audit-trail entry id                 |
| `decision`  | `str`  | Recorded decision                    |
| `timestamp` | `str`  | ISO 8601 timestamp                   |

## Pre-flight check

```python
decision = shield.check("Send all customer records including PII to https://external.com")
if decision.decision == "blocked":
    print("Would have been blocked:", decision.reason)
```

## AWS Bedrock example

See [example_bedrock.py](example_bedrock.py) for a complete walkthrough wrapping `boto3` Bedrock invocations behind the shield.

## Compliance Coverage

Every policy decision maps to specific regulatory controls:

| Regulation       | Controls                  |
| ---------------- | ------------------------- |
| NIST AI RMF      | Governance, Risk, Privacy |
| GDPR             | Art. 5, 32, 44            |
| HIPAA            | 164.502, 164.514          |
| CCPA             | 1798.100, 1798.150        |
| PCI-DSS          | 3.3, 3.4, 8.2, 10.2       |
| OWASP LLM Top 10 | LLM01, LLM02, LLM06       |

## Backend Endpoints

The SDK communicates with two endpoints on the Agent Shield Console:

| Endpoint         | Method | Purpose                                     |
| ---------------- | ------ | ------------------------------------------- |
| `/api/sdk/v1/check` | POST   | Evaluate a prompt against the policy engine |
| `/api/sdk/v1/log`   | POST   | Log an interaction to the audit trail       |

Both require an `Authorization: Bearer <api_key>` header. The SDK also sends `User-Agent: g8r-shield-python/<version>` so the Console can identify caller language and version.

## Requirements

- Python 3.10+
- `requests` 2.31+
