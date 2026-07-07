/**
 * G8R Agent Shield SDK
 *
 * Lightweight TypeScript client that wraps LLM calls with policy enforcement.
 * Automatically intercepts prompts, applies best-effort local-first redaction,
 * checks them against the G8R policy engine, and logs all activity to the
 * Agent Shield Console.
 *
 * Usage:
 *   import { AgentShield, tenantId } from '@g8r-security/agent-shield-sdk';
 *
 *   const shield = new AgentShield({
 *     // consoleUrl / apiKey can be omitted and resolved from the
 *     // G8R_CONSOLE_URL / G8R_API_KEY environment variables instead.
 *     consoleUrl: 'https://shield.yourcompany.com',
 *     apiKey: 'sk-shield-...',
 *     tenantId: tenantId('acme-corp'),
 *     department: 'Finance',   // optional — defaults to 'General'
 *     userId: 'usr_FIN_042',   // optional — defaults to 'unknown'
 *     aiModel: 'GPT-4o',       // optional — defaults to 'unknown'
 *   });
 *
 *   // Wrap any LLM call — the factory function is only invoked if the policy allows it
 *   const result = await shield.wrap(
 *     () => openai.chat.completions.create({
 *       model: 'gpt-4o',
 *       messages: [{ role: 'user', content: 'Summarize Q1 earnings' }],
 *     }),
 *     'Summarize Q1 earnings'
 *   );
 */

import { match } from 'ts-pattern';
import { newRequestId, type RequestId, type TenantId } from './ids';
import { log } from './logger';
import { redactSensitiveData } from './redaction';

// ── Public API re-exports ────────────────────────────────────────────────────
// Consumers need `tenantId()` to construct the branded TenantId required by
// ShieldConfig, and `redactSensitiveData` is documented as a public helper.
export { tenantId, newRequestId } from './ids';
export type { TenantId, RequestId } from './ids';
export { redactSensitiveData } from './redaction';
export type { RedactionResult } from './redaction';

/**
 * SDK version. Kept in lockstep with `package.json` and with the Python SDK's
 * `__version__` so "are these two in parity?" is answerable by a version-equality
 * check in CI. Bump both together.
 */
export const VERSION = '0.2.0';

/**
 * User-Agent identifying this SDK (language + version) to the Console on every
 * request. Lets the server distinguish python-vs-ts callers without polluting
 * customer-controlled fields like `agentId`. Mirrors the Python SDK's
 * `g8r-shield-python/{version}`.
 */
const SDK_USER_AGENT = `g8r-shield-typescript/${VERSION}`;

/**
 * Single-retry backoff (ms) for transient network errors on /check. Kept short
 * so it adds no user-visible latency on the happy path or on hard failures.
 */
const RETRY_BACKOFF_MS = 500;

/** Environment variable fallbacks for deployment config (12-factor). */
const ENV_CONSOLE_URL = 'G8R_CONSOLE_URL';
const ENV_API_KEY = 'G8R_API_KEY';

// ── Field defaults ────────────────────────────────────────────────────────────
// Defaulted-not-required fields. Attribution labels that degrade an audit trail
// when missing but never open a security hole — kept optional for adoption
// ergonomics, matching the Python SDK's construction-time defaults.
const DEFAULT_DEPARTMENT = 'General';
const DEFAULT_USER_ID = 'unknown';
const DEFAULT_AI_MODEL = 'unknown';
const DEFAULT_AGENT_ID = 'sdk-client';
const DEFAULT_TIMEOUT_SECONDS = 10.0;

export interface ShieldConfig {
  /**
   * Base URL of the deployed G8R Console. Optional at the type level, but
   * effectively required: resolved from this field OR the `G8R_CONSOLE_URL`
   * env var. If neither is present the constructor throws. Never defaults to
   * localhost — an SDK that ships prompts + API keys must fail closed rather
   * than silently exfiltrate to 127.0.0.1. A trailing slash is stripped.
   */
  consoleUrl?: string;
  /**
   * Bearer token for /api/sdk/v1/check and /log. Optional at the type level,
   * but effectively required: resolved from this field OR the `G8R_API_KEY`
   * env var. If neither yields a non-empty value the constructor throws. Never
   * included in toString()/logs.
   */
  apiKey?: string;
  /** Tenant this SDK instance operates on behalf of. The one hard-required field. */
  tenantId: TenantId;
  /** Optional: functional department for governance attribution (defaults to "General"). */
  department?: string;
  /** Optional: identifier of the end-user initiating the action (defaults to "unknown"). */
  userId?: string;
  /** Optional: model identifier being called (defaults to "unknown"). */
  aiModel?: string;
  /** Optional: agent identifier (defaults to "sdk-client"). */
  agentId?: string;
  /** Optional: employee display name for the audit trail (falls back to userId at /log time). */
  employeeName?: string;
  /** Optional: HTTP request timeout in seconds applied to both /check and /log (defaults to 10). */
  timeout?: number;
  /**
   * Optional: when true, wrap() throws ShieldBlockedError on an 'escalated'
   * decision instead of proceeding with a warning (defaults to false — escalated
   * actions proceed pending out-of-band human review).
   */
  blockOnEscalated?: boolean;
}

export interface PolicyCheckResult {
  decision: 'allowed' | 'blocked' | 'escalated';
  reason: string;
  violatedRule: string | null;
  requiresApproval: boolean;
  /**
   * Set to true when a kill-switch policy fires. Consumers should tear down
   * the agent session in response.
   */
  sessionRevoked?: boolean;
  complianceMappings: Array<{
    regulation: string;
    controlId: string;
    controlName: string;
    description: string;
  }>;
  /**
   * Tokens that were redacted from the prompt before it reached the gateway.
   * Undefined when no tokens were redacted (clean prompt).
   * Populated by the local-first redaction layer.
   */
  redactedTokens?: string[];
}

export interface ShieldLogEntry {
  id: string;
  decision: string;
  timestamp: string;
}

/** Options for {@link AgentShield.check}. */
export interface CheckOptions {
  /**
   * Explicit request id to correlate /check and /log. When omitted, a fresh id
   * is minted per call. wrap() passes its own id so the whole invocation shares
   * one correlation id end-to-end.
   */
  requestId?: RequestId;
  /**
   * Whether to also record this evaluation in the audit trail. Default true, so
   * standalone check() calls are self-auditing. Pass false if you will follow up
   * with wrap() for the same prompt — wrap() logs internally and a second log
   * here would duplicate the audit entry.
   */
  log?: boolean;
}

export class AgentShield {
  private readonly consoleUrl: string;
  private readonly apiKey: string;
  private readonly tenantId: TenantId;
  private readonly department: string;
  private readonly userId: string;
  private readonly aiModel: string;
  private readonly agentId: string;
  private readonly employeeName?: string;
  private readonly timeoutMs: number;
  private readonly blockOnEscalated: boolean;

  constructor(config: ShieldConfig) {
    if (!config.tenantId) {
      throw new Error('tenantId is required');
    }

    // Resolve deployment config from arg-or-env. Fail closed if unresolvable —
    // never fall back to localhost, which would silently exfiltrate customer
    // prompts + API keys to whatever is bound on 127.0.0.1 in the runtime.
    const resolvedUrl = config.consoleUrl || readEnv(ENV_CONSOLE_URL);
    if (!resolvedUrl) {
      throw new Error(
        `consoleUrl is required. Pass consoleUrl or set the ${ENV_CONSOLE_URL} env var. ` +
          'An SDK that ships customer prompts and API keys must never default to localhost.'
      );
    }

    const resolvedKey = config.apiKey || readEnv(ENV_API_KEY);
    if (!resolvedKey) {
      throw new Error(
        `apiKey is required. Pass apiKey or set the ${ENV_API_KEY} env var.`
      );
    }

    // Store all fields (with defaults applied) as write-once instance state.
    // The instance holds no mutable state and is safe to share across loops.
    this.consoleUrl = resolvedUrl.replace(/\/+$/, ''); // strip trailing slash(es)
    this.apiKey = resolvedKey;
    this.tenantId = config.tenantId;
    this.department = config.department ?? DEFAULT_DEPARTMENT;
    this.userId = config.userId ?? DEFAULT_USER_ID;
    this.aiModel = config.aiModel ?? DEFAULT_AI_MODEL;
    // Normalize agentId to a construction-time value so BOTH /check and /log
    // always send the same agentId (no inline '?? sdk-client' per call site).
    this.agentId = config.agentId ?? DEFAULT_AGENT_ID;
    this.employeeName = config.employeeName;
    this.timeoutMs = (config.timeout ?? DEFAULT_TIMEOUT_SECONDS) * 1000;
    this.blockOnEscalated = config.blockOnEscalated ?? false;
  }

  /**
   * Custom toString() that never exposes the api_key. tenantId is not secret;
   * include it for operational clarity.
   */
  toString(): string {
    return (
      `AgentShield(consoleUrl=${JSON.stringify(this.consoleUrl)}, ` +
      `tenantId=${JSON.stringify(this.tenantId)}, ` +
      `agentId=${JSON.stringify(this.agentId)}, department=${JSON.stringify(this.department)})`
    );
  }

  /**
   * Check a prompt against the policy engine before sending to the LLM.
   *
   * Applies best-effort local-first redaction before sending to the gateway, so
   * recognized signing keys, custodial IDs, common PII, and high-entropy secrets
   * are stripped before the prompt leaves the process. Redaction is one layer of
   * defense, not a guarantee that every secret is caught (see redaction.ts).
   *
   * Returns the policy decision without executing the LLM call. NEVER raises on a
   * blocked/escalated decision — it returns the decision for the caller to act on.
   *
   * By default this ALSO logs the evaluation to /log with the same requestId, so
   * standalone check() calls are self-auditing. Callers who will immediately call
   * wrap() for the same prompt should pass `{ log: false }` to avoid a duplicate
   * audit entry.
   */
  async check(prompt: string, opts: CheckOptions = {}): Promise<PolicyCheckResult> {
    // `requestId` is minted per-call by default, but wrap() passes its own value
    // so /check and /log share a single correlation id end-to-end.
    const requestId = opts.requestId ?? newRequestId();
    const shouldLog = opts.log ?? true;

    const result = await this.evaluate(prompt, requestId);

    if (shouldLog) {
      await this.log(prompt, result, requestId);
    }

    return result;
  }

  /**
   * Wrap an LLM call with policy enforcement.
   *
   * The `llmCallFactory` is a function that creates the LLM promise. It is only
   * invoked if the policy engine allows the action, preventing the LLM call from
   * executing before the policy check completes.
   *
   * @param llmCallFactory - A function that returns the LLM call promise
   * @param prompt - The prompt text to evaluate against the policy engine
   * @returns The result of the LLM call if allowed
   * @throws ShieldBlockedError if the policy engine blocks the action (or escalates
   *   it while blockOnEscalated is true)
   *
   * @example
   *   const result = await shield.wrap(
   *     () => openai.chat.completions.create({
   *       model: 'gpt-4o',
   *       messages: [{ role: 'user', content: prompt }],
   *     }),
   *     prompt
   *   );
   */
  async wrap<T>(llmCallFactory: () => Promise<T>, prompt: string): Promise<T> {
    // Mint ONE request_id for the whole invocation and thread it through both
    // /check and /log so the two server-side log lines can be joined end-to-end.
    const requestId = newRequestId();

    // Step 1: Check the prompt against the policy engine (includes redaction).
    // Suppress check()'s own logging — we log once explicitly below with the same
    // requestId so blocked attempts are still recorded without a duplicate entry.
    const policyResult = await this.check(prompt, { requestId, log: false });

    // Step 2: Log the attempt regardless of decision, BEFORE enforcement, so even
    // blocked attempts land in the audit trail. log() redacts before transmitting.
    await this.log(prompt, policyResult, requestId);

    // Step 3: Enforce the decision. Exhaustive match — adding a fourth decision
    // value will fail TypeScript compilation here until handled (fail-closed).
    match(policyResult.decision)
      .with('blocked', () => {
        if (policyResult.sessionRevoked) {
          log.warn('session_revoked', {
            tenant_id: this.tenantId,
            agent_id: this.agentId,
            reason: policyResult.reason,
          });
        }
        throw new ShieldBlockedError(
          policyResult.decision,
          policyResult.reason,
          policyResult.violatedRule,
          policyResult.complianceMappings,
          policyResult.sessionRevoked ?? false
        );
      })
      .with('escalated', () => {
        if (this.blockOnEscalated) {
          // Strict mode — treat escalated like blocked. Caller opted in at
          // construction time.
          throw new ShieldBlockedError(
            policyResult.decision,
            policyResult.reason,
            policyResult.violatedRule,
            policyResult.complianceMappings,
            policyResult.sessionRevoked ?? false
          );
        }
        log.warn('action_escalated', {
          tenant_id: this.tenantId,
          agent_id: this.agentId,
          reason: policyResult.reason,
        });
      })
      .with('allowed', () => {
        /* fall through to invoke the LLM */
      })
      .exhaustive();

    // Step 4: Only now invoke the LLM call — after the policy check passed.
    return llmCallFactory();
  }

  // ── Internal ────────────────────────────────────────────────────────────────

  /**
   * POST the redacted prompt + governance fields to /api/sdk/v1/check and parse
   * the decision. Retries exactly once on a transient connection/timeout error
   * after a short backoff, then raises ShieldConnectionError. Non-2xx responses
   * raise ShieldConsoleError, whose message never carries the raw body.
   */
  private async evaluate(prompt: string, requestId: RequestId): Promise<PolicyCheckResult> {
    // Step 1: Local-first redaction — strip recognized secrets and PII before
    // the prompt reaches the remote gateway.
    const { redacted, tokensReplaced } = redactSensitiveData(prompt);

    const scopedLog = log.child({
      tenant_id: this.tenantId,
      request_id: requestId,
    });

    const url = `${this.consoleUrl}/api/sdk/v1/check`;
    const body = JSON.stringify({
      input: redacted, // send the redacted version — never the raw prompt
      tenantId: this.tenantId,
      requestId,
      department: this.department,
      userId: this.userId,
      aiModel: this.aiModel,
      agentId: this.agentId, // construction-time value — same on /check and /log
    });

    // Single retry on transient network failures (connection refused / timeout).
    // Hard failures (non-2xx HTTP responses) are surfaced immediately — retrying
    // those just doubles user-visible latency.
    let res: Response | undefined;
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        res = await fetch(url, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${this.apiKey}`,
            'User-Agent': SDK_USER_AGENT,
          },
          body,
          signal: AbortSignal.timeout(this.timeoutMs),
        });
        break;
      } catch (err) {
        // fetch rejects only on network-level failures (DNS, connection refused,
        // abort/timeout) — never on a non-2xx status. Treat all of these as
        // transient and retry once.
        if (attempt === 0) {
          await delay(RETRY_BACKOFF_MS);
          continue;
        }
        scopedLog.error('Console unreachable', { url: this.consoleUrl });
        throw new ShieldConnectionError(this.consoleUrl, err);
      }
    }

    // Unreachable in practice (loop either breaks with `res` set or throws), but
    // keeps the type checker honest.
    if (!res) {
      throw new ShieldConnectionError(this.consoleUrl);
    }

    if (!res.ok) {
      scopedLog.error('Shield policy check failed', { status: res.status });
      // Preserve the raw body on `.detail` for opt-in inspection, but keep it
      // out of the exception message (see ShieldConsoleError rationale).
      const detail = await safeReadText(res);
      throw new ShieldConsoleError(res.status, detail);
    }

    const data = await res.json();
    return {
      decision: data.decision,
      reason: data.reason,
      violatedRule: data.violatedRule ?? null,
      requiresApproval: data.requiresApproval ?? false,
      ...(data.sessionRevoked !== undefined ? { sessionRevoked: data.sessionRevoked } : {}),
      complianceMappings: data.complianceMappings ?? [],
      ...(tokensReplaced.length > 0 ? { redactedTokens: tokensReplaced } : {}),
    };
  }

  /**
   * Log an interaction to /api/sdk/v1/log.
   *
   * Redacts the prompt before transmitting: the audit trail must not store or
   * carry raw secrets/PII, and this is an egress point just like /check.
   *
   * Failures are logged and swallowed (returns null) — a logging outage must
   * NEVER break the user's LLM call or mask the decision path.
   */
  private async log(
    input: string,
    result: PolicyCheckResult,
    requestId?: RequestId
  ): Promise<ShieldLogEntry | null> {
    const id = requestId ?? newRequestId();
    const scopedLog = log.child({
      tenant_id: this.tenantId,
      request_id: id,
    });

    // Redact at the egress boundary — never send the raw prompt to /log.
    const { redacted } = redactSensitiveData(input);

    try {
      const res = await fetch(`${this.consoleUrl}/api/sdk/v1/log`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${this.apiKey}`,
          'User-Agent': SDK_USER_AGENT,
        },
        body: JSON.stringify({
          input: redacted,
          tenantId: this.tenantId,
          requestId: id,
          userId: this.userId,
          department: this.department,
          aiModel: this.aiModel,
          agentId: this.agentId, // construction-time value
          employeeName: this.employeeName ?? this.userId,
          decision: result.decision,
          reason: result.reason,
          violatedRule: result.violatedRule,
          requiresApproval: result.requiresApproval,
          complianceMappings: result.complianceMappings,
        }),
        signal: AbortSignal.timeout(this.timeoutMs),
      });

      if (!res.ok) {
        // Swallow non-2xx — logging must never break the decision path.
        scopedLog.error('Failed to log interaction', { status: res.status });
        return null;
      }

      return (await res.json()) as ShieldLogEntry;
    } catch (err) {
      // Catch broadly — network errors, timeouts, JSON parse failures. Logging
      // must never interrupt the caller's LLM call.
      scopedLog.error('log_failed', { error: String(err) });
      return null;
    }
  }
}

/**
 * Error thrown by wrap() when the policy engine blocks an LLM call (or escalates
 * it while blockOnEscalated is true). This is the one error a normal caller catches.
 */
export class ShieldBlockedError extends Error {
  public readonly decision: string;
  public readonly reason: string;
  public readonly violatedRule: string | null;
  public readonly complianceMappings: PolicyCheckResult['complianceMappings'];
  public readonly sessionRevoked: boolean;

  constructor(
    decision: string,
    reason: string,
    violatedRule: string | null,
    complianceMappings: PolicyCheckResult['complianceMappings'],
    sessionRevoked: boolean = false
  ) {
    super(`[G8R Shield BLOCKED] ${reason}`);
    this.name = 'ShieldBlockedError';
    this.decision = decision;
    this.reason = reason;
    this.violatedRule = violatedRule;
    this.complianceMappings = complianceMappings;
    this.sessionRevoked = sessionRevoked;
    // Restore prototype chain for `instanceof` after transpilation to ES targets
    // that don't preserve it across `extends Error`.
    Object.setPrototypeOf(this, ShieldBlockedError.prototype);
  }
}

/**
 * Error thrown on a non-2xx HTTP response from /check.
 *
 * The message exposes ONLY the safe, status-code-level string
 * `[G8R Shield] Console returned HTTP {status}`. The raw response body is
 * preserved on `.detail` for OPT-IN inspection but never appears in the message,
 * guarding against host frameworks echoing internal stack traces / auth payloads
 * / PII to end users.
 */
export class ShieldConsoleError extends Error {
  public readonly statusCode: number;
  public readonly detail: string;

  constructor(statusCode: number, detail: string = '') {
    super(`[G8R Shield] Console returned HTTP ${statusCode}`);
    this.name = 'ShieldConsoleError';
    this.statusCode = statusCode;
    this.detail = detail;
    Object.setPrototypeOf(this, ShieldConsoleError.prototype);
  }
}

/**
 * Error thrown when the Console is unreachable after the single retry
 * (connection refused / timeout). Names the console URL and that a retry was
 * attempted, but carries no response body. Lets callers distinguish
 * "server said no" (ShieldConsoleError) from "couldn't reach server".
 */
export class ShieldConnectionError extends Error {
  public readonly consoleUrl: string;
  public readonly cause?: unknown;

  constructor(consoleUrl: string, cause?: unknown) {
    super(
      `[G8R Shield] Could not connect to console at ${consoleUrl} after retry. Is the console running?`
    );
    this.name = 'ShieldConnectionError';
    this.consoleUrl = consoleUrl;
    this.cause = cause;
    Object.setPrototypeOf(this, ShieldConnectionError.prototype);
  }
}

// ── Helpers ────────────────────────────────────────────────────────────────────

/** Read an environment variable, tolerating environments without `process`. */
function readEnv(name: string): string | undefined {
  if (typeof process !== 'undefined' && process.env) {
    const v = process.env[name];
    return v && v.length > 0 ? v : undefined;
  }
  return undefined;
}

/** Promise-based delay used for the single-retry backoff. */
function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** Read a response body as text, never throwing (best-effort detail capture). */
async function safeReadText(res: Response): Promise<string> {
  try {
    return await res.text();
  } catch {
    return '';
  }
}
