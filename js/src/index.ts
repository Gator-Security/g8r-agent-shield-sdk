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
 *     consoleUrl: 'https://shield.yourcompany.com',
 *     apiKey: 'sk-shield-...',
 *     tenantId: tenantId('acme-corp'),
 *     department: 'Finance',
 *     userId: 'usr_FIN_042',
 *     aiModel: 'GPT-4o',
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

export interface ShieldConfig {
  /** URL of the G8R Agent Shield Console */
  consoleUrl: string;
  /** API key for authentication */
  apiKey: string;
  /** Tenant this SDK instance operates on behalf of. Required. */
  tenantId: TenantId;
  /** Department of the calling user */
  department: string;
  /** User identifier */
  userId: string;
  /** AI model being called */
  aiModel: string;
  /** Optional: agent identifier (defaults to "sdk-client") */
  agentId?: string;
  /** Optional: employee display name (defaults to userId) */
  employeeName?: string;
}

export interface PolicyCheckResult {
  decision: 'allowed' | 'blocked' | 'escalated';
  reason: string;
  violatedRule: string | null;
  requiresApproval: boolean;
  /**
   * Set to true when a kill-switch rule fires (e.g. unauthorized partner data
   * access). Consumers should tear down the agent session in response.
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

export class AgentShield {
  private config: ShieldConfig;

  constructor(config: ShieldConfig) {
    this.config = config;
  }

  /**
   * Check a prompt against the policy engine before sending to the LLM.
   *
   * Applies best-effort local-first redaction before sending to the gateway, so
   * recognized signing keys, custodial IDs, common PII, and high-entropy secrets
   * are stripped before the prompt leaves the process. Redaction is one layer of
   * defense, not a guarantee that every secret is caught (see redaction.ts).
   *
   * Returns the policy decision without executing the LLM call.
   */
  async check(
    prompt: string,
    requestId: RequestId = newRequestId()
  ): Promise<PolicyCheckResult> {
    // Step 1: Local-first redaction — strip recognized secrets and PII
    // before the prompt reaches the remote gateway.
    const { redacted, tokensReplaced } = redactSensitiveData(prompt);

    // `requestId` is generated per-call by default, but `wrap()` passes its
    // own value so /check and /log share a single correlation id end-to-end
    // (C2). Build a scoped logger bound to tenantId + requestId so any
    // failure path emits lines with that context automatically.
    const scopedLog = log.child({
      tenant_id: this.config.tenantId,
      request_id: requestId,
    });

    const res = await fetch(`${this.config.consoleUrl}/api/sdk/v1/check`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${this.config.apiKey}`,
      },
      body: JSON.stringify({
        input: redacted, // send the redacted version — never the raw prompt
        tenantId: this.config.tenantId,
        requestId,
        userId: this.config.userId,
        department: this.config.department,
        aiModel: this.config.aiModel,
        agentId: this.config.agentId ?? 'sdk-client',
      }),
    });

    if (!res.ok) {
      scopedLog.error('Shield policy check failed', { status: res.status });
      throw new Error(`Shield policy check failed: ${res.status}`);
    }

    const result = await res.json();
    return {
      ...result,
      ...(tokensReplaced.length > 0 ? { redactedTokens: tokensReplaced } : {}),
    };
  }

  /**
   * Wrap an LLM call with policy enforcement.
   *
   * The `llmCallFactory` is a function that creates the LLM promise.
   * It is only invoked if the policy engine allows the action.
   * This prevents the LLM call from executing before the policy check completes.
   *
   * @param llmCallFactory - A function that returns the LLM call promise
   * @param prompt - The prompt text to evaluate against the policy engine
   * @returns The result of the LLM call if allowed
   * @throws ShieldBlockedError if the policy engine blocks the action
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
    // Generate a single requestId for this wrap() invocation and thread it
    // through both /check and /log so the two server-side log lines can be
    // joined end-to-end (C2). Without this, each call would mint its own id
    // and the audit trail would lose the policy→action linkage.
    const requestId = newRequestId();

    // Step 1: Check the prompt against the policy engine (includes redaction)
    const policyResult = await this.check(prompt, requestId);

    // Step 2: Log the attempt regardless of decision. log() redacts before
    // transmitting, so the audit-log path never leaks raw secrets either.
    await this.log(prompt, policyResult, requestId);

    // Step 3: Enforce the decision. Exhaustive match — adding a fourth
    // decision value will fail TypeScript compilation here until handled.
    match(policyResult.decision)
      .with('blocked', () => {
        throw new ShieldBlockedError(
          policyResult.reason,
          policyResult.violatedRule,
          policyResult.complianceMappings,
          policyResult.sessionRevoked ?? false
        );
      })
      .with('escalated', () => {
        // In production, this would await human approval via webhook
        log.warn('Action escalated for human review', {
          reason: policyResult.reason,
        });
      })
      .with('allowed', () => {
        /* fall through to invoke the LLM */
      })
      .exhaustive();

    // Step 4: Only now invoke the LLM call — after policy check passed
    return llmCallFactory();
  }

  /**
   * Log an interaction to the Agent Shield Console.
   *
   * Redacts the prompt before transmitting: the audit trail must not store or
   * carry raw secrets/PII, and this is an egress point just like /check.
   */
  private async log(
    input: string,
    result: PolicyCheckResult,
    requestId: RequestId = newRequestId()
  ): Promise<ShieldLogEntry> {
    const scopedLog = log.child({
      tenant_id: this.config.tenantId,
      request_id: requestId,
    });

    // Redact at the egress boundary — never send the raw prompt to /log.
    const { redacted } = redactSensitiveData(input);

    const res = await fetch(`${this.config.consoleUrl}/api/sdk/v1/log`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${this.config.apiKey}`,
      },
      body: JSON.stringify({
        input: redacted,
        tenantId: this.config.tenantId,
        requestId,
        userId: this.config.userId,
        department: this.config.department,
        aiModel: this.config.aiModel,
        agentId: this.config.agentId ?? 'sdk-client',
        employeeName: this.config.employeeName ?? this.config.userId,
        decision: result.decision,
        reason: result.reason,
        violatedRule: result.violatedRule,
        requiresApproval: result.requiresApproval,
        complianceMappings: result.complianceMappings,
      }),
    });

    if (!res.ok) {
      scopedLog.error('Failed to log interaction', { status: res.status });
    }

    return res.json();
  }
}

/**
 * Error thrown when the policy engine blocks an LLM call.
 */
export class ShieldBlockedError extends Error {
  public readonly violatedRule: string | null;
  public readonly complianceMappings: PolicyCheckResult['complianceMappings'];
  public readonly sessionRevoked: boolean;

  constructor(
    reason: string,
    violatedRule: string | null,
    complianceMappings: PolicyCheckResult['complianceMappings'],
    sessionRevoked: boolean = false
  ) {
    super(`[G8R Shield BLOCKED] ${reason}`);
    this.name = 'ShieldBlockedError';
    this.violatedRule = violatedRule;
    this.complianceMappings = complianceMappings;
    this.sessionRevoked = sessionRevoked;
  }
}
