/**
 * Branded id types + constructors used by the SDK.
 *
 * Self-contained in the SDK so the published `@g8r-security/agent-shield-sdk`
 * package has no dependency on internal packages. Only the id types/helpers the
 * SDK actually uses are included here.
 */

/**
 * Identifies a single tenant in the multi-tenant governance plane.
 * Branded so a raw string can't be passed where a TenantId is expected.
 */
export type TenantId = string & { readonly __brand: 'TenantId' };

/** Per-request correlation ID. Generated client-side by the SDK. */
export type RequestId = string & { readonly __brand: 'RequestId' };

const TENANT_ID_PATTERN = /^[a-z0-9][a-z0-9-]{0,63}$/;

/**
 * Cast a string to TenantId. Use at boundaries (config, env, request body).
 * Enforces the charset / length contract: 1-64 chars of `[a-z0-9-]`,
 * starting with `[a-z0-9]` — catches programmatic misuse (config typos,
 * hard-coded slugs that drift).
 */
export function tenantId(s: string): TenantId {
  if (!s) throw new Error('tenantId cannot be empty');
  if (!TENANT_ID_PATTERN.test(s)) {
    throw new Error(
      `tenantId must be 1-64 chars, [a-z0-9-], starting with [a-z0-9] (got ${JSON.stringify(s)})`
    );
  }
  return s as TenantId;
}

/** Generate a fresh request ID. Prefers crypto.randomUUID where available. */
export function newRequestId(): RequestId {
  // crypto.randomUUID is available in Node 19+ and all modern browsers.
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID() as RequestId;
  }
  // Fallback: timestamp + Math.random (best-effort, not crypto-strong).
  return `req-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}` as RequestId;
}
