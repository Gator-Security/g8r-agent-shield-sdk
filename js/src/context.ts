/**
 * Ambient governance context — the session + parent-agent lineage that flows
 * IMPLICITLY through nested agent calls, so each hop is governed with chain
 * awareness and no manual instrumentation at every call site.
 *
 * Backed by Node's AsyncLocalStorage (node:async_hooks, stable since Node 16)
 * when it can be loaded, which gives TRUE per-async-chain isolation: two agent
 * runs executing concurrently never observe each other's lineage even while
 * their promises interleave on the same event loop.
 *
 * When AsyncLocalStorage cannot be loaded — a browser bundle, or any runtime
 * without node:async_hooks — the SDK degrades to a single module-level
 * variable. That fallback still propagates lineage through SYNCHRONOUS nesting
 * (the common case: a wrap() whose factory synchronously kicks off a nested
 * wrap()), and it always restores the prior value when the scope returns. What
 * it CANNOT do is isolate concurrent async chains: once fn() returns its
 * promise, later async continuations run with whatever the module-level
 * variable happens to hold, so two interleaved runs may read each other's
 * context. Governance still functions; only the cross-run isolation guarantee
 * is relaxed. Prefer a Node runtime (and the CommonJS entry, where a
 * synchronous require is available) for lineage-critical multi-tenant work.
 *
 * The load is intentionally NOT a static `import` of node:async_hooks: a static
 * import would make browser bundlers fail to resolve the module at build time,
 * whereas the guarded require below simply falls through to the fallback.
 */

// Type-only import — erased at compile time, so it never triggers a runtime
// module resolution (browser-safe). Supplies the AsyncLocalStorage type only.
import type { AsyncLocalStorage as AsyncLocalStorageInstance } from 'node:async_hooks';

/**
 * The ambient lineage carried through a logical agent run.
 *
 * `agentChain` is ROOT-first / immediate-parent-last, matching the wire
 * contract's `parentAgents` ordering exactly.
 */
export interface GovernanceContext {
  /** Stable id for a logical agent run; propagated across nested + multi-turn calls. */
  readonly sessionId?: string;
  /** Ancestor agent-id chain, ROOT-first, immediate-parent last. */
  readonly agentChain: string[];
}

/**
 * The single process-wide store. Undefined when node:async_hooks could not be
 * loaded, in which case {@link getGovernanceContext} / {@link
 * runWithGovernanceContext} use the module-level fallback below.
 */
const als: AsyncLocalStorageInstance<GovernanceContext> | undefined = createAls();

function createAls(): AsyncLocalStorageInstance<GovernanceContext> | undefined {
  try {
    // `require` exists in CommonJS builds and in the ts-jest / Node test
    // runtime. In a pure-ESM bundle (or a browser) it is undefined, so we fall
    // through to the module-level fallback rather than crashing.
    if (typeof require === 'function') {
      const mod = require('node:async_hooks') as typeof import('node:async_hooks');
      return new mod.AsyncLocalStorage<GovernanceContext>();
    }
  } catch {
    // node:async_hooks is unavailable in this environment — degrade gracefully.
  }
  return undefined;
}

/**
 * True when true async-isolated context is available (AsyncLocalStorage was
 * loaded). False when the SDK is running on the module-level fallback, which
 * does not isolate concurrent async chains — see the file header.
 */
export const asyncContextIsolated: boolean = als !== undefined;

// Module-level fallback for environments without AsyncLocalStorage. NOTE: this
// is process-global and is NOT async-isolated — see the file header.
let fallbackContext: GovernanceContext | undefined;

/** Read the lineage in scope for the current async chain (undefined at top level). */
export function getGovernanceContext(): GovernanceContext | undefined {
  return als ? als.getStore() : fallbackContext;
}

/**
 * Run `fn` with `context` established as the ambient lineage. With
 * AsyncLocalStorage the context propagates into every async continuation
 * spawned by `fn` and auto-restores when run() returns. On the fallback it is
 * set for the synchronous span of `fn` and restored in a `finally` (even if
 * `fn` throws), with the async-isolation caveat documented in the file header.
 */
export function runWithGovernanceContext<T>(context: GovernanceContext, fn: () => T): T {
  if (als) {
    return als.run(context, fn);
  }
  const previous = fallbackContext;
  fallbackContext = context;
  try {
    return fn();
  } finally {
    fallbackContext = previous;
  }
}
