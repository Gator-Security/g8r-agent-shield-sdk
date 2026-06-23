/**
 * G8R structured JSON logger.
 *
 * Tiny, dependency-free logger that emits one JSON object per line. Designed
 * for governance contexts where each log line must carry `tenant_id` and
 * `request_id` so downstream pipelines can route audit trails per-tenant.
 *
 * Vendored into the SDK (a verbatim copy of the engine's logger) so the
 * published `@g8r-security/agent-shield-sdk` package carries no `@g8r-security/core`
 * dependency — the engine is private IP and must not be a public-package
 * dependency.
 *
 * Use the default `log` singleton for app-level chatter; call `createLogger`
 * (or `.child()`) when you need per-request bindings injected.
 */

export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

export interface LogContext {
  tenant_id?: string;
  request_id?: string;
  [key: string]: unknown;
}

export interface Logger {
  debug(msg: string, ctx?: LogContext): void;
  info(msg: string, ctx?: LogContext): void;
  warn(msg: string, ctx?: LogContext): void;
  error(msg: string, ctx?: LogContext): void;
  child(ctx: LogContext): Logger;
}

export interface LoggerOptions {
  /** Defaults to 'info'. Anything below is dropped. */
  level?: LogLevel;
  /** Defaults to console.log. Override for testing or transport injection. */
  sink?: (line: string) => void;
  /** Context merged into every log line. */
  bindings?: LogContext;
}

const LEVEL_ORDER: Record<LogLevel, number> = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40,
};

export function createLogger(opts: LoggerOptions = {}): Logger {
  const minLevel = LEVEL_ORDER[opts.level ?? 'info'];
  const sink = opts.sink ?? ((line: string) => console.log(line));
  const bindings = opts.bindings ?? {};

  function emit(level: LogLevel, msg: string, ctx?: LogContext): void {
    if (LEVEL_ORDER[level] < minLevel) return;
    const payload = {
      level,
      msg,
      ts: new Date().toISOString(),
      ...bindings,
      ...ctx,
    };
    sink(JSON.stringify(payload));
  }

  return {
    debug: (msg, ctx) => emit('debug', msg, ctx),
    info: (msg, ctx) => emit('info', msg, ctx),
    warn: (msg, ctx) => emit('warn', msg, ctx),
    error: (msg, ctx) => emit('error', msg, ctx),
    child: (extra) => createLogger({ ...opts, bindings: { ...bindings, ...extra } }),
  };
}

/** Default singleton — convenient for apps that don't need DI. */
export const log = createLogger();
