import { createLogger, log } from '../src/logger';

describe('logger', () => {
  it('emits one JSON line carrying level, msg, ts, and context', () => {
    const lines: string[] = [];
    const l = createLogger({ sink: (line) => lines.push(line) });
    l.info('hello', { request_id: 'r1' });
    expect(lines).toHaveLength(1);
    const parsed = JSON.parse(lines[0]);
    expect(parsed).toMatchObject({ level: 'info', msg: 'hello', request_id: 'r1' });
    expect(typeof parsed.ts).toBe('string');
  });

  it('drops levels below the configured minimum', () => {
    const lines: string[] = [];
    const l = createLogger({ level: 'warn', sink: (line) => lines.push(line) });
    l.debug('d');
    l.info('i');
    l.warn('w');
    l.error('e');
    expect(lines).toHaveLength(2); // warn + error only
  });

  it('child() merges bindings into every line', () => {
    const lines: string[] = [];
    const l = createLogger({ sink: (line) => lines.push(line) }).child({ tenant_id: 't1' });
    l.error('boom');
    expect(JSON.parse(lines[0]).tenant_id).toBe('t1');
  });

  it('exposes a default `log` singleton', () => {
    expect(typeof log.info).toBe('function');
    expect(typeof log.child).toBe('function');
  });
});
