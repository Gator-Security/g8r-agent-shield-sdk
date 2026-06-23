import { tenantId, newRequestId } from '../src/ids';

describe('tenantId', () => {
  it('accepts a valid slug', () => {
    expect(tenantId('acme-inc')).toBe('acme-inc');
  });

  it('rejects the empty string', () => {
    expect(() => tenantId('')).toThrow(/empty/);
  });

  it('rejects an out-of-charset slug', () => {
    expect(() => tenantId('Bad_Slug')).toThrow(/1-64 chars/);
  });
});

describe('newRequestId', () => {
  it('returns a non-empty string', () => {
    const id = newRequestId();
    expect(typeof id).toBe('string');
    expect(id.length).toBeGreaterThan(0);
  });

  it('returns a fresh id on each call', () => {
    expect(newRequestId()).not.toBe(newRequestId());
  });
});
