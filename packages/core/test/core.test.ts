import { describe, expect, it } from 'vitest';
import { bucketHash, checkBinding, isPattern, matches, parseRef, select, type Binding } from '@appport/resolver-core';

describe('reference names', () => {
  it('accepts ref://namespace/name and rejects everything else', () => {
    expect(parseRef('ref://prod/chat/model').ok).toBe(true);
    for (const bad of ['prod/chat', 'ref://prod', 'ref://Prod/chat', 'ref://prod//x', 'ref://prod/a b', 'ref://prod/-x', 42, `ref://p/${'a'.repeat(300)}`]) {
      expect(parseRef(bad).ok, String(bad)).toBe(false);
    }
  });

  it('matches grant patterns by exact name or by prefix', () => {
    expect(matches('ref://prod/payments/endpoint', 'ref://prod/payments/*')).toBe(true);
    expect(matches('ref://prod/payments-legacy/x', 'ref://prod/payments/*')).toBe(false);
    expect(matches('ref://prod/a', 'ref://prod/a')).toBe(true);
    expect(matches('ref://staging/a', 'ref://prod/*')).toBe(false);
    expect(matches('ref://anything/x', '*')).toBe(true);
    expect(isPattern('ref://prod/*') && isPattern('*') && isPattern('ref://prod/a')).toBe(true);
    expect(isPattern('prod/*')).toBe(false);
  });
});

describe('bindings', () => {
  it('validates targets against the kind', () => {
    expect(checkBinding('model', { value: { provider: 'openai', model: 'gpt-x' } }).ok).toBe(true);
    expect(checkBinding('model', { value: { provider: 'openai' } }).ok).toBe(false);
    expect(checkBinding('model', { value: { provider: 'openai', model: 'm', options: { apiKey: 'sk-1' } } }).ok).toBe(false);
    expect(checkBinding('endpoint', { value: { url: 'https://api.example.com/v1' } }).ok).toBe(true);
    expect(checkBinding('endpoint', { value: { url: 'javascript:alert(1)' } }).ok).toBe(false);
    expect(checkBinding('endpoint', { value: { url: 'https://u:p@example.com' } }).ok).toBe(false);
    expect(checkBinding('endpoint', { value: { url: 'https://x.example', headers: { Authorization: 'Bearer x' } } }).ok).toBe(false);
    expect(checkBinding('agent', { value: { origin: 'https://claims.example.com' } }).ok).toBe(true);
    expect(checkBinding('agent', { value: { origin: 'http://claims.example.com' } }).ok).toBe(false);
    expect(checkBinding('agent', { value: { origin: 'https://claims.example.com/path' } }).ok).toBe(false);
    expect(checkBinding('agent', { value: { origin: 'https://a.example', capabilities: { 'claims.review@1': 'sha256:abc' } } }).ok).toBe(false);
    expect(checkBinding('secret', { value: 'sk-123' }).ok).toBe(false);
    expect(checkBinding('value', { value: { anything: [1, 'two'] } }).ok).toBe(true);
  });

  it('validates strategies and weights', () => {
    expect(checkBinding('value', { strategy: 'weighted', targets: [{ value: 1, weight: 90 }, { value: 2, weight: 10 }] }).ok).toBe(true);
    expect(checkBinding('value', { strategy: 'weighted', targets: [{ value: 1, weight: 0 }] }).ok).toBe(false);
    expect(checkBinding('value', { strategy: 'weighted', targets: [{ value: 1, weight: 1.5 }] }).ok).toBe(false);
    expect(checkBinding('value', { strategy: 'single', targets: [{ value: 1 }, { value: 2 }] }).ok).toBe(false);
    expect(checkBinding('value', { strategy: 'failover', targets: [{ value: 1 }, { value: 2 }] }).ok).toBe(true);
    expect(checkBinding('value', { value: 1, targets: [] }).ok).toBe(false);
    expect(checkBinding('value', { strategy: 'other', targets: [{ value: 1 }] }).ok).toBe(false);
  });
});

describe('steering', () => {
  const split: Binding<string> = {
    strategy: 'weighted',
    targets: [
      { value: 'stable', weight: 90, label: 'stable' },
      { value: 'canary', weight: 10, label: 'canary' },
    ],
  };

  it('is sticky: the same key always lands on the same target', () => {
    for (let i = 0; i < 50; i++) {
      const a = select(split, { ref: 'ref://prod/chat/model', key: `user-${i}` });
      const b = select(split, { ref: 'ref://prod/chat/model', key: `user-${i}` });
      expect(a.value).toBe(b.value);
    }
  });

  it('splits traffic close to the weights', () => {
    let canary = 0;
    const n = 20000;
    for (let i = 0; i < n; i++) if (select(split, { ref: 'ref://prod/chat/model', key: `u${i}` }).value === 'canary') canary += 1;
    expect(canary / n).toBeGreaterThan(0.085);
    expect(canary / n).toBeLessThan(0.115);
  });

  it('gives a failover order: the selection first, then the others by weight', () => {
    const s = select(split, { ref: 'r', random: () => 0.95 });
    expect(s.value).toBe('canary');
    expect(s.order.map((t) => t.value)).toEqual(['canary', 'stable']);
    const f = select<string>({ strategy: 'failover', targets: [{ value: 'a' }, { value: 'b' }, { value: 'c' }] }, { ref: 'r' });
    expect(f.value).toBe('a');
    expect(f.order.map((t) => t.value)).toEqual(['a', 'b', 'c']);
  });

  it('never selects a zero-weight target', () => {
    const drained: Binding<string> = { strategy: 'weighted', targets: [{ value: 'old', weight: 0 }, { value: 'new', weight: 1 }] };
    for (let i = 0; i < 200; i++) expect(select(drained, { ref: 'r', key: String(i) }).value).toBe('new');
  });

  it('hashes identically everywhere (pinned values)', () => {
    expect(bucketHash('')).toBe(0x811c9dc5);
    expect(bucketHash('a')).toBe(0xe40c292c);
  });
});
