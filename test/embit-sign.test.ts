import { describe, expect, it } from 'vitest';
import { sha256 } from '@noble/hashes/sha256';
import { secp256k1 } from '@noble/curves/secp256k1';
import { MAX_DER_LENGTH, counterToExtraEntropy, signEmbit } from '../src/embit-sign.js';

const priv = sha256(new TextEncoder().encode('embit-sign-test-key'));
const hashFor = (label: string) => sha256(new TextEncoder().encode(label));

describe('counterToExtraEntropy', () => {
  it('encodes as 32-byte little-endian, matching embit\'s to_bytes(32, "little")', () => {
    expect(Buffer.from(counterToExtraEntropy(1)).toString('hex')).toBe('01'.padEnd(64, '0'));
    // 258 == 0x0102, little-endian => 02 01 ...
    expect(Buffer.from(counterToExtraEntropy(258)).toString('hex')).toBe('0201'.padEnd(64, '0'));
    expect(counterToExtraEntropy(7)).toHaveLength(32);
  });

  it('rejects nonsense counters', () => {
    expect(() => counterToExtraEntropy(-1)).toThrow();
    expect(() => counterToExtraEntropy(1.5)).toThrow();
  });
});

describe('signEmbit', () => {
  it('always grinds down to a low-R signature', () => {
    for (let i = 0; i < 200; i++) {
      const sig = signEmbit(hashFor('grind' + i), priv);
      expect(sig.derLength).toBeLessThanOrEqual(MAX_DER_LENGTH);
      expect(sig.lowR).toBe(true);
    }
  });

  it('exercises grind counters of 0, 1, and 2+ rather than only the easy path', () => {
    const counters = new Set<number>();
    for (let i = 0; i < 400 && counters.size < 3; i++) {
      counters.add(Math.min(signEmbit(hashFor('spread' + i), priv).grindCounter, 2));
    }
    expect([...counters].sort()).toEqual([0, 1, 2]);
  });

  it('differs from plain RFC6979 about half the time, which is why grinding matters', () => {
    let differs = 0;
    const total = 200;
    for (let i = 0; i < total; i++) {
      const h = hashFor('cmp' + i);
      const ground = signEmbit(h, priv, true);
      const plain = signEmbit(h, priv, false);
      if (Buffer.from(ground.der).toString('hex') !== Buffer.from(plain.der).toString('hex')) {
        differs++;
      }
    }
    // Binomial around 50%; a wide band keeps this from being flaky.
    expect(differs).toBeGreaterThan(total * 0.3);
    expect(differs).toBeLessThan(total * 0.7);
  });

  it('is deterministic: the same input always gives the same signature', () => {
    const h = hashFor('stable');
    const a = signEmbit(h, priv);
    const b = signEmbit(h, priv);
    expect(Buffer.from(a.der).toString('hex')).toBe(Buffer.from(b.der).toString('hex'));
    expect(a.grindCounter).toBe(b.grindCounter);
  });

  it('produces signatures that verify', () => {
    const pub = secp256k1.getPublicKey(priv, true);
    for (let i = 0; i < 25; i++) {
      const h = hashFor('verify' + i);
      expect(secp256k1.verify(signEmbit(h, priv).compact, h, pub)).toBe(true);
    }
  });

  it('rejects wrongly sized inputs', () => {
    expect(() => signEmbit(new Uint8Array(31), priv)).toThrow(/32 bytes/);
    expect(() => signEmbit(new Uint8Array(32), new Uint8Array(31))).toThrow(/32 bytes/);
  });
});
