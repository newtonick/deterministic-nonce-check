/**
 * Randomness source.
 *
 * The browser uses `crypto.getRandomValues`. The test harness uses a seeded
 * stream instead, so a failing case can be reproduced exactly from its `--seed`
 * rather than being lost the moment the process exits.
 *
 * The seeded stream is for test reproducibility only — never for generating a
 * seed a user might rely on.
 */
import { sha256 } from '@noble/hashes/sha256';

export interface Rng {
  /** n uniformly random bytes. */
  bytes(n: number): Uint8Array;
  /** Uniform integer in [0, maxExclusive). */
  int(maxExclusive: number): number;
  /** Uniform integer in [min, max], inclusive both ends. */
  range(min: number, max: number): number;
  /** Uniformly chosen element. */
  pick<T>(items: readonly T[]): T;
  /** True with the given probability. */
  chance(probability: number): boolean;
}

function makeRng(bytes: (n: number) => Uint8Array): Rng {
  const rng: Rng = {
    bytes,
    int(maxExclusive: number): number {
      if (!Number.isInteger(maxExclusive) || maxExclusive <= 0) {
        throw new Error(`maxExclusive must be a positive integer, got ${maxExclusive}`);
      }
      if (maxExclusive === 1) return 0;
      // Rejection sampling. Taking a modulus directly would bias low values,
      // which would quietly skew the generated test cases.
      const limit = Math.floor(0x100000000 / maxExclusive) * maxExclusive;
      for (;;) {
        const b = bytes(4);
        const v = ((b[0] << 24) >>> 0) + (b[1] << 16) + (b[2] << 8) + b[3];
        if (v < limit) return v % maxExclusive;
      }
    },
    range(min: number, max: number): number {
      return min + rng.int(max - min + 1);
    },
    pick<T>(items: readonly T[]): T {
      if (items.length === 0) throw new Error('cannot pick from an empty list');
      return items[rng.int(items.length)];
    },
    chance(probability: number): boolean {
      return rng.int(1_000_000) < Math.round(probability * 1_000_000);
    },
  };
  return rng;
}

/** Cryptographically secure randomness. This is what the site itself uses. */
export function cryptoRng(): Rng {
  return makeRng((n) => {
    const out = new Uint8Array(n);
    crypto.getRandomValues(out);
    return out;
  });
}

/**
 * Deterministic stream from a seed string: sha256(seed || counter), chunked.
 * Test-only.
 */
export function seededRng(seed: string): Rng {
  const seedBytes = new TextEncoder().encode(seed);
  let counter = 0;
  let buffer = new Uint8Array(0);

  return makeRng((n) => {
    while (buffer.length < n) {
      const block = new Uint8Array(seedBytes.length + 4);
      block.set(seedBytes, 0);
      const view = new DataView(block.buffer);
      view.setUint32(seedBytes.length, counter++, false);
      const digest = sha256(block);
      const grown = new Uint8Array(buffer.length + digest.length);
      grown.set(buffer, 0);
      grown.set(digest, buffer.length);
      buffer = grown;
    }
    const out = buffer.slice(0, n);
    buffer = buffer.slice(n);
    return out;
  });
}
