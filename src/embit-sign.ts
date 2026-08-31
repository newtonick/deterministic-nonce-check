/**
 * embit-compatible ECDSA signing.
 *
 * This is the whole point of the project, so it is worth being precise about
 * what "deterministic" means here. embit does NOT use plain RFC6979. From
 * embit/src/embit/ec.py:
 *
 *     def sign(self, msg_hash, grind=True) -> Signature:
 *         sig = Signature(secp256k1.ecdsa_sign(msg_hash, self._secret))
 *         if grind:
 *             counter = 1
 *             while len(sig.serialize()) > 70:
 *                 sig = Signature(secp256k1.ecdsa_sign(
 *                     msg_hash, self._secret, None, counter.to_bytes(32, "little")))
 *                 counter += 1
 *                 if counter > 200:
 *                     break
 *         return sig
 *
 * It grinds for low-R: re-signing with a counter as extra entropy until the DER
 * encoding fits in 70 bytes (i.e. until r's high bit is clear and needs no 0x00
 * prefix). Roughly half of all sighashes need at least one grind iteration, so a
 * signer that stops after plain RFC6979 disagrees with embit about half the time.
 *
 * The nonce is reproducible in JS because the seed material lines up byte for
 * byte. libsecp256k1's default nonce function (secp256k1_nonce_function_rfc6979,
 * algo=NULL) seeds HMAC-DRBG with key32 || msg32 || data32, and @noble/curves
 * builds concatBytes(int2octets(d), int2octets(h1int), extraEntropy) — same
 * order, same lengths.
 */
// Explicit import: `Buffer` is a Node global but not a browser one, and
// bitcoinjs-lib's API is Buffer-based throughout.
import { Buffer } from 'buffer';
import { secp256k1 } from '@noble/curves/secp256k1';

/** embit's own guard against an infinite grind loop (ec.py). */
export const MAX_GRIND_COUNTER = 200;

/** DER length at which embit stops grinding. */
export const MAX_DER_LENGTH = 70;

export interface EmbitSignature {
  /** DER-encoded signature, no sighash byte appended. */
  der: Uint8Array;
  /** 64-byte r||s, which is what bitcoinjs-lib's Signer interface wants. */
  compact: Uint8Array;
  /**
   * How many grind iterations were needed. 0 means plain RFC6979 already
   * produced a low-R signature; >0 means extra entropy was mixed in.
   */
  grindCounter: number;
  /** Length of `der`. <= 70 unless the grind loop hit MAX_GRIND_COUNTER. */
  derLength: number;
  /** Whether r's high bit is clear, i.e. r encodes in 32 bytes or fewer. */
  lowR: boolean;
}

/**
 * embit's counter encoding: `counter.to_bytes(32, "little")`.
 *
 * Written out in full rather than using a DataView so the 32-byte width and the
 * little-endian order stay obvious — both matter, and both are easy to get
 * silently wrong.
 */
export function counterToExtraEntropy(counter: number): Uint8Array {
  if (!Number.isInteger(counter) || counter < 0) {
    throw new Error(`grind counter must be a non-negative integer, got ${counter}`);
  }
  const out = new Uint8Array(32);
  let n = counter;
  for (let i = 0; i < 32 && n > 0; i++) {
    out[i] = n & 0xff;
    n = Math.floor(n / 256);
  }
  return out;
}

/**
 * Sign a 32-byte hash exactly as embit's `PrivateKey.sign(msg_hash)` would.
 *
 * `grind` mirrors embit's keyword argument. It defaults to true because that is
 * embit's default and therefore what SeedSigner actually does; the false path
 * exists so tests can demonstrate the difference.
 */
export function signEmbit(
  msgHash: Uint8Array,
  privateKey: Uint8Array,
  grind = true,
): EmbitSignature {
  if (msgHash.length !== 32) {
    throw new Error(`message hash must be 32 bytes, got ${msgHash.length}`);
  }
  if (privateKey.length !== 32) {
    throw new Error(`private key must be 32 bytes, got ${privateKey.length}`);
  }

  // lowS matches libsecp256k1, which always normalises s to the lower half.
  // prehash stays off: the sighash is already a hash, we must not hash it again.
  let sig = secp256k1.sign(msgHash, privateKey, { lowS: true, prehash: false });
  let der = sig.toDERRawBytes();
  let counter = 0;

  if (grind) {
    let next = 1;
    while (der.length > MAX_DER_LENGTH && next <= MAX_GRIND_COUNTER) {
      sig = secp256k1.sign(msgHash, privateKey, {
        lowS: true,
        prehash: false,
        extraEntropy: counterToExtraEntropy(next),
      });
      der = sig.toDERRawBytes();
      counter = next;
      next++;
    }
  }

  return {
    der,
    compact: sig.toCompactRawBytes(),
    grindCounter: counter,
    derLength: der.length,
    lowR: der.length <= MAX_DER_LENGTH,
  };
}

/**
 * Adapt `signEmbit` to bitcoinjs-lib's `Signer` interface.
 *
 * bitcoinjs-lib computes the BIP143 sighash, hands it to `sign()`, and
 * DER-encodes whatever 64-byte compact signature comes back. That keeps the
 * sighash machinery inside reviewed library code and leaves only the nonce rule
 * to us — which is the one thing this project actually needs to own.
 *
 * The `lowR` argument bitcoinjs passes is deliberately ignored. bitcoinjs has
 * its own low-R grinding whose counter encoding happens to resemble embit's;
 * relying on that coincidence between two libraries would be a latent bug, so
 * embit's loop is always applied explicitly.
 */
export function createEmbitSigner(privateKey: Uint8Array, publicKey: Uint8Array) {
  const calls: EmbitSignature[] = [];
  return {
    publicKey: Buffer.from(publicKey),
    sign(hash: Buffer): Buffer {
      const result = signEmbit(new Uint8Array(hash), privateKey);
      calls.push(result);
      return Buffer.from(result.compact);
    },
    /** Diagnostics for the results card: grind counts, DER lengths, low-R. */
    get calls(): readonly EmbitSignature[] {
      return calls;
    },
  };
}
