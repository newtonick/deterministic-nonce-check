/**
 * UR2 `crypto-psbt` transport.
 *
 * The payload of a `ur:crypto-psbt` is a plain CBOR byte string. The registry
 * defines crypto-psbt as `#6.310(bytes)`, but that tag is only written when the
 * item is embedded inside another structure — at the top level the UR type
 * string already identifies it, and every wallet in practice sends the bare
 * byte string. We emit untagged and accept either, because a decoder that
 * rejects the tagged form would fail against some devices for no good reason.
 */
// Explicit import: `Buffer` is a Node global but not a browser one, and
// bitcoinjs-lib's API is Buffer-based throughout.
import { Buffer } from 'buffer';
import { UR, UREncoder, URDecoder } from '@ngraveio/bc-ur';

/** CBOR tag 310, if a device chooses to write it. */
const TAG_CRYPTO_PSBT = [0xd9, 0x01, 0x36];

export const UR_TYPE = 'crypto-psbt';

/**
 * Bytes per fragment. Small enough that each frame stays a low-density QR the
 * device's camera can read quickly, large enough to keep the animation short.
 */
export const DEFAULT_FRAGMENT_LENGTH = 100;

function wrapAsCborBytes(payload: Uint8Array): Buffer {
  const len = payload.length;
  let header: number[];
  if (len < 24) header = [0x40 + len];
  else if (len < 0x100) header = [0x58, len];
  else if (len < 0x10000) header = [0x59, len >> 8, len & 0xff];
  else header = [0x5a, (len >>> 24) & 0xff, (len >>> 16) & 0xff, (len >>> 8) & 0xff, len & 0xff];
  return Buffer.concat([Buffer.from(header), Buffer.from(payload)]);
}

/**
 * Pull the raw bytes back out of a crypto-psbt CBOR payload.
 * Tolerates the optional #6.310 tag and every byte-string length encoding.
 */
export function unwrapCborBytes(cbor: Uint8Array): Uint8Array {
  let i = 0;
  if (
    cbor.length >= 3 &&
    cbor[0] === TAG_CRYPTO_PSBT[0] &&
    cbor[1] === TAG_CRYPTO_PSBT[1] &&
    cbor[2] === TAG_CRYPTO_PSBT[2]
  ) {
    i = 3;
  }

  const major = cbor[i];
  if (major === undefined) throw new Error('empty CBOR payload');
  if (major >= 0x40 && major <= 0x57) return cbor.slice(i + 1, i + 1 + (major - 0x40));
  if (major === 0x58) return cbor.slice(i + 2, i + 2 + cbor[i + 1]);
  if (major === 0x59) return cbor.slice(i + 3, i + 3 + ((cbor[i + 1] << 8) | cbor[i + 2]));
  if (major === 0x5a) {
    const len =
      cbor[i + 1] * 0x1000000 + (cbor[i + 2] << 16) + (cbor[i + 3] << 8) + cbor[i + 4];
    return cbor.slice(i + 5, i + 5 + len);
  }
  throw new Error(`expected a CBOR byte string, got major byte 0x${major.toString(16)}`);
}

export interface PsbtUrEncoder {
  /** Number of distinct fragments; 1 means the PSBT fits in a single QR. */
  totalParts: number;
  /**
   * Next frame to display.
   *
   * The first `totalParts` calls return the pure fragments. After that the
   * sequence never repeats: each frame is a fountain-coded XOR mix of several
   * fragments, so a scanner can finish from whatever subset it happens to
   * catch instead of waiting for one specific frame it keeps missing. This is
   * the same BC-UR scheme Sparrow uses for animated PSBTs.
   */
  next(): string;
}

/** Build an animated `ur:crypto-psbt` sequence for a base64 PSBT. */
export function createPsbtUrEncoder(
  psbtBase64: string,
  fragmentLength = DEFAULT_FRAGMENT_LENGTH,
): PsbtUrEncoder {
  const raw = Uint8Array.from(atob(psbtBase64), (c) => c.charCodeAt(0));
  const ur = new UR(wrapAsCborBytes(raw), UR_TYPE);
  const encoder = new UREncoder(ur, fragmentLength);
  return {
    totalParts: encoder.fragmentsLength,
    next: () => encoder.nextPart().toUpperCase(),
  };
}

export interface UrScanProgress {
  complete: boolean;
  /** 0..1, how much of the payload has been recovered. */
  progress: number;
  /** Distinct fragments seen so far. */
  received: number;
  expected: number;
  psbtBase64?: string;
  error?: string;
}

/**
 * Accumulates scanned frames until the PSBT is recoverable.
 *
 * A device set to emit base64 or Specter-style QRs instead of UR is a common
 * and confusing failure, so it is named explicitly rather than reported as an
 * unreadable code.
 */
export function createPsbtUrDecoder() {
  let decoder = new URDecoder();
  let received = 0;
  const seen = new Set<string>();

  return {
    reset() {
      decoder = new URDecoder();
      received = 0;
      seen.clear();
    },

    receive(text: string): UrScanProgress {
      const trimmed = text.trim();
      const lower = trimmed.toLowerCase();

      if (!lower.startsWith('ur:')) {
        const hint = trimmed.startsWith('cHNidP')
          ? 'That is a plain base64 PSBT. Set the device to output UR (ur:crypto-psbt) QR codes.'
          : /^p\d+of\d+ /i.test(trimmed)
            ? 'That is a Specter-style QR. Set the device to output UR (ur:crypto-psbt) QR codes.'
            : 'Not a UR QR code.';
        return { complete: false, progress: 0, received, expected: 0, error: hint };
      }

      if (!lower.startsWith(`ur:${UR_TYPE}/`)) {
        const type = lower.slice(3).split('/')[0];
        return {
          complete: false,
          progress: 0,
          received,
          expected: 0,
          error: `Expected a signed PSBT but got a "${type}" QR code.`,
        };
      }

      if (!seen.has(lower)) {
        seen.add(lower);
        decoder.receivePart(lower);
        received = seen.size;
      }

      if (!decoder.isComplete()) {
        return {
          complete: false,
          progress: decoder.estimatedPercentComplete(),
          received,
          expected: decoder.expectedPartCount(),
        };
      }

      if (!decoder.isSuccess()) {
        return {
          complete: false,
          progress: 0,
          received,
          expected: decoder.expectedPartCount(),
          error: decoder.resultError(),
        };
      }

      const bytes = unwrapCborBytes(new Uint8Array(decoder.resultUR().cbor));
      let binary = '';
      bytes.forEach((b) => (binary += String.fromCharCode(b)));
      return {
        complete: true,
        progress: 1,
        received,
        expected: decoder.expectedPartCount(),
        psbtBase64: btoa(binary),
      };
    },
  };
}
