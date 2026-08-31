import { describe, expect, it } from 'vitest';
import { createPsbtUrDecoder, createPsbtUrEncoder, unwrapCborBytes } from '../src/ur.js';
import { generateTest } from '../src/psbt.js';
import { seededRng } from '../src/rng.js';

describe('crypto-psbt UR transport', () => {
  it('round-trips a multi-frame PSBT, even out of order', () => {
    const test = generateTest(seededRng('ur'), { walletType: 'p2wsh-2of3', inputCount: 3 });
    const encoder = createPsbtUrEncoder(test.psbtBase64);
    expect(encoder.totalParts).toBeGreaterThan(1);

    const frames = Array.from({ length: encoder.totalParts + 4 }, () => encoder.next());
    expect(frames[0]).toMatch(/^UR:CRYPTO-PSBT\//);

    // Cameras rarely see frames in order; fountain decoding must cope.
    const decoder = createPsbtUrDecoder();
    let result;
    for (const frame of [...frames].reverse()) {
      result = decoder.receive(frame);
      if (result.complete) break;
    }
    expect(result?.complete).toBe(true);
    expect(result?.psbtBase64).toBe(test.psbtBase64);
  });

  it('accepts both tagged and untagged CBOR byte strings', () => {
    const payload = Uint8Array.from([0x70, 0x73, 0x62, 0x74, 0xff]);
    const untagged = Uint8Array.from([0x45, ...payload]);
    const tagged = Uint8Array.from([0xd9, 0x01, 0x36, 0x45, ...payload]);
    expect(unwrapCborBytes(untagged)).toEqual(payload);
    expect(unwrapCborBytes(tagged)).toEqual(payload);
  });

  it('names the wrong QR format instead of failing silently', () => {
    const decoder = createPsbtUrDecoder();
    expect(decoder.receive('cHNidP8BALACAAAAA').error).toMatch(/base64 PSBT/);
    expect(decoder.receive('p1of3 cHNidP8BALAC').error).toMatch(/Specter/);
    expect(decoder.receive('ur:crypto-hdkey/1-2/abcd').error).toMatch(/crypto-hdkey/);
    expect(decoder.receive('hello').error).toMatch(/Not a UR/);
  });
});

describe('fountain encoding', () => {
  it('recovers the PSBT from fountain frames alone, with no pure fragments', () => {
    // The distinguishing property of a fountain code: frames past the pure set
    // are XOR mixes, so the payload is recoverable without ever seeing a given
    // pure fragment. A plain repeating cycle could not do this.
    const test = generateTest(seededRng('fountain-only'), {
      walletType: 'p2wsh-2of3',
      inputCount: 3,
    });
    const encoder = createPsbtUrEncoder(test.psbtBase64);
    expect(encoder.totalParts).toBeGreaterThan(1);

    const frames = Array.from({ length: encoder.totalParts * 4 }, () => encoder.next());
    const fountainOnly = frames.slice(encoder.totalParts);

    const decoder = createPsbtUrDecoder();
    let result;
    for (const frame of fountainOnly) {
      result = decoder.receive(frame);
      if (result.complete) break;
    }
    expect(result?.complete).toBe(true);
    expect(result?.psbtBase64).toBe(test.psbtBase64);
  });

  it('never repeats a frame, so the sequence keeps adding information', () => {
    const test = generateTest(seededRng('no-repeat'), { inputCount: 3 });
    const encoder = createPsbtUrEncoder(test.psbtBase64);
    const frames = Array.from({ length: encoder.totalParts * 3 }, () => encoder.next());
    expect(new Set(frames).size).toBe(frames.length);
  });
});
