import { describe, expect, it } from 'vitest';
import * as bitcoin from 'bitcoinjs-lib';
import { Buffer } from 'buffer';
import { secp256k1 } from '@noble/curves/secp256k1';
import { MAX_TOTAL_SPEND, MIN_TOTAL_SPEND, generateTest } from '../src/psbt.js';
import { seededRng } from '../src/rng.js';
import { signPsbtLocally } from '../src/sign-psbt.js';
import { compareSignatures } from '../src/compare.js';
import { NETWORK, deriveKey, generateWallet } from '../src/wallet.js';

const makeTest = (seed: string, opts = {}) =>
  generateTest(seededRng(seed), { walletType: 'p2wpkh', inputCount: 2, outputCount: 2, ...opts });

/** A device that signs correctly but with a random nonce each time. */
function signWithRandomNonce(test: ReturnType<typeof makeTest>): string {
  const psbt = bitcoin.Psbt.fromBase64(test.psbtBase64, { network: NETWORK });
  test.inputs.forEach((input, index) => {
    const key = deriveKey(test.wallet, input.change, input.index);
    psbt.signInput(index, {
      publicKey: key.pubkey,
      sign: (h: Buffer) =>
        Buffer.from(
          secp256k1
            .sign(new Uint8Array(h), key.privkey, { lowS: true, extraEntropy: true })
            .toCompactRawBytes(),
        ),
    });
  });
  return psbt.toBase64();
}

describe('compareSignatures', () => {
  it('passes when the device signs exactly as embit does', () => {
    const test = makeTest('honest');
    const signed = signPsbtLocally(test.psbtBase64, test.wallet);
    const result = compareSignatures(test.psbtBase64, test.wallet, signed.psbtBase64);

    expect(result.verdict).toBe('pass');
    expect(result.inputs.every((i) => i.outcome === 'match')).toBe(true);
    expect(result.inputs).toHaveLength(test.inputs.length);
  });

  it('flags a random nonce as non-deterministic, not as invalid', () => {
    const test = makeTest('random');
    const result = compareSignatures(test.psbtBase64, test.wallet, signWithRandomNonce(test));

    // The signatures are perfectly valid — that is exactly what makes this
    // failure mode dangerous and easy to miss.
    expect(result.verdict).toBe('nondeterministic');
    expect(result.inputs.every((i) => i.outcome === 'valid-but-different')).toBe(true);
  });

  it('reports a wrong seed as inconclusive rather than a nonce failure', () => {
    const test = makeTest('wrong-seed');
    const other = generateWallet(seededRng('other'), { walletType: 'p2wpkh', wordCount: 12 });

    const psbt = bitcoin.Psbt.fromBase64(test.psbtBase64, { network: NETWORK });
    test.inputs.forEach((input, index) => {
      const ours = deriveKey(test.wallet, input.change, input.index);
      const theirs = deriveKey(other, input.change, input.index);
      psbt.data.updateInput(index, {
        partialSig: [
          {
            pubkey: ours.pubkey,
            signature: Buffer.concat([
              Buffer.from(
                secp256k1.sign(new Uint8Array(32).fill(3), theirs.privkey, { lowS: true }).toDERRawBytes(),
              ),
              Buffer.from([0x01]),
            ]),
          },
        ],
      });
    });

    const result = compareSignatures(test.psbtBase64, test.wallet, psbt.toBase64());
    expect(result.verdict).toBe('inconclusive');
    expect(result.inputs.every((i) => i.outcome === 'invalid')).toBe(true);
  });

  it('detects a signed PSBT from a different transaction', () => {
    const test = makeTest('tx-a');
    const otherTest = makeTest('tx-b', { inputCount: 1 });
    const otherSigned = signPsbtLocally(otherTest.psbtBase64, otherTest.wallet);

    const result = compareSignatures(test.psbtBase64, test.wallet, otherSigned.psbtBase64);
    expect(result.transactionMismatch).toBe(true);
    expect(result.verdict).toBe('inconclusive');
    expect(result.summary).toMatch(/different transaction/);
  });

  it('reports missing signatures when the device signed nothing', () => {
    const test = makeTest('unsigned');
    const result = compareSignatures(test.psbtBase64, test.wallet, test.psbtBase64);
    expect(result.verdict).toBe('inconclusive');
    expect(result.inputs.every((i) => i.outcome === 'missing')).toBe(true);
  });

  it('works for 2-of-3 multisig too', () => {
    const test = makeTest('multisig', { walletType: 'p2wsh-2of3', inputCount: 2 });
    const signed = signPsbtLocally(test.psbtBase64, test.wallet);
    expect(compareSignatures(test.psbtBase64, test.wallet, signed.psbtBase64).verdict).toBe('pass');
    expect(compareSignatures(test.psbtBase64, test.wallet, signWithRandomNonce(test)).verdict).toBe(
      'nondeterministic',
    );
  });
});

describe('generated transactions', () => {
  it('never gives a multisig wallet a change output', () => {
    for (let i = 0; i < 40; i++) {
      const test = generateTest(seededRng('ms' + i), { walletType: 'p2wsh-2of3' });
      expect(test.outputs.some((o) => o.isChange)).toBe(false);
    }
  });

  it('always leaves a positive fee and spends less than it takes in', () => {
    for (let i = 0; i < 40; i++) {
      const test = generateTest(seededRng('fee' + i));
      const totalIn = test.inputs.reduce((n, x) => n + x.value, 0);
      const totalOut = test.outputs.reduce((n, x) => n + x.value, 0);
      expect(totalOut).toBeLessThan(totalIn);
      expect(totalIn - totalOut).toBe(test.fee);
      expect(test.fee).toBeGreaterThan(0);
    }
  });
});

describe('spend amounts', () => {
  it('keeps the total spent between 50,000 and 20,000,000 sats for every input count', () => {
    for (let inputCount = 1; inputCount <= 3; inputCount++) {
      for (let i = 0; i < 60; i++) {
        const test = generateTest(seededRng(`amt${inputCount}-${i}`), { inputCount });
        const total = test.inputs.reduce((n, x) => n + x.value, 0);
        expect(total).toBeGreaterThanOrEqual(MIN_TOTAL_SPEND);
        expect(total).toBeLessThanOrEqual(MAX_TOTAL_SPEND);
        expect(test.inputs).toHaveLength(inputCount);
        // Every input must carry a plausible, positive amount.
        test.inputs.forEach((input) => expect(input.value).toBeGreaterThan(0));
      }
    }
  });
});
