/**
 * Anti-fingerprinting invariants.
 *
 * A determinism probe is only useful if it is indistinguishable from ordinary
 * spending. These lock in the properties that a statistical sweep of generated
 * transactions previously showed were giving the game away.
 */
import { describe, expect, it } from 'vitest';
import * as bitcoin from 'bitcoinjs-lib';
import { estimatedBlockHeight, generateTest } from '../src/psbt.js';
import { cryptoRng, seededRng } from '../src/rng.js';
import { NETWORK } from '../src/wallet.js';

const sample = (n: number) =>
  Array.from({ length: n }, (_, i) => {
    const test = generateTest(seededRng('fp' + i));
    return { test, psbt: bitcoin.Psbt.fromBase64(test.psbtBase64, { network: NETWORK }) };
  });

describe('Sparrow compatibility', () => {
  it('omits non_witness_utxo, as Sparrow does for segwit QR signing', () => {
    // Sparrow strips previous transactions for segwit inputs when producing
    // PSBTs for QR signing. Including them would not match what SeedSigner
    // receives in the field, and would inflate the animated QR considerably.
    for (const { psbt } of sample(40)) {
      psbt.data.inputs.forEach((input) => expect(input.nonWitnessUtxo).toBeUndefined());
    }
  });

  it('carries exactly the input fields Sparrow emits for segwit', () => {
    for (const { test, psbt } of sample(40)) {
      // Matched field-for-field against a real Sparrow PSBT.
      const expected =
        test.wallet.walletType === 'p2wsh-2of3'
          ? ['witnessUtxo', 'sighashType', 'witnessScript', 'bip32Derivation']
          : ['witnessUtxo', 'sighashType', 'bip32Derivation'];
      psbt.data.inputs.forEach((input) => {
        expect(Object.keys(input).sort()).toEqual([...expected].sort());
      });
    }
  });

  it('writes an explicit SIGHASH_ALL, as Sparrow does', () => {
    for (const { psbt } of sample(30)) {
      psbt.data.inputs.forEach((input) => expect(input.sighashType).toBe(1));
    }
  });

  it('advertises the account key(s) via PSBT_GLOBAL_XPUB, as Sparrow does', () => {
    for (const { test, psbt } of sample(30)) {
      const xpubs = (psbt.data.globalMap as unknown as { globalXpub?: unknown[] }).globalXpub;
      // Single-sig carries one account key; a 2-of-3 carries all three.
      expect(xpubs).toHaveLength(test.wallet.walletType === 'p2wsh-2of3' ? 3 : 1);
    }
  });

  it('signals RBF on every input, matching Sparrow\'s default', () => {
    for (const { psbt } of sample(40)) {
      psbt.txInputs.forEach((input) => expect(input.sequence).toBe(0xfffffffd));
    }
  });
});

describe('transaction shape', () => {
  it('uses one sequence across all inputs, as a real wallet does', () => {
    for (const { psbt } of sample(60)) {
      expect(new Set(psbt.txInputs.map((i) => i.sequence)).size).toBe(1);
    }
  });

  it('sets transaction version 2', () => {
    for (const { psbt } of sample(30)) expect(psbt.version).toBe(2);
  });

  it('always sets nLockTime to the current tip, as Sparrow does', () => {
    const tip = estimatedBlockHeight();
    for (const { psbt } of sample(60)) {
      // Sparrow does anti-fee-sniping on every transaction; it never leaves
      // nLockTime at zero, so neither should a transaction imitating one.
      expect(psbt.locktime).toBe(tip);
    }
  });

  it('does not always place change in the same position', () => {
    // Change was previously last 100% of the time — the clearest single tell.
    const positions = { first: 0, last: 0 };
    for (let i = 0; i < 400; i++) {
      const test = generateTest(cryptoRng());
      if (!test.outputs.some((o) => o.isChange)) continue;
      const idx = test.outputs.findIndex((o) => o.isChange);
      if (idx === 0) positions.first++;
      else if (idx === test.outputs.length - 1) positions.last++;
    }
    const total = positions.first + positions.last;
    expect(total).toBeGreaterThan(20);
    // Neither position should dominate; a wide band keeps this non-flaky.
    expect(positions.first / total).toBeGreaterThan(0.25);
    expect(positions.first / total).toBeLessThan(0.75);
  });
});

describe('transaction math', () => {
  it('reconciles: inputs - sent - fee = change, for every generated transaction', () => {
    // The approval card shows this arithmetic so it can be checked against the
    // device screen. If it did not balance, the tool would be teaching users to
    // ignore a mismatch on their own hardware.
    for (let i = 0; i < 120; i++) {
      const test = generateTest(seededRng('math' + i));
      const inputTotal = test.inputs.reduce((n, x) => n + x.value, 0);
      const sent = test.outputs.filter((o) => !o.isChange).reduce((n, o) => n + o.value, 0);
      const change = test.outputs.filter((o) => o.isChange).reduce((n, o) => n + o.value, 0);
      expect(inputTotal - sent - test.fee).toBe(change);
    }
  });
});

describe('output descriptor', () => {
  it('produces a scannable ur:crypto-output for both wallet types', async () => {
    const { walletDescriptor, cryptoOutputCbor } = await import('../src/descriptor.js');
    const { createDescriptorUrEncoder } = await import('../src/ur.js');
    for (const walletType of ['p2wpkh', 'p2wsh-2of3'] as const) {
      const test = generateTest(seededRng('desc-' + walletType), { walletType });
      const encoder = createDescriptorUrEncoder(cryptoOutputCbor(test.wallet));
      const ur = encoder.next();
      expect(ur).toMatch(/^UR:CRYPTO-OUTPUT\//);
      // Every frame must stay under the density a modest device camera can
      // resolve; that is the whole reason the descriptor is animated.
      expect(ur.length).toBeLessThan(400);

      const text = walletDescriptor(test.wallet);
      expect(text).toMatch(walletType === 'p2wpkh' ? /^wpkh\(/ : /^wsh\(sortedmulti\(2,/);
      // Hardened markers must be apostrophes: that is what the device renders
      // from the QR, and the text and QR have to agree.
      expect(text).not.toContain('h]');
      expect(text).toContain("/0/*");
    }
  });
});
