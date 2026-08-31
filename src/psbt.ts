/**
 * Random unsigned PSBT generation.
 *
 * The transaction does not need to be valid against the chain — an airgapped
 * signer has no chain state and cannot tell. What it does need is to look
 * entirely ordinary: nothing about the amounts, addresses, or shape should mark
 * it as a determinism probe if someone glanced at the device screen.
 *
 * DOM-free on purpose: the Node test harness imports this module directly.
 */
// Explicit import: `Buffer` is a Node global but not a browser one, and
// bitcoinjs-lib's API is Buffer-based throughout.
import { Buffer } from 'buffer';
import * as bitcoin from 'bitcoinjs-lib';
import type { Rng } from './rng.js';
import {
  NETWORK,
  type DerivedKey,
  type TestWallet,
  type WalletType,
  type WordCount,
  cosignerDerivations,
  deriveKey,
  generateWallet,
  globalXpubs,
  keyPath,
} from './wallet.js';

export interface TestInput extends DerivedKey {
  txid: string;
  vout: number;
  value: number;
  sequence: number;
}

export interface TestOutput {
  address: string;
  value: number;
  isChange: boolean;
  path?: string;
}

export interface GeneratedTest {
  wallet: TestWallet;
  /** Unsigned PSBT, ready to hand to the device. */
  psbtBase64: string;
  inputs: TestInput[];
  outputs: TestOutput[];
  fee: number;
  version: number;
  locktime: number;
}

export interface GenerateOptions {
  walletType?: WalletType;
  wordCount?: WordCount;
  inputCount?: number;
  outputCount?: number;
}

/** RBF-signalling. Sparrow enables RBF by default, so this is what it emits. */
const SEQUENCE_RBF = 0xfffffffd;

/**
 * Known block height and its date, used to estimate the current tip.
 *
 * Taken from a real Sparrow PSBT (nLockTime 964,805 on 2026-08-30) rather than
 * from a halving, so the estimate starts accurate instead of extrapolating
 * across years of drift.
 */
const HEIGHT_ANCHOR = { height: 964_805, timestamp: Date.UTC(2026, 7, 30) };
const BLOCKS_PER_DAY = 144;

/**
 * Estimate the current block height from the clock.
 *
 * Wallets set nLockTime to roughly the current height for anti-fee-sniping, so
 * a stale value is a giveaway: a locktime tens of thousands of blocks in the
 * past marks the transaction as synthetic to anyone who knows the tip. This has
 * to be derived rather than hard-coded, or it goes stale again in a few months.
 */
export function estimatedBlockHeight(now = Date.now()): number {
  const days = (now - HEIGHT_ANCHOR.timestamp) / 86_400_000;
  return Math.max(HEIGHT_ANCHOR.height, Math.round(HEIGHT_ANCHOR.height + days * BLOCKS_PER_DAY));
}

/** Bounds on the total value a generated transaction spends, in satoshis. */
export const MIN_TOTAL_SPEND = 1_000_000;
export const MAX_TOTAL_SPEND = 100_000_000;

/** Highest address index used, so derivation paths stay short and readable. */
export const MAX_ADDRESS_INDEX = 100;

/** How far apart clustered addresses may sit. */
const ADDRESS_CLUSTER_WIDTH = 12;

/** Smallest value any single input may carry, to keep amounts plausible. */
const MIN_INPUT_VALUE = 2_000;

/**
 * Pick the total being spent, then split it across the inputs.
 *
 * Choosing the total first is what keeps it inside the intended range no matter
 * how many inputs there are — drawing each input independently would let a
 * three-input transaction total three times the maximum.
 *
 * The total is spread across several orders of magnitude rather than drawn
 * uniformly, so repeated runs are not fingerprintable by amount.
 */
function randomInputValues(rng: Rng, inputCount: number): number[] {
  // Three bands, each drawn about a third of the time. A uniform draw over the
  // whole range would put nearly every transaction near the top of it.
  const band = rng.pick([
    [MIN_TOTAL_SPEND, 5_000_000],
    [5_000_000, 25_000_000],
    [25_000_000, MAX_TOTAL_SPEND],
  ]);
  const total = rng.range(band[0], band[1]);

  if (inputCount === 1) return [total];

  // Random cut points give an uneven, natural-looking split; a proportional
  // division would make every input a suspiciously round fraction of the total.
  const spare = total - MIN_INPUT_VALUE * inputCount;
  const cuts = Array.from({ length: inputCount - 1 }, () => rng.int(spare + 1)).sort(
    (a, b) => a - b,
  );

  const values: number[] = [];
  let previous = 0;
  for (const cut of cuts) {
    values.push(MIN_INPUT_VALUE + (cut - previous));
    previous = cut;
  }
  values.push(MIN_INPUT_VALUE + (spare - previous));
  return values;
}

/** A random mainnet bech32 address belonging to nobody in particular. */
function randomExternalAddress(rng: Rng): string {
  // Mix P2WPKH and P2WSH recipients; both are ordinary destinations.
  if (rng.chance(0.75)) {
    return bitcoin.payments.p2wpkh({
      hash: Buffer.from(rng.bytes(20)),
      network: NETWORK,
    }).address!;
  }
  return bitcoin.payments.p2wsh({
    hash: Buffer.from(rng.bytes(32)),
    network: NETWORK,
  }).address!;
}

/**
 * Generate a full test: a throwaway wallet plus an unsigned PSBT spending from
 * it. Everything is random and nothing is user-selectable.
 *
 * `options` exists so the test harness can stratify its cases across the whole
 * space rather than hoping random draws cover it.
 */
export function generateTest(rng: Rng, options: GenerateOptions = {}): GeneratedTest {
  const wallet = generateWallet(rng, options);
  const isMultisig = wallet.walletType === 'p2wsh-2of3';

  const inputCount = options.inputCount ?? rng.range(1, 3);
  const outputCount = options.outputCount ?? rng.range(1, 2);

  // Multisig never gets a change output, so there is nothing for the device to
  // verify a wallet registration against and no descriptor QR step is needed.
  // Single-sig takes change only when there are two outputs.
  const hasChange = !isMultisig && outputCount === 2 && rng.chance(0.8);

  const version = 2;
  // Sparrow always sets nLockTime to the current block height for
  // anti-fee-sniping; it does not leave it at zero.
  const locktime = estimatedBlockHeight();

  // Sparrow enables RBF by default, so every transaction it builds signals it
  // on every input. Mixing in the occasional final sequence would not match.
  const sequence = SEQUENCE_RBF;

  // UTXOs cluster around recently used addresses rather than scattering
  // uniformly across the whole gap limit. Kept within 0-100: a wallet with a
  // couple of hundred used addresses is plausible but makes the paths tedious
  // to read off a device screen.
  const indexBase = rng.range(0, MAX_ADDRESS_INDEX - ADDRESS_CLUSTER_WIDTH);

  const psbt = new bitcoin.Psbt({ network: NETWORK });
  psbt.setVersion(version);
  psbt.setLocktime(locktime);
  // Sparrow advertises the account key(s) in the global map so the signer can
  // confirm the transaction belongs to a wallet it knows.
  psbt.updateGlobal({ globalXpub: globalXpubs(wallet) });

  const inputs: TestInput[] = [];
  const usedIndices = new Set<string>();
  const inputValues = randomInputValues(rng, inputCount);

  for (let i = 0; i < inputCount; i++) {
    // Distinct paths per input, so a bug that reuses one key cannot hide.
    let change: 0 | 1;
    let index: number;
    do {
      change = rng.chance(0.75) ? 0 : 1;
      index = indexBase + rng.range(0, ADDRESS_CLUSTER_WIDTH);
    } while (usedIndices.has(`${change}/${index}`));
    usedIndices.add(`${change}/${index}`);

    const key = deriveKey(wallet, change, index);
    const value = inputValues[i];
    // Low vouts dominate in practice; most transactions have two outputs.
    const vout = rng.chance(0.85) ? rng.range(0, 1) : rng.range(2, 3);
    const txid = Buffer.from(rng.bytes(32));

    psbt.addInput({
      hash: txid,
      index: vout,
      sequence,
      witnessUtxo: { script: key.script, value },
      // Sparrow writes an explicit PSBT_IN_SIGHASH_TYPE of SIGHASH_ALL rather
      // than leaving it to default.
      sighashType: bitcoin.Transaction.SIGHASH_ALL,
      bip32Derivation: [
        {
          masterFingerprint: wallet.fingerprint,
          pubkey: key.pubkey,
          path: key.path,
        },
        ...(isMultisig ? cosignerDerivations(wallet, change, index) : []),
      ],
      ...(key.witnessScript ? { witnessScript: key.witnessScript } : {}),
    });

    inputs.push({
      ...key,
      // bitcoinjs treats `hash` as internal byte order; the displayed txid is
      // the reverse. Record the display form for the UI and test output.
      txid: Buffer.from(txid).reverse().toString('hex'),
      vout,
      value,
      sequence,
    });
  }

  const totalIn = inputs.reduce((sum, input) => sum + input.value, 0);
  // A plausible fee for a transaction this size, rather than a round number.
  const vsizeEstimate = 11 + inputCount * (isMultisig ? 105 : 68) + outputCount * 31;
  const feeRate = rng.range(1, 40);
  const fee = Math.max(200, vsizeEstimate * feeRate);
  const spendable = totalIn - fee;

  if (spendable <= 0) {
    // Only reachable if the fee estimate ever exceeds the smallest input range.
    throw new Error('generated fee exceeds total input value');
  }

  const outputs: TestOutput[] = [];

  if (outputCount === 1) {
    outputs.push({
      address: randomExternalAddress(rng),
      value: spendable,
      isChange: false,
    });
  } else {
    // Split so neither output is a suspiciously round fraction of the other.
    const primary = rng.range(Math.floor(spendable * 0.15), Math.floor(spendable * 0.85));
    const secondary = spendable - primary;

    outputs.push({ address: randomExternalAddress(rng), value: primary, isChange: false });

    if (hasChange) {
      const changeIndex = indexBase + rng.range(0, ADDRESS_CLUSTER_WIDTH);
      const changeKey = deriveKey(wallet, 1, changeIndex);
      const address = bitcoin.address.fromOutputScript(changeKey.script, NETWORK);
      outputs.push({
        address,
        value: secondary,
        isChange: true,
        path: keyPath(wallet, 1, changeIndex),
      });
    } else {
      outputs.push({
        address: randomExternalAddress(rng),
        value: secondary,
        isChange: false,
      });
    }

    // Randomise change position. Wallets deliberately shuffle it (or sort by
    // BIP69) so that chain analysis cannot pick out change by position — always
    // placing it last was both unrealistic and the single clearest tell in the
    // generated transactions.
    if (rng.chance(0.5)) outputs.reverse();
  }

  outputs.forEach((output, i) => {
    psbt.addOutput({ address: output.address, value: output.value });
    if (!output.isChange) return;
    // Marking change with its derivation is what lets the device display it as
    // "change" rather than as a payment to a stranger.
    const changeIndex = Number(output.path!.split('/').pop());
    const changeKey = deriveKey(wallet, 1, changeIndex);
    psbt.updateOutput(i, {
      bip32Derivation: [
        {
          masterFingerprint: wallet.fingerprint,
          pubkey: changeKey.pubkey,
          path: changeKey.path,
        },
      ],
    });
  });

  return {
    wallet,
    psbtBase64: psbt.toBase64(),
    inputs,
    outputs,
    fee,
    version,
    locktime,
  };
}
