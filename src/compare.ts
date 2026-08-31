/**
 * Comparing the device's signatures against what embit would have produced.
 *
 * The site knows the seed, so it can recompute the exact signature a correct
 * signer must return. Anything else means the device's nonce is not the
 * deterministic one — which, for ECDSA, is a key-recovery risk rather than a
 * cosmetic difference.
 *
 * The outcomes are deliberately finer-grained than pass/fail. A signature that
 * differs but still verifies is a genuine nonce problem; one that does not
 * verify at all almost always means the wrong seed was loaded or the scan was
 * corrupted. Reporting the second as a nonce failure would frighten users about
 * working hardware, so the two are kept apart.
 */
// Explicit import: `Buffer` is a Node global but not a browser one, and
// bitcoinjs-lib's API is Buffer-based throughout.
import { Buffer } from 'buffer';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { NETWORK, type TestWallet } from './wallet.js';
import { signPsbtLocally } from './sign-psbt.js';

export type Outcome =
  /** Byte-identical to what embit produces. */
  | 'match'
  /** Verifies, but differs — the nonce was not deterministic. */
  | 'valid-but-different'
  /** Does not verify at all — a setup problem, not a nonce problem. */
  | 'invalid'
  /** The device returned no signature for this input. */
  | 'missing';

export interface InputComparison {
  inputIndex: number;
  path: string;
  outcome: Outcome;
  expected: string;
  actual?: string;
  /** How many grind iterations the expected signature needed. */
  grindCounter: number;
  expectedDerLength: number;
  actualDerLength?: number;
  /** Whether the device's signature is low-R, as embit's grinding guarantees. */
  actualLowR?: boolean;
}

export type Verdict =
  | 'pass'
  /** At least one signature verified but differed. The dangerous case. */
  | 'nondeterministic'
  /** Something about the setup is wrong; the test is inconclusive. */
  | 'inconclusive';

export interface ComparisonResult {
  verdict: Verdict;
  inputs: InputComparison[];
  /** Set when the scanned PSBT is not the one we handed out. */
  transactionMismatch: boolean;
  summary: string;
}

/**
 * Canonical fingerprint of the transaction a PSBT commits to.
 *
 * Segwit signatures live in the witness, so the unsigned transaction is
 * unchanged by signing and the two PSBTs must agree exactly. If they do not,
 * the user scanned a different transaction and every signature would compare as
 * invalid — a confusing way to learn you scanned the wrong QR.
 */
function transactionFingerprint(psbt: bitcoin.Psbt): string {
  const inputs = psbt.txInputs
    .map((i) => `${Buffer.from(i.hash).toString('hex')}:${i.index}:${i.sequence}`)
    .join(',');
  const outputs = psbt.txOutputs
    .map((o) => `${o.script.toString('hex')}:${o.value}`)
    .join(',');
  return `v${psbt.version}|l${psbt.locktime}|${inputs}|${outputs}`;
}

function verifySignature(pubkey: Uint8Array, msgHash: Uint8Array, signature: Uint8Array): boolean {
  try {
    return ecc.verify(msgHash, pubkey, signature);
  } catch {
    return false;
  }
}

/**
 * Compare a signed PSBT returned by the device against locally recomputed
 * signatures.
 */
export function compareSignatures(
  unsignedPsbtBase64: string,
  wallet: TestWallet,
  devicePsbtBase64: string,
): ComparisonResult {
  const expectedResult = signPsbtLocally(unsignedPsbtBase64, wallet);
  const unsigned = bitcoin.Psbt.fromBase64(unsignedPsbtBase64, { network: NETWORK });
  const device = bitcoin.Psbt.fromBase64(devicePsbtBase64, { network: NETWORK });

  const transactionMismatch =
    transactionFingerprint(unsigned) !== transactionFingerprint(device);

  const inputs: InputComparison[] = [];

  for (const expected of expectedResult.signatures) {
    const expectedHex = expected.signature.toString('hex');
    const deviceInput = device.data.inputs[expected.inputIndex];
    const actual = deviceInput?.partialSig?.find((s) =>
      Buffer.from(s.pubkey).equals(expected.pubkey),
    );

    const base = {
      inputIndex: expected.inputIndex,
      path: expected.path,
      expected: expectedHex,
      grindCounter: expected.grindCounter,
      expectedDerLength: expected.derLength,
    };

    if (!actual) {
      inputs.push({ ...base, outcome: 'missing' });
      continue;
    }

    const actualBuf = Buffer.from(actual.signature);
    const actualHex = actualBuf.toString('hex');
    // The trailing byte is the sighash type; the DER body is everything before.
    const actualDerLength = actualBuf.length - 1;
    const actualLowR = actualDerLength <= 70;

    if (actualHex === expectedHex) {
      inputs.push({ ...base, outcome: 'match', actual: actualHex, actualDerLength, actualLowR });
      continue;
    }

    // Differs. Does it at least verify? That distinguishes a bad nonce from a
    // bad setup, and only bitcoinjs knows the sighash, so ask it.
    let verifies = false;
    if (!transactionMismatch) {
      try {
        verifies = device.validateSignaturesOfInput(
          expected.inputIndex,
          verifySignature,
          expected.pubkey,
        );
      } catch {
        verifies = false;
      }
    }

    inputs.push({
      ...base,
      outcome: verifies ? 'valid-but-different' : 'invalid',
      actual: actualHex,
      actualDerLength,
      actualLowR,
    });
  }

  const counts = {
    match: inputs.filter((i) => i.outcome === 'match').length,
    different: inputs.filter((i) => i.outcome === 'valid-but-different').length,
    invalid: inputs.filter((i) => i.outcome === 'invalid').length,
    missing: inputs.filter((i) => i.outcome === 'missing').length,
  };

  let verdict: Verdict;
  let summary: string;

  if (transactionMismatch) {
    verdict = 'inconclusive';
    summary =
      'The scanned PSBT is for a different transaction than the one generated. ' +
      'Scan the signed PSBT produced from this run.';
  } else if (counts.different > 0) {
    verdict = 'nondeterministic';
    summary =
      `${counts.different} of ${inputs.length} signature${inputs.length === 1 ? '' : 's'} ` +
      `${counts.different === 1 ? 'is valid but differs' : 'are valid but differ'} from the ` +
      'deterministic result. This device is not using RFC6979 nonces as embit does.';
  } else if (counts.invalid > 0 || counts.missing > 0) {
    verdict = 'inconclusive';
    summary =
      `${counts.invalid} invalid and ${counts.missing} missing signatures. ` +
      'This usually means a different seed was loaded, or the scan was incomplete.';
  } else {
    verdict = 'pass';
    summary =
      counts.match === 1
        ? 'The signature is byte-identical to the deterministic result.'
        : `All ${counts.match} signatures are byte-identical to the deterministic result.`;
  }

  return { verdict, inputs, transactionMismatch, summary };
}
