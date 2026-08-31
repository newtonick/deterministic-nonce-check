/**
 * Signing a PSBT the way the device should.
 *
 * bitcoinjs-lib owns the BIP143 sighash and the PSBT plumbing; `createEmbitSigner`
 * owns the nonce. Routing the local signature through exactly the same
 * `psbt.signInput` path the comparison uses means a misunderstanding about
 * sighash construction cannot masquerade as a determinism failure.
 *
 * DOM-free on purpose: the Node test harness imports this module directly.
 */
// Explicit import: `Buffer` is a Node global but not a browser one, and
// bitcoinjs-lib's API is Buffer-based throughout.
import { Buffer } from 'buffer';
import * as bitcoin from 'bitcoinjs-lib';
import { createEmbitSigner, type EmbitSignature } from './embit-sign.js';
import { NETWORK, type TestWallet, deriveKey } from './wallet.js';

export interface LocalSignature {
  inputIndex: number;
  path: string;
  pubkey: Buffer;
  /** DER + the appended sighash byte, exactly as it sits in the PSBT. */
  signature: Buffer;
  grindCounter: number;
  derLength: number;
}

export interface LocalSigningResult {
  /** The PSBT with our signatures added, base64. */
  psbtBase64: string;
  signatures: LocalSignature[];
}

/**
 * Parse a PSBT and identify which inputs the wallet's own key can sign, by
 * matching the master fingerprint in each input's BIP32 derivations.
 *
 * Fingerprint matching is what a real signer does, so doing the same here keeps
 * the harness honest: if the generated PSBT carries a fingerprint the device
 * cannot match, this finds nothing and the test fails loudly rather than
 * silently passing on zero signatures.
 */
export function signPsbtLocally(psbtBase64: string, wallet: TestWallet): LocalSigningResult {
  const psbt = bitcoin.Psbt.fromBase64(psbtBase64, { network: NETWORK });
  const fingerprint = wallet.fingerprint;
  const signatures: LocalSignature[] = [];

  psbt.data.inputs.forEach((input, inputIndex) => {
    const ours = input.bip32Derivation?.find((d) =>
      Buffer.from(d.masterFingerprint).equals(fingerprint),
    );
    if (!ours) return;

    // Recover change/index from the tail of the derivation path, e.g. ".../1/7".
    const parts = ours.path.split('/');
    const index = Number(parts[parts.length - 1]);
    const change = Number(parts[parts.length - 2]) as 0 | 1;
    const key = deriveKey(wallet, change, index);

    const signer = createEmbitSigner(key.privkey, key.pubkey);
    psbt.signInput(inputIndex, signer);

    const call: EmbitSignature = signer.calls[0];
    const placed = psbt.data.inputs[inputIndex].partialSig!.find((s) =>
      Buffer.from(s.pubkey).equals(key.pubkey),
    )!;

    signatures.push({
      inputIndex,
      path: ours.path,
      pubkey: key.pubkey,
      signature: Buffer.from(placed.signature),
      grindCounter: call.grindCounter,
      derLength: call.derLength,
    });
  });

  return { psbtBase64: psbt.toBase64(), signatures };
}
