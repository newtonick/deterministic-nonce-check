/**
 * Throwaway test wallets.
 *
 * Every seed generated here exists only to be signed with once and thrown away.
 * The site can recompute the device's expected signatures precisely because it
 * knows the seed — that is the whole mechanism. It also means these seeds must
 * never hold funds, and the UI says so loudly.
 *
 * DOM-free on purpose: the Node test harness imports this module directly.
 */
// Explicit import: `Buffer` is a Node global but not a browser one, and
// bitcoinjs-lib's API is Buffer-based throughout.
import { Buffer } from 'buffer';
import * as bitcoin from 'bitcoinjs-lib';
import { BIP32Factory, type BIP32Interface } from 'bip32';
import * as ecc from '@bitcoinerlab/secp256k1';
import { generateMnemonic, mnemonicToSeedSync, wordlists } from 'bip39';
import type { Rng } from './rng.js';

export const bip32 = BIP32Factory(ecc);
export const NETWORK = bitcoin.networks.bitcoin;

bitcoin.initEccLib(ecc);

export type WalletType = 'p2wpkh' | 'p2wsh-2of3';
export type WordCount = 12 | 24;

/** BIP48 script-type index for native segwit (P2WSH) multisig. */
const BIP48_NATIVE_SEGWIT = 2;

export const MULTISIG_THRESHOLD = 2;
export const MULTISIG_TOTAL = 3;

export interface Cosigner {
  fingerprint: Buffer;
  /** Account-level extended key, at the same path as the signing device's. */
  accountNode: BIP32Interface;
}

export interface TestWallet {
  walletType: WalletType;
  mnemonic: string;
  wordCount: WordCount;
  seed: Buffer;
  root: BIP32Interface;
  /** Master fingerprint the device will match against the scanned SeedQR. */
  fingerprint: Buffer;
  /** e.g. "m/84'/0'/0'" or "m/48'/0'/0'/2'" */
  accountPath: string;
  accountNode: BIP32Interface;
  /** Empty for single-sig; the two other keys for 2-of-3. */
  cosigners: Cosigner[];
}

export function accountPathFor(walletType: WalletType): string {
  return walletType === 'p2wpkh'
    ? "m/84'/0'/0'"
    : `m/48'/0'/0'/${BIP48_NATIVE_SEGWIT}'`;
}

/**
 * Human-readable wallet description, e.g. "Native Segwit Single Sig · BIP-84".
 *
 * Derived from the wallet type rather than written out per caller, so it cannot
 * drift from the derivation path actually used.
 */
export function describeWallet(wallet: TestWallet): string {
  return wallet.walletType === 'p2wpkh'
    ? 'Native Segwit Single Sig · BIP-84'
    : `Native Segwit Multisig ${MULTISIG_THRESHOLD} of ${MULTISIG_TOTAL} · BIP-48`;
}

/** Full derivation path for one key, e.g. "m/84'/0'/0'/1/7". */
export function keyPath(wallet: TestWallet, change: 0 | 1, index: number): string {
  return `${wallet.accountPath}/${change}/${index}`;
}

function generateSeedPhrase(wordCount: WordCount, rng: Rng) {
  // bip39 wants an rng returning Buffer; route it through ours so a seeded run
  // reproduces the same mnemonic.
  const strength = wordCount === 12 ? 128 : 256;
  const mnemonic = generateMnemonic(
    strength,
    (size: number) => Buffer.from(rng.bytes(size)),
    wordlists.english,
  );
  const seed = mnemonicToSeedSync(mnemonic);
  return { mnemonic, seed, root: bip32.fromSeed(seed, NETWORK) };
}

/**
 * Build a random test wallet.
 *
 * Both the word count and the wallet type are chosen at random and are not
 * user-selectable — the whole run should look like an ordinary transaction,
 * with nothing about it identifying it as a determinism probe.
 */
export function generateWallet(
  rng: Rng,
  overrides: { walletType?: WalletType; wordCount?: WordCount } = {},
): TestWallet {
  const walletType = overrides.walletType ?? rng.pick<WalletType>(['p2wpkh', 'p2wsh-2of3']);
  const wordCount = overrides.wordCount ?? rng.pick<WordCount>([12, 24]);

  const { mnemonic, seed, root } = generateSeedPhrase(wordCount, rng);
  const accountPath = accountPathFor(walletType);
  const accountNode = root.derivePath(accountPath);

  const cosigners: Cosigner[] = [];
  if (walletType === 'p2wsh-2of3') {
    // Two throwaway cosigners. Only their public account keys matter — nothing
    // in this flow ever needs their private material, and the device only has
    // to produce its own single signature.
    for (let i = 0; i < MULTISIG_TOTAL - 1; i++) {
      const cosignerRoot = bip32.fromSeed(Buffer.from(rng.bytes(32)), NETWORK);
      cosigners.push({
        fingerprint: cosignerRoot.fingerprint,
        accountNode: cosignerRoot.derivePath(accountPath).neutered(),
      });
    }
  }

  return {
    walletType,
    mnemonic,
    wordCount,
    seed,
    root,
    fingerprint: root.fingerprint,
    accountPath,
    accountNode,
    cosigners,
  };
}

export interface DerivedKey {
  path: string;
  change: 0 | 1;
  index: number;
  /** The device's own key at this path. */
  pubkey: Buffer;
  privkey: Buffer;
  /** scriptPubKey this key controls, for the synthetic witnessUtxo. */
  script: Buffer;
  /** Present for multisig only; the PSBT carries it so the device can verify. */
  witnessScript?: Buffer;
  /** All three pubkeys in sortedmulti order; multisig only. */
  multisigPubkeys?: Buffer[];
}

/**
 * Derive one spendable key and its script.
 *
 * Multisig uses `sortedmulti`: pubkeys are sorted lexicographically so all
 * cosigners derive an identical script without agreeing on an order. This is
 * what SeedSigner and essentially every current multisig wallet expect.
 */
export function deriveKey(
  wallet: TestWallet,
  change: 0 | 1,
  index: number,
): DerivedKey {
  const node = wallet.accountNode.derive(change).derive(index);
  const pubkey = Buffer.from(node.publicKey);
  const privkey = Buffer.from(node.privateKey!);
  const path = keyPath(wallet, change, index);

  if (wallet.walletType === 'p2wpkh') {
    const payment = bitcoin.payments.p2wpkh({ pubkey, network: NETWORK });
    return { path, change, index, pubkey, privkey, script: payment.output! };
  }

  const cosignerPubkeys = wallet.cosigners.map((c) =>
    Buffer.from(c.accountNode.derive(change).derive(index).publicKey),
  );
  const pubkeys = [pubkey, ...cosignerPubkeys].sort(Buffer.compare);
  const p2ms = bitcoin.payments.p2ms({
    m: MULTISIG_THRESHOLD,
    pubkeys,
    network: NETWORK,
  });
  const p2wsh = bitcoin.payments.p2wsh({ redeem: p2ms, network: NETWORK });

  return {
    path,
    change,
    index,
    pubkey,
    privkey,
    script: p2wsh.output!,
    witnessScript: p2ms.output!,
    multisigPubkeys: pubkeys,
  };
}

/**
 * Raw 78-byte BIP32 serialisation of an account key, for PSBT_GLOBAL_XPUB.
 *
 * Built by hand rather than base58-decoding `toBase58()`, to avoid depending on
 * a base58 package that only reaches us transitively.
 */
export function serializeExtendedPubkey(node: BIP32Interface): Buffer {
  const out = Buffer.alloc(78);
  out.writeUInt32BE(NETWORK.bip32.public, 0);
  out.writeUInt8(node.depth, 4);
  out.writeUInt32BE(
    Buffer.isBuffer(node.parentFingerprint)
      ? (node.parentFingerprint as Buffer).readUInt32BE(0)
      : (node.parentFingerprint as number),
    5,
  );
  out.writeUInt32BE(node.index, 9);
  Buffer.from(node.chainCode).copy(out, 13);
  Buffer.from(node.publicKey).copy(out, 45);
  return out;
}

/**
 * PSBT_GLOBAL_XPUB entries, as Sparrow emits them: the account key with its
 * origin. Single-sig carries one; multisig carries every cosigner.
 */
export function globalXpubs(
  wallet: TestWallet,
): { extendedPubkey: Buffer; masterFingerprint: Buffer; path: string }[] {
  return [
    {
      extendedPubkey: serializeExtendedPubkey(wallet.accountNode.neutered()),
      masterFingerprint: wallet.fingerprint,
      path: wallet.accountPath,
    },
    ...wallet.cosigners.map((c) => ({
      extendedPubkey: serializeExtendedPubkey(c.accountNode),
      masterFingerprint: c.fingerprint,
      path: wallet.accountPath,
    })),
  ];
}

/** Cosigner BIP32 derivation entries for a PSBT input, multisig only. */
export function cosignerDerivations(
  wallet: TestWallet,
  change: 0 | 1,
  index: number,
): { masterFingerprint: Buffer; pubkey: Buffer; path: string }[] {
  return wallet.cosigners.map((c) => ({
    masterFingerprint: c.fingerprint,
    pubkey: Buffer.from(c.accountNode.derive(change).derive(index).publicKey),
    path: keyPath(wallet, change, index),
  }));
}
