/**
 * Wallet output descriptors, as text and as `ur:crypto-output`.
 *
 * Format choice matters here. SeedSigner's plain-text descriptor path only
 * matches strings containing "sortedmulti", so a single-sig `wpkh(...)`
 * descriptor sent as plain text is not recognised as a wallet at all. Both
 * SeedSigner and Krux do accept `ur:crypto-output`, so that is what the QR
 * carries — it works for single-sig and multisig alike.
 *
 * The CBOR layout follows BCR-2020-010 and is checked against `urtypes`, the
 * same decoder Krux uses, in the test suite.
 */
import { Buffer } from 'buffer';
import {
  MULTISIG_THRESHOLD,
  type TestWallet,
  serializeExtendedPubkey,
} from './wallet.js';

/** Registry tags used by crypto-output. */
const TAG_HDKEY = 303;
const TAG_KEYPATH = 304;
const TAG_WSH = 401;
const TAG_WPKH = 404;
const TAG_SORTEDMULTI = 407;

/** Only the receive chain is described, so text and QR say the same thing. */
const CHILDREN_PATH = '/0/*';

type Cbor = number | boolean | Uint8Array | Cbor[] | Map<number, Cbor> | Tagged;
class Tagged {
  constructor(readonly tag: number, readonly value: Cbor) {}
}

function head(major: number, value: number): number[] {
  const base = major << 5;
  if (value < 24) return [base | value];
  if (value < 0x100) return [base | 24, value];
  if (value < 0x10000) return [base | 25, value >> 8, value & 0xff];
  return [base | 26, (value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff];
}

function encode(item: Cbor): number[] {
  if (typeof item === 'number') return head(0, item);
  if (typeof item === 'boolean') return [item ? 0xf5 : 0xf4];
  if (item instanceof Uint8Array) return [...head(2, item.length), ...item];
  if (item instanceof Tagged) return [...head(6, item.tag), ...encode(item.value)];
  if (Array.isArray(item)) return item.reduce<number[]>((out, v) => [...out, ...encode(v)], head(4, item.length));
  const entries = [...item.entries()];
  return entries.reduce<number[]>(
    (out, [k, v]) => [...out, ...encode(k), ...encode(v)],
    head(5, entries.length),
  );
}

function fingerprintToInt(fingerprint: Buffer): number {
  return fingerprint.readUInt32BE(0);
}

/** Path components as the flat [index, hardened, ...] array the registry uses. */
function pathComponents(path: string): Cbor[] {
  const out: Cbor[] = [];
  for (const part of path.replace(/^m\//, '').split('/')) {
    const hardened = part.endsWith("'") || part.endsWith('h');
    out.push(Number(part.replace(/['h]$/, '')), hardened);
  }
  return out;
}

function hdKey(accountNode: { chainCode: Uint8Array; publicKey: Uint8Array; parentFingerprint: number | Buffer; depth: number }, masterFingerprint: Buffer, accountPath: string): Tagged {
  const origin = new Map<number, Cbor>([
    [1, pathComponents(accountPath)],
    [2, fingerprintToInt(masterFingerprint)],
    [3, accountPath.replace(/^m\//, '').split('/').length],
  ]);
  // Receive chain then wildcard: [0, false, [], false].
  const children = new Map<number, Cbor>([[1, [0, false, [], false]]]);

  const map = new Map<number, Cbor>([
    [3, Uint8Array.from(accountNode.publicKey)],
    [4, Uint8Array.from(accountNode.chainCode)],
    [6, new Tagged(TAG_KEYPATH, origin)],
    [7, new Tagged(TAG_KEYPATH, children)],
    [
      8,
      Buffer.isBuffer(accountNode.parentFingerprint)
        ? (accountNode.parentFingerprint as Buffer).readUInt32BE(0)
        : (accountNode.parentFingerprint as number),
    ],
  ]);
  return new Tagged(TAG_HDKEY, map);
}

/** The wallet's output descriptor as text. */
export function walletDescriptor(wallet: TestWallet): string {
  // Apostrophes, not "h": both are valid BIP-380, but this is what the device
  // renders from the QR, and the text and the QR must agree exactly.
  const origin = wallet.accountPath.replace(/^m/, '');
  const key = (fp: Buffer, xpub: string) => `[${fp.toString('hex')}${origin}]${xpub}${CHILDREN_PATH}`;

  if (wallet.walletType === 'p2wpkh') {
    return `wpkh(${key(wallet.fingerprint, wallet.accountNode.neutered().toBase58())})`;
  }

  const keys = [
    key(wallet.fingerprint, wallet.accountNode.neutered().toBase58()),
    ...wallet.cosigners.map((c) => key(c.fingerprint, c.accountNode.toBase58())),
  ];
  return `wsh(sortedmulti(${MULTISIG_THRESHOLD},${keys.join(',')}))`;
}

/**
 * The same descriptor as a `crypto-output` CBOR payload.
 *
 * The outer 308 tag is not written: the UR type string identifies it, exactly
 * as with crypto-psbt.
 */
export function cryptoOutputCbor(wallet: TestWallet): Uint8Array {
  const own = hdKey(
    wallet.accountNode.neutered() as never,
    wallet.fingerprint,
    wallet.accountPath,
  );

  if (wallet.walletType === 'p2wpkh') {
    return Uint8Array.from(encode(new Tagged(TAG_WPKH, own)));
  }

  const keys: Cbor[] = [
    own,
    ...wallet.cosigners.map((c) => hdKey(c.accountNode as never, c.fingerprint, wallet.accountPath)),
  ];
  const multi = new Map<number, Cbor>([
    [1, MULTISIG_THRESHOLD],
    [2, keys],
  ]);
  return Uint8Array.from(encode(new Tagged(TAG_WSH, new Tagged(TAG_SORTEDMULTI, multi))));
}

/** Serialised account key, re-exported so callers need one import. */
export { serializeExtendedPubkey };
