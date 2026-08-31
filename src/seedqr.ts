/**
 * SeedSigner Standard SeedQR.
 *
 * Format, per SeedSigner's docs/qr_formats.md: each BIP39 word becomes its
 * zero-indexed position in the English wordlist, zero-padded to four digits,
 * all concatenated. 12 words produce 48 digits, 24 words produce 96.
 *
 * The digits-only payload matters: it lets the QR encoder use numeric mode,
 * which is what keeps a 96-digit seed inside a QR version the device's camera
 * can resolve. Encoding the same string as bytes would work but produce a
 * denser code than SeedSigner expects.
 */
import { wordlists } from 'bip39';

const english = wordlists.english;

export const SEEDQR_DIGITS_PER_WORD = 4;

/** Convert a BIP39 mnemonic to its Standard SeedQR digit string. */
export function mnemonicToSeedQrDigits(mnemonic: string): string {
  const words = mnemonic.trim().split(/\s+/);
  if (words.length !== 12 && words.length !== 24) {
    throw new Error(`SeedQR supports 12 or 24 words, got ${words.length}`);
  }
  return words
    .map((word) => {
      const index = english.indexOf(word);
      if (index < 0) throw new Error(`"${word}" is not in the English BIP39 wordlist`);
      return index.toString().padStart(SEEDQR_DIGITS_PER_WORD, '0');
    })
    .join('');
}

/** Inverse of the above, so the format can be verified rather than assumed. */
export function seedQrDigitsToMnemonic(digits: string): string {
  if (!/^\d+$/.test(digits) || digits.length % SEEDQR_DIGITS_PER_WORD !== 0) {
    throw new Error('SeedQR payload must be a multiple of 4 digits');
  }
  const words: string[] = [];
  for (let i = 0; i < digits.length; i += SEEDQR_DIGITS_PER_WORD) {
    const index = Number(digits.slice(i, i + SEEDQR_DIGITS_PER_WORD));
    const word = english[index];
    if (!word) throw new Error(`no BIP39 word at index ${index}`);
    words.push(word);
  }
  return words.join(' ');
}

/** The mnemonic split into numbered words, for the on-screen fallback list. */
export function mnemonicWords(mnemonic: string): { number: number; word: string }[] {
  return mnemonic
    .trim()
    .split(/\s+/)
    .map((word, i) => ({ number: i + 1, word }));
}
