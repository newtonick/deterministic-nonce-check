import { describe, expect, it } from 'vitest';
import { mnemonicToSeedQrDigits, seedQrDigitsToMnemonic } from '../src/seedqr.js';
import { generateWallet } from '../src/wallet.js';
import { seededRng } from '../src/rng.js';

const CANONICAL_12 =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

describe('Standard SeedQR', () => {
  it('matches the canonical all-zero-entropy mnemonic', () => {
    // abandon is index 0, about is index 3.
    expect(mnemonicToSeedQrDigits(CANONICAL_12)).toBe('0'.repeat(44) + '0003');
  });

  it('produces 48 digits for 12 words and 96 for 24', () => {
    for (const wordCount of [12, 24] as const) {
      const wallet = generateWallet(seededRng('sq' + wordCount), { wordCount, walletType: 'p2wpkh' });
      const digits = mnemonicToSeedQrDigits(wallet.mnemonic);
      expect(digits).toHaveLength(wordCount * 4);
      // Digits-only is what lets the QR encoder pick numeric mode.
      expect(digits).toMatch(/^\d+$/);
      expect(seedQrDigitsToMnemonic(digits)).toBe(wallet.mnemonic);
    }
  });

  it('rejects unsupported word counts and unknown words', () => {
    expect(() => mnemonicToSeedQrDigits('abandon abandon')).toThrow(/12 or 24/);
    expect(() => mnemonicToSeedQrDigits(CANONICAL_12.replace('about', 'zzzz'))).toThrow(/wordlist/);
  });
});
