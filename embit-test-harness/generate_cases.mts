/**
 * Stage 1 of the determinism harness: generate test cases with the site's own
 * modules, sign them with the site's own embit-compatible signer, and write
 * everything out for the Python side to check against real embit.
 *
 * Cases are stratified rather than purely random. 100 random draws would very
 * likely cover the space, but "very likely" is the wrong standard for the test
 * that underwrites the whole tool — every combination of word count, wallet
 * type, input count, and output count is covered explicitly.
 *
 * Usage: tsx embit-test-harness/generate_cases.mts [--count 100] [--seed <string>]
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateTest, type GenerateOptions } from '../src/psbt.js';
import { signPsbtLocally } from '../src/sign-psbt.js';
import { seededRng } from '../src/rng.js';
import type { WalletType, WordCount } from '../src/wallet.js';
import { walletDescriptor } from '../src/descriptor.js';

const here = dirname(fileURLToPath(import.meta.url));

function arg(name: string, fallback: string): string {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 && process.argv[i + 1] ? process.argv[i + 1] : fallback;
}

const count = Number(arg('count', '100'));
const seed = arg('seed', `run-${Date.now()}`);

/** Every combination that matters, cycled so a run of N covers all of them. */
function stratum(i: number): GenerateOptions {
  const walletTypes: WalletType[] = ['p2wpkh', 'p2wsh-2of3'];
  const wordCounts: WordCount[] = [12, 24];
  return {
    walletType: walletTypes[i % 2],
    wordCount: wordCounts[Math.floor(i / 2) % 2],
    inputCount: (Math.floor(i / 4) % 3) + 1,
    outputCount: (Math.floor(i / 12) % 2) + 1,
  };
}

const cases = [];
for (let i = 0; i < count; i++) {
  // Each case gets its own derived seed, so one case's draw count cannot shift
  // every later case when the generator changes.
  const rng = seededRng(`${seed}/${i}`);
  const test = generateTest(rng, stratum(i));
  const signed = signPsbtLocally(test.psbtBase64, test.wallet);

  if (signed.signatures.length !== test.inputs.length) {
    throw new Error(
      `case ${i}: signed ${signed.signatures.length} of ${test.inputs.length} inputs — ` +
        `the wallet could not match its own fingerprint, which means the generated ` +
        `PSBT would not be signable by a real device either`,
    );
  }

  cases.push({
    index: i,
    seed: `${seed}/${i}`,
    mnemonic: test.wallet.mnemonic,
    word_count: test.wallet.wordCount,
    wallet_type: test.wallet.walletType,
    account_path: test.wallet.accountPath,
    master_fingerprint: test.wallet.fingerprint.toString('hex'),
    descriptor: walletDescriptor(test.wallet),
    input_count: test.inputs.length,
    output_count: test.outputs.length,
    has_change: test.outputs.some((o) => o.isChange),
    derivation_paths: test.inputs.map((i2) => i2.path),
    unsigned_psbt: test.psbtBase64,
    js_signed_psbt: signed.psbtBase64,
    js_signatures: signed.signatures.map((s) => ({
      input_index: s.inputIndex,
      path: s.path,
      pubkey: s.pubkey.toString('hex'),
      signature: s.signature.toString('hex'),
      grind_counter: s.grindCounter,
      der_length: s.derLength,
    })),
  });
}

const outDir = resolve(here, 'cases');
mkdirSync(outDir, { recursive: true });
const outFile = resolve(outDir, 'cases.json');
writeFileSync(outFile, JSON.stringify({ seed, count, cases }, null, 2));

const grinds = cases.flatMap((c) => c.js_signatures).filter((s) => s.grind_counter > 0).length;
const totalSigs = cases.reduce((n, c) => n + c.js_signatures.length, 0);
console.log(`generated ${cases.length} cases (seed: ${seed})`);
console.log(`  ${totalSigs} signatures, ${grinds} required grinding`);
console.log(`  single-sig: ${cases.filter((c) => c.wallet_type === 'p2wpkh').length}` +
  `, multisig: ${cases.filter((c) => c.wallet_type === 'p2wsh-2of3').length}`);
console.log(`  wrote ${outFile}`);
