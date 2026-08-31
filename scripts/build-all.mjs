/**
 * Build both artifacts and stage the offline one for download.
 *
 * The hosted site and the offline single file are built from the same commit,
 * so what you download is the same code the page you downloaded it from is
 * running. A checksum is written beside it: this is a file people are invited
 * to run offline against real signing hardware, so being able to confirm it is
 * the published build matters.
 */
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { copyFileSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const run = (...args) => execFileSync('npx', args, { cwd: root, stdio: 'inherit' });

run('vite', 'build');
run('vite', 'build', '--config', 'vite.single.config.ts');

const NAME = 'deterministic-nonce-check.html';
const source = resolve(root, 'dist-single', NAME);
const target = resolve(root, 'dist', NAME);
copyFileSync(source, target);

const bytes = readFileSync(target);
const digest = createHash('sha256').update(bytes).digest('hex');
// sha256sum format, so `shasum -a 256 -c` can verify it directly.
writeFileSync(`${target}.sha256`, `${digest}  ${NAME}\n`);

console.log(`\noffline build staged for download:`);
console.log(`  dist/${NAME}  ${(bytes.length / 1024).toFixed(0)} kB`);
console.log(`  sha256 ${digest}`);
