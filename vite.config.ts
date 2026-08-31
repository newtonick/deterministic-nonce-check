import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vite';

export default defineConfig({
  // Relative asset paths so dist/ is hostable at any domain or subpath.
  base: './',
  resolve: {
    alias: [
      {
        // bc-ur pulls sha.js -> cipher-base -> readable-stream, which Vite can
        // only externalise into stubs that throw in the browser. The shim is a
        // dependency-free @noble/hashes equivalent producing identical digests.
        find: /^sha\.js$/,
        replacement: fileURLToPath(new URL('./src/shims/sha.js.ts', import.meta.url)),
      },
      {
        // bip39 eagerly requires all ten BIP39 language wordlists (~324 kB).
        // This site only generates and reads English seeds, and SeedQR is
        // defined against the English list, so the rest are dead weight.
        find: /^\.\/wordlists\/(?!english)[a-z_]+\.json$/,
        replacement: fileURLToPath(new URL('./src/shims/empty-wordlist.json', import.meta.url)),
      },
    ],
  },
  define: {
    // bitcoinjs-lib and its deps reach for `global` in a few places.
    global: 'globalThis',
  },
  build: {
    target: 'es2020',
    // Everything self-hosted: no CDN, no external font or script host.
    assetsInlineLimit: 0,
  },
  server: {
    host: true, // reachable from another device on the LAN
  },
  preview: {
    host: true,
  },
});
