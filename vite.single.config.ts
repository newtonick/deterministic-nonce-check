/**
 * Single-file build.
 *
 * Produces one self-contained .html that runs from the local filesystem, with
 * no server and no network. That matches how this tool is likely to be used:
 * on a machine kept away from the internet, next to the signing device.
 *
 * Two things make file:// work. The output is an IIFE rather than an ES module,
 * because a `<script type="module">` is fetched under CORS rules that file://
 * cannot satisfy. And every asset is inlined, because a relative <script src>
 * would be a cross-origin fetch from a file:// page.
 */
import type { Plugin } from 'vite';
import { defineConfig, mergeConfig } from 'vite';
import base from './vite.config';

const OUTPUT_NAME = 'deterministic-nonce-check.html';

function inlineEverything(): Plugin {
  return {
    name: 'inline-everything',
    enforce: 'post',
    generateBundle(_options, bundle) {
      const files = Object.values(bundle);
      const js = files.find((f) => f.type === 'chunk' && f.isEntry);
      const css = files.find((f) => f.type === 'asset' && f.fileName.endsWith('.css'));
      const html = files.find((f) => f.type === 'asset' && f.fileName.endsWith('.html'));
      if (!html || html.type !== 'asset' || !js || js.type !== 'chunk') return;

      // A literal </script> inside a string would end the tag early. Replacer
      // functions are used throughout so that $-sequences in minified code are
      // not treated as replacement patterns.
      const code = js.code.replace(/<\/script/gi, '<\\/script');
      let source = String(html.source);

      // Placement matters. Vite emits the script in <head>, where a module is
      // deferred until the document is parsed. A classic script is not: inline
      // scripts ignore `defer`, so left in <head> it runs before <body> exists
      // and every getElementById returns null. Moving it to the end of <body>
      // restores the ordering the module build got for free.
      source = source.replace(/<script[^>]*\ssrc="[^"]*"[^>]*><\/script>\s*/, '');
      source = source.replace('</body>', () => `<script>${code}</script>\n</body>`);
      if (css && css.type === 'asset') {
        source = source.replace(
          /<link[^>]*rel="stylesheet"[^>]*>/,
          () => `<style>${String(css.source)}</style>`,
        );
        delete bundle[css.fileName];
      }
      delete bundle[js.fileName];

      html.source = source;
      html.fileName = OUTPUT_NAME;
    },
  };
}

export default mergeConfig(
  base,
  defineConfig({
    plugins: [inlineEverything()],
    define: { __SINGLE_FILE__: 'true' },
    build: {
      outDir: 'dist-single',
      emptyOutDir: true,
      assetsInlineLimit: Number.MAX_SAFE_INTEGER,
      cssCodeSplit: false,
      rollupOptions: {
        output: {
          format: 'iife',
          inlineDynamicImports: true,
          entryFileNames: 'bundle.js',
          assetFileNames: '[name][extname]',
        },
      },
    },
  }),
);
