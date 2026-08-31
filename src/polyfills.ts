/**
 * Node globals that bitcoinjs-lib and its dependencies expect.
 *
 * Several of them reference the `Buffer` global directly at module scope rather
 * than importing it, so it must exist before those modules are evaluated. ES
 * module evaluation follows import order, which is why this is the very first
 * import in main.ts — importing it later would run too late to help.
 */
import { Buffer as BufferPolyfill } from 'buffer';

declare global {
  // eslint-disable-next-line no-var
  var Buffer: typeof BufferPolyfill;
}

if (typeof globalThis.Buffer === 'undefined') {
  globalThis.Buffer = BufferPolyfill;
}

// A few dependencies probe `process.env` or `process.browser` at module scope.
// Only the handful of fields they actually touch are provided — pulling in a
// full process polyfill would add weight for no benefit.
if (typeof globalThis.process === 'undefined') {
  // Cast: @types/node types this as the full Node `Process`, which a browser
  // shim has no business implementing.
  (globalThis as Record<string, unknown>).process = {
    env: {},
    browser: true,
    version: '',
    nextTick: (fn: () => void) => queueMicrotask(fn),
  };
}

export {};
