/**
 * Browser shim for `sha.js`, used only by @ngraveio/bc-ur.
 *
 * The real package builds on Node's stream module via cipher-base, which Vite
 * cannot bundle for the browser — it externalises `stream` and `events` into
 * stubs that throw the moment bc-ur hashes anything. Since bc-ur's fountain
 * encoder hashes on every frame, that would break animated QR codes outright.
 *
 * @noble/hashes is already a dependency (via @noble/curves), is dependency-free,
 * and produces identical digests, so aliasing to it removes the entire
 * readable-stream tree rather than polyfilling around it.
 */
// Explicit import: `Buffer` is a Node global but not a browser one, and
// bitcoinjs-lib's API is Buffer-based throughout.
import { Buffer } from 'buffer';
import { sha256 } from '@noble/hashes/sha256';
import { sha512 } from '@noble/hashes/sha512';

type Algorithm = 'sha256' | 'sha512';

const IMPLEMENTATIONS = {
  sha256,
  sha512,
} satisfies Record<Algorithm, (input: Uint8Array) => Uint8Array>;

class Hash {
  private chunks: Uint8Array[] = [];

  constructor(private readonly algorithm: Algorithm) {}

  update(data: Uint8Array | string): this {
    this.chunks.push(typeof data === 'string' ? new TextEncoder().encode(data) : data);
    return this;
  }

  digest(encoding?: 'hex'): Buffer | string {
    const total = this.chunks.reduce((n, c) => n + c.length, 0);
    const joined = new Uint8Array(total);
    let offset = 0;
    for (const chunk of this.chunks) {
      joined.set(chunk, offset);
      offset += chunk.length;
    }
    const digest = Buffer.from(IMPLEMENTATIONS[this.algorithm](joined));
    return encoding === 'hex' ? digest.toString('hex') : digest;
  }
}

export default function shaJs(algorithm: string): Hash {
  const normalised = algorithm.toLowerCase().replace('-', '') as Algorithm;
  if (!(normalised in IMPLEMENTATIONS)) {
    throw new Error(`sha.js shim does not implement ${algorithm}`);
  }
  return new Hash(normalised);
}
