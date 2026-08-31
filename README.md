# Deterministic Nonce Check

A static site that verifies an airgapped QR Bitcoin signing device derives its
ECDSA nonces deterministically.

## Why this exists

Every ECDSA signature needs a secret random value, the nonce `k`. It has an
unforgiving property: if a signer ever reuses a nonce across two signatures, or
generates nonces with a biased RNG, **the private key can be recovered from the
signatures alone**. This is not theoretical — it is how the Sony PS3 signing key
leaked, and how a series of Android wallets were drained in 2013.

The defence is to stop using randomness at all. [RFC 6979][rfc6979] derives the
nonce deterministically from the private key and the message, so the same input
always yields the same signature and there is no RNG to get wrong. Every
reputable Bitcoin signer does this.

The catch is that you cannot tell from the outside. A signature made with a
badly generated random nonce is *perfectly valid* and verifies like any other.
Your wallet accepts it, the network accepts it, and nothing looks wrong until
someone recovers your key.

This tool checks it directly. Because the site generates the seed itself, it can
compute exactly what signature a correct device must return, and compare byte
for byte.

[rfc6979]: https://datatracker.ietf.org/doc/html/rfc6979

### Dark Skippy

The sharpest reason to care is [Dark Skippy][darkskippy].

Malicious signing-device firmware does not need to steal your seed over a
network — it can publish it on the blockchain. Instead of sampling nonces
randomly, the compromised firmware derives them from the seed itself: the first
8 bytes of a 12-word seed become the nonce for one signature, the remaining 8
bytes the nonce for the next. An attacker watching the chain recovers those
low-entropy nonces with Pollard's Kangaroo algorithm and reassembles the seed.

Two signatures are enough to leak a full 12-word seed, and the signatures are
valid and impractical to detect forensically. Nothing about the transaction
looks wrong. It is not a flaw in any particular product — it applies to any
signing device running firmware you cannot verify.

This check does not look for Dark Skippy specifically. It checks the property
that makes such an attack impossible: that the nonce is derived from the seed
*and* the message, so the same inputs always produce the same signature. That
is the whole reason for a deterministic nonce — a deterministic nonce means a
deterministic signature, which is something you can verify from the outside.

If this check fails, assume the firmware or software on your signing device has
been tampered with.

[darkskippy]: https://darkskippy.com

## How it works

1. **Generate.** The site creates a throwaway BIP39 seed and a random unsigned
   mainnet PSBT spending from it.
2. **Send.** The PSBT is displayed as an animated `ur:crypto-psbt` QR code for
   the device to scan.
3. **Load.** The seed is displayed as a SeedSigner Standard SeedQR. The device
   loads it and signs. The mnemonic words stay hidden behind a toggle — they are
   only a fallback for a device that cannot scan the QR.
4. **Compare.** The signed PSBT is scanned back through the camera. The site
   recomputes the expected signatures locally and compares them.

Each step folds down to a one-line summary once it is done, so the step that
needs attention is the one on screen. A collapsed step can be reopened if a QR
needs showing to the device again.

The transaction does not need to be valid against the chain — an airgapped
signer has no chain state and cannot tell the difference. It is randomised in
shape, amounts, and addresses so that a run looks like ordinary spending rather
than an obvious probe.

## The critical detail: embit does not use plain RFC 6979

SeedSigner, Krux, and several other signers are built on [embit][embit]. embit
does not stop at RFC 6979 — it **grinds for a low R value**. From
`embit/ec.py`:

```python
def sign(self, msg_hash, grind=True) -> Signature:
    sig = Signature(secp256k1.ecdsa_sign(msg_hash, self._secret))
    if grind:
        counter = 1
        while len(sig.serialize()) > 70:
            sig = Signature(secp256k1.ecdsa_sign(
                msg_hash, self._secret, None, counter.to_bytes(32, "little")))
            counter += 1
            if counter > 200:
                break
    return sig
```

If the DER encoding exceeds 70 bytes — meaning `r` needs a leading zero byte —
it re-signs with a counter mixed in as extra entropy and tries again. This saves
a byte of transaction weight, and it is still fully deterministic.

It also means **a signer that stops after plain RFC 6979 disagrees with embit
about half the time.** Roughly 50% of sighashes need at least one grind
iteration. Any tool that compares against unground RFC 6979 would report working
hardware as broken on every other signature. Reproducing this loop exactly is
the core of this project, and it is what the test suite exists to guarantee.

The nonce is reproducible in JavaScript because the seed material lines up byte
for byte: libsecp256k1's default nonce function seeds HMAC-DRBG with
`key32 || msg32 || data32`, and `@noble/curves` builds
`int2octets(d) || int2octets(h1) || extraEntropy` — the same order and the same
lengths.

[embit]: https://github.com/diybitcoinhardware/embit

## Looking like a Sparrow transaction

The probe is only useful if SeedSigner cannot recognise it, so the target is
not "a plausible transaction" in the abstract — it is **a PSBT indistinguishable
from one Sparrow produces for QR airgapped signing**, since that is what
SeedSigner receives in the field.

Generated PSBTs have been diffed field-for-field against a real Sparrow mainnet
PSBT:

| Field | Sparrow | Generated |
| --- | --- | --- |
| Global map | `unsignedTx`, `globalXpub` | same |
| `PSBT_GLOBAL_XPUB` | account key with origin | same (all three keys for multisig) |
| Transaction version | 2 | same |
| `nSequence` | `0xFFFFFFFD` (RBF) | same |
| `nLockTime` | current tip | same, estimated from the clock |
| `PSBT_IN_SIGHASH_TYPE` | explicit `SIGHASH_ALL` | same |
| Input fields | `witness_utxo`, `bip32_derivation` (+`witness_script` for multisig) | same |
| `PSBT_IN_NON_WITNESS_UTXO` | present in the reference | omitted — the reference wallet was not configured as airgapped QR; see below |

### Why `non_witness_utxo` is omitted

Sparrow decides whether to include a full previous transaction per input from
the **wallet's configured device type**. A wallet set up for airgapped QR
signing — a SeedSigner keystore — strips them, because they dominate the
payload and every byte costs animated QR frames. A wallet configured for a
USB device such as Trezor or Ledger keeps them, since those devices have
required them since the 2020 segwit fee attack.

Generated PSBTs therefore omit `non_witness_utxo`, matching what SeedSigner
actually receives.

The reference PSBT above *does* carry it, because it was exported from a wallet
that was not configured as airgapped QR. That is the only field where the two
differ, and the difference comes from the reference wallet's configuration
rather than from the generator.

Omitting it also roughly halves the animated QR: a three-input PSBT is about
9 frames instead of 14.

Note also that both outputs in the reference carry `bip32_derivation`, because
it happened to be a self-send. A payment to a third party has a derivation only
on the change output, which is what is generated here.

### Animated QR transport

The PSBT is sent as UR2 `ur:crypto-psbt`, the same transport Sparrow uses.
Past the pure fragments the sequence never repeats: each frame is a
fountain-coded XOR mix of several fragments, so the device finishes from
whatever it happens to catch rather than waiting on one frame it keeps missing.

Frames advance at 3 per second. Fountain encoding makes the rate forgiving: a
frame the camera misses costs a little extra time rather than a full cycle
waiting for that specific one to come back around. The rate is
`FRAME_INTERVAL_MS` in `src/main.ts`; the scanner samples at 10 Hz, well above
the display rate.

No counter is shown beneath the QR. Because the frames past the pure set are
fountain mixes rather than repeats, there is no fixed sequence to count through
and a counter would only mislead.

### Statistical tells

A sweep of generated transactions caught several giveaways, all since fixed:

| Tell | Fix |
| --- | --- |
| Change always the last output (100%) | Randomise its position |
| `nLockTime` in a fixed historical range | Derive from the estimated current tip |
| Sequences mixed within one transaction (30%) | One sequence per transaction |
| Derivation indices spread uniformly over the gap limit | Cluster around a recently used base |

`test/fingerprint.test.ts` enforces all of this, so a future change cannot
quietly reintroduce a fingerprint.

One pattern remains by design: multisig transactions never include change, so
across many runs a multisig probe never produces one. This follows from the
no-change decision above and is not detectable within any single transaction.

## Interpreting the result

| Result | Meaning |
| --- | --- |
| **Deterministic nonce confirmed** | Every signature is byte-identical to the expected one. |
| **⚠ Non-deterministic nonce** | Signatures are *valid* but differ. This is the real failure: the device is not deriving nonces the way embit does. Stop using it with funds until you know why. |
| **Inconclusive** | Signatures did not verify, were missing, or the scanned PSBT was for a different transaction. Almost always a wrong seed or an incomplete scan — a setup problem, not a nonce problem. |

The distinction between the last two matters. Reporting a bad scan as a nonce
failure would frighten people about working hardware, so the two are kept
strictly apart.

## Architecture

```
src/
  embit-sign.ts   RFC 6979 + embit's low-R grind loop      <- the heart
  wallet.ts       throwaway seeds, P2WPKH and 2-of-3 P2WSH
  psbt.ts         random unsigned PSBT generation
  sign-psbt.ts    signs a PSBT with the embit-compatible signer
  compare.ts      expected vs returned signatures, and the verdict
  ur.ts           animated ur:crypto-psbt encode / multi-frame decode
  seedqr.ts       SeedSigner Standard SeedQR
  scanner.ts      camera capture (BarcodeDetector, jsQR fallback)
  rng.ts          crypto randomness, plus a seeded stream for tests
  main.ts         the card-stack flow
  polyfills.ts    Buffer/process globals the Bitcoin libraries expect

test/                 unit tests (vitest)         -> npm test
embit-test-harness/   cross-check against embit   -> make test
```

The two test trees are separate on purpose: `test/` checks units in isolation,
while `embit-test-harness/` checks this implementation against the reference
one.

Responsibilities are split deliberately:

- **bitcoinjs-lib** builds, serialises, and parses PSBTs, constructs scripts and
  addresses, and computes BIP143 sighashes. Hand-rolling BIP174 or BIP143 would
  be a large bug surface, and a bug there would make working hardware look
  broken — the worst possible failure for a verification tool.
- **`@noble/curves`** produces the signature itself, with embit's nonce rule.

The seam between them is bitcoinjs-lib's `Signer` interface: it computes the
sighash, calls `sign()`, and places the result. So the sighash machinery stays
in reviewed library code, and the only thing this project owns is the nonce.

`wallet.ts`, `psbt.ts`, `sign-psbt.ts`, and `embit-sign.ts` are DOM-free so the
Node test harness can import them directly and test the same code the browser
runs.

## Testing

The correctness claim is that the JS signer agrees with embit exactly, so the
primary test checks precisely that — against real embit, not against a
reimplementation or a checked-in vector file.

```
make test          # venv + 100 stratified cases + pytest
make test COUNT=500
npm test           # unit tests (signer, SeedQR, UR, comparison)
```

`make test` runs three stages:

1. `embit-test-harness/generate_cases.mts` builds N cases **using the site's own modules** and
   signs them with the site's own signer.
2. `embit-test-harness/sign_with_embit.py` signs the same PSBTs with real embit, walking the
   same path SeedSigner does (`mnemonic_to_seed` → `HDKey.from_seed` →
   `PSBT.parse` → `sign_with`). It contains no nonce logic of its own.
3. `embit-test-harness/test_determinism.py` asserts every signed PSBT is byte-identical.

Cases are **stratified rather than random**: every combination of word count,
wallet type, input count, and output count is covered explicitly, because "100
random draws probably covered it" is the wrong standard for the test the whole
tool rests on.

Two things the harness deliberately guards:

- **Vacuous passes.** If embit cannot match the master fingerprint it signs
  nothing, both sides come back unsigned, and a naive equality check would pass
  while proving nothing. The test asserts each case actually produced a
  signature per input.
- **Backend drift.** embit falls back to a pure-Python secp256k1 when the native
  library is missing. The harness prints which backend loaded, because a run
  against the fallback is testing something subtly different from what ships on
  devices.

Reproduce a failing case with the seed it prints:

```
npx tsx embit-test-harness/generate_cases.mts --count 100 --seed <seed-from-failure>
```

## Dependencies

All dependencies are pinned to exact versions — no `^` ranges — in both
`package.json` and `embit-test-harness/requirements.txt`. `package-lock.json`
additionally pins the full transitive tree (292 packages) with integrity
hashes. Install with `npm ci` rather than `npm install` to get exactly the
locked tree and fail loudly if it has drifted.

For a tool whose whole purpose is verifying cryptographic behaviour, a silent
minor-version bump in a signing dependency is precisely the kind of change that
should not arrive unnoticed. Two of the pins are load-bearing:

- **`bitcoinjs-lib` 6.x** takes `value` as a `number` in satoshis; 7.x switched
  to `bigint` and reshaped the PSBT API.
- **`@noble/curves` 1.x** exposes `sign(...).toDERRawBytes()` and the
  `extraEntropy` option the embit signer depends on; 2.x renamed these.

After changing any dependency, re-run `make test`. Agreement with embit is the
property that matters, and it is not something a type-checker can confirm.

## Development

```
npm install
npm run dev        # http://localhost:5173, reachable on the LAN for phone testing
npm run build      # -> dist/, a plain folder of static files
npm run preview
```

In dev builds only, `window.__dnc.simulateDevice('honest' | 'random')` stands in
for a signing device so every result screen can be reached without hardware. It
is stripped from production builds.

### Deployment

`dist/` is entirely self-contained: three files, no CDN, no external fonts, and
no network requests after load. Asset paths are relative (`./assets/...`), so
the same build works at a domain root or under a subpath —
`example.com/` and `example.com/deterministic-nonce-check/` both work with no
rebuild or configuration.

**The camera requires HTTPS.** Browsers only grant camera access on a secure
origin (or `localhost`), so the site must be served over TLS to reach the
signature-scanning step. Any static host with a certificate works.

#### nginx

Build and copy the output:

```
npm run build
sudo mkdir -p /var/www/deterministic-nonce-check
sudo cp -r dist/* /var/www/deterministic-nonce-check/
```

Serving at a domain root:

```nginx
server {
    listen 80;
    listen [::]:80;
    server_name example.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    server_name example.com;

    ssl_certificate     /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;

    root /var/www/deterministic-nonce-check;
    index index.html;

    # The bundle is ~745 kB and compresses to ~250 kB.
    gzip on;
    gzip_types text/css application/javascript;
    gzip_min_length 1024;

    # Camera access must stay permitted. Many hardening templates set
    # "camera=()", which silently breaks the signature-scanning step.
    add_header Permissions-Policy "camera=(self), microphone=(), geolocation=()" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "no-referrer" always;
    # The page is fully self-contained, so this can be strict. connect-src
    # 'none' enforces that nothing is ever sent anywhere.
    add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; media-src 'self' blob:; connect-src 'none'; object-src 'none'; base-uri 'self'; form-action 'none'; frame-ancestors 'none'" always;

    # Filenames are content-hashed, so they can be cached indefinitely.
    location /assets/ {
        expires 1y;
        add_header Cache-Control "public, immutable" always;
        # Repeated because add_header in a location block discards the ones
        # inherited from the server block.
        add_header Permissions-Policy "camera=(self), microphone=(), geolocation=()" always;
        add_header X-Content-Type-Options "nosniff" always;
    }

    # index.html must not be cached, or a redeploy keeps serving the old build.
    location = /index.html {
        add_header Cache-Control "no-cache" always;
    }

    location / {
        try_files $uri $uri/ =404;
    }
}
```

To serve under a subpath instead, use `alias` — no rebuild is needed, since
asset paths are relative:

```nginx
location /deterministic-nonce-check/ {
    alias /var/www/deterministic-nonce-check/;
    index index.html;
    try_files $uri $uri/ =404;
}
```

Notes:

- **No SPA fallback.** This is a single page with no client-side routing, so
  `try_files ... =404` is correct; rewriting every path to `index.html` would
  only mask mistakes.
- **`camera=(self)` matters.** Without it — or with a blanket `camera=()` from a
  hardening template — steps 1 to 3 work and step 4 fails with "no camera",
  which is a confusing way to discover a header problem.
- The CSP above was checked against the built app: the full flow runs with zero
  violations. `connect-src 'none'` is safe precisely because the page never
  makes a network request after load.
- Get certificates with `sudo certbot --nginx -d example.com`. Reload with
  `sudo nginx -t && sudo systemctl reload nginx`.

## Security

- Seeds generated here are for testing only. **Never send funds to them.** The
  site can only verify determinism *because* it knows the seed.
- Everything runs locally in the browser. Nothing is uploaded.
- A pass means the device produced the expected signatures for the seed and
  transaction tested. It is evidence about this device and this firmware, not a
  general proof of correctness.

## Scope

- Mainnet, native segwit only: P2WPKH (`m/84'/0'/0'`) and 2-of-3 P2WSH
  (`m/48'/0'/0'/2'`, `sortedmulti`).
- Multisig transactions never include a change output, so no wallet descriptor
  registration is needed. `multisigDescriptor()` exists in `wallet.ts` should a
  device turn out to require registration before it will sign.
- Transactions have 1-3 inputs, 1-2 outputs, and spend a total between 50,000
  and 20,000,000 sats.
- Transport is UR2 `ur:crypto-psbt` in both directions. A device set to emit
  base64 or Specter-style QRs is detected and named, rather than silently
  failing to scan.
