/**
 * Flow controller.
 *
 * One page, cards stacked top to bottom, each revealed as the previous one is
 * confirmed. Nothing about the transaction is configurable: wallet type, word
 * count, and transaction shape are all random, so a run cannot be tailored and
 * looks like ordinary spending on the device screen.
 */
// Must come first: dependencies reference the Node `Buffer` global at module
// scope, so the polyfill has to be installed before they are evaluated.
import './polyfills.js';
import './style.css';
import QRCode from 'qrcode';
import { cryptoRng } from './rng.js';
import { generateTest, type GeneratedTest } from './psbt.js';
import { createPsbtUrEncoder, createPsbtUrDecoder } from './ur.js';
import { mnemonicToSeedQrDigits, mnemonicWords } from './seedqr.js';
import { startScanner, type ScannerHandle } from './scanner.js';
import { compareSignatures, type ComparisonResult, type InputComparison } from './compare.js';
import * as bitcoin from 'bitcoinjs-lib';
import { Buffer } from 'buffer';
import { NETWORK, deriveKey } from './wallet.js';
import { signPsbtLocally } from './sign-psbt.js';

const cards = document.getElementById('cards')!;

/**
 * How long each animated UR frame is shown — 3 frames per second.
 *
 * Fountain encoding makes this forgiving: frames past the pure set are XOR
 * mixes rather than repeats, so a frame the camera misses costs a little extra
 * time rather than a full cycle waiting for that specific one to return.
 */
const FRAME_INTERVAL_MS = Math.round(1000 / 3);

let test: GeneratedTest | null = null;
let frameTimer: number | undefined;
let scanner: ScannerHandle | null = null;

function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Record<string, string> = {},
  ...children: (Node | string)[]
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v);
  children.forEach((c) => node.append(c));
  return node;
}

interface Card {
  section: HTMLElement;
  /** Everything below the heading. Content goes here so it can be collapsed. */
  body: HTMLElement;
  /**
   * Fold the card down to a one-line summary once its step is done, so the
   * step that now needs attention is the one on screen. Re-expandable, since
   * a user may need to show a QR to the device again.
   */
  collapse(summary: string): void;
}

function card(step: number, title: string, hint?: string): Card {
  const section = el('section', { class: 'card' });
  const heading = el('h2');
  const number = el('span', { class: 'step-number' }, String(step));
  heading.append(number, title);
  section.append(heading);

  const body = el('div', { class: 'card-body' });
  if (hint) body.append(el('p', { class: 'hint' }, hint));
  section.append(body);

  cards.append(section);
  section.scrollIntoView({ behavior: 'smooth', block: 'start' });

  return {
    section,
    body,
    collapse(summary: string) {
      if (section.classList.contains('is-collapsed')) return;
      section.classList.add('is-collapsed');
      number.classList.add('is-done');
      body.hidden = true;

      const toggle = el('button', { class: 'link', type: 'button' }, 'Show');
      const line = el('div', { class: 'card-summary' }, el('span', {}, summary));
      line.append(toggle);
      toggle.addEventListener('click', () => {
        const collapsed = section.classList.toggle('is-collapsed');
        body.hidden = collapsed;
        toggle.textContent = collapsed ? 'Show' : 'Hide';
        if (!collapsed) section.scrollIntoView({ behavior: 'smooth', block: 'start' });
      });
      section.append(line);
    },
  };
}

/**
 * What is being spent and what it costs.
 *
 * Deliberately plain: wallet type, fingerprint and derivation paths are
 * irrelevant to the person holding the phone and only make an ordinary-looking
 * transaction look technical. Shown twice — once when sending the transaction,
 * and again while approving it, so the device's own figures can be compared
 * against these without scrolling back.
 */
function transactionSummary(t: GeneratedTest): HTMLElement {
  const amounts = (values: number[]) =>
    values.map((v) => v.toLocaleString('en-US')).join(' · ') + ' sats';

  const facts = el('dl', { class: 'facts' });
  for (const [label, value] of [
    [t.inputs.length === 1 ? '1 input' : `${t.inputs.length} inputs`, amounts(t.inputs.map((i) => i.value))],
    [t.outputs.length === 1 ? '1 output' : `${t.outputs.length} outputs`, amounts(t.outputs.map((o) => o.value))],
    ['Fee', sats(t.fee)],
  ] as const) {
    facts.append(el('dt', {}, label), el('dd', {}, value));
  }
  return facts;
}

function sats(value: number): string {
  return `${value.toLocaleString('en-US')} sats`;
}

async function drawQr(target: HTMLElement, text: string, opts: QRCode.QRCodeRenderersOptions = {}) {
  const canvas = el('canvas');
  await QRCode.toCanvas(canvas, text, {
    errorCorrectionLevel: 'L',
    margin: 2,
    scale: 8,
    color: { dark: '#000000', light: '#ffffff' },
    ...opts,
  });
  target.replaceChildren(canvas);
}

/* ---------------------------------------------------------------- step 1 */

function renderIntro() {
  const step = card(1, 'Generate a test transaction');
  step.body.append(
    el(
      'p',
      { class: 'hint' },
      'This creates a throwaway seed and an unsigned mainnet PSBT without real ' +
        'funds. It\'ll use these to check the signatures your device returns ' +
        'against the ones a deterministic signer must produce. The airgapped ' +
        'signer does not know the PSBT does not have real funds.',
    ),
    el(
      'div',
      { class: 'callout warn' },
      'The seed generated here is for testing only. Never send funds to it.',
    ),
  );

  const button = el('button', {}, 'Generate test');
  button.addEventListener('click', () => {
    button.disabled = true;
    test = generateTest(cryptoRng());
    step.collapse('Test generated');
    renderPsbtCard(test);
  });
  step.body.append(button);
}

/* ---------------------------------------------------------------- step 2 */

function renderPsbtCard(t: GeneratedTest) {
  const step = card(2, 'Scan the unsigned transaction');

  step.body.append(transactionSummary(t));

  const frame = el('div', { class: 'qr-frame' });
  step.body.append(frame);

  const encoder = createPsbtUrEncoder(t.psbtBase64);

  // No caption under the QR. A frame counter would be misleading anyway: past
  // the pure fragments bc-ur emits fountain-coded mixes rather than repeats, so
  // there is no fixed sequence to count through.
  const showNextFrame = async () => {
    await drawQr(frame, encoder.next(), { scale: 6 });
  };

  window.clearInterval(frameTimer);
  void showNextFrame();
  if (encoder.totalParts > 1) {
    frameTimer = window.setInterval(() => void showNextFrame(), FRAME_INTERVAL_MS);
  }

  const next = el('button', {}, 'My device has scanned it');
  next.addEventListener('click', () => {
    window.clearInterval(frameTimer);
    next.disabled = true;
    const ins = `${t.inputs.length} input${t.inputs.length === 1 ? '' : 's'}`;
    const outs = `${t.outputs.length} output${t.outputs.length === 1 ? '' : 's'}`;
    step.collapse(`Transaction sent · ${ins}, ${outs}`);
    renderSeedCard(t);
  });
  step.body.append(next);
}

/* ---------------------------------------------------------------- step 3 */

function renderSeedCard(t: GeneratedTest) {
  const step = card(
    3,
    'Scan the test seed',
    'Load this seed onto the device as a SeedQR, then sign the transaction.',
  );

  step.body.append(
    el(
      'div',
      { class: 'callout warn' },
      'Test seed only — never send funds to it. The site needs to know the seed ' +
        'in order to recompute the signatures your device should produce.',
    ),
  );

  const frame = el('div', { class: 'qr-frame' });
  step.body.append(frame);
  void drawQr(frame, mnemonicToSeedQrDigits(t.wallet.mnemonic), { scale: 8 });
  step.body.append(
    el('p', { class: 'frame-status' }, `SeedSigner Standard SeedQR · ${t.wallet.wordCount} words`),
  );

  // The words are only a fallback for a device that cannot read the SeedQR, so
  // they stay hidden by default rather than sitting on screen the whole time.
  // <details> gives this keyboard and screen-reader behaviour for free.
  const words = el('ul', { class: 'words' });
  for (const { number, word } of mnemonicWords(t.wallet.mnemonic)) {
    const item = el('li');
    item.append(el('span', { class: 'n' }, `${number}.`), word);
    words.append(item);
  }

  const disclosure = el('details', { class: 'words-disclosure' });
  const label = el('summary', {}, `Show the ${t.wallet.wordCount} words`);
  disclosure.append(
    label,
    el(
      'p',
      { class: 'hint' },
      'Only needed if the device cannot scan the SeedQR — it can be typed in instead.',
    ),
    words,
  );
  disclosure.addEventListener('toggle', () => {
    label.textContent = `${disclosure.open ? 'Hide' : 'Show'} the ${t.wallet.wordCount} words`;
  });
  step.body.append(disclosure);

  const next = el('button', {}, 'Seed loaded — continue');
  next.addEventListener('click', () => {
    next.disabled = true;
    step.collapse('Seed loaded');
    renderApproveCard(t);
  });
  step.body.append(next);
}

/* ---------------------------------------------------------------- step 4 */

/**
 * Transaction details in the shape SeedSigner presents them.
 *
 * The device shows each recipient with its amount, then a "transaction math"
 * screen reconciling input value against what is sent, the fee, and the change.
 * Mirroring that layout means the figures can be compared line by line against
 * the device screen instead of mentally re-deriving them.
 */
function transactionDetails(t: GeneratedTest): HTMLElement {
  const n = (v: number) => v.toLocaleString('en-US');
  const panel = el('div', { class: 'tx-details' });

  const inputTotal = t.inputs.reduce((sum, i) => sum + i.value, 0);
  const sent = t.outputs.filter((o) => !o.isChange).reduce((sum, o) => sum + o.value, 0);
  const change = t.outputs.filter((o) => o.isChange).reduce((sum, o) => sum + o.value, 0);

  // Addresses are deliberately omitted: they are random, nothing is broadcast,
  // and the approval step tells the user to skip checking them.
  for (const output of t.outputs) {
    const row = el('div', { class: 'tx-out' });
    row.append(
      el('span', { class: 'tx-label' }, output.isChange ? 'Change' : 'Send'),
      el('span', { class: 'tx-amount' }, `${n(output.value)} sats`),
    );
    panel.append(row);
  }

  // The device reconciles these four numbers; showing the same arithmetic makes
  // a mismatch obvious rather than something to work out by hand.
  const math = el('dl', { class: 'tx-math' });
  const rows: [string, string][] = [
    ['Input value', n(inputTotal)],
    ['– Amount sent', n(sent)],
    ['– Fee', n(t.fee)],
  ];
  // Always shown, zero included, so the arithmetic visibly closes and matches
  // what the device displays rather than leaving the reader to infer it.
  rows.push(['= Change', n(change)]);
  for (const [label, value] of rows) {
    const isTotal = label.startsWith('=');
    math.append(
      el('dt', isTotal ? { class: 'total' } : {}, label),
      el('dd', isTotal ? { class: 'total' } : {}, value),
    );
  }

  panel.append(el('p', { class: 'tx-math-title' }, 'Transaction math'), math);
  return panel;
}

/**
 * Approving on the device.
 *
 * Signing is not one button on these devices — the transaction has to be
 * reviewed and confirmed screen by screen, and it is easy to leave the device
 * sitting on a review screen wondering why no signature appeared. The same
 * figures shown when the transaction was sent are repeated here so they can be
 * checked against the device's own display.
 */
function renderApproveCard(t: GeneratedTest) {
  const step = card(
    4,
    'Approve the transaction on your device',
    'Check these figures against the device screen, then approve. Wording differs by device; SeedSigner is named below.',
  );

  const list = el('ol', { class: 'steps' });
  for (const [action, detail] of [
    ['Open the transaction review', 'On SeedSigner: "Review Transaction".'],
    ['Step through the transaction math', 'The device totals should match the figures above.'],
    // The addresses belong to nobody and the transaction is never broadcast, so
    // there is nothing to verify here. Saying so saves the tedious part of the
    // review on a device with a small screen and a joystick.
    ['Skip the recipient checks', 'The addresses are random and this transaction is never broadcast, so they do not matter for this check.'],
    ['Approve and sign', 'The device then shows the signed transaction as an animated QR code.'],
  ] as const) {
    const item = el('li');
    item.append(el('strong', {}, action), el('span', { class: 'detail' }, detail));
    list.append(item);
  }
  step.body.append(transactionDetails(t), list);

  const next = el('button', {}, 'Signed — scan the result');
  next.addEventListener('click', () => {
    next.disabled = true;
    step.collapse('Transaction approved');
    renderScanCard(t);
  });
  step.body.append(next);
}

/* ---------------------------------------------------------------- step 5 */

function renderScanCard(t: GeneratedTest) {
  const step = card(
    5,
    'Scan the signed transaction',
    'Show the signed PSBT from your device to this camera. Animated QR codes are read frame by frame.',
  );

  const video = el('video', { playsinline: 'true' });
  const bar = el('progress', { max: '1', value: '0' });
  const status = el('p', { class: 'frame-status' }, 'Starting camera…');
  const error = el('div', { class: 'callout danger', hidden: 'hidden' });
  const restart = el('button', { class: 'secondary' }, 'Restart camera');
  step.body.append(video, bar, status, error, restart);

  const decoder = createPsbtUrDecoder();
  let finished = false;

  const finish = (signedPsbt: string) => {
    finished = true;
    scanner?.stop();
    scanner = null;
    video.remove();
    bar.remove();
    restart.remove();
    status.textContent = 'Signed transaction received.';
    step.collapse('Signed transaction received');
    renderResultCard(t, compareSignatures(t.psbtBase64, t.wallet, signedPsbt));
  };

  /**
   * Start (or restart) scanning.
   *
   * Recoverable failures are common — permission denied and then granted, the
   * camera held by another app, a device unplugged — and none of them should
   * force a page reload, which would discard the generated transaction and the
   * seed already loaded onto the signing device.
   */
  const start = async () => {
    if (finished) return;

    // Tear down any previous attempt first, or the old stream keeps the camera.
    scanner?.stop();
    scanner = null;

    // Partially accumulated fragments may be from an interrupted read; start
    // the reassembly clean so a stale part cannot block completion.
    decoder.reset();
    bar.value = 0;

    restart.disabled = true;
    error.hidden = true;
    status.textContent = 'Starting camera…';

    const handle = await startScanner(
      video,
      (text) => {
        if (finished) return;
        const progress = decoder.receive(text);
        if (progress.error) {
          error.hidden = false;
          error.textContent = progress.error;
          return;
        }
        error.hidden = true;
        bar.value = progress.progress;
        status.textContent = progress.expected
          ? `${progress.received} of ${progress.expected} frames`
          : `${progress.received} frames read`;
        if (progress.complete && progress.psbtBase64) finish(progress.psbtBase64);
      },
      (message) => {
        error.hidden = false;
        error.textContent = message;
        status.textContent = 'Camera unavailable.';
      },
    );

    scanner = handle;
    restart.disabled = false;
    if (status.textContent === 'Starting camera…') status.textContent = 'Looking for a QR code…';
  };

  restart.addEventListener('click', () => void start());
  void start();
}

/* ---------------------------------------------------------------- step 6 */

const OUTCOME_LABEL: Record<InputComparison['outcome'], [string, string]> = {
  match: ['Match', 'match'],
  'valid-but-different': ['Differs', 'diff'],
  invalid: ['Invalid', 'other'],
  missing: ['Missing', 'other'],
};

function renderResultCard(t: GeneratedTest, result: ComparisonResult) {
  const step = card(6, 'Result');
  const section = step.body;

  const banner = el('div', {
    class: `verdict ${
      result.verdict === 'pass' ? 'pass' : result.verdict === 'nondeterministic' ? 'fail' : 'inconclusive'
    }`,
  });
  banner.append(
    el(
      'p',
      { class: 'headline' },
      result.verdict === 'pass'
        ? 'Deterministic nonce confirmed'
        : result.verdict === 'nondeterministic'
          ? '⚠ NON-DETERMINISTIC NONCE'
          : 'Inconclusive',
    ),
    el('p', {}, result.summary),
  );
  section.append(banner);

  if (result.verdict === 'nondeterministic') {
    section.append(
      el(
        'div',
        { class: 'callout danger' },
        'This device produced valid signatures that differ from the deterministic ' +
          'result. Reusing or biasing an ECDSA nonce can expose the private key. ' +
          'Do not use this device with funds until the cause is understood.',
      ),
    );
  }

  const table = el('table');
  table.append(
    el(
      'tr',
      {},
      ...['Input', 'Path', 'Result', 'Grind', 'Signature'].map((h) => el('th', {}, h)),
    ),
  );
  for (const input of result.inputs) {
    const [label, tone] = OUTCOME_LABEL[input.outcome];
    const shown = input.actual ?? input.expected;
    const row = el('tr');
    row.append(
      el('td', {}, String(input.inputIndex)),
      el('td', {}, input.path),
      el('td', {}, el('span', { class: `tag ${tone}` }, label)),
      el('td', {}, String(input.grindCounter)),
      el('td', { class: 'sig' }, `${shown.slice(0, 16)}…${shown.slice(-8)}`),
    );
    table.append(row);
  }
  const scroll = el('div', { class: 'table-scroll' });
  scroll.append(table);
  section.append(scroll);

  const again = el('button', { class: 'secondary' }, 'Run another test');
  again.addEventListener('click', () => {
    window.clearInterval(frameTimer);
    scanner?.stop();
    cards.replaceChildren();
    test = null;
    renderIntro();
  });
  section.append(el('div', { class: 'button-row' }, again));
  void t;
}

/**
 * Development hook.
 *
 * The result card is the most important screen in the app and the hardest to
 * reach, since getting there normally requires a camera and a real signing
 * device. In dev builds only, this exposes a way to drive it directly and to
 * stand in for a device. Stripped from production by `import.meta.env.DEV`.
 */
if (import.meta.env.DEV) {
  const showResult = (signedPsbtBase64: string) => {
    if (!test) throw new Error('generate a test first');
    renderResultCard(test, compareSignatures(test.psbtBase64, test.wallet, signedPsbtBase64));
  };

  /**
   * Stand in for a signing device. 'honest' signs the way embit does; 'random'
   * uses a random nonce — the failure this whole tool exists to detect.
   */
  const simulateDevice = async (mode: 'honest' | 'random' = 'honest') => {
    if (!test) throw new Error('generate a test first');
    const current = test;

    if (mode === 'honest') {
      showResult(signPsbtLocally(current.psbtBase64, current.wallet).psbtBase64);
      return 'honest device simulated';
    }

    const { secp256k1 } = await import('@noble/curves/secp256k1');
    const psbt = bitcoin.Psbt.fromBase64(current.psbtBase64, { network: NETWORK });
    current.inputs.forEach((input, index) => {
      const key = deriveKey(current.wallet, input.change, input.index);
      psbt.signInput(index, {
        publicKey: key.pubkey,
        sign: (h: Buffer) =>
          Buffer.from(
            secp256k1
              .sign(new Uint8Array(h), key.privkey, { lowS: true, extraEntropy: true })
              .toCompactRawBytes(),
          ),
      });
    });
    showResult(psbt.toBase64());
    return 'random-nonce device simulated';
  };

  (window as unknown as Record<string, unknown>).__dnc = {
    get test() {
      return test;
    },
    showResult,
    simulateDevice,
  };
}

renderIntro();
