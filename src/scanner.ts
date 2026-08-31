/**
 * Camera QR scanning.
 *
 * Uses the native BarcodeDetector where it exists (much faster on phones) and
 * falls back to jsQR on a downscaled canvas everywhere else, notably iOS Safari.
 *
 * The scan loop is deliberately throttled. Decoding on every animation frame
 * saturates the main thread — a full-resolution `getImageData` forces a
 * GPU-to-CPU readback each time — and Chrome responds by stalling the video
 * pipeline, which shows up as the preview going black after a second or two.
 * Ten scans a second is far more than enough to catch animated QR frames that
 * change every 500 ms.
 */
import jsQR from 'jsqr';

/** ~10 scans/sec. Animated frames change every 500 ms, so this is plenty. */
const SCAN_INTERVAL_MS = 100;

/** Longest edge used for jsQR. Full sensor resolution is wasted work. */
const MAX_ANALYSIS_EDGE = 640;

/** Consecutive decode failures before the problem is surfaced rather than hidden. */
const FAILURE_REPORT_THRESHOLD = 30;

export interface ScannerHandle {
  stop(): void;
}

interface BarcodeDetectorLike {
  detect(source: CanvasImageSource): Promise<{ rawValue: string }[]>;
}

declare global {
  interface Window {
    BarcodeDetector?: {
      new (options?: { formats: string[] }): BarcodeDetectorLike;
      getSupportedFormats?(): Promise<string[]>;
    };
  }
}

async function createDetector(): Promise<BarcodeDetectorLike | null> {
  if (!window.BarcodeDetector) return null;
  try {
    const formats = (await window.BarcodeDetector.getSupportedFormats?.()) ?? [];
    if (formats.length && !formats.includes('qr_code')) return null;
    return new window.BarcodeDetector({ formats: ['qr_code'] });
  } catch {
    return null;
  }
}

export async function startScanner(
  video: HTMLVideoElement,
  onResult: (text: string) => void,
  onError: (message: string) => void,
): Promise<ScannerHandle> {
  let stopped = false;
  let stream: MediaStream | null = null;

  if (!navigator.mediaDevices?.getUserMedia) {
    onError(
      'This browser will not give the page a camera. Note that camera access ' +
        'requires HTTPS (or localhost).',
    );
    return { stop: () => {} };
  }

  // Safari on desktop rejects facingMode: 'environment' outright when there is
  // no rear camera, where Chrome treats it as a preference. Ask for the ideal
  // setup first and fall back, rather than failing on a machine that has a
  // perfectly usable webcam.
  const attempts: MediaStreamConstraints[] = [
    {
      video: {
        facingMode: { ideal: 'environment' },
        width: { ideal: 1280 },
        height: { ideal: 720 },
      },
      audio: false,
    },
    { video: { width: { ideal: 1280 }, height: { ideal: 720 } }, audio: false },
    { video: true, audio: false },
  ];

  let lastError: unknown = null;
  for (const constraints of attempts) {
    try {
      stream = await navigator.mediaDevices.getUserMedia(constraints);
      break;
    } catch (err) {
      lastError = err;
      // A denial will not be fixed by relaxing constraints, so stop asking.
      if ((err as DOMException)?.name === 'NotAllowedError') break;
    }
  }

  if (!stream) {
    const name = (lastError as DOMException)?.name;
    onError(
      name === 'NotAllowedError'
        ? 'Camera permission was denied. Allow camera access, then use Restart camera.'
        : name === 'NotFoundError'
          ? 'No camera found on this device.'
          : name === 'NotReadableError'
            ? 'The camera is in use by another app. Close it, then use Restart camera.'
            : `Could not start the camera: ${(lastError as Error)?.message ?? name}`,
    );
    return { stop: () => {} };
  }

  // These must be set as properties, not attributes: Chrome's autoplay policy
  // checks the property, and iOS needs playsInline to avoid going fullscreen.
  video.srcObject = stream;
  video.muted = true;
  video.autoplay = true;
  video.playsInline = true;
  video.setAttribute('playsinline', 'true');

  try {
    await video.play();
  } catch (err) {
    // Previously swallowed, which made a failed start look like a dead camera.
    onError(`The camera preview could not start: ${(err as Error).message}`);
  }

  // If the track dies — device unplugged, another app claims it, OS revokes
  // permission — the preview goes black with no other clue. Say so.
  stream.getVideoTracks().forEach((track) => {
    track.addEventListener('ended', () => {
      if (!stopped) onError('The camera stopped unexpectedly. Try again.');
    });
  });

  const detector = await createDetector();
  const canvas = document.createElement('canvas');
  const context = canvas.getContext('2d', { willReadFrequently: true });

  let timer = 0;
  const stop = () => {
    stopped = true;
    window.clearInterval(timer);
    stream?.getTracks().forEach((track) => track.stop());
    video.srcObject = null;
  };

  let scanning = false;
  let consecutiveFailures = 0;
  let reportedFailure = false;

  const scanOnce = async () => {
    // Re-entrancy guard: BarcodeDetector.detect is async, and overlapping calls
    // pile up work faster than it can be retired.
    if (scanning || stopped) return;
    scanning = true;
    try {
      // HAVE_CURRENT_DATA is enough to sample a frame; waiting for
      // HAVE_ENOUGH_DATA can stall indefinitely on a live stream.
      if (video.readyState < video.HAVE_CURRENT_DATA) return;
      if (!video.videoWidth || !video.videoHeight) return;

      // Chrome can pause a stream-backed element on its own; nudge it back.
      if (video.paused) void video.play().catch(() => {});

      if (detector) {
        const codes = await detector.detect(video);
        codes.forEach((code) => onResult(code.rawValue));
      } else if (context) {
        const scale = Math.min(
          1,
          MAX_ANALYSIS_EDGE / Math.max(video.videoWidth, video.videoHeight),
        );
        canvas.width = Math.round(video.videoWidth * scale);
        canvas.height = Math.round(video.videoHeight * scale);
        context.drawImage(video, 0, 0, canvas.width, canvas.height);
        const image = context.getImageData(0, 0, canvas.width, canvas.height);
        const code = jsQR(image.data, image.width, image.height, {
          inversionAttempts: 'dontInvert',
        });
        if (code?.data) onResult(code.data);
      }
      consecutiveFailures = 0;
    } catch (err) {
      // One bad frame is noise; a persistent fault should not stay invisible.
      consecutiveFailures++;
      if (consecutiveFailures >= FAILURE_REPORT_THRESHOLD && !reportedFailure) {
        reportedFailure = true;
        onError(`Could not read from the camera: ${(err as Error).message}`);
      }
    } finally {
      scanning = false;
    }
  };

  // A plain interval rather than a requestAnimationFrame or
  // requestVideoFrameCallback chain. Those reschedule themselves from inside
  // their own callback, which gives no guaranteed yield on the path that skips
  // a scan — enough to wedge the renderer. An interval cannot re-enter itself
  // and keeps the cadence independent of frame delivery.
  timer = window.setInterval(() => void scanOnce(), SCAN_INTERVAL_MS);

  return { stop };
}
