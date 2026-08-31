"""
Stage 2 of the determinism harness: sign each generated case with real embit.

This deliberately contains no nonce logic of its own. It walks the same path
SeedSigner does — mnemonic to seed, seed to root HDKey, parse the PSBT, call
`psbt.sign_with(root)` — so the comparison validates the JS signer against
embit's actual behaviour rather than against my reading of embit's source.
"""
from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from pathlib import Path

from embit import bip32, bip39
from embit.psbt import PSBT

CASES_FILE = Path(__file__).parent / "cases" / "cases.json"


def secp256k1_backend() -> str:
    """Which secp256k1 implementation embit loaded.

    embit falls back to a pure-Python implementation when the native library is
    unavailable. SeedSigner ships the native one, so a run against the fallback
    is testing something subtly different and the harness should say so out loud
    rather than quietly reporting a pass.
    """
    from embit.util import secp256k1

    return secp256k1.ecdsa_sign.__module__


@dataclass
class EmbitResult:
    index: int
    signed_psbt: str
    signature_count: int
    signatures: list[dict]


def sign_case(case: dict) -> EmbitResult:
    seed = bip39.mnemonic_to_seed(case["mnemonic"])
    root = bip32.HDKey.from_seed(seed)

    psbt = PSBT.parse(base64.b64decode(case["unsigned_psbt"]))
    # embit's default sighash handling matches what a segwit v0 signer uses.
    added = psbt.sign_with(root)

    signatures = []
    for input_index, psbt_input in enumerate(psbt.inputs):
        for pubkey, sig in psbt_input.partial_sigs.items():
            signatures.append(
                {
                    "input_index": input_index,
                    "pubkey": pubkey.serialize().hex(),
                    # partial_sigs values are raw bytes: DER + the sighash byte.
                    "signature": sig.hex() if isinstance(sig, bytes) else sig.serialize().hex(),
                }
            )

    return EmbitResult(
        index=case["index"],
        signed_psbt=psbt.to_string(),
        signature_count=added,
        signatures=signatures,
    )


def load_cases() -> dict:
    if not CASES_FILE.exists():
        raise SystemExit(
            f"no generated cases at {CASES_FILE}\n"
            "run: npx tsx embit-test-harness/generate_cases.mts --count 100"
        )
    return json.loads(CASES_FILE.read_text())


if __name__ == "__main__":
    data = load_cases()
    print(f"embit secp256k1 backend: {secp256k1_backend()}")
    for case in data["cases"]:
        result = sign_case(case)
        status = "match" if result.signed_psbt == case["js_signed_psbt"] else "MISMATCH"
        print(f"case {result.index:3d} {case['wallet_type']:12s} sigs={result.signature_count} {status}")
