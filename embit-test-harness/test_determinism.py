"""
Stage 3 of the determinism harness: assert the JS signer and embit agree.

Every generated case must produce a byte-identical signed PSBT. This is the
correctness claim the whole tool rests on — if it does not hold, the site will
tell users their hardware is broken when it is not.
"""
from __future__ import annotations

import pytest

from sign_with_embit import load_cases, secp256k1_backend, sign_case

DATA = load_cases()
CASES = DATA["cases"]


def case_id(case: dict) -> str:
    return (
        f"{case['index']:03d}-{case['wallet_type']}-{case['word_count']}w-"
        f"{case['input_count']}in-{case['output_count']}out"
    )


def test_backend_is_reported(capsys):
    """Surface which secp256k1 embit used; the fallback is not what devices run."""
    backend = secp256k1_backend()
    with capsys.disabled():
        print(f"\nembit secp256k1 backend: {backend}")
        print(f"cases: {len(CASES)} (generator seed: {DATA['seed']})")
    assert backend.endswith(("ctypes_secp256k1", "secp256k1"))


def test_case_count():
    assert len(CASES) > 0, "no cases generated"


@pytest.mark.parametrize("case", CASES, ids=case_id)
def test_signatures_match_embit(case: dict):
    result = sign_case(case)

    # Guard against a vacuous pass. If embit cannot match the master fingerprint
    # it signs nothing, both PSBTs come back unsigned, and a naive equality check
    # would report success while proving nothing at all.
    assert result.signature_count == case["input_count"], (
        f"embit signed {result.signature_count} of {case['input_count']} inputs. "
        f"The PSBT is not signable by a real device either. seed={case['seed']}"
    )
    assert len(case["js_signatures"]) == case["input_count"], (
        f"JS signed {len(case['js_signatures'])} of {case['input_count']} inputs. "
        f"seed={case['seed']}"
    )

    if result.signed_psbt != case["js_signed_psbt"]:
        embit_sigs = {(s["input_index"], s["pubkey"]): s["signature"] for s in result.signatures}
        js_sigs = {(s["input_index"], s["pubkey"]): s["signature"] for s in case["js_signatures"]}
        diffs = [
            f"  input {k[0]} pubkey {k[1][:16]}...\n"
            f"    embit: {embit_sigs.get(k, '(absent)')}\n"
            f"    js   : {js_sigs.get(k, '(absent)')}"
            for k in sorted(set(embit_sigs) | set(js_sigs))
            if embit_sigs.get(k) != js_sigs.get(k)
        ]
        pytest.fail(
            f"signed PSBTs differ for {case['wallet_type']} case {case['index']}\n"
            + ("\n".join(diffs) if diffs else "  (signatures agree; PSBT serialisation differs)")
            + f"\nreproduce with: npx tsx embit-test-harness/generate_cases.mts --seed {DATA['seed']}"
        )


@pytest.mark.parametrize("case", CASES, ids=case_id)
def test_multisig_has_no_change(case: dict):
    """Multisig runs must not include change; without a registered wallet
    descriptor the device has no way to verify a multisig change output."""
    if case["wallet_type"] == "p2wsh-2of3":
        assert not case["has_change"]
