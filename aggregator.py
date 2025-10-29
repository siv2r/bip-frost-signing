"""Aggregator worksheet for the FROST workshop.

Edit this file to mirror the two responsibilities of the non-signing participant:
  1. Aggregate the pubnonces shared by the two signers.
  2. After receiving their partial signatures, verify and combine them into the
     final Schnorr signature.

Switch RUN_STEP between "aggregate_nonces" and "finalize" as you progress.
"""
from pathlib import Path
import sys

# Make the reference implementation importable when running from the repo root.
ROOT = Path(__file__).resolve().parent
REFERENCE_DIR = ROOT / "reference"
if str(REFERENCE_DIR) not in sys.path:
    sys.path.insert(0, str(REFERENCE_DIR))

import reference as frost  # pylint: disable=import-error
from secp256k1lab.bip340 import schnorr_verify


# ---------------------------------------------------------------------------
# Control switch:
#   "aggregate_nonces" -> compute aggregated nonce from signer pubnonces.
#   "finalize"         -> verify partial signatures and produce final signature.
RUN_STEP = "finalize"


# ---------------------------------------------------------------------------
# STEP 0: Paste the dealer outputs that everyone shares.
GROUP_PUBKEY_HEX = "0349b51dbb4d6d25e4cfeb7ee9922a9228c4a627a44928cd8292d7a12de0cfcf50"  # 33-byte compressed group public key
MESSAGE_BYTES = b"workshop msg"  # Shared message, e.g., b"workshop message"


# ---------------------------------------------------------------------------
# STEP 1 inputs: fill these with the pubnonces you received from each signer.
# Ensure the order matches PARTICIPANT_IDS.
PARTICIPANT_IDS = [0, 1]  # e.g., [0, 1]
PARTICIPANT_PUBNONCES_HEX = ["03cf9360086e7a8ceb13492c8bbb0a9609cfaf3fc902d2cbd9e3956a41b825e57502f600306521b53fd2dbd38d03218d22694d5430c36e6f4d1faf12c5a1c800a23c", "02a805de8e170a4fea1f5c8809b4e2f365478d1a90a89a08014330039a7fa3cb57034e52d046e778c7e2e4a38ee0897ceb8ffc5094da47d349aab7b78642d1bf62a4"]  # e.g., ["03...", "02..."]


# ---------------------------------------------------------------------------
# STEP 2 inputs: after signers share their partial signatures, paste them here.
# Use the same order as PARTICIPANT_IDS.
AGGREGATED_NONCE_HEX = "03cb54af908230b817686df064781b6b8328039fdd8aadcd05b1de67ce902b1d410223663991674a83d570de70b80f462916b915aa351b837edfe38c3f2fe5609068"  # Paste your output from Step 1
PARTICIPANT_PUBSHARES_HEX = ["02c19dfcd0294beb072e0d430706f1e7144c9b29d60373c061d7dd7ad84bd1dfb6", "0376ee7fe45c9c758ca1469a74702060d4cda441f5d62df11ba72748e77785a37b"]  # Dealer-supplied pubshares for each signer
PARTIAL_SIGNATURES_HEX = ["4f27fc266ea6a9c1aeb804cc56957413cf3c86e3a6cbfda230525dad51a53c77", "23c7cc2db402c5742cb584c56e7963328e7f2d8da7b5d4320957de21e9628b4a"]  # e.g., ["89...", "ab..."]


def ensure_step0_complete():
    if not GROUP_PUBKEY_HEX or not MESSAGE_BYTES:
        raise SystemExit("Fill GROUP_PUBKEY_HEX and MESSAGE_BYTES from the dealer.")


def ensure_step1_complete():
    if not (PARTICIPANT_IDS and PARTICIPANT_PUBNONCES_HEX):
        raise SystemExit("Fill PARTICIPANT_IDS and PARTICIPANT_PUBNONCES_HEX.")
    if len(PARTICIPANT_IDS) != len(PARTICIPANT_PUBNONCES_HEX):
        raise SystemExit("PARTICIPANT_IDS and PUBNONCES_HEX must have the same length.")


def step1_aggregate_nonces():
    ensure_step0_complete()
    ensure_step1_complete()

    pubnonces = [bytes.fromhex(h) for h in PARTICIPANT_PUBNONCES_HEX]
    aggnonce = frost.nonce_agg(pubnonces=pubnonces, ids=PARTICIPANT_IDS)

    print("=== STEP 1: Nonce Aggregation ===")
    print("aggregated_nonce_hex (share with signers):", aggnonce.hex())


def ensure_step2_complete():
    if not AGGREGATED_NONCE_HEX:
        raise SystemExit("Paste AGGREGATED_NONCE_HEX (your Step 1 output).")
    if not (
        PARTICIPANT_PUBSHARES_HEX
        and PARTICIPANT_IDS
        and PARTICIPANT_PUBNONCES_HEX
        and PARTIAL_SIGNATURES_HEX
    ):
        raise SystemExit(
            "Fill PARTICIPANT_PUBSHARES_HEX, PARTICIPANT_IDS, "
            "PARTICIPANT_PUBNONCES_HEX, and PARTIAL_SIGNATURES_HEX."
        )
    counts = {
        len(PARTICIPANT_IDS),
        len(PARTICIPANT_PUBSHARES_HEX),
        len(PARTICIPANT_PUBNONCES_HEX),
        len(PARTIAL_SIGNATURES_HEX),
    }
    if len(counts) != 1:
        raise SystemExit("All participant lists must have the same length.")


def step2_finalize_signature():
    ensure_step0_complete()
    ensure_step2_complete()

    aggnonce = bytes.fromhex(AGGREGATED_NONCE_HEX)
    pubshares = [frost.PlainPk(bytes.fromhex(h)) for h in PARTICIPANT_PUBSHARES_HEX]
    pubnonces = [bytes.fromhex(h) for h in PARTICIPANT_PUBNONCES_HEX]
    partial_sigs = [bytes.fromhex(h) for h in PARTIAL_SIGNATURES_HEX]

    session_ctx = frost.SessionContext(
        aggnonce=aggnonce,
        identifiers=PARTICIPANT_IDS,
        pubshares=pubshares,
        tweaks=[],
        is_xonly=[],
        msg=MESSAGE_BYTES,
    )

    for idx, (psig, pid) in enumerate(zip(partial_sigs, PARTICIPANT_IDS)):
        verified = frost.partial_sig_verify(
            psig=psig,
            ids=PARTICIPANT_IDS,
            pubnonces=pubnonces,
            pubshares=pubshares,
            tweaks=[],
            is_xonly=[],
            msg=MESSAGE_BYTES,
            i=idx,
        )
        if not verified:
            raise SystemExit(f"Partial signature from participant {pid} failed verification.")

    aggregated_sig = frost.partial_sig_agg(partial_sigs, PARTICIPANT_IDS, session_ctx)

    group_point = frost.cpoint(bytes.fromhex(GROUP_PUBKEY_HEX))
    group_pk_xonly = group_point.to_bytes_xonly()
    valid = schnorr_verify(MESSAGE_BYTES, group_pk_xonly, aggregated_sig)

    print("=== STEP 2: Final Signature ===")
    print("final_signature_hex:", aggregated_sig.hex())
    print("schnorr_verify:", valid)


def main():
    if RUN_STEP == "aggregate_nonces":
        step1_aggregate_nonces()
    elif RUN_STEP == "finalize":
        step2_finalize_signature()
    else:
        raise SystemExit('Set RUN_STEP to "aggregate_nonces" or "finalize".')


if __name__ == "__main__":
    main()
