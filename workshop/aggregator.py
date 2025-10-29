"""Aggregator worksheet for the FROST workshop.

Edit this file to mirror the two responsibilities of the non-signing participant:
  1. Aggregate the pubnonces shared by the two signers.
  2. After receiving their partial signatures, verify and combine them into the
     final Schnorr signature.

Switch RUN_STEP between "aggregate_nonces" and "finalize" as you progress.
"""
from pathlib import Path
import sys

# Make the reference implementation importable from the project root.
WORKSHOP_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = WORKSHOP_ROOT.parent
REFERENCE_DIR = PROJECT_ROOT / "reference"
if str(REFERENCE_DIR) not in sys.path:
    sys.path.insert(0, str(REFERENCE_DIR))

# ---------------------------------------------------------------------------
# Control switch:
#   "aggregate_nonces" -> compute aggregated nonce from signer pubnonces.
#   "finalize"         -> verify partial signatures and produce final signature.
RUN_STEP = "aggregate_nonces"

def ensure_step0_complete():
    if not GROUP_PUBKEY_HEX or not MESSAGE_BYTES:
        raise SystemExit("Fill GROUP_PUBKEY_HEX and MESSAGE_BYTES from the dealer.")


def ensure_step1_complete():
    if not (PARTICIPANT_IDS and PARTICIPANT_PUBNONCES_HEX):
        raise SystemExit("Fill PARTICIPANT_IDS and PARTICIPANT_PUBNONCES_HEX.")
    if len(PARTICIPANT_IDS) != len(PARTICIPANT_PUBNONCES_HEX):
        raise SystemExit("PARTICIPANT_IDS and PUBNONCES_HEX must have the same length.")

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


#####################################
# IGNORE EVERYTHING ABOVE THIS LINE #
#####################################

import reference as frost 
from secp256k1lab.bip340 import schnorr_verify

#####################################################################
# ROUND 1: Aggregate the randomness (aka nonces) received from both #
# signer 0 and signer 1                                             #
#####################################################################

# ---------------------------------------------------------------------------
# TODO 1.1: Paste the FROST keys & message you received from the trusted dealer
GROUP_PUBKEY_HEX = ""  # 33-byte compressed group public key
MESSAGE_BYTES = b""  # Shared message, e.g., b"workshop message"

# TODO 1.2: Fill these with the pubnonces you received from signer 0 and signer 1.
# Ensure the order matches PARTICIPANT_IDS.
PARTICIPANT_IDS = [0, 1]
PARTICIPANT_PUBNONCES_HEX = []

def round1_aggregate_nonces():
    ensure_step0_complete()
    ensure_step1_complete()

    pubnonces = [bytes.fromhex(value) for value in PARTICIPANT_PUBNONCES_HEX]
    # TODO 1.3: Call the appropriate nonce aggregation FROST API on the above inputs
    # aggnonce = frost.nonce_agg(pubnonces=pubnonces, ids=PARTICIPANT_IDS)
    aggnonce = b""

    print("=== STEP 1: Nonce Aggregation ===")
    print("aggregated_nonce_hex (share with signers):", aggnonce.hex())
    print("pubnonces list:", PARTICIPANT_PUBNONCES_HEX)
    print("SHARE the aggregated_nonce_hex, pubnonces list, pubshares list with both signers")
    print("=================================")

#####################################################################
# ROUND 2: Aggregate the partial signatures received from both      #
# signer 0 and signer 1                                             #
#####################################################################

# ---------------------------------------------------------------------------
# TODO 2.1: after signers share their partial signatures, paste them here.
# Use the same order as PARTICIPANT_IDS.
AGGREGATED_NONCE_HEX = ""
PARTICIPANT_PUBSHARES_HEX = [] # Received from the trusted dealer. e.g., ["03...", "02..."]
PARTIAL_SIGNATURES_HEX = [] # Received from signer 0 and signer 1


def round2_aggregate_partialsigs():
    ensure_step0_complete()
    ensure_step2_complete()

    aggnonce = bytes.fromhex(AGGREGATED_NONCE_HEX)
    pubshares = [frost.PlainPk(bytes.fromhex(value)) for value in PARTICIPANT_PUBSHARES_HEX]
    pubnonces = [bytes.fromhex(value) for value in PARTICIPANT_PUBNONCES_HEX]
    partial_sigs = [bytes.fromhex(value) for value in PARTIAL_SIGNATURES_HEX]

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
            raise SystemExit(
                f"Partial signature from participant {pid} failed verification."
            )

    # TODO 2.2: Aggregate the partial signatures using the appropriate FROST API
    aggregated_sig = b""
    # aggregated_sig = frost.partial_sig_agg(partial_sigs, PARTICIPANT_IDS, session_ctx)

    group_point = frost.cpoint(bytes.fromhex(GROUP_PUBKEY_HEX))
    group_pk_xonly = group_point.to_bytes_xonly()
    valid = schnorr_verify(MESSAGE_BYTES, group_pk_xonly, aggregated_sig)

    print("=== STEP 2: Final Signature ===")
    print("final_signature_hex:", aggregated_sig.hex())
    if valid:
        print("Congratulations!! You successfully ran the FROST protocol")
    else:
        print("Invalid signature :(")
    print("===============================")


def main():
    if RUN_STEP == "aggregate_nonces":
        round1_aggregate_nonces()
    elif RUN_STEP == "finalize":
        round2_aggregate_partialsigs()
    else:
        raise SystemExit('Set RUN_STEP to "aggregate_nonces" or "finalize".')


if __name__ == "__main__":
    main()
