"""Signer worksheet for the FROST workshop.

Edit this file by filling in the constants below. Run it twice:
  1. Set RUN_STEP = "nonce" to produce your `secnonce_hex` and `pubnonce_hex`.
     Keep the secnonce secret; share only the pubnonce with the aggregator.
  2. After the aggregator shares the aggregated nonce and the other signer’s data,
     paste those values into the STEP 2 section, set RUN_STEP = "sign", and rerun
     to obtain your partial signature.
"""
from pathlib import Path
import sys

# Make the reference implementation importable from the project root.
WORKSHOP_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = WORKSHOP_ROOT.parent
REFERENCE_DIR = PROJECT_ROOT / "reference"
if str(REFERENCE_DIR) not in sys.path:
    sys.path.insert(0, str(REFERENCE_DIR))

def ensure_step0_complete():
    if not (
        isinstance(MY_IDENTIFIER, int)
        and MY_SECSHARE_HEX
        and MY_PUBSHARE_HEX
        and GROUP_PUBKEY_HEX
        and MESSAGE_BYTES
    ):
        raise SystemExit(
            "Please fill in STEP 0 values (identifier, shares, group key, message)."
        )


def ensure_step2_complete():
    if not MY_SECNONCE_HEX:
        raise SystemExit("Paste MY_SECNONCE_HEX from Step 1.")
    if not AGGREGATED_NONCE_HEX:
        raise SystemExit("Paste AGGREGATED_NONCE_HEX from the aggregator.")
    if not (PARTICIPANT_IDS and PARTICIPANT_PUBSHARES_HEX and PARTICIPANT_PUBNONCES_HEX):
        raise SystemExit("Fill PARTICIPANT_IDS, PUBSHARES_HEX, and PUBNONCES_HEX lists.")
    if not (
        len(PARTICIPANT_IDS)
        == len(PARTICIPANT_PUBSHARES_HEX)
        == len(PARTICIPANT_PUBNONCES_HEX)
    ):
        raise SystemExit("Participant lists must all have the same length.")
    if MY_IDENTIFIER not in PARTICIPANT_IDS:
        raise SystemExit("Your identifier must be included in PARTICIPANT_IDS.")

# ---------------------------------------------------------------------------
# Control switch: pick which part of the protocol you want to run.
#   "nonce" -> generate a fresh nonce pair (Step 1)
#   "sign"  -> produce a partial signature using pasted inputs (Step 2)
RUN_STEP = "nonce"


####################################
# IGNORE EVERYTHING ABOVE THIS LINE#
####################################

import reference as frost

# You can now access the FROST signing APIs via this `frost` module
# e.g. `frost.sign(...)`.

#################################################################
# ROUND 1: Generate randomness (aka nonces) required for signing #
#################################################################

# TODO 1.1: Paste the FROST keys & message you received from the trusted dealer
# Replace the placeholder strings with the actual hex values and integers.
MY_IDENTIFIER = 0  # change this to 1 if you are signer 1
MY_SECSHARE_HEX = ""  # 32-byte secret share in hex (KEEP PRIVATE)
MY_PUBSHARE_HEX = ""  # 33-byte public share in hex
GROUP_PUBKEY_HEX = ""  # 33-byte group public key (compressed) from dealer
MESSAGE_BYTES = b"workshop message"  # Message being signed

def round1_generate_nonce():
    ensure_step0_complete()
    # Convert hex values to bytes as FROST APIs require
    # their inputs to be in bytes
    secshare = bytes.fromhex(MY_SECSHARE_HEX)
    pubshare = frost.PlainPk(bytes.fromhex(MY_PUBSHARE_HEX))
    group_point = frost.cpoint(bytes.fromhex(GROUP_PUBKEY_HEX))
    group_pk_xonly = frost.XonlyPk(group_point.to_bytes_xonly())

    # TODO 1.2: Call the appropriate nonce generation FROST API on the above inputs
    secnonce, pubnonce = ()
    # secnonce, pubnonce = frost.nonce_gen(
    #     secshare=secshare,
    #     pubshare=pubshare,
    #     group_pk=group_pk_xonly,
    #     msg=MESSAGE_BYTES,
    #     extra_in=None,
    # )

    print("=== ROUND 1: Nonce Generation ===")
    print("secnonce_hex (KEEP PRIVATE):", secnonce.hex())
    print("pubnonce_hex (share with aggregator):", pubnonce.hex())
    print("SHARE ONLY the `pubnonce_hex` value with your aggregator")
    print("=================================")

#################################################################
# ROUND 2: Generate partial (digital) signature                 #
#################################################################

# TODO 2.1: After the aggregator sends you aggregate nonce and pubnonce list,
# paste it below.
# All lists must be ordered consistently (same order as the aggregator used)
MY_SECNONCE_HEX = ""  # Paste your own secnonce_hex from round 1 (KEEP PRIVATE)
AGGREGATED_NONCE_HEX = ""  # Aggregated nonce received from the aggregator
PARTICIPANT_IDS = [0, 1]  # Don't change this
PARTICIPANT_PUBSHARES_HEX = ["", ""]  # Received from the trusted dealer. e.g., ["03...", "02..."]
PARTICIPANT_PUBNONCES_HEX = ["", ""]  # Received from aggregator e.g., ["03...", "02..."]

def round2_sign():
    ensure_step0_complete()
    ensure_step2_complete()

    secshare = bytes.fromhex(MY_SECSHARE_HEX)
    secnonce = bytearray(bytes.fromhex(MY_SECNONCE_HEX))
    aggnonce = bytes.fromhex(AGGREGATED_NONCE_HEX)

    pubshares = [frost.PlainPk(bytes.fromhex(value)) for value in PARTICIPANT_PUBSHARES_HEX]
    pubnonces = [bytes.fromhex(value) for value in PARTICIPANT_PUBNONCES_HEX]

    session_ctx = frost.SessionContext(
        aggnonce=aggnonce,
        identifiers=PARTICIPANT_IDS,
        pubshares=pubshares,
        tweaks=[],
        is_xonly=[],
        msg=MESSAGE_BYTES,
    )

    # TODO 2.2: Create a signature using FROST API on the above inputs
    psig = b""
    # psig = frost.sign(
    #     secnonce=secnonce,
    #     secshare=secshare,
    #     my_id=MY_IDENTIFIER,
    #     session_ctx=session_ctx,
    # )

    signer_index = PARTICIPANT_IDS.index(MY_IDENTIFIER)
    verified = frost.partial_sig_verify(
        psig=psig,
        ids=PARTICIPANT_IDS,
        pubnonces=pubnonces,
        pubshares=pubshares,
        tweaks=[],
        is_xonly=[],
        msg=MESSAGE_BYTES,
        i=signer_index,
    )
    if not verified:
        raise SystemExit("Partial signature failed local verification.")

    print("=== ROUND 2: SIGNING ===")
    print("partial_signature_hex (share with aggregator):", psig.hex())
    print("========================")

def main():
    if RUN_STEP == "nonce":
        round1_generate_nonce()
    elif RUN_STEP == "sign":
        round2_sign()
    else:
        raise SystemExit('Set RUN_STEP to "nonce" or "sign".')


if __name__ == "__main__":
    main()
