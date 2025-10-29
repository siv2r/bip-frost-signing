"""Signer worksheet for the FROST workshop.

Edit this file by filling in the constants below. Run it twice:
  1. Set RUN_STEP = "nonce" to produce your `secnonce_hex` and `pubnonce_hex`.
     Keep the secnonce secret; share only the pubnonce with the aggregator.
  2. After the aggregator shares the aggregated nonce and the other signer’s data,
     paste those values into the STEP 2 section, set RUN_STEP = "sign", and rerun
     to obtain your partial signature.

This script intentionally keeps things simple—no command-line arguments, just
edit-and-run to mirror the manual workshop flow.
"""
from pathlib import Path
import sys

# Make the reference implementation importable when running from the repo root.
ROOT = Path(__file__).resolve().parent
REFERENCE_DIR = ROOT / "reference"
if str(REFERENCE_DIR) not in sys.path:
    sys.path.insert(0, str(REFERENCE_DIR))

import reference as frost  # pylint: disable=import-error


# ---------------------------------------------------------------------------
# Control switch: pick which part of the protocol you want to run.
#   "nonce" -> generate a fresh nonce pair (Step 1)
#   "sign"  -> produce a partial signature using pasted inputs (Step 2)
RUN_STEP = "sign"


# ---------------------------------------------------------------------------
# STEP 0: Paste the values you received from the dealer.
# Replace the placeholder strings with the actual hex values and integers.
MY_IDENTIFIER = 1  # e.g., 0 or 1
MY_SECSHARE_HEX = "7c1fc8ec54e7c77066314bae068a460ab9b46edc6296f270ca5dbaf2f976539a"  # 32-byte secret share in hex (KEEP PRIVATE)
MY_PUBSHARE_HEX = "0376ee7fe45c9c758ca1469a74702060d4cda441f5d62df11ba72748e77785a37b"  # 33-byte public share in hex
GROUP_PUBKEY_HEX = "0349b51dbb4d6d25e4cfeb7ee9922a9228c4a627a44928cd8292d7a12de0cfcf50"  # 33-byte group public key (compressed) from dealer
MESSAGE_BYTES = b"workshop msg"  # Shared message, e.g., b"workshop message"


# ---------------------------------------------------------------------------
# STEP 1 placeholders: (leave blank until ready)
# No additional data required—run the script with RUN_STEP = "nonce".


# ---------------------------------------------------------------------------
# STEP 2: After the aggregator sends you the session info, paste it below.
# All lists must be ordered consistently (same order as the aggregator used).
MY_SECNONCE_HEX = "170d942e1ed6aacec86affe9bb182547cfbd5a65c4907c0884f413a1e5a31d2086b2b01829865c31f6b07813b96eccae62313ebe4b620c4fbae13cb00e89a369"  # Paste your own secnonce_hex from Step 1 (KEEP PRIVATE)
AGGREGATED_NONCE_HEX = "03cb54af908230b817686df064781b6b8328039fdd8aadcd05b1de67ce902b1d410223663991674a83d570de70b80f462916b915aa351b837edfe38c3f2fe5609068"  # Aggregated nonce from the aggregator
PARTICIPANT_IDS = [0, 1]  # e.g., [0, 1]
PARTICIPANT_PUBSHARES_HEX = ["02c19dfcd0294beb072e0d430706f1e7144c9b29d60373c061d7dd7ad84bd1dfb6", "0376ee7fe45c9c758ca1469a74702060d4cda441f5d62df11ba72748e77785a37b"]  # e.g., ["03...", "02..."]
PARTICIPANT_PUBNONCES_HEX = ["03cf9360086e7a8ceb13492c8bbb0a9609cfaf3fc902d2cbd9e3956a41b825e57502f600306521b53fd2dbd38d03218d22694d5430c36e6f4d1faf12c5a1c800a23c", "02a805de8e170a4fea1f5c8809b4e2f365478d1a90a89a08014330039a7fa3cb57034e52d046e778c7e2e4a38ee0897ceb8ffc5094da47d349aab7b78642d1bf62a4"]  # e.g., ["03...", "02..."]


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

def step1_generate_nonce():
    ensure_step0_complete()

    secshare = bytes.fromhex(MY_SECSHARE_HEX)
    pubshare = frost.PlainPk(bytes.fromhex(MY_PUBSHARE_HEX))
    group_point = frost.cpoint(bytes.fromhex(GROUP_PUBKEY_HEX))
    group_pk_xonly = frost.XonlyPk(group_point.to_bytes_xonly())

    secnonce, pubnonce = frost.nonce_gen(
        secshare=secshare,
        pubshare=pubshare,
        group_pk=group_pk_xonly,
        msg=MESSAGE_BYTES,
        extra_in=None,
    )

    print("=== STEP 1: Nonce Generation ===")
    print("secnonce_hex (KEEP PRIVATE):", secnonce.hex())
    print("pubnonce_hex (share with aggregator):", pubnonce.hex())


def step2_sign():
    ensure_step0_complete()
    ensure_step2_complete()

    secshare = bytes.fromhex(MY_SECSHARE_HEX)
    secnonce = bytearray(bytes.fromhex(MY_SECNONCE_HEX))
    aggnonce = bytes.fromhex(AGGREGATED_NONCE_HEX)

    pubshares = [frost.PlainPk(bytes.fromhex(h)) for h in PARTICIPANT_PUBSHARES_HEX]
    pubnonces = [bytes.fromhex(h) for h in PARTICIPANT_PUBNONCES_HEX]

    session_ctx = frost.SessionContext(
        aggnonce=aggnonce,
        identifiers=PARTICIPANT_IDS,
        pubshares=pubshares,
        tweaks=[],
        is_xonly=[],
        msg=MESSAGE_BYTES,
    )

    psig = frost.sign(
        secnonce=secnonce,
        secshare=secshare,
        my_id=MY_IDENTIFIER,
        session_ctx=session_ctx,
    )

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

    print("=== STEP 2: Partial Signature ===")
    print("partial_signature_hex (share with aggregator):", psig.hex())


def main():
    if RUN_STEP == "nonce":
        step1_generate_nonce()
    elif RUN_STEP == "sign":
        step2_sign()
    else:
        raise SystemExit('Set RUN_STEP to "nonce" or "sign".')


if __name__ == "__main__":
    main()
