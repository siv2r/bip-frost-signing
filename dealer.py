"""Trusted dealer helper for the FROST workshop demo.

Generates a 2-of-3 key set and prints everything in hex so the facilitator can
hand each participant their secret share and public share.

WARNING: This is a pedagogical script built on the reference implementation.
"""
from __future__ import annotations

from pathlib import Path
import sys
from typing import List, Tuple

# Make the reference implementation importable when running from the repo root.
ROOT = Path(__file__).resolve().parent
REFERENCE_DIR = ROOT / "reference"
if str(REFERENCE_DIR) not in sys.path:
    sys.path.insert(0, str(REFERENCE_DIR))

import reference as frost  # type: ignore  # pylint: disable=import-error

MAX_PARTICIPANTS = 3
MIN_PARTICIPANTS = 2

def format_participant(
    index: int, identifier: int, secshare: bytes, pubshare: frost.PlainPk
) -> str:
    return (
        f"Participant {index}\n"
        f"  identifier: {identifier}\n"
        f"  secret_share: {secshare.hex()}\n"
        f"  public_share: {pubshare.hex()}\n"
    )


def print_key_material(
    group_pk: frost.PlainPk,
    identifiers: List[int],
    secshares: List[bytes],
    pubshares: List[frost.PlainPk],
) -> None:
    group_point = frost.cpoint(group_pk)
    group_pk_xonly = group_point.to_bytes_xonly()

    print("=== Group Parameters ===")
    print(f"group_public_key (plain/compressed): {group_pk.hex()}")
    print(f"group_public_key (x-only): {group_pk_xonly.hex()}")
    print()

    print("=== Participant Shares ===")
    for idx, (identifier, secshare, pubshare) in enumerate(
        zip(identifiers, secshares, pubshares)
    ):
        print(format_participant(idx, identifier, secshare, pubshare))


def generate_keys() -> Tuple[frost.PlainPk, List[int], List[bytes], List[frost.PlainPk]]:
    max_participants = 3
    min_participants = 2
    return frost.generate_frost_keys(MAX_PARTICIPANTS, MIN_PARTICIPANTS)


def main() -> None:
    group_pk, identifiers, secshares, pubshares = generate_keys()
    print_key_material(group_pk, identifiers, secshares, pubshares)
    assert frost.check_frost_key_compatibility(MAX_PARTICIPANTS, MIN_PARTICIPANTS, group_pk, identifiers, secshares, pubshares) == True


if __name__ == "__main__":
    main()
