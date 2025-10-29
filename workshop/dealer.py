"""Trusted dealer helper for the FROST workshop demo.

Generates a 2-of-3 key set and prints everything in hex so the facilitator can
hand each participant their secret share and public share.

WARNING: This is a pedagogical script built on the reference implementation.
"""
from pathlib import Path
import sys

# Make the reference implementation importable from the project root.
WORKSHOP_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = WORKSHOP_ROOT.parent
REFERENCE_DIR = PROJECT_ROOT / "reference"
if str(REFERENCE_DIR) not in sys.path:
    sys.path.insert(0, str(REFERENCE_DIR))

import reference as frost  # pylint: disable=import-error

MAX_PARTICIPANTS = 3
MIN_PARTICIPANTS = 2


def format_participant(index, identifier, secshare, pubshare):
    return (
        f"Participant {index}\n"
        f"  identifier: {identifier}\n"
        f"  secret_share: {secshare.hex()}\n"
        f"  public_share: {pubshare.hex()}\n"
    )


def print_key_material(group_pk, identifiers, secshares, pubshares):
    group_point = frost.cpoint(group_pk)
    group_pk_xonly = group_point.to_bytes_xonly()

    print("=== Group Parameters ===")
    print(f"group_public_key (plain/compressed): {group_pk.hex()}\n")
    # print(f"group_public_key (x-only): {group_pk_xonly.hex()}")
    # print()

    print("=== Participant Shares ===")
    for idx, (identifier, secshare, pubshare) in enumerate(
        zip(identifiers, secshares, pubshares)
    ):
        print(format_participant(idx, identifier, secshare, pubshare))


def generate_keys():
    return frost.generate_frost_keys(MAX_PARTICIPANTS, MIN_PARTICIPANTS)


def main():
    group_pk, identifiers, secshares, pubshares = generate_keys()
    print_key_material(group_pk, identifiers, secshares, pubshares)
    assert frost.check_frost_key_compatibility(
        MAX_PARTICIPANTS,
        MIN_PARTICIPANTS,
        group_pk,
        identifiers,
        secshares,
        pubshares,
    )


if __name__ == "__main__":
    main()
