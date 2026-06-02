#!/usr/bin/env python3

import glob
import json
import os
import re
import sys
from typing import Dict, List, Sequence, Union
import secrets

from frost_ref import (
    InvalidContributionError,
    SessionContext,
    SignersContext,
    deterministic_sign,
    nonce_agg,
    partial_sig_agg,
    partial_sig_verify,
    sign,
)
from frost_ref.signing import derive_interpolating_value, nonce_gen_internal
from secp256k1lab.secp256k1 import G, GE, Scalar
from secp256k1lab.keys import pubkey_gen_plain
from trusted_dealer import trusted_dealer_keygen


def bytes_to_hex(data: bytes) -> str:
    return data.hex().upper()


def bytes_list_to_hex(lst: Sequence[bytes]) -> List[str]:
    return [l_i.hex().upper() for l_i in lst]


def hex_list_to_bytes(lst: List[str]) -> List[bytes]:
    return [bytes.fromhex(l_i) for l_i in lst]


ErrorInfo = Dict[str, Union[int, str, None, "ErrorInfo"]]


def exception_asdict(e: Exception) -> dict:
    error_info: ErrorInfo = {"type": e.__class__.__name__}

    for key, value in e.__dict__.items():
        if isinstance(value, (str, int, type(None))):
            error_info[key] = value
        elif isinstance(value, bytes):
            error_info[key] = bytes_to_hex(value)
        else:
            raise NotImplementedError(
                f"Conversion for type {type(value).__name__} is not implemented"
            )

    # If the last argument is not found in the instance’s attributes and
    # is a string, treat it as an extra message.
    if e.args and isinstance(e.args[-1], str) and e.args[-1] not in e.__dict__.values():
        error_info.setdefault("message", e.args[-1])
    return error_info


def expect_exception(try_fn, expected_exception):
    try:
        try_fn()
    except expected_exception as e:
        return exception_asdict(e)
    except Exception as e:
        raise AssertionError(f"Wrong exception raised: {type(e).__name__}")
    else:
        raise AssertionError("Expected exception")


COMMON_RAND = bytes.fromhex(
    "0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F"
)

COMMON_MSGS = [
    bytes.fromhex(
        "F95466D086770E689964664219266FE5ED215C92AE20BAB5C9D79ADDDDF3C0CF"
    ),  # 32-byte message
    bytes.fromhex(""),  # Empty message
    bytes.fromhex(
        "2626262626262626262626262626262626262626262626262626262626262626262626262626"
    ),  # 38-byte message
]

COMMON_TWEAKS = hex_list_to_bytes(
    [
        "E8F791FF9225A2AF0102AFFF4A9A723D9612A682A25EBE79802B263CDFCD83BB",
        "AE2EA797CC0FE72AC5B97B97F3C6957D7E4199A167A58EB08BCAFFDA70AC0455",
        "F52ECBC565B3D8BEA2DFD5B75A4F457E54369809322E4120831626F290FA87E0",
        "1969AD73CC177FA0B4FCED6DF1F7BF9907E665FDE9BA196A74FED0A3CF5AEF9D",
    ]
)

OUT_OF_RANGE_TWEAK = bytes.fromhex(
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
)

INVALID_PUBSHARE = bytes.fromhex(
    "020000000000000000000000000000000000000000000000000000000000000007"
)


_SCALAR_TOKEN = r"-?\d+|true|false|null"
_SCALAR_ARRAY_RE = re.compile(
    rf"\[\s*(?:(?:{_SCALAR_TOKEN})(?:\s*,\s*(?:{_SCALAR_TOKEN}))*)?\s*\]"
)


def _inline_scalar_array(match):
    tokens = re.findall(_SCALAR_TOKEN, match.group(0))
    return "[" + ", ".join(tokens) + "]"


def write_test_vectors(filename, vectors):
    output_file = os.path.join("vectors", filename)
    text = _SCALAR_ARRAY_RE.sub(_inline_scalar_array, json.dumps(vectors, indent=4))
    json.loads(text)  # guard: inlining must keep the JSON parseable
    with open(output_file, "w") as f:
        f.write(text)


def generate_all_nonces(rand, secshares, pubshares, xonly_thresh_pk, msg=None):
    secnonces = []
    pubnonces = []
    for i in range(len(secshares)):
        sec, pub = nonce_gen_internal(
            rand, secshares[i], pubshares[i], xonly_thresh_pk, msg, None
        )
        secnonces.append(sec)
        pubnonces.append(pub)
    return secnonces, pubnonces


def reconstruct_thresh_sk(ids, secshares):
    assert len(ids) == len(secshares)
    result = Scalar(0)
    for i, s in zip(ids, secshares):
        result = result + derive_interpolating_value(
            ids, i
        ) * Scalar.from_bytes_checked(s)
    return result


SECKEY_1OF3 = bytes.fromhex(
    "06D47E05E97481428654563E5AE69C20C49642773B7334220E63110259A30C32"
)
SECKEY_2OF3 = bytes.fromhex(
    "4C08C37F5B9A88FAE396A06E286BA41B654457BF5E35B4A693096ED9AB1491F5"
)
SECKEY_3OF3 = bytes.fromhex(
    "70E90852E9541FE47552B738A14C2B9B5B38C0979D640BA8C7A5A5EEE1BDA405"
)
SECKEY_3OF5 = bytes.fromhex(
    "827FBF411520966DAF1D5D8BDAFCA4FEC34EEB7A954927D8AA1FD55BDDD15902"
)


def frost_keygen(seckey=None, n=3, t=2):
    # NOTE: don't default `seckey` to secrets.token_bytes(32) in the signature, as that is evaluated once at import time and every no-arg call would reuse it.
    if seckey is None:
        seckey = secrets.token_bytes(32)
    assert len(seckey) == 32
    assert 1 <= t <= n
    thresh_pk, secshares, pubshares = trusted_dealer_keygen(seckey, n, t)
    assert thresh_pk == pubkey_gen_plain(seckey)
    return (n, t, thresh_pk, list(range(n)), secshares, pubshares)


def generate_nonce_gen_vectors():
    vectors = {}
    vectors["valid_tests"] = []
    tc_id = 1

    _, _, thresh_pk, _, secshares, pubshares = frost_keygen(SECKEY_2OF3)
    xonly_thresh_pk = thresh_pk[1:]
    extra_in = bytes.fromhex(
        "0808080808080808080808080808080808080808080808080808080808080808"
    )

    # --- Valid Test Case 1 ---
    msg = bytes.fromhex(
        "0101010101010101010101010101010101010101010101010101010101010101"
    )
    secnonce, pubnonce = nonce_gen_internal(
        COMMON_RAND, secshares[0], pubshares[0], xonly_thresh_pk, msg, extra_in
    )
    vectors["valid_tests"].append(
        {
            "tc_id": tc_id,
            "comment": "All optional defense-in-depth arguments present",
            "rand_": bytes_to_hex(COMMON_RAND),
            "secshare": bytes_to_hex(secshares[0]),
            "pubshare": bytes_to_hex(pubshares[0]),
            "thresh_pk": bytes_to_hex(xonly_thresh_pk),
            "msg": bytes_to_hex(msg),
            "extra_in": bytes_to_hex(extra_in),
            "expected": [bytes_to_hex(secnonce), bytes_to_hex(pubnonce)],
        }
    )
    tc_id += 1
    # --- Valid Test Case 2 ---
    secnonce, pubnonce = nonce_gen_internal(
        COMMON_RAND,
        secshares[0],
        pubshares[0],
        xonly_thresh_pk,
        COMMON_MSGS[1],
        extra_in,
    )
    vectors["valid_tests"].append(
        {
            "tc_id": tc_id,
            "comment": "Empty message",
            "rand_": bytes_to_hex(COMMON_RAND),
            "secshare": bytes_to_hex(secshares[0]),
            "pubshare": bytes_to_hex(pubshares[0]),
            "thresh_pk": bytes_to_hex(xonly_thresh_pk),
            "msg": bytes_to_hex(COMMON_MSGS[1]),
            "extra_in": bytes_to_hex(extra_in),
            "expected": [bytes_to_hex(secnonce), bytes_to_hex(pubnonce)],
        }
    )
    tc_id += 1
    # --- Valid Test Case 3 ---
    secnonce, pubnonce = nonce_gen_internal(
        COMMON_RAND,
        secshares[0],
        pubshares[0],
        xonly_thresh_pk,
        COMMON_MSGS[2],
        extra_in,
    )
    vectors["valid_tests"].append(
        {
            "tc_id": tc_id,
            "comment": "Non-standard message length (38 bytes)",
            "rand_": bytes_to_hex(COMMON_RAND),
            "secshare": bytes_to_hex(secshares[0]),
            "pubshare": bytes_to_hex(pubshares[0]),
            "thresh_pk": bytes_to_hex(xonly_thresh_pk),
            "msg": bytes_to_hex(COMMON_MSGS[2]),
            "extra_in": bytes_to_hex(extra_in),
            "expected": [bytes_to_hex(secnonce), bytes_to_hex(pubnonce)],
        }
    )
    tc_id += 1
    # --- Valid Test Case 4 ---
    secnonce, pubnonce = nonce_gen_internal(COMMON_RAND, None, None, None, None, None)
    vectors["valid_tests"].append(
        {
            "tc_id": tc_id,
            "comment": "All optional defense-in-depth arguments omitted",
            "rand_": bytes_to_hex(COMMON_RAND),
            "secshare": None,
            "pubshare": None,
            "thresh_pk": None,
            "msg": None,
            "extra_in": None,
            "expected": [bytes_to_hex(secnonce), bytes_to_hex(pubnonce)],
        }
    )
    tc_id += 1
    # --- Valid Test Case 5 ---
    secnonce, pubnonce = nonce_gen_internal(
        COMMON_RAND, secshares[0], pubshares[0], xonly_thresh_pk, None, extra_in
    )
    vectors["valid_tests"].append(
        {
            "tc_id": tc_id,
            "comment": "Message omitted, other optional arguments present",
            "rand_": bytes_to_hex(COMMON_RAND),
            "secshare": bytes_to_hex(secshares[0]),
            "pubshare": bytes_to_hex(pubshares[0]),
            "thresh_pk": bytes_to_hex(xonly_thresh_pk),
            "msg": None,
            "extra_in": bytes_to_hex(extra_in),
            "expected": [bytes_to_hex(secnonce), bytes_to_hex(pubnonce)],
        }
    )
    tc_id += 1

    write_test_vectors("nonce_gen_vectors.json", vectors)


def generate_nonce_agg_vectors():
    vectors = {}

    # Special pubnonce indices for test cases
    INVALID_TAG_IDX = 4
    INVALID_XCOORD_IDX = 5
    INVALID_EXCEEDS_FIELD_IDX = 6

    pubnonces = hex_list_to_bytes(
        [
            "020151C80F435648DF67A22B749CD798CE54E0321D034B92B709B567D60A42E66603BA47FBC1834437B3212E89A84D8425E7BF12E0245D98262268EBDCB385D50641",
            "03FF406FFD8ADB9CD29877E4985014F66A59F6CD01C0E88CAA8E5F3166B1F676A60248C264CDD57D3C24D79990B0F865674EB62A0F9018277A95011B41BFC193B833",
            "020151C80F435648DF67A22B749CD798CE54E0321D034B92B709B567D60A42E6660279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
            "03FF406FFD8ADB9CD29877E4985014F66A59F6CD01C0E88CAA8E5F3166B1F676A60379BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
            "04FF406FFD8ADB9CD29877E4985014F66A59F6CD01C0E88CAA8E5F3166B1F676A60248C264CDD57D3C24D79990B0F865674EB62A0F9018277A95011B41BFC193B833",
            "03FF406FFD8ADB9CD29877E4985014F66A59F6CD01C0E88CAA8E5F3166B1F676A60248C264CDD57D3C24D79990B0F865674EB62A0F9018277A95011B41BFC193B831",
            "03FF406FFD8ADB9CD29877E4985014F66A59F6CD01C0E88CAA8E5F3166B1F676A602FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30",
        ]
    )
    vectors["pubnonces"] = bytes_list_to_hex(pubnonces)

    tc_id = 1
    vectors["valid_tests"] = []
    # --- Valid Test Case 1 ---
    pubnonce_indices = [0, 1]
    curr_pubnonces = [pubnonces[i] for i in pubnonce_indices]
    aggnonce = nonce_agg(curr_pubnonces)
    vectors["valid_tests"].append(
        {
            "tc_id": tc_id,
            "comment": "Two well-formed public nonces",
            "pubnonce_indices": pubnonce_indices,
            "expected": bytes_to_hex(aggnonce),
        }
    )
    tc_id += 1
    # --- Valid Test Case 2 ---
    pubnonce_indices = [2, 3]
    curr_pubnonces = [pubnonces[i] for i in pubnonce_indices]
    aggnonce = nonce_agg(curr_pubnonces)
    vectors["valid_tests"].append(
        {
            "tc_id": tc_id,
            "comment": "Second halves sum to the point at infinity, which is serialized as the all-zero encoding",
            "pubnonce_indices": pubnonce_indices,
            "expected": bytes_to_hex(aggnonce),
        }
    )
    tc_id += 1

    vectors["error_tests"] = []
    # --- Error Test Case 1 ---
    pubnonce_indices = [0, INVALID_TAG_IDX]
    curr_pubnonces = [pubnonces[i] for i in pubnonce_indices]
    error = expect_exception(
        lambda: nonce_agg(curr_pubnonces), InvalidContributionError
    )
    vectors["error_tests"].append(
        {
            "tc_id": tc_id,
            "comment": "Public nonce is invalid: first half has an unknown tag 0x04",
            "pubnonce_indices": pubnonce_indices,
            "error": error,
        }
    )
    tc_id += 1
    # --- Error Test Case 2 ---
    pubnonce_indices = [INVALID_XCOORD_IDX, 1]
    curr_pubnonces = [pubnonces[i] for i in pubnonce_indices]
    error = expect_exception(
        lambda: nonce_agg(curr_pubnonces), InvalidContributionError
    )
    vectors["error_tests"].append(
        {
            "tc_id": tc_id,
            "comment": "Public nonce is invalid: second half is not a point on the curve",
            "pubnonce_indices": pubnonce_indices,
            "error": error,
        }
    )
    tc_id += 1
    # --- Error Test Case 3 ---
    pubnonce_indices = [INVALID_EXCEEDS_FIELD_IDX, 1]
    curr_pubnonces = [pubnonces[i] for i in pubnonce_indices]
    error = expect_exception(
        lambda: nonce_agg(curr_pubnonces), InvalidContributionError
    )
    vectors["error_tests"].append(
        {
            "tc_id": tc_id,
            "comment": "Public nonce is invalid: second half's x-coordinate exceeds the field size",
            "pubnonce_indices": pubnonce_indices,
            "error": error,
        }
    )
    tc_id += 1

    write_test_vectors("nonce_agg_vectors.json", vectors)


def generate_sign_verify_vectors():
    n, t, thresh_pk, ids, secshares, pubshares = frost_keygen(SECKEY_2OF3)
    xonly_thresh_pk = thresh_pk[1:]

    secnonces, pubnonces = generate_all_nonces(
        COMMON_RAND, secshares, pubshares, xonly_thresh_pk
    )

    # Build participant-aligned pools: first n values are for participants followed by invalids/specials.
    # Referencing convention in the emitted cases: literal integers for
    # participant indices (e.g. pubshare_indices=[0, 1]), named constants for
    # the appended specials (e.g. INVALID_PUBSHARE_IDX, OUT_OF_RANGE_ID).
    INVALID_PUBSHARE_IDX = n
    INVALID_PUBNONCE_IDX = n
    INVERSE_PUBNONCE_IDX = n + 1
    SECSHARE_ZERO_IDX = n
    SECNONCE_ZERO_IDX = n
    SECNONCE_ZERO_SECOND_IDX = n + 1
    OUT_OF_RANGE_ID = n

    assert INVALID_PUBSHARE_IDX == 3
    assert INVERSE_PUBNONCE_IDX == 4

    pool_pubshares = pubshares + [INVALID_PUBSHARE]
    pool_secshares = secshares + [b"\x00" * 32]

    # compute inverse pubnonce: -(pubnonce[0] + pubnonce[1])
    tmp = nonce_agg(pubnonces[:2])
    R1 = GE.from_bytes_compressed_with_infinity(tmp[0:33])
    R2 = GE.from_bytes_compressed_with_infinity(tmp[33:66])
    inverse_pubnonce = (-R1).to_bytes_compressed_with_infinity() + (
        -R2
    ).to_bytes_compressed_with_infinity()
    invalid_pubnonce = bytes.fromhex(
        "0200000000000000000000000000000000000000000000000000000000000000090287BF891D2A6DEAEBADC909352AA9405D1428C15F4B75F04DAE642A95C2548480"
    )
    # Append order: invalid at index n (=3), inverse at index n+1 (=4)
    pool_pubnonces = pubnonces + [invalid_pubnonce, inverse_pubnonce]

    secnonce_all_zero = bytes.fromhex(
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    )
    zero_second_secnonce = secnonces[0][0:32] + b"\x00" * 32
    assert Scalar.from_bytes_nonzero_checked(zero_second_secnonce[0:32])
    # Append order: all-zero at index n (=3), zero-second-half at index n+1 (=4)
    pool_secnonces = secnonces + [secnonce_all_zero, zero_second_secnonce]

    # Precompute inline aggnonces
    aggnonce_01 = nonce_agg([pubnonces[0], pubnonces[1]])
    aggnonce_02 = nonce_agg([pubnonces[0], pubnonces[2]])
    aggnonce_012 = nonce_agg([pubnonces[0], pubnonces[1], pubnonces[2]])
    # Infinity aggnonce: P0 + P1 + inverse_pubnonce cancels to infinity
    aggnonce_inf = nonce_agg([pubnonces[0], pubnonces[1], inverse_pubnonce])
    # Invalid aggnonce literals
    aggnonce_wrong_tag = bytes.fromhex(
        "048465FCF0BBDBCF443AABCCE533D42B4B5A10966AC09A49655E8C42DAAB8FCD61037496A3CC86926D452CAFCFD55D25972CA1675D549310DE296BFF42F72EEEA8C9"
    )
    aggnonce_bad_xcoord = bytes.fromhex(
        "028465FCF0BBDBCF443AABCCE533D42B4B5A10966AC09A49655E8C42DAAB8FCD61020000000000000000000000000000000000000000000000000000000000000009"
    )
    aggnonce_exceeds_field = bytes.fromhex(
        "028465FCF0BBDBCF443AABCCE533D42B4B5A10966AC09A49655E8C42DAAB8FCD6102FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30"
    )

    group = {
        "tg_id": "2of3",
        "t": t,
        "n": n,
        "thresh_pk": bytes_to_hex(thresh_pk),
        "pubshares": bytes_list_to_hex(pool_pubshares),
        "pubnonces": bytes_list_to_hex(pool_pubnonces),
        "secshares": bytes_list_to_hex(pool_secshares),
        "secnonces": bytes_list_to_hex(pool_secnonces),
        "valid_tests": [],
        "sign_error_tests": [],
        "verify_fail_tests": [],
        "verify_error_tests": [],
    }
    tc_id = 1

    # --- Valid Test Cases ---
    valid_cases = [
        {
            "my_id": 0,
            "ids": [0, 1],
            "pubshare_indices": [0, 1],
            "pubnonce_indices": [0, 1],
            "aggnonce": aggnonce_01,
            "msg": COMMON_MSGS[0],
            "secshare_index": 0,
            "secnonce_index": 0,
            "comment": "Minimum threshold subset of signers (t=2 of n=3)",
        },
        {
            "my_id": 0,
            "ids": [1, 0],
            "pubshare_indices": [1, 0],
            "pubnonce_indices": [1, 0],
            "aggnonce": aggnonce_01,
            "msg": COMMON_MSGS[0],
            "secshare_index": 0,
            "secnonce_index": 0,
            "comment": "Signer order does not affect the partial signature: the signer set is sorted internally, so this matches the first valid case",
        },
        {
            "my_id": 0,
            "ids": [0, 2],
            "pubshare_indices": [0, 2],
            "pubnonce_indices": [0, 2],
            "aggnonce": aggnonce_02,
            "msg": COMMON_MSGS[0],
            "secshare_index": 0,
            "secnonce_index": 0,
            "comment": "A different threshold subset gives a different partial signature, since the Lagrange coefficients depend on the signer set",
        },
        {
            "my_id": 1,
            "ids": [0, 1, 2],
            "pubshare_indices": [0, 1, 2],
            "pubnonce_indices": [0, 1, 2],
            "aggnonce": aggnonce_012,
            "msg": COMMON_MSGS[0],
            "secshare_index": 1,
            "secnonce_index": 1,
            "comment": "All n=3 signers participate, signed by a non-first member in the set",
        },
        {
            "my_id": 0,
            "ids": [0, 1, 2],
            "pubshare_indices": [0, 1, 2],
            "pubnonce_indices": [0, 1, INVERSE_PUBNONCE_IDX],
            "aggnonce": aggnonce_inf,
            "msg": COMMON_MSGS[0],
            "secshare_index": 0,
            "secnonce_index": 0,
            "comment": "Aggregate nonce is the point at infinity, so the final nonce point falls back to the generator G",
        },
        {
            "my_id": 0,
            "ids": [0, 1],
            "pubshare_indices": [0, 1],
            "pubnonce_indices": [0, 1],
            "aggnonce": aggnonce_01,
            "msg": COMMON_MSGS[1],
            "secshare_index": 0,
            "secnonce_index": 0,
            "comment": "Empty message",
        },
        {
            "my_id": 0,
            "ids": [0, 1],
            "pubshare_indices": [0, 1],
            "pubnonce_indices": [0, 1],
            "aggnonce": aggnonce_01,
            "msg": COMMON_MSGS[2],
            "secshare_index": 0,
            "secnonce_index": 0,
            "comment": "Non-standard message length (38 bytes)",
        },
    ]
    for case in valid_cases:
        curr_ids = case["ids"]
        curr_pubshares = [pool_pubshares[i] for i in case["pubshare_indices"]]
        curr_pubnonces = [pool_pubnonces[i] for i in case["pubnonce_indices"]]
        curr_aggnonce = case["aggnonce"]
        curr_msg = case["msg"]
        my_id = case["my_id"]
        curr_secshare = pool_secshares[case["secshare_index"]]
        curr_secnonce = bytearray(pool_secnonces[case["secnonce_index"]])

        curr_signers = SignersContext(n, t, curr_ids, curr_pubshares, thresh_pk)
        session_ctx = SessionContext(curr_aggnonce, curr_signers, [], [], curr_msg)
        expected_psig = sign(curr_secnonce, curr_secshare, my_id, session_ctx)
        signer_index = curr_ids.index(my_id)
        assert partial_sig_verify(
            expected_psig, curr_pubnonces, curr_signers, [], [], curr_msg, signer_index
        )
        group["valid_tests"].append(
            {
                "tc_id": tc_id,
                "comment": case["comment"],
                "my_id": my_id,
                "ids": curr_ids,
                "pubshare_indices": case["pubshare_indices"],
                "pubnonce_indices": case["pubnonce_indices"],
                "secshare_index": case["secshare_index"],
                "secnonce_index": case["secnonce_index"],
                "aggnonce": bytes_to_hex(curr_aggnonce),
                "msg": bytes_to_hex(curr_msg),
                "expected": bytes_to_hex(expected_psig),
            }
        )
        tc_id += 1

    # --- Sign Error Test Cases ---
    sign_error_cases = [
        {
            # my_id=2 is outside ids=[0,1]. The signer presents participant 0's
            # valid in-set material (secshare_index=0), since the id-membership
            # check is only reached after the pubshare-membership check passes.
            "my_id": 2,
            "ids": [0, 1],
            "pubshare_indices": [0, 1],
            "aggnonce": aggnonce_01,
            "msg": COMMON_MSGS[0],
            "secshare_index": 0,
            "secnonce_index": 0,
            "error": "value",
            "comment": "my_id is not in the signer set",
        },
        {
            "my_id": 0,
            "ids": [0, 1, 1],
            "pubshare_indices": [0, 1, 1],
            "aggnonce": aggnonce_01,
            "msg": COMMON_MSGS[0],
            "secshare_index": 0,
            "secnonce_index": 0,
            "error": "value",
            "comment": "Signer set contains a duplicate id",
        },
        {
            # The signer is set member my_id=1 but loads participant 0's secret
            # share (secshare_index=0, the single bad field), so the derived public
            # share is absent from the set {1,2}.
            "my_id": 1,
            "ids": [1, 2],
            "pubshare_indices": [1, 2],
            "aggnonce": aggnonce_01,
            "msg": COMMON_MSGS[0],
            "secshare_index": 0,
            "secnonce_index": 0,
            "error": "value",
            "comment": "Signer's public share is not in the public share list",
        },
        {
            "my_id": 0,
            "ids": [0, 1],
            "pubshare_indices": [0, INVALID_PUBSHARE_IDX],
            "aggnonce": aggnonce_01,
            "msg": COMMON_MSGS[0],
            "secshare_index": 0,
            "secnonce_index": 0,
            "error": "value",
            "comment": "A public share is not a valid point",
        },
        {
            # ids=[3, 1] where 3 == n is out of range. The signer is the in-range
            # member my_id=1, using participant 1's own secret share and nonce.
            "my_id": 1,
            "ids": [OUT_OF_RANGE_ID, 1],
            "pubshare_indices": [0, 1],
            "aggnonce": aggnonce_01,
            "msg": COMMON_MSGS[0],
            "secshare_index": 1,
            "secnonce_index": 1,
            "error": "value",
            "comment": "A signer id is outside the valid range [0, n-1]",
        },
        {
            "my_id": 0,
            "ids": [0, 1],
            "pubshare_indices": [0, 2],
            "aggnonce": aggnonce_01,
            "msg": COMMON_MSGS[0],
            "secshare_index": 0,
            "secnonce_index": 0,
            "error": "value",
            "comment": "Signer set's public shares do not match the threshold public key",
        },
        {
            "my_id": 0,
            "ids": [0, 1],
            "pubshare_indices": [0, 1],
            "aggnonce": aggnonce_wrong_tag,
            "msg": COMMON_MSGS[0],
            "secshare_index": 0,
            "secnonce_index": 0,
            "error": "invalid_contrib",
            "comment": "Aggregate nonce is invalid: first half has an unknown tag 0x04",
        },
        {
            "my_id": 0,
            "ids": [0, 1],
            "pubshare_indices": [0, 1],
            "aggnonce": aggnonce_bad_xcoord,
            "msg": COMMON_MSGS[0],
            "secshare_index": 0,
            "secnonce_index": 0,
            "error": "invalid_contrib",
            "comment": "Aggregate nonce is invalid: second half is not a point on the curve",
        },
        {
            "my_id": 0,
            "ids": [0, 1],
            "pubshare_indices": [0, 1],
            "aggnonce": aggnonce_exceeds_field,
            "msg": COMMON_MSGS[0],
            "secshare_index": 0,
            "secnonce_index": 0,
            "error": "invalid_contrib",
            "comment": "Aggregate nonce is invalid: second half's x-coordinate exceeds the field size",
        },
        {
            "my_id": 0,
            "ids": [0, 1],
            "pubshare_indices": [0, 1],
            "aggnonce": aggnonce_01,
            "msg": COMMON_MSGS[0],
            "secshare_index": 0,
            "secnonce_index": SECNONCE_ZERO_IDX,
            "error": "value",
            "comment": "Secret nonce's first half is out of range (all-zero nonce, which may indicate nonce reuse)",
        },
        {
            "my_id": 0,
            "ids": [0, 1],
            "pubshare_indices": [0, 1],
            "aggnonce": aggnonce_01,
            "msg": COMMON_MSGS[0],
            "secshare_index": 0,
            "secnonce_index": SECNONCE_ZERO_SECOND_IDX,
            "error": "value",
            "comment": "Secret nonce's second half is out of range (zero)",
        },
        {
            # aggnonce_01 doesn't match the single-signer set, but it's never
            # inspected: SignersContext rejects the sub-threshold set first.
            "my_id": 0,
            "ids": [0],
            "pubshare_indices": [0],
            "aggnonce": aggnonce_01,
            "msg": COMMON_MSGS[0],
            "secshare_index": 0,
            "secnonce_index": 0,
            "error": "value",
            "comment": "Fewer signers than the threshold t",
        },
        {
            "my_id": 0,
            "ids": [0, 1],
            "pubshare_indices": [0, 1],
            "aggnonce": aggnonce_01,
            "msg": COMMON_MSGS[0],
            "secshare_index": SECSHARE_ZERO_IDX,
            "secnonce_index": 0,
            "error": "value",
            "comment": "Secret share is out of range (zero)",
        },
    ]
    for case in sign_error_cases:
        curr_ids = case["ids"]
        curr_pubshares = [pool_pubshares[i] for i in case["pubshare_indices"]]
        curr_aggnonce = case["aggnonce"]
        curr_msg = case["msg"]
        my_id = case["my_id"]
        curr_secnonce = bytearray(pool_secnonces[case["secnonce_index"]])
        curr_secshare = pool_secshares[case["secshare_index"]]

        curr_signers = SignersContext(n, t, curr_ids, curr_pubshares, thresh_pk)
        session_ctx = SessionContext(curr_aggnonce, curr_signers, [], [], curr_msg)
        expected_error = (
            ValueError if case["error"] == "value" else InvalidContributionError
        )
        error = expect_exception(
            lambda: sign(curr_secnonce, curr_secshare, my_id, session_ctx),
            expected_error,
        )
        group["sign_error_tests"].append(
            {
                "tc_id": tc_id,
                "comment": case["comment"],
                "my_id": my_id,
                "ids": curr_ids,
                "pubshare_indices": case["pubshare_indices"],
                "secshare_index": case["secshare_index"],
                "secnonce_index": case["secnonce_index"],
                "aggnonce": bytes_to_hex(curr_aggnonce),
                "msg": bytes_to_hex(curr_msg),
                "error": error,
            }
        )
        tc_id += 1

    # --- Verify Fail and Verify Error base: sign as P0 over [0,1], agg(0,1), msg0 ---
    vf_ids = [0, 1]
    vf_pubshare_indices = [0, 1]
    vf_pubnonce_indices = [0, 1]
    vf_msg = COMMON_MSGS[0]
    vf_aggnonce = aggnonce_01
    vf_my_id = 0

    vf_pubshares = [pool_pubshares[i] for i in vf_pubshare_indices]
    vf_signers = SignersContext(n, t, vf_ids, vf_pubshares, thresh_pk)
    vf_session = SessionContext(vf_aggnonce, vf_signers, [], [], vf_msg)
    vf_secnonce = bytearray(pool_secnonces[0])
    psig = sign(vf_secnonce, pool_secshares[0], vf_my_id, vf_session)

    # --- Verify Fail Test Cases ---
    psig_scalar = Scalar.from_bytes_checked(psig)
    neg_psig = (-psig_scalar).to_bytes()

    group["verify_fail_tests"].append(
        {
            "tc_id": tc_id,
            "comment": "Negated partial signature fails the verification equation",
            "psig": bytes_to_hex(neg_psig),
            "ids": vf_ids,
            "pubshare_indices": vf_pubshare_indices,
            "pubnonce_indices": vf_pubnonce_indices,
            "signer_index": 0,
            "msg": bytes_to_hex(vf_msg),
        }
    )
    tc_id += 1

    group["verify_fail_tests"].append(
        {
            "tc_id": tc_id,
            "comment": "A valid partial signature checked against the wrong signer fails the verification equation",
            "psig": bytes_to_hex(psig),
            "ids": vf_ids,
            "pubshare_indices": vf_pubshare_indices,
            "pubnonce_indices": vf_pubnonce_indices,
            "signer_index": 1,
            "msg": bytes_to_hex(vf_msg),
        }
    )
    tc_id += 1

    group["verify_fail_tests"].append(
        {
            "tc_id": tc_id,
            "comment": "Partial signature equals the group order, which is out of range",
            "psig": "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
            "ids": vf_ids,
            "pubshare_indices": vf_pubshare_indices,
            "pubnonce_indices": vf_pubnonce_indices,
            "signer_index": 0,
            "msg": bytes_to_hex(vf_msg),
        }
    )
    tc_id += 1

    # --- Verify Error Test Cases ---
    verify_error_cases = [
        {
            "ids": [0, 1],
            "pubshare_indices": [0, 1],
            "pubnonce_indices": [INVALID_PUBNONCE_IDX, 1],
            "msg": COMMON_MSGS[0],
            "signer_index": 0,
            "error": "invalid_contrib",
            "comment": "Public nonce is invalid: first half is not a point on the curve",
        },
        {
            "ids": [0, 1],
            "pubshare_indices": [INVALID_PUBSHARE_IDX, 1],
            "pubnonce_indices": [0, 1],
            "msg": COMMON_MSGS[0],
            "signer_index": 0,
            "error": "value",
            "comment": "A public share is not a valid point",
        },
    ]
    for case in verify_error_cases:
        curr_ids = case["ids"]
        curr_pubshares = [pool_pubshares[i] for i in case["pubshare_indices"]]
        curr_pubnonces = [pool_pubnonces[i] for i in case["pubnonce_indices"]]
        curr_msg = case["msg"]
        signer_index = case["signer_index"]
        curr_signers = SignersContext(n, t, curr_ids, curr_pubshares, thresh_pk)
        expected_error = (
            ValueError if case["error"] == "value" else InvalidContributionError
        )
        error = expect_exception(
            # reuse the valid psig generated for verify_fail cases
            lambda: partial_sig_verify(
                psig, curr_pubnonces, curr_signers, [], [], curr_msg, signer_index
            ),
            expected_error,
        )
        group["verify_error_tests"].append(
            {
                "tc_id": tc_id,
                "comment": case["comment"],
                "psig": bytes_to_hex(psig),
                "ids": curr_ids,
                "pubshare_indices": case["pubshare_indices"],
                "pubnonce_indices": case["pubnonce_indices"],
                "signer_index": signer_index,
                "msg": bytes_to_hex(curr_msg),
                "error": error,
            }
        )
        tc_id += 1

    vectors = {"test_groups": [group]}
    write_test_vectors("sign_verify_vectors.json", vectors)


def generate_tweak_vectors():
    n, t, thresh_pk, ids, secshares, pubshares = frost_keygen(SECKEY_2OF3)
    xonly_thresh_pk = thresh_pk[1:]

    pubshares_with_invalid = pubshares + [INVALID_PUBSHARE]

    secnonces, pubnonces = generate_all_nonces(
        COMMON_RAND, secshares, pubshares, xonly_thresh_pk
    )

    # Precompute inline aggnonces
    aggnonce_01 = nonce_agg([pubnonces[0], pubnonces[1]])
    aggnonce_012 = nonce_agg([pubnonces[0], pubnonces[1], pubnonces[2]])

    # Compute a plain tweak that drives Q + twk*G to the point at infinity: twk = -thresh_sk.
    infinity_tweak_scalar = -reconstruct_thresh_sk([0, 1], secshares[:2])
    assert (GE.from_bytes_compressed(thresh_pk) + infinity_tweak_scalar * G).infinity

    # 6 entries: indices 0-3 valid (COMMON_TWEAKS), index 4 out-of-range,
    # index 5 drives the tweaked threshold public key to infinity
    OUT_OF_RANGE_TWEAK_IDX = len(COMMON_TWEAKS)
    INFINITY_TWEAK_IDX = len(COMMON_TWEAKS) + 1
    tweaks_pool = COMMON_TWEAKS + [
        OUT_OF_RANGE_TWEAK,
        infinity_tweak_scalar.to_bytes(),
    ]

    group = {
        "tg_id": "2of3",
        "t": t,
        "n": n,
        "thresh_pk": bytes_to_hex(thresh_pk),
        "pubshares": bytes_list_to_hex(pubshares_with_invalid),
        "pubnonces": bytes_list_to_hex(pubnonces),
        "secshares": bytes_list_to_hex(secshares),
        "secnonces": bytes_list_to_hex(secnonces),
        "tweaks": bytes_list_to_hex(tweaks_pool),
        "valid_tests": [],
        "error_tests": [],
    }
    tc_id = 1

    # --- Valid Test Cases ---
    valid_cases = [
        {
            "tweaks_indices": [],
            "is_xonly": [],
            "aggnonce": bytes_to_hex(aggnonce_01),
            "comment": "No tweaks applied",
        },
        {
            "tweaks_indices": [0],
            "is_xonly": [True],
            "aggnonce": bytes_to_hex(aggnonce_01),
            "comment": "Single x-only tweak (used for BIP341 Taproot)",
        },
        {
            "tweaks_indices": [0],
            "is_xonly": [False],
            "aggnonce": bytes_to_hex(aggnonce_01),
            "comment": "Single plain tweak (used for BIP32 derivation)",
        },
        {
            "tweaks_indices": [0, 1],
            "is_xonly": [False, True],
            "aggnonce": bytes_to_hex(aggnonce_01),
            "comment": "A plain tweak followed by an x-only tweak",
        },
        {
            "tweaks_indices": [0, 1, 2, 3],
            "is_xonly": [True, False, True, False],
            "aggnonce": bytes_to_hex(aggnonce_01),
            "comment": "Four tweaks alternating x-only and plain",
        },
        {
            "tweaks_indices": [0, 1, 2, 3],
            "is_xonly": [False, False, True, True],
            "aggnonce": bytes_to_hex(aggnonce_01),
            "comment": "Four tweaks: two plain followed by two x-only",
        },
        {
            "tweaks_indices": [0, 1, 2, 3],
            "is_xonly": [False, False, True, True],
            "indices": [0, 1, 2],
            "signer_idx": 1,
            "aggnonce": bytes_to_hex(aggnonce_012),
            "comment": "Same tweaks as the previous case but with all 3 signers and signed by a non-first member of the signer set",
        },
    ]
    for case in valid_cases:
        indices = case.get("indices", [0, 1])
        curr_ids = [ids[i] for i in indices]
        curr_pubshares = [pubshares_with_invalid[i] for i in indices]
        curr_aggnonce = bytes.fromhex(case["aggnonce"])
        curr_tweaks = [tweaks_pool[i] for i in case["tweaks_indices"]]
        curr_tweak_modes = case["is_xonly"]
        signer_idx = case.get("signer_idx", 0)
        my_id = ids[signer_idx]

        curr_signers = SignersContext(n, t, curr_ids, curr_pubshares, thresh_pk)
        session_ctx = SessionContext(
            curr_aggnonce, curr_signers, curr_tweaks, curr_tweak_modes, COMMON_MSGS[0]
        )
        psig = sign(
            bytearray(secnonces[signer_idx]), secshares[signer_idx], my_id, session_ctx
        )

        group["valid_tests"].append(
            {
                "tc_id": tc_id,
                "comment": case["comment"],
                "my_id": my_id,
                "ids": curr_ids,
                "pubshare_indices": indices,
                "pubnonce_indices": indices,
                "secshare_index": signer_idx,
                "secnonce_index": signer_idx,
                "aggnonce": case["aggnonce"],
                "msg": bytes_to_hex(COMMON_MSGS[0]),
                "tweak_indices": case["tweaks_indices"],
                "is_xonly": curr_tweak_modes,
                "expected": bytes_to_hex(psig),
            }
        )
        tc_id += 1

    # --- Error Test Cases ---
    error_cases = [
        {
            "tweaks_indices": [OUT_OF_RANGE_TWEAK_IDX],
            "is_xonly": [False],
            "comment": "Tweak exceeds the group order",
        },
        {
            "tweaks_indices": [INFINITY_TWEAK_IDX],
            "is_xonly": [False],
            "comment": "Plain tweak drives the tweaked threshold public key to the point at infinity",
        },
    ]
    for case in error_cases:
        indices = [0, 1]
        curr_ids = [ids[i] for i in indices]
        curr_pubshares = [pubshares_with_invalid[i] for i in indices]
        curr_tweaks = [tweaks_pool[i] for i in case["tweaks_indices"]]
        curr_tweak_modes = case["is_xonly"]
        my_id = curr_ids[0]

        curr_signers = SignersContext(n, t, curr_ids, curr_pubshares, thresh_pk)
        session_ctx = SessionContext(
            aggnonce_01, curr_signers, curr_tweaks, curr_tweak_modes, COMMON_MSGS[0]
        )
        error = expect_exception(
            lambda: sign(bytearray(secnonces[0]), secshares[0], my_id, session_ctx),
            ValueError,
        )
        group["error_tests"].append(
            {
                "tc_id": tc_id,
                "comment": case["comment"],
                "my_id": my_id,
                "ids": curr_ids,
                "pubshare_indices": indices,
                "secshare_index": 0,
                "secnonce_index": 0,
                "aggnonce": bytes_to_hex(aggnonce_01),
                "msg": bytes_to_hex(COMMON_MSGS[0]),
                "tweak_indices": case["tweaks_indices"],
                "is_xonly": curr_tweak_modes,
                "error": error,
            }
        )
        tc_id += 1

    vectors = {"test_groups": [group]}
    write_test_vectors("tweak_vectors.json", vectors)


def generate_det_sign_vectors():
    n, t, thresh_pk, ids, secshares, pubshares = frost_keygen(SECKEY_2OF3)
    xonly_thresh_pk = thresh_pk[1:]

    # Special indices for test cases
    INVALID_PUBSHARE_IDX = n
    INVALID_TWEAK_IDX = 1
    RAND_NONE_IDX = 1
    RAND_MAX_IDX = 2

    assert len(COMMON_MSGS[2]) == 38

    pubshares.append(INVALID_PUBSHARE)

    group = {
        "tg_id": "2of3",
        "t": t,
        "n": n,
        "thresh_pk": bytes_to_hex(thresh_pk),
        "pubshares": bytes_list_to_hex(pubshares),
        "secshares": bytes_list_to_hex(secshares),
        "valid_tests": [],
        "error_tests": [],
    }
    tc_id = 1

    rands = [
        bytes.fromhex(
            "0000000000000000000000000000000000000000000000000000000000000000"
        ),
        None,
        bytes.fromhex(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
        ),
    ]

    tweaks = [
        [COMMON_TWEAKS[0]],
        [OUT_OF_RANGE_TWEAK],
    ]

    # --- Valid Test Cases ---
    valid_cases = [
        {
            "indices": [0, 1],
            "my_id": 0,
            "msg": 0,
            "rand": 0,
            "comment": "Minimum threshold subset of signers (t=2 of n=3)",
        },
        {
            "indices": [1, 0],
            "my_id": 0,
            "msg": 0,
            "rand": 0,
            "comment": "Signer order does not affect the output: the signer set is sorted internally, so this matches the first valid case",
        },
        {
            "indices": [0, 2],
            "my_id": 0,
            "msg": 0,
            "rand": 0,
            "comment": "A different threshold subset gives a different deterministic nonce, since the signer set is bound into the nonce derivation",
        },
        {
            "indices": [0, 1],
            "my_id": 0,
            "msg": 0,
            "rand": RAND_NONE_IDX,
            "comment": "No auxiliary randomness (rand omitted)",
        },
        {
            "indices": [0, 1],
            "my_id": 0,
            "msg": 0,
            "rand": RAND_MAX_IDX,
            "comment": "Maximum auxiliary randomness",
        },
        {
            "indices": [0, 1, 2],
            "my_id": 1,
            "msg": 0,
            "rand": 0,
            "comment": "All n=3 signers participate, signed by a non-first member of the signer set",
        },
        {
            "indices": [0, 1],
            "my_id": 0,
            "msg": 1,
            "rand": 0,
            "comment": "Empty message",
        },
        {
            "indices": [0, 1],
            "my_id": 0,
            "msg": 2,
            "rand": 0,
            "comment": "Non-standard message length (38 bytes)",
        },
        {
            "indices": [0, 1],
            "my_id": 0,
            "msg": 0,
            "rand": 0,
            "tweaks": 0,
            "is_xonly": [True],
            "comment": "Single x-only tweak applied",
        },
    ]
    for case in valid_cases:
        curr_ids = [ids[i] for i in case["indices"]]
        curr_pubshares = [pubshares[i] for i in case["indices"]]
        curr_msg = COMMON_MSGS[case["msg"]]
        curr_rand = rands[case["rand"]]
        my_id = case["my_id"]
        tweaks_idx = case.get("tweaks", None)
        curr_tweaks = [] if tweaks_idx is None else tweaks[tweaks_idx]
        curr_tweak_modes = case.get("is_xonly", [])
        secshare_index = ids.index(my_id)

        # generate `aggothernonce` (every signer's nonce except this signer's own)
        other_pubnonces = []
        for i in case["indices"]:
            if ids[i] == my_id:
                continue
            tmp = b"" if curr_rand is None else curr_rand
            _, pub = nonce_gen_internal(
                tmp, secshares[i], pubshares[i], xonly_thresh_pk, curr_msg, None
            )
            other_pubnonces.append(pub)
        curr_aggothernonce = nonce_agg(other_pubnonces)

        curr_signers = SignersContext(n, t, curr_ids, curr_pubshares, thresh_pk)
        expected = deterministic_sign(
            secshares[secshare_index],
            my_id,
            curr_aggothernonce,
            curr_signers,
            curr_tweaks,
            curr_tweak_modes,
            curr_msg,
            curr_rand,
        )

        group["valid_tests"].append(
            {
                "tc_id": tc_id,
                "comment": case["comment"],
                "my_id": my_id,
                "ids": curr_ids,
                "pubshare_indices": case["indices"],
                "secshare_index": secshare_index,
                "aggothernonce": bytes_to_hex(curr_aggothernonce),
                "rand": bytes_to_hex(curr_rand) if curr_rand is not None else curr_rand,
                "msg": bytes_to_hex(curr_msg),
                "tweaks": bytes_list_to_hex(curr_tweaks),
                "is_xonly": curr_tweak_modes,
                "expected": bytes_list_to_hex(expected),
            }
        )
        tc_id += 1

    # --- Error Test Cases ---
    error_cases = [
        {
            # my_id=2 is outside ids=[0,1]. The signer presents participant 0's
            # valid in-set material (secshare_index=0), since the id-membership
            # check is only reached after the pubshare-membership check passes.
            "ids": [0, 1],
            "pubshares": [0, 1],
            "my_id": 2,
            "secshare_index": 0,
            "msg": 0,
            "rand": 0,
            "error": "value",
            "comment": "my_id is not in the signer set",
        },
        {
            "ids": [0, 1, 1],
            "pubshares": [0, 1, 1],
            "my_id": 0,
            "secshare_index": 0,
            "msg": 0,
            "rand": 0,
            "error": "value",
            "comment": "Signer set contains a duplicate id",
        },
        {
            # The signer is set member my_id=1 but loads participant 0's secret
            # share (secshare_index=0, the single bad field), so the derived public
            # share is absent from the set {1,2}.
            "ids": [1, 2],
            "pubshares": [1, 2],
            "my_id": 1,
            "secshare_index": 0,
            "msg": 0,
            "rand": 0,
            "error": "value",
            "comment": "Signer's public share is not in the public share list",
        },
        {
            "ids": [0, 1],
            "pubshares": [0, INVALID_PUBSHARE_IDX],
            "my_id": 0,
            "secshare_index": 0,
            "msg": 0,
            "rand": 0,
            "error": "value",
            "comment": "A public share is not a valid point",
        },
        {
            # Context-validation error independent of the secret; align signer to my_id=2.
            "ids": [2, 1],
            "pubshares": [0, 1],
            "my_id": 2,
            "secshare_index": 2,
            "msg": 0,
            "rand": 0,
            "error": "value",
            "comment": "Signer set's public shares do not match the threshold public key",
        },
        {
            "ids": [0, 1],
            "pubshares": [0, 1],
            "my_id": 0,
            "secshare_index": 0,
            "msg": 0,
            "rand": 0,
            "aggothernonce": "048465FCF0BBDBCF443AABCCE533D42B4B5A10966AC09A49655E8C42DAAB8FCD61037496A3CC86926D452CAFCFD55D25972CA1675D549310DE296BFF42F72EEEA8C9",
            "error": "invalid_contrib",
            "comment": "Aggregate of the other signers' nonces is invalid: first half has an unknown tag 0x04",
        },
        {
            "ids": [0, 1],
            "pubshares": [0, 1],
            "my_id": 0,
            "secshare_index": 0,
            "msg": 0,
            "rand": 0,
            "aggothernonce": "0000000000000000000000000000000000000000000000000000000000000000000287BF891D2A6DEAEBADC909352AA9405D1428C15F4B75F04DAE642A95C2548480",
            "error": "invalid_contrib",
            "comment": "Aggregate of the other signers' nonces is invalid: first half is all zeros",
        },
        {
            "ids": [0, 1],
            "pubshares": [0, 1],
            "my_id": 0,
            "secshare_index": 0,
            "msg": 0,
            "rand": 0,
            "aggothernonce": "0353BC2314D46C813AF81317AF1BDF99816B6444E416BB8D3DC04ACB2F5388D1AC020000000000000000000000000000000000000000000000000000000000000009",
            "error": "invalid_contrib",
            "comment": "Aggregate of the other signers' nonces is invalid: second half is not a point on the curve",
        },
        {
            "ids": [0, 1],
            "pubshares": [0, 1],
            "my_id": 0,
            "secshare_index": 0,
            "msg": 0,
            "rand": 0,
            "aggothernonce": "0353BC2314D46C813AF81317AF1BDF99816B6444E416BB8D3DC04ACB2F5388D1AC02FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30",
            "error": "invalid_contrib",
            "comment": "Aggregate of the other signers' nonces is invalid: second half's x-coordinate exceeds the field size",
        },
        {
            "ids": [0, 1],
            "pubshares": [0, 1],
            "my_id": 0,
            "secshare_index": 0,
            "msg": 0,
            "rand": 0,
            "tweaks": INVALID_TWEAK_IDX,
            "is_xonly": [False],
            "error": "value",
            "comment": "Tweak exceeds the group order",
        },
    ]
    for case in error_cases:
        curr_ids = [ids[i] for i in case["ids"]]
        curr_pubshares = [pubshares[i] for i in case["pubshares"]]
        curr_msg = COMMON_MSGS[case["msg"]]
        curr_rand = rands[case["rand"]]
        my_id = case["my_id"]
        secshare_index = case["secshare_index"]
        tweaks_idx = case.get("tweaks", None)
        curr_tweaks = [] if tweaks_idx is None else tweaks[tweaks_idx]
        curr_tweak_modes = case.get("is_xonly", [])

        # generate `aggothernonce` (every signer's nonce except this signer's own)
        is_aggothernonce = case.get("aggothernonce", None)
        if is_aggothernonce is None:
            other_pubnonces = []
            for i in case["ids"]:
                if ids[i] == my_id:
                    continue
                tmp = b"" if curr_rand is None else curr_rand
                _, pub = nonce_gen_internal(
                    tmp, secshares[i], pubshares[i], xonly_thresh_pk, curr_msg, None
                )
                other_pubnonces.append(pub)
            curr_aggothernonce = nonce_agg(other_pubnonces)
        else:
            curr_aggothernonce = bytes.fromhex(is_aggothernonce)

        expected_exception = (
            ValueError if case["error"] == "value" else InvalidContributionError
        )
        curr_signers = SignersContext(n, t, curr_ids, curr_pubshares, thresh_pk)
        error = expect_exception(
            lambda: deterministic_sign(
                secshares[secshare_index],
                my_id,
                curr_aggothernonce,
                curr_signers,
                curr_tweaks,
                curr_tweak_modes,
                curr_msg,
                curr_rand,
            ),
            expected_exception,
        )

        group["error_tests"].append(
            {
                "tc_id": tc_id,
                "comment": case["comment"],
                "my_id": my_id,
                "ids": curr_ids,
                "pubshare_indices": case["pubshares"],
                "secshare_index": secshare_index,
                "aggothernonce": bytes_to_hex(curr_aggothernonce),
                "rand": bytes_to_hex(curr_rand) if curr_rand is not None else curr_rand,
                "msg": bytes_to_hex(curr_msg),
                "tweaks": bytes_list_to_hex(curr_tweaks),
                "is_xonly": curr_tweak_modes,
                "error": error,
            }
        )
        tc_id += 1

    vectors = {"test_groups": [group]}
    write_test_vectors("det_sign_vectors.json", vectors)


def generate_sig_agg_vectors():
    n, t, thresh_pk, ids, secshares, pubshares = frost_keygen(SECKEY_2OF3)
    xonly_thresh_pk = thresh_pk[1:]

    secnonces, pubnonces = generate_all_nonces(
        COMMON_RAND, secshares, pubshares, xonly_thresh_pk
    )

    msg = COMMON_MSGS[0]

    group = {
        "tg_id": "2of3",
        "t": t,
        "n": n,
        "thresh_pk": bytes_to_hex(thresh_pk),
        "pubshares": bytes_list_to_hex(pubshares),
        "tweaks": bytes_list_to_hex(COMMON_TWEAKS),
        "valid_tests": [],
        "error_tests": [],
    }
    tc_id = 1

    # --- Valid Test Cases ---
    valid_cases = [
        {
            "indices": [0, 1],
            "comment": "Minimum threshold subset of signers (t=2 of n=3), no tweaks",
        },
        {
            "indices": [1, 0],
            "comment": "Signer order does not affect the aggregate signature: partial signatures are summed, so this matches the first valid case",
        },
        {
            "indices": [0, 1],
            "tweaks": [0, 1, 2],
            "is_xonly": [True, False, False],
            "comment": "Aggregation with three tweaks applied (one x-only, two plain)",
        },
        {
            "indices": [0, 1, 2],
            "comment": "All n=3 signers participate, no tweaks",
        },
    ]
    for case in valid_cases:
        curr_ids = [ids[i] for i in case["indices"]]
        curr_pubshares = [pubshares[i] for i in case["indices"]]
        curr_pubnonces = [pubnonces[i] for i in case["indices"]]
        curr_aggnonce = nonce_agg(curr_pubnonces)
        curr_msg = msg
        tweak_indices = case.get("tweaks", [])
        curr_tweaks = [COMMON_TWEAKS[i] for i in tweak_indices]
        curr_tweak_modes = case.get("is_xonly", [])
        psigs = []
        curr_signers = SignersContext(n, t, curr_ids, curr_pubshares, thresh_pk)
        session_ctx = SessionContext(
            curr_aggnonce,
            curr_signers,
            curr_tweaks,
            curr_tweak_modes,
            curr_msg,
        )
        for signer_index, i in enumerate(case["indices"]):
            my_id = ids[i]
            sig = sign(bytearray(secnonces[i]), secshares[i], my_id, session_ctx)
            psigs.append(sig)
            assert partial_sig_verify(
                sig,
                curr_pubnonces,
                curr_signers,
                curr_tweaks,
                curr_tweak_modes,
                curr_msg,
                signer_index,
            )
        bip340_sig = partial_sig_agg(psigs, session_ctx)
        group["valid_tests"].append(
            {
                "tc_id": tc_id,
                "comment": case["comment"],
                "ids": curr_ids,
                "pubshare_indices": case["indices"],
                "aggnonce": bytes_to_hex(curr_aggnonce),
                "tweak_indices": tweak_indices,
                "is_xonly": curr_tweak_modes,
                "psigs": bytes_list_to_hex(psigs),
                "msg": bytes_to_hex(curr_msg),
                "expected": bytes_to_hex(bip340_sig),
            }
        )
        tc_id += 1

    # --- Error Test Cases ---
    error_cases = [
        {
            "indices": [0, 1],
            "error": "invalid_contrib",
            "comment": "Partial signature equals the group order, which is out of range",
        },
    ]
    for j, case in enumerate(error_cases):
        curr_ids = [ids[i] for i in case["indices"]]
        curr_pubshares = [pubshares[i] for i in case["indices"]]
        curr_pubnonces = [pubnonces[i] for i in case["indices"]]
        curr_aggnonce = nonce_agg(curr_pubnonces)
        curr_msg = msg
        psigs = []
        curr_signers = SignersContext(n, t, curr_ids, curr_pubshares, thresh_pk)
        session_ctx = SessionContext(curr_aggnonce, curr_signers, [], [], curr_msg)
        for signer_index, i in enumerate(case["indices"]):
            my_id = ids[i]
            sig = sign(bytearray(secnonces[i]), secshares[i], my_id, session_ctx)
            psigs.append(sig)
            assert partial_sig_verify(
                sig,
                curr_pubnonces,
                curr_signers,
                [],
                [],
                curr_msg,
                signer_index,
            )

        if j == 0:
            invalid_psig = bytes.fromhex(
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
            )
            psigs[1] = invalid_psig

        expected_exception = (
            ValueError if case["error"] == "value" else InvalidContributionError
        )
        error = expect_exception(
            lambda: partial_sig_agg(psigs, session_ctx), expected_exception
        )
        group["error_tests"].append(
            {
                "tc_id": tc_id,
                "comment": case["comment"],
                "ids": curr_ids,
                "pubshare_indices": case["indices"],
                "aggnonce": bytes_to_hex(curr_aggnonce),
                "tweak_indices": [],
                "is_xonly": [],
                "psigs": bytes_list_to_hex(psigs),
                "msg": bytes_to_hex(curr_msg),
                "error": error,
            }
        )
        tc_id += 1

    vectors = {"test_groups": [group]}
    write_test_vectors("sig_agg_vectors.json", vectors)


def create_vectors_directory():
    os.makedirs("vectors", exist_ok=True)
    for f in glob.glob("vectors/*.json"):
        os.remove(f)


def run_gen_vectors(test_name, test_func):
    max_len = 30
    test_name = test_name.ljust(max_len, ".")
    print(f"Running {test_name}...", end="", flush=True)
    try:
        test_func()
        print("Done!")
    except Exception as e:
        print(f"Failed :'(\nError: {e}")


def main():
    create_vectors_directory()

    run_gen_vectors("generate_nonce_gen_vectors", generate_nonce_gen_vectors)
    run_gen_vectors("generate_nonce_agg_vectors", generate_nonce_agg_vectors)
    run_gen_vectors("generate_sign_verify_vectors", generate_sign_verify_vectors)
    run_gen_vectors("generate_tweak_vectors", generate_tweak_vectors)
    run_gen_vectors("generate_det_sign_vectors", generate_det_sign_vectors)
    run_gen_vectors("generate_sig_agg_vectors", generate_sig_agg_vectors)
    print("Test vectors generated successfully")


if __name__ == "__main__":
    sys.exit(main())
