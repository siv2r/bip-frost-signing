import json
import os
import re
import secrets
from typing import Dict, List, Sequence, Union

from frost_ref.signing import derive_interpolating_value, nonce_gen_internal
from secp256k1lab.secp256k1 import Scalar
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
