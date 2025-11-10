#!/usr/bin/env python3

import json
import os
import shutil
import sys
from copy import deepcopy
from typing import Dict, List, Sequence, Union

from frost_ref import (
    InvalidContributionError,
    SessionContext,
    deterministic_sign,
    nonce_agg,
    partial_sig_agg,
    partial_sig_verify,
    sign,
)
from frost_ref.signing import nonce_gen_internal
from secp256k1lab.secp256k1 import GE
from secp256k1lab.util import bytes_from_int, int_from_bytes

scalar_size = GE.ORDER


def bytes_to_hex(data: bytes) -> str:
    return data.hex().upper()


def bytes_list_to_hex(lst: Sequence[bytes]) -> List[str]:
    return [l_i.hex().upper() for l_i in lst]


def hex_list_to_bytes(lst: List[str]) -> List[bytes]:
    return [bytes.fromhex(l_i) for l_i in lst]


def int_list_to_bytes(lst: List[int]) -> List[bytes]:
    return [x.to_bytes(32, "big") for x in lst]


def point_to_hex(P):
    res = b""
    if P[1] % 2 == 0:
        res += b"\x02"
    else:
        res += b"\x03"
    res += P[0].to_bytes(32, "big")
    assert len(res) == 33
    return res.hex().upper()


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


def get_frost_keys():
    n = 5  # noqa: F841
    t = 3
    group_pubkey = bytes.fromhex(
        "03F9186397E61022663935B3FDFF7880A9F0EC288D8B054DF6AC2BC5777B5FBBB1"
    )
    secshares = hex_list_to_bytes(
        [
            "6FF0F78C1F0E76C4AB67C1B32E0B4B1652120B794AC1AE7EC3992DE06092B566",
            "6AA9C77B0E11698988CFC04769B0C1C75302BEA5F13A952A0F6CDE10B7CB5281",
            "23D5D746FA6798F85E3E58A02FBBD1529D58651A2F5C986FBA85E0C36E445E84",
            "9B7526EFE41105112BB38ABD802C79B6EBC1DBBCB470588B84B6948554341AB0",
            "D187B675CB0DADD3F12F569F5B02BAF5839045A6D12D3541AE2C9AC9996445C4",
        ]
    )
    pubshares = hex_list_to_bytes(
        [
            "0260C5B10BAF5D471F0D09ED9BDED80B23CEFE0C9DC0F26AD1A0453A6FDFF663E2",
            "028B96AE32F17C49C6111D6BF7D17E89428734D6DED0E31C480F2BABD263DDFA28",
            "029456C5A981CF9DA72BF7AF0F82C44A343DC08419911286E975D16697D93B9A61",
            "030CAA62081616E0B833FBD39A1058C1A11A23FB8307127D486914E8BF2E5935BB",
            "03E483B7D41072D6E883447EB85617A086290EB67B40C89F3A787CF1B66005F488",
        ]
    )
    return (t, group_pubkey, secshares, pubshares)
    # group_pubkey = individual_pk(group_secret)
    # gpk, secshares, pubshares = trusted_dealer_keygen(
    #     int.from_bytes(group_secret, "big"),
    #     5,
    #     3
    # )
    # # assert group_pubkey == gpk
    # pprint(group_pubkey.hex().upper())
    # print("....")
    # secshares = [hex(share[1]).upper() for share in secshares]
    # pubshares = [point_to_hex(P) for P in pubshares]
    # print(f"group pk = {point_to_hex(gpk)}")
    # print(f"secshares = ")
    # print(secshares)
    # print(f"pubshares = ")
    # print(pubshares)


# REVIEW: I think we don't need this vector because this doesn't really test
# the keygen mechanism used by the user. It simply gives one example of a
# valid FROST key
def generate_keygen_vectors():
    vectors = {
        "valid_test_cases": [],
        "pubshare_correctness_fail_test_cases": [],
        "group_pubkey_correctness_fail_test_cases": [],
    }

    t, group_pk, secshares, pubshares = get_frost_keys()
    n = len(pubshares)
    # --- Valid Test Case 1 ---
    vectors["valid_test_cases"].append(
        {
            "max_participants": n,
            "min_participants": t,
            "group_public_key": bytes_to_hex(group_pk),
            "participant_identifiers": list(range(n)),
            "participant_pubshares": bytes_list_to_hex(pubshares),
            "participant_secshares": bytes_list_to_hex(secshares),
        }
    )

    # --- Pubshare correctness Fail Test Case 1 ---
    invalid_pubshare = deepcopy(pubshares[0])
    # flips '\x02' to '\x03`, and vice versa`
    invalid_pubshare = bytes([invalid_pubshare[0] ^ 1]) + invalid_pubshare[1:]
    invalid_pubshares = [invalid_pubshare] + pubshares[1:]
    vectors["pubshare_correctness_fail_test_cases"].append(
        {
            "max_participants": n,
            "min_participants": t,
            "group_public_key": bytes_to_hex(group_pk),
            "participant_identifiers": list(range(n)),
            "participant_pubshares": bytes_list_to_hex(invalid_pubshares),
            "participant_secshares": bytes_list_to_hex(secshares),
        }
    )

    # --- Group Pubkey correctness Fail Test Case 1 ---
    # flips '\x02' to '\x03`, and vice versa`
    invalid_group_pk = bytes([group_pk[0] ^ 1]) + group_pk[1:]
    vectors["group_pubkey_correctness_fail_test_cases"].append(
        {
            "max_participants": n,
            "min_participants": t,
            "group_public_key": bytes_to_hex(invalid_group_pk),
            "participant_identifiers": list(range(n)),
            "participant_pubshares": bytes_list_to_hex(pubshares),
            "participant_secshares": bytes_list_to_hex(secshares),
        }
    )

    output_file = os.path.join("vectors", "keygen_vectors.json")
    with open(output_file, "w") as f:
        json.dump(vectors, f, indent=4)


def generate_nonce_gen_vectors():
    vectors = {"test_cases": []}

    t, group_pk, secshares, pubshares = get_frost_keys()
    rand = bytes.fromhex(
        "0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F"
    )
    extra_in = bytes.fromhex(
        "0808080808080808080808080808080808080808080808080808080808080808"
    )
    xonly_group_pk = group_pk[1:]

    # --- Valid Test Case 1 ---
    msg = bytes.fromhex(
        "0101010101010101010101010101010101010101010101010101010101010101"
    )
    secnonce, pubnonce = nonce_gen_internal(
        rand, secshares[0], pubshares[0], xonly_group_pk, msg, extra_in
    )
    vectors["test_cases"].append(
        {
            "rand_": bytes_to_hex(rand),
            "secshare": bytes_to_hex(secshares[0]),
            "pubshare": bytes_to_hex(pubshares[0]),
            "group_pk": bytes_to_hex(xonly_group_pk),
            "msg": bytes_to_hex(msg),
            "extra_in": bytes_to_hex(extra_in),
            "expected_secnonce": bytes_to_hex(secnonce),
            "expected_pubnonce": bytes_to_hex(pubnonce),
            "comment": "",
        }
    )
    # --- Valid Test Case 2 ---
    empty_msg = b""
    secnonce, pubnonce = nonce_gen_internal(
        rand, secshares[0], pubshares[0], xonly_group_pk, empty_msg, extra_in
    )
    vectors["test_cases"].append(
        {
            "rand_": bytes_to_hex(rand),
            "secshare": bytes_to_hex(secshares[0]),
            "pubshare": bytes_to_hex(pubshares[0]),
            "group_pk": bytes_to_hex(xonly_group_pk),
            "msg": bytes_to_hex(empty_msg),
            "extra_in": bytes_to_hex(extra_in),
            "expected_secnonce": bytes_to_hex(secnonce),
            "expected_pubnonce": bytes_to_hex(pubnonce),
            "comment": "Empty Message",
        }
    )
    # --- Valid Test Case 3 ---
    long_msg = bytes.fromhex(
        "2626262626262626262626262626262626262626262626262626262626262626262626262626"
    )
    secnonce, pubnonce = nonce_gen_internal(
        rand, secshares[0], pubshares[0], xonly_group_pk, long_msg, extra_in
    )
    vectors["test_cases"].append(
        {
            "rand_": bytes_to_hex(rand),
            "secshare": bytes_to_hex(secshares[0]),
            "pubshare": bytes_to_hex(pubshares[0]),
            "group_pk": bytes_to_hex(xonly_group_pk),
            "msg": bytes_to_hex(long_msg),
            "extra_in": bytes_to_hex(extra_in),
            "expected_secnonce": bytes_to_hex(secnonce),
            "expected_pubnonce": bytes_to_hex(pubnonce),
            "comment": "38-byte message",
        }
    )
    # --- Valid Test Case 4 ---
    secnonce, pubnonce = nonce_gen_internal(rand, None, None, None, None, None)
    vectors["test_cases"].append(
        {
            "rand_": bytes_to_hex(rand),
            "secshare": None,
            "pubshare": None,
            "group_pk": None,
            "msg": None,
            "extra_in": None,
            "expected_secnonce": bytes_to_hex(secnonce),
            "expected_pubnonce": bytes_to_hex(pubnonce),
            "comment": "Every optional parameter is absent",
        }
    )

    output_file = os.path.join("vectors", "nonce_gen_vectors.json")
    with open(output_file, "w") as f:
        json.dump(vectors, f, indent=4)


# REVIEW: we can simply use the pubnonces directly in the valid & error
# test cases, instead of referencing their indices
def generate_nonce_agg_vectors():
    vectors = dict()

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

    vectors["valid_test_cases"] = []
    # --- Valid Test Case 1 ---
    pubnonce_indices = [0, 1]
    curr_pubnonces = [pubnonces[i] for i in pubnonce_indices]
    pids = [0, 1]
    aggnonce = nonce_agg(curr_pubnonces, pids)
    vectors["valid_test_cases"].append(
        {
            "pubnonce_indices": pubnonce_indices,
            "participant_identifiers": pids,
            "expected_aggnonce": bytes_to_hex(aggnonce),
        }
    )
    # --- Valid Test Case 2 ---
    pubnonce_indices = [2, 3]
    curr_pubnonces = [pubnonces[i] for i in pubnonce_indices]
    pids = [0, 1]
    aggnonce = nonce_agg(curr_pubnonces, pids)
    vectors["valid_test_cases"].append(
        {
            "pubnonce_indices": pubnonce_indices,
            "participant_identifiers": pids,
            "expected_aggnonce": bytes_to_hex(aggnonce),
            "comment": "Sum of second points encoded in the nonces is point at infinity which is serialized as 33 zero bytes",
        }
    )

    vectors["error_test_cases"] = []
    # --- Error Test Case 1 ---
    pubnonce_indices = [0, 4]
    curr_pubnonces = [pubnonces[i] for i in pubnonce_indices]
    pids = [0, 1]
    error = expect_exception(
        lambda: nonce_agg(curr_pubnonces, pids), InvalidContributionError
    )
    vectors["error_test_cases"].append(
        {
            "pubnonce_indices": pubnonce_indices,
            "participant_identifiers": pids,
            "error": error,
            "comment": "Public nonce from signer 2 is invalid due wrong tag, 0x04, in the first half",
        }
    )
    # --- Error Test Case 2 ---
    pubnonce_indices = [5, 1]
    curr_pubnonces = [pubnonces[i] for i in pubnonce_indices]
    pids = [0, 1]
    error = expect_exception(
        lambda: nonce_agg(curr_pubnonces, pids), InvalidContributionError
    )
    vectors["error_test_cases"].append(
        {
            "pubnonce_indices": pubnonce_indices,
            "participant_identifiers": pids,
            "error": error,
            "comment": "Public nonce from signer 1 is invalid because the second half does not correspond to an X coordinate",
        }
    )
    # --- Error Test Case 3 ---
    pubnonce_indices = [6, 1]
    curr_pubnonces = [pubnonces[i] for i in pubnonce_indices]
    pids = [0, 1]
    error = expect_exception(
        lambda: nonce_agg(curr_pubnonces, pids), InvalidContributionError
    )
    vectors["error_test_cases"].append(
        {
            "pubnonce_indices": pubnonce_indices,
            "participant_identifiers": pids,
            "error": error,
            "comment": "Public nonce from signer 1 is invalid because second half exceeds field size",
        }
    )

    output_file = os.path.join("vectors", "nonce_agg_vectors.json")
    with open(output_file, "w") as f:
        json.dump(vectors, f, indent=4)


# TODO: Remove `pubnonces` param from these vectors. It's not used.
def generate_sign_verify_vectors():
    vectors = dict()

    t, group_pk, secshares, pubshares = get_frost_keys()
    n = len(pubshares)
    xonly_group_pk = group_pk[1:]
    secshare_p1 = secshares[0]
    ids = list(range(n))
    assert len(pubshares) == len(secshares)

    vectors["max_participants"] = n
    vectors["min_participants"] = t
    vectors["group_public_key"] = bytes_to_hex(group_pk)
    vectors["secshare_p1"] = bytes_to_hex(secshare_p1)
    vectors["identifiers"] = ids
    pubshares.append(  # add an invalid pubshare at the end
        bytes.fromhex(
            "020000000000000000000000000000000000000000000000000000000000000007"
        )
    )
    vectors["pubshares"] = bytes_list_to_hex(pubshares)

    rand_ = bytes.fromhex(
        "0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F"
    )
    secnonces = []
    pubnonces = []
    for i in range(n):
        sec, pub = nonce_gen_internal(
            rand_, secshares[i], pubshares[i], xonly_group_pk, None, None
        )
        secnonces.append(sec)
        pubnonces.append(pub)
    secnonces_p1 = [
        secnonces[0],
        bytes.fromhex(
            "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        ),  # all zero
    ]
    vectors["secnonces_p1"] = bytes_list_to_hex(secnonces_p1)
    # compute -(pubnonce[0] + pubnonce[1])
    tmp = nonce_agg(pubnonces[:2], ids[:2])
    inv_pubnonce = b"".join(
        [
            bytes([tmp[0] ^ 1]),  # flip first byte
            tmp[1:33],  # keep next 32 bytes
            bytes([tmp[33] ^ 1]),  # flip 34th byte
            tmp[34:66],  # keep next 32 bytes
        ]
    )
    invalid_pubnonce = bytes.fromhex(
        "0200000000000000000000000000000000000000000000000000000000000000090287BF891D2A6DEAEBADC909352AA9405D1428C15F4B75F04DAE642A95C2548480"
    )
    pubnonces += [invalid_pubnonce, inv_pubnonce]
    vectors["pubnonces"] = bytes_list_to_hex(pubnonces)

    # create valid aggnonces
    indices_grp = [
        [0, 1, 2],
        [0, 3, 4],
        [0, 1, 2, 3],
        [0, 1, 2, 3, 4],
    ]
    aggnonces = [
        nonce_agg([pubnonces[i] for i in indices], [ids[i] for i in indices])
        for indices in indices_grp
    ]
    # aggnonce with inf points
    aggnonces.append(
        nonce_agg(
            [pubnonces[0], pubnonces[1], pubnonces[-1]],
            [ids[0], ids[1], ids[2]],
        )
    )
    # invalid aggnonces
    aggnonces += [
        bytes.fromhex(
            "048465FCF0BBDBCF443AABCCE533D42B4B5A10966AC09A49655E8C42DAAB8FCD61037496A3CC86926D452CAFCFD55D25972CA1675D549310DE296BFF42F72EEEA8C9"
        ),  # wrong parity tag 04
        bytes.fromhex(
            "028465FCF0BBDBCF443AABCCE533D42B4B5A10966AC09A49655E8C42DAAB8FCD61020000000000000000000000000000000000000000000000000000000000000009"
        ),  # invalid x coordinate in second half
        bytes.fromhex(
            "028465FCF0BBDBCF443AABCCE533D42B4B5A10966AC09A49655E8C42DAAB8FCD6102FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30"
        ),  # second half exceeds field size
    ]
    vectors["aggnonces"] = bytes_list_to_hex(aggnonces)

    msgs = [
        bytes.fromhex(
            "F95466D086770E689964664219266FE5ED215C92AE20BAB5C9D79ADDDDF3C0CF"
        ),
        bytes.fromhex(""),
        bytes.fromhex(
            "2626262626262626262626262626262626262626262626262626262626262626262626262626"
        ),
    ]
    vectors["msgs"] = bytes_list_to_hex(msgs)

    vectors["valid_test_cases"] = []
    # --- Valid Test Cases ---
    # Every List[int] & int below represents indices
    # REVIEW: add secnonce here (easy readability), than using `secnonce_p1` list as common prefix
    valid_cases = [
        {
            "ids": [0, 1, 2],
            "pubshares": [0, 1, 2],
            "pubnonces": [0, 1, 2],
            "aggnonce": 0,
            "msg": 0,
            "signer": 0,
            "comment": "Signing with minimum number of participants",
        },
        {
            "ids": [1, 0, 2],
            "pubshares": [1, 0, 2],
            "pubnonces": [1, 0, 2],
            "aggnonce": 0,
            "msg": 0,
            "signer": 1,
            "comment": "Partial-signature doesn't change if the order of signers set changes (without changing secnonces)",
        },
        {
            "ids": [0, 3, 4],
            "pubshares": [0, 3, 4],
            "pubnonces": [0, 3, 4],
            "aggnonce": 1,
            "msg": 0,
            "signer": 0,
            "comment": "Partial-signature changes if the members of signers set changes",
        },
        {
            "ids": [0, 1, 2, 3],
            "pubshares": [0, 1, 2, 3],
            "pubnonces": [0, 1, 2, 3],
            "aggnonce": 2,
            "msg": 0,
            "signer": 0,
            "comment": "Signing with t < number of participants < n",
        },
        {
            "ids": [0, 1, 2, 3, 4],
            "pubshares": [0, 1, 2, 3, 4],
            "pubnonces": [0, 1, 2, 3, 4],
            "aggnonce": 3,
            "msg": 0,
            "signer": 0,
            "comment": "Signing with max number of participants",
        },
        {
            "ids": [0, 1, 2],
            "pubshares": [0, 1, 2],
            "pubnonces": [0, 1, 6],
            "aggnonce": 4,
            "msg": 0,
            "signer": 0,
            "comment": "Both halves of aggregate nonce correspond to point at infinity",
        },
        {
            "ids": [0, 1, 2],
            "pubshares": [0, 1, 2],
            "pubnonces": [0, 1, 2],
            "aggnonce": 0,
            "msg": 1,
            "signer": 0,
            "comment": "Empty message",
        },
        {
            "ids": [0, 1, 2],
            "pubshares": [0, 1, 2],
            "pubnonces": [0, 1, 2],
            "aggnonce": 0,
            "msg": 2,
            "signer": 0,
            "comment": "Message longer than 32 bytes (38-byte msg)",
        },
    ]
    for case in valid_cases:
        curr_ids = [ids[i] for i in case["ids"]]
        curr_pubshares = [pubshares[i] for i in case["pubshares"]]
        curr_pubnonces = [pubnonces[i] for i in case["pubnonces"]]
        curr_aggnonce = aggnonces[case["aggnonce"]]
        curr_msg = msgs[case["msg"]]
        my_id = curr_ids[case["signer"]]
        session_ctx = SessionContext(
            curr_aggnonce, curr_ids, curr_pubshares, [], [], curr_msg
        )
        expected_psig = sign(
            bytearray(secnonces_p1[0]), secshare_p1, my_id, session_ctx
        )
        vectors["valid_test_cases"].append(
            {
                "id_indices": case["ids"],
                "pubshare_indices": case["pubshares"],
                "pubnonce_indices": case["pubnonces"],
                "aggnonce_index": case["aggnonce"],
                "msg_index": case["msg"],
                "signer_index": case["signer"],
                "expected": bytes_to_hex(expected_psig),
                "comment": case["comment"],
            }
        )
        # TODO: verify the signatures here

    vectors["sign_error_test_cases"] = []
    # --- Sign Error Test Cases ---
    error_cases = [
        {
            "ids": [3, 1, 2],
            "pubshares": [0, 1, 2],
            "aggnonce": 0,
            "msg": 0,
            "signer_idx": None,
            "signer_id": 0,
            "secnonce": 0,
            "error": "value",
            "comment": "The signer's id is not in the participant identifier list",
        },
        {
            "ids": [0, 1, 2, 1],
            "pubshares": [0, 1, 2, 1],
            "aggnonce": 0,
            "msg": 0,
            "signer_idx": 0,
            "secnonce": 0,
            "error": "value",
            "comment": "The participant identifier list contains duplicate elements",
        },
        {
            "ids": [0, 1, 2],
            "pubshares": [3, 1, 2],
            "aggnonce": 0,
            "msg": 0,
            "signer_idx": 0,
            "secnonce": 0,
            "error": "value",
            "comment": "The signer's pubshare is not in the list of pubshares. This test case is optional: it can be skipped by implementations that do not check that the signer's pubshare is included in the list of pubshares.",
        },
        {
            "ids": [0, 1, 2],
            "pubshares": [0, 1],
            "aggnonce": 0,
            "msg": 0,
            "signer_idx": 0,
            "secnonce": 0,
            "error": "value",
            "comment": "The participant identifiers count exceed the participant public shares count",
        },
        {
            "ids": [0, 1, 2],
            "pubshares": [0, 1, 5],
            "aggnonce": 0,
            "msg": 0,
            "signer_idx": 0,
            "secnonce": 0,
            "error": "invalid_contrib",
            "comment": "Signer 3 provided an invalid participant public share",
        },
        {
            "ids": [0, 1, 2],
            "pubshares": [0, 1, 2],
            "aggnonce": 5,
            "msg": 0,
            "signer_idx": 0,
            "secnonce": 0,
            "error": "invalid_contrib",
            "comment": "Aggregate nonce is invalid due wrong tag, 0x04, in the first half",
        },
        {
            "ids": [0, 1, 2],
            "pubshares": [0, 1, 2],
            "aggnonce": 6,
            "msg": 0,
            "signer_idx": 0,
            "secnonce": 0,
            "error": "invalid_contrib",
            "comment": "Aggregate nonce is invalid because the second half does not correspond to an X coordinate",
        },
        {
            "ids": [0, 1, 2],
            "pubshares": [0, 1, 2],
            "aggnonce": 7,
            "msg": 0,
            "signer_idx": 0,
            "secnonce": 0,
            "error": "invalid_contrib",
            "comment": "Aggregate nonce is invalid because second half exceeds field size",
        },
        {
            "ids": [0, 1, 2],
            "pubshares": [0, 1, 2],
            "aggnonce": 0,
            "msg": 0,
            "signer_idx": 0,
            "secnonce": 1,
            "error": "value",
            "comment": "Secnonce is invalid which may indicate nonce reuse",
        },
    ]
    for case in error_cases:
        curr_ids = [ids[i] for i in case["ids"]]
        curr_pubshares = [pubshares[i] for i in case["pubshares"]]
        curr_aggnonce = aggnonces[case["aggnonce"]]
        curr_msg = msgs[case["msg"]]
        if case["signer_idx"] is None:
            my_id = case["signer_id"]
        else:
            my_id = curr_ids[case["signer_idx"]]
        session_ctx = SessionContext(
            curr_aggnonce, curr_ids, curr_pubshares, [], [], curr_msg
        )
        curr_secnonce = bytearray(secnonces_p1[case["secnonce"]])
        expected_error = (
            ValueError if case["error"] == "value" else InvalidContributionError
        )
        error = expect_exception(
            lambda: sign(curr_secnonce, secshare_p1, my_id, session_ctx), expected_error
        )
        vectors["sign_error_test_cases"].append(
            {
                "id_indices": case["ids"],
                "pubshare_indices": case["pubshares"],
                "aggnonce_index": case["aggnonce"],
                "msg_index": case["msg"],
                "signer_index": case["signer_idx"],
                **(
                    {"signer_id": case["signer_id"]}
                    if case["signer_idx"] is None
                    else {}
                ),
                "secnonce_index": case["secnonce"],
                "error": error,
                "comment": case["comment"],
            }
        )

    # REVIEW: In the following vectors, pubshare_indices are not required,
    # just aggnonce value would do. But we should include `secshare` and
    # `secnonce` indices tho.
    vectors["verify_fail_test_cases"] = []
    # --- Verify Fail Test Cases ---
    id_indices = [0, 1, 2]
    pubshare_indices = [0, 1, 2]
    pubnonce_indices = [0, 1, 2]
    aggnonce_idx = 0
    msg_idx = 0
    signer_idx = 0

    curr_ids = [ids[i] for i in id_indices]
    curr_pubshares = [pubshares[i] for i in pubnonce_indices]
    curr_aggnonce = aggnonces[aggnonce_idx]
    curr_msg = msgs[msg_idx]
    my_id = curr_ids[signer_idx]
    session_ctx = SessionContext(
        curr_aggnonce, curr_ids, curr_pubshares, [], [], curr_msg
    )
    curr_secnonce = bytearray(secnonces_p1[0])
    psig = sign(curr_secnonce, secshare_p1, my_id, session_ctx)
    # --- Verify Fail Test Cases 1 ---
    neg_psig = bytes_from_int(scalar_size - int_from_bytes(psig))
    vectors["verify_fail_test_cases"].append(
        {
            "psig": bytes_to_hex(neg_psig),
            "id_indices": id_indices,
            "pubshare_indices": pubshare_indices,
            "pubnonce_indices": pubnonce_indices,
            "msg_index": msg_idx,
            "signer_index": signer_idx,
            "comment": "Wrong signature (which is equal to the negation of valid signature)",
        }
    )
    # --- Verify Fail Test Cases 2 ---
    vectors["verify_fail_test_cases"].append(
        {
            "psig": bytes_to_hex(psig),
            "id_indices": id_indices,
            "pubshare_indices": pubshare_indices,
            "pubnonce_indices": pubnonce_indices,
            "msg_index": msg_idx,
            "signer_index": signer_idx + 1,
            "comment": "Wrong signer index",
        }
    )
    # --- Verify Fail Test Cases 3 ---
    vectors["verify_fail_test_cases"].append(
        {
            "psig": bytes_to_hex(psig),
            "id_indices": id_indices,
            "pubshare_indices": [3] + pubshare_indices[1:],
            "pubnonce_indices": pubnonce_indices,
            "msg_index": msg_idx,
            "signer_index": signer_idx,
            "comment": "The signer's pubshare is not in the list of pubshares",
        }
    )
    # --- Verify Fail Test Cases 4 ---
    vectors["verify_fail_test_cases"].append(
        {
            "psig": "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
            "id_indices": id_indices,
            "pubshare_indices": pubshare_indices,
            "pubnonce_indices": pubnonce_indices,
            "msg_index": msg_idx,
            "signer_index": signer_idx,
            "comment": "Signature value is out of range",
        }
    )

    vectors["verify_error_test_cases"] = []
    # --- Verify Error Test Cases ---
    verify_error_cases = [
        {
            "ids": [0, 1, 2],
            "pubshares": [0, 1, 2],
            "pubnonces": [5, 1, 2],
            "msg": 0,
            "signer": 0,
            "error": "invalid_contrib",
            "comment": "Invalid pubnonce",
        },
        {
            "ids": [0, 1, 2],
            "pubshares": [5, 1, 2],
            "pubnonces": [0, 1, 2],
            "msg": 0,
            "signer": 0,
            "error": "invalid_contrib",
            "comment": "Invalid pubshare",
        },
        {
            "ids": [0, 1, 2],
            "pubshares": [0, 1, 2],
            "pubnonces": [0, 1, 2, 3],
            "msg": 0,
            "signer": 0,
            "error": "value",
            "comment": "public nonces count is greater than ids and pubshares",
        },
    ]
    for case in verify_error_cases:
        curr_ids = [ids[i] for i in case["ids"]]
        curr_pubshares = [pubshares[i] for i in case["pubshares"]]
        curr_pubnonces = [pubnonces[i] for i in case["pubnonces"]]
        msg = case["msg"]
        signer_idx = case["signer"]
        expected_error = (
            ValueError if case["error"] == "value" else InvalidContributionError
        )
        error = expect_exception(
            # reuse the valid `psig` generated at the start of "verify fail test cases"
            lambda: partial_sig_verify(
                psig, curr_ids, curr_pubnonces, curr_pubshares, [], [], msg, signer_idx
            ),
            expected_error,
        )
        vectors["verify_error_test_cases"].append(
            {
                "psig": bytes_to_hex(psig),
                "id_indices": case["ids"],
                "pubshare_indices": case["pubshares"],
                "pubnonce_indices": case["pubnonces"],
                "msg_index": case["msg"],
                "signer_index": case["signer"],
                "error": error,
                "comment": case["comment"],
            }
        )

    output_file = os.path.join("vectors", "sign_verify_vectors.json")
    with open(output_file, "w") as f:
        json.dump(vectors, f, indent=4)


def generate_tweak_vectors():
    vectors = dict()

    t, group_pk, secshares, pubshares = get_frost_keys()
    n = len(pubshares)
    xonly_group_pk = group_pk[1:]
    secshare_p1 = secshares[0]
    ids = list(range(n))
    assert len(pubshares) == len(secshares)

    vectors["max_participants"] = n
    vectors["min_participants"] = t
    vectors["group_public_key"] = bytes_to_hex(group_pk)
    vectors["secshare_p1"] = bytes_to_hex(secshare_p1)
    vectors["identifiers"] = ids
    pubshares.append(  # add an invalid pubshare at the end
        bytes.fromhex(
            "020000000000000000000000000000000000000000000000000000000000000007"
        )
    )
    vectors["pubshares"] = bytes_list_to_hex(pubshares)

    rand_ = bytes.fromhex(
        "0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F"
    )
    secnonces = []
    pubnonces = []
    for i in range(n):
        sec, pub = nonce_gen_internal(
            rand_, secshares[i], pubshares[i], xonly_group_pk, None, None
        )
        secnonces.append(sec)
        pubnonces.append(pub)
    secnonce_p1 = secnonces[0]
    vectors["secnonce_p1"] = bytes_to_hex(secnonce_p1)
    vectors["pubnonces"] = bytes_list_to_hex(pubnonces)

    # create valid aggnonces
    indices_grp = [
        [0, 1, 2],
        [0, 1, 2, 3],
        [0, 1, 2, 3, 4],
    ]
    aggnonces = [
        nonce_agg([pubnonces[i] for i in indices], [ids[i] for i in indices])
        for indices in indices_grp
    ]
    # aggnonce with inf points
    aggnonces.append(
        nonce_agg(
            [pubnonces[0], pubnonces[1], pubnonces[-1]],
            [ids[0], ids[1], ids[2]],
        )
    )
    vectors["aggnonces"] = bytes_list_to_hex(aggnonces)

    tweaks = hex_list_to_bytes(
        [
            "E8F791FF9225A2AF0102AFFF4A9A723D9612A682A25EBE79802B263CDFCD83BB",
            "AE2EA797CC0FE72AC5B97B97F3C6957D7E4199A167A58EB08BCAFFDA70AC0455",
            "F52ECBC565B3D8BEA2DFD5B75A4F457E54369809322E4120831626F290FA87E0",
            "1969AD73CC177FA0B4FCED6DF1F7BF9907E665FDE9BA196A74FED0A3CF5AEF9D",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
        ]
    )
    vectors["tweaks"] = bytes_list_to_hex(tweaks)

    msg = bytes.fromhex(
        "F95466D086770E689964664219266FE5ED215C92AE20BAB5C9D79ADDDDF3C0CF"
    )
    vectors["msg"] = bytes_to_hex(msg)

    vectors["valid_test_cases"] = []
    # --- Valid Test Cases ---
    valid_cases = [
        {"tweaks_indices": [], "is_xonly": [], "comment": "No tweak"},
        {"tweaks_indices": [0], "is_xonly": [True], "comment": "A single x-only tweak"},
        {"tweaks_indices": [0], "is_xonly": [False], "comment": "A single plain tweak"},
        {
            "tweaks_indices": [0, 1],
            "is_xonly": [False, True],
            "comment": "A plain tweak followed by an x-only tweak",
        },
        {
            "tweaks_indices": [0, 1, 2, 3],
            "is_xonly": [True, False, True, False],
            "comment": "Four tweaks: x-only, plain, x-only, plain. If an implementation prohibits applying plain tweaks after x-only tweaks, it can skip this test vector or return an error",
        },
        {
            "tweaks_indices": [0, 1, 2, 3],
            "is_xonly": [False, False, True, True],
            "comment": "Four tweaks: plain, plain, x-only, x-only",
        },
        {
            "tweaks_indices": [0, 1, 2, 3],
            "is_xonly": [False, False, True, True],
            "indices": [0, 1, 2, 3],
            "aggnonce_idx": 1,
            "comment": "Tweaking with t < number of signers < n. The expected value (partial sig) must match the previous test vector",
        },
        {
            "tweaks_indices": [0, 1, 2, 3],
            "is_xonly": [False, False, True, True],
            "indices": [0, 1, 2, 3, 4],
            "aggnonce_idx": 2,
            "comment": "Tweaking with maximum possible signers",
        },
    ]
    for case in valid_cases:
        indices = case.get("indices", [0, 1, 2])
        curr_ids = [ids[i] for i in indices]
        curr_pubshares = [pubshares[i] for i in indices]
        aggnonce_idx = case.get("aggnonce_idx", 0)
        curr_aggnonce = aggnonces[aggnonce_idx]
        curr_tweaks = [tweaks[i] for i in case["tweaks_indices"]]
        curr_tweak_modes = case["is_xonly"]
        signer_idx = 0
        my_id = curr_ids[signer_idx]

        session_ctx = SessionContext(
            curr_aggnonce, curr_ids, curr_pubshares, curr_tweaks, curr_tweak_modes, msg
        )
        psig = sign(bytearray(secnonce_p1), secshare_p1, my_id, session_ctx)

        vectors["valid_test_cases"].append(
            {
                "id_indices": indices,
                "pubshare_indices": indices,
                "pubnonce_indices": indices,
                "tweak_indices": case["tweaks_indices"],
                "aggnonce_index": aggnonce_idx,
                "is_xonly": curr_tweak_modes,
                "signer_index": signer_idx,
                "expected": bytes_to_hex(psig),
                "comment": case["comment"],
            }
        )

    vectors["error_test_cases"] = []
    # --- Error Test Cases ---
    error_cases = [
        {
            "tweaks_indices": [4],
            "is_xonly": [False],
            "comment": "Tweak is invalid because it exceeds group size",
        },
        {
            "tweaks_indices": [0, 1, 2, 3],
            "is_xonly": [True, False],
            "comment": "Tweaks count doesn't match the tweak modes count",
        },
    ]
    for case in error_cases:
        indices = [0, 1, 2]
        curr_ids = [ids[i] for i in indices]
        curr_pubshares = [pubshares[i] for i in indices]
        aggnonce_idx = 0
        curr_aggnonce = aggnonces[aggnonce_idx]
        curr_tweaks = [tweaks[i] for i in case["tweaks_indices"]]
        curr_tweak_modes = case["is_xonly"]
        signer_idx = 0
        my_id = curr_ids[signer_idx]

        session_ctx = SessionContext(
            curr_aggnonce, curr_ids, curr_pubshares, curr_tweaks, curr_tweak_modes, msg
        )
        error = expect_exception(
            lambda: sign(bytearray(secnonce_p1), secshare_p1, my_id, session_ctx),
            ValueError,
        )
        vectors["error_test_cases"].append(
            {
                "id_indices": indices,
                "pubshare_indices": indices,
                "tweak_indices": case["tweaks_indices"],
                "aggnonce_index": 0,
                "is_xonly": curr_tweak_modes,
                "signer_index": signer_idx,
                "error": error,
                "comment": case["comment"],
            }
        )

    output_file = os.path.join("vectors", "tweak_vectors.json")
    with open(output_file, "w") as f:
        json.dump(vectors, f, indent=4)


def generate_det_sign_vectors():
    vectors = dict()

    t, group_pk, secshares, pubshares = get_frost_keys()
    n = len(pubshares)
    xonly_group_pk = group_pk[1:]
    secshare_p1 = secshares[0]
    ids = list(range(n))
    assert len(pubshares) == len(secshares)

    vectors["max_participants"] = n
    vectors["min_participants"] = t
    vectors["group_public_key"] = bytes_to_hex(group_pk)
    vectors["secshare_p1"] = bytes_to_hex(secshare_p1)
    vectors["identifiers"] = ids
    pubshares.append(  # add an invalid pubshare at the end
        bytes.fromhex(
            "020000000000000000000000000000000000000000000000000000000000000007"
        )
    )
    vectors["pubshares"] = bytes_list_to_hex(pubshares)

    msgs = [
        bytes.fromhex(
            "F95466D086770E689964664219266FE5ED215C92AE20BAB5C9D79ADDDDF3C0CF"
        ),
        bytes.fromhex(""),
        bytes.fromhex(
            "2626262626262626262626262626262626262626262626262626262626262626262626262626"
        ),
    ]
    vectors["msgs"] = bytes_list_to_hex(msgs)
    assert len(msgs[2]) == 38

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
        [
            bytes.fromhex(
                "E8F791FF9225A2AF0102AFFF4A9A723D9612A682A25EBE79802B263CDFCD83BB"
            )
        ],
        [
            bytes.fromhex(
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
            )
        ],
    ]

    vectors["valid_test_cases"] = []
    # --- Valid Test Cases ---
    valid_cases = [
        {
            "indices": [0, 1, 2],
            "signer": 0,
            "msg": 0,
            "rand": 0,
            "comment": "Signing with minimum number of participants",
        },
        {
            "indices": [1, 0, 2],
            "signer": 1,
            "msg": 0,
            "rand": 0,
            "comment": "Partial-signature shouldn't change if the order of signers set changes. Note: The deterministic sign will generate the same secnonces due to unchanged parameters",
        },
        {
            "indices": [0, 3, 4],
            "signer": 0,
            "msg": 0,
            "rand": 0,
            "comment": "Partial-signature changes if the members of signers set changes",
        },
        {
            "indices": [0, 1, 2],
            "signer": 0,
            "msg": 0,
            "rand": 1,
            "comment": "Signing without auxiliary randomness",
        },
        {
            "indices": [0, 1, 2],
            "signer": 0,
            "msg": 0,
            "rand": 2,
            "comment": "Signing with max auxiliary randomness",
        },
        {
            "indices": [0, 1, 2, 3],
            "signer": 0,
            "msg": 0,
            "rand": 0,
            "comment": "Signing with t < no of participants < n",
        },
        {
            "indices": [0, 1, 2, 3, 4],
            "signer": 0,
            "msg": 0,
            "rand": 0,
            "comment": "Signing with maximum number of participants",
        },
        {
            "indices": [0, 1, 2],
            "signer": 0,
            "msg": 1,
            "rand": 0,
            "comment": "Empty message",
        },
        {
            "indices": [0, 1, 2],
            "signer": 0,
            "msg": 2,
            "rand": 0,
            "comment": "Message longer than 32 bytes (38-byte msg)",
        },
        {
            "indices": [0, 1, 2],
            "signer": 0,
            "msg": 0,
            "rand": 0,
            "tweaks": 0,
            "is_xonly": [True],
            "comment": "Signing with tweaks",
        },
    ]
    for case in valid_cases:
        curr_ids = [ids[i] for i in case["indices"]]
        curr_pubshares = [pubshares[i] for i in case["indices"]]
        curr_msg = msgs[case["msg"]]
        curr_rand = rands[case["rand"]]
        signer_index = case["signer"]
        my_id = curr_ids[signer_index]
        tweaks_idx = case.get("tweaks", None)
        curr_tweaks = [] if tweaks_idx is None else tweaks[tweaks_idx]
        curr_tweak_modes = case.get("is_xonly", [])

        # generate `aggothernonce`
        other_ids = curr_ids[:signer_index] + curr_ids[signer_index + 1 :]
        other_pubnonces = []
        for i in case["indices"]:
            if i == signer_index:
                continue
            tmp = b"" if curr_rand is None else curr_rand
            _, pub = nonce_gen_internal(
                tmp, secshares[i], pubshares[i], xonly_group_pk, curr_msg, None
            )
            other_pubnonces.append(pub)
        curr_aggothernonce = nonce_agg(other_pubnonces, other_ids)

        expected = deterministic_sign(
            secshare_p1,
            my_id,
            curr_aggothernonce,
            curr_ids,
            curr_pubshares,
            curr_tweaks,
            curr_tweak_modes,
            curr_msg,
            curr_rand,
        )

        vectors["valid_test_cases"].append(
            {
                "rand": bytes_to_hex(curr_rand) if curr_rand is not None else curr_rand,
                "aggothernonce": bytes_to_hex(curr_aggothernonce),
                "id_indices": case["indices"],
                "pubshare_indices": case["indices"],
                "tweaks": bytes_list_to_hex(curr_tweaks),
                "is_xonly": curr_tweak_modes,
                "msg_index": case["msg"],
                "signer_index": signer_index,
                "expected": bytes_list_to_hex(list(expected)),
                "comment": case["comment"],
            }
        )

    vectors["error_test_cases"] = []
    # --- Error Test Cases ---
    error_cases = [
        {
            "ids": [3, 1, 2],
            "pubshares": [0, 1, 2],
            "signer_idx": None,
            "signer_id": 0,
            "msg": 0,
            "rand": 0,
            "aggothernonce": "02FCDBEE416E4426FB4004BAB2B416164845DEC27337AD2B96184236D715965AB2039F71F389F6808DC6176F062F80531E13EA5BC2612B690FC284AE66C2CD859CE9",
            "error": "value",
            "comment": "The signer's id is not in the participant identifier list",
        },
        {
            "ids": [0, 1, 2, 1],
            "pubshares": [0, 1, 2, 1],
            "signer_idx": 0,
            "msg": 0,
            "rand": 0,
            "error": "value",
            "comment": "The participant identifier list contains duplicate elements",
        },
        {
            "ids": [0, 1, 2],
            "pubshares": [3, 1, 2],
            "signer_idx": 0,
            "msg": 0,
            "rand": 0,
            "error": "value",
            "comment": "The signer's pubshare is not in the list of pubshares. This test case is optional: it can be skipped by implementations that do not check that the signer's pubshare is included in the list of pubshares.",
        },
        {
            "ids": [0, 1, 2],
            "pubshares": [0, 1],
            "signer_idx": 0,
            "msg": 0,
            "rand": 0,
            "aggothernonce": "02FCDBEE416E4426FB4004BAB2B416164845DEC27337AD2B96184236D715965AB2039F71F389F6808DC6176F062F80531E13EA5BC2612B690FC284AE66C2CD859CE9",
            "error": "value",
            "comment": "The participant identifiers count exceed the participant public shares count",
        },
        {
            "ids": [0, 1, 2],
            "pubshares": [0, 1, 5],
            "signer_idx": 0,
            "msg": 0,
            "rand": 0,
            "error": "invalid_contrib",
            "comment": "Signer 3 provided an invalid participant public share",
        },
        {
            "ids": [0, 1, 2],
            "pubshares": [0, 1, 2],
            "signer_idx": 0,
            "msg": 0,
            "rand": 0,
            "aggothernonce": "048465FCF0BBDBCF443AABCCE533D42B4B5A10966AC09A49655E8C42DAAB8FCD61037496A3CC86926D452CAFCFD55D25972CA1675D549310DE296BFF42F72EEEA8C9",
            "error": "invalid_contrib",
            "comment": "aggothernonce is invalid due wrong tag, 0x04, in the first half",
        },
        {
            "ids": [0, 1, 2],
            "pubshares": [0, 1, 2],
            "signer_idx": 0,
            "msg": 0,
            "rand": 0,
            "aggothernonce": "0000000000000000000000000000000000000000000000000000000000000000000287BF891D2A6DEAEBADC909352AA9405D1428C15F4B75F04DAE642A95C2548480",
            "error": "invalid_contrib",
            "comment": "aggothernonce is invalid because first half corresponds to point at infinity",
        },
        {
            "ids": [0, 1, 2],
            "pubshares": [0, 1, 2],
            "signer_idx": 0,
            "msg": 0,
            "rand": 0,
            "tweaks": 1,
            "is_xonly": [False],
            "error": "value",
            "comment": "Tweak is invalid because it exceeds group size",
        },
    ]
    for case in error_cases:
        curr_ids = [ids[i] for i in case["ids"]]
        curr_pubshares = [pubshares[i] for i in case["pubshares"]]
        curr_msg = msgs[case["msg"]]
        curr_rand = rands[case["rand"]]
        signer_index = case["signer_idx"]
        if case["signer_idx"] is None:
            my_id = case["signer_id"]
        else:
            my_id = curr_ids[case["signer_idx"]]
        tweaks_idx = case.get("tweaks", None)
        curr_tweaks = [] if tweaks_idx is None else tweaks[tweaks_idx]
        curr_tweak_modes = case.get("is_xonly", [])

        # generate `aggothernonce`
        is_aggothernonce = case.get("aggothernonce", None)
        if is_aggothernonce is None:
            if signer_index is None:
                other_ids = curr_ids[1:]
            else:
                other_ids = curr_ids[:signer_index] + curr_ids[signer_index + 1 :]
            other_pubnonces = []
            for i in case["ids"]:
                if i == signer_index:
                    continue
                tmp = b"" if curr_rand is None else curr_rand
                _, pub = nonce_gen_internal(
                    tmp, secshares[i], pubshares[i], xonly_group_pk, curr_msg, None
                )
                other_pubnonces.append(pub)
            curr_aggothernonce = nonce_agg(other_pubnonces, other_ids)
        else:
            curr_aggothernonce = bytes.fromhex(is_aggothernonce)

        expected_exception = (
            ValueError if case["error"] == "value" else InvalidContributionError
        )
        error = expect_exception(
            lambda: deterministic_sign(
                secshare_p1,
                my_id,
                curr_aggothernonce,
                curr_ids,
                curr_pubshares,
                curr_tweaks,
                curr_tweak_modes,
                curr_msg,
                curr_rand,
            ),
            expected_exception,
        )

        vectors["error_test_cases"].append(
            {
                "rand": bytes_to_hex(curr_rand) if curr_rand is not None else curr_rand,
                "aggothernonce": bytes_to_hex(curr_aggothernonce),
                "id_indices": case["ids"],
                "pubshare_indices": case["pubshares"],
                "tweaks": bytes_list_to_hex(curr_tweaks),
                "is_xonly": curr_tweak_modes,
                "msg_index": case["msg"],
                "signer_index": signer_index,
                **(
                    {"signer_id": case["signer_id"]}
                    if case["signer_idx"] is None
                    else {}
                ),
                "error": error,
                "comment": case["comment"],
            }
        )

    output_file = os.path.join("vectors", "det_sign_vectors.json")
    with open(output_file, "w") as f:
        json.dump(vectors, f, indent=4)


def generate_sig_agg_vectors():
    vectors = dict()

    t, group_pk, secshares, pubshares = get_frost_keys()
    n = len(pubshares)
    xonly_group_pk = group_pk[1:]
    ids = list(range(n))
    assert len(pubshares) == len(secshares)

    vectors["max_participants"] = n
    vectors["min_participants"] = t
    vectors["group_public_key"] = bytes_to_hex(group_pk)
    vectors["identifiers"] = ids
    vectors["pubshares"] = bytes_list_to_hex(pubshares)

    rand_ = bytes.fromhex(
        "0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F"
    )
    secnonces = []
    pubnonces = []
    for i in range(n):
        sec, pub = nonce_gen_internal(
            rand_, secshares[i], pubshares[i], xonly_group_pk, None, None
        )
        secnonces.append(sec)
        pubnonces.append(pub)
    vectors["pubnonces"] = bytes_list_to_hex(pubnonces)

    tweaks = hex_list_to_bytes(
        [
            "B511DA492182A91B0FFB9A98020D55F260AE86D7ECBD0399C7383D59A5F2AF7C",
            "A815FE049EE3C5AAB66310477FBC8BCCCAC2F3395F59F921C364ACD78A2F48DC",
            "75448A87274B056468B977BE06EB1E9F657577B7320B0A3376EA51FD420D18A8",
        ]
    )
    vectors["tweaks"] = bytes_list_to_hex(tweaks)

    msg = bytes.fromhex(
        "599C67EA410D005B9DA90817CF03ED3B1C868E4DA4EDF00A5880B0082C237869"
    )
    vectors["msg"] = bytes_to_hex(msg)

    vectors["valid_test_cases"] = []
    # --- Valid Test Cases ---
    valid_cases = [
        {
            "indices": [0, 1, 2],
            "comment": "Signing with minimum number of participants",
        },
        {
            "indices": [2, 0, 1],
            "comment": "Order of the singer set shouldn't affect the aggregate signature. The expected value must match the previous test vector.",
        },
        {
            "indices": [0, 1, 2],
            "tweaks": [0, 1, 2],
            "is_xonly": [True, False, False],
            "comment": "Signing with tweaked group public key",
        },
        {
            "indices": [0, 1, 2, 3],
            "comment": "Signing with t < number of participants < n",
        },
        {
            "indices": [0, 1, 2, 3, 4],
            "comment": "Signing with max number of participants and tweaked group public key",
        },
    ]
    for case in valid_cases:
        curr_ids = [ids[i] for i in case["indices"]]
        curr_pubshares = [pubshares[i] for i in case["indices"]]
        curr_pubnonces = [pubnonces[i] for i in case["indices"]]
        curr_aggnonce = nonce_agg(curr_pubnonces, curr_ids)
        curr_msg = msg
        tweak_indices = case.get("tweaks", [])
        curr_tweaks = [tweaks[i] for i in tweak_indices]
        curr_tweak_modes = case.get("is_xonly", [])
        psigs = []
        session_ctx = SessionContext(
            curr_aggnonce,
            curr_ids,
            curr_pubshares,
            curr_tweaks,
            curr_tweak_modes,
            curr_msg,
        )
        for i in case["indices"]:
            my_id = ids[i]
            sig = sign(bytearray(secnonces[i]), secshares[i], my_id, session_ctx)
            psigs.append(sig)
            # TODO: verify the signatures here
        bip340_sig = partial_sig_agg(psigs, curr_ids, session_ctx)
        vectors["valid_test_cases"].append(
            {
                "id_indices": case["indices"],
                "pubshare_indices": case["indices"],
                "pubnonce_indices": case["indices"],
                "aggnonce": bytes_to_hex(curr_aggnonce),
                "tweak_indices": tweak_indices,
                "is_xonly": curr_tweak_modes,
                "psigs": bytes_list_to_hex(psigs),
                "expected": bytes_to_hex(bip340_sig),
                "comment": case["comment"],
            }
        )

    vectors["error_test_cases"] = []
    # --- Error Test Cases ---
    error_cases = [
        {
            "indices": [0, 1, 2],
            "error": "invalid_contrib",
            "comment": "Partial signature is invalid because it exceeds group size",
        },
        {
            "indices": [0, 1, 2],
            "error": "value",
            "comment": "Partial signature count doesn't match the signer set count",
        },
    ]
    for j, case in enumerate(error_cases):
        curr_ids = [ids[i] for i in case["indices"]]
        curr_pubshares = [pubshares[i] for i in case["indices"]]
        curr_pubnonces = [pubnonces[i] for i in case["indices"]]
        curr_aggnonce = nonce_agg(curr_pubnonces, curr_ids)
        curr_msg = msg
        psigs = []
        session_ctx = SessionContext(
            curr_aggnonce, curr_ids, curr_pubshares, [], [], curr_msg
        )
        for i in case["indices"]:
            my_id = ids[i]
            sig = sign(bytearray(secnonces[i]), secshares[i], my_id, session_ctx)
            psigs.append(sig)
            # TODO: verify the signatures here

        if j == 0:
            invalid_psig = bytes.fromhex(
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
            )
            psigs[1] = invalid_psig
        if j == 1:
            psigs.pop()

        expected_exception = (
            ValueError if case["error"] == "value" else InvalidContributionError
        )
        error = expect_exception(
            lambda: partial_sig_agg(psigs, curr_ids, session_ctx), expected_exception
        )
        vectors["error_test_cases"].append(
            {
                "id_indices": case["indices"],
                "pubshare_indices": case["indices"],
                "pubnonce_indices": case["indices"],
                "aggnonce": bytes_to_hex(curr_aggnonce),
                "tweak_indices": [],
                "is_xonly": [],
                "psigs": bytes_list_to_hex(psigs),
                "error": error,
                "comment": case["comment"],
            }
        )

    output_file = os.path.join("vectors", "sig_agg_vectors.json")
    with open(output_file, "w") as f:
        json.dump(vectors, f, indent=4)


def create_vectors_directory():
    if os.path.exists("vectors"):
        shutil.rmtree("vectors")
    os.makedirs("vectors")


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
    run_gen_vectors("generate_keygen_vectors", generate_keygen_vectors)
    run_gen_vectors("generate_tweak_vectors", generate_tweak_vectors)
    run_gen_vectors("generate_nonce_gen_vectors", generate_nonce_gen_vectors)
    run_gen_vectors("generate_nonce_agg_vectors", generate_nonce_agg_vectors)
    run_gen_vectors("generate_sign_verify_vectors", generate_sign_verify_vectors)
    run_gen_vectors("generate_sig_agg_vectors", generate_sig_agg_vectors)
    run_gen_vectors("generate_det_sign_vectors", generate_det_sign_vectors)
    generate_sig_agg_vectors()
    print("Test vectors generated successfully")


if __name__ == "__main__":
    sys.exit(main())
