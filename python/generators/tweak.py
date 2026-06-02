from frost_ref import SessionContext, SignersContext, nonce_agg, sign
from secp256k1lab.secp256k1 import G, GE

from generators.common import (
    COMMON_MSGS,
    COMMON_RAND,
    COMMON_TWEAKS,
    INVALID_PUBSHARE,
    OUT_OF_RANGE_TWEAK,
    SECKEY_2OF3,
    bytes_list_to_hex,
    bytes_to_hex,
    expect_exception,
    frost_keygen,
    generate_all_nonces,
    reconstruct_thresh_sk,
    write_test_vectors,
)

# an invalid 33-byte tweak value
INVALID_33_BYTE_TWEAK = bytes.fromhex(
    "E8F791FF9225A2AF0102AFFF4A9A723D9612A682A25EBE79802B263CDFCD83BBFF"
)


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

    # 7 entries: indices 0-3 valid (COMMON_TWEAKS), index 4 out-of-range,
    # index 5 drives the tweaked threshold public key to infinity,
    # index 6 is not a 32-byte array
    OUT_OF_RANGE_TWEAK_IDX = len(COMMON_TWEAKS)
    INFINITY_TWEAK_IDX = len(COMMON_TWEAKS) + 1
    INVALID_33_BYTE_TWEAK_IDX = len(COMMON_TWEAKS) + 2
    tweaks_pool = COMMON_TWEAKS + [
        OUT_OF_RANGE_TWEAK,
        infinity_tweak_scalar.to_bytes(),
        INVALID_33_BYTE_TWEAK,
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
        {
            "tweaks_indices": [0],
            "is_xonly": [],
            "comment": "Number of tweaks does not match the number of tweak modes",
        },
        {
            "tweaks_indices": [INVALID_33_BYTE_TWEAK_IDX],
            "is_xonly": [False],
            "comment": "Tweak is not a 32-byte array",
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
