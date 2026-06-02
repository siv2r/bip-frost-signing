from frost_ref import (
    InvalidContributionError,
    SignersContext,
    deterministic_sign,
    nonce_agg,
)
from frost_ref.signing import nonce_gen_internal

from generators.common import (
    COMMON_MSGS,
    COMMON_TWEAKS,
    INVALID_PUBSHARE,
    OUT_OF_RANGE_TWEAK,
    SECKEY_2OF3,
    bytes_list_to_hex,
    bytes_to_hex,
    expect_exception,
    frost_keygen,
    write_test_vectors,
)


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
            "comment": "Reordering the signer set leaves the deterministic output unchanged, because the identifiers are sorted before they are bound into the nonce derivation and the binding value",
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
            "comment": "Auxiliary randomness omitted (null), which is not equivalent to all-zeros randomness",
        },
        {
            "indices": [0, 1],
            "my_id": 0,
            "msg": 0,
            "rand": RAND_MAX_IDX,
            "comment": "Auxiliary randomness is all ones, distinct from the all-zeros and omitted cases",
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
