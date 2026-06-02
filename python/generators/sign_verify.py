from frost_ref import (
    InvalidContributionError,
    SessionContext,
    SignersContext,
    nonce_agg,
    partial_sig_verify,
    sign,
)
from secp256k1lab.secp256k1 import GE, Scalar

from generators.common import (
    COMMON_MSGS,
    COMMON_RAND,
    INVALID_PUBSHARE,
    SECKEY_2OF3,
    bytes_list_to_hex,
    bytes_to_hex,
    expect_exception,
    frost_keygen,
    generate_all_nonces,
    write_test_vectors,
)


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
