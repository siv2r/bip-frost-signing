from frost_ref import (
    InvalidContributionError,
    SessionContext,
    SignersContext,
    nonce_agg,
    partial_sig_agg,
    partial_sig_verify,
    sign,
)

from generators.common import (
    COMMON_MSGS,
    COMMON_RAND,
    COMMON_TWEAKS,
    SECKEY_2OF3,
    bytes_list_to_hex,
    bytes_to_hex,
    expect_exception,
    frost_keygen,
    generate_all_nonces,
    write_test_vectors,
)


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
            "comment": "Reordering the signer set leaves the aggregate signature unchanged, because the partial signatures are summed and the identifiers are sorted before they are bound into the binding value",
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
            "fault": "psig_out_of_range",
            "error": "invalid_contrib",
            "comment": "Partial signature equals the group order, which is out of range",
        },
        {
            "indices": [0, 1],
            "fault": "psig_count_mismatch",
            "error": "value",
            "comment": "Number of partial signatures does not match the number of signers",
        },
    ]
    for case in error_cases:
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

        if case["fault"] == "psig_out_of_range":
            invalid_psig = bytes.fromhex(
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
            )
            psigs[1] = invalid_psig
        elif case["fault"] == "psig_count_mismatch":
            psigs = psigs[:-1]

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
