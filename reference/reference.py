# BIP FROST Signing reference implementation
#
# It's worth noting that many functions, types, and exceptions were directly
# copied or modified from the MuSig2 (BIP 327) reference code, found at:
# https://github.com/bitcoin/bips/blob/master/bip-0327/reference.py
#
# WARNING: This implementation is for demonstration purposes only and _not_ to
# be used in production environments. The code is vulnerable to timing attacks,
# for example.

from typing import Any, List, Optional, Tuple, NewType, NamedTuple
import itertools
import secrets
import time

from utils.bip340 import *
from utils.trusted_keygen import generate_frost_keys

PlainPk = NewType('PlainPk', bytes)
XonlyPk = NewType('XonlyPk', bytes)

# There are two types of exceptions that can be raised by this implementation:
#   - ValueError for indicating that an input doesn't conform to some function
#     precondition (e.g. an input array is the wrong length, a serialized
#     representation doesn't have the correct format).
#   - InvalidContributionError for indicating that a signer (or the
#     aggregator) is misbehaving in the protocol.
#
# Assertions are used to (1) satisfy the type-checking system, and (2) check for
# inconvenient events that can't happen except with negligible probability (e.g.
# output of a hash function is 0) and can't be manually triggered by any
# signer.

# This exception is raised if a party (signer or nonce aggregator) sends invalid
# values. Actual implementations should not crash when receiving invalid
# contributions. Instead, they should hold the offending party accountable.
class InvalidContributionError(Exception):
    def __init__(self, signer_id, contrib):
        # participant identifier of the signer who sent the invalid value
        self.id = signer_id
        # contrib is one of "pubkey", "pubnonce", "aggnonce", or "psig".
        self.contrib = contrib

infinity = None

def xbytes(P: Point) -> bytes:
    return bytes_from_int(x(P))

def cbytes(P: Point) -> bytes:
    a = b'\x02' if has_even_y(P) else b'\x03'
    return a + xbytes(P)

def cbytes_ext(P: Optional[Point]) -> bytes:
    if is_infinite(P):
        return (0).to_bytes(33, byteorder='big')
    assert P is not None
    return cbytes(P)

def point_negate(P: Optional[Point]) -> Optional[Point]:
    if P is None:
        return P
    return (x(P), p - y(P))

def cpoint(x: bytes) -> Point:
    if len(x) != 33:
        raise ValueError('x is not a valid compressed point.')
    P = lift_x(x[1:33])
    if P is None:
        raise ValueError('x is not a valid compressed point.')
    if x[0] == 2:
        return P
    elif x[0] == 3:
        P = point_negate(P)
        assert P is not None
        return P
    else:
        raise ValueError('x is not a valid compressed point.')

def cpoint_ext(x: bytes) -> Optional[Point]:
    if x == (0).to_bytes(33, 'big'):
        return None
    else:
        return cpoint(x)

def int_ids(lst: List[bytes]) -> List[int]:
    res = []
    for x in lst:
        id_ = int_from_bytes(x)
        #todo: add check for < max_participants?
        if not 1 <= id_ < n:
            raise ValueError('x is not a valid participant identifier.')
        res.append(id_)
    return res

# Return the plain public key corresponding to a given secret key
# todo: remove if unused
def individual_pk(seckey: bytes) -> PlainPk:
    d0 = int_from_bytes(seckey)
    if not (1 <= d0 <= n - 1):
        raise ValueError('The secret key must be an integer in the range 1..n-1.')
    P = point_mul(G, d0)
    assert P is not None
    return PlainPk(cbytes(P))

#todo: change inputs to bytes & add a check 1 <= ids[i] <= max_participants, when converting it to int
# `derive_group_pubkey` and `sign` both would benefit from this change
# maybe keep taking its as `derive_interpolating_value_internal`?
def derive_interpolating_value_internal(L: List[int], x_i: int) -> int:
    num, deno = 1, 1
    for x_j in L:
        if x_j == x_i:
            continue
        num *= x_j
        deno *= (x_j - x_i)
    return num * pow(deno, n - 2, n) % n

def derive_interpolating_value(ids: List[bytes], my_id: bytes) -> int:
    if not my_id in ids:
        raise ValueError('The signer\'s id must be present in the participant identifier list.')
    if not all(ids.count(my_id) <= 1 for my_id in ids):
        raise ValueError('The participant identifier list must contain unique elements.')
    #todo: turn this into raise ValueError?
    assert 1 <= int_from_bytes(my_id) < n
    integer_ids = int_ids(ids)
    return derive_interpolating_value_internal(integer_ids, int_from_bytes(my_id))

#todo: take ids as input? but we don't need to blame the malicious participant here
def check_pubshares_correctness(secshares: List[bytes], pubshares: List[PlainPk]) -> bool:
    if not len(secshares) == len(pubshares):
        raise ValueError('The secshares and pubshares arrays must have the same length.')
    for secshare, pubshare in zip(secshares, pubshares):
        if not individual_pk(secshare) == pubshare:
            return False
    return True

#TODO: do this without reconstructing the group secret key
def check_group_pubkey_correctness(max_participants: int, min_participants: int, group_pk: PlainPk, ids: List[bytes], secshares: List[bytes], pubshares: List[PlainPk]) -> bool:
    if not max_participants >= min_participants > 1:
        raise ValueError('The 2 <= min participants <= max participants condition was violated.')
    #todo: add ids array too, in this check
    if not len(secshares) == len(pubshares) == max_participants:
        raise ValueError('The secshares and pubshares arrays length must be equal to max participants.')
    integer_ids = int_ids(ids)
    # loop through all possible signer sets
    for num_signers in range(min_participants, max_participants + 1):
        for signer_set in itertools.combinations(integer_ids, num_signers):
            # compute the group secret key
            group_sk_ = 0
            for i in signer_set:
                secshare_i = int_from_bytes(secshares[i-1])
                lambda_i = derive_interpolating_value_internal(list(signer_set), i)
                group_sk_ += lambda_i * secshare_i
            group_sk = bytes_from_int(group_sk_ % n)
            # reconstructed group_sk must correspond to group_pk
            if not individual_pk(group_sk) == group_pk:
                return False
    return True

TweakContext = NamedTuple('TweakContext', [('Q', Point),
                                           ('gacc', int),
                                           ('tacc', int)])

def get_xonly_pk(tweak_ctx: TweakContext) -> XonlyPk:
    Q, _, _ = tweak_ctx
    return XonlyPk(xbytes(Q))

#todo: remove this func, if unused
def get_plain_pk(tweak_ctx: TweakContext) -> PlainPk:
    Q, _, _ = tweak_ctx
    return PlainPk(cbytes(Q))

def tweak_ctx_init(group_pk: PlainPk) -> TweakContext:
    Q = cpoint(group_pk)
    gacc = 1
    tacc = 0
    return TweakContext(Q, gacc, tacc)

def apply_tweak(tweak_ctx: TweakContext, tweak: bytes, is_xonly: bool) -> TweakContext:
    if len(tweak) != 32:
        raise ValueError('The tweak must be a 32-byte array.')
    Q, gacc, tacc = tweak_ctx
    if is_xonly and not has_even_y(Q):
        g = n - 1
    else:
        g = 1
    t = int_from_bytes(tweak)
    if t >= n:
        raise ValueError('The tweak must be less than n.')
    Q_ = point_add(point_mul(Q, g), point_mul(G, t))
    if Q_ is None:
        raise ValueError('The result of tweaking cannot be infinity.')
    gacc_ = g * gacc % n
    tacc_ = (t + g * tacc) % n
    return TweakContext(Q_, gacc_, tacc_)

def bytes_xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def nonce_hash(rand: bytes, pubshare: PlainPk, group_pk: XonlyPk, i: int, msg_prefixed: bytes, extra_in: bytes) -> int:
    buf = b''
    buf += rand
    buf += len(pubshare).to_bytes(1, 'big')
    buf += pubshare
    buf += len(group_pk).to_bytes(1, 'big')
    buf += group_pk
    buf += msg_prefixed
    buf += len(extra_in).to_bytes(4, 'big')
    buf += extra_in
    buf += i.to_bytes(1, 'big')
    return int_from_bytes(tagged_hash('FROST/nonce', buf))

def nonce_gen_internal(rand_: bytes, secshare: Optional[bytes], pubshare: Optional[PlainPk], group_pk: Optional[XonlyPk], msg: Optional[bytes], extra_in: Optional[bytes]) -> Tuple[bytearray, bytes]:
    if secshare is not None:
        rand = bytes_xor(secshare, tagged_hash('FROST/aux', rand_))
    else:
        rand = rand_
    if pubshare is None:
        pubshare = PlainPk(b'')
    if group_pk is None:
        group_pk = XonlyPk(b'')
    if msg is None:
        msg_prefixed = b'\x00'
    else:
        msg_prefixed = b'\x01'
        msg_prefixed += len(msg).to_bytes(8, 'big')
        msg_prefixed += msg
    if extra_in is None:
        extra_in = b''
    k_1 = nonce_hash(rand, pubshare, group_pk, 0, msg_prefixed, extra_in) % n
    k_2 = nonce_hash(rand, pubshare, group_pk, 1, msg_prefixed, extra_in) % n
    # k_1 == 0 or k_2 == 0 cannot occur except with negligible probability.
    assert k_1 != 0
    assert k_2 != 0
    R_s1 = point_mul(G, k_1)
    R_s2 = point_mul(G, k_2)
    assert R_s1 is not None
    assert R_s2 is not None
    pubnonce = cbytes(R_s1) + cbytes(R_s2)
    # use mutable `bytearray` since secnonce need to be replaced with zeros during signing.
    secnonce = bytearray(bytes_from_int(k_1) + bytes_from_int(k_2))
    return secnonce, pubnonce

#think: can msg & extra_in be of any length here?
#think: why doesn't musig2 ref code check for `pk` length here?
def nonce_gen(secshare: Optional[bytes], pubshare: Optional[PlainPk], group_pk: Optional[XonlyPk], msg: Optional[bytes], extra_in: Optional[bytes]) -> Tuple[bytearray, bytes]:
    if secshare is not None and len(secshare) != 32:
        raise ValueError('The optional byte array secshare must have length 32.')
    if pubshare is not None and len(pubshare) != 33:
        raise ValueError('The optional byte array pubshare must have length 33.')
    if group_pk is not None and len(group_pk) != 32:
        raise ValueError('The optional byte array group_pk must have length 32.')
    # bench: will adding individual_pk(secshare) == pubshare check, increase the execution time significantly?
    rand_ = secrets.token_bytes(32)
    return nonce_gen_internal(rand_, secshare, pubshare, group_pk, msg, extra_in)

def nonce_agg(pubnonces: List[bytes], ids: List[bytes]) -> bytes:
    #think: needs check for min_participants <= len <= max_participants?
    if len(pubnonces) != len(ids):
        raise ValueError('The pubnonces and ids arrays must have the same length.')
    aggnonce = b''
    for j in (1, 2):
        R_j = infinity
        for my_id, pubnonce in zip(ids, pubnonces):
            try:
                R_ij = cpoint(pubnonce[(j-1)*33:j*33])
            except ValueError:
                raise InvalidContributionError(int_from_bytes(my_id), "pubnonce")
            R_j = point_add(R_j, R_ij)
        aggnonce += cbytes_ext(R_j)
    return aggnonce

#think: should identifiers be list of ints or bytes?
SessionContext = NamedTuple('SessionContext', [('aggnonce', bytes),
                                               ('identifiers', List[bytes]),
                                               ('pubshares', List[PlainPk]),
                                               ('tweaks', List[bytes]),
                                               ('is_xonly', List[bool]),
                                               ('msg', bytes)])

def derive_group_pubkey(pubshares: List[PlainPk], ids: List[bytes]) -> PlainPk:
    #think: needs check for min_participants <= len <= max_participants?
    assert len(pubshares) == len(ids)
    Q = infinity
    for my_id, pubshare in zip(ids, pubshares):
        try:
            X_i = cpoint(pubshare)
        except ValueError:
            raise InvalidContributionError(int_from_bytes(my_id), "pubshare")
        lam_i = derive_interpolating_value(ids, my_id)
        Q = point_add(Q, point_mul(X_i, lam_i))
    # Q is not the point at infinity except with negligible probability.
    assert(Q is not None)
    return PlainPk(cbytes(Q))

def group_pubkey_and_tweak(pubshares: List[PlainPk], ids: List[bytes], tweaks: List[bytes], is_xonly: List[bool]) -> TweakContext:
    if len(pubshares) != len(ids):
        raise ValueError('The pubshares and ids arrays must have the same length.')
    if len(tweaks) != len(is_xonly):
        raise ValueError('The tweaks and is_xonly arrays must have the same length.')
    group_pk = derive_group_pubkey(pubshares, ids)
    tweak_ctx = tweak_ctx_init(group_pk)
    v = len(tweaks)
    for i in range(v):
        tweak_ctx = apply_tweak(tweak_ctx, tweaks[i], is_xonly[i])
    return tweak_ctx

def get_session_values(session_ctx: SessionContext) -> Tuple[Point, int, int, int, Point, int]:
    (aggnonce, ids, pubshares, tweaks, is_xonly, msg) = session_ctx
    #think: add check (or assert) min_participants <= len(ids, pubshares) <= max_participants?
    Q, gacc, tacc = group_pubkey_and_tweak(pubshares, ids, tweaks, is_xonly)
    # sort before serializing because signers set in unordered
    concat_ids = b''.join(sorted(ids))
    b = int_from_bytes(tagged_hash('FROST/noncecoef', concat_ids + aggnonce + xbytes(Q) + msg)) % n
    try:
        R_1 = cpoint_ext(aggnonce[0:33])
        R_2 = cpoint_ext(aggnonce[33:66])
    except ValueError:
        # Nonce aggregator sent invalid nonces
        raise InvalidContributionError(None, "aggnonce")
    R_ = point_add(R_1, point_mul(R_2, b))
    #think: why replace it with G?
    R = R_ if not is_infinite(R_) else G
    assert R is not None
    e = int_from_bytes(tagged_hash('BIP0340/challenge', xbytes(R) + xbytes(Q) + msg)) % n
    return (Q, gacc, tacc, b, R, e)

def get_session_interpolating_value(session_ctx: SessionContext, my_id: bytes) -> int:
    (_, ids, _, _, _, _) = session_ctx
    return derive_interpolating_value(ids, my_id)

def session_has_signer_pubshare(session_ctx: SessionContext, pubshare: PlainPk) -> bool:
    (_, _, pubshares_list, _, _, _) = session_ctx
    return pubshare in pubshares_list

def sign(secnonce: bytearray, secshare: bytes, my_id: bytes, session_ctx: SessionContext) -> bytes:
    #think: add a check for 1 <= my_id <= max_participant here?
    # do we really need the below check?
    # add test vector for this check if confirmed
    if not 0 < int_from_bytes(my_id) < n:
        raise ValueError('The signer\'s participant identifier is out of range')
    (Q, gacc, _, b, R, e) = get_session_values(session_ctx)
    k_1_ = int_from_bytes(secnonce[0:32])
    k_2_ = int_from_bytes(secnonce[32:64])
    # Overwrite the secnonce argument with zeros such that subsequent calls of
    # sign with the same secnonce raise a ValueError.
    secnonce[:] = bytearray(b'\x00'*64)
    if not 0 < k_1_ < n:
        raise ValueError('first secnonce value is out of range.')
    if not 0 < k_2_ < n:
        raise ValueError('second secnonce value is out of range.')
    k_1 = k_1_ if has_even_y(R) else n - k_1_
    k_2 = k_2_ if has_even_y(R) else n - k_2_
    d_ = int_from_bytes(secshare)
    if not 0 < d_ < n:
        raise ValueError('The signer\'s secret share value is out of range.')
    P = point_mul(G, d_)
    assert P is not None
    pubshare = PlainPk(cbytes(P))
    if not session_has_signer_pubshare(session_ctx, pubshare):
        raise ValueError('The signer\'s pubshare must be included in the list of pubshares.')
    a = get_session_interpolating_value(session_ctx, my_id)
    g = 1 if has_even_y(Q) else n - 1
    d = g * gacc * d_ % n
    s = (k_1 + b * k_2 + e * a * d) % n
    psig = bytes_from_int(s)
    R_s1 = point_mul(G, k_1_)
    R_s2 = point_mul(G, k_2_)
    assert R_s1 is not None
    assert R_s2 is not None
    pubnonce = cbytes(R_s1) + cbytes(R_s2)
    # Optional correctness check. The result of signing should pass signature verification.
    assert partial_sig_verify_internal(psig, my_id, pubnonce, pubshare, session_ctx)
    return psig

def det_nonce_hash(secshare_: bytes, aggothernonce: bytes, tweaked_gpk: bytes, msg: bytes, i: int) -> int:
    buf = b''
    buf += secshare_
    buf += tweaked_gpk
    buf += aggpk
    buf += len(msg).to_bytes(8, 'big')
    buf += msg
    buf += i.to_bytes(1, 'big')
    return int_from_bytes(tagged_hash('FROST/deterministic/nonce', buf))

def deterministic_sign(secshare: bytes, my_id: bytes, aggothernonce: bytes, ids: List[bytes], pubshares: List[PlainPk], tweaks: List[bytes], is_xonly: List[bool], msg: bytes, rand: Optional[bytes]) -> Tuple[bytes, bytes]:
    if not 0 < int_from_bytes(secshare) < n:
        raise ValueError('The signer\'s secret share value is out of range.')
    signer_pubshare = individual_pk(secshare)
    if signer_pubshare not in pubshares:
         raise ValueError('The signer\'s pubshare must be included in the list of pubshares.')

    if rand is not None:
        secshare_ = bytes_xor(secshare, tagged_hash('FROST/aux', rand))
    else:
        secshare_ = secshare
    tweaked_gpk = get_xonly_pk(group_pubkey_and_tweak(pubshares, ids, tweaks, is_xonly))

    k_1 = det_nonce_hash(secshare_, aggothernonce, tweaked_gpk, msg, 0) % n
    k_2 = det_nonce_hash(secshare_, aggothernonce, tweaked_gpk, msg, 1) % n
    # k_1 == 0 or k_2 == 0 cannot occur except with negligible probability.
    assert k_1 != 0
    assert k_2 != 0

    R_s1 = point_mul(G, k_1)
    R_s2 = point_mul(G, k_2)
    assert R_s1 is not None
    assert R_s2 is not None
    pubnonce = cbytes(R_s1) + cbytes(R_s2)
    secnonce = bytearray(bytes_from_int(k_1) + bytes_from_int(k_2))
    try:
        # use null 32-bytes as an identifier for the aggregator
        aggnonce = nonce_agg([pubnonce, aggothernonce], [my_id, b'\x00' * 32])
    except Exception:
        raise InvalidContributionError(None, "aggothernonce")
    session_ctx = SessionContext(aggnonce, ids, pubshares, tweaks, is_xonly, msg)
    psig = sign(secnonce, secshare, my_id, session_ctx)
    return (pubnonce, psig)

def partial_sig_verify(psig: bytes, ids: List[bytes], pubnonces: List[bytes], pubshares: List[PlainPk], tweaks: List[bytes], is_xonly: List[bool], msg: bytes, i: int) -> bool:
    if not len(ids) == len(pubnonces) == len(pubshares):
        raise ValueError('The ids, pubnonces and pubshares arrays must have the same length.')
    if len(tweaks) != len(is_xonly):
        raise ValueError('The tweaks and is_xonly arrays must have the same length.')
    aggnonce = nonce_agg(pubnonces, ids)
    session_ctx = SessionContext(aggnonce, ids, pubshares, tweaks, is_xonly, msg)
    return partial_sig_verify_internal(psig, ids[i], pubnonces[i], pubshares[i], session_ctx)

def partial_sig_verify_internal(psig: bytes, my_id: bytes, pubnonce: bytes, pubshare: bytes, session_ctx: SessionContext) -> bool:
    (Q, gacc, _, b, R, e) = get_session_values(session_ctx)
    s = int_from_bytes(psig)
    if s >= n:
        return False
    #it's impossible to perform this check during verify, because we don't have access to the secshare!
    # we can only make sure the verification fails, when we have such a vector!
    #todo: Remove this check, also modify the spec accordingly
    if not session_has_signer_pubshare(session_ctx, pubshare):
        raise ValueError('The signer\'s pubshare must be included in the list of pubshares.')
    R_s1 = cpoint(pubnonce[0:33])
    R_s2 = cpoint(pubnonce[33:66])
    Re_s_ = point_add(R_s1, point_mul(R_s2, b))
    Re_s = Re_s_ if has_even_y(R) else point_negate(Re_s_)
    P = cpoint(pubshare)
    if P is None:
        return False
    a = get_session_interpolating_value(session_ctx, my_id)
    g = 1 if has_even_y(Q) else n - 1
    g_ = g * gacc % n
    return point_mul(G, s) == point_add(Re_s, point_mul(P, e * a * g_ % n))

def partial_sig_agg(psigs: List[bytes], ids: List[bytes], session_ctx: SessionContext) -> bytes:
    if len(psigs) != len(ids):
        raise ValueError('The psigs and ids arrays must have the same length.')
    (Q, _, tacc, _, R, e) = get_session_values(session_ctx)
    s = 0
    for my_id, psig in zip(ids, psigs):
        s_i = int_from_bytes(psig)
        if s_i >= n:
            raise InvalidContributionError(int_from_bytes(my_id), "psig")
        s = (s + s_i) % n
    g = 1 if has_even_y(Q) else n - 1
    s = (s + e * g * tacc) % n
    return xbytes(R) + bytes_from_int(s)

#
# The following code is only used for testing.
#

import json
import os
import sys

def fromhex_all(l):
    return [bytes.fromhex(l_i) for l_i in l]

# Check that calling `try_fn` raises a `exception`. If `exception` is raised,
# examine it with `except_fn`.
def assert_raises(exception, try_fn, except_fn):
    raised = False
    try:
        try_fn()
    except exception as e:
        raised = True
        assert(except_fn(e))
    except BaseException:
        raise AssertionError("Wrong exception raised in a test.")
    if not raised:
        raise AssertionError("Exception was _not_ raised in a test where it was required.")

def get_error_details(test_case):
    error = test_case["error"]
    def except_fn1(e):
        print(f"LHS: {str(e)}")
        print(f"RHS: {error['message']}")
        return str(e) == error["message"]
    if error["type"] == "invalid_contribution":
        exception = InvalidContributionError
        if "contrib" in error:
            except_fn = lambda e: e.id == error["signer_id"] and e.contrib == error["contrib"]
        else:
            except_fn = lambda e: e.id == error["signer_id"]
    elif error["type"] == "value":
        exception = ValueError
        # except_fn = except_fn1
        except_fn = lambda e: str(e) == error["message"]
    else:
        raise RuntimeError(f"Invalid error type: {error['type']}")
    return exception, except_fn

def test_keygen_vectors():
    with open(os.path.join(sys.path[0], 'vectors', 'keygen_vectors.json')) as f:
        test_data = json.load(f)

    valid_test_cases = test_data["valid_test_cases"]
    for test_case in valid_test_cases:
        max_participants = test_case["max_participants"]
        min_participants = test_case["min_participants"]
        group_pk = bytes.fromhex(test_case["group_public_key"])
        # assert the length using min & max participants?
        ids = [bytes_from_int(i) for i in test_case["participant_identifiers"]]
        pubshares = fromhex_all(test_case["participant_pubshares"])
        secshares = fromhex_all(test_case["participant_secshares"])

        assert check_pubshares_correctness(secshares, pubshares) == True
        assert check_group_pubkey_correctness(max_participants, min_participants, group_pk, ids, secshares, pubshares) == True

    pubshare_fail_test_cases = test_data["pubshare_correctness_fail_test_cases"]
    for test_case in pubshare_fail_test_cases:
        pubshares = fromhex_all(test_case["participant_pubshares"])
        secshares = fromhex_all(test_case["participant_secshares"])

        assert check_pubshares_correctness(secshares, pubshares) == False

    group_pubkey_fail_test_cases = test_data["group_pubkey_correctness_fail_test_cases"]
    for test_case in group_pubkey_fail_test_cases:
        max_participants = test_case["max_participants"]
        min_participants = test_case["min_participants"]
        group_pk = bytes.fromhex(test_case["group_public_key"])
        ids = [bytes_from_int(i) for i in test_case["participant_identifiers"]]
        pubshares = fromhex_all(test_case["participant_pubshares"])
        secshares = fromhex_all(test_case["participant_secshares"])

        assert check_group_pubkey_correctness(max_participants, min_participants, group_pk, ids, secshares, pubshares) == False

def test_nonce_gen_vectors():
    with open(os.path.join(sys.path[0], 'vectors', 'nonce_gen_vectors.json')) as f:
        test_data = json.load(f)

    for test_case in test_data["test_cases"]:
        def get_value(key) -> bytes:
            return bytes.fromhex(test_case[key])

        def get_value_maybe(key) -> Optional[bytes]:
            if test_case[key] is not None:
                return get_value(key)
            else:
                return None

        rand_ = get_value("rand_")
        secshare = get_value_maybe("secshare")
        pubshare = get_value_maybe("pubshare")
        if pubshare is not None:
            pubshare = PlainPk(pubshare)
        group_pk = get_value_maybe("group_pk")
        if group_pk is not None:
            group_pk = XonlyPk(group_pk)
        msg = get_value_maybe("msg")
        extra_in = get_value_maybe("extra_in")
        expected_secnonce = get_value("expected_secnonce")
        expected_pubnonce = get_value("expected_pubnonce")

        assert nonce_gen_internal(rand_, secshare, pubshare, group_pk, msg, extra_in) == (expected_secnonce, expected_pubnonce)

def test_nonce_agg_vectors():
    with open(os.path.join(sys.path[0], 'vectors', 'nonce_agg_vectors.json')) as f:
        test_data = json.load(f)

    pubnonces_list = fromhex_all(test_data["pubnonces"])
    valid_test_cases = test_data["valid_test_cases"]
    error_test_cases = test_data["error_test_cases"]

    for test_case in valid_test_cases:
        #todo: assert the min_participants <= len(pubnonces, ids) <= max_participants
        #todo: assert the values of ids too? 1 <= id <= max_participants?
        pubnonces = [pubnonces_list[i] for i in test_case["pubnonce_indices"]]
        ids = [bytes_from_int(i) for i in test_case["participant_identifiers"]]
        expected_aggnonce = bytes.fromhex(test_case["expected_aggnonce"])
        assert nonce_agg(pubnonces, ids) == expected_aggnonce

    for i, test_case in enumerate(error_test_cases):
        exception, except_fn = get_error_details(test_case)
        pubnonces = [pubnonces_list[i] for i in test_case["pubnonce_indices"]]
        ids = [bytes_from_int(i) for i in test_case["participant_identifiers"]]
        assert_raises(exception, lambda: nonce_agg(pubnonces, ids), except_fn)

# todo: include vectors from the frost draft too
# todo: add a test where group_pk is even (might need to modify json file)
def test_sign_verify_vectors():
    with open(os.path.join(sys.path[0], 'vectors', 'sign_verify_vectors.json')) as f:
        test_data = json.load(f)

    max_participants = test_data["max_participants"]
    min_participants = test_data["min_participants"]
    group_pk = XonlyPk(bytes.fromhex(test_data["group_public_key"]))
    secshare_p1 = bytes.fromhex(test_data["secshare_p1"])
    ids = test_data["identifiers"]
    pubshares = fromhex_all(test_data["pubshares"])
    # The public key corresponding to the first participant (secshare_p1) is at index 0
    assert pubshares[0] == individual_pk(secshare_p1)

    secnonces_p1 = fromhex_all(test_data["secnonces_p1"])
    pubnonces = fromhex_all(test_data["pubnonces"])
    # The public nonce corresponding to first participant (secnonce_p1[0]) is at index 0
    k_1 = int_from_bytes(secnonces_p1[0][0:32])
    k_2 = int_from_bytes(secnonces_p1[0][32:64])
    R_s1 = point_mul(G, k_1)
    R_s2 = point_mul(G, k_2)
    assert R_s1 is not None and R_s2 is not None
    assert pubnonces[0] == cbytes(R_s1) + cbytes(R_s2)

    aggnonces = fromhex_all(test_data["aggnonces"])
    msgs = fromhex_all(test_data["msgs"])

    valid_test_cases = test_data["valid_test_cases"]
    sign_error_test_cases = test_data["sign_error_test_cases"]
    verify_fail_test_cases = test_data["verify_fail_test_cases"]
    verify_error_test_cases = test_data["verify_error_test_cases"]

    for test_case in valid_test_cases:
        ids_tmp = [bytes_from_int(ids[i]) for i in test_case["id_indices"]]
        pubshares_tmp = [PlainPk(pubshares[i]) for i in test_case["pubshare_indices"]]
        pubnonces_tmp = [pubnonces[i] for i in test_case["pubnonce_indices"]]
        aggnonce_tmp = aggnonces[test_case["aggnonce_index"]]
        # Make sure that pubnonces and aggnonce in the test vector are consistent
        assert nonce_agg(pubnonces_tmp, ids_tmp) == aggnonce_tmp
        msg = msgs[test_case["msg_index"]]
        signer_index = test_case["signer_index"]
        my_id = ids_tmp[signer_index]
        expected = bytes.fromhex(test_case["expected"])

        session_ctx = SessionContext(aggnonce_tmp, ids_tmp, pubshares_tmp, [], [], msg)
        # WARNING: An actual implementation should _not_ copy the secnonce.
        # Reusing the secnonce, as we do here for testing purposes, can leak the
        # secret key.
        secnonce_tmp = bytearray(secnonces_p1[0])
        assert sign(secnonce_tmp, secshare_p1, my_id, session_ctx) == expected
        assert partial_sig_verify(expected, ids_tmp, pubnonces_tmp, pubshares_tmp, [], [], msg, signer_index)

    for test_case in sign_error_test_cases:
        exception, except_fn = get_error_details(test_case)
        ids_tmp = [bytes_from_int(ids[i]) for i in test_case["id_indices"]]
        pubshares_tmp = [PlainPk(pubshares[i]) for i in test_case["pubshare_indices"]]
        aggnonce_tmp = aggnonces[test_case["aggnonce_index"]]
        msg = msgs[test_case["msg_index"]]
        signer_index = test_case["signer_index"]
        my_id = bytes_from_int(test_case["signer_id"]) if signer_index is None else ids_tmp[signer_index]
        secnonce_tmp = bytearray(secnonces_p1[test_case["secnonce_index"]])

        session_ctx = SessionContext(aggnonce_tmp, ids_tmp, pubshares_tmp, [], [], msg)
        assert_raises(exception, lambda: sign(secnonce_tmp, secshare_p1, my_id, session_ctx), except_fn)

    for test_case in verify_fail_test_cases:
        psig = bytes.fromhex(test_case["psig"])
        ids_tmp = [bytes_from_int(ids[i]) for i in test_case["id_indices"]]
        pubshares_tmp = [PlainPk(pubshares[i]) for i in test_case["pubshare_indices"]]
        pubnonces_tmp = [pubnonces[i] for i in test_case["pubnonce_indices"]]
        msg = msgs[test_case["msg_index"]]
        signer_index = test_case["signer_index"]

        assert not partial_sig_verify(psig, ids_tmp, pubnonces_tmp, pubshares_tmp, [], [], msg, signer_index)

    for test_case in verify_error_test_cases:
        exception, except_fn = get_error_details(test_case)

        psig = bytes.fromhex(test_case["psig"])
        ids_tmp = [bytes_from_int(ids[i]) for i in test_case["id_indices"]]
        pubshares_tmp = [PlainPk(pubshares[i]) for i in test_case["pubshare_indices"]]
        pubnonces_tmp = [pubnonces[i] for i in test_case["pubnonce_indices"]]
        msg = msgs[test_case["msg_index"]]
        signer_index = test_case["signer_index"]
        assert_raises(exception, lambda: partial_sig_verify(psig, ids_tmp, pubnonces_tmp, pubshares_tmp, [], [], msg, signer_index), except_fn)

def test_tweak_vectors():
    with open(os.path.join(sys.path[0], 'vectors', 'tweak_vectors.json')) as f:
        test_data = json.load(f)

    max_participants = test_data["max_participants"]
    min_participants = test_data["min_participants"]
    group_pk = XonlyPk(bytes.fromhex(test_data["group_public_key"]))
    secshare_p1 = bytes.fromhex(test_data["secshare_p1"])
    ids = test_data["identifiers"]
    pubshares = fromhex_all(test_data["pubshares"])
    # The public key corresponding to the first participant (secshare_p1) is at index 0
    assert pubshares[0] == individual_pk(secshare_p1)

    secnonce_p1 = bytearray(bytes.fromhex(test_data["secnonce_p1"]))
    pubnonces = fromhex_all(test_data["pubnonces"])
    # The public nonce corresponding to first participant (secnonce_p1[0]) is at index 0
    k_1 = int_from_bytes(secnonce_p1[0:32])
    k_2 = int_from_bytes(secnonce_p1[32:64])
    R_s1 = point_mul(G, k_1)
    R_s2 = point_mul(G, k_2)
    assert R_s1 is not None and R_s2 is not None
    assert pubnonces[0] == cbytes(R_s1) + cbytes(R_s2)

    aggnonces = fromhex_all(test_data["aggnonces"])
    tweaks = fromhex_all(test_data["tweaks"])

    msg = bytes.fromhex(test_data["msg"])

    valid_test_cases = test_data["valid_test_cases"]
    error_test_cases = test_data["error_test_cases"]

    for test_case in valid_test_cases:
        ids_tmp = [bytes_from_int(ids[i]) for i in test_case["id_indices"]]
        pubshares_tmp = [PlainPk(pubshares[i]) for i in test_case["pubshare_indices"]]
        pubnonces_tmp = [pubnonces[i] for i in test_case["pubnonce_indices"]]
        aggnonce_tmp = aggnonces[test_case["aggnonce_index"]]
        # Make sure that pubnonces and aggnonce in the test vector are consistent
        assert nonce_agg(pubnonces_tmp, ids_tmp) == aggnonce_tmp
        tweaks_tmp = [tweaks[i] for i in test_case["tweak_indices"]]
        tweak_modes_tmp = test_case["is_xonly"]
        signer_index = test_case["signer_index"]
        my_id = ids_tmp[signer_index]
        expected = bytes.fromhex(test_case["expected"])

        session_ctx = SessionContext(aggnonce_tmp, ids_tmp, pubshares_tmp, tweaks_tmp, tweak_modes_tmp, msg)
        # WARNING: An actual implementation should _not_ copy the secnonce.
        # Reusing the secnonce, as we do here for testing purposes, can leak the
        # secret key.
        secnonce_tmp = bytearray(secnonce_p1)
        assert sign(secnonce_tmp, secshare_p1, my_id, session_ctx) == expected
        assert partial_sig_verify(expected, ids_tmp, pubnonces_tmp, pubshares_tmp, tweaks_tmp, tweak_modes_tmp, msg, signer_index)

    for test_case in error_test_cases:
        exception, except_fn = get_error_details(test_case)
        ids_tmp = [bytes_from_int(ids[i]) for i in test_case["id_indices"]]
        pubshares_tmp = [PlainPk(pubshares[i]) for i in test_case["pubshare_indices"]]
        aggnonce_tmp = aggnonces[test_case["aggnonce_index"]]
        tweaks_tmp = [tweaks[i] for i in test_case["tweak_indices"]]
        tweak_modes_tmp = test_case["is_xonly"]
        signer_index = test_case["signer_index"]
        my_id = ids_tmp[signer_index]

        session_ctx = SessionContext(aggnonce_tmp, ids_tmp, pubshares_tmp, tweaks_tmp, tweak_modes_tmp, msg)
        assert_raises(exception, lambda: sign(secnonce_p1, secshare_p1, my_id, session_ctx), except_fn)

def test_sig_agg_vectors():
    with open(os.path.join(sys.path[0], 'vectors', 'sig_agg_vectors.json')) as f:
        test_data = json.load(f)

    max_participants = test_data["max_participants"]
    min_participants = test_data["min_participants"]
    group_pk = XonlyPk(bytes.fromhex(test_data["group_public_key"]))
    ids = test_data["identifiers"]
    pubshares = fromhex_all(test_data["pubshares"])
    # These nonces are only required if the tested API takes the individual
    # nonces and not the aggregate nonce.
    pubnonces = fromhex_all(test_data["pubnonces"])

    tweaks = fromhex_all(test_data["tweaks"])
    psigs = fromhex_all(test_data["psigs"])
    msg = bytes.fromhex(test_data["msg"])

    valid_test_cases = test_data["valid_test_cases"]
    error_test_cases = test_data["error_test_cases"]

    for test_case in valid_test_cases:
        ids_tmp = [bytes_from_int(ids[i]) for i in test_case["id_indices"]]
        pubshares_tmp = [PlainPk(pubshares[i]) for i in test_case["pubshare_indices"]]
        pubnonces_tmp = [pubnonces[i] for i in test_case["pubnonce_indices"]]
        aggnonce_tmp = bytes.fromhex(test_case["aggnonce"])
        # Make sure that pubnonces and aggnonce in the test vector are consistent
        assert aggnonce_tmp == nonce_agg(pubnonces_tmp, ids_tmp)

        tweaks_tmp = [tweaks[i] for i in test_case["tweak_indices"]]
        tweak_modes_tmp = test_case["is_xonly"]
        psigs_tmp = [psigs[i] for i in test_case["psig_indices"]]
        expected = bytes.fromhex(test_case["expected"])

        session_ctx = SessionContext(aggnonce_tmp, ids_tmp, pubshares_tmp, tweaks_tmp, tweak_modes_tmp, msg)
        # Make sure that the partial signatures in the test vector are consistent. The tested API takes only aggnonce (not pubnonces list), this check can be ignored
        for i in range(len(ids_tmp)):
            partial_sig_verify(psigs_tmp[i], ids_tmp, pubnonces_tmp, pubshares_tmp, tweaks_tmp, tweak_modes_tmp, msg, i)

        bip340sig = partial_sig_agg(psigs_tmp, ids_tmp, session_ctx)
        assert bip340sig == expected
        tweaked_group_pk = get_xonly_pk(group_pubkey_and_tweak(pubshares_tmp, ids_tmp, tweaks_tmp, tweak_modes_tmp))
        assert schnorr_verify(msg, tweaked_group_pk, bip340sig)

    for test_case in error_test_cases:
        exception, except_fn = get_error_details(test_case)

        ids_tmp = [bytes_from_int(ids[i]) for i in test_case["id_indices"]]
        pubshares_tmp = [PlainPk(pubshares[i]) for i in test_case["pubshare_indices"]]
        pubnonces_tmp = [pubnonces[i] for i in test_case["pubnonce_indices"]]
        aggnonce_tmp = bytes.fromhex(test_case["aggnonce"])

        tweaks_tmp = [tweaks[i] for i in test_case["tweak_indices"]]
        tweak_modes_tmp = test_case["is_xonly"]
        psigs_tmp = [psigs[i] for i in test_case["psig_indices"]]

        session_ctx = SessionContext(aggnonce_tmp, ids_tmp, pubshares_tmp, tweaks_tmp, tweak_modes_tmp, msg)
        assert_raises(exception, lambda: partial_sig_agg(psigs_tmp, ids_tmp, session_ctx), except_fn)


def test_sign_and_verify_random(iters: int) -> None:
    # note: if we include a deterministic sign algo, include that in this test
    for i in range(iters):
        secure_rng = secrets.SystemRandom()
        # randomly choose a number: 2 <= number <= 10
        max_participants = secure_rng.randrange(2, 11)
        # randomly choose a number: 2 <= number <= max_participants
        min_participants = secure_rng.randrange(2, max_participants + 1)

        group_pk, ids, secshares, pubshares = generate_frost_keys(max_participants, min_participants)
        assert len(ids) == len(secshares) == len(pubshares) == max_participants
        assert check_pubshares_correctness(secshares, pubshares)
        assert check_group_pubkey_correctness(max_participants, min_participants, group_pk, ids, secshares, pubshares)

        # In this example, the message and group pubkey are known
        # before nonce generation, so they can be passed into the nonce
        # generation function as a defense-in-depth measure to protect
        # against nonce reuse.
        #
        # If these values are not known when nonce_gen is called, empty
        # byte arrays can be passed in for the corresponding arguments
        # instead.
        msg = secrets.token_bytes(32)
        v = secrets.randbelow(4)
        tweaks = [secrets.token_bytes(32) for _ in range(v)]
        tweak_modes = [secrets.choice([False, True]) for _ in range(v)]
        tweaked_group_pk = get_xonly_pk(group_pubkey_and_tweak(pubshares, ids, tweaks, tweak_modes))

        secnonces = []
        pubnonces = []
        for i in range(max_participants):
            # Use a clock for extra_in
            t = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
            secnonce_i, pubnonce_i = nonce_gen(secshares[i], pubshares[i], tweaked_group_pk, msg, t.to_bytes(8, 'big'))
            secnonces.append(secnonce_i)
            pubnonces.append(pubnonce_i)

        # randomly choose a signer set with length: min_participants <= len <= max_participants
        signers_count = secure_rng.randrange(min_participants, max_participants + 1)
        signer_indices = secure_rng.sample(range(max_participants), signers_count)
        assert len(set(signer_indices)) == signers_count

        signer_ids = [ids[i] for i in signer_indices]
        signer_pubshares = [pubshares[i] for i in signer_indices]
        signer_pubnonces = [pubnonces[i] for i in signer_indices]

        aggnonce = nonce_agg(signer_pubnonces, signer_ids)
        session_ctx = SessionContext(aggnonce, signer_ids, signer_pubshares, tweaks, tweak_modes, msg)

        signer_psigs = []
        for i, signer_index in enumerate(signer_indices):
            psig_i = sign(secnonces[signer_index], secshares[signer_index], ids[signer_index], session_ctx)
            assert partial_sig_verify(psig_i, signer_ids, signer_pubnonces, signer_pubshares, tweaks, tweak_modes, msg, i)
            signer_psigs.append(psig_i)
            # An exception is thrown if secnonce is accidentally reused
            assert_raises(ValueError, lambda: sign(secnonces[signer_index], secshares[signer_index], ids[signer_index], session_ctx), lambda e: True)

        # Wrong (signer_ids, signer_pubnonces, signer_pubshares) index
        assert not partial_sig_verify(signer_psigs[0], signer_ids, signer_pubnonces, signer_pubshares, tweaks, tweak_modes, msg, 1)
        # Wrong message
        assert not partial_sig_verify(signer_psigs[0], signer_ids, signer_pubnonces, signer_pubshares, tweaks, tweak_modes, secrets.token_bytes(32), 0)

        bip340sig = partial_sig_agg(signer_psigs, signer_ids, session_ctx)
        assert schnorr_verify(msg, tweaked_group_pk, bip340sig)

def run_test(test_name, test_func):
    max_len = 30
    test_name = test_name.ljust(max_len, ".")
    print(f"Running {test_name}...", end="", flush=True)
    try:
        test_func()
        print("Passed!")
    except Exception as e:
        print(f"\nFailed: {e}")

if __name__ == '__main__':
    run_test("test_keygen_vectors", test_keygen_vectors)
    run_test("test_nonce_gen_vectors", test_nonce_gen_vectors)
    run_test("test_nonce_agg_vectors", test_nonce_agg_vectors)
    run_test("test_sign_verify_vectors", test_sign_verify_vectors)
    run_test("test_tweak_vectors", test_tweak_vectors)
    run_test("test_sig_agg_vectors", test_sig_agg_vectors)
    run_test("test_sign_and_verify_random", lambda: test_sign_and_verify_random(6))