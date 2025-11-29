# BIP FROST Signing reference implementation
#
# It's worth noting that many functions, types, and exceptions were directly
# copied or modified from the MuSig2 (BIP 327) reference code, found at:
# https://github.com/bitcoin/bips/blob/master/bip-0327/reference.py
#
# WARNING: This implementation is for demonstration purposes only and _not_ to
# be used in production environments. The code is vulnerable to timing attacks,
# for example.

from typing import List, Optional, Tuple, NewType, NamedTuple, Sequence, Literal
import itertools
import secrets

from secp256k1lab.keys import pubkey_gen_plain
from secp256k1lab.secp256k1 import G, GE, Scalar
from secp256k1lab.util import int_from_bytes, tagged_hash

PlainPk = NewType("PlainPk", bytes)
XonlyPk = NewType("XonlyPk", bytes)
ContribKind = Literal[
    "aggothernonce", "aggnonce", "psig", "pubkey", "pubnonce", "pubshare"
]

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
    def __init__(self, signer_id: Optional[int], contrib: ContribKind) -> None:
        # participant identifier of the signer who sent the invalid value
        self.id = signer_id
        # contrib is one of "pubkey", "pubnonce", "aggnonce", or "psig".
        self.contrib = contrib


# TODO: remove these functions and use secp256k1lab functions directly
def xbytes(P: GE) -> bytes:
    return P.to_bytes_xonly()


def cbytes(P: GE) -> bytes:
    return P.to_bytes_compressed()


def cbytes_ext(P: GE) -> bytes:
    if P.infinity:
        return (0).to_bytes(33, byteorder="big")
    return cbytes(P)


def cpoint(x: bytes) -> GE:
    return GE.from_bytes_compressed(x)


def cpoint_ext(x: bytes) -> GE:
    if x == (0).to_bytes(33, "big"):
        return GE()
    else:
        return cpoint(x)


# Return the plain public key corresponding to a given secret key
def individual_pk(seckey: bytes) -> PlainPk:
    return PlainPk(pubkey_gen_plain(seckey))


# TODO: add my_id < n check
def derive_interpolating_value(ids: List[int], my_id: int) -> Scalar:
    if my_id not in ids:
        raise ValueError(
            "The signer's id must be present in the participant identifier list."
        )
    if not all(ids.count(my_id) <= 1 for my_id in ids):
        raise ValueError(
            "The participant identifier list must contain unique elements."
        )
    # todo: turn this into raise ValueError?
    assert 0 <= my_id < 2**32
    num, deno = 1, 1
    for curr_id in ids:
        if curr_id == my_id:
            continue
        num *= curr_id + 1
        deno *= curr_id - my_id
    return Scalar.from_int_wrapping(num * pow(deno, GE.ORDER - 2, GE.ORDER))


def check_pubshares_correctness(
    secshares: List[bytes], pubshares: List[PlainPk]
) -> bool:
    assert len(secshares) == len(pubshares)
    for secshare, pubshare in zip(secshares, pubshares):
        if not individual_pk(secshare) == pubshare:
            return False
    return True


def check_thresh_pubkey_correctness(
    t: int, thresh_pk: PlainPk, ids: List[int], pubshares: List[PlainPk]
) -> bool:
    assert len(ids) == len(pubshares)
    assert len(ids) >= t

    n = len(ids)
    # loop through all possible number of signers
    for signer_count in range(t, n + 1):
        # loop through all possible signer sets with length `signer_count`
        for signer_set in itertools.combinations(zip(ids, pubshares), signer_count):
            signer_ids = [pid for pid, pubshare in signer_set]
            signer_pubshares = [pubshare for pid, pubshare in signer_set]
            expected_pk = derive_thresh_pubkey(signer_pubshares, signer_ids)
            if expected_pk != thresh_pk:
                return False
    return True


def check_frost_key_compatibility(
    n: int,
    t: int,
    thresh_pk: PlainPk,
    ids: List[int],
    secshares: List[bytes],
    pubshares: List[PlainPk],
) -> bool:
    if not n >= t > 1:
        return False
    if not len(ids) == len(secshares) == len(pubshares) == n:
        return False
    pubshare_check = check_pubshares_correctness(secshares, pubshares)
    thresh_pk_check = check_thresh_pubkey_correctness(
        t, thresh_pk, ids, pubshares
    )
    return pubshare_check and thresh_pk_check


TweakContext = NamedTuple(
    "TweakContext", [("Q", GE), ("gacc", Scalar), ("tacc", Scalar)]
)
AGGREGATOR_ID = None


def get_xonly_pk(tweak_ctx: TweakContext) -> XonlyPk:
    Q, _, _ = tweak_ctx
    return XonlyPk(xbytes(Q))


def get_plain_pk(tweak_ctx: TweakContext) -> PlainPk:
    Q, _, _ = tweak_ctx
    return PlainPk(cbytes(Q))


# nit: switch the args ordering
def derive_thresh_pubkey(pubshares: List[PlainPk], ids: List[int]) -> PlainPk:
    assert len(pubshares) == len(ids)
    # assert AGGREGATOR_ID not in ids
    Q = GE()
    for my_id, pubshare in zip(ids, pubshares):
        try:
            X_i = cpoint(pubshare)
        except ValueError:
            raise InvalidContributionError(my_id, "pubshare")
        lam_i = derive_interpolating_value(ids, my_id)
        Q = Q + lam_i * X_i
    # Q is not the point at infinity except with negligible probability.
    assert not Q.infinity
    return PlainPk(cbytes(Q))


def tweak_ctx_init(pubshares: List[PlainPk], ids: List[int]) -> TweakContext:
    thresh_pk = derive_thresh_pubkey(pubshares, ids)
    Q = cpoint(thresh_pk)
    gacc = Scalar(1)
    tacc = Scalar(0)
    return TweakContext(Q, gacc, tacc)


def apply_tweak(tweak_ctx: TweakContext, tweak: bytes, is_xonly: bool) -> TweakContext:
    if len(tweak) != 32:
        raise ValueError("The tweak must be a 32-byte array.")
    Q, gacc, tacc = tweak_ctx
    if is_xonly and not Q.has_even_y():
        g = Scalar(-1)
    else:
        g = Scalar(1)
    try:
        twk = Scalar.from_bytes_checked(tweak)
    except ValueError:
        raise ValueError("The tweak must be less than n.")
    Q_ = g * Q + twk * G
    if Q_.infinity:
        raise ValueError("The result of tweaking cannot be infinity.")
    gacc_ = g * gacc
    tacc_ = twk + g * tacc
    return TweakContext(Q_, gacc_, tacc_)


def bytes_xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def nonce_hash(
    rand: bytes,
    pubshare: PlainPk,
    thresh_pk: XonlyPk,
    i: int,
    msg_prefixed: bytes,
    extra_in: bytes,
) -> int:
    buf = b""
    buf += rand
    buf += len(pubshare).to_bytes(1, "big")
    buf += pubshare
    buf += len(thresh_pk).to_bytes(1, "big")
    buf += thresh_pk
    buf += msg_prefixed
    buf += len(extra_in).to_bytes(4, "big")
    buf += extra_in
    buf += i.to_bytes(1, "big")
    return int_from_bytes(tagged_hash("FROST/nonce", buf))


def nonce_gen_internal(
    rand_: bytes,
    secshare: Optional[bytes],
    pubshare: Optional[PlainPk],
    thresh_pk: Optional[XonlyPk],
    msg: Optional[bytes],
    extra_in: Optional[bytes],
) -> Tuple[bytearray, bytes]:
    if secshare is not None:
        rand = bytes_xor(secshare, tagged_hash("FROST/aux", rand_))
    else:
        rand = rand_
    if pubshare is None:
        pubshare = PlainPk(b"")
    if thresh_pk is None:
        thresh_pk = XonlyPk(b"")
    if msg is None:
        msg_prefixed = b"\x00"
    else:
        msg_prefixed = b"\x01"
        msg_prefixed += len(msg).to_bytes(8, "big")
        msg_prefixed += msg
    if extra_in is None:
        extra_in = b""
    k_1 = Scalar.from_int_wrapping(
        nonce_hash(rand, pubshare, thresh_pk, 0, msg_prefixed, extra_in)
    )
    k_2 = Scalar.from_int_wrapping(
        nonce_hash(rand, pubshare, thresh_pk, 1, msg_prefixed, extra_in)
    )
    # k_1 == 0 or k_2 == 0 cannot occur except with negligible probability.
    assert k_1 != 0
    assert k_2 != 0
    R_s1 = k_1 * G
    R_s2 = k_2 * G
    assert not R_s1.infinity
    assert not R_s2.infinity
    pubnonce = cbytes(R_s1) + cbytes(R_s2)
    # use mutable `bytearray` since secnonce need to be replaced with zeros during signing.
    secnonce = bytearray(k_1.to_bytes() + k_2.to_bytes())
    return secnonce, pubnonce


# think: can msg & extra_in be of any length here?
# think: why doesn't musig2 ref code check for `pk` length here?
# REVIEW: Why should thresh_pk be XOnlyPk here? Shouldn't it be PlainPk?
def nonce_gen(
    secshare: Optional[bytes],
    pubshare: Optional[PlainPk],
    thresh_pk: Optional[XonlyPk],
    msg: Optional[bytes],
    extra_in: Optional[bytes],
) -> Tuple[bytearray, bytes]:
    if secshare is not None and len(secshare) != 32:
        raise ValueError("The optional byte array secshare must have length 32.")
    if pubshare is not None and len(pubshare) != 33:
        raise ValueError("The optional byte array pubshare must have length 33.")
    if thresh_pk is not None and len(thresh_pk) != 32:
        raise ValueError("The optional byte array thresh_pk must have length 32.")
    # bench: will adding individual_pk(secshare) == pubshare check, increase the execution time significantly?
    rand_ = secrets.token_bytes(32)
    return nonce_gen_internal(rand_, secshare, pubshare, thresh_pk, msg, extra_in)


# REVIEW should we raise value errors for:
#     (1) duplicate ids
#     (2) 0 <= id < max_participants < 2^32
# in each function that takes `ids` as argument?


# `ids` is typed as Sequence[Optional[int]] so that callers can pass either
# List[int] or List[Optional[int]] without triggering mypy invariance errors.
# Sequence is read-only and covariant.
def nonce_agg(pubnonces: List[bytes], ids: Sequence[Optional[int]]) -> bytes:
    if len(pubnonces) != len(ids):
        raise ValueError("The pubnonces and ids arrays must have the same length.")
    aggnonce = b""
    for j in (1, 2):
        R_j = GE()
        for my_id, pubnonce in zip(ids, pubnonces):
            try:
                R_ij = cpoint(pubnonce[(j - 1) * 33 : j * 33])
            except ValueError:
                raise InvalidContributionError(my_id, "pubnonce")
            R_j = R_j + R_ij
        aggnonce += cbytes_ext(R_j)
    return aggnonce


SessionContext = NamedTuple(
    "SessionContext",
    [
        ("aggnonce", bytes),
        ("identifiers", List[int]),
        ("pubshares", List[PlainPk]),
        ("tweaks", List[bytes]),
        ("is_xonly", List[bool]),
        ("msg", bytes),
    ],
)


def thresh_pubkey_and_tweak(
    pubshares: List[PlainPk], ids: List[int], tweaks: List[bytes], is_xonly: List[bool]
) -> TweakContext:
    if len(pubshares) != len(ids):
        raise ValueError("The pubshares and ids arrays must have the same length.")
    if len(tweaks) != len(is_xonly):
        raise ValueError("The tweaks and is_xonly arrays must have the same length.")
    tweak_ctx = tweak_ctx_init(pubshares, ids)
    v = len(tweaks)
    for i in range(v):
        tweak_ctx = apply_tweak(tweak_ctx, tweaks[i], is_xonly[i])
    return tweak_ctx


def get_session_values(
    session_ctx: SessionContext,
) -> Tuple[GE, Scalar, Scalar, Scalar, GE, Scalar]:
    (aggnonce, ids, pubshares, tweaks, is_xonly, msg) = session_ctx
    Q, gacc, tacc = thresh_pubkey_and_tweak(pubshares, ids, tweaks, is_xonly)
    # sort the ids before serializing because ROAST paper considers them as a set
    ser_ids = serialize_ids(ids)
    b = Scalar.from_bytes_wrapping(
        tagged_hash("FROST/noncecoef", ser_ids + aggnonce + xbytes(Q) + msg)
    )
    try:
        R_1 = cpoint_ext(aggnonce[0:33])
        R_2 = cpoint_ext(aggnonce[33:66])
    except ValueError:
        # Nonce aggregator sent invalid nonces
        raise InvalidContributionError(None, "aggnonce")
    R_ = R_1 + b * R_2
    R = R_ if not R_.infinity else G
    assert not R.infinity
    e = Scalar.from_bytes_wrapping(
        tagged_hash("BIP0340/challenge", xbytes(R) + xbytes(Q) + msg)
    )
    return (Q, gacc, tacc, b, R, e)


def serialize_ids(ids: List[int]) -> bytes:
    # REVIEW assert for ids not being unsigned values?
    sorted_ids = sorted(ids)
    ser_ids = b"".join(i.to_bytes(4, byteorder="big", signed=False) for i in sorted_ids)
    return ser_ids


def get_session_interpolating_value(session_ctx: SessionContext, my_id: int) -> Scalar:
    (_, ids, _, _, _, _) = session_ctx
    return derive_interpolating_value(ids, my_id)


def session_has_signer_pubshare(session_ctx: SessionContext, pubshare: bytes) -> bool:
    (_, _, pubshares_list, _, _, _) = session_ctx
    return pubshare in pubshares_list


def sign(
    secnonce: bytearray, secshare: bytes, my_id: int, session_ctx: SessionContext
) -> bytes:
    # do we really need the below check?
    # add test vector for this check if confirmed
    if not 0 <= my_id < 2**32:
        raise ValueError("The signer's participant identifier is out of range")
    (Q, gacc, _, b, R, e) = get_session_values(session_ctx)
    try:
        k_1_ = Scalar.from_bytes_nonzero_checked(bytes(secnonce[0:32]))
    except ValueError:
        raise ValueError("first secnonce value is out of range.")
    try:
        k_2_ = Scalar.from_bytes_nonzero_checked(bytes(secnonce[32:64]))
    except ValueError:
        raise ValueError("second secnonce value is out of range.")
    # Overwrite the secnonce argument with zeros such that subsequent calls of
    # sign with the same secnonce raise a ValueError.
    secnonce[:] = bytearray(b"\x00" * 64)
    k_1 = k_1_ if R.has_even_y() else -k_1_
    k_2 = k_2_ if R.has_even_y() else -k_2_
    d_ = int_from_bytes(secshare)
    if not 0 < d_ < GE.ORDER:
        raise ValueError("The signer's secret share value is out of range.")
    P = d_ * G
    assert not P.infinity
    pubshare = cbytes(P)
    if not session_has_signer_pubshare(session_ctx, pubshare):
        raise ValueError(
            "The signer's pubshare must be included in the list of pubshares."
        )
    a = get_session_interpolating_value(session_ctx, my_id)
    g = Scalar(1) if Q.has_even_y() else Scalar(-1)
    d = g * gacc * d_
    s = k_1 + b * k_2 + e * a * d
    psig = s.to_bytes()
    R_s1 = k_1_ * G
    R_s2 = k_2_ * G
    assert not R_s1.infinity
    assert not R_s2.infinity
    pubnonce = cbytes(R_s1) + cbytes(R_s2)
    # Optional correctness check. The result of signing should pass signature verification.
    assert partial_sig_verify_internal(psig, my_id, pubnonce, pubshare, session_ctx)
    return psig


# REVIEW should we hash the signer set (or pubshares) too? Otherwise same nonce will be generate even if the signer set changes
def det_nonce_hash(
    secshare_: bytes, aggothernonce: bytes, tweaked_tpk: bytes, msg: bytes, i: int
) -> int:
    buf = b""
    buf += secshare_
    buf += aggothernonce
    buf += tweaked_tpk
    buf += len(msg).to_bytes(8, "big")
    buf += msg
    buf += i.to_bytes(1, "big")
    return int_from_bytes(tagged_hash("FROST/deterministic/nonce", buf))


def deterministic_sign(
    secshare: bytes,
    my_id: int,
    aggothernonce: bytes,
    ids: List[int],
    pubshares: List[PlainPk],
    tweaks: List[bytes],
    is_xonly: List[bool],
    msg: bytes,
    rand: Optional[bytes],
) -> Tuple[bytes, bytes]:
    if rand is not None:
        secshare_ = bytes_xor(secshare, tagged_hash("FROST/aux", rand))
    else:
        secshare_ = secshare

    tweaked_tpk = get_xonly_pk(
        thresh_pubkey_and_tweak(pubshares, ids, tweaks, is_xonly)
    )

    k_1 = Scalar.from_int_wrapping(
        det_nonce_hash(secshare_, aggothernonce, tweaked_tpk, msg, 0)
    )
    k_2 = Scalar.from_int_wrapping(
        det_nonce_hash(secshare_, aggothernonce, tweaked_tpk, msg, 1)
    )
    # k_1 == 0 or k_2 == 0 cannot occur except with negligible probability.
    assert k_1 != 0
    assert k_2 != 0

    R_s1 = k_1 * G
    R_s2 = k_2 * G
    assert not R_s1.infinity
    assert not R_s2.infinity
    pubnonce = cbytes(R_s1) + cbytes(R_s2)
    secnonce = bytearray(k_1.to_bytes() + k_2.to_bytes())
    try:
        aggnonce = nonce_agg([pubnonce, aggothernonce], [my_id, AGGREGATOR_ID])
    except Exception:
        # Since `pubnonce` can never be invalid, blame aggregator's pubnonce.
        # REVIEW: should we introduce an unknown participant or aggregator error?
        raise InvalidContributionError(AGGREGATOR_ID, "aggothernonce")
    session_ctx = SessionContext(aggnonce, ids, pubshares, tweaks, is_xonly, msg)
    psig = sign(secnonce, secshare, my_id, session_ctx)
    return (pubnonce, psig)


def partial_sig_verify(
    psig: bytes,
    ids: List[int],
    pubnonces: List[bytes],
    pubshares: List[PlainPk],
    tweaks: List[bytes],
    is_xonly: List[bool],
    msg: bytes,
    i: int,
) -> bool:
    if not len(ids) == len(pubnonces) == len(pubshares):
        raise ValueError(
            "The ids, pubnonces and pubshares arrays must have the same length."
        )
    if len(tweaks) != len(is_xonly):
        raise ValueError("The tweaks and is_xonly arrays must have the same length.")
    aggnonce = nonce_agg(pubnonces, ids)
    session_ctx = SessionContext(aggnonce, ids, pubshares, tweaks, is_xonly, msg)
    return partial_sig_verify_internal(
        psig, ids[i], pubnonces[i], pubshares[i], session_ctx
    )


# todo: catch `cpoint`` ValueError and return false
def partial_sig_verify_internal(
    psig: bytes,
    my_id: int,
    pubnonce: bytes,
    pubshare: bytes,
    session_ctx: SessionContext,
) -> bool:
    (Q, gacc, _, b, R, e) = get_session_values(session_ctx)
    try:
        s = Scalar.from_bytes_checked(psig)
    except ValueError:
        return False
    if not session_has_signer_pubshare(session_ctx, pubshare):
        return False
    R_s1 = cpoint(pubnonce[0:33])
    R_s2 = cpoint(pubnonce[33:66])
    Re_s_ = R_s1 + b * R_s2
    Re_s = Re_s_ if R.has_even_y() else -Re_s_
    P = cpoint(pubshare)
    if P is None:
        return False
    a = get_session_interpolating_value(session_ctx, my_id)
    g = Scalar(1) if Q.has_even_y() else Scalar(-1)
    g_ = g * gacc
    return s * G == Re_s + (e * a * g_) * P


def partial_sig_agg(
    psigs: List[bytes], ids: List[int], session_ctx: SessionContext
) -> bytes:
    assert AGGREGATOR_ID not in ids
    if len(psigs) != len(ids):
        raise ValueError("The psigs and ids arrays must have the same length.")
    (Q, _, tacc, _, R, e) = get_session_values(session_ctx)
    s = Scalar(0)
    for my_id, psig in zip(ids, psigs):
        try:
            s_i = Scalar.from_bytes_checked(psig)
        except ValueError:
            raise InvalidContributionError(my_id, "psig")
        s = s + s_i
    g = Scalar(1) if Q.has_even_y() else Scalar(-1)
    s = s + e * g * tacc
    return xbytes(R) + s.to_bytes()
