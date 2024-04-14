# BIP FROST Signing reference implementation
#
# It's worth noting that many functions, types, and exceptions were directly
# copied or adapted from the MuSig2 (BIP 327) reference code, found at:
# https://github.com/bitcoin/bips/blob/master/bip-0327/reference.py
#
# WARNING: This implementation is for demonstration purposes only and _not_ to
# be used in production environments. The code is vulnerable to timing attacks,
# for example.

from typing import Any, List, Optional, Tuple, NewType, NamedTuple
from bip340_utils import *

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
    def __init__(self, signer, contrib):
        self.signer = signer
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

# Return the plain public key corresponding to a given secret key
# todo: remove if unused
def individual_pk(seckey: bytes) -> PlainPk:
    d0 = int_from_bytes(seckey)
    if not (1 <= d0 <= n - 1):
        raise ValueError('The secret key must be an integer in the range 1..n-1.')
    P = point_mul(G, d0)
    assert P is not None
    return PlainPk(cbytes(P))

TweakContext = NamedTuple('TweakContext', [('Q', Point),
                                           ('gacc', int),
                                           ('tacc', int)])

def get_xonly_pk(tweak_ctx: TweakContext) -> XonlyPk:
    Q, _, _ = tweak_ctx
    return XonlyPk(xbytes(Q))

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

def nonce_gen_internal(rand_: bytes, sk: Optional[bytes], pubshare: Optional[PlainPk], group_pk: Optional[XonlyPk], msg: Optional[bytes], extra_in: Optional[bytes]) -> Tuple[bytearray, bytes]:
    if sk is not None:
        rand = bytes_xor(sk, tagged_hash('FROST/aux', rand_))
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
    # think: do we need this to be 'bytearray'? Unlike MuSig2, we don't include pk in secnonce.
    secnonce = bytearray(bytes_from_int(k_1) + bytes_from_int(k_2))
    return secnonce, pubnonce

#think: can msg & extra_in be of any length here?
#think: why doesn't musig2 ref code check for `pk` length here?
def nonce_gen(sk: Optional[bytes], pubshare: Optional[PlainPk], group_pk: Optional[XonlyPk], msg: Optional[bytes], extra_in: Optional[bytes]) -> Tuple[bytearray, bytes]:
    if sk is not None and len(sk) != 32:
        raise ValueError('The optional byte array sk must have length 32.')
    if pubshare is not None and len(pubshare) != 33:
        raise ValueError('The optional byte array pubshare must have length 33.')
    if group_pk is not None and len(group_pk) != 32:
        raise ValueError('The optional byte array group_pk must have length 32.')
    rand_ = secrets.token_bytes(32)
    return nonce_gen_internal(rand_, sk, pubshare, group_pk, msg, extra_in)

def nonce_agg(pubnonces: List[bytes]) -> bytes:
    u = len(pubnonces)
    aggnonce = b''
    for j in (1, 2):
        R_j = infinity
        for i in range(u):
            try:
                R_ij = cpoint(pubnonces[i][(j-1)*33:j*33])
            except ValueError:
                raise InvalidContributionError(i, "pubnonce")
            R_j = point_add(R_j, R_ij)
        aggnonce += cbytes_ext(R_j)
    return aggnonce

#
# The following code is only used for testing.
#

def test_sign_and_verify_random(iters: int) -> None:
    pass

if __name__ == '__main__':
    test_sign_and_verify_random(10)