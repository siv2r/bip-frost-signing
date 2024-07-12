# Implementation of the Trusted Dealer Key Generation approach for FROST mentioned
# in https://datatracker.ietf.org/doc/draft-irtf-cfrg-frost/15/ (Appendix D).
#
# It's worth noting that this isn't the only compatible method (with BIP FROST Signing),
# there are alternative key generation methods available, such as BIP-FROST-DKG:
# https://github.com/BlockstreamResearch/bip-frost-dkg

# todo: use the `Scalar` type like BIP-DKG?
#todo: this shows mypy error, but the file runs

from typing import Tuple, List, NewType
import unittest
# todo: replace random module with secrets
import random
# for [1] import functions from reference
#     [2] specify path for bip340 when running reference.py
# import sys, os
# script_dir = os.path.dirname(os.path.abspath(__file__))
# parent_dir = os.path.abspath(os.path.join(script_dir, '..'))
# sys.path.append(parent_dir)
from .bip340 import (
    Point, n as curve_order, bytes_from_int,
    point_mul, G, has_even_y, x
)

# point on the secret polynomial, represents a signer's secret share
PolyPoint = Tuple[int, int]
# point on the secp256k1 curve, represents a signer's public share
ECPoint = Point

#
# The following helper functions and types were copied from reference.py
#
PlainPk = NewType('PlainPk', bytes)

def xbytes(P: Point) -> bytes:
    return bytes_from_int(x(P))

def cbytes(P: Point) -> bytes:
    a = b'\x02' if has_even_y(P) else b'\x03'
    return a + xbytes(P)

def derive_interpolating_value_internal(L: List[int], x_i: int) -> int:
    num, deno = 1, 1
    for x_j in L:
        if x_j == x_i:
            continue
        num *= x_j
        deno *= (x_j - x_i)
    return num * pow(deno, curve_order - 2, curve_order) % curve_order
#
# End of helper functions and types copied from reference.py.
#

# evaluates poly using Horner's method, assuming coeff[0] corresponds
# to the coefficient of highest degree term
def polynomial_evaluate(coeffs: List[int], x: int) -> int:
    res = 0
    for coeff in coeffs:
        res = res * x + coeff
    return res % curve_order


def secret_share_combine(shares: List[PolyPoint]) -> int:
    x_coords = []
    for (x, y) in shares:
        x_coords.append(x)

    secret = 0
    for (x, y) in shares:
        delta = y * derive_interpolating_value_internal(x_coords, x)
        secret += delta
    return secret % curve_order

# coeffs shouldn't include the const term (i.e. secret)
def secret_share_shard(secret: int, coeffs: List[int], max_participants: int) -> List[PolyPoint]:
    coeffs = coeffs + [secret]

    secshares: List[PolyPoint] = []
    for x_i in range(1, max_participants + 1):
        y_i = polynomial_evaluate(coeffs, x_i)
        secshare_i = (x_i, y_i)
        secshares.append(secshare_i)
    return secshares

def trusted_dealer_keygen(secret_key: int, max_participants: int, min_participants: int) -> Tuple[ECPoint, List[PolyPoint], List[ECPoint]]:
    assert (1 <= secret_key <= curve_order - 1)
    assert (2 <= min_participants <= max_participants)
    # we don't force BIP340 compatibility of group pubkey in keygen
    P = point_mul(G, secret_key)
    assert P is not None

    coeffs = []
    for i in range(min_participants - 1):
        coeffs.append(random.randint(1, curve_order - 1))
    secshares = secret_share_shard(secret_key, coeffs, max_participants)
    pubshares = []
    for secshare in secshares:
        X = point_mul(G, secshare[1])
        assert X is not None
        pubshares.append(X)
    return (P, secshares, pubshares)

def generate_frost_keys(max_participants: int, min_participants: int) -> Tuple[PlainPk, List[bytes], List[PlainPk]]:
    if not (2 <= min_participants <= max_participants):
        raise ValueError('values must satisfy: 2 <= min_participants <= max_participants')

    secret = random.randint(1, curve_order - 1)
    P, secshares, pubshares = trusted_dealer_keygen(secret, max_participants, min_participants)

    group_pk = PlainPk(cbytes(P))
    ser_identifiers = [bytes_from_int(secshare_i[0]) for secshare_i in secshares]
    ser_secshares = [bytes_from_int(secshare_i[1]) for secshare_i in secshares]
    ser_pubshares = [PlainPk(cbytes(pubshare_i)) for pubshare_i in pubshares]
    return (group_pk, ser_identifiers, ser_secshares, ser_pubshares)

# Test vector from RFC draft.
# section F.5 of https://datatracker.ietf.org/doc/draft-irtf-cfrg-frost/15/
class Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.max_participants = 3
        self.min_participants = 2
        self.poly = [
            0xfbf85eadae3058ea14f19148bb72b45e4399c0b16028acaf0395c9b03c823579,
            0x0d004150d27c3bf2a42f312683d35fac7394b1e9e318249c1bfe7f0795a83114,
        ]
        self.shares: List[PolyPoint] = [
            (1, 0x08f89ffe80ac94dcb920c26f3f46140bfc7f95b493f8310f5fc1ea2b01f4254c),
            (2, 0x04f0feac2edcedc6ce1253b7fab8c86b856a797f44d83d82a385554e6e401984),
            (3, 0x00e95d59dd0d46b0e303e500b62b7ccb0e555d49f5b849f5e748c071da8c0dbc),
        ]
        self.secret = 0x0d004150d27c3bf2a42f312683d35fac7394b1e9e318249c1bfe7f0795a83114

    def test_polynomial_evaluate(self) -> None:
        coeffs = self.poly.copy()
        expected_secret = self.secret

        self.assertEqual(polynomial_evaluate(coeffs, 0), expected_secret)

    def test_secret_share_combine(self) -> None:
        shares: List[PolyPoint] = self.shares.copy()
        expected_secret = self.secret

        self.assertEqual(secret_share_combine([shares[0], shares[1]]), expected_secret)
        self.assertEqual(secret_share_combine([shares[1], shares[2]]), expected_secret)
        self.assertEqual(secret_share_combine([shares[0], shares[2]]), expected_secret)
        self.assertEqual(secret_share_combine(shares), expected_secret)

    def test_trusted_dealer_keygen(self) -> None:
        secret_key = random.randint(1, curve_order - 1)
        max_participants = 5
        min_participants = 3
        group_pk, secshares, pubshares = trusted_dealer_keygen(secret_key, max_participants, min_participants)

        # group_pk need not be xonly (i.e., have even y always)
        self.assertEqual(group_pk, point_mul(G, secret_key))
        self.assertEqual(secret_share_combine(secshares), secret_key)
        self.assertEqual(len(secshares), max_participants)
        self.assertEqual(len(pubshares), max_participants)
        for i in range(len(pubshares)):
            with self.subTest(i=i):
                self.assertEqual(pubshares[i], point_mul(G, secshares[i][1]))

if __name__=='__main__':
    unittest.main()
