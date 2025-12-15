# TODO: remove this file, and use trusted dealer BIP's reference code instead

# Implementation of the Trusted Dealer Key Generation approach for FROST mentioned
# in https://datatracker.ietf.org/doc/draft-irtf-cfrg-frost/15/ (Appendix D).
#
# It's worth noting that this isn't the only compatible method (with BIP FROST Signing),
# there are alternative key generation methods available, such as BIP-FROST-DKG:
# https://github.com/BlockstreamResearch/bip-frost-dkg

# todo: this shows mypy error, but the file runs

from typing import Tuple, List, NewType
import unittest

# todo: replace random module with secrets
import random
import secrets
# for [1] import functions from reference
#     [2] specify path for bip340 when running reference.py
# import sys, os
# script_dir = os.path.dirname(os.path.abspath(__file__))
# parent_dir = os.path.abspath(os.path.join(script_dir, '..'))
# sys.path.append(parent_dir)

# Add the vendored copy of secp256k1lab to path.
from secp256k1lab.secp256k1 import G, GE, Scalar

# todo: FIX IMPORTS. don't defined own types. Import them from signing or secp256k1lab
curve_order = GE.ORDER
# point on the secret polynomial, represents a signer's secret share
PolyPoint = Tuple[int, int]
# point on the secp256k1 curve, represents a signer's public share
ECPoint = GE

#
# The following helper functions and types were copied from reference.py
#
PlainPk = NewType("PlainPk", bytes)


def derive_interpolating_value_internal(L: List[int], x_i: int) -> Scalar:
    num, deno = 1, 1
    for x_j in L:
        if x_j == x_i:
            continue
        num *= x_j
        deno *= x_j - x_i
    return Scalar.from_int_wrapping(num * pow(deno, curve_order - 2, curve_order))


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


def secret_share_combine(shares: List[PolyPoint]) -> Scalar:
    x_coords = []
    for x, y in shares:
        x_coords.append(x)

    secret = Scalar(0)
    for x, y in shares:
        delta = y * derive_interpolating_value_internal(x_coords, x)
        secret += delta
    return secret


# coeffs shouldn't include the const term (i.e. secret)
def secret_share_shard(secret: int, coeffs: List[int], n: int) -> List[PolyPoint]:
    coeffs = coeffs + [secret]

    secshares: List[PolyPoint] = []
    for x_i in range(1, n + 1):
        y_i = polynomial_evaluate(coeffs, x_i)
        secshare_i = (x_i, y_i)
        secshares.append(secshare_i)
    return secshares


def trusted_dealer_keygen(
    secret_key: Scalar, n: int, t: int
) -> Tuple[ECPoint, List[PolyPoint], List[ECPoint]]:
    assert secret_key != 0
    assert 2 <= t <= n
    # we don't force BIP340 compatibility of threshold pubkey in keygen
    P = secret_key * G
    assert not P.infinity

    coeffs = []
    for i in range(t - 1):
        coeffs.append(random.randint(1, curve_order - 1))
    secshares = secret_share_shard(int(secret_key), coeffs, n)
    pubshares = []
    for secshare in secshares:
        X = secshare[1] * G
        assert not X.infinity
        pubshares.append(X)
    return (P, secshares, pubshares)


# Test vector from RFC draft.
# section F.5 of https://datatracker.ietf.org/doc/draft-irtf-cfrg-frost/15/
class Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.n = 3
        self.t = 2
        self.poly = [
            0xFBF85EADAE3058EA14F19148BB72B45E4399C0B16028ACAF0395C9B03C823579,
            0x0D004150D27C3BF2A42F312683D35FAC7394B1E9E318249C1BFE7F0795A83114,
        ]
        self.shares: List[PolyPoint] = [
            (1, 0x08F89FFE80AC94DCB920C26F3F46140BFC7F95B493F8310F5FC1EA2B01F4254C),
            (2, 0x04F0FEAC2EDCEDC6CE1253B7FAB8C86B856A797F44D83D82A385554E6E401984),
            (3, 0x00E95D59DD0D46B0E303E500B62B7CCB0E555D49F5B849F5E748C071DA8C0DBC),
        ]
        self.secret = 0x0D004150D27C3BF2A42F312683D35FAC7394B1E9E318249C1BFE7F0795A83114

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
        secret_key = Scalar.from_bytes_wrapping(secrets.token_bytes(32))
        n = 5
        t = 3
        thresh_pk, secshares, pubshares = trusted_dealer_keygen(secret_key, n, t)

        # thresh_pk need not be xonly (i.e., have even y always)
        self.assertEqual(thresh_pk, secret_key * G)
        self.assertEqual(secret_share_combine(secshares), secret_key)
        self.assertEqual(len(secshares), n)
        self.assertEqual(len(pubshares), n)
        for i in range(len(pubshares)):
            with self.subTest(i=i):
                self.assertEqual(pubshares[i], secshares[i][1] * G)


if __name__ == "__main__":
    unittest.main()
