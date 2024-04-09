# todo: mention this is utility and unrelated to the spec
# todo: link the frost draft
# todo: use the `Scalar` type like BIP-DKG

from typing import Tuple, List
import unittest
import random
from bip340_utils import (
    Point, n as curve_order, bytes_from_int,
    point_mul, G, has_even_y
)
from reference import point_negate, cbytes, PlainPk, individual_pk

# point on the secret polynomial
SecShare = Tuple[int, int]
# point on the secp256k1 curve
PubShare = Point

# evaluates poly using Horner's method, assuming coeff[0] corresponds
# to the coefficient of highest degree term
# todo: where is this used?
def polynomial_evaluate(coeffs: int, x: int) -> int:
    res = 0
    for coeff in coeffs:
        res = res * x + coeff
    return res % curve_order

#TODO: move this fn to reference.py since it is part of the spec
def derive_interpolating_value(L: List[int], x_i: int):
    assert x_i in L
    assert all(L.count(x_j) <= 1 for x_j in L)
    num, denom = 1, 1
    for x_j in L:
        if x_j == x_i:
            continue
        num *= x_j
        denom *= (x_j - x_i)
    return num * pow(denom, curve_order - 2, curve_order) % curve_order

def secret_share_combine(shares: List[SecShare]) -> int:
    x_coords = []
    for (x, y) in shares:
        x_coords.append(x)

    secret = 0
    for (x, y) in shares:
        delta = y * derive_interpolating_value(x_coords, x)
        secret += delta
    return secret % curve_order

# coeffs shouldn't include the const term (i.e. secret)
def secret_share_shard(secret: int, coeffs: List[int], max_participants: int) -> List[SecShare]:
    coeffs = coeffs + [secret]

    secshares: List[SecShare] = []
    for x_i in range(1, max_participants + 1):
        y_i = polynomial_evaluate(coeffs, x_i)
        secshare_i = (x_i, y_i)
        secshares.append(secshare_i)
    return secshares

def trusted_dealer_keygen(secret_key: int, max_participants: int, min_participants: int) -> Tuple[PlainPk, List[SecShare], List[PlainPk]]:
    assert 1 <= secret_key <= curve_order - 1
    # BIP340 compatible group public key
    P = point_mul(G, secret_key)
    if not has_even_y(P):
        secret_key = curve_order - secret_key
        P = point_negate(P)

    coeffs = []
    for i in range(min_participants - 1):
        coeffs.append(random.randint(1, curve_order - 1))
    secshares = secret_share_shard(secret_key, coeffs, max_participants)
    pubshares = [point_mul(G, secshare[1]) for secshare in secshares]
    # serialize outputs
    group_pubkey = cbytes(P)
    participant_secshares = [bytes_from_int(share[1]) for share in secshares]
    participant_pubshares = [cbytes(share) for share in pubshares]
    return (group_pubkey, participant_secshares, participant_pubshares)


# Test vector from RFC draft.
# section F.5 of https://datatracker.ietf.org/doc/draft-irtf-cfrg-frost/15/
class Tests(unittest.TestCase):
    def setUp(self):
        self.max_participants = 3
        self.min_participants = 2
        self.poly = [
            0xfbf85eadae3058ea14f19148bb72b45e4399c0b16028acaf0395c9b03c823579,
            0x0d004150d27c3bf2a42f312683d35fac7394b1e9e318249c1bfe7f0795a83114,
        ]
        self.shares: List[SecShare] = [
            (1, 0x08f89ffe80ac94dcb920c26f3f46140bfc7f95b493f8310f5fc1ea2b01f4254c),
            (2, 0x04f0feac2edcedc6ce1253b7fab8c86b856a797f44d83d82a385554e6e401984),
            (3, 0x00e95d59dd0d46b0e303e500b62b7ccb0e555d49f5b849f5e748c071da8c0dbc),
        ]
        self.secret = 0x0d004150d27c3bf2a42f312683d35fac7394b1e9e318249c1bfe7f0795a83114

    def test_polynomial_evaluate(self):
        coeffs = self.poly.copy()
        expected_secret = self.secret

        self.assertEqual(polynomial_evaluate(coeffs, 0), expected_secret)

    def test_secret_share_combine(self):
        shares: List[SecShare] = self.shares.copy()
        expected_secret = self.secret

        self.assertEqual(secret_share_combine([shares[0], shares[1]]), expected_secret)
        self.assertEqual(secret_share_combine([shares[1], shares[2]]), expected_secret)
        self.assertEqual(secret_share_combine([shares[0], shares[2]]), expected_secret)
        self.assertEqual(secret_share_combine(shares), expected_secret)

    def test_trusted_dealer_keygen(self):
        secret_key = random.randint(1, curve_order - 1)
        max_participants = 5
        min_participants = 3
        group_pk, secshares, pubshares = trusted_dealer_keygen(secret_key, max_participants, min_participants)

        self.assertEqual(group_pk, cbytes(point_mul(G, secret_key)))
        self.assertEqual(secret_share_combine(secshares), secret_key)
        self.assertEqual(len(secshares), max_participants)
        self.assertEqual(len(pubshares), max_participants)
        for i in range(len(pubshares)):
            with self.subTest(i=i):
                self.assertEqual(pubshares[i], individual_pk(secshares[i][1]))



if __name__=='__main__':
    unittest.main()
