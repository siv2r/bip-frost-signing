# todo: mention this is utility and unrelated to the spec
# todo: link the frost draft
# todo: use the `Scalar` type like BIP-DKG

from typing import Tuple, List
from bip340_utils import Point, n
import unittest

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
    return res % n

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
    return num * pow(denom, n - 2, n) % n

def secret_share_combine(shares: List[SecShare]) -> int:
    x_coords = []
    for (x, y) in shares:
        x_coords.append(x)

    secret = 0
    for (x, y) in shares:
        delta = y * derive_interpolating_value(x_coords, x)
        secret += delta
    return secret % n

def secret_share_shard(s: int, coefficients: List[int], MAX_PARTICIPANTS: int):
    pass

# output: group_pubkey (PlainPK), N-secret_shares, N-pubshares (Point)
def trusted_dealer_keygen(secret_key: int, MAX_PARTICIPANTS: int, MIN_PARTICIPANTS: int):
    pass

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

if __name__=='__main__':
    unittest.main()
