# todo: mention this is utility and unrelated to the spec
# todo: link the frost draft
# todo: use the `Scalar` type like BIP-DKG

from typing import Tuple, List
from bip340_utils import Point, n

# point on the secret polynomial
SecShare = Tuple[int, int]
# point on the secp256k1 curve
PubShare = Point

# evaluates poly using Horner's method, assuming coeff[0] corresponds
# to the coefficient of highest degree term
def polynomial_evaluate(x: int, coeffs: int) -> int:
    res = 0
    for coeff in reversed(coeffs):
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
     for (x, y) in points:
       x_coords.append(x)

     secret = 0
     for (x, y) in points:
       delta = y * derive_interpolating_value(x_coords, x)
       secret += delta
     return secret

def secret_share_shard(s: int, coefficients: List[int], MAX_PARTICIPANTS: int):
    pass

# output: group_pubkey (PlainPK), N-secret_shares, N-pubshares (Point)
def trusted_dealer_keygen(secret_key: int, MAX_PARTICIPANTS: int, MIN_PARTICIPANTS: int):
    pass

