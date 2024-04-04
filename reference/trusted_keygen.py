from typing import Tuple, List
from bip340_utils import Point

# 'NewType' vs type-alias
SecShare = Tuple[int, int]
PubShare = Point

def polynomial_evaluate(x: int, coeffs: int) -> int:
    pass

def polynomial_interpolate_constant(points: Point) -> int:
    pass

def secret_share_shard(s: int, coefficients: List[int], MAX_PARTICIPANTS: int):
    pass

def secret_share_combine(shares: List[SecShare]):
    pass

# output: group_pubkey (PlainPK), N-secret_shares, N-pubshares (Point)
def trusted_dealer_keygen(secret_key: int, MAX_PARTICIPANTS: int, MIN_PARTICIPANTS: int):
    pass