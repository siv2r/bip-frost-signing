from pathlib import Path
import sys

# Add the vendored copy of secp256k1lab to path.
sys.path.append(str(Path(__file__).parent / "../secp256k1lab/src"))

from .signing import (
    # Functions
    nonce_gen,
    nonce_agg,
    sign,
    deterministic_sign,
    partial_sig_verify,
    partial_sig_agg,
    # Exceptions
    InvalidContributionError,
    # Types
    PlainPk,
    XonlyPk,
    SessionContext,
)

__all__ = [
    # Functions
    "nonce_gen",
    "nonce_agg",
    "sign",
    "deterministic_sign",
    "partial_sig_verify",
    "partial_sig_agg",
    # Exceptions
    "InvalidContributionError",
    # Types
    "PlainPk",
    "XonlyPk",
    "SessionContext",
]
