from pathlib import Path
import sys


# Add the vendored copy of secp256k1lab to path.
sys.path.append(str(Path(__file__).parent / "../secp256k1lab/src"))
