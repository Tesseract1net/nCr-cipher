"""
ncr-cipher: combinatorics-based symmetric encryption.
"""
from ncr_cipher.core import (
    NCRKey,
    NCRError,
    NCRAuthError,
    NCRFormatError,
    VERSION,
)

__version__ = VERSION
__all__ = ["NCRKey", "NCRError", "NCRAuthError", "NCRFormatError", "__version__"]
