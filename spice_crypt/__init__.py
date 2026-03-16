# SPDX-FileCopyrightText: © 2025-2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
SpiceCrypt - A library for decrypting LTspice® encrypted files
"""

__version__ = "1.1.1-dev"

from spice_crypt.binary_file import BinaryFileParser
from spice_crypt.crypto_state import CryptoState
from spice_crypt.decrypt import LTspiceFileParser, decrypt, decrypt_stream
from spice_crypt.des import LTspiceDES

__all__ = [
    "BinaryFileParser",
    "CryptoState",
    "LTspiceDES",
    "LTspiceFileParser",
    "decrypt",
    "decrypt_stream",
]
