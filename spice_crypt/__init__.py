# SPDX-FileCopyrightText: © 2025 Bayou Bits Technologies, LLC
# SPDX-FileCopyrightText: © 2025 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
# SPDX-License-Identifier: LicenseRef-Proprietary
#
# This source code is proprietary and confidential.  It is provided under the
# terms of a written license agreement between BAYOU BITS TECHNOLOGIES, LLC
# and the recipient.  Any unauthorized use, copying, modification, or
# distribution is strictly prohibited.
#
# Authorized representatives of the licensed recipient may request a copy of
# the written license agreement via email at joe.sylve@gmail.com.

"""
SpiceCrypt - A library for decrypting LTSpice encrypted files
"""

__version__ = "1.0.0"

from spice_crypt.crypto_state import CryptoState
from spice_crypt.decrypt import LTSpiceFileParser, decrypt, decrypt_stream
from spice_crypt.des import LTSpiceDES

__all__ = ["CryptoState", "LTSpiceDES", "LTSpiceFileParser", "decrypt", "decrypt_stream"]
