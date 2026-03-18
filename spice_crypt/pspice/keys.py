# SPDX-FileCopyrightText: © 2025-2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
PSpice encryption key derivation for all 6 modes.

Modes 0-2 use ``CDesEncoder`` (DES); modes 3-5 use ``PSpiceAESEncoder``
(AES-256 ECB).  All key material for modes 0-3 and 5 is derived from
hardcoded constants.  Mode 4 optionally XORs user-provided key bytes.
"""

from __future__ import annotations

import os
import re

# Marker patterns for mode detection
_MARKER_RE = re.compile(
    r"\$CDNENCSTART(?:_(USER_)?ADV|_CENC)?(\d*)",
    re.IGNORECASE,
)


def mode_from_marker(marker: str) -> tuple[int, str]:
    """Determine the encryption mode and version from a marker line.

    Args:
        marker: The ``$CDNENCSTART`` marker line (leading/trailing whitespace OK).

    Returns:
        ``(mode, version_string)`` tuple.  *version_string* is the
        trailing digit(s) from the marker (e.g., ``"2"`` for
        ``$CDNENCSTART_ADV2``), or ``""`` for bare ``$CDNENCSTART``.
    """
    marker = marker.strip()

    if marker == "$CDNENCSTART":
        return (0, "")

    m = _MARKER_RE.match(marker)
    if m is None:
        return (0, "")

    user_prefix = m.group(1)  # "USER_" or None
    version = m.group(2)  # trailing digits (may be empty)

    # CENC markers
    if "_CENC" in marker.upper():
        if version == "5":
            return (5, version)
        return (1, version)

    # ADV / USER_ADV markers
    if version == "1":
        return (2, version)
    if version == "2":
        return (3, version)
    if version == "3":
        return (4, version)
    if user_prefix:
        return (4, version)

    # Unrecognized version defaults to mode 0 (matches PSpice behavior)
    return (0, version)


_SHORT_BASE = b"8gM2"
"""Mode 3/4 short key base string."""

_EXT_BASE = b"H41Mlwqaspj1nxasyhq8530nh1r"
"""Mode 3/4 extended key base string."""


def version_suffix(version_str: str) -> bytes:
    """Compute the numeric suffix bytes from a marker version string."""
    n = int(version_str) + 999 if version_str else 999
    return str(n).encode("ascii")


def derive_keys(
    mode: int,
    version_str: str = "",
    user_key_bytes: bytes | None = None,
) -> tuple[bytes, bytes]:
    """Derive the short and extended key strings for a given mode.

    Args:
        mode: Encryption mode (0--5).
        version_str: Version digit string from the marker.
        user_key_bytes: Optional 31-byte XOR key for mode 4.

    Returns:
        ``(short_key, extended_key)`` byte strings.  *short_key* is
        the actual encryption key passed to ``setKey``; *extended_key*
        appears only in encrypted header metadata.
    """
    if mode == 0:
        return (b"0a0vr7jo", b"ths0m02ukhy034r6")

    n_bytes = version_suffix(version_str)

    if mode == 1:
        return (b"1b1w" + n_bytes, b"uit1n13vliz1" + n_bytes)
    if mode == 2:
        return (b"1b1x" + n_bytes, b"uit1x13vlka1" + n_bytes)
    if mode == 5:
        return (b"1yti" + n_bytes, b"nhtti50rplx2" + n_bytes)

    # Modes 3 and 4 share the same base strings
    short_base = bytearray(_SHORT_BASE)
    ext_base = bytearray(_EXT_BASE)

    if mode == 4 and user_key_bytes and len(user_key_bytes) >= 4:
        # XOR first 4 bytes of user key into the short key base
        for i in range(4):
            short_base[i] ^= user_key_bytes[i]
        # XOR bytes 4-30 into the extended key base
        for i in range(min(27, len(user_key_bytes) - 4)):
            ext_base[i] ^= user_key_bytes[4 + i]

    return (bytes(short_base) + n_bytes, bytes(ext_base) + n_bytes)


def load_user_keys(
    key_file_path: str | os.PathLike,
    encrypted_file_path: str | os.PathLike | None = None,
) -> bytes | None:
    """Load user XOR key bytes from a PSpice key CSV file.

    The CSV file has lines of the form ``<file_path>; <xor_key_bytes>``.
    Lines whose file path matches *encrypted_file_path* are skipped
    (self-referential key prevention).  Returns the first non-matching
    key bytes, or ``None`` if no valid entry is found.

    Args:
        key_file_path: Path to the CSV key file.
        encrypted_file_path: Path of the file being decrypted (for
            identity comparison).

    Returns:
        Raw XOR key bytes, or ``None``.
    """
    try:
        enc_path = os.path.abspath(encrypted_file_path) if encrypted_file_path else None

        with open(key_file_path) as f:
            for line in f:
                line = line.strip()
                if not line or ";" not in line:
                    continue
                path_part, _, key_part = line.partition(";")
                path_part = path_part.strip()
                key_part = key_part.strip()

                if enc_path and os.path.abspath(path_part) == enc_path:
                    continue

                return key_part.encode("ascii")
    except (OSError, ValueError):
        pass
    return None
