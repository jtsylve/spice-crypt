# SPDX-FileCopyrightText: © 2025-2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Brute-force key recovery for PSpice Mode 4 encryption.

Mode 4 uses AES-256 ECB but a key-derivation bug leaves only 4 of the
32 key bytes unknown, shrinking the effective keyspace to 2^32.  The
encrypted header block always decrypts to ``"0001.0000 "`` in the first
10 bytes, providing a known-plaintext crib for validating candidates.

The Rust extension ``_aes_brute`` (compiled at install time via
maturin) provides hardware-accelerated AES and rayon parallelism
across all cores, completing the search in seconds.
"""

from __future__ import annotations

import struct
from typing import TYPE_CHECKING, NamedTuple

if TYPE_CHECKING:
    import os

try:
    from spice_crypt.pspice._aes_brute import search_range as _native_search
except ImportError:
    _native_search = None

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_HEADER_PREFIX = b"0001.0000 "
_TOTAL = 0x1_0000_0000  # 2^32


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------


class RecoveredKey(NamedTuple):
    """Result of a Mode 4 key recovery attack."""

    short_key_bytes: bytes
    """The 4 unknown AES key bytes (positions 0-3)."""

    user_key_short: bytes
    """User key bytes 0-3: ``XOR(short_key_bytes, b\"8gM2\")``."""

    user_key_extended: bytes
    """User key bytes 4-30, recovered from the encrypted header."""

    user_key_full: bytes
    """Complete user key string (31 bytes) from the CSV file."""


# ---------------------------------------------------------------------------
# File parsing
# ---------------------------------------------------------------------------


def _extract_header_block(
    file_path: str | os.PathLike,
) -> tuple[str, bytes]:
    """Return ``(version_str, header_block)`` from *file_path*.

    The header block is the first 64-byte ciphertext line after a
    Mode 4 ``$CDNENCSTART`` marker.

    Raises :class:`ValueError` if no Mode 4 blocks are found.
    """
    from spice_crypt.pspice.keys import mode_from_marker

    active = False
    version_str = ""

    with open(file_path) as f:
        for line in f:
            stripped = line.strip()

            if stripped.startswith("$CDNENCSTART"):
                mode, ver = mode_from_marker(stripped)
                active = mode == 4
                if active:
                    version_str = ver
                continue

            if stripped.startswith("$CDNENCFINISH"):
                active = False
                continue

            if not active or not stripped:
                continue

            try:
                raw = bytes.fromhex(stripped)
            except ValueError:
                continue
            if len(raw) != 64:
                continue

            # First valid 64-byte line after the marker is the header
            return version_str, raw

    raise ValueError(
        "No Mode 4 encrypted blocks found.  "
        "The file must contain $CDNENCSTART_ADV3 or "
        "$CDNENCSTART_USER_ADV3 markers."
    )


# ---------------------------------------------------------------------------
# Default-key fast path
# ---------------------------------------------------------------------------


def _is_default_key(header_block: bytes, version_str: str) -> bool:
    """Return ``True`` if the header decrypts with unmodified base keys."""
    from spice_crypt.pspice.decrypt import _decrypt_64_block, _make_cipher
    from spice_crypt.pspice.keys import derive_keys

    short_key, _ = derive_keys(mode=4, version_str=version_str)
    cipher = _make_cipher(4, short_key)
    pt = _decrypt_64_block(cipher, 4, header_block)
    return pt[:10] == _HEADER_PREFIX


# ---------------------------------------------------------------------------
# Header decryption & extended key recovery
# ---------------------------------------------------------------------------


def _recover_extended_key(
    short_key_bytes: bytes,
    suffix: bytes,
    header_block: bytes,
) -> bytes:
    """Decrypt the header and return ``user_key[4:31]``."""
    from spice_crypt.pspice.decrypt import _decrypt_64_block, _make_cipher
    from spice_crypt.pspice.keys import _EXT_BASE

    short_key = short_key_bytes + suffix
    cipher = _make_cipher(4, short_key)
    header_pt = _decrypt_64_block(cipher, 4, header_block)

    # Validate structure
    if header_pt[:10] != _HEADER_PREFIX:
        raise RuntimeError(
            f"Header decryption failed: expected {_HEADER_PREFIX!r}, got {header_pt[:10]!r}"
        )

    # g_aesKey sits at fixed offset 10, length = 27 (base) + len(suffix)
    ext_key_len = 27 + len(suffix)
    g_aes_key = header_pt[10 : 10 + ext_key_len]

    # Strip version suffix to get the XOR'd base
    xord_base = g_aes_key[: -len(suffix)]

    # Recover user_key[4:31] = XOR(xord_base, ext_base)
    return bytes(a ^ b for a, b in zip(xord_base, _EXT_BASE, strict=True))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def recover_mode4_key(
    file_path: str | os.PathLike,
) -> RecoveredKey:
    """Recover the user key from a Mode 4 encrypted PSpice file.

    Brute-forces the 2^32 candidate keyspace using the known header
    prefix ``"0001.0000 "`` as a plaintext crib, then decrypts the full
    header to recover the user key.  Uses the Rust ``_aes_brute``
    extension for hardware-accelerated AES across all CPU cores.

    Args:
        file_path: Path to the encrypted PSpice file.

    Returns:
        :class:`RecoveredKey` with all recovered key material.

    Raises:
        ValueError: If the file lacks Mode 4 blocks or uses default keys.
        RuntimeError: If the Rust extension is not available or the search fails.
    """
    if _native_search is None:
        raise RuntimeError(
            "Brute-force key recovery requires the compiled Rust extension "
            "(_aes_brute), which is not available.  Install from a pre-built "
            "wheel (pip install spice-crypt) or build from source with a "
            "Rust toolchain installed."
        )

    from spice_crypt.pspice.keys import _SHORT_BASE, version_suffix

    version_str, header_block = _extract_header_block(file_path)

    # Fast path: check default (no user key) Mode 4 key
    if _is_default_key(header_block, version_str):
        raise ValueError(
            "File uses default Mode 4 keys (no user key applied).  "
            "No key recovery needed -- decrypt directly."
        )

    # Build key template: bytes 4+ = version suffix, rest zeros
    suffix = version_suffix(version_str)
    key_tpl = bytearray(32)
    key_tpl[4 : 4 + len(suffix)] = suffix
    key_tpl = bytes(key_tpl)

    # Brute-force: first AES sub-block of the header
    found = _native_search(header_block[0:16], key_tpl, 0, _TOTAL, _HEADER_PREFIX)

    if found is None:
        raise RuntimeError(
            "Exhausted 2^32 keyspace without finding a valid key.  "
            "Verify the file contains genuine Mode 4 encrypted blocks."
        )

    short_key_bytes = struct.pack("<I", found)

    # Recover user key bytes 0-3
    user_key_short = bytes(a ^ b for a, b in zip(short_key_bytes, _SHORT_BASE, strict=True))

    # Recover user key bytes 4-30 from header
    user_key_extended = _recover_extended_key(short_key_bytes, suffix, header_block)

    return RecoveredKey(
        short_key_bytes=short_key_bytes,
        user_key_short=user_key_short,
        user_key_extended=user_key_extended,
        user_key_full=user_key_short + user_key_extended,
    )
