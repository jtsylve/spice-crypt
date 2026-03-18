# SPDX-FileCopyrightText: © 2025-2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Decryption support for PSpice encrypted model files.

PSpice files are plain-text SPICE netlists with selected ``.SUBCKT``
and ``.MODEL`` blocks replaced by hex-encoded ciphertext between
``$CDNENCSTART`` / ``$CDNENCFINISH`` marker pairs.  Six encryption
modes are supported (0-5), spanning DES (modes 0-2) and AES-256 ECB
(modes 3-5).

See ``.claude/plans/pspice-encryption.md`` for the full specification.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from spice_crypt.pspice.keys import derive_keys, load_user_keys, mode_from_marker

if TYPE_CHECKING:
    import os
    from collections.abc import Generator

# Sentinel bytes in each 64-byte encrypted block
_BLOCK_MARKER = b"\x24\x2b"  # '$+' at bytes 62-63
_PAD_SENTINEL = b" $jbs$"


def _make_cipher(mode: int, short_key: bytes):
    """Instantiate and key the correct cipher engine for *mode*."""
    if mode <= 2:
        from spice_crypt.pspice.des import PSpiceDES

        cipher = PSpiceDES()
        cipher.set_key(short_key)
        return cipher

    # Modes 3-5: AES-256 ECB
    from spice_crypt._aes import AES256ECB

    # Short key zero-padded to 32 bytes
    aes_key = (short_key + b"\x00" * 32)[:32]
    return AES256ECB(aes_key)


def _decrypt_64_block(cipher, mode: int, data: bytes) -> bytes:
    """Decrypt a single 64-byte block using the appropriate engine."""
    if mode <= 2:
        return cipher.process_block(data, decrypt=True)

    # AES: 4 x 16-byte ECB blocks
    result = bytearray(64)
    for i in range(4):
        result[i * 16 : i * 16 + 16] = cipher.decrypt_block(data[i * 16 : i * 16 + 16])
    return bytes(result)


def _extract_plaintext(block: bytes) -> bytes:
    """Extract the plaintext content from a decrypted 64-byte block.

    - Bytes 62-63 are the ``$+`` block marker (validation sentinel).
    - The content before position 62 may end with the `` $jbs$`` padding
      sentinel followed by random fill.  If found, content is truncated
      at the sentinel.
    """
    # Content is in bytes 0-61 (bytes 62-63 are the $+ marker)
    content = block[:62]
    idx = content.find(_PAD_SENTINEL)
    if idx >= 0:
        content = content[:idx]
    # Strip trailing null bytes
    return content.rstrip(b"\x00")


class PSpiceFileParser:
    """Parser for PSpice encrypted files with streaming support.

    Reads a text-mode file object, passes non-encrypted lines through
    unchanged, and decrypts ``$CDNENCSTART`` / ``$CDNENCFINISH`` blocks.
    """

    def __init__(
        self,
        file_obj,
        user_key_file: str | os.PathLike | None = None,
        encrypted_file_path: str | os.PathLike | None = None,
        user_key_bytes: bytes | None = None,
    ):
        """
        Args:
            file_obj: Seekable text-mode file-like object.
            user_key_file: Path to user key CSV file for mode 4.
            encrypted_file_path: Path of the file being decrypted
                (used for user key identity matching in mode 4).
            user_key_bytes: Raw user key bytes for mode 4 (alternative
                to loading from a CSV file via *user_key_file*).
        """
        self.file_obj = file_obj
        self.user_key_file = user_key_file
        self.encrypted_file_path = encrypted_file_path
        self.user_key_bytes = user_key_bytes

    def decrypt_stream(self) -> Generator[bytes, None, tuple[int, int]]:
        """Stream-decrypt the file, yielding plaintext chunks.

        Non-encrypted lines are yielded as-is (encoded to bytes).
        Encrypted blocks are decrypted and the plaintext content is
        yielded line by line.

        Returns:
            Generator yielding bytes chunks.
            The return value (via ``StopIteration``) is ``(0, 0)``
            (PSpice files have no verification checksums).
        """
        continuation = b""
        in_encrypted_block = False
        cipher = None
        mode = 0
        is_header = False

        for line in self.file_obj:
            stripped = (
                line.strip() if isinstance(line, str) else line.decode("utf-8", "replace").strip()
            )

            # Check for block start marker
            if stripped.startswith("$CDNENCSTART"):
                in_encrypted_block = True
                is_header = True
                mode, version_str = mode_from_marker(stripped)

                # Derive keys
                user_key = self.user_key_bytes
                if user_key is None and mode == 4 and self.user_key_file:
                    user_key = load_user_keys(self.user_key_file, self.encrypted_file_path)
                short_key, _ = derive_keys(mode, version_str, user_key)
                cipher = _make_cipher(mode, short_key)
                continue

            # Check for block end marker
            if stripped.startswith("$CDNENCFINISH"):
                # Flush any pending continuation line
                if continuation:
                    yield continuation + b"\n"
                    continuation = b""
                in_encrypted_block = False
                cipher = None
                continue

            if not in_encrypted_block:
                # Pass through non-encrypted lines
                line_bytes = line.encode("utf-8") if isinstance(line, str) else line
                yield line_bytes
                continue

            # Inside an encrypted block — decode and decrypt the hex line
            hex_str = stripped
            if not hex_str:
                continue

            try:
                block_data = bytes.fromhex(hex_str)
            except ValueError:
                continue

            if len(block_data) != 64:
                continue

            plaintext_block = _decrypt_64_block(cipher, mode, block_data)

            # Skip the encrypted header (first block after marker)
            if is_header:
                is_header = False
                continue

            content = _extract_plaintext(plaintext_block)

            # Handle continuation lines: if the decrypted content starts
            # with '+', it's a continuation of the previous line.
            if content.startswith(b"+"):
                continuation += content[1:]
            else:
                if continuation:
                    yield continuation + b"\n"
                continuation = content

        # Flush final continuation
        if continuation:
            yield continuation + b"\n"

        return (0, 0)
