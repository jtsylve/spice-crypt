# SPDX-FileCopyrightText: © 2025-2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Decryption support for LTspice encrypted text-based (hex/DES) files.

This module provides :class:`LTspiceFileParser` for streaming decryption of
the text-based hex/DES format, as well as the convenience functions
:func:`decrypt` and :func:`decrypt_stream` which auto-detect the file format
(text-based or Binary File) and delegate accordingly.
"""

import binascii
import contextlib
import io
import os
import re
import warnings
from collections.abc import Generator

from spice_crypt.binary_file import BinaryFileParser
from spice_crypt.crypto_state import CryptoState

_END_CHECKSUM_RE = re.compile(r"\*\s*End\s+(\d+)\s+(\d+)", re.IGNORECASE)


class LTspiceFileParser:
    """Parser for LTspice® encrypted files with efficient streaming support."""

    def __init__(self, file_obj, raw_mode=False):
        """
        Initialize the parser with a file object.

        Args:
            file_obj: File-like object (text mode) or path to file
            raw_mode: Whether to treat the input as raw hex data
        """
        self.file_obj = file_obj
        self.raw_mode = raw_mode
        self.checksums = None
        self._crypto_table = None
        self._crypto_state = None

    def _read_until_begin(self):
        """Read the file until the 'Begin:' marker is found."""
        if self.raw_mode:
            return

        for line in self.file_obj:
            line = line.strip()
            if line.lower().startswith("* begin:"):
                return

    def _extract_checksums(self, line):
        """Extract checksums from an End line."""
        end_match = _END_CHECKSUM_RE.search(line)

        if end_match:
            self.checksums = (int(end_match.group(1)), int(end_match.group(2)))

    @staticmethod
    def _convert_hex_block(hex_values):
        """Convert a list of hex strings to a bytes block.

        If fewer than 8 values are provided the block is zero-padded on the
        right to 8 bytes.
        """
        if len(hex_values) < 8:
            hex_values = hex_values + ["00"] * (8 - len(hex_values))
        try:
            return bytes.fromhex("".join(hex_values))
        except ValueError as e:
            raise ValueError(f"Invalid hex data: {' '.join(hex_values)}") from e

    def _process_hex_chunks(self):
        """Process hex data in chunks and yield 8-byte blocks to decrypt."""
        hex_data = []
        pos = 0  # read cursor; avoids O(n) front-deletion on the list

        for line in self.file_obj:
            line = line.strip()

            # Check if we've reached the end marker
            if not self.raw_mode and line.lower().startswith("* end"):
                self._extract_checksums(line)
                break

            # Skip comments in LTspice format
            if not self.raw_mode and line.startswith("*"):
                continue

            hex_data.extend(line.split())

            # Yield complete 8-value blocks as soon as they are available
            while len(hex_data) - pos >= 8:
                yield self._convert_hex_block(hex_data[pos : pos + 8])
                pos += 8

            # Reclaim memory periodically to avoid unbounded list growth
            if pos >= 1024:
                del hex_data[:pos]
                pos = 0

        # Yield any remaining partial block (zero-padded)
        remaining = hex_data[pos:]
        if remaining:
            yield self._convert_hex_block(remaining)

    def decrypt_stream(self) -> Generator[bytes, None, tuple[int, int]]:
        """
        Stream decrypt the file, yielding decrypted chunks.

        Returns:
            Generator that yields decrypted chunks
            The final value is the verification tuple (v1, v2)
        """
        # Start processing the file
        self._read_until_begin()

        block_count = 0
        table_bytes = bytearray(1024)
        plaintext_crc = 0
        ciphertext_crc = 0

        # Process the hex data in chunks
        for byte_block in self._process_hex_chunks():
            # First 1024 bytes (128 blocks) are the crypto table
            if block_count < 128:
                table_bytes[block_count * 8 : (block_count + 1) * 8] = byte_block
                block_count += 1

                # Once we have the complete table, initialize the crypto state
                if block_count == 128:
                    self._crypto_table = bytes(table_bytes)
                    self._crypto_state = CryptoState(self._crypto_table)
            else:
                # Update ciphertext CRC incrementally
                ciphertext_crc = binascii.crc32(byte_block, ciphertext_crc)

                # Decrypt the block
                result = self._crypto_state.decrypt_block(byte_block)

                # Convert result to bytes
                result_bytes = result.to_bytes(4, "little")

                # Update plaintext CRC
                plaintext_crc = binascii.crc32(result_bytes, plaintext_crc)

                # Yield the decrypted chunk
                yield result_bytes

        # Calculate verification values
        if self._crypto_table:
            table_word_44 = int.from_bytes(self._crypto_table[0x44:0x48], byteorder="little")
            table_word_94 = int.from_bytes(self._crypto_table[0x94:0x98], byteorder="little")
            v1 = plaintext_crc ^ 0x7A6D2C3A ^ table_word_44
            v2 = ciphertext_crc ^ 0x4DA77FD3 ^ table_word_94

            # Check against file checksums if available
            if self.checksums and (v1, v2) != self.checksums:
                warnings.warn(
                    f"Checksum mismatch! File: {self.checksums}, Calculated: ({v1}, {v2})",
                    stacklevel=2,
                )

            return (v1, v2)

        return (0, 0)


def _detect_ltspice_format(file_obj) -> bool:
    """
    Auto-detect whether a seekable file object contains LTspice-format data.

    Reads the first line, checks for known markers, then resets the stream
    position.  Returns True if the file appears to be in LTspice format.
    """
    first_line = file_obj.readline()
    file_obj.seek(0)
    return "* LTspice Encrypted File" in first_line or "* Begin:" in first_line


def _run_decrypt_generator(gen, output_file, stack):
    """Drive a parser's ``decrypt_stream`` generator, writing output.

    Returns ``(content, verification)`` in the same form as
    :func:`decrypt_stream`.
    """
    return_string = output_file is None
    if return_string:
        buffer = stack.enter_context(io.StringIO())
    elif isinstance(output_file, str):
        output_file = stack.enter_context(open(output_file, "wb"))  # noqa: SIM115

    try:
        while True:
            chunk = next(gen)
            if return_string:
                buffer.write(chunk.decode("utf-8", errors="replace"))
            else:
                output_file.write(chunk)
    except StopIteration as e:
        verification = e.value or (0, 0)

    return (buffer.getvalue() if return_string else None), verification


def decrypt_stream(
    input_file, output_file=None, is_ltspice_file=None
) -> tuple[str | None, tuple[int, int]]:
    """
    Stream decrypt data from input_file to output_file.

    Supports both the text-based hex/DES format and the Binary File
    format.  When *is_ltspice_file* is ``None`` (the default), the
    format is auto-detected: files beginning with the Binary File
    signature are handled by :class:`BinaryFileParser`; otherwise the
    text-based :class:`LTspiceFileParser` is used.

    Args:
        input_file: File object or path to read from
        output_file: File object or path to write to (if None, returns result as string)
        is_ltspice_file: Boolean indicating if file is in LTspice format
                         If None, auto-detect based on content

    Returns:
        tuple: (content, verification)
            - content: Decrypted text as string (if output_file is None) or None
            - verification: Tuple of verification values
    """
    with contextlib.ExitStack() as stack:
        # Handle path input -- open the file once and detect format from
        # the initial bytes, avoiding a separate open-read-close probe.
        if isinstance(input_file, str | os.PathLike):
            if is_ltspice_file is not False:
                raw = stack.enter_context(open(input_file, "rb"))
                header = raw.read(20)
                if BinaryFileParser.check_signature(header):
                    raw.seek(0)
                    parser = BinaryFileParser(raw)
                    return _run_decrypt_generator(parser.decrypt_stream(), output_file, stack)
                # Not a Binary File -- wrap the already-open handle as text
                raw.seek(0)
                input_file = stack.enter_context(
                    io.TextIOWrapper(raw, encoding="utf-8", errors="replace")
                )
            else:
                input_file = stack.enter_context(open(input_file))

        # Auto-detect if file is in LTspice format if not specified
        if is_ltspice_file is None:
            is_ltspice_file = _detect_ltspice_format(input_file)

        # Create parser
        parser = LTspiceFileParser(input_file, raw_mode=not is_ltspice_file)

        return _run_decrypt_generator(parser.decrypt_stream(), output_file, stack)


def decrypt(data, is_ltspice_file=None):
    """
    Decrypts encrypted data.

    Args:
        data: String containing encrypted data, either raw hex or LTspice file format
        is_ltspice_file: Boolean indicating if the data is in LTspice file format.
                         If None, auto-detect based on content.

    Returns:
        tuple: (plaintext, verification)
            - plaintext: Decrypted text as string
            - verification: Tuple of verification values
    """
    # Delegate to decrypt_stream which handles auto-detection via
    # _detect_ltspice_format, avoiding duplicated detection logic.
    with io.StringIO(data) as input_file:
        return decrypt_stream(input_file, is_ltspice_file=is_ltspice_file)
