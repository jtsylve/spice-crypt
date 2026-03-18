# SPDX-FileCopyrightText: © 2025-2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Top-level decryption dispatch.

This module provides the public :func:`decrypt` and :func:`decrypt_stream`
convenience functions which auto-detect the encryption format (LTspice
text-based, LTspice Binary File, or PSpice) and delegate to the
appropriate parser.
"""

import contextlib
import io
import os

from spice_crypt.ltspice.binary_file import BinaryFileParser
from spice_crypt.ltspice.decrypt import LTspiceFileParser, _detect_ltspice_format


def _try_binary_file(stream):
    """Peek at *stream* and return a :class:`BinaryFileParser` if it matches.

    Reads up to 20 bytes from the current position, checks for the Binary
    File signature, and seeks back.  Returns ``None`` when the signature
    does not match.
    """
    pos = stream.tell()
    header = stream.read(20)
    stream.seek(pos)
    if BinaryFileParser.check_signature(header):
        return BinaryFileParser(stream)
    return None


def _try_pspice_format(file_obj, user_key=None):
    """Peek at *file_obj* and return a :class:`PSpiceFileParser` if it matches.

    Scans up to 50 lines for PSpice markers, then resets the stream
    position.  Returns ``None`` when no PSpice markers are found.
    """
    pos = file_obj.tell()
    try:
        for i, line in enumerate(file_obj):
            if i >= 50:
                break
            stripped = (
                line.strip() if isinstance(line, str) else line.decode("utf-8", "replace").strip()
            )
            if stripped.startswith("$CDNENCSTART") or stripped.startswith("**$ENCRYPTED_LIB"):
                file_obj.seek(pos)
                from spice_crypt.pspice.decrypt import PSpiceFileParser

                return PSpiceFileParser(file_obj, user_key_bytes=user_key)
    except (OSError, UnicodeDecodeError):
        pass
    file_obj.seek(pos)
    return None


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
    input_file, output_file=None, is_ltspice_file=None, user_key=None
) -> tuple[str | None, tuple[int, int]]:
    """
    Stream decrypt data from input_file to output_file.

    Supports the text-based hex/DES format, the Binary File format
    (both LTspice), and PSpice encrypted formats.  When *is_ltspice_file*
    is ``None`` (the default), the format is auto-detected.

    Args:
        input_file: File object or path to read from
        output_file: File object or path to write to (if None, returns result as string)
        is_ltspice_file: Boolean indicating if file is in LTspice format
                         If None, auto-detect based on content
        user_key: Optional user key bytes for PSpice Mode 4 decryption

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
                parser = _try_binary_file(raw)
                if parser is not None:
                    return _run_decrypt_generator(parser.decrypt_stream(), output_file, stack)
                # Not a Binary File -- wrap the already-open handle as text
                # (_try_binary_file already restored the stream position)
                input_file = stack.enter_context(
                    io.TextIOWrapper(raw, encoding="utf-8", errors="replace")
                )
            else:
                input_file = stack.enter_context(open(input_file))

        # When given a seekable binary file object (not a path), check
        # for Binary File format before falling through to text-based
        # detection.  This ensures callers who pass an already-open
        # binary handle get correct auto-detection.
        elif (
            is_ltspice_file is not False
            and isinstance(input_file, io.RawIOBase | io.BufferedIOBase)
            and input_file.seekable()
        ):
            parser = _try_binary_file(input_file)
            if parser is not None:
                return _run_decrypt_generator(parser.decrypt_stream(), output_file, stack)
            # Not a Binary File -- wrap the binary handle as text so the
            # text-based detection and LTspiceFileParser receive strings.
            input_file = stack.enter_context(
                io.TextIOWrapper(input_file, encoding="utf-8", errors="replace")
            )

        # Try PSpice format detection (text-mode, seekable)
        if is_ltspice_file is None and hasattr(input_file, "seek"):
            parser = _try_pspice_format(input_file, user_key=user_key)
            if parser is not None:
                return _run_decrypt_generator(parser.decrypt_stream(), output_file, stack)

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
