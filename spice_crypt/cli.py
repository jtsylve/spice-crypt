#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: © 2025-2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Command-line interface for SpiceCrypt
"""

import argparse
import sys
import warnings
from pathlib import Path

from spice_crypt import __version__
from spice_crypt.decrypt import decrypt_stream


class _DeprecatedShortVersionAction(argparse.Action):
    """Handles deprecated ``-v`` flag for ``--version``."""

    def __init__(self, option_strings, version, **kwargs):
        kwargs.setdefault("nargs", 0)
        kwargs.setdefault("default", argparse.SUPPRESS)
        self.version = version
        super().__init__(option_strings=option_strings, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        if option_string == "-v":
            warnings.warn(
                "-v is deprecated for --version, use --version instead",
                DeprecationWarning,
                stacklevel=2,
            )
        print(self.version)
        parser.exit()


def _recover_key(args):
    """Run Mode 4 brute-force key recovery."""
    from spice_crypt.pspice.attack import recover_mode4_key

    try:
        if args.verbose:
            print("PSpice Mode 4 key recovery (Rust/AES-NI)", file=sys.stderr)

        result = recover_mode4_key(args.input_file)
    except FileNotFoundError:
        if not args.quiet:
            sys.stderr.write(f"Error: File not found: {args.input_file}\n")
        return 1
    except (ValueError, RuntimeError) as e:
        if not args.quiet:
            sys.stderr.write(f"Error: {e}\n")
        return 1

    print(f"User key: {result.user_key_full.decode('ascii', errors='replace')}")
    if args.verbose:
        print(f"Short key bytes (hex): {result.short_key_bytes.hex()}")
        print(f"User key short: {result.user_key_short.decode('ascii', errors='replace')}")
        print(f"User key extended: {result.user_key_extended.decode('ascii', errors='replace')}")

    return 0


def main():
    """Main entry point for the CLI."""
    parser = argparse.ArgumentParser(
        description="SpiceCrypt - A tool for decrypting LTspice® and PSpice® encrypted files"
    )
    parser.add_argument(
        "input_file",
        help="Path to the encrypted file to decrypt (LTspice encrypted format or raw hex)",
    )
    parser.add_argument("-o", "--output", help="Output file path (default: print to stdout)")
    parser.add_argument(
        "-f", "--force", action="store_true", help="Overwrite output file if it exists"
    )
    parser.add_argument(
        "-r",
        "--raw",
        action="store_true",
        help="Treat input as raw hex data instead of LTspice® format",
    )
    parser.add_argument(
        "-v",
        "--version",
        action=_DeprecatedShortVersionAction,
        version=f"SpiceCrypt {__version__}",
        help="Show program version and exit",
    )

    parser.add_argument(
        "--user-key",
        help="User key string for PSpice Mode 4 decryption (31-byte key from CSV file)",
    )
    parser.add_argument(
        "--recover-key",
        action="store_true",
        help="Recover the Mode 4 user encryption key via brute-force attack",
    )

    verbosity = parser.add_mutually_exclusive_group()
    verbosity.add_argument("--verbose", action="store_true", help="Display additional information")
    verbosity.add_argument("--quiet", action="store_true", help="Suppress all error messages")

    args = parser.parse_args()

    # Key recovery mode
    if args.recover_key:
        return _recover_key(args)

    # Check if output file exists and handle accordingly
    if args.output and Path(args.output).exists() and not args.force:
        if not args.quiet:
            sys.stderr.write(
                f"Error: Output file '{args.output}' already exists. Use --force to overwrite.\n"
            )
        return 1

    try:
        # Process with streaming API
        if args.verbose:
            if args.raw:
                print(f"Processing as raw hex data: {args.input_file}", file=sys.stderr)
            else:
                print(f"Processing file: {args.input_file}", file=sys.stderr)

        # Stream processing - much more memory efficient
        output_dest = (
            args.output
            if args.output
            else (sys.stdout.buffer if hasattr(sys.stdout, "buffer") else sys.stdout)
        )
        is_ltspice = False if args.raw else None
        user_key = args.user_key.encode("ascii") if args.user_key else None
        _, verification = decrypt_stream(
            args.input_file, output_dest, is_ltspice_file=is_ltspice, user_key=user_key
        )
        if args.verbose:
            if args.output:
                print(f"Decrypted content written to '{args.output}'", file=sys.stderr)
            print(f"Verification values: {verification}", file=sys.stderr)

    except FileNotFoundError:
        if not args.quiet:
            sys.stderr.write(f"Error: File not found: {args.input_file}\n")
        return 1
    except ValueError as e:
        if not args.quiet:
            sys.stderr.write(f"Error: {e}\n")
        return 1
    except Exception as e:
        if not args.quiet:
            sys.stderr.write(f"Error during decryption: {e}\n")
        return 1

    return 0


def main_deprecated():
    """Deprecated entry point. Use ``spice-crypt`` instead."""
    warnings.warn(
        "spice-decrypt is deprecated, use spice-crypt instead",
        DeprecationWarning,
        stacklevel=2,
    )
    return main()


if __name__ == "__main__":
    sys.exit(main())
