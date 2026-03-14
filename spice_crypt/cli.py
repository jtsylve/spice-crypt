#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2025 Bayou Bits Technologies, LLC
# SPDX-FileCopyrightText: © 2025 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
# SPDX-FileCopyrightText: LicenseRef-Proprietary
#
# This source code is proprietary and confidential.  It is provided under the
# terms of a written license agreement between BAYOU BITS TECHNOLOGIES, LLC
# and the recipient.  Any unauthorized use, copying, modification, or
# distribution is strictly prohibited.
#
# Authorized representatives of the licensed recipient may request a copy of
# the written license agreement via email at joe.sylve@gmail.com.

"""
Command-line interface for SpiceCrypt
"""

import argparse
import sys
from pathlib import Path

from spice_crypt import __version__
from spice_crypt.decrypt import decrypt_stream


def main():
    """Main entry point for the CLI"""
    parser = argparse.ArgumentParser(
        description="SpiceCrypt - A tool for decrypting LTSpice encrypted files"
    )
    parser.add_argument(
        "input_file",
        help="Path to the encrypted file to decrypt (LTSpice .CIR/.SUB format or raw hex)",
    )
    parser.add_argument("-o", "--output", help="Output file path (default: print to stdout)")
    parser.add_argument(
        "-f", "--force", action="store_true", help="Overwrite output file if it exists"
    )
    parser.add_argument(
        "-r",
        "--raw",
        action="store_true",
        help="Treat input as raw hex data instead of LTSpice format",
    )
    parser.add_argument("-v", "--version", action="version", version=f"SpiceCrypt {__version__}")
    parser.add_argument("--verbose", action="store_true", help="Display additional information")

    args = parser.parse_args()

    # Check if output file exists and handle accordingly
    if args.output and Path(args.output).exists() and not args.force:
        sys.stderr.write(
            f"Error: Output file '{args.output}' already exists. Use --force to overwrite.\n"
        )
        return 1

    try:
        # Process with streaming API
        if args.verbose:
            input_path = Path(args.input_file)
            if input_path.suffix.lower() in (".cir", ".sub") and not args.raw:
                print(f"Processing LTSpice file: {args.input_file}", file=sys.stderr)
            elif args.raw:
                print(f"Processing as raw hex data: {args.input_file}", file=sys.stderr)

        # Stream processing - much more memory efficient
        output_dest = (
            args.output
            if args.output
            else (sys.stdout.buffer if hasattr(sys.stdout, "buffer") else sys.stdout)
        )
        _, verification = decrypt_stream(args.input_file, output_dest, is_ltspice_file=not args.raw)
        if args.verbose:
            if args.output:
                print(f"Decrypted content written to '{args.output}'", file=sys.stderr)
            print(f"Verification values: {verification}", file=sys.stderr)

    except FileNotFoundError:
        sys.stderr.write(f"Error: File not found: {args.input_file}\n")
        return 1
    except ValueError as e:
        sys.stderr.write(f"Error: {e}\n")
        return 1
    except Exception as e:
        sys.stderr.write(f"Error during decryption: {e}\n")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
