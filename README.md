# SpiceCrypt

A Python library and CLI tool for decrypting encrypted SPICE model files.  SpiceCrypt supports LTspice® and PSpice® encryption formats with automatic format detection, enabling engineers to use lawfully obtained models in any simulator.

## Features

- **LTspice text-based format** — Custom DES variant used in encrypted `.CIR`, `.SUB`, `.LIB`, `.ASY`, and other files
- **LTspice Binary File format** — Two-layer XOR stream cipher identified by the `<Binary File>` signature
- **PSpice Modes 0–5** — Custom DES (modes 0–2) and AES-256 ECB (modes 3–5) with `$CDNENCSTART`/`$CDNENCFINISH` delimited blocks
- **PSpice Mode 4 key recovery** — Brute-force recovery of the user-supplied encryption key via a hardware-accelerated Rust extension (AES-NI / ARM Crypto)
- **Automatic format detection** — All formats are detected and handled transparently
- **Streaming API** — Memory-efficient processing for large files
- **No runtime dependencies** — Pure Python with an optional compiled Rust extension for key recovery

## Installation

Install from [PyPI](https://pypi.org/project/spice-crypt/):

```bash
pip install spice-crypt
```

Or with [uv](https://docs.astral.sh/uv/):

```bash
uv tool install spice-crypt
```

Or add as a dependency to an existing project:

```bash
uv add spice-crypt
```

### Updating

```bash
pip install --upgrade spice-crypt    # pip
uv tool upgrade spice-crypt          # uv tool
uv lock --upgrade-package spice-crypt # uv project dependency
```

## Requirements

- Python 3.10 or higher
- No runtime dependencies for decryption
- Rust toolchain required only to build the optional extension for Mode 4 key recovery

## Command Line Usage

SpiceCrypt provides the `spice-crypt` command.  All encryption formats are auto-detected.

```bash
# Run directly without installing
uvx spice-crypt path/to/encrypted_file.lib

# Decrypt to stdout
spice-crypt path/to/encrypted_file.lib

# Decrypt to a file
spice-crypt -o output.lib path/to/encrypted_file.lib

# Force overwrite if output file exists
spice-crypt -f -o output.lib path/to/encrypted_file.lib

# Verbose output (shows verification values)
spice-crypt --verbose path/to/encrypted_file.lib

# Suppress all error messages
spice-crypt --quiet -o output.lib path/to/encrypted_file.lib

# Process raw hex data (bypass LTspice format detection)
spice-crypt --raw path/to/hex_file.txt

# Show version
spice-crypt --version
```

### PSpice Mode 4

Mode 4 is the only PSpice mode that uses a user-supplied encryption key.  SpiceCrypt can recover this key via brute force or decrypt directly if the key is known.

```bash
# Brute-force recover the user key (~seconds on modern hardware)
spice-crypt --recover-key path/to/encrypted_file.lib

# Decrypt with a known user key
spice-crypt --user-key KEY path/to/encrypted_file.lib
```

Key recovery exploits a bug in PSpice's key derivation that reduces the effective keyspace from 2^256 to 2^32.  See [SPECIFICATIONS/pspice-attack-summary.md](SPECIFICATIONS/pspice-attack-summary.md) for details.

## Python API

### `decrypt_stream(input_file, output_file=None, is_ltspice_file=None, user_key=None)`

Stream-decrypt from a file path or file object.  Supports all LTspice and PSpice formats with automatic detection.

```python
from spice_crypt import decrypt_stream

# Decrypt file to file
_, verification = decrypt_stream("encrypted.lib", "decrypted.lib")

# Decrypt file to string
plaintext, verification = decrypt_stream("encrypted.lib")

# Use file objects
with open("encrypted.lib") as infile:
    plaintext, verification = decrypt_stream(infile)

# PSpice Mode 4 with a user key
plaintext, _ = decrypt_stream("encrypted.lib", user_key=b"mykey")
```

**Parameters:**
- `input_file` — File path (str/PathLike) or file object (text or binary mode).
- `output_file` (optional) — File path (str) or binary-mode file object.  If `None`, returns decrypted content as a string.
- `is_ltspice_file` (bool, optional) — Whether the data is in LTspice format.  If `True`, skip PSpice detection; if `False`, treat as raw hex.  Auto-detected if `None`.
- `user_key` (bytes, optional) — User key bytes for PSpice Mode 4 decryption.

**Returns:** `(content, (v1, v2))` — `content` is the decrypted string if no output file was given, otherwise `None`.  `(v1, v2)` are format-specific verification values: CRC-based checksums for LTspice text format, CRC-32 and rotate-left hash for Binary File format, or `(0, 0)` for PSpice format.

### `decrypt(data, is_ltspice_file=None)`

Decrypt an in-memory string of encrypted data.  Supports LTspice text-based format, raw hex, and PSpice text-based formats (but not Binary File format or PSpice Mode 4 with a user key).

```python
from spice_crypt import decrypt

with open("encrypted.lib") as f:
    data = f.read()

plaintext, (v1, v2) = decrypt(data)
```

**Parameters:**
- `data` (str) — Encrypted data as a string (LTspice format, PSpice format, or raw hex).
- `is_ltspice_file` (bool, optional) — Whether the data is in LTspice format.  Auto-detected if `None`.

**Returns:** `(plaintext, (v1, v2))` — The decrypted text and a tuple of format-specific verification values (see `decrypt_stream` above).

### Lower-level APIs

The following classes are exported for direct use:

- `LTspiceFileParser` — Text-based DES format parser
- `BinaryFileParser` — Binary File format parser
- `PSpiceFileParser` — PSpice format parser (modes 0–5)
- `CryptoState` — LTspice DES key derivation and per-block decryption
- `LTspiceDES` — LTspice custom DES variant
- `PSpiceDES` — PSpice custom DES variant

## Supported Formats

### LTspice Text-Based DES

Encrypted files contain hex-encoded ciphertext delimited by `* Begin:` and `* End <v1> <v2>` comment markers.  The first 1024 bytes form a crypto table used for key derivation and as an XOR keystream source.  All subsequent blocks are decrypted with a custom DES variant that uses non-standard S-boxes and permutation tables, preceded by an XOR stream cipher layer keyed from the same table.

### LTspice Binary File

Binary files are identified by a 20-byte signature (`\r\n<Binary File>\r\n\r\n\x1a`).  Decrypted with a two-layer XOR stream cipher using two 32-bit keys from the file header and a 2593-byte substitution table with prime-based stepping.

### PSpice Modes 0–5

Encrypted regions are delimited by `$CDNENCSTART` / `$CDNENCFINISH` markers within otherwise plaintext files.  Six encryption modes exist:

| Mode | Cipher | Key Source |
|------|--------|------------|
| 0 | Custom DES | Hardcoded |
| 1–2 | Custom DES | Hardcoded + version |
| 3 | AES-256 ECB | Hardcoded + version |
| 4 | AES-256 ECB | Hardcoded XOR user key + version |
| 5 | AES-256 ECB | Hardcoded + version |

Modes 0–3 and 5 use key material derived entirely from constants in the PSpice binary.  Mode 4 incorporates a user-supplied key, but a bug in the key derivation passes only the short key to the AES engine instead of the extended key, leaving just 4 bytes unknown and reducing the effective keyspace to 2^32.  This makes the key recoverable by brute force.

## Specifications

Detailed technical documentation of the encryption schemes:

- [SPECIFICATIONS/ltspice.md](SPECIFICATIONS/ltspice.md) — LTspice encryption: key derivation, DES variant, stream cipher, and Binary File format
- [SPECIFICATIONS/pspice.md](SPECIFICATIONS/pspice.md) — PSpice encryption: modes 0–5, custom DES, AES-256 ECB, and key derivation
- [SPECIFICATIONS/pspice-attack-summary.md](SPECIFICATIONS/pspice-attack-summary.md) — PSpice Mode 4 key derivation bug and brute-force key recovery

## Purpose and Legal Basis

Many third-party component vendors distribute SPICE models exclusively as LTspice- or PSpice-encrypted files.  This encryption locks the models to a single simulator, preventing their use in open-source and alternative tools such as [NGSpice](https://ngspice.sourceforge.io/), [Xyce](https://xyce.sandia.gov/), [PySpice](https://github.com/PySpice-org/PySpice), and others.  SpiceCrypt exists to restore interoperability by allowing engineers to use lawfully obtained models in the simulator of their choice.

This type of reverse engineering for interoperability is specifically permitted by law:

- **United States**: [17 U.S.C. § 1201(f)](https://www.law.cornell.edu/uscode/text/17/1201) permits circumvention of technological protection measures for the sole purpose of achieving interoperability between independently created programs.  Section 1201(f)(2) explicitly allows distributing the tools developed for this purpose to others seeking interoperability.  Additionally, [§ 1201(g)](https://www.law.cornell.edu/uscode/text/17/1201) permits circumvention when conducted in good-faith encryption research — studying the flaws and vulnerabilities of encryption technologies — and allows dissemination of the research findings.
- **European Union**: [Article 6 of the Software Directive (2009/24/EC)](https://eur-lex.europa.eu/eli/dir/2009/24/oj) permits decompilation and reverse engineering when it is indispensable to achieve interoperability with independently created programs.  Article 6(3) provides that this right cannot be overridden by contract.

## Research Contributors

- **Joe T. Sylve, Ph.D.** — Reverse engineering and documentation of the LTspice text-based DES encryption format and PSpice encryption modes.
- **Lucas Gerads** — Reverse engineering and documentation of the LTspice Binary File encryption format.

## Trademarks

LTspice® is a registered trademark of Analog Devices, Inc.\
PSpice® is a registered trademark of Cadence Design Systems, Inc.

## License

This project is licensed under the [GNU Affero General Public License v3.0 or later](LICENSES/AGPL-3.0-or-later.txt).

Copyright (c) 2025-2026 Joe T. Sylve, Ph.D.
