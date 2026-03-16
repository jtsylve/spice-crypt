# SpiceCrypt

A specialized Python library for decrypting LTspice® encrypted model files. It supports both the text-based format (`.CIR` / `.SUB` files using a modified DES variant) and the Binary File format (a two-layer XOR stream cipher), with automatic format detection.

## Installation

Install as a tool with [uv](https://docs.astral.sh/uv/):

```bash
uv tool install git+https://github.com/jtsylve/spice-crypt.git
```

Or add as a dependency to an existing project:

```bash
uv add git+https://github.com/jtsylve/spice-crypt.git
```

## Updating

Update an existing tool installation:

```bash
uv tool upgrade spice-crypt
```

Or update the dependency in a project:

```bash
uv lock --upgrade-package spice-crypt
```

## Requirements

- Python 3.10 or higher
- No external dependencies

## Command Line Usage

SpiceCrypt provides a `spice-crypt` command for decrypting LTspice encrypted files. The legacy `spice-decrypt` alias is deprecated and will be removed in a future release.

```bash
# Run directly without installing
uvx --from git+https://github.com/jtsylve/spice-crypt.git spice-crypt path/to/encrypted_file.CIR

# Or after installation, decrypt to stdout
spice-crypt path/to/encrypted_file.CIR

# Decrypt to a file
spice-crypt -o output.cir path/to/encrypted_file.CIR

# Force overwrite if output file exists
spice-crypt -f -o output.cir path/to/encrypted_file.CIR

# Decrypt with verbose output (shows verification values)
spice-crypt --verbose path/to/encrypted_file.CIR

# Process raw hex data (not LTspice format)
spice-crypt --raw path/to/hex_file.txt

# Show version
spice-crypt -v
```

## Python API

### `decrypt(data, is_ltspice_file=None)`

Decrypt an in-memory string of encrypted data.

```python
from spice_crypt import decrypt

with open("encrypted_file.CIR") as f:
    data = f.read()

plaintext, (v1, v2) = decrypt(data)
print(plaintext)
```

**Parameters:**
- `data` (str): Encrypted data as a string (LTspice format or raw hex).
- `is_ltspice_file` (bool, optional): Whether the data is in LTspice format. Auto-detected if `None`.

**Returns:** `(plaintext, (v1, v2))`: The decrypted text and a tuple of CRC-based verification values.

### `decrypt_stream(input_file, output_file=None, is_ltspice_file=None)`

Stream-decrypt from a file path or file object. Supports both the text-based hex/DES format and the Binary File format. When called with a file path, the format is auto-detected: files beginning with the Binary File signature are handled accordingly; otherwise the text-based LTspice format is assumed.

```python
from spice_crypt import decrypt_stream

# Decrypt file to file (format auto-detected)
_, verification = decrypt_stream("encrypted.CIR", "decrypted.cir")

# Decrypt file to string
plaintext, verification = decrypt_stream("encrypted.CIR")

# Use file objects directly
with open("encrypted.CIR") as infile:
    plaintext, verification = decrypt_stream(infile)
```

**Parameters:**
- `input_file`: File path (str/PathLike) or text-mode file object.
- `output_file` (optional): File path (str) or binary-mode file object. If `None`, returns decrypted content as a string.
- `is_ltspice_file` (bool, optional): Whether the input is in LTspice text format. Auto-detected if `None`.

**Returns:** `(content, (v1, v2))`: `content` is the decrypted string if no output file was given, otherwise `None`. `(v1, v2)` are verification values -- for the text-based format these are CRC-based checksums that should match the values on the file's `End` line; for the Binary File format they are a CRC-32 and rotate-left hash of the decrypted content.

## File Formats

SpiceCrypt supports two LTspice encryption formats, both auto-detected when decrypting:

### Text-Based DES Format

Encrypted files in this format contain hex-encoded ciphertext wrapped in comment headers:

```
* LTspice Encrypted File
*
* This encrypted file has been supplied by a 3rd
* party vendor that does not wish to publicize
* the technology used to implement this library.
*
* Permission is granted to use this file for
* simulations but not to reverse engineer its
* contents.
*
* [Header Comments]
*
* Begin:
  A7 CD 92 6F EA 22 42 3D 95 5E D2 59 B6 03 E5 31
  67 06 C2 AF 8A BB 32 98 00 15 89 AF C1 15 0C D9
  ...additional hex data...
* End 1032371916 1759126504
```

The first 128 eight-byte blocks (1024 bytes) form the crypto table. All subsequent blocks are ciphertext. The two integers on the `End` line are CRC-based checksums used to verify decryption integrity.

### Binary File Format

Encrypted files in this format are binary files identified by a 20-byte signature (`\r\n<Binary File>\r\n\r\n\x1a`). They use a two-layer XOR stream cipher unrelated to the DES-based scheme. The file header contains two 32-bit keys used to derive a substitution table index and step value for decryption.

## Specification

For a detailed technical description of the encryption scheme -- including the full key derivation process, pre-DES stream cipher layer, all deviations from standard DES, and the integrity verification mechanism: see [SPECIFICATION.md](SPECIFICATION.md).

## Purpose and Legal Basis

Many third-party component vendors distribute SPICE models exclusively as LTspice-encrypted files. This encryption locks the models to a single simulator, preventing their use in open-source and alternative tools such as [NGSpice](https://ngspice.sourceforge.io/), [Xyce](https://xyce.sandia.gov/), [PySpice](https://github.com/PySpice-org/PySpice), and others. SpiceCrypt exists to restore interoperability by allowing engineers to use lawfully obtained models in the simulator of their choice.

This type of reverse engineering for interoperability is specifically permitted by law:

- **United States**: [17 U.S.C. § 1201(f)](https://www.law.cornell.edu/uscode/text/17/1201) permits circumvention of technological protection measures for the sole purpose of achieving interoperability between independently created programs. Section 1201(f)(2) explicitly allows distributing the tools developed for this purpose to others seeking interoperability. Additionally, [§ 1201(g)](https://www.law.cornell.edu/uscode/text/17/1201) permits circumvention when conducted in good-faith encryption research — studying the flaws and vulnerabilities of encryption technologies — and allows dissemination of the research findings.
- **European Union**: [Article 6 of the Software Directive (2009/24/EC)](https://eur-lex.europa.eu/eli/dir/2009/24/oj) permits decompilation and reverse engineering when it is indispensable to achieve interoperability with independently created programs. Article 6(3) provides that this right cannot be overridden by contract.

## Research Contributors

- **Joe T. Sylve, Ph.D.** -- Reverse engineering and documentation of the text-based DES encryption format.
- **Lucas Gerads** -- Reverse engineering and documentation of the Binary File encryption format.

## Trademarks

LTspice® is a registered trademark of Analog Devices, Inc.

## License

This project is licensed under the [GNU Affero General Public License v3.0 or later](LICENSES/AGPL-3.0-or-later.txt).

Copyright (c) 2025-2026 Joe T. Sylve, Ph.D.
