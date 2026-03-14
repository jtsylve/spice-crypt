# SpiceCrypt

A specialized Python library for decrypting LTSpice encrypted model files (`.CIR` / `.SUB` formats). It implements a variant of the DES encryption algorithm with custom modifications used by LTSpice for protecting proprietary circuit models.

## Installation

```bash
pip install spice-crypt
```

Or install from source:

```bash
git clone https://github.com/bayou-bits/spice-crypt.git
cd spice-crypt
pip install -e .
```

## Requirements

- Python 3.6 or higher
- No external dependencies

## Command Line Usage

SpiceCrypt provides a `spice-decrypt` command for decrypting LTSpice encrypted files:

```bash
# Decrypt to stdout
spice-decrypt path/to/encrypted_file.CIR

# Decrypt to a file
spice-decrypt -o output.cir path/to/encrypted_file.CIR

# Force overwrite if output file exists
spice-decrypt -f -o output.cir path/to/encrypted_file.CIR

# Decrypt with verbose output (shows verification values)
spice-decrypt --verbose path/to/encrypted_file.CIR

# Process raw hex data (not LTSpice format)
spice-decrypt --raw path/to/hex_file.txt

# Show version
spice-decrypt -v
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
- `data` (str) -- Encrypted data as a string (LTSpice format or raw hex).
- `is_ltspice_file` (bool, optional) -- Whether the data is in LTSpice format. Auto-detected if `None`.

**Returns:** `(plaintext, (v1, v2))` -- The decrypted text and a tuple of CRC-based verification values.

### `decrypt_stream(input_file, output_file=None, is_ltspice_file=None)`

Stream-decrypt from a file path or file object. Memory-efficient for large files.

```python
from spice_crypt import decrypt_stream

# Decrypt file to file
_, verification = decrypt_stream("encrypted.CIR", "decrypted.cir")

# Decrypt file to string
plaintext, verification = decrypt_stream("encrypted.CIR")

# Use file objects directly
with open("encrypted.CIR") as infile:
    plaintext, verification = decrypt_stream(infile)
```

**Parameters:**
- `input_file` -- File path (str/PathLike) or text-mode file object.
- `output_file` (optional) -- File path (str) or binary-mode file object. If `None`, returns decrypted content as a string.
- `is_ltspice_file` (bool, optional) -- Whether the input is in LTSpice format. Auto-detected if `None`.

**Returns:** `(content, (v1, v2))` -- `content` is the decrypted string if no output file was given, otherwise `None`. `(v1, v2)` are CRC-based verification values that should match the checksums in the file's `End` line.

## File Format

SpiceCrypt supports standard LTSpice encrypted files which have this structure:

```
* LTspice Encrypted File
*
* This encrypted file has been supplied by a 3rd
* party vendor that does not wish to publicize
* the technology used to implement this library.
*
* Begin:
  A7 CD 92 6F EA 22 42 3D 95 5E D2 59 B6 03 E5 31
  67 06 C2 AF 8A BB 32 98 00 15 89 AF C1 15 0C D9
  ...additional hex data...
* End 1032371916 1759126504
```

The first 128 eight-byte blocks (1024 bytes) form the crypto table. All subsequent blocks are ciphertext. The two integers on the `End` line are CRC-based checksums used to verify decryption integrity.

## License

This source code is proprietary and confidential. It is provided under the terms of a written license agreement between BAYOU BITS TECHNOLOGIES, LLC and the recipient. Any unauthorized use, copying, modification, or distribution is strictly prohibited.

Contact joe.sylve@gmail.com for licensing information.