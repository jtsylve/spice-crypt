# LTspice® Encryption Specification

**Version**: 1.0.0
**Author**: Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
**Repository**: https://github.com/jtsylve/spice-crypt

This document describes the encryption scheme used by LTspice to protect proprietary circuit model files (`.CIR` / `.SUB`). The scheme is built on a modified variant of the Data Encryption Standard (DES), combined with a pre-DES stream cipher layer and a custom key derivation process. Each deviation from standard DES is explicitly noted.

A reference implementation of this specification is available as [SpiceCrypt](https://github.com/jtsylve/spice-crypt), a command-line tool and Python library licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later).

## Purpose

Many third-party component vendors distribute SPICE simulation models exclusively as LTspice-encrypted files. This encryption locks the models to a single proprietary simulator, preventing their use in open-source and alternative tools such as NGSpice, Xyce, PySpice, and others.

This specification is published in service of two goals:

- **Interoperability**: Documenting the encryption scheme allows developers of alternative SPICE simulators to support lawfully obtained encrypted models, restoring the user's ability to choose their tools. The accompanying [SpiceCrypt](README.md) reference implementation demonstrates a working decryption based on this specification.
- **Encryption research**: The scheme is a textbook case of security through obscurity -- the key material is stored in the clear alongside the ciphertext, and the algorithm's modifications to DES do not add cryptographic strength (see [Section 8](#8-security-assessment)). Documenting these properties contributes to the broader understanding of how proprietary encryption schemes deviate from established standards and where they fall short.

Both activities are specifically permitted by law:

- **United States** -- [17 U.S.C. § 1201(f)](https://www.law.cornell.edu/uscode/text/17/1201) permits circumvention of technological protection measures for the purpose of achieving interoperability between independently created programs, and Section 1201(f)(2) explicitly allows distributing the tools developed for this purpose. [§ 1201(g)](https://www.law.cornell.edu/uscode/text/17/1201) further permits circumvention conducted in good-faith encryption research and allows dissemination of the findings.
- **European Union** -- [Article 6 of the Software Directive (2009/24/EC)](https://eur-lex.europa.eu/eli/dir/2009/24/oj) permits decompilation and reverse engineering when indispensable to achieve interoperability with independently created programs. Article 6(3) provides that this right cannot be overridden by contract.

## 1. Encrypted File Format

An LTspice encrypted file is a plain-text file with the following structure:

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
* [Header comments...]
*
* Begin:
  A7 CD 92 6F EA 22 42 3D 95 5E D2 59 B6 03 E5 31
  67 06 C2 AF 8A BB 32 98 00 15 89 AF C1 15 0C D9
  ... more hex data ...
* End <v1> <v2>
```

**Header**: Lines beginning with `*` before the `* Begin:` marker are comments and are ignored during decryption. The `* Begin:` marker is matched case-insensitively.

**Hex payload**: After the `* Begin:` marker, the file contains space-separated hexadecimal byte values. Each pair of hex characters represents one byte. Whitespace (spaces and newlines) separates individual byte values. Lines beginning with `*` within the payload are comments and are skipped.

**Payload structure**: The hex payload is consumed as a flat stream of bytes, grouped into 8-byte (64-bit) blocks:

| Block range  | Count     | Purpose                                |
|-------------|-----------|----------------------------------------|
| 0 -- 127    | 128 blocks (1024 bytes) | Crypto table (key material)   |
| 128+        | Variable  | Ciphertext blocks                      |

If the final ciphertext block contains fewer than 8 bytes, it is zero-padded on the right.

**End line**: The `* End` line contains two unsigned 32-bit decimal integers, `v1` and `v2`, which are CRC-32-based verification checksums (see [Section 6](#6-integrity-verification)).

## 2. Key Derivation

The 64-bit DES key and the initial stream cipher state are derived entirely from the 1024-byte crypto table (the first 128 blocks of the payload).

### 2.1 Byte Checksums (Stream Cipher Seeds)

The table bytes are split by parity of their index position. Two 8-bit checksums are computed:

```
even_byte_sum = (table[0] + table[2] + table[4] + ... + table[1022]) mod 256
odd_byte_sum  = (table[1] + table[3] + table[5] + ... + table[1023]) mod 256
```

These are then XOR'd with fixed constants to produce the initial stream cipher state values:

```
odd_byte_checksum  = odd_byte_sum  XOR 0x54
even_byte_checksum = even_byte_sum XOR 0xE7
```

The `even_byte_checksum` acts as a fixed increment and `odd_byte_checksum` acts as a running accumulator in the stream cipher (see [Section 3](#3-pre-des-stream-cipher-layer)).

### 2.2 DES Key Construction

The table is also processed at the 64-bit (qword) level. It is treated as 64 groups of 16 bytes (two little-endian 64-bit words per group). The even-offset and odd-offset qwords are accumulated separately:

```
qword_sum_even = 0
qword_sum_odd  = 0

for i in range(0, 1024, 16):
    qword_sum_even += uint64_le(table[i   : i+8])
    qword_sum_odd  += uint64_le(table[i+8 : i+16])

# All arithmetic is mod 2^64
combined = (qword_sum_even + qword_sum_odd) mod 2^64
```

Two 16-bit words are extracted from the combined sum:

```
qword_low_word  = combined & 0xFFFF           # bits [15:0]
qword_high_word = (combined >> 32) & 0xFFFF   # bits [47:32]
```

These are XOR'd with 32-bit constants and combined into the 64-bit DES key:

```
key_low  = qword_low_word  XOR 0x66E22120
key_high = qword_high_word XOR 0x20E905C8
key      = (key_high << 32) | key_low
```

> **Note on key entropy**: Although the key is 64 bits wide, it is derived from only two independent 16-bit values (extracted from bits [15:0] and [47:32] of the combined qword sum). Bits [31:16] and [63:48] of each key half are entirely determined by the fixed XOR constants. The effective key entropy is therefore at most 32 bits, significantly less than the 56-bit effective key size of standard DES.

### 2.3 Unused Intermediate Passes

The original LTspice binary contains two additional passes over the crypto table whose results are computed but never used:

- **Pass 2 (byte-group sums)**: The table is treated as 256 groups of 4 bytes. Four positional accumulators sum the bytes at each offset within the groups, and the totals are added together. The result is discarded.
- **Pass 3 (word-group sums)**: The table is treated as 128 groups of 8 bytes (four little-endian 16-bit words per group). Four positional accumulators sum the words at each offset, and the totals are added together. The result is discarded.

These may be vestiges of a previous version of the algorithm or placeholders for future use.

## 3. Pre-DES Stream Cipher Layer

Before each 8-byte ciphertext block is passed to the DES decryption function, a stream cipher layer XORs each byte of the block with a byte selected from the crypto table. This layer uses two state variables, `odd_byte_checksum` and `even_byte_checksum`, initialized during key derivation ([Section 2.1](#21-byte-checksums-stream-cipher-seeds)).

For each byte `i` (0 through 7) within a block:

```
odd_byte_checksum = (odd_byte_checksum + even_byte_checksum) mod 2^32
table_index       = (odd_byte_checksum mod 0x3FD) + 1
block[i]         ^= crypto_table[table_index]
```

Key observations:

- **`even_byte_checksum` is constant** -- it is set once during key derivation and never modified. It serves as a fixed additive step.
- **`odd_byte_checksum` is a running accumulator** -- it advances by `even_byte_checksum` for every byte processed across all blocks. Its arithmetic is mod 2^32 (it is promoted from its initial 8-bit value to a 32-bit accumulator on the first addition).
- **Table index range**: The modulus `0x3FD` (1021) combined with the `+1` offset produces indices in the range [1, 1021]. Index 0 is never used.
- **State carries across blocks** -- the checksum state is not reset between blocks, making this a proper stream cipher where the keystream depends on the block position.

After the XOR pass, the modified 8-byte block is interpreted as a little-endian 64-bit integer and passed to the DES decryption function.

## 4. DES Variant: Deviations from FIPS 46-3

The core block cipher is a 16-round Feistel network structurally similar to DES (FIPS 46-3), using the same permutation tables (IP, IP^-1, E, P, PC-1, PC-2) and S-boxes. However, the LTspice implementation introduces several deviations from the standard.

### 4.1 Pre-Permutation Half-Swap (Input Block)

**Standard DES**: The 64-bit plaintext/ciphertext block is passed directly to the Initial Permutation (IP).

**LTspice variant**: Before applying IP, the lower 32 bits and upper 32 bits of the input block are swapped:

```
swapped = (input >> 32) | ((input & 0xFFFFFFFF) << 32)
permuted = IP(swapped)
```

This means the DES round function operates on bit-transposed data relative to what standard DES would process given the same input.

### 4.2 Pre-PC-1 Half-Swap (Key Schedule)

**Standard DES**: The 64-bit key is passed directly to Permuted Choice 1 (PC-1) to extract the 56-bit key material.

**LTspice variant**: Before applying PC-1, the same lower/upper 32-bit half-swap is applied to the key:

```
swapped_key = (key >> 32) | ((key & 0xFFFFFFFF) << 32)
reduced_key = PC1(swapped_key)
```

This effectively remaps which key bits feed into which positions of the 56-bit reduced key.

### 4.3 Reversed Key Rotation Direction

**Standard DES**: During key schedule generation, the two 28-bit halves of the reduced key (C and D) are **left-rotated** by the amounts specified in the rotation table: `[1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]`.

**LTspice variant**: The two 28-bit halves are **right-rotated** by the same amounts.

```
# Standard DES (left rotate):
lower = ((lower << count) | (lower >> (28 - count))) & 0x0FFFFFFF

# LTspice variant (right rotate):
lower = ((lower >> count) | (lower << (28 - count))) & 0x0FFFFFFF
```

This produces an entirely different set of 16 round subkeys from the same starting key material.

### 4.4 Output Truncation

**Standard DES**: After the final permutation (IP^-1), the full 64-bit result is returned as the ciphertext/plaintext block.

**LTspice variant**: Only the low 32 bits of the IP^-1 output are retained. The upper 32 bits are discarded:

```
result = FP(combined) & 0xFFFFFFFF   # only low 32 bits
```

This is a critical difference: each 64-bit ciphertext block decrypts to only a 32-bit (4-byte) plaintext block, halving the output size relative to the input.

### 4.5 Summary of Unmodified DES Components

The following components are identical to standard DES:

| Component | Description |
|-----------|-------------|
| Initial Permutation (IP) | Standard 64-bit IP table |
| Final Permutation (IP^-1) | Standard 64-bit FP table |
| Expansion (E) | Standard 32-to-48-bit expansion |
| S-boxes (S1--S8) | Standard 8 S-boxes, 6-bit input to 4-bit output |
| P-box (P) | Standard 32-bit permutation |
| PC-1 | Standard 64-to-56-bit permuted choice |
| PC-2 | Standard 56-to-48-bit permuted choice |
| Rotation schedule | Same counts: [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1] |
| Feistel structure | Standard 16-round Feistel network |
| Decrypt mode | Standard subkey reversal (use subkeys 15..0) |

### 4.6 Combined Effect

The half-swaps (Sections 4.1 and 4.2) and the reversed rotation (Section 4.3) together mean that even with the same key and plaintext, the LTspice variant produces completely different round computations and outputs compared to standard DES. These modifications are not equivalent to any simple re-keying or re-ordering of the standard algorithm. The output truncation (Section 4.4) further means the cipher has fundamentally different input/output dimensions: 64 bits in, 32 bits out -- making it a one-way compression function rather than a bijective block cipher.

## 5. Block Decryption Pipeline

For each 8-byte ciphertext block (blocks 128 onward), the full decryption pipeline is:

```
1. Read 8 bytes of ciphertext from the hex payload.
2. Apply the pre-DES stream cipher:
   For each byte i = 0..7:
     a. odd_byte_checksum += even_byte_checksum  (mod 2^32)
     b. table_index = (odd_byte_checksum mod 0x3FD) + 1
     c. block[i] ^= crypto_table[table_index]
3. Interpret the 8-byte modified block as a little-endian uint64.
4. Apply the LTspice DES variant in decrypt mode:
     a. Swap the low and high 32-bit halves of the input.
     b. Apply the Initial Permutation (IP).
     c. Split into left (L) and right (R) 32-bit halves.
     d. For 16 rounds (using subkeys in reverse order 15..0):
        - new_R = L XOR F(R, subkey[round])
        - new_L = R
     e. Combine: (L << 32) | R
     f. Apply the Final Permutation (IP^-1).
     g. Mask to 32 bits (discard upper half).
5. Output the 32-bit result as 4 little-endian bytes of plaintext.
```

The plaintext output is therefore half the size of the ciphertext input (4 bytes out per 8 bytes in, excluding the 1024-byte crypto table).

## 6. Integrity Verification

Two CRC-32 checksums are maintained incrementally during decryption:

- **`plaintext_crc`**: CRC-32 of all decrypted 4-byte output blocks, computed sequentially.
- **`ciphertext_crc`**: CRC-32 of all 8-byte ciphertext blocks (after block 127), computed sequentially.

After all blocks are processed, two verification values are derived:

```
table_word_44 = uint32_le(crypto_table[0x44 : 0x48])
table_word_94 = uint32_le(crypto_table[0x94 : 0x98])

v1 = plaintext_crc  XOR 0x7A6D2C3A XOR table_word_44
v2 = ciphertext_crc XOR 0x4DA77FD3 XOR table_word_94
```

These values are compared against the two integers on the `* End` line of the file. A mismatch indicates data corruption or an incorrect decryption implementation.

## 7. S-Box Layout

The S-box data is stored in a flat array with 1-based indexing (index 0 is padding). Each S-box maps a 6-bit input to a 4-bit output. The 6-bit input is decomposed as:

```
row    = (bit5 << 0) | (bit0 << 1)                           # 2 bits from MSB and LSB
column = (bit1 << 3) | (bit2 << 2) | (bit3 << 1) | bit4     # 4 bits from middle, reversed
```

> Note: Both the row and column bit orderings are reversed compared to standard DES. In standard DES, row = {bit5, bit0} (bit5 as MSB) and column = {bit4, bit3, bit2, bit1} (bit4 as MSB). In this implementation, bit0 is the MSB of row and bit1 is the MSB of column. The interleaved S-box storage and bit-transform together compensate for this, producing the same net substitution values as standard DES S-boxes.

The S-box value is looked up at flat-array offset:

```
offset = (36 * column) + (9 * row) + sbox_index + 1
```

where `sbox_index` ranges from 0 to 7. This interleaved storage format differs from the conventional per-S-box matrix layout in DES literature, but produces the same mapping.

After lookup, the 4-bit S-box output is passed through a bit-transform table that reverses the bit order:

```
DES_BIT_TRANSFORM[n]:
  0→0, 1→8, 2→4, 3→C, 4→2, 5→A, 6→6, 7→E,
  8→1, 9→9, A→5, B→D, C→3, D→B, E→7, F→F
```

This is equivalent to reflecting bits [3:0] to [0:3] (i.e., bit-reversal within the nibble). This transform is folded into the S-box output as part of the implementation, but the net result of S-box + transform produces the same 4-bit substitution values as standard DES S-boxes -- the transform compensates for the interleaved storage format.

## 8. Security Assessment

From a cryptographic perspective, this scheme has several notable properties:

- **Low effective key entropy**: The DES key is derived from only 32 bits of independent data (two 16-bit words extracted from the crypto table checksum). This is well below the 56-bit effective key size of standard DES and far below modern standards.
- **Static key material in cleartext**: The entire 1024-byte crypto table from which the key is derived is stored in the clear as the first 128 blocks of the payload. Anyone with knowledge of the key derivation algorithm can compute the key.
- **Deterministic stream cipher**: The pre-DES XOR layer's keystream is fully determined by the crypto table, which is public. It adds no additional security beyond the DES layer.
- **Obfuscation, not encryption**: The security of this scheme relies entirely on secrecy of the algorithm (security through obscurity) rather than secrecy of the key. Once the algorithm is known, any encrypted file can be decrypted without any secret.

---

LTspice® is a registered trademark of Analog Devices, Inc.

## License

Copyright © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>

This document is licensed under the [Creative Commons Attribution 4.0 International License](https://creativecommons.org/licenses/by/4.0/) (CC-BY-4.0). You are free to share and adapt this material for any purpose, including commercial use, provided appropriate credit is given.
