## PSpice® Mode 4 Encryption Weakness

PSpice is a SPICE circuit simulator from Cadence Design Systems that encrypts proprietary semiconductor model files to protect vendor IP and prevent reuse in third-party SPICE simulators.  The encryption scheme is proprietary and undocumented.

PSpice supports six encryption modes (0–5).  Modes 0–3 and 5 derive all key material from constants hardcoded in the binary; once those constants are extracted, files in these modes can be decrypted directly.  Mode 4 is the only mode that incorporates user-supplied key material: vendors provide a key string via a CSV file referenced by the `CDN_PSPICE_ENCKEYS` environment variable.  This key is XOR'd with the hardcoded base keys during derivation, so decryption requires the same key file.  A bug in key derivation reduces the effective keyspace to 2^32, making the user key recoverable by brute force in seconds.

### The Bug

Mode 4 uses AES-256 in ECB mode.  Key derivation starts from two base strings:

- `g_desKey`: a 4-byte "short" base key (`"8gM2"`)
- `g_aesKey`: a 27-byte "extended" base key (`"H41Mlwqaspj1nxasyhq8530nh1r"`)

When a user provides a key via the `CDN_PSPICE_ENCKEYS` CSV file, user key bytes 0–3 are XOR'd into the short base, and bytes 4–30 are XOR'd into the extended base.  A version suffix (e.g., `"1002"`) is then appended to each base key.

`PSpiceAESEncoder_setKey` receives only the short key (`g_desKey`), not the extended key (`g_aesKey`).  The 32-byte AES-256 key is constructed by zero-padding this null-terminated string:

```
Byte  0–3:  XOR("8gM2", user_key[0:4])   -- unknown (4 bytes)
Byte  4–7:  "1002"                       -- version suffix (atoi(version_string) + 999)
Byte  8:    0x00 (null terminator)       -- known
Byte  9–31: 0x00 (zero padding)          -- known
```

`EncryptionContext_init` (`0x140008540`) calls `initEncryptionKeys` to derive both keys, then passes only `g_desKey` to the cipher engine via a vtable call at `0x14000871F`:

```
lea     rdx, g_desKey           ; 0x1400085F5 -- short key loaded as setKey argument
...
call    qword ptr [rax]         ; 0x14000871F -- vtable[0]: setKey(&g_desKey)
```

`PSpiceAESEncoder_setKey` (`0x140012E00`) copies this null-terminated string into a zero-filled 32-byte local buffer and calls `AES_keyExpansion(self+8, keyBuf, 256)`.  `g_desKey` in mode 4 is 8 characters (4 XOR'd bytes + `"1002"`) followed by a null terminator, so bytes 9–31 of the AES key are always zero.

Since 28 of 32 key bytes are known, the effective keyspace shrinks from 2^256 to 2^32.

### Brute-Force Attack

The first encrypted block after every `$CDNENCSTART` marker is a metadata header whose plaintext always begins with the fixed prefix `"0001.0000 "` (10 ASCII bytes).  This prefix falls entirely within the first 16-byte AES sub-block, providing a known-plaintext crib for validating candidate keys.

The attack:

1. Take the first 16 bytes of the header ciphertext block.
2. For each of the 2^32 candidate 4-byte values, construct the full 32-byte key (4 candidate bytes + known suffix + zeros) and decrypt the sub-block.
3. If the first 10 bytes of the decrypted sub-block equal `"0001.0000 "`, the candidate is correct.

Exhaustive search takes seconds with AES-NI, or under 1 second on a GPU.

### Full User Key Recovery

Once the 4-byte brute-force attack succeeds, the full user key is recoverable.  The metadata header's plaintext contains the derived `g_aesKey`: the extended base XOR'd with user key bytes, with the version suffix appended.

1. **Short user key** (bytes 0–3): XOR the recovered 4 bytes with the known base `"8gM2"`.

2. **Extended user key** (bytes 4–30): Decrypt the metadata header with the recovered AES key.  The embedded `g_aesKey` equals `XOR("H41Mlwqaspj1nxasyhq8530nh1r", user_key[4:31]) + "1002"`.  Strip the version suffix and XOR with the known base to recover the remaining 27 user key bytes.

The entire user key string from the CSV file is now known, and all files encrypted with that key are compromised.

### Root Cause

The names `g_desKey` and `g_aesKey` are reverse-engineered labels, not original source names.  The key sizes suggest the extended key was intended for AES and the short key for DES.  The short key is 8 bytes after derivation, matching a DES key size.  The extended key is 31 bytes plus a null terminator to fill 32 bytes, which is likely an off-by-one error since AES-256 requires 32 bytes of key material.  Passing the short key to the AES engine appears to be a copy-paste error from the DES code path.  Had the extended key been used, the effective keyspace would be 2^216, making a brute-force attack infeasible.

AES-256 encryption support was introduced in PSpice 16.6 (April 2014), alongside the existing DES-based modes.  The bug has presumably been present since that release.  Fixing it now would break compatibility with every encrypted model created in the twelve years since its introduction.

---
PSpice is a trademark of Cadence Design Systems, Inc.
