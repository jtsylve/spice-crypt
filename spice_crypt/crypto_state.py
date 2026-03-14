# SPDX-FileCopyrightText: © 2025 Bayou Bits Technologies, LLC
# SPDX-FileCopyrightText: © 2025 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
# SPDX-License-Identifier: LicenseRef-Proprietary
#
# This source code is proprietary and confidential.  It is provided under the
# terms of a written license agreement between BAYOU BITS TECHNOLOGIES, LLC
# and the recipient.  Any unauthorized use, copying, modification, or
# distribution is strictly prohibited.
#
# Authorized representatives of the licensed recipient may request a copy of
# the written license agreement via email at joe.sylve@gmail.com.

from spice_crypt.des import LTSpiceDES

# Masks for wrapping arithmetic to fixed-width unsigned integers
_MASK32 = 0xFFFFFFFF
_MASK64 = 0xFFFFFFFFFFFFFFFF


class CryptoState:
    def __init__(self, table: bytes):
        if len(table) != 1024:
            raise ValueError("crypto table must be exactly 1024 bytes")

        self.crypto_table = table
        self.DES = LTSpiceDES()
        self.reset()

    def reset(self):
        """
        Initializes the cryptographic state using the predefined 1024-byte table.
        """
        table = self.crypto_table

        # Pass 1: Compute checksums over even-indexed and odd-indexed bytes.
        # Only the low 8 bits of each sum are kept.
        even_byte_sum = 0
        odd_byte_sum = 0
        for i in range(0, 1024, 2):
            even_byte_sum += table[i]
            odd_byte_sum += table[i + 1]
        even_byte_sum &= 0xFF
        odd_byte_sum &= 0xFF

        # Pass 2: Sum bytes by their position in 4-byte chunks.
        # The table is treated as 256 groups of 4 bytes.  Each of the 4
        # positional accumulators receives bytes at the same offset within
        # every group, and the totals are then summed together.
        # (present in the original binary but the results are unused)
        # byte_group_sums = [0] * 4
        # for i in range(0, 1024, 4):
        #     for j in range(4):
        #         byte_group_sums[j] = (byte_group_sums[j] + table[i + j]) & _MASK32
        # byte_sum_result = sum(byte_group_sums) & _MASK32

        # Pass 3: Sum 16-bit little-endian words by their position in
        # 4-word (8-byte) chunks.  Same idea as Pass 2 but operating on
        # 16-bit units instead of bytes.
        # (present in the original binary but the results are unused)
        # word_group_sums = [0] * 4
        # for i in range(0, 1024, 8):
        #     for j in range(4):
        #         word_group_sums[j] = (
        #             word_group_sums[j]
        #             + int.from_bytes(table[i + j * 2 : i + j * 2 + 2], "little")
        #         ) & _MASK32
        # word_sum_result = sum(word_group_sums) & _MASK32

        # Pass 4: Sum 64-bit little-endian qwords in 2-qword (16-byte)
        # chunks.  The table is treated as 64 groups of two qwords.
        # Even-offset (0) and odd-offset (8) qwords are accumulated
        # separately, then added together.
        qword_sum_even = 0  # accumulator for qwords at offset 0 in each group
        qword_sum_odd = 0  # accumulator for qwords at offset 8 in each group
        for i in range(0, 1024, 16):
            qword_sum_even += int.from_bytes(table[i : i + 8], "little")
            qword_sum_odd += int.from_bytes(table[i + 8 : i + 16], "little")
        qword_sum_even &= _MASK64
        qword_sum_odd &= _MASK64

        # Combine the two qword accumulators and extract the 16-bit words
        # that will feed into the DES key: bits [15:0] and bits [47:32].
        combined_qword = (qword_sum_even + qword_sum_odd) & _MASK64
        qword_low_word = combined_qword & 0xFFFF
        qword_high_word = (combined_qword >> 32) & 0xFFFF

        # Final XOR transformation to produce the crypto state.
        # The checksums are XOR'd with fixed constants and the two 16-bit
        # qword-derived words are XOR'd with 32-bit constants to form the
        # 64-bit DES key.
        self.odd_byte_checksum = odd_byte_sum ^ 0x54
        self.even_byte_checksum = even_byte_sum ^ 0xE7
        key_low = (qword_low_word ^ 0x66E22120) & _MASK32
        key_high = (qword_high_word ^ 0x20E905C8) & _MASK32
        self.key_value = (key_high << 32) | key_low

    def decrypt_block(self, data: bytes):
        """
        Decrypts a block of data using the cryptographic state and table.

        Args:
            data: 8-byte block to decrypt

        Returns:
            32-bit decrypted result
        """
        if len(data) != 8:
            raise ValueError("Data block must be 8 bytes")

        crypto_table = self.crypto_table
        data_copy = bytearray(data)

        # For each byte in the block, advance the checksum state and XOR
        # the ciphertext byte with a table byte selected by the running
        # checksum.  This acts as a pre-DES stream-cipher layer.
        for i in range(8):
            # Advance the odd checksum by adding the even checksum (mod 2^32)
            self.odd_byte_checksum = (self.odd_byte_checksum + self.even_byte_checksum) & _MASK32

            # Use the checksum to pick an index into the crypto table
            # (range 1..0x3fd, i.e. avoiding the first byte)
            table_index = (self.odd_byte_checksum % 0x3FD) + 1

            # XOR the ciphertext byte with the selected table byte
            data_copy[i] ^= crypto_table[table_index]

        # Decrypt the XOR'd block with the DES variant (little-endian
        # 64-bit input, returns the low 32-bit result)
        return self.DES.crypt(int.from_bytes(data_copy, "little"), self.key_value, True)
