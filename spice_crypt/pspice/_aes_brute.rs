// SPDX-FileCopyrightText: © 2025-2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! AES-256 ECB brute-force key search for PSpice Mode 4.
//!
//! Exploits the fact that only 4 of 32 AES key bytes are unknown (2^32
//! keyspace).  A custom unrolled key schedule uses software S-box
//! lookups and elides zero-valued key words, while decrypt rounds use
//! hardware intrinsics where available.  Rayon parallelises across all
//! CPU cores; `cpufeatures` provides runtime detection on platforms
//! where hardware AES may or may not be present.
//!
//! # Backend selection
//!
//! | Platform | Compile-time feature | Backend |
//! |---|---|---|
//! | aarch64-apple-darwin | `target_feature="aes"` (default) | ARM Crypto — inlined |
//! | aarch64-unknown-linux-gnu | runtime `cpufeatures` check | ARM Crypto — not inlined |
//! | x86_64 with `-C target-feature=+aes` | `target_feature="aes"` | AES-NI — inlined |
//! | x86_64 default | runtime `cpufeatures` check | AES-NI — not inlined |
//! | Everything else | — | Software fallback |

use pyo3::prelude::*;
use rayon::prelude::*;

// -----------------------------------------------------------------------
// AES constants
// -----------------------------------------------------------------------

/// Standard AES forward S-box (FIPS 197).
#[rustfmt::skip]
static SBOX: [u8; 256] = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
];

/// Standard AES inverse S-box (FIPS 197).
#[rustfmt::skip]
static INV_SBOX: [u8; 256] = [
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d,
];

static RCON: [u32; 7] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40];

// -----------------------------------------------------------------------
// Key schedule (shared across all backends)
// -----------------------------------------------------------------------

/// Apply the AES S-box to each byte of a 32-bit word.
#[inline(always)]
fn sub_word(w: u32) -> u32 {
    let b = w.to_le_bytes();
    u32::from_le_bytes([
        SBOX[b[0] as usize],
        SBOX[b[1] as usize],
        SBOX[b[2] as usize],
        SBOX[b[3] as usize],
    ])
}

/// RotWord then SubWord — the combined operation at every 8th key word.
#[inline(always)]
fn sub_rot_word(w: u32) -> u32 {
    sub_word(w.rotate_right(8))
}

/// AES-256 key expansion optimised for keys where W2-W7 are all zero.
///
/// Only W0 (the candidate) and W1 (the version suffix) are non-zero.
/// The first two epochs are fully unrolled with zero elisions; the
/// remaining epochs use the standard recurrence.
#[inline(always)]
fn key_schedule(candidate: u32, w1: u32, c8: u32) -> [u32; 60] {
    let mut w = [0u32; 60];
    w[0] = candidate;
    w[1] = w1;

    // Epoch 0 (W8-W15): W2-W7 = 0 ⇒ W10 = W11 = W9, W12-W15 = S1
    let w8 = candidate ^ c8;
    let w9 = w1 ^ w8;
    w[8] = w8;
    w[9] = w9;
    w[10] = w9;
    w[11] = w9;
    let s1 = sub_word(w9);
    w[12] = s1;
    w[13] = s1;
    w[14] = s1;
    w[15] = s1;

    // Epoch 1 (W16-W23): still benefits from W2-W7 = 0 simplifications
    let t = sub_rot_word(s1) ^ RCON[1];
    w[16] = w8 ^ t;
    w[17] = w9 ^ w[16];
    w[18] = w9 ^ w[17];
    w[19] = w9 ^ w[18];
    let s2 = sub_word(w[19]);
    w[20] = s1 ^ s2;
    w[21] = s1 ^ w[20];
    w[22] = s1 ^ w[21];
    w[23] = s1 ^ w[22];

    // Epochs 2-4 (W24-W55): standard AES-256 recurrence
    let mut i = 24;
    let mut rc = 2;
    while i < 56 {
        let t = sub_rot_word(w[i - 1]) ^ RCON[rc];
        w[i] = w[i - 8] ^ t;
        w[i + 1] = w[i - 7] ^ w[i];
        w[i + 2] = w[i - 6] ^ w[i + 1];
        w[i + 3] = w[i - 5] ^ w[i + 2];
        let s = sub_word(w[i + 3]);
        w[i + 4] = w[i - 4] ^ s;
        w[i + 5] = w[i - 3] ^ w[i + 4];
        w[i + 6] = w[i - 2] ^ w[i + 5];
        w[i + 7] = w[i - 1] ^ w[i + 6];
        i += 8;
        rc += 1;
    }

    // Final half-epoch (W56-W59)
    let t = sub_rot_word(w[55]) ^ RCON[rc];
    w[56] = w[48] ^ t;
    w[57] = w[49] ^ w[56];
    w[58] = w[50] ^ w[57];
    w[59] = w[51] ^ w[58];

    w
}

// -----------------------------------------------------------------------
// Runtime hardware-AES detection (same pattern as RustCrypto `aes` crate)
// -----------------------------------------------------------------------

#[cfg(target_arch = "aarch64")]
cpufeatures::new!(hw_aes_available, "aes");

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
cpufeatures::new!(hw_aes_available, "aes");

// -----------------------------------------------------------------------
// Backend: ARM Crypto Extensions (AESD / AESIMC)
// -----------------------------------------------------------------------

#[cfg(target_arch = "aarch64")]
mod armv8 {
    use core::arch::aarch64::*;

    /// Pack four round-key words into a NEON register.
    #[inline(always)]
    unsafe fn pack(a: u32, b: u32, c: u32, d: u32) -> uint8x16_t {
        let mut v = vdupq_n_u32(0);
        v = vsetq_lane_u32(a, v, 0);
        v = vsetq_lane_u32(b, v, 1);
        v = vsetq_lane_u32(c, v, 2);
        v = vsetq_lane_u32(d, v, 3);
        vreinterpretq_u8_u32(v)
    }

    /// Compile-time feature path — fully inlinable.
    #[cfg(target_feature = "aes")]
    #[inline(always)]
    pub fn decrypt(w: &[u32; 60], ct: &[u8; 16]) -> [u8; 16] {
        unsafe { decrypt_impl(w, ct) }
    }

    /// Runtime-detected path — not inlinable across the feature boundary.
    #[cfg(not(target_feature = "aes"))]
    #[target_feature(enable = "aes,neon")]
    pub unsafe fn decrypt(w: &[u32; 60], ct: &[u8; 16]) -> [u8; 16] {
        decrypt_impl(w, ct)
    }

    /// 14-round AES-256 decrypt.
    ///
    /// ARM `AESD` = AddRoundKey ⊕ InvSubBytes ⊕ InvShiftRows (no
    /// InvMixColumns), so each full round is `AESIMC(AESD(block, key))`.
    /// Middle round keys have `AESIMC` pre-applied (equivalent inverse
    /// cipher).  The last round omits the outer `AESIMC`.
    #[inline(always)]
    unsafe fn decrypt_impl(w: &[u32; 60], ct: &[u8; 16]) -> [u8; 16] {
        let rk = |i: usize| pack(w[i], w[i + 1], w[i + 2], w[i + 3]);

        let mut blk = vld1q_u8(ct.as_ptr());

        // Round 1 (RK14, no pre-AESIMC)
        blk = vaesimcq_u8(vaesdq_u8(blk, rk(56)));
        // Rounds 2-13 (RK13..RK2, with pre-AESIMC)
        blk = vaesimcq_u8(vaesdq_u8(blk, vaesimcq_u8(rk(52))));
        blk = vaesimcq_u8(vaesdq_u8(blk, vaesimcq_u8(rk(48))));
        blk = vaesimcq_u8(vaesdq_u8(blk, vaesimcq_u8(rk(44))));
        blk = vaesimcq_u8(vaesdq_u8(blk, vaesimcq_u8(rk(40))));
        blk = vaesimcq_u8(vaesdq_u8(blk, vaesimcq_u8(rk(36))));
        blk = vaesimcq_u8(vaesdq_u8(blk, vaesimcq_u8(rk(32))));
        blk = vaesimcq_u8(vaesdq_u8(blk, vaesimcq_u8(rk(28))));
        blk = vaesimcq_u8(vaesdq_u8(blk, vaesimcq_u8(rk(24))));
        blk = vaesimcq_u8(vaesdq_u8(blk, vaesimcq_u8(rk(20))));
        blk = vaesimcq_u8(vaesdq_u8(blk, vaesimcq_u8(rk(16))));
        blk = vaesimcq_u8(vaesdq_u8(blk, vaesimcq_u8(rk(12))));
        blk = vaesimcq_u8(vaesdq_u8(blk, vaesimcq_u8(rk(8))));
        // Round 14 (RK1, pre-AESIMC, no outer AESIMC)
        blk = vaesdq_u8(blk, vaesimcq_u8(rk(4)));
        // Final AddRoundKey (RK0)
        blk = veorq_u8(blk, rk(0));

        let mut out = [0u8; 16];
        vst1q_u8(out.as_mut_ptr(), blk);
        out
    }
}

// -----------------------------------------------------------------------
// Backend: x86 / x86_64 AES-NI (AESDEC / AESDECLAST)
// -----------------------------------------------------------------------

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod x86ni {
    #[cfg(target_arch = "x86")]
    use core::arch::x86::*;
    #[cfg(target_arch = "x86_64")]
    use core::arch::x86_64::*;

    #[inline(always)]
    unsafe fn pack(a: u32, b: u32, c: u32, d: u32) -> __m128i {
        _mm_set_epi32(d as i32, c as i32, b as i32, a as i32)
    }

    #[cfg(target_feature = "aes")]
    #[inline(always)]
    pub fn decrypt(w: &[u32; 60], ct: &[u8; 16]) -> [u8; 16] {
        unsafe { decrypt_impl(w, ct) }
    }

    #[cfg(not(target_feature = "aes"))]
    #[target_feature(enable = "aes")]
    pub unsafe fn decrypt(w: &[u32; 60], ct: &[u8; 16]) -> [u8; 16] {
        decrypt_impl(w, ct)
    }

    /// 14-round AES-256 decrypt.
    ///
    /// x86 `AESDEC` = AddRoundKey ⊕ InvSubBytes ⊕ InvShiftRows ⊕
    /// InvMixColumns (all four steps).  `AESDECLAST` omits
    /// InvMixColumns for the final round.  Middle round keys have
    /// `AESIMC` pre-applied.
    #[inline(always)]
    unsafe fn decrypt_impl(w: &[u32; 60], ct: &[u8; 16]) -> [u8; 16] {
        let rk = |i: usize| pack(w[i], w[i + 1], w[i + 2], w[i + 3]);

        let mut blk = _mm_loadu_si128(ct.as_ptr().cast());

        // Initial AddRoundKey
        blk = _mm_xor_si128(blk, rk(56));
        // Rounds 1-13 (AESDEC includes InvMixColumns)
        blk = _mm_aesdec_si128(blk, _mm_aesimc_si128(rk(52)));
        blk = _mm_aesdec_si128(blk, _mm_aesimc_si128(rk(48)));
        blk = _mm_aesdec_si128(blk, _mm_aesimc_si128(rk(44)));
        blk = _mm_aesdec_si128(blk, _mm_aesimc_si128(rk(40)));
        blk = _mm_aesdec_si128(blk, _mm_aesimc_si128(rk(36)));
        blk = _mm_aesdec_si128(blk, _mm_aesimc_si128(rk(32)));
        blk = _mm_aesdec_si128(blk, _mm_aesimc_si128(rk(28)));
        blk = _mm_aesdec_si128(blk, _mm_aesimc_si128(rk(24)));
        blk = _mm_aesdec_si128(blk, _mm_aesimc_si128(rk(20)));
        blk = _mm_aesdec_si128(blk, _mm_aesimc_si128(rk(16)));
        blk = _mm_aesdec_si128(blk, _mm_aesimc_si128(rk(12)));
        blk = _mm_aesdec_si128(blk, _mm_aesimc_si128(rk(8)));
        // Round 14 (AESDECLAST omits InvMixColumns)
        blk = _mm_aesdeclast_si128(blk, rk(0));

        let mut out = [0u8; 16];
        _mm_storeu_si128(out.as_mut_ptr().cast(), blk);
        out
    }
}

// -----------------------------------------------------------------------
// Backend: portable software AES-256 decrypt
// -----------------------------------------------------------------------

mod soft {
    use super::INV_SBOX;

    #[inline(always)]
    fn xtime(a: u8) -> u8 {
        ((a as u16) << 1 ^ if a & 0x80 != 0 { 0x1b } else { 0 }) as u8
    }

    #[inline(always)]
    fn gf_mul(mut a: u8, mut b: u8) -> u8 {
        let mut r = 0u8;
        for _ in 0..8 {
            if b & 1 != 0 {
                r ^= a;
            }
            a = xtime(a);
            b >>= 1;
        }
        r
    }

    pub fn decrypt(w: &[u32; 60], ct: &[u8; 16]) -> [u8; 16] {
        let mut s = *ct;
        add_round_key(&mut s, w, 56);
        for round in (1..14).rev() {
            inv_shift_rows(&mut s);
            inv_sub_bytes(&mut s);
            add_round_key(&mut s, w, round * 4);
            inv_mix_columns(&mut s);
        }
        inv_shift_rows(&mut s);
        inv_sub_bytes(&mut s);
        add_round_key(&mut s, w, 0);
        s
    }

    #[inline(always)]
    fn add_round_key(state: &mut [u8; 16], w: &[u32; 60], offset: usize) {
        for col in 0..4 {
            let k = w[offset + col].to_le_bytes();
            for row in 0..4 {
                state[col * 4 + row] ^= k[row];
            }
        }
    }

    #[inline(always)]
    fn inv_sub_bytes(s: &mut [u8; 16]) {
        for b in s.iter_mut() {
            *b = INV_SBOX[*b as usize];
        }
    }

    #[inline(always)]
    fn inv_shift_rows(s: &mut [u8; 16]) {
        // Row 1: right-rotate by 1
        let t = s[13];
        s[13] = s[9];
        s[9] = s[5];
        s[5] = s[1];
        s[1] = t;
        // Row 2: right-rotate by 2
        let (t0, t1) = (s[2], s[6]);
        s[2] = s[10];
        s[6] = s[14];
        s[10] = t0;
        s[14] = t1;
        // Row 3: right-rotate by 3
        let t = s[3];
        s[3] = s[7];
        s[7] = s[11];
        s[11] = s[15];
        s[15] = t;
    }

    #[inline(always)]
    fn inv_mix_columns(s: &mut [u8; 16]) {
        for col in 0..4 {
            let i = col * 4;
            let (a, b, c, d) = (s[i], s[i + 1], s[i + 2], s[i + 3]);
            s[i] = gf_mul(0x0e, a) ^ gf_mul(0x0b, b) ^ gf_mul(0x0d, c) ^ gf_mul(0x09, d);
            s[i + 1] = gf_mul(0x09, a) ^ gf_mul(0x0e, b) ^ gf_mul(0x0b, c) ^ gf_mul(0x0d, d);
            s[i + 2] = gf_mul(0x0d, a) ^ gf_mul(0x09, b) ^ gf_mul(0x0e, c) ^ gf_mul(0x0b, d);
            s[i + 3] = gf_mul(0x0b, a) ^ gf_mul(0x0d, b) ^ gf_mul(0x09, c) ^ gf_mul(0x0e, d);
        }
    }
}

// -----------------------------------------------------------------------
// Dispatch: key schedule + best available decrypt backend
// -----------------------------------------------------------------------

/// Precomputed constants from the fixed key bytes (W1 and W7=0).
#[derive(Clone)]
struct FixedState {
    w1: u32,
    c8: u32,
    ct: [u8; 16],
}

impl FixedState {
    fn new(key_tpl: &[u8; 32], ct: &[u8; 16]) -> Self {
        Self {
            w1: u32::from_le_bytes(key_tpl[4..8].try_into().unwrap()),
            c8: sub_word(0) ^ RCON[0],
            ct: *ct,
        }
    }
}

/// Expand the key schedule for `candidate` and decrypt `state.ct`.
#[inline(always)]
fn decrypt_candidate(state: &FixedState, candidate: u32) -> [u8; 16] {
    let w = key_schedule(candidate, state.w1, state.c8);

    // Compile-time feature → inlinable, safe call.
    #[cfg(all(target_arch = "aarch64", target_feature = "aes"))]
    return armv8::decrypt(&w, &state.ct);

    #[cfg(all(
        any(target_arch = "x86", target_arch = "x86_64"),
        target_feature = "aes"
    ))]
    return x86ni::decrypt(&w, &state.ct);

    // Runtime detection → not inlinable, unsafe call.
    #[cfg(all(target_arch = "aarch64", not(target_feature = "aes")))]
    if hw_aes_available::get() {
        return unsafe { armv8::decrypt(&w, &state.ct) };
    }

    #[cfg(all(
        any(target_arch = "x86", target_arch = "x86_64"),
        not(target_feature = "aes")
    ))]
    if hw_aes_available::get() {
        return unsafe { x86ni::decrypt(&w, &state.ct) };
    }

    #[allow(unreachable_code)]
    soft::decrypt(&w, &state.ct)
}

// -----------------------------------------------------------------------
// Python entry point
// -----------------------------------------------------------------------

/// Search candidate keys in `[start, end)` for a known-plaintext match.
///
/// For each candidate, bytes 0-3 of `key_tpl` are replaced with the
/// candidate value (little-endian), the full AES-256 key schedule is
/// expanded, one 16-byte ECB block is decrypted, and the first
/// `len(prefix)` plaintext bytes are compared against `prefix`.
///
/// Returns the first matching candidate, or `None`.
#[pyfunction]
fn search_range(
    py: Python<'_>,
    ct: &[u8],
    key_tpl: &[u8],
    start: u64,
    end: u64,
    prefix: &[u8],
) -> PyResult<Option<u64>> {
    if ct.len() != 16 || key_tpl.len() != 32 || prefix.len() > 16 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "ct must be 16 bytes, key_tpl must be 32 bytes, prefix must be <= 16 bytes",
        ));
    }

    let ct_arr: [u8; 16] = ct.try_into().unwrap();
    let tpl: [u8; 32] = key_tpl.try_into().unwrap();
    let prefix_len = prefix.len();
    let mut prefix_arr = [0u8; 16];
    prefix_arr[..prefix_len].copy_from_slice(prefix);

    let state = FixedState::new(&tpl, &ct_arr);

    let result = py.detach(|| {
        (start..end).into_par_iter().find_any(|&cand| {
            let pt = decrypt_candidate(&state, cand as u32);
            pt[0] == prefix_arr[0] && pt[..prefix_len] == prefix_arr[..prefix_len]
        })
    });

    Ok(result)
}

#[pymodule]
fn _aes_brute(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(search_range, m)?)?;
    Ok(())
}
