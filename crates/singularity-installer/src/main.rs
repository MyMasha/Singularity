#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! Singularity Official Pure Native Win32 Setup Wizard (`Singularity-Setup.exe`).
//!
//! Engineered with 100% pure Win32 C-ABI (`user32`, `gdi32`, `dwmapi`, `advapi32`, `ole32`, `shell32`):
//! - ZERO WebView2 / Edge subprocesses (eliminates elevated/PCA WebView2 `wait_with_pump` freezes).
//! - ZERO `powershell.exe`, `cmd.exe`, or `taskkill.exe` child processes (eliminates AMSI/stdin hangs).
//! - Embedded `asInvoker` + `PerMonitorV2` Win32 manifest for instant (<10ms) high-DPI launch.
//! - 60 FPS double-buffered SDF + ClearType GDI UI on main thread; 100% of disk, Registry, and COM
//!   `.lnk` shortcut work runs asynchronously on a background worker thread via `PostMessageW`.

use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};

const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Compile-time optional 64-hex-character Ed25519 release signing public key injected by CI
/// (`.github/workflows/release.yml`) from `SINGULARITY_RELEASE_SIGNING_KEY`.
/// When present, every `SGX1` SFX ZIP overlay MUST carry a valid Ed25519 signature.
const EMBEDDED_RELEASE_SIGNING_PUBKEY_HEX: Option<&str> =
    option_env!("SINGULARITY_RELEASE_SIGNING_PUBKEY_HEX");

/// Fixed 116-byte authenticated SFX trailer format synchronized with `scripts/package-windows-cef.py`:
/// - [0..4]    : magic_start = b"SGX1"
/// - [4..12]   : zip_len (u64 little-endian)
/// - [12..44]  : zip_sha256 ([u8; 32]) over exact ZIP bytes [zip_start .. zip_start + zip_len]
/// - [44]      : flags (0x00 = SHA-256 sealed, 0x01 = SHA-256 + Ed25519 signed; other bits reserved)
/// - [45..48]  : reserved ([0, 0, 0])
/// - [48..112] : ed25519_sig ([u8; 64]) over bytes [0..48], or all zeroes when flags == 0x00
/// - [112..116]: magic_end = b"SGX1"
const SFX_TRAILER_MAGIC: &[u8; 4] = b"SGX1";
const SFX_TRAILER_LEN: usize = 116;
const SFX_SIGNED_HEADER_LEN: usize = 48;
const SFX_FLAG_ED25519_SIGNED: u8 = 0x01;

const EMBEDDED_SINGULARITY_EXE: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/embedded_singularity.bin"));
const EMBEDDED_SINGULARITY_ICO: &[u8] =
    include_bytes!("../../singularity-ui/assets/singularity.ico");

#[cfg(target_os = "windows")]
const EMBEDDED_LOGO_128_RGBA: &[u8] =
    include_bytes!("../../singularity-ui/assets/logo_128.rgba");

/// Zero-dependency pure-Rust cryptographic verification primitives (FIPS 180-4 SHA-256/SHA-512
/// and RFC 8032 Ed25519 verification) used to authenticate the `SGX1` SFX ZIP overlay before
/// extracting a single byte to disk.
mod crypto_verify {
    pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        let mut diff: u8 = 0;
        for (&x, &y) in a.iter().zip(b.iter()) {
            diff |= x ^ y;
        }
        diff == 0
    }

    pub fn decode_hex_32(hex_str: &str) -> Result<[u8; 32], String> {
        let s = hex_str.trim();
        if s.len() != 64 {
            return Err(format!(
                "Ed25519 public key must be 64 hex characters (got {}).",
                s.len()
            ));
        }
        let mut out = [0u8; 32];
        let bytes = s.as_bytes();
        for i in 0..32 {
            let hi = hex_nibble(bytes[i * 2])
                .ok_or_else(|| "Invalid hex digit in Ed25519 public key.".to_string())?;
            let lo = hex_nibble(bytes[i * 2 + 1])
                .ok_or_else(|| "Invalid hex digit in Ed25519 public key.".to_string())?;
            out[i] = (hi << 4) | lo;
        }
        Ok(out)
    }

    fn hex_nibble(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }

    // ---- FIPS 180-4 SHA-256 ----

    pub struct Sha256 {
        state: [u32; 8],
        buf: [u8; 64],
        buf_len: usize,
        total_len: u64,
    }

    impl Sha256 {
        pub fn new() -> Self {
            Self {
                state: [
                    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
                ],
                buf: [0u8; 64],
                buf_len: 0,
                total_len: 0,
            }
        }

        pub fn update(&mut self, mut data: &[u8]) {
            self.total_len = self.total_len.wrapping_add(data.len() as u64);
            if self.buf_len > 0 {
                let take = (64 - self.buf_len).min(data.len());
                self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
                self.buf_len += take;
                data = &data[take..];
                if self.buf_len == 64 {
                    let block = self.buf;
                    self.compress(&block);
                    self.buf_len = 0;
                }
            }
            while data.len() >= 64 {
                let mut block = [0u8; 64];
                block.copy_from_slice(&data[..64]);
                self.compress(&block);
                data = &data[64..];
            }
            if !data.is_empty() {
                self.buf[..data.len()].copy_from_slice(data);
                self.buf_len = data.len();
            }
        }

        pub fn finalize(mut self) -> [u8; 32] {
            let bit_len = self.total_len.wrapping_mul(8);
            self.buf[self.buf_len] = 0x80;
            self.buf_len += 1;
            if self.buf_len > 56 {
                for b in &mut self.buf[self.buf_len..64] {
                    *b = 0;
                }
                let block = self.buf;
                self.compress(&block);
                self.buf_len = 0;
            }
            for b in &mut self.buf[self.buf_len..56] {
                *b = 0;
            }
            self.buf[56..64].copy_from_slice(&bit_len.to_be_bytes());
            let block = self.buf;
            self.compress(&block);

            let mut out = [0u8; 32];
            for (i, &w) in self.state.iter().enumerate() {
                out[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
            }
            out
        }

        fn compress(&mut self, block: &[u8; 64]) {
            const K: [u32; 64] = [
                0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
                0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
                0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
                0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
                0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
                0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
                0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
            ];
            let mut w = [0u32; 64];
            for i in 0..16 {
                w[i] = u32::from_be_bytes([
                    block[i * 4],
                    block[i * 4 + 1],
                    block[i * 4 + 2],
                    block[i * 4 + 3],
                ]);
            }
            for i in 16..64 {
                let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
                let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
                w[i] = w[i - 16]
                    .wrapping_add(s0)
                    .wrapping_add(w[i - 7])
                    .wrapping_add(s1);
            }
            let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;
            for i in 0..64 {
                let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
                let ch = (e & f) ^ ((!e) & g);
                let t1 = h
                    .wrapping_add(s1)
                    .wrapping_add(ch)
                    .wrapping_add(K[i])
                    .wrapping_add(w[i]);
                let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
                let maj = (a & b) ^ (a & c) ^ (b & c);
                let t2 = s0.wrapping_add(maj);

                h = g;
                g = f;
                f = e;
                e = d.wrapping_add(t1);
                d = c;
                c = b;
                b = a;
                a = t1.wrapping_add(t2);
            }
            self.state[0] = self.state[0].wrapping_add(a);
            self.state[1] = self.state[1].wrapping_add(b);
            self.state[2] = self.state[2].wrapping_add(c);
            self.state[3] = self.state[3].wrapping_add(d);
            self.state[4] = self.state[4].wrapping_add(e);
            self.state[5] = self.state[5].wrapping_add(f);
            self.state[6] = self.state[6].wrapping_add(g);
            self.state[7] = self.state[7].wrapping_add(h);
        }
    }

    // ---- FIPS 180-4 SHA-512 (for RFC 8032 Ed25519) ----

    pub struct Sha512 {
        state: [u64; 8],
        buf: [u8; 128],
        buf_len: usize,
        total_len: u128,
    }

    impl Sha512 {
        pub fn new() -> Self {
            Self {
                state: [
                    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
                    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
                ],
                buf: [0u8; 128],
                buf_len: 0,
                total_len: 0,
            }
        }

        pub fn update(&mut self, mut data: &[u8]) {
            self.total_len = self.total_len.wrapping_add(data.len() as u128);
            if self.buf_len > 0 {
                let take = (128 - self.buf_len).min(data.len());
                self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
                self.buf_len += take;
                data = &data[take..];
                if self.buf_len == 128 {
                    let block = self.buf;
                    self.compress(&block);
                    self.buf_len = 0;
                }
            }
            while data.len() >= 128 {
                let mut block = [0u8; 128];
                block.copy_from_slice(&data[..128]);
                self.compress(&block);
                data = &data[128..];
            }
            if !data.is_empty() {
                self.buf[..data.len()].copy_from_slice(data);
                self.buf_len = data.len();
            }
        }

        pub fn finalize(mut self) -> [u8; 64] {
            let bit_len = self.total_len.wrapping_mul(8);
            self.buf[self.buf_len] = 0x80;
            self.buf_len += 1;
            if self.buf_len > 112 {
                for b in &mut self.buf[self.buf_len..128] {
                    *b = 0;
                }
                let block = self.buf;
                self.compress(&block);
                self.buf_len = 0;
            }
            for b in &mut self.buf[self.buf_len..112] {
                *b = 0;
            }
            self.buf[112..128].copy_from_slice(&bit_len.to_be_bytes());
            let block = self.buf;
            self.compress(&block);

            let mut out = [0u8; 64];
            for (i, &w) in self.state.iter().enumerate() {
                out[i * 8..i * 8 + 8].copy_from_slice(&w.to_be_bytes());
            }
            out
        }

        fn compress(&mut self, block: &[u8; 128]) {
            const K: [u64; 80] = [
                0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
                0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
                0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
                0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
                0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
                0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
                0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
                0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
                0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
                0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
                0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
                0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
                0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
                0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
                0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
                0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
                0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
                0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
                0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
                0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
            ];
            let mut w = [0u64; 80];
            for i in 0..16 {
                w[i] = u64::from_be_bytes([
                    block[i * 8],
                    block[i * 8 + 1],
                    block[i * 8 + 2],
                    block[i * 8 + 3],
                    block[i * 8 + 4],
                    block[i * 8 + 5],
                    block[i * 8 + 6],
                    block[i * 8 + 7],
                ]);
            }
            for i in 16..80 {
                let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
                let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
                w[i] = w[i - 16]
                    .wrapping_add(s0)
                    .wrapping_add(w[i - 7])
                    .wrapping_add(s1);
            }
            let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;
            for i in 0..80 {
                let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
                let ch = (e & f) ^ ((!e) & g);
                let t1 = h
                    .wrapping_add(s1)
                    .wrapping_add(ch)
                    .wrapping_add(K[i])
                    .wrapping_add(w[i]);
                let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
                let maj = (a & b) ^ (a & c) ^ (b & c);
                let t2 = s0.wrapping_add(maj);

                h = g;
                g = f;
                f = e;
                e = d.wrapping_add(t1);
                d = c;
                c = b;
                b = a;
                a = t1.wrapping_add(t2);
            }
            self.state[0] = self.state[0].wrapping_add(a);
            self.state[1] = self.state[1].wrapping_add(b);
            self.state[2] = self.state[2].wrapping_add(c);
            self.state[3] = self.state[3].wrapping_add(d);
            self.state[4] = self.state[4].wrapping_add(e);
            self.state[5] = self.state[5].wrapping_add(f);
            self.state[6] = self.state[6].wrapping_add(g);
            self.state[7] = self.state[7].wrapping_add(h);
        }
    }

    // ---- RFC 8032 Ed25519 Verification over GF(2^255 - 19) ----

    const MASK51: u64 = (1u64 << 51) - 1;
    // Group order L = 2^252 + 27742317777372353535851937790883648493 (little-endian u64 limbs)
    const L_LIMBS: [u64; 4] = [
        0x5812_631a_5cf5_d3ed,
        0x14de_f9de_a2f7_9cd6,
        0x0000_0000_0000_0000,
        0x1000_0000_0000_0000,
    ];
    // d = -121665 / 121666 mod p
    const FE_D: Fe = Fe([
        0x34dca135978a3,
        0x1a8283b156ebd,
        0x5e7a26001c029,
        0x739c663a03cbb,
        0x52036cee2b6ff,
    ]);
    // 2 * d mod p
    const FE_D2: Fe = Fe([
        0x69b9426b2f159,
        0x35050762add7a,
        0x3cf44c0038052,
        0x6738cc7407977,
        0x2406d9dc56dff,
    ]);
    // sqrt(-1) = 2^((p - 1) / 4) mod p
    const FE_SQRT_M1: Fe = Fe([
        0x61b274a0ea0b0,
        0x0d5a5fc8f189d,
        0x7ef5e9cbd0c60,
        0x78595a6804c9e,
        0x2b8324804fc1d,
    ]);

    #[derive(Clone, Copy)]
    struct Fe([u64; 5]);

    impl Fe {
        const ZERO: Fe = Fe([0, 0, 0, 0, 0]);
        const ONE: Fe = Fe([1, 0, 0, 0, 0]);

        fn reduce(mut h: [u64; 5]) -> Fe {
            let mut c = h[0] >> 51;
            h[0] &= MASK51;
            h[1] += c;
            c = h[1] >> 51;
            h[1] &= MASK51;
            h[2] += c;
            c = h[2] >> 51;
            h[2] &= MASK51;
            h[3] += c;
            c = h[3] >> 51;
            h[3] &= MASK51;
            h[4] += c;
            c = h[4] >> 51;
            h[4] &= MASK51;
            h[0] += c * 19;
            c = h[0] >> 51;
            h[0] &= MASK51;
            h[1] += c;
            Fe(h)
        }

        fn add(self, rhs: Fe) -> Fe {
            Fe::reduce([
                self.0[0] + rhs.0[0],
                self.0[1] + rhs.0[1],
                self.0[2] + rhs.0[2],
                self.0[3] + rhs.0[3],
                self.0[4] + rhs.0[4],
            ])
        }

        fn sub(self, rhs: Fe) -> Fe {
            // Add 2*p to avoid underflow before reducing
            const P2_0: u64 = 0xffff_ffff_fffd_a; // 2 * (2^51 - 19)
            const P2_I: u64 = 0xffff_ffff_ffff_e; // 2 * (2^51 - 1)
            Fe::reduce([
                self.0[0] + P2_0 - rhs.0[0],
                self.0[1] + P2_I - rhs.0[1],
                self.0[2] + P2_I - rhs.0[2],
                self.0[3] + P2_I - rhs.0[3],
                self.0[4] + P2_I - rhs.0[4],
            ])
        }

        fn neg(self) -> Fe {
            Fe::ZERO.sub(self)
        }

        fn mul(self, rhs: Fe) -> Fe {
            let a = self.0;
            let b = rhs.0;
            let a0 = a[0] as u128;
            let a1 = a[1] as u128;
            let a2 = a[2] as u128;
            let a3 = a[3] as u128;
            let a4 = a[4] as u128;
            let b0 = b[0] as u128;
            let b1 = b[1] as u128;
            let b2 = b[2] as u128;
            let b3 = b[3] as u128;
            let b4 = b[4] as u128;
            let b1_19 = b1 * 19;
            let b2_19 = b2 * 19;
            let b3_19 = b3 * 19;
            let b4_19 = b4 * 19;

            let mut t0 = a0 * b0 + a1 * b4_19 + a2 * b3_19 + a3 * b2_19 + a4 * b1_19;
            let mut t1 = a0 * b1 + a1 * b0 + a2 * b4_19 + a3 * b3_19 + a4 * b2_19;
            let mut t2 = a0 * b2 + a1 * b1 + a2 * b0 + a3 * b4_19 + a4 * b3_19;
            let mut t3 = a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0 + a4 * b4_19;
            let mut t4 = a0 * b4 + a1 * b3 + a2 * b2 + a3 * b1 + a4 * b0;

            let m = MASK51 as u128;
            t1 += t0 >> 51;
            let h0 = (t0 & m) as u64;
            t2 += t1 >> 51;
            let h1 = (t1 & m) as u64;
            t3 += t2 >> 51;
            let h2 = (t2 & m) as u64;
            t4 += t3 >> 51;
            let h3 = (t3 & m) as u64;
            let c4 = t4 >> 51;
            let h4 = (t4 & m) as u64;
            t0 = (h0 as u128) + c4 * 19;
            let h0 = (t0 & m) as u64;
            let h1 = h1 + (t0 >> 51) as u64;
            Fe::reduce([h0, h1, h2, h3, h4])
        }

        fn sq(self) -> Fe {
            self.mul(self)
        }

        fn pow_sq_n(mut self, n: usize) -> Fe {
            for _ in 0..n {
                self = self.sq();
            }
            self
        }

        fn pow22523(self) -> Fe {
            // self^((p - 5) / 8) = self^(2^252 - 3)
            let t0 = self.sq();
            let t1 = t0.pow_sq_n(2);
            let t1 = self.mul(t1);
            let t0 = t0.mul(t1);
            let t0 = t0.sq();
            let t0 = t1.mul(t0);
            let t1 = t0.pow_sq_n(5);
            let t0 = t1.mul(t0);
            let t1 = t0.pow_sq_n(10);
            let t1 = t1.mul(t0);
            let t2 = t1.pow_sq_n(20);
            let t1 = t2.mul(t1);
            let t1 = t1.pow_sq_n(10);
            let t0 = t1.mul(t0);
            let t1 = t0.pow_sq_n(50);
            let t1 = t1.mul(t0);
            let t2 = t1.pow_sq_n(100);
            let t1 = t2.mul(t1);
            let t1 = t1.pow_sq_n(50);
            let t0 = t1.mul(t0);
            let t0 = t0.pow_sq_n(2);
            t0.mul(self)
        }

        fn invert(self) -> Fe {
            // self^(p - 2) = self^(2^255 - 21)
            let t0 = self.sq();
            let t1 = t0.pow_sq_n(2);
            let t1 = self.mul(t1);
            let t0 = t0.mul(t1);
            let t2 = t0.sq();
            let t1 = t1.mul(t2);
            let t2 = t1.pow_sq_n(5);
            let t1 = t2.mul(t1);
            let t2 = t1.pow_sq_n(10);
            let t2 = t2.mul(t1);
            let t3 = t2.pow_sq_n(20);
            let t2 = t3.mul(t2);
            let t2 = t2.pow_sq_n(10);
            let t1 = t2.mul(t1);
            let t2 = t1.pow_sq_n(50);
            let t2 = t2.mul(t1);
            let t3 = t2.pow_sq_n(100);
            let t2 = t3.mul(t2);
            let t2 = t2.pow_sq_n(50);
            let t1 = t2.mul(t1);
            let t1 = t1.pow_sq_n(5);
            t1.mul(t0)
        }

        fn to_bytes(self) -> [u8; 32] {
            let mut h = Fe::reduce(self.0).0;
            // Conditional subtraction of p = 2^255 - 19
            let mut q = (h[0] + 19) >> 51;
            q = (h[1] + q) >> 51;
            q = (h[2] + q) >> 51;
            q = (h[3] + q) >> 51;
            q = (h[4] + q) >> 51;

            h[0] += 19 * q;
            let mut c = h[0] >> 51;
            h[0] &= MASK51;
            h[1] += c;
            c = h[1] >> 51;
            h[1] &= MASK51;
            h[2] += c;
            c = h[2] >> 51;
            h[2] &= MASK51;
            h[3] += c;
            c = h[3] >> 51;
            h[3] &= MASK51;
            h[4] += c;
            h[4] &= MASK51;

            let mut out = [0u8; 32];
            let w0 = h[0] | (h[1] << 51);
            let w1 = (h[1] >> 13) | (h[2] << 38);
            let w2 = (h[2] >> 26) | (h[3] << 25);
            let w3 = (h[3] >> 39) | (h[4] << 12);
            out[0..8].copy_from_slice(&w0.to_le_bytes());
            out[8..16].copy_from_slice(&w1.to_le_bytes());
            out[16..24].copy_from_slice(&w2.to_le_bytes());
            out[24..32].copy_from_slice(&w3.to_le_bytes());
            out
        }

        fn from_canonical_y_bytes(b: &[u8; 32]) -> Result<(Fe, u8), String> {
            let sign = (b[31] >> 7) & 1;
            let mut clamped = *b;
            clamped[31] &= 0x7F;
            let w0 = u64::from_le_bytes(clamped[0..8].try_into().unwrap());
            let w1 = u64::from_le_bytes(clamped[8..16].try_into().unwrap());
            let w2 = u64::from_le_bytes(clamped[16..24].try_into().unwrap());
            let w3 = u64::from_le_bytes(clamped[24..32].try_into().unwrap());
            // Reject non-canonical y >= 2^255 - 19
            let ge_p = w3 == 0x7fff_ffff_ffff_ffff
                && w2 == u64::MAX
                && w1 == u64::MAX
                && w0 >= 0xffff_ffff_ffff_ffed;
            if ge_p {
                return Err("Non-canonical Ed25519 coordinate y >= p.".to_string());
            }
            let h0 = w0 & MASK51;
            let h1 = ((w0 >> 51) | (w1 << 13)) & MASK51;
            let h2 = ((w1 >> 38) | (w2 << 26)) & MASK51;
            let h3 = ((w2 >> 25) | (w3 << 39)) & MASK51;
            let h4 = (w3 >> 12) & MASK51;
            Ok((Fe([h0, h1, h2, h3, h4]), sign))
        }
    }

    #[derive(Clone, Copy)]
    struct ExtPoint {
        x: Fe,
        y: Fe,
        z: Fe,
        t: Fe,
    }

    impl ExtPoint {
        const IDENTITY: ExtPoint = ExtPoint {
            x: Fe::ZERO,
            y: Fe::ONE,
            z: Fe::ONE,
            t: Fe::ZERO,
        };

        const BASE: ExtPoint = ExtPoint {
            x: Fe([
                0x62d608f25d51a,
                0x412a4b4f6592a,
                0x75b7171a4b31d,
                0x1ff60527118fe,
                0x216936d3cd6e5,
            ]),
            y: Fe([
                0x6666666666658,
                0x4cccccccccccc,
                0x1999999999999,
                0x3333333333333,
                0x6666666666666,
            ]),
            z: Fe::ONE,
            t: Fe([
                0x68ab3a5b7dda3,
                0x00eea2a5eadbb,
                0x2af8df483c27e,
                0x332b375274732,
                0x67875f0fd78b7,
            ]),
        };

        fn add(self, q: ExtPoint) -> ExtPoint {
            let a = self.y.sub(self.x).mul(q.y.sub(q.x));
            let b = self.y.add(self.x).mul(q.y.add(q.x));
            let c = self.t.mul(FE_D2).mul(q.t);
            let d = self.z.mul(q.z);
            let d = d.add(d);
            let e = b.sub(a);
            let f = d.sub(c);
            let g = d.add(c);
            let h = b.add(a);
            ExtPoint {
                x: e.mul(f),
                y: g.mul(h),
                z: f.mul(g),
                t: e.mul(h),
            }
        }

        fn double(self) -> ExtPoint {
            self.add(self)
        }

        fn scalar_mul(self, s: &[u64; 4]) -> ExtPoint {
            let mut acc = ExtPoint::IDENTITY;
            let mut base = self;
            for &limb in s {
                for bit in 0..64 {
                    if ((limb >> bit) & 1) == 1 {
                        acc = acc.add(base);
                    }
                    base = base.double();
                }
            }
            acc
        }

        fn compress(self) -> [u8; 32] {
            let zi = self.z.invert();
            let x = self.x.mul(zi);
            let y = self.y.mul(zi);
            let mut out = y.to_bytes();
            let x_bytes = x.to_bytes();
            out[31] |= (x_bytes[0] & 1) << 7;
            out
        }

        fn decompress(bytes: &[u8; 32]) -> Result<ExtPoint, String> {
            let (y, sign) = Fe::from_canonical_y_bytes(bytes)?;
            let y2 = y.sq();
            let u = y2.sub(Fe::ONE);
            let v = FE_D.mul(y2).add(Fe::ONE);
            let v3 = v.sq().mul(v);
            let v7 = v3.sq().mul(v);
            let mut x = u.mul(v3).mul(u.mul(v7).pow22523());

            let vx2 = v.mul(x.sq());
            let vx2_bytes = vx2.to_bytes();
            let u_bytes = u.to_bytes();
            let neg_u_bytes = u.neg().to_bytes();
            if ct_eq(&vx2_bytes, &u_bytes) {
                // valid root
            } else if ct_eq(&vx2_bytes, &neg_u_bytes) {
                x = x.mul(FE_SQRT_M1);
            } else {
                return Err("Encoded Ed25519 point does not lie on curve.".to_string());
            }

            let x_bytes = x.to_bytes();
            let is_zero = x_bytes.iter().all(|&b| b == 0);
            if is_zero && sign == 1 {
                return Err("Non-canonical Ed25519 zero x-coordinate with sign bit set.".to_string());
            }
            if (x_bytes[0] & 1) != sign {
                x = x.neg();
            }
            Ok(ExtPoint {
                x,
                y,
                z: Fe::ONE,
                t: x.mul(y),
            })
        }
    }

    fn u256_ge(a: &[u64; 4], b: &[u64; 4]) -> bool {
        for i in (0..4).rev() {
            if a[i] > b[i] {
                return true;
            }
            if a[i] < b[i] {
                return false;
            }
        }
        true
    }

    fn u256_sub_assign(a: &mut [u64; 4], b: &[u64; 4]) {
        let mut borrow = 0u128;
        for i in 0..4 {
            let ai = a[i] as u128;
            let bi = (b[i] as u128) + borrow;
            if ai >= bi {
                a[i] = (ai - bi) as u64;
                borrow = 0;
            } else {
                a[i] = ((1u128 << 64) + ai - bi) as u64;
                borrow = 1;
            }
        }
    }

    fn scalar_from_canonical_bytes(s_bytes: &[u8; 32]) -> Result<[u64; 4], String> {
        let s = [
            u64::from_le_bytes(s_bytes[0..8].try_into().unwrap()),
            u64::from_le_bytes(s_bytes[8..16].try_into().unwrap()),
            u64::from_le_bytes(s_bytes[16..24].try_into().unwrap()),
            u64::from_le_bytes(s_bytes[24..32].try_into().unwrap()),
        ];
        if u256_ge(&s, &L_LIMBS) {
            return Err("Non-canonical Ed25519 signature scalar S >= L.".to_string());
        }
        Ok(s)
    }

    fn scalar_reduce_512(hash: &[u8; 64]) -> [u64; 4] {
        let mut rem = [0u64; 4];
        for byte_idx in (0..64).rev() {
            let b = hash[byte_idx];
            for bit_idx in (0..8).rev() {
                let carry_bit = ((b >> bit_idx) & 1) as u64;
                rem[3] = (rem[3] << 1) | (rem[2] >> 63);
                rem[2] = (rem[2] << 1) | (rem[1] >> 63);
                rem[1] = (rem[1] << 1) | (rem[0] >> 63);
                rem[0] = (rem[0] << 1) | carry_bit;
                if u256_ge(&rem, &L_LIMBS) {
                    u256_sub_assign(&mut rem, &L_LIMBS);
                }
            }
        }
        rem
    }

    /// Verifies an RFC 8032 Ed25519 signature over `msg` using a 32-byte public key.
    pub fn ed25519_verify(pubkey: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> Result<(), String> {
        let mut r_bytes = [0u8; 32];
        let mut s_bytes = [0u8; 32];
        r_bytes.copy_from_slice(&sig[0..32]);
        s_bytes.copy_from_slice(&sig[32..64]);

        let s = scalar_from_canonical_bytes(&s_bytes)?;
        let a_pt = ExtPoint::decompress(pubkey)?;
        let r_pt = ExtPoint::decompress(&r_bytes)?;

        let mut h = Sha512::new();
        h.update(&r_bytes);
        h.update(pubkey);
        h.update(msg);
        let k = scalar_reduce_512(&h.finalize());

        let lhs = ExtPoint::BASE.scalar_mul(&s).compress();
        let rhs = r_pt.add(a_pt.scalar_mul(&k)).compress();
        if !ct_eq(&lhs, &rhs) {
            return Err("Ed25519 cryptographic signature verification failed.".to_string());
        }
        Ok(())
    }
}

/// Read+Seek window restricting `zip::ZipArchive` strictly to the verified `[offset .. offset + len]`
/// byte range of the already-open file handle (eliminating both trailing-footer confusion and TOCTOU).
struct BoundedSectionReader<R> {
    inner: R,
    start: u64,
    len: u64,
    pos: u64,
}

impl<R: Read + Seek> BoundedSectionReader<R> {
    fn new(mut inner: R, start: u64, len: u64) -> std::io::Result<Self> {
        inner.seek(SeekFrom::Start(start))?;
        Ok(Self {
            inner,
            start,
            len,
            pos: 0,
        })
    }
}

impl<R: Read> Read for BoundedSectionReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.pos >= self.len {
            return Ok(0);
        }
        let max_read = (self.len - self.pos).min(buf.len() as u64) as usize;
        let n = self.inner.read(&mut buf[..max_read])?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl<R: Seek> Seek for BoundedSectionReader<R> {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let new_pos: i128 = match pos {
            SeekFrom::Start(off) => off as i128,
            SeekFrom::End(off) => (self.len as i128) + (off as i128),
            SeekFrom::Current(off) => (self.pos as i128) + (off as i128),
        };
        if new_pos < 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Seek before start of verified SFX ZIP section",
            ));
        }
        let clamped = (new_pos as u64).min(self.len);
        self.inner.seek(SeekFrom::Start(self.start + clamped))?;
        self.pos = clamped;
        Ok(self.pos)
    }
}

#[derive(Debug, Clone)]
struct InstallOptions {
    install_dir: String,
    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    desktop_shortcut: bool,
    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    start_menu_shortcut: bool,
    init_roaming_vault: bool,
    launch_after_install: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InstallPhase {
    Idle,
    Running,
    Done,
    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    Error,
}

#[derive(Debug, Clone)]
struct SharedProgress {
    phase: InstallPhase,
    target_pct: f32,
    step_label: String,
    installed_exe: String,
    error_msg: String,
}

#[cfg(not(target_os = "windows"))]
fn resolve_unix_home_dir() -> Result<PathBuf, String> {
    if let Ok(home) = std::env::var("HOME") {
        let trimmed = home.trim();
        if !trimmed.is_empty() && Path::new(trimmed).is_absolute() {
            return Ok(PathBuf::from(trimmed));
        }
    }
    // Fallback to the real UID's home directory in /etc/passwd (never /tmp)
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        if let Some(uid_str) = status
            .lines()
            .find_map(|l| l.strip_prefix("Uid:"))
            .and_then(|rest| rest.split_whitespace().next())
        {
            if let Ok(passwd) = std::fs::read_to_string("/etc/passwd") {
                for line in passwd.lines() {
                    let fields: Vec<&str> = line.split(':').collect();
                    if fields.len() >= 6 && fields[2] == uid_str {
                        let home = fields[5].trim();
                        if !home.is_empty()
                            && Path::new(home).is_absolute()
                            && Path::new(home).is_dir()
                        {
                            return Ok(PathBuf::from(home));
                        }
                    }
                }
            }
        }
    }
    Err(
        "Cannot determine user home directory: HOME is unset or empty and /etc/passwd lookup failed. \
         Refusing insecure /tmp fallback; set HOME or pass --dir explicitly."
            .to_string(),
    )
}

fn default_install_dir() -> Result<PathBuf, String> {
    #[cfg(target_os = "windows")]
    {
        if let Ok(local) = std::env::var("LOCALAPPDATA") {
            let trimmed = local.trim();
            if !trimmed.is_empty() {
                return Ok(PathBuf::from(trimmed).join("Programs").join("Singularity"));
            }
        }
        if let Ok(profile) = std::env::var("USERPROFILE") {
            let trimmed = profile.trim();
            if !trimmed.is_empty() {
                return Ok(PathBuf::from(trimmed)
                    .join("AppData")
                    .join("Local")
                    .join("Programs")
                    .join("Singularity"));
            }
        }
        Err(
            "Cannot determine default Windows installation directory (LOCALAPPDATA and USERPROFILE are unset)."
                .to_string(),
        )
    }
    #[cfg(not(target_os = "windows"))]
    {
        Ok(resolve_unix_home_dir()?
            .join(".local")
            .join("share")
            .join("Singularity"))
    }
}

fn roaming_singularity_dir() -> Result<PathBuf, String> {
    if let Ok(override_dir) = std::env::var("SINGULARITY_ROAMING_DIR") {
        let trimmed = override_dir.trim();
        if !trimmed.is_empty() {
            return Ok(PathBuf::from(trimmed));
        }
    }
    #[cfg(target_os = "windows")]
    {
        if let Ok(appdata) = std::env::var("APPDATA") {
            let trimmed = appdata.trim();
            if !trimmed.is_empty() {
                return Ok(PathBuf::from(trimmed).join(".singularity"));
            }
        }
        if let Ok(profile) = std::env::var("USERPROFILE") {
            let trimmed = profile.trim();
            if !trimmed.is_empty() {
                return Ok(PathBuf::from(trimmed)
                    .join("AppData")
                    .join("Roaming")
                    .join(".singularity"));
            }
        }
        Err(
            "Cannot determine Windows roaming profile directory (APPDATA and USERPROFILE are unset)."
                .to_string(),
        )
    }
    #[cfg(not(target_os = "windows"))]
    {
        Ok(resolve_unix_home_dir()?.join(".singularity"))
    }
}

fn embedded_release_pubkey_hex() -> Option<&'static str> {
    EMBEDDED_RELEASE_SIGNING_PUBKEY_HEX
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

/// Validates an appended `SGX1` SFX ZIP overlay on `reader`:
/// - Requires a well-formed 116-byte `SGX1` trailer at EOF.
/// - Streams and verifies the exact SHA-256 digest of `[zip_start .. zip_start + zip_len]`.
/// - When `pubkey_hex` is `Some(...)`, requires `flags & 0x01` and verifies the RFC 8032 Ed25519
///   signature over the 48-byte signed header (`SGX1 || zip_len || zip_sha256 || flags || reserved`).
/// - Refuses any arbitrary unsealed ZIP overlay attached without a valid `SGX1` trailer.
fn open_verified_sfx_zip<R: Read + Seek>(
    mut reader: R,
    pubkey_hex: Option<&str>,
) -> Result<Option<(zip::ZipArchive<BoundedSectionReader<R>>, u64)>, String> {
    let file_len = reader
        .seek(SeekFrom::End(0))
        .map_err(|e| format!("Failed seeking installer executable: {e}"))?;

    let mut has_sgx1_trailer = false;
    let mut trailer = [0u8; SFX_TRAILER_LEN];
    if file_len >= SFX_TRAILER_LEN as u64 {
        reader
            .seek(SeekFrom::End(-(SFX_TRAILER_LEN as i64)))
            .map_err(|e| format!("Failed reading SFX integrity trailer: {e}"))?;
        reader
            .read_exact(&mut trailer)
            .map_err(|e| format!("Failed reading SFX integrity trailer: {e}"))?;
        if &trailer[0..4] == SFX_TRAILER_MAGIC
            && &trailer[SFX_TRAILER_LEN - 4..SFX_TRAILER_LEN] == SFX_TRAILER_MAGIC
        {
            has_sgx1_trailer = true;
        }
    }

    if !has_sgx1_trailer {
        // Detect and reject any arbitrary unsealed ZIP overlay appended to the executable!
        if reader.seek(SeekFrom::Start(0)).is_ok() {
            if let Ok(raw_zip) = zip::ZipArchive::new(&mut reader) {
                if raw_zip.offset() > 0 && !raw_zip.is_empty() {
                    return Err(
                        "Refusing unsealed/unauthenticated ZIP SFX overlay (missing SGX1 integrity trailer)."
                            .to_string(),
                    );
                }
            }
        }
        return Ok(None);
    }

    let zip_len = u64::from_le_bytes(trailer[4..12].try_into().unwrap());
    let mut expected_sha256 = [0u8; 32];
    expected_sha256.copy_from_slice(&trailer[12..44]);
    let flags = trailer[44];
    let reserved = &trailer[45..48];
    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(&trailer[48..112]);

    if (flags & !SFX_FLAG_ED25519_SIGNED) != 0 || reserved != [0u8; 3] {
        return Err("Malformed SGX1 SFX integrity trailer (invalid flags or reserved bytes).".into());
    }

    let trailer_offset = file_len - SFX_TRAILER_LEN as u64;
    if zip_len < 22 || zip_len >= trailer_offset {
        return Err(format!(
            "Invalid SGX1 SFX payload length ({zip_len} bytes vs executable size {file_len})."
        ));
    }
    let zip_start = trailer_offset - zip_len;

    if let Some(pk_hex) = pubkey_hex.map(str::trim).filter(|s| !s.is_empty()) {
        if (flags & SFX_FLAG_ED25519_SIGNED) == 0 {
            return Err(
                "SFX bundle is unsigned, but this release installer requires a valid Ed25519 signature."
                    .to_string(),
            );
        }
        let pk_bytes = crypto_verify::decode_hex_32(pk_hex)?;
        crypto_verify::ed25519_verify(&pk_bytes, &trailer[0..SFX_SIGNED_HEADER_LEN], &sig_bytes)
            .map_err(|e| format!("SFX overlay Ed25519 signature verification failed: {e}"))?;
    }

    // Stream exact ZIP slice `[zip_start .. zip_start + zip_len]` through SHA-256 on the same handle
    reader
        .seek(SeekFrom::Start(zip_start))
        .map_err(|e| format!("Failed seeking to SFX ZIP overlay: {e}"))?;
    let mut hasher = crypto_verify::Sha256::new();
    let mut buf = vec![0u8; 131_072];
    let mut remaining = zip_len;
    while remaining > 0 {
        let to_read = remaining.min(buf.len() as u64) as usize;
        reader
            .read_exact(&mut buf[..to_read])
            .map_err(|e| format!("Failed reading SFX ZIP overlay for SHA-256 check: {e}"))?;
        hasher.update(&buf[..to_read]);
        remaining -= to_read as u64;
    }
    let actual_sha256 = hasher.finalize();
    if !crypto_verify::ct_eq(&actual_sha256, &expected_sha256) {
        return Err(
            "SFX ZIP overlay SHA-256 integrity verification failed (bundle corrupted or tampered)."
                .to_string(),
        );
    }

    let bounded = BoundedSectionReader::new(reader, zip_start, zip_len)
        .map_err(|e| format!("Failed initializing bounded SFX reader: {e}"))?;
    let archive = zip::ZipArchive::new(bounded)
        .map_err(|e| format!("Failed parsing verified SGX1 SFX ZIP archive: {e}"))?;
    if archive.is_empty() {
        return Err("Verified SGX1 SFX ZIP archive is empty.".to_string());
    }
    Ok(Some((archive, zip_len)))
}

fn open_self_sfx_zip() -> Result<Option<(zip::ZipArchive<BoundedSectionReader<std::fs::File>>, u64)>, String>
{
    let exe_path = std::env::current_exe()
        .map_err(|e| format!("Failed locating current installer executable: {e}"))?;
    let file = std::fs::File::open(&exe_path)
        .map_err(|e| format!("Failed opening installer executable '{}': {e}", exe_path.display()))?;
    open_verified_sfx_zip(file, embedded_release_pubkey_hex())
}

fn detect_payload_size_bytes() -> u64 {
    static CACHED: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *CACHED.get_or_init(|| {
        if let Ok(Some((_, sz))) = open_self_sfx_zip() {
            return sz;
        }
        EMBEDDED_SINGULARITY_EXE.len() as u64
    })
}

#[cfg(target_os = "windows")]
fn detect_installed_uncompressed_kb() -> u32 {
    if let Ok(Some((mut archive, _))) = open_self_sfx_zip() {
        let mut total: u64 = 0;
        for i in 0..archive.len() {
            if let Ok(entry) = archive.by_index(i) {
                total = total.saturating_add(entry.size());
            }
        }
        return ((total / 1024).max(1024)) as u32;
    }
    ((EMBEDDED_SINGULARITY_EXE.len() / 1024).max(1024)) as u32
}

/// Refuses to follow symbolic links or Windows NTFS reparse points / junctions at `path`.
fn reject_symlink_or_reparse(path: &Path) -> Result<(), String> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                return Err(format!(
                    "Refusing to follow symbolic link at '{}'.",
                    path.display()
                ));
            }
            #[cfg(target_os = "windows")]
            {
                use std::os::windows::fs::MetadataExt;
                const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
                if (meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
                    return Err(format!(
                        "Refusing to follow Windows reparse point / junction at '{}'.",
                        path.display()
                    ));
                }
            }
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("Failed inspecting '{}': {e}", path.display())),
    }
}

/// Ensures `base_dir` exists and is a real directory (not a symlink or reparse point).
fn ensure_real_root_dir(base_dir: &Path) -> Result<(), String> {
    reject_symlink_or_reparse(base_dir)?;
    if let Ok(meta) = std::fs::symlink_metadata(base_dir) {
        if !meta.is_dir() {
            return Err(format!(
                "Target path '{}' exists and is not a directory.",
                base_dir.display()
            ));
        }
        return Ok(());
    }
    std::fs::create_dir_all(base_dir)
        .map_err(|e| format!("Failed to create directory '{}': {e}", base_dir.display()))?;
    reject_symlink_or_reparse(base_dir)?;
    let meta = std::fs::symlink_metadata(base_dir)
        .map_err(|e| format!("Failed verifying directory '{}': {e}", base_dir.display()))?;
    if !meta.is_dir() {
        return Err(format!(
            "Target path '{}' is not a directory.",
            base_dir.display()
        ));
    }
    Ok(())
}

/// Walks every component of `rel_dir` under `target_dir`, creating missing directories while
/// rejecting any symbolic link or Windows reparse point at every single step.
fn ensure_subpath_dirs_no_symlink(target_dir: &Path, rel_dir: &Path) -> Result<PathBuf, String> {
    reject_symlink_or_reparse(target_dir)?;
    let mut cur = target_dir.to_path_buf();
    for comp in rel_dir.components() {
        match comp {
            Component::Normal(seg) => {
                cur.push(seg);
                reject_symlink_or_reparse(&cur)?;
                match std::fs::symlink_metadata(&cur) {
                    Ok(meta) => {
                        if !meta.is_dir() {
                            return Err(format!(
                                "Expected directory but found non-directory at '{}'.",
                                cur.display()
                            ));
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        std::fs::create_dir(&cur).map_err(|e| {
                            format!("Failed to create directory '{}': {e}", cur.display())
                        })?;
                        reject_symlink_or_reparse(&cur)?;
                    }
                    Err(e) => {
                        return Err(format!("Failed inspecting '{}': {e}", cur.display()));
                    }
                }
            }
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(format!(
                    "Refusing unsafe relative path '{}' during extraction.",
                    rel_dir.display()
                ));
            }
        }
    }
    Ok(cur)
}

/// Creates a fresh temporary staging file in `parent_dir` using `create_new(true)` (never follows
/// symlinks), runs `writer`, flushes, verifies `dest_path` is not a symlink/reparse point, and
/// replaces `dest_path`.
fn write_file_safely_no_symlink<W>(
    parent_dir: &Path,
    dest_path: &Path,
    mut write_fn: W,
) -> Result<(), String>
where
    W: FnMut(&mut std::fs::File) -> Result<(), String>,
{
    reject_symlink_or_reparse(parent_dir)?;
    reject_symlink_or_reparse(dest_path)?;

    static TMP_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let pid = std::process::id();
    let mut tmp_path = None;
    let mut tmp_file = None;
    for attempt in 0..32u32 {
        let seq = TMP_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let candidate = parent_dir.join(format!(".singularity-stage-{pid}-{seq}-{attempt}.tmp"));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(f) => {
                tmp_path = Some(candidate);
                tmp_file = Some(f);
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => {
                return Err(format!(
                    "Failed to create staging file in '{}': {e}",
                    parent_dir.display()
                ));
            }
        }
    }
    let tmp_path = tmp_path.ok_or_else(|| {
        format!(
            "Failed to allocate unique staging file in '{}'.",
            parent_dir.display()
        )
    })?;
    let mut tmp_file = tmp_file.unwrap();

    if let Err(e) = write_fn(&mut tmp_file).and_then(|()| {
        tmp_file
            .flush()
            .map_err(|fe| format!("Disk flush error for '{}': {fe}", dest_path.display()))
    }) {
        drop(tmp_file);
        let _ = std::fs::remove_file(&tmp_path);
        return Err(e);
    }
    drop(tmp_file);

    // Re-verify destination is not a symlink / reparse point right before replacing
    if let Err(e) = reject_symlink_or_reparse(dest_path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(e);
    }

    if let Err(e) = std::fs::rename(&tmp_path, dest_path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(format!(
            "Failed to write '{}' (close Singularity if it is open): {e}",
            dest_path.display()
        ));
    }
    Ok(())
}

fn extract_zip_archive_to_dir<R: Read + Seek, F: Fn()>(
    archive: &mut zip::ZipArchive<R>,
    target_dir: &Path,
    progress: &Arc<Mutex<SharedProgress>>,
    notify: &F,
) -> Result<(), String> {
    ensure_real_root_dir(target_dir)?;
    set_step(
        progress,
        24.0,
        "Extracting Singularity + Pure Chromium runtime...",
        notify,
    );
    let mut total_uncompressed: u64 = 0;
    for i in 0..archive.len() {
        if let Ok(entry) = archive.by_index(i) {
            total_uncompressed = total_uncompressed.saturating_add(entry.size());
        }
    }
    let total_uncompressed = total_uncompressed.max(1);
    let mut written_total: u64 = 0;
    let mut buf = vec![0u8; 131_072];

    for i in 0..archive.len() {
        let mut entry = archive
            .by_index(i)
            .map_err(|e| format!("Failed reading bundle entry #{i}: {e}"))?;
        // Refuse symlink entries encoded inside the ZIP archive
        if entry
            .unix_mode()
            .is_some_and(|mode| (mode & 0o170_000) == 0o120_000)
        {
            return Err(format!(
                "Refusing symbolic link entry '{}' inside SFX bundle.",
                entry.name()
            ));
        }
        let Some(rel_path) = entry.enclosed_name().map(|p| p.to_path_buf()) else {
            continue;
        };
        if entry.is_dir() {
            ensure_subpath_dirs_no_symlink(target_dir, &rel_path)?;
            continue;
        }
        let parent_dir = if let Some(rel_parent) = rel_path.parent() {
            ensure_subpath_dirs_no_symlink(target_dir, rel_parent)?
        } else {
            reject_symlink_or_reparse(target_dir)?;
            target_dir.to_path_buf()
        };
        let file_name = rel_path.file_name().ok_or_else(|| {
            format!("Invalid file entry '{}' in SFX bundle.", rel_path.display())
        })?;
        let out_path = parent_dir.join(file_name);
        reject_symlink_or_reparse(&out_path)?;

        let display_name = file_name.to_str().unwrap_or("runtime");
        let step_lbl = format!("Extracting Pure Chromium ({display_name})...");
        write_file_safely_no_symlink(&parent_dir, &out_path, |out_file| {
            loop {
                let n = Read::read(&mut entry, &mut buf)
                    .map_err(|e| format!("Decompression error on '{display_name}': {e}"))?;
                if n == 0 {
                    break;
                }
                out_file
                    .write_all(&buf[..n])
                    .map_err(|e| format!("Disk write error on '{display_name}': {e}"))?;
                written_total = written_total.saturating_add(n as u64);
                let pct = 24.0 + (written_total as f32 / total_uncompressed as f32).min(1.0) * 48.0;
                set_step(progress, pct, &step_lbl, notify);
            }
            Ok(())
        })?;
    }
    Ok(())
}

fn parse_custom_dir_arg(args: &[String]) -> Option<String> {
    let mut custom_dir: Option<String> = None;
    let mut i = 1;
    while i < args.len() {
        if (args[i] == "--dir" || args[i] == "-d") && i + 1 < args.len() {
            let val = args[i + 1].trim();
            if !val.is_empty() {
                custom_dir = Some(val.to_string());
            }
            i += 2;
            continue;
        }
        if let Some(val) = args[i].strip_prefix("--dir=") {
            let val = val.trim();
            if !val.is_empty() {
                custom_dir = Some(val.to_string());
            }
        }
        i += 1;
    }
    custom_dir
}

fn main() {
    #[cfg(target_os = "windows")]
    {
        // Restrict default DLL search order strictly to System32 before loading any COM/Shell/GDI DLLs
        // to neutralize DLL hijacking from the user's Downloads or working directory.
        unsafe {
            let _ = windows::Win32::System::LibraryLoader::SetDefaultDllDirectories(
                windows::Win32::System::LibraryLoader::LOAD_LIBRARY_SEARCH_SYSTEM32,
            );
        }
    }

    let args: Vec<String> = std::env::args().collect();

    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!(
            "Singularity-Setup v{} (native Win32 installer, payload: {} bytes)",
            APP_VERSION,
            detect_payload_size_bytes()
        );
        return;
    }

    if args.iter().any(|a| a == "--verify-only") {
        assert!(
            EMBEDDED_SINGULARITY_ICO.len() > 4096,
            "Embedded singularity.ico looks truncated"
        );
        let sfx = match open_self_sfx_zip() {
            Ok(v) => v,
            Err(e) => {
                eprintln!("[ERROR] SFX integrity verification failed: {e}");
                std::process::exit(1);
            }
        };
        if let Some((mut archive, payload_len)) = sfx {
            assert!(
                payload_len > 10 * 1024 * 1024,
                "SFX Pure Chromium CEF bundle looks truncated ({payload_len} bytes)"
            );
            assert!(
                archive.by_name("singularity.exe").is_ok(),
                "SFX bundle missing singularity.exe"
            );
            assert!(
                archive.by_name("libcef.dll").is_ok(),
                "SFX bundle missing libcef.dll"
            );
            assert!(
                archive.by_name("icudtl.dat").is_ok(),
                "SFX bundle missing icudtl.dat"
            );
            assert!(
                archive.by_name("resources.pak").is_ok(),
                "SFX bundle missing resources.pak"
            );
            let auth_mode = if embedded_release_pubkey_hex().is_some() {
                "SGX1 SHA-256 + Ed25519"
            } else {
                "SGX1 SHA-256"
            };
            println!(
                "[OK] Singularity-Setup v{} (Pure Native Win32 + Pure Chromium CEF SFX, {}) verified — bundle = {:.2} MB ({} files), icon = {} KB",
                APP_VERSION,
                auth_mode,
                payload_len as f64 / (1024.0 * 1024.0),
                archive.len(),
                EMBEDDED_SINGULARITY_ICO.len() / 1024
            );
        } else if EMBEDDED_SINGULARITY_EXE.starts_with(b"PK\x03\x04") {
            let mut archive = zip::ZipArchive::new(std::io::Cursor::new(EMBEDDED_SINGULARITY_EXE))
                .expect("Embedded ZIP bundle is corrupted");
            assert!(
                archive.by_name("singularity.exe").is_ok(),
                "Embedded ZIP bundle missing singularity.exe"
            );
            assert!(
                archive.by_name("libcef.dll").is_ok(),
                "Embedded ZIP bundle missing libcef.dll"
            );
            println!(
                "[OK] Singularity-Setup v{} (Pure Native Win32 + Pure Chromium CEF) verified — bundle = {:.2} MB ({} files), icon = {} KB",
                APP_VERSION,
                EMBEDDED_SINGULARITY_EXE.len() as f64 / (1024.0 * 1024.0),
                archive.len(),
                EMBEDDED_SINGULARITY_ICO.len() / 1024
            );
        } else {
            if cfg!(target_os = "windows") {
                eprintln!(
                    "[ERROR] Windows Singularity-Setup requires a sealed SGX1 Pure Chromium CEF SFX bundle (none attached)."
                );
                std::process::exit(1);
            }
            assert!(
                EMBEDDED_SINGULARITY_EXE.len() > 512 * 1024,
                "Embedded singularity payload looks truncated (no SFX ZIP overlay attached)"
            );
            println!(
                "[OK] Singularity-Setup v{} (Pure Native) verified — payload = {:.2} MB, icon = {} KB",
                APP_VERSION,
                EMBEDDED_SINGULARITY_EXE.len() as f64 / (1024.0 * 1024.0),
                EMBEDDED_SINGULARITY_ICO.len() / 1024
            );
        }
        return;
    }

    let silent = args
        .iter()
        .any(|a| a == "--silent" || a.eq_ignore_ascii_case("/s") || a == "--quiet");
    let launch_flag = args.iter().any(|a| a == "--launch");
    let custom_dir = parse_custom_dir_arg(&args);

    if silent || cfg!(not(target_os = "windows")) {
        let install_dir = match custom_dir {
            Some(dir) => dir,
            None => match default_install_dir() {
                Ok(dir) => dir.to_string_lossy().into_owned(),
                Err(e) => {
                    eprintln!("[Singularity-Setup] Error: {e}");
                    std::process::exit(1);
                }
            },
        };
        let opts = InstallOptions {
            install_dir,
            desktop_shortcut: true,
            start_menu_shortcut: true,
            init_roaming_vault: true,
            launch_after_install: launch_flag,
        };
        let progress = Arc::new(Mutex::new(SharedProgress {
            phase: InstallPhase::Idle,
            target_pct: 0.0,
            step_label: String::new(),
            installed_exe: String::new(),
            error_msg: String::new(),
        }));
        if let Err(e) = perform_installation(&opts, &progress, || {}) {
            eprintln!("[Singularity-Setup] Error: {e}");
            std::process::exit(1);
        }
        let g = progress.lock().unwrap_or_else(|e| e.into_inner());
        println!(
            "[Singularity-Setup] Installed Singularity v{} to {}",
            APP_VERSION, g.installed_exe
        );
        return;
    }

    #[cfg(target_os = "windows")]
    {
        if let Err(e) = win32_gui::run_native_installer(custom_dir) {
            eprintln!("[Singularity-Setup] GUI error: {e}");
            std::process::exit(1);
        }
    }
}

fn set_step<F: Fn()>(
    progress: &Arc<Mutex<SharedProgress>>,
    pct: f32,
    label: &str,
    notify: &F,
) {
    {
        let mut g = progress.lock().unwrap_or_else(|e| e.into_inner());
        g.phase = InstallPhase::Running;
        g.target_pct = pct;
        g.step_label = label.to_string();
    }
    notify();
}

fn perform_installation<F: Fn()>(
    opts: &InstallOptions,
    progress: &Arc<Mutex<SharedProgress>>,
    notify: F,
) -> Result<PathBuf, String> {
    let sfx_opt = open_self_sfx_zip()?;
    if sfx_opt.is_none() {
        if cfg!(target_os = "windows") && !EMBEDDED_SINGULARITY_EXE.starts_with(b"PK\x03\x04") {
            return Err(
                "Windows installer is missing its sealed SGX1 Pure Chromium CEF bundle (single-binary fallback is unsupported on Windows). Please re-download the official Singularity-setup.exe."
                    .into(),
            );
        }
        if EMBEDDED_SINGULARITY_EXE.is_empty() {
            return Err("Installer binary was built without an embedded singularity payload.".into());
        }
    }
    let target_dir = PathBuf::from(opts.install_dir.trim());
    if target_dir.as_os_str().is_empty() {
        return Err("Installation path is empty.".into());
    }

    let exe_name = if cfg!(target_os = "windows") {
        "singularity.exe"
    } else {
        "singularity"
    };
    let exe_path = target_dir.join(exe_name);
    let ico_path = target_dir.join("singularity.ico");

    set_step(
        progress,
        12.0,
        "Checking for running Singularity processes...",
        &notify,
    );

    #[cfg(target_os = "windows")]
    {
        let terminated_live = win32_ops::terminate_running_singularity(&target_dir, &exe_path)?;
        if terminated_live {
            // The installer intentionally closed a running Singularity instance to upgrade it;
            // remove `running.lock` and set `planned_restart.flag` so the updated browser restores
            // all open windows cleanly without a false-positive crash dialog.
            if let Ok(roam) = roaming_singularity_dir() {
                if ensure_real_root_dir(&roam).is_ok() {
                    let lock_file = roam.join("running.lock");
                    if reject_symlink_or_reparse(&lock_file).is_ok() {
                        let _ = std::fs::remove_file(&lock_file);
                    }
                    let flag_file = roam.join("planned_restart.flag");
                    if reject_symlink_or_reparse(&flag_file).is_ok() {
                        let _ = write_file_safely_no_symlink(&roam, &flag_file, |f| {
                            f.write_all(b"1").map_err(|e| e.to_string())
                        });
                    }
                }
            }
        }
    }

    ensure_real_root_dir(&target_dir)?;

    // Remove legacy v1.0.x WebView2Loader.dll if upgrading in-place (never follow symlinks)
    let legacy_wv2 = target_dir.join("WebView2Loader.dll");
    reject_symlink_or_reparse(&legacy_wv2)?;
    let _ = std::fs::remove_file(&legacy_wv2);

    // Extract verified Pure Chromium CEF ZIP bundle (SGX1 SFX overlay preferred) or Unix single binary
    if let Some((mut archive, _)) = sfx_opt {
        extract_zip_archive_to_dir(&mut archive, &target_dir, progress, &notify)?;
    } else if EMBEDDED_SINGULARITY_EXE.starts_with(b"PK\x03\x04") {
        let mut archive = zip::ZipArchive::new(std::io::Cursor::new(EMBEDDED_SINGULARITY_EXE))
            .map_err(|e| format!("Corrupted embedded Chromium bundle: {e}"))?;
        extract_zip_archive_to_dir(&mut archive, &target_dir, progress, &notify)?;
    } else {
        if cfg!(target_os = "windows") {
            return Err(
                "Windows installer requires a Pure Chromium CEF bundle; single-binary fallback is unsupported."
                    .into(),
            );
        }
        let extract_label = format!("Extracting native browser {}...", exe_name);
        set_step(progress, 24.0, &extract_label, &notify);
        reject_symlink_or_reparse(&exe_path)?;
        let total = EMBEDDED_SINGULARITY_EXE.len().max(1);
        let chunk_size = 131_072; // 128 KB
        let mut written = 0usize;
        write_file_safely_no_symlink(&target_dir, &exe_path, |file| {
            for chunk in EMBEDDED_SINGULARITY_EXE.chunks(chunk_size) {
                file.write_all(chunk)
                    .map_err(|e| format!("Disk write error: {e}"))?;
                written += chunk.len();
                let pct = 24.0 + (written as f32 / total as f32) * 48.0;
                set_step(progress, pct, &extract_label, &notify);
            }
            Ok(())
        })?;
    }

    reject_symlink_or_reparse(&ico_path)?;
    write_file_safely_no_symlink(&target_dir, &ico_path, |f| {
        f.write_all(EMBEDDED_SINGULARITY_ICO)
            .map_err(|e| format!("Failed writing singularity.ico: {e}"))
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        reject_symlink_or_reparse(&exe_path)?;
        if let Ok(meta) = std::fs::symlink_metadata(&exe_path) {
            let mut perms = meta.permissions();
            perms.set_mode(0o755);
            let _ = std::fs::set_permissions(&exe_path, perms);
        }
    }

    if opts.init_roaming_vault {
        set_step(
            progress,
            76.0,
            "Preparing encrypted Roaming\\.singularity profile...",
            &notify,
        );
        let roaming = roaming_singularity_dir()?;
        ensure_real_root_dir(&roaming)?;
        let _cef_dir = ensure_subpath_dirs_no_symlink(&roaming, Path::new("cef-profile"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&roaming, std::fs::Permissions::from_mode(0o700));
            let _ = std::fs::set_permissions(&_cef_dir, std::fs::Permissions::from_mode(0o700));
        }
        let readme_sec = roaming.join("SECURITY-README.txt");
        reject_symlink_or_reparse(&readme_sec)?;
        if std::fs::symlink_metadata(&readme_sec).is_err() {
            let _ = write_file_safely_no_symlink(&roaming, &readme_sec, |f| {
                f.write_all(
                    b"Singularity Encrypted Roaming Profile (.singularity)\r\n\
                     ====================================================\r\n\
                     - master.dpapi : 256-bit key sealed by Windows DPAPI (CryptProtectData)\r\n\
                     - tokens.enc   : XChaCha20-Poly1305 AEAD encrypted session tokens (Google, Microsoft, GitHub, Discord, OAuth/SSO)\r\n\
                     - vault.singularity-vault : Argon2id + XChaCha20-Poly1305 encrypted password & 2FA vault\r\n\
                     - profile.json : User preferences, bookmarks, and workspace configuration\r\n\
                     - settings.toml: Custom overrides across the 2,165 Singularity engine settings\r\n",
                )
                .map_err(|e| e.to_string())
            });
        }
    }

    #[cfg(target_os = "windows")]
    {
        if opts.start_menu_shortcut {
            set_step(
                progress,
                88.0,
                "Registering in Windows Installed Apps...",
                &notify,
            );
            win32_ops::register_uninstall_registry(&target_dir, &exe_path, &ico_path);
        }

        if opts.desktop_shortcut || opts.start_menu_shortcut {
            set_step(
                progress,
                95.0,
                "Creating Desktop and Start Menu shortcuts...",
                &notify,
            );
            win32_ops::create_shell_shortcuts(
                &target_dir,
                &exe_path,
                &ico_path,
                opts.desktop_shortcut,
                opts.start_menu_shortcut,
            );
        }
    }

    {
        let mut g = progress.lock().unwrap_or_else(|e| e.into_inner());
        g.phase = InstallPhase::Done;
        g.target_pct = 100.0;
        g.step_label = "Installation complete — Singularity is ready!".to_string();
        g.installed_exe = exe_path.to_string_lossy().into_owned();
        g.error_msg.clear();
    }
    notify();

    if opts.launch_after_install {
        #[cfg(target_os = "windows")]
        win32_ops::launch_exe_detached(&exe_path, &target_dir);
    }

    Ok(exe_path)
}

#[cfg(target_os = "windows")]
mod win32_ops {
    use super::{detect_installed_uncompressed_kb, APP_VERSION};
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant};
    use windows::core::{Interface, PCWSTR, PWSTR};
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Com::{
        CoCreateInstance, CoInitializeEx, CoTaskMemFree, CoUninitialize, IPersistFile,
        CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED,
    };
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    use windows::Win32::System::Registry::{
        RegCloseKey, RegCreateKeyExW, RegSetValueExW, HKEY, HKEY_CURRENT_USER, KEY_WRITE,
        REG_DWORD, REG_OPTION_NON_VOLATILE, REG_SZ,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, TerminateProcess, WaitForSingleObject,
        PROCESS_NAME_FORMAT, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
        PROCESS_TERMINATE,
    };
    use windows::Win32::UI::Shell::{
        FOLDERID_Desktop, FOLDERID_Programs, IShellLinkW, SHGetKnownFolderPath, ShellExecuteW,
        ShellLink, KF_FLAG_DEFAULT,
    };
    use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    pub fn to_wide(s: &str) -> Vec<u16> {
        OsStr::new(s).encode_wide().chain(Some(0)).collect()
    }

    pub fn path_to_wide(p: &Path) -> Vec<u16> {
        p.as_os_str().encode_wide().chain(Some(0)).collect()
    }

    fn normalize_win_path(p: &Path) -> String {
        let s = std::fs::canonicalize(p)
            .unwrap_or_else(|_| p.to_path_buf())
            .to_string_lossy()
            .into_owned();
        s.strip_prefix(r"\\?\")
            .unwrap_or(&s)
            .replace('/', "\\")
            .to_ascii_lowercase()
    }

    fn find_matching_install_pids(expected_dir_prefix: &str, expected_exe: &str) -> Vec<u32> {
        let mut pids = Vec::new();
        unsafe {
            let Ok(snap) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) else {
                return pids;
            };
            let my_pid = std::process::id();
            let mut entry = PROCESSENTRY32W {
                dwSize: core::mem::size_of::<PROCESSENTRY32W>() as u32,
                ..Default::default()
            };

            if Process32FirstW(snap, &mut entry).is_ok() {
                loop {
                    if entry.th32ProcessID != my_pid {
                        if let Ok(proc_h) = OpenProcess(
                            PROCESS_QUERY_LIMITED_INFORMATION,
                            false,
                            entry.th32ProcessID,
                        ) {
                            let mut path_buf = vec![0u16; 1024];
                            let mut len = path_buf.len() as u32;
                            if QueryFullProcessImageNameW(
                                proc_h,
                                PROCESS_NAME_FORMAT(0),
                                PWSTR(path_buf.as_mut_ptr()),
                                &mut len,
                            )
                            .is_ok()
                            {
                                let actual =
                                    String::from_utf16_lossy(&path_buf[..len as usize]);
                                let norm = normalize_win_path(Path::new(&actual));
                                if norm == expected_exe
                                    || (!expected_dir_prefix.is_empty()
                                        && norm.starts_with(expected_dir_prefix))
                                {
                                    pids.push(entry.th32ProcessID);
                                }
                            }
                            let _ = CloseHandle(proc_h);
                        }
                    }
                    if Process32NextW(snap, &mut entry).is_err() {
                        break;
                    }
                }
            }
            let _ = CloseHandle(snap);
        }
        pids
    }

    fn locked_binaries_released(target_dir: &Path, target_exe: &Path) -> bool {
        for candidate in [target_exe.to_path_buf(), target_dir.join("libcef.dll")] {
            if candidate.is_file() {
                if std::fs::OpenOptions::new()
                    .write(true)
                    .open(&candidate)
                    .is_err()
                {
                    return false;
                }
            }
        }
        true
    }

    /// Terminates running `singularity.exe` and any Chromium/CEF subprocesses executing from
    /// `target_dir`, polling with timeout until all matching processes exit and file locks on
    /// `singularity.exe` / `libcef.dll` are released before overwriting.
    /// Returns `Ok(true)` if at least one live matching process was terminated.
    pub fn terminate_running_singularity(
        target_dir: &Path,
        target_exe: &Path,
    ) -> Result<bool, String> {
        let expected_exe = normalize_win_path(target_exe);
        let dir_norm = normalize_win_path(target_dir);
        let expected_dir_prefix = if dir_norm.is_empty() {
            String::new()
        } else if dir_norm.ends_with('\\') {
            dir_norm
        } else {
            format!("{dir_norm}\\")
        };

        let mut terminated_any = false;
        let deadline = Instant::now() + Duration::from_secs(10);

        loop {
            let pids = find_matching_install_pids(&expected_dir_prefix, &expected_exe);
            if pids.is_empty() {
                if !terminated_any || locked_binaries_released(target_dir, target_exe) {
                    return Ok(terminated_any);
                }
            } else {
                terminated_any = true;
                for pid in pids {
                    unsafe {
                        if let Ok(proc_h) =
                            OpenProcess(PROCESS_TERMINATE | PROCESS_SYNCHRONIZE, false, pid)
                        {
                            let _ = TerminateProcess(proc_h, 0);
                            let _ = WaitForSingleObject(proc_h, 1_000);
                            let _ = CloseHandle(proc_h);
                        }
                    }
                }
            }

            if Instant::now() >= deadline {
                return Err(
                    "Timed out waiting for running Singularity / Chromium (CEF) processes to exit. Please close Singularity and retry."
                        .to_string(),
                );
            }
            std::thread::sleep(Duration::from_millis(150));
        }
    }

    /// Writes `HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\Singularity` via `advapi32.dll`.
    pub fn register_uninstall_registry(install_dir: &Path, exe_path: &Path, ico_path: &Path) {
        unsafe {
            let subkey = to_wide("Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Singularity");
            let mut hkey = HKEY::default();
            let err = RegCreateKeyExW(
                HKEY_CURRENT_USER,
                PCWSTR(subkey.as_ptr()),
                None,
                PCWSTR::null(),
                REG_OPTION_NON_VOLATILE,
                KEY_WRITE,
                None,
                &mut hkey,
                None,
            );
            if err.0 != 0 {
                return;
            }

            let set_sz = |name: &str, val: &str| {
                let n = to_wide(name);
                let v = to_wide(val);
                let bytes =
                    core::slice::from_raw_parts(v.as_ptr() as *const u8, v.len() * 2);
                let _ = RegSetValueExW(hkey, PCWSTR(n.as_ptr()), None, REG_SZ, Some(bytes));
            };
            let set_dword = |name: &str, val: u32| {
                let n = to_wide(name);
                let bytes = val.to_le_bytes();
                let _ = RegSetValueExW(hkey, PCWSTR(n.as_ptr()), None, REG_DWORD, Some(&bytes));
            };

            let uninst_cmd = format!("\"{}\" --uninstall", exe_path.display());
            let quiet_uninst_cmd = format!("\"{}\" --uninstall --silent", exe_path.display());
            let icon_loc = format!("{},0", ico_path.display());
            let est_kb = detect_installed_uncompressed_kb();

            set_sz("DisplayName", "Singularity");
            set_sz("DisplayVersion", APP_VERSION);
            set_sz("Publisher", "Singularity");
            set_sz("DisplayIcon", &icon_loc);
            set_sz("InstallLocation", &install_dir.to_string_lossy());
            set_sz("UninstallString", &uninst_cmd);
            set_sz("QuietUninstallString", &quiet_uninst_cmd);
            set_dword("EstimatedSize", est_kb);
            set_dword("NoModify", 1);
            set_dword("NoRepair", 1);

            let _ = RegCloseKey(hkey);
        }
    }

    fn known_folder(rfid: *const windows::core::GUID) -> Option<PathBuf> {
        unsafe {
            let pwstr = SHGetKnownFolderPath(rfid, KF_FLAG_DEFAULT, None).ok()?;
            let mut len = 0usize;
            while *pwstr.0.add(len) != 0 {
                len += 1;
            }
            let slice = core::slice::from_raw_parts(pwstr.0, len);
            let s = String::from_utf16_lossy(slice);
            CoTaskMemFree(Some(pwstr.0 as *const _));
            if s.is_empty() {
                None
            } else {
                Some(PathBuf::from(s))
            }
        }
    }

    /// Creates real Windows `.lnk` shortcuts via COM `IShellLinkW` + `IPersistFile` (zero `WScript.Shell`).
    pub fn create_shell_shortcuts(
        install_dir: &Path,
        exe_path: &Path,
        ico_path: &Path,
        desktop: bool,
        start_menu: bool,
    ) {
        unsafe {
            let hr = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
            let need_uninit = hr.is_ok();

            let write_lnk = |lnk_path: &Path| {
                let Ok(link) =
                    CoCreateInstance::<_, IShellLinkW>(&ShellLink, None, CLSCTX_INPROC_SERVER)
                else {
                    return;
                };
                let exe_w = path_to_wide(exe_path);
                let dir_w = path_to_wide(install_dir);
                let ico_w = path_to_wide(ico_path);
                let desc_w = to_wide("Singularity Browser — Privacy & High Performance");

                let _ = link.SetPath(PCWSTR(exe_w.as_ptr()));
                let _ = link.SetWorkingDirectory(PCWSTR(dir_w.as_ptr()));
                let _ = link.SetIconLocation(PCWSTR(ico_w.as_ptr()), 0);
                let _ = link.SetDescription(PCWSTR(desc_w.as_ptr()));

                if let Ok(persist) = link.cast::<IPersistFile>() {
                    let lnk_w = path_to_wide(lnk_path);
                    let _ = persist.Save(PCWSTR(lnk_w.as_ptr()), true);
                }
            };

            if desktop {
                if let Some(desk) = known_folder(&FOLDERID_Desktop) {
                    write_lnk(&desk.join("Singularity.lnk"));
                }
            }
            if start_menu {
                if let Some(progs) = known_folder(&FOLDERID_Programs) {
                    write_lnk(&progs.join("Singularity.lnk"));
                }
            }

            if need_uninit {
                CoUninitialize();
            }
        }
    }

    pub fn launch_exe_detached(exe_path: &Path, work_dir: &Path) {
        unsafe {
            let op = to_wide("open");
            let file = path_to_wide(exe_path);
            let dir = path_to_wide(work_dir);
            let _ = ShellExecuteW(
                None,
                PCWSTR(op.as_ptr()),
                PCWSTR(file.as_ptr()),
                PCWSTR::null(),
                PCWSTR(dir.as_ptr()),
                SW_SHOWNORMAL,
            );
        }
    }
}

#[cfg(target_os = "windows")]
mod win32_gui {
    use super::win32_ops::{launch_exe_detached, to_wide};
    use super::{
        default_install_dir, detect_payload_size_bytes, perform_installation,
        roaming_singularity_dir, InstallOptions, InstallPhase, SharedProgress, APP_VERSION,
        EMBEDDED_LOGO_128_RGBA,
    };
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{COLORREF, HWND, LPARAM, LRESULT, POINT, RECT, WPARAM};
    use windows::Win32::Graphics::Dwm::{
        DwmSetWindowAttribute, DWMWA_USE_IMMERSIVE_DARK_MODE, DWMWA_WINDOW_CORNER_PREFERENCE,
        DWMWCP_ROUND,
    };
    use windows::Win32::Graphics::Gdi::{
        BeginPaint, BitBlt, CreateCompatibleDC, CreateDIBSection, CreateFontW, DeleteDC,
        DeleteObject, DrawTextW, EndPaint, InvalidateRect, SelectObject, SetBkMode, SetTextColor,
        UpdateWindow, BITMAPINFO, BITMAPINFOHEADER, BI_RGB, CLEARTYPE_QUALITY, CLIP_DEFAULT_PRECIS,
        DEFAULT_CHARSET, DIB_RGB_COLORS, DT_CALCRECT, DT_END_ELLIPSIS, DT_LEFT, DT_NOPREFIX,
        DT_RIGHT, DT_SINGLELINE, DT_VCENTER, DT_WORDBREAK, FW_BOLD, FW_MEDIUM, FW_NORMAL,
        FW_SEMIBOLD, HFONT, OUT_DEFAULT_PRECIS, PAINTSTRUCT, SRCCOPY, TRANSPARENT,
    };
    use windows::Win32::System::Com::{
        CoCreateInstance, CoInitializeEx, CoTaskMemFree, CoUninitialize, CLSCTX_INPROC_SERVER,
        COINIT_APARTMENTTHREADED,
    };
    use windows::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows::Win32::UI::HiDpi::GetDpiForWindow;
    use windows::Win32::UI::Input::KeyboardAndMouse::{
        ReleaseCapture, SetCapture, TrackMouseEvent, TME_LEAVE, TRACKMOUSEEVENT,
    };
    use windows::Win32::UI::Shell::{
        FileOpenDialog, IFileOpenDialog, IShellItem, SHCreateItemFromParsingName,
        FOS_FORCEFILESYSTEM, FOS_NOCHANGEDIR, FOS_PICKFOLDERS, SIGDN_FILESYSPATH,
    };
    use windows::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetClientRect,
        GetMessageW, GetSystemMetrics, GetWindowLongPtrW, IsWindow, KillTimer, LoadCursorW,
        LoadIconW, PostMessageW, PostQuitMessage, RegisterClassExW, SetCursor, SetTimer,
        SetWindowLongPtrW, ShowWindow, TranslateMessage, CS_HREDRAW, CS_VREDRAW, GWLP_USERDATA,
        HTCAPTION, HTCLIENT, IDC_ARROW, IDC_HAND, MSG, SM_CXSCREEN, SM_CYSCREEN, SW_MINIMIZE,
        SW_SHOW, WINDOW_EX_STYLE, WM_APP, WM_CLOSE, WM_DESTROY, WM_ERASEBKGND, WM_LBUTTONDOWN,
        WM_LBUTTONUP, WM_MOUSEMOVE, WM_NCHITTEST, WM_PAINT, WM_SETCURSOR, WM_TIMER, WNDCLASSEXW,
        WS_CLIPCHILDREN, WS_MINIMIZEBOX, WS_POPUP, WS_SYSMENU,
    };

    const WM_MOUSELEAVE: u32 = 0x02A3;
    const WM_APP_PROGRESS: u32 = WM_APP + 1;
    const TIMER_ANIM: usize = 1;

    const LOGICAL_W: f32 = 660.0;
    const LOGICAL_H: f32 = 500.0;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum HitZone {
        None,
        CloseDot,
        MinDot,
        BrowseBtn,
        ChkDesktop,
        ChkStartMenu,
        ChkRoaming,
        ChkLaunch,
        CancelBtn,
        PrimaryBtn,
    }

    #[derive(Clone, Copy, Default)]
    struct RectF {
        x0: f32,
        y0: f32,
        x1: f32,
        y1: f32,
    }

    impl RectF {
        fn contains(&self, x: f32, y: f32) -> bool {
            x >= self.x0 && x <= self.x1 && y >= self.y0 && y <= self.y1
        }
        fn to_win_rect(self) -> RECT {
            RECT {
                left: self.x0.round() as i32,
                top: self.y0.round() as i32,
                right: self.x1.round() as i32,
                bottom: self.y1.round() as i32,
            }
        }
    }

    struct Layout {
        scale: f32,
        close_dot: (f32, f32, f32),
        min_dot: (f32, f32, f32),
        dis_dot: (f32, f32, f32),
        titlebar_h: f32,
        logo_rect: RectF,
        card_rect: RectF,
        dir_box: RectF,
        browse_btn: RectF,
        roaming_box: RectF,
        chk_rects: [RectF; 4],
        chk_boxes: [RectF; 4],
        prog_bar: RectF,
        cancel_btn: RectF,
        primary_btn: RectF,
    }

    impl Layout {
        fn compute(w: f32, h: f32, s: f32) -> Self {
            let titlebar_h = 40.0 * s;
            let dot_y = titlebar_h * 0.5;
            let dot_r = 6.2 * s;
            let close_dot = (22.0 * s, dot_y, dot_r);
            let min_dot = (42.0 * s, dot_y, dot_r);
            let dis_dot = (62.0 * s, dot_y, dot_r);

            let pad_x = 30.0 * s;
            let logo_size = 68.0 * s;
            let hero_top = titlebar_h + 20.0 * s;
            let logo_rect = RectF {
                x0: pad_x,
                y0: hero_top,
                x1: pad_x + logo_size,
                y1: hero_top + logo_size,
            };

            let card_top = hero_top + logo_size + 18.0 * s;
            let footer_h = 62.0 * s;
            let card_bot = h - footer_h;
            let card_rect = RectF {
                x0: pad_x,
                y0: card_top,
                x1: w - pad_x,
                y1: card_bot,
            };

            let cx0 = card_rect.x0 + 18.0 * s;
            let cx1 = card_rect.x1 - 18.0 * s;

            let browse_w = 96.0 * s;
            let dir_y0 = card_top + 36.0 * s;
            let dir_y1 = dir_y0 + 34.0 * s;
            let dir_box = RectF {
                x0: cx0,
                y0: dir_y0,
                x1: cx1 - browse_w - 8.0 * s,
                y1: dir_y1,
            };
            let browse_btn = RectF {
                x0: cx1 - browse_w,
                y0: dir_y0,
                x1: cx1,
                y1: dir_y1,
            };

            let roam_y0 = dir_y1 + 12.0 * s;
            let roam_y1 = roam_y0 + 32.0 * s;
            let roaming_box = RectF {
                x0: cx0,
                y0: roam_y0,
                x1: cx1,
                y1: roam_y1,
            };

            let chk_top1 = roam_y1 + 15.0 * s;
            let chk_top2 = chk_top1 + 28.0 * s;
            let mid_x = (cx0 + cx1) * 0.5 + 8.0 * s;
            let box_sz = 16.0 * s;

            let chk_rects = [
                RectF {
                    x0: cx0,
                    y0: chk_top1,
                    x1: mid_x - 8.0 * s,
                    y1: chk_top1 + 22.0 * s,
                },
                RectF {
                    x0: mid_x,
                    y0: chk_top1,
                    x1: cx1,
                    y1: chk_top1 + 22.0 * s,
                },
                RectF {
                    x0: cx0,
                    y0: chk_top2,
                    x1: mid_x - 8.0 * s,
                    y1: chk_top2 + 22.0 * s,
                },
                RectF {
                    x0: mid_x,
                    y0: chk_top2,
                    x1: cx1,
                    y1: chk_top2 + 22.0 * s,
                },
            ];
            let mut chk_boxes = [RectF::default(); 4];
            for i in 0..4 {
                let cy = (chk_rects[i].y0 + chk_rects[i].y1) * 0.5;
                chk_boxes[i] = RectF {
                    x0: chk_rects[i].x0,
                    y0: cy - box_sz * 0.5,
                    x1: chk_rects[i].x0 + box_sz,
                    y1: cy + box_sz * 0.5,
                };
            }

            let prog_y0 = chk_top2 + 38.0 * s;
            let prog_bar = RectF {
                x0: cx0,
                y0: prog_y0 + 20.0 * s,
                x1: cx1,
                y1: prog_y0 + 29.0 * s,
            };

            let btn_h = 36.0 * s;
            let btn_y0 = h - footer_h + (footer_h - btn_h) * 0.5 - 2.0 * s;
            let btn_y1 = btn_y0 + btn_h;
            let prim_w = 205.0 * s;
            let canc_w = 94.0 * s;

            let primary_btn = RectF {
                x0: w - pad_x - prim_w,
                y0: btn_y0,
                x1: w - pad_x,
                y1: btn_y1,
            };
            let cancel_btn = RectF {
                x0: primary_btn.x0 - 10.0 * s - canc_w,
                y0: btn_y0,
                x1: primary_btn.x0 - 10.0 * s,
                y1: btn_y1,
            };

            Self {
                scale: s,
                close_dot,
                min_dot,
                dis_dot,
                titlebar_h,
                logo_rect,
                card_rect,
                dir_box,
                browse_btn,
                roaming_box,
                chk_rects,
                chk_boxes,
                prog_bar,
                cancel_btn,
                primary_btn,
            }
        }

        fn hit_test(&self, x: f32, y: f32, phase: InstallPhase) -> HitZone {
            let pad = 3.0 * self.scale;
            let in_circle = |(cx, cy, r): (f32, f32, f32)| -> bool {
                let dx = x - cx;
                let dy = y - cy;
                let hit_r = r + pad;
                dx * dx + dy * dy <= hit_r * hit_r
            };
            if in_circle(self.close_dot) && phase != InstallPhase::Running {
                return HitZone::CloseDot;
            }
            if in_circle(self.min_dot) {
                return HitZone::MinDot;
            }
            if phase == InstallPhase::Idle || phase == InstallPhase::Error {
                if self.browse_btn.contains(x, y) || self.dir_box.contains(x, y) {
                    return HitZone::BrowseBtn;
                }
                if self.chk_rects[0].contains(x, y) {
                    return HitZone::ChkDesktop;
                }
                if self.chk_rects[1].contains(x, y) {
                    return HitZone::ChkStartMenu;
                }
                if self.chk_rects[2].contains(x, y) {
                    return HitZone::ChkRoaming;
                }
                if self.cancel_btn.contains(x, y) {
                    return HitZone::CancelBtn;
                }
            }
            if phase != InstallPhase::Running && self.chk_rects[3].contains(x, y) {
                return HitZone::ChkLaunch;
            }
            if phase != InstallPhase::Running && self.primary_btn.contains(x, y) {
                return HitZone::PrimaryBtn;
            }
            HitZone::None
        }
    }

    struct AppState {
        install_dir: String,
        roaming_dir: String,
        chk_desktop: bool,
        chk_start_menu: bool,
        chk_roaming: bool,
        chk_launch: bool,
        hover: HitZone,
        pressed: HitZone,
        tracking_mouse: bool,
        visual_pct: f32,
        progress: Arc<Mutex<SharedProgress>>,
        window_alive: Arc<AtomicBool>,
    }

    pub fn run_native_installer(initial_install_dir: Option<String>) -> Result<(), String> {
        let initial_dir = match initial_install_dir
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
        {
            Some(dir) => dir,
            None => default_install_dir()?.to_string_lossy().into_owned(),
        };
        let initial_roaming = roaming_singularity_dir()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| "%APPDATA%\\.singularity".to_string());

        unsafe {
            let co_hr = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
            let hinst = GetModuleHandleW(PCWSTR::null())
                .map_err(|e| format!("GetModuleHandleW: {e}"))?;

            let class_name = to_wide("SingularityNativeSetupWndClass");
            let app_icon = LoadIconW(Some(hinst.into()), PCWSTR(1usize as *const u16)).ok();
            let arrow_cur = LoadCursorW(None, IDC_ARROW).ok();

            let wc = WNDCLASSEXW {
                cbSize: core::mem::size_of::<WNDCLASSEXW>() as u32,
                style: CS_HREDRAW | CS_VREDRAW,
                lpfnWndProc: Some(wnd_proc),
                hInstance: hinst.into(),
                hIcon: app_icon.unwrap_or_default(),
                hIconSm: app_icon.unwrap_or_default(),
                hCursor: arrow_cur.unwrap_or_default(),
                lpszClassName: PCWSTR(class_name.as_ptr()),
                ..Default::default()
            };
            RegisterClassExW(&wc);

            let screen_w = GetSystemMetrics(SM_CXSCREEN);
            let screen_h = GetSystemMetrics(SM_CYSCREEN);

            // Initial size at 96 DPI, resized cleanly once GetDpiForWindow is queried
            let init_w = LOGICAL_W as i32;
            let init_h = LOGICAL_H as i32;
            let init_x = ((screen_w - init_w) / 2).max(0);
            let init_y = ((screen_h - init_h) / 2).max(0);

            let state = Box::new(std::cell::RefCell::new(AppState {
                install_dir: initial_dir,
                roaming_dir: initial_roaming,
                chk_desktop: true,
                chk_start_menu: true,
                chk_roaming: true,
                chk_launch: true,
                hover: HitZone::None,
                pressed: HitZone::None,
                tracking_mouse: false,
                visual_pct: 0.0,
                progress: Arc::new(Mutex::new(SharedProgress {
                    phase: InstallPhase::Idle,
                    target_pct: 0.0,
                    step_label: "Ready to install Singularity on this computer.".into(),
                    installed_exe: String::new(),
                    error_msg: String::new(),
                })),
                window_alive: Arc::new(AtomicBool::new(true)),
            }));
            let state_ptr = Box::into_raw(state);

            let title = to_wide("Singularity Browser Setup");
            let hwnd = CreateWindowExW(
                WINDOW_EX_STYLE(0),
                PCWSTR(class_name.as_ptr()),
                PCWSTR(title.as_ptr()),
                WS_POPUP | WS_SYSMENU | WS_MINIMIZEBOX | WS_CLIPCHILDREN,
                init_x,
                init_y,
                init_w,
                init_h,
                None,
                None,
                Some(hinst.into()),
                None,
            )
            .map_err(|e| {
                let _ = Box::from_raw(state_ptr);
                format!("CreateWindowExW: {e}")
            })?;

            SetWindowLongPtrW(hwnd, GWLP_USERDATA, state_ptr as isize);

            // Scale window cleanly to monitor DPI
            let dpi = GetDpiForWindow(hwnd);
            let scale = if dpi > 0 { dpi as f32 / 96.0 } else { 1.0 };
            if (scale - 1.0).abs() > 0.01 {
                let sw = (LOGICAL_W * scale).round() as i32;
                let sh = (LOGICAL_H * scale).round() as i32;
                let sx = ((screen_w - sw) / 2).max(0);
                let sy = ((screen_h - sh) / 2).max(0);
                let _ = windows::Win32::UI::WindowsAndMessaging::SetWindowPos(
                    hwnd,
                    None,
                    sx,
                    sy,
                    sw,
                    sh,
                    windows::Win32::UI::WindowsAndMessaging::SWP_NOZORDER
                        | windows::Win32::UI::WindowsAndMessaging::SWP_NOACTIVATE,
                );
            }

            // Enable Windows 11 hardware rounded corners + dark window frame
            let dark: i32 = 1;
            let _ = DwmSetWindowAttribute(
                hwnd,
                DWMWA_USE_IMMERSIVE_DARK_MODE,
                &dark as *const _ as *const _,
                4,
            );
            let corner = DWMWCP_ROUND;
            let _ = DwmSetWindowAttribute(
                hwnd,
                DWMWA_WINDOW_CORNER_PREFERENCE,
                &corner as *const _ as *const _,
                4,
            );

            let _ = ShowWindow(hwnd, SW_SHOW);
            let _ = UpdateWindow(hwnd);

            // Exit cleanly on both WM_QUIT (0) and Win32 error (-1)
            let mut msg = MSG::default();
            loop {
                let ret = GetMessageW(&mut msg, None, 0, 0).0;
                if ret <= 0 {
                    break;
                }
                let _ = TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }

            // Ensure GWLP_USERDATA is cleared before reclaiming heap state
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
            let _ = Box::from_raw(state_ptr);
            if co_hr.is_ok() {
                CoUninitialize();
            }
            Ok(())
        }
    }

    fn dpi_scale(hwnd: HWND) -> f32 {
        let dpi = unsafe { GetDpiForWindow(hwnd) };
        if dpi > 0 {
            dpi as f32 / 96.0
        } else {
            1.0
        }
    }

    fn pick_folder_dialog(hwnd: HWND, current: &str) -> Option<PathBuf> {
        unsafe {
            let dlg: IFileOpenDialog =
                CoCreateInstance(&FileOpenDialog, None, CLSCTX_INPROC_SERVER).ok()?;
            let opts = dlg.GetOptions().ok()?;
            dlg.SetOptions(opts | FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM | FOS_NOCHANGEDIR)
                .ok()?;
            let title = to_wide("Choose Singularity installation folder");
            let _ = dlg.SetTitle(PCWSTR(title.as_ptr()));

            // Pre-select the existing current directory (or its closest existing ancestor)
            let mut seed = PathBuf::from(current.trim());
            while !seed.as_os_str().is_empty() && !seed.exists() {
                if !seed.pop() {
                    break;
                }
            }
            if seed.is_dir() {
                let wide_dir = to_wide(&seed.to_string_lossy());
                if let Ok(folder_item) =
                    SHCreateItemFromParsingName::<_, _, IShellItem>(PCWSTR(wide_dir.as_ptr()), None)
                {
                    let _ = dlg.SetFolder(&folder_item);
                }
            }

            if dlg.Show(Some(hwnd)).is_err() {
                return None;
            }
            let item = dlg.GetResult().ok()?;
            let pwstr = item.GetDisplayName(SIGDN_FILESYSPATH).ok()?;
            let mut len = 0usize;
            while *pwstr.0.add(len) != 0 {
                len += 1;
            }
            let s = String::from_utf16_lossy(core::slice::from_raw_parts(pwstr.0, len));
            CoTaskMemFree(Some(pwstr.0 as *const _));
            if s.trim().is_empty() {
                None
            } else {
                Some(PathBuf::from(s))
            }
        }
    }

    fn start_async_install(hwnd: HWND, cell: &std::cell::RefCell<AppState>) {
        let (opts, prog_bg, alive_bg) = {
            let mut st = cell.borrow_mut();
            {
                let mut g = st.progress.lock().unwrap_or_else(|e| e.into_inner());
                if g.phase == InstallPhase::Running {
                    return;
                }
                g.phase = InstallPhase::Running;
                g.target_pct = 8.0;
                g.step_label = "Starting installation...".into();
                g.error_msg.clear();
            }
            st.visual_pct = 4.0;
            let opts = InstallOptions {
                install_dir: st.install_dir.clone(),
                desktop_shortcut: st.chk_desktop,
                start_menu_shortcut: st.chk_start_menu,
                init_roaming_vault: st.chk_roaming,
                launch_after_install: false,
            };
            let prog_bg = Arc::clone(&st.progress);
            let alive_bg = Arc::clone(&st.window_alive);
            (opts, prog_bg, alive_bg)
        };

        unsafe {
            let _ = SetTimer(Some(hwnd), TIMER_ANIM, 16, None);
            let _ = InvalidateRect(Some(hwnd), None, false);
        }

        let hwnd_raw = hwnd.0 as isize;
        std::thread::spawn(move || {
            let notify = || unsafe {
                if !alive_bg.load(Ordering::Acquire) {
                    return;
                }
                let h = HWND(hwnd_raw as *mut _);
                if IsWindow(Some(h)).as_bool() {
                    let _ = PostMessageW(Some(h), WM_APP_PROGRESS, WPARAM(0), LPARAM(0));
                }
            };
            if let Err(err) = perform_installation(&opts, &prog_bg, notify) {
                {
                    let mut g = prog_bg.lock().unwrap_or_else(|e| e.into_inner());
                    g.phase = InstallPhase::Error;
                    g.error_msg = err;
                }
                notify();
            }
        });
    }

    unsafe extern "system" fn wnd_proc(
        hwnd: HWND,
        msg: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        let ptr = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *const std::cell::RefCell<AppState>;
        if ptr.is_null() {
            return DefWindowProcW(hwnd, msg, wparam, lparam);
        }
        let cell = &*ptr;

        match msg {
            WM_ERASEBKGND => LRESULT(1),

            WM_NCHITTEST => {
                let screen_x = (lparam.0 & 0xFFFF) as i16 as i32;
                let screen_y = ((lparam.0 >> 16) & 0xFFFF) as i16 as i32;
                let mut pt = POINT {
                    x: screen_x,
                    y: screen_y,
                };
                let _ = windows::Win32::Graphics::Gdi::ScreenToClient(hwnd, &mut pt);
                let mut rc = RECT::default();
                let _ = GetClientRect(hwnd, &mut rc);
                let s = dpi_scale(hwnd);
                let lay = Layout::compute(rc.right as f32, rc.bottom as f32, s);
                let phase = cell
                    .borrow()
                    .progress
                    .lock()
                    .map(|g| g.phase)
                    .unwrap_or(InstallPhase::Idle);

                if pt.y >= 0
                    && (pt.y as f32) < lay.titlebar_h
                    && lay.hit_test(pt.x as f32, pt.y as f32, phase) == HitZone::None
                {
                    return LRESULT(HTCAPTION as isize);
                }
                LRESULT(HTCLIENT as isize)
            }

            WM_SETCURSOR => {
                let hover = cell.borrow().hover;
                let cur_id = if hover != HitZone::None {
                    IDC_HAND
                } else {
                    IDC_ARROW
                };
                if let Ok(c) = LoadCursorW(None, cur_id) {
                    SetCursor(Some(c));
                    return LRESULT(1);
                }
                DefWindowProcW(hwnd, msg, wparam, lparam)
            }

            WM_MOUSEMOVE => {
                let need_track = !cell.borrow().tracking_mouse;
                if need_track {
                    let mut tme = TRACKMOUSEEVENT {
                        cbSize: core::mem::size_of::<TRACKMOUSEEVENT>() as u32,
                        dwFlags: TME_LEAVE,
                        hwndTrack: hwnd,
                        dwHoverTime: 0,
                    };
                    if TrackMouseEvent(&mut tme).is_ok() {
                        cell.borrow_mut().tracking_mouse = true;
                    }
                }
                let mx = (lparam.0 & 0xFFFF) as i16 as f32;
                let my = ((lparam.0 >> 16) & 0xFFFF) as i16 as f32;
                let mut rc = RECT::default();
                let _ = GetClientRect(hwnd, &mut rc);
                let lay = Layout::compute(rc.right as f32, rc.bottom as f32, dpi_scale(hwnd));
                let changed = {
                    let mut st = cell.borrow_mut();
                    let phase = st
                        .progress
                        .lock()
                        .map(|g| g.phase)
                        .unwrap_or(InstallPhase::Idle);
                    let new_hover = lay.hit_test(mx, my, phase);
                    if new_hover != st.hover {
                        st.hover = new_hover;
                        true
                    } else {
                        false
                    }
                };
                if changed {
                    let _ = InvalidateRect(Some(hwnd), None, false);
                }
                LRESULT(0)
            }

            WM_MOUSELEAVE => {
                let changed = {
                    let mut st = cell.borrow_mut();
                    st.tracking_mouse = false;
                    if st.hover != HitZone::None {
                        st.hover = HitZone::None;
                        true
                    } else {
                        false
                    }
                };
                if changed {
                    let _ = InvalidateRect(Some(hwnd), None, false);
                }
                LRESULT(0)
            }

            WM_LBUTTONDOWN => {
                let mx = (lparam.0 & 0xFFFF) as i16 as f32;
                let my = ((lparam.0 >> 16) & 0xFFFF) as i16 as f32;
                let mut rc = RECT::default();
                let _ = GetClientRect(hwnd, &mut rc);
                let lay = Layout::compute(rc.right as f32, rc.bottom as f32, dpi_scale(hwnd));
                let pressed_any = {
                    let mut st = cell.borrow_mut();
                    let phase = st
                        .progress
                        .lock()
                        .map(|g| g.phase)
                        .unwrap_or(InstallPhase::Idle);
                    st.pressed = lay.hit_test(mx, my, phase);
                    st.pressed != HitZone::None
                };
                if pressed_any {
                    SetCapture(hwnd);
                    let _ = InvalidateRect(Some(hwnd), None, false);
                }
                LRESULT(0)
            }

            WM_LBUTTONUP => {
                let _ = ReleaseCapture();
                let mx = (lparam.0 & 0xFFFF) as i16 as f32;
                let my = ((lparam.0 >> 16) & 0xFFFF) as i16 as f32;
                let mut rc = RECT::default();
                let _ = GetClientRect(hwnd, &mut rc);
                let lay = Layout::compute(rc.right as f32, rc.bottom as f32, dpi_scale(hwnd));

                let (phase, clicked, cur_dir) = {
                    let mut st = cell.borrow_mut();
                    let phase = st
                        .progress
                        .lock()
                        .map(|g| g.phase)
                        .unwrap_or(InstallPhase::Idle);
                    let released_on = lay.hit_test(mx, my, phase);
                    let clicked = if st.pressed != HitZone::None && st.pressed == released_on {
                        released_on
                    } else {
                        HitZone::None
                    };
                    st.pressed = HitZone::None;
                    (phase, clicked, st.install_dir.clone())
                };

                match clicked {
                    HitZone::CloseDot | HitZone::CancelBtn => {
                        if phase != InstallPhase::Running {
                            let _ = DestroyWindow(hwnd);
                            return LRESULT(0);
                        }
                    }
                    HitZone::MinDot => {
                        let _ = ShowWindow(hwnd, SW_MINIMIZE);
                    }
                    HitZone::BrowseBtn => {
                        if let Some(chosen) = pick_folder_dialog(hwnd, &cur_dir) {
                            let final_dir = if chosen
                                .file_name()
                                .and_then(|n| n.to_str())
                                .is_some_and(|s| s.eq_ignore_ascii_case("Singularity"))
                            {
                                chosen
                            } else {
                                chosen.join("Singularity")
                            };
                            cell.borrow_mut().install_dir = final_dir.to_string_lossy().into_owned();
                        }
                    }
                    HitZone::ChkDesktop => {
                        let mut st = cell.borrow_mut();
                        st.chk_desktop = !st.chk_desktop;
                    }
                    HitZone::ChkStartMenu => {
                        let mut st = cell.borrow_mut();
                        st.chk_start_menu = !st.chk_start_menu;
                    }
                    HitZone::ChkRoaming => {
                        let mut st = cell.borrow_mut();
                        st.chk_roaming = !st.chk_roaming;
                    }
                    HitZone::ChkLaunch => {
                        let mut st = cell.borrow_mut();
                        st.chk_launch = !st.chk_launch;
                    }
                    HitZone::PrimaryBtn => {
                        if phase == InstallPhase::Done {
                            let (chk_launch, exe) = {
                                let st = cell.borrow();
                                let exe = st
                                    .progress
                                    .lock()
                                    .map(|g| g.installed_exe.clone())
                                    .unwrap_or_default();
                                (st.chk_launch, exe)
                            };
                            if chk_launch && !exe.is_empty() {
                                let p = Path::new(&exe);
                                let wd = p.parent().unwrap_or_else(|| Path::new("."));
                                launch_exe_detached(p, wd);
                            }
                            let _ = DestroyWindow(hwnd);
                            return LRESULT(0);
                        } else if phase == InstallPhase::Idle || phase == InstallPhase::Error {
                            start_async_install(hwnd, cell);
                        }
                    }
                    HitZone::None => {}
                }
                let _ = InvalidateRect(Some(hwnd), None, false);
                LRESULT(0)
            }

            WM_APP_PROGRESS => {
                let _ = InvalidateRect(Some(hwnd), None, false);
                LRESULT(0)
            }

            WM_CLOSE => {
                let phase = cell
                    .borrow()
                    .progress
                    .lock()
                    .map(|g| g.phase)
                    .unwrap_or(InstallPhase::Idle);
                if phase != InstallPhase::Running {
                    let _ = DestroyWindow(hwnd);
                }
                LRESULT(0)
            }

            WM_TIMER => {
                if wparam.0 == TIMER_ANIM {
                    let mut kill = false;
                    let mut redraw = false;
                    {
                        let mut st = cell.borrow_mut();
                        let (phase, target) = {
                            let g = st.progress.lock().unwrap_or_else(|e| e.into_inner());
                            (g.phase, g.target_pct)
                        };
                        let diff = target - st.visual_pct;
                        if diff.abs() > 0.25 {
                            st.visual_pct += diff * 0.24 + diff.signum() * 0.35;
                            if (diff > 0.0 && st.visual_pct > target)
                                || (diff < 0.0 && st.visual_pct < target)
                            {
                                st.visual_pct = target;
                            }
                            redraw = true;
                        } else {
                            st.visual_pct = target;
                            if phase != InstallPhase::Running {
                                kill = true;
                                redraw = true;
                            }
                        }
                    }
                    if kill {
                        let _ = KillTimer(Some(hwnd), TIMER_ANIM);
                    }
                    if redraw {
                        let _ = InvalidateRect(Some(hwnd), None, false);
                    }
                }
                LRESULT(0)
            }

            WM_PAINT => {
                if let Ok(st) = cell.try_borrow() {
                    paint_window(hwnd, &st);
                } else {
                    let mut ps = PAINTSTRUCT::default();
                    let _ = BeginPaint(hwnd, &mut ps);
                    let _ = EndPaint(hwnd, &ps);
                }
                LRESULT(0)
            }

            WM_DESTROY => {
                if let Ok(st) = cell.try_borrow() {
                    st.window_alive.store(false, Ordering::SeqCst);
                }
                SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
                let _ = KillTimer(Some(hwnd), TIMER_ANIM);
                PostQuitMessage(0);
                LRESULT(0)
            }

            _ => DefWindowProcW(hwnd, msg, wparam, lparam),
        }
    }

    // -------------------------------------------------------------------------
    // 60 FPS Anti-Aliased SDF Pixel Compositor + ClearType GDI Typography
    // -------------------------------------------------------------------------

    #[inline]
    fn pack_bgra(r: u8, g: u8, b: u8) -> u32 {
        0xFF00_0000 | ((r as u32) << 16) | ((g as u32) << 8) | (b as u32)
    }

    #[inline]
    fn blend_pixel(dst: u32, r: u8, g: u8, b: u8, alpha: f32) -> u32 {
        let a = alpha.clamp(0.0, 1.0);
        if a <= 0.001 {
            return dst;
        }
        if a >= 0.999 {
            return pack_bgra(r, g, b);
        }
        let dr = ((dst >> 16) & 0xFF) as f32;
        let dg = ((dst >> 8) & 0xFF) as f32;
        let db = (dst & 0xFF) as f32;
        let inv = 1.0 - a;
        let or = (r as f32 * a + dr * inv).round() as u8;
        let og = (g as f32 * a + dg * inv).round() as u8;
        let ob = (b as f32 * a + db * inv).round() as u8;
        pack_bgra(or, og, ob)
    }

    #[inline]
    fn sdf_rounded_rect(px: f32, py: f32, r: RectF, rad: f32) -> f32 {
        let cx = (r.x0 + r.x1) * 0.5;
        let cy = (r.y0 + r.y1) * 0.5;
        let hx = (r.x1 - r.x0) * 0.5 - rad;
        let hy = (r.y1 - r.y0) * 0.5 - rad;
        let qx = (px - cx).abs() - hx;
        let qy = (py - cy).abs() - hy;
        let out_x = qx.max(0.0);
        let out_y = qy.max(0.0);
        (out_x * out_x + out_y * out_y).sqrt() + qx.max(qy).min(0.0) - rad
    }

    fn draw_rounded_box(
        buf: &mut [u32],
        bw: usize,
        bh: usize,
        rect: RectF,
        rad: f32,
        fill: (u8, u8, u8, f32),
        border: Option<(u8, u8, u8, f32)>,
    ) {
        let x0 = (rect.x0.floor() as isize - 2).max(0) as usize;
        let y0 = (rect.y0.floor() as isize - 2).max(0) as usize;
        let x1 = (rect.x1.ceil() as usize + 2).min(bw);
        let y1 = (rect.y1.ceil() as usize + 2).min(bh);

        for y in y0..y1 {
            let py = y as f32 + 0.5;
            let row = y * bw;
            for x in x0..x1 {
                let px = x as f32 + 0.5;
                let d = sdf_rounded_rect(px, py, rect, rad);
                if d < 0.75 {
                    let cov = (0.5 - d).clamp(0.0, 1.0);
                    let mut p = buf[row + x];
                    if fill.3 > 0.0 {
                        p = blend_pixel(p, fill.0, fill.1, fill.2, fill.3 * cov);
                    }
                    if let Some((br, bg, bb, ba)) = border {
                        // 1px crisp inner-centered stroke
                        let bd = (d + 0.5).abs();
                        if bd < 0.95 {
                            let bcov = (0.95 - bd).clamp(0.0, 1.0) * cov;
                            p = blend_pixel(p, br, bg, bb, ba * bcov);
                        }
                    }
                    buf[row + x] = p;
                }
            }
        }
    }

    fn draw_gradient_button(
        buf: &mut [u32],
        bw: usize,
        bh: usize,
        rect: RectF,
        rad: f32,
        top_rgb: (u8, u8, u8),
        bot_rgb: (u8, u8, u8),
        alpha: f32,
    ) {
        let x0 = (rect.x0.floor() as isize - 2).max(0) as usize;
        let y0 = (rect.y0.floor() as isize - 2).max(0) as usize;
        let x1 = (rect.x1.ceil() as usize + 2).min(bw);
        let y1 = (rect.y1.ceil() as usize + 2).min(bh);
        let h_span = (rect.y1 - rect.y0).max(1.0);

        for y in y0..y1 {
            let py = y as f32 + 0.5;
            let t = ((py - rect.y0) / h_span).clamp(0.0, 1.0);
            let cr = (top_rgb.0 as f32 * (1.0 - t) + bot_rgb.0 as f32 * t).round() as u8;
            let cg = (top_rgb.1 as f32 * (1.0 - t) + bot_rgb.1 as f32 * t).round() as u8;
            let cb = (top_rgb.2 as f32 * (1.0 - t) + bot_rgb.2 as f32 * t).round() as u8;
            let row = y * bw;
            for x in x0..x1 {
                let px = x as f32 + 0.5;
                let d = sdf_rounded_rect(px, py, rect, rad);
                if d < 0.75 {
                    let cov = (0.5 - d).clamp(0.0, 1.0);
                    buf[row + x] = blend_pixel(buf[row + x], cr, cg, cb, alpha * cov);
                }
            }
        }
    }

    fn draw_circle(
        buf: &mut [u32],
        bw: usize,
        bh: usize,
        cx: f32,
        cy: f32,
        r: f32,
        rgb: (u8, u8, u8),
        alpha: f32,
    ) {
        let x0 = ((cx - r - 2.0).floor() as isize).max(0) as usize;
        let y0 = ((cy - r - 2.0).floor() as isize).max(0) as usize;
        let x1 = ((cx + r + 2.0).ceil() as usize).min(bw);
        let y1 = ((cy + r + 2.0).ceil() as usize).min(bh);

        for y in y0..y1 {
            let dy = y as f32 + 0.5 - cy;
            let row = y * bw;
            for x in x0..x1 {
                let dx = x as f32 + 0.5 - cx;
                let dist = (dx * dx + dy * dy).sqrt() - r;
                if dist < 0.75 {
                    let cov = (0.5 - dist).clamp(0.0, 1.0);
                    buf[row + x] = blend_pixel(buf[row + x], rgb.0, rgb.1, rgb.2, alpha * cov);
                }
            }
        }
    }

    fn draw_segment_aa(
        buf: &mut [u32],
        bw: usize,
        bh: usize,
        ax: f32,
        ay: f32,
        bx: f32,
        by: f32,
        thickness: f32,
        rgb: (u8, u8, u8),
    ) {
        let pad = thickness + 2.0;
        let x0 = ((ax.min(bx) - pad).floor() as isize).max(0) as usize;
        let y0 = ((ay.min(by) - pad).floor() as isize).max(0) as usize;
        let x1 = ((ax.max(bx) + pad).ceil() as usize).min(bw);
        let y1 = ((ay.max(by) + pad).ceil() as usize).min(bh);
        let vx = bx - ax;
        let vy = by - ay;
        let len2 = (vx * vx + vy * vy).max(0.0001);
        let half_t = thickness * 0.5;

        for y in y0..y1 {
            let py = y as f32 + 0.5;
            let row = y * bw;
            for x in x0..x1 {
                let px = x as f32 + 0.5;
                let t = (((px - ax) * vx + (py - ay) * vy) / len2).clamp(0.0, 1.0);
                let dx = px - (ax + t * vx);
                let dy = py - (ay + t * vy);
                let d = (dx * dx + dy * dy).sqrt() - half_t;
                if d < 0.75 {
                    let cov = (0.5 - d).clamp(0.0, 1.0);
                    buf[row + x] = blend_pixel(buf[row + x], rgb.0, rgb.1, rgb.2, cov);
                }
            }
        }
    }

    fn blit_logo_bilinear(buf: &mut [u32], bw: usize, bh: usize, dst: RectF) {
        let x0 = (dst.x0.floor() as isize).max(0) as usize;
        let y0 = (dst.y0.floor() as isize).max(0) as usize;
        let x1 = (dst.x1.ceil() as usize).min(bw);
        let y1 = (dst.y1.ceil() as usize).min(bh);
        let dw = (dst.x1 - dst.x0).max(1.0);
        let dh = (dst.y1 - dst.y0).max(1.0);

        for y in y0..y1 {
            let v = ((y as f32 + 0.5 - dst.y0) / dh * 127.0).clamp(0.0, 127.0);
            let v0 = v.floor() as usize;
            let v1 = (v0 + 1).min(127);
            let fv = v - v0 as f32;
            let row = y * bw;

            for x in x0..x1 {
                let u = ((x as f32 + 0.5 - dst.x0) / dw * 127.0).clamp(0.0, 127.0);
                let u0 = u.floor() as usize;
                let u1 = (u0 + 1).min(127);
                let fu = u - u0 as f32;

                let sample = |sx: usize, sy: usize| -> (f32, f32, f32, f32) {
                    let idx = (sy * 128 + sx) * 4;
                    (
                        EMBEDDED_LOGO_128_RGBA[idx] as f32,
                        EMBEDDED_LOGO_128_RGBA[idx + 1] as f32,
                        EMBEDDED_LOGO_128_RGBA[idx + 2] as f32,
                        EMBEDDED_LOGO_128_RGBA[idx + 3] as f32 / 255.0,
                    )
                };
                let c00 = sample(u0, v0);
                let c10 = sample(u1, v0);
                let c01 = sample(u0, v1);
                let c11 = sample(u1, v1);

                let w00 = (1.0 - fu) * (1.0 - fv);
                let w10 = fu * (1.0 - fv);
                let w01 = (1.0 - fu) * fv;
                let w11 = fu * fv;

                let r = (c00.0 * w00 + c10.0 * w10 + c01.0 * w01 + c11.0 * w11).round() as u8;
                let g = (c00.1 * w00 + c10.1 * w10 + c01.1 * w01 + c11.1 * w11).round() as u8;
                let b = (c00.2 * w00 + c10.2 * w10 + c01.2 * w01 + c11.2 * w11).round() as u8;
                let a = c00.3 * w00 + c10.3 * w10 + c01.3 * w01 + c11.3 * w11;

                buf[row + x] = blend_pixel(buf[row + x], r, g, b, a);
            }
        }
    }

    unsafe fn make_font(px_height: f32, weight: i32, mono: bool) -> HFONT {
        let face = if mono {
            to_wide("Consolas")
        } else {
            to_wide("Segoe UI")
        };
        CreateFontW(
            -(px_height.round() as i32),
            0,
            0,
            0,
            weight,
            0,
            0,
            0,
            DEFAULT_CHARSET,
            OUT_DEFAULT_PRECIS,
            CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY,
            0,
            PCWSTR(face.as_ptr()),
        )
    }

    #[inline]
    fn rgb_colorref(r: u8, g: u8, b: u8) -> COLORREF {
        COLORREF((r as u32) | ((g as u32) << 8) | ((b as u32) << 16))
    }

    unsafe fn draw_str(
        hdc: windows::Win32::Graphics::Gdi::HDC,
        font: HFONT,
        color: COLORREF,
        text: &str,
        rect: RectF,
        flags: windows::Win32::Graphics::Gdi::DRAW_TEXT_FORMAT,
    ) {
        let old = SelectObject(hdc, font.into());
        let _ = SetTextColor(hdc, color);
        let mut wide: Vec<u16> = text.encode_utf16().collect();
        let mut rc = rect.to_win_rect();
        let _ = DrawTextW(hdc, &mut wide, &mut rc, flags | DT_NOPREFIX);
        let _ = SelectObject(hdc, old);
    }

    unsafe fn paint_window(hwnd: HWND, st: &AppState) {
        let mut ps = PAINTSTRUCT::default();
        let paint_dc = BeginPaint(hwnd, &mut ps);

        let mut rc = RECT::default();
        let _ = GetClientRect(hwnd, &mut rc);
        let bw = rc.right.max(1) as usize;
        let bh = rc.bottom.max(1) as usize;
        let wf = bw as f32;
        let hf = bh as f32;
        let s = dpi_scale(hwnd);
        let lay = Layout::compute(wf, hf, s);

        let (phase, step_label, err_msg) = {
            let g = st.progress.lock().unwrap_or_else(|e| e.into_inner());
            (g.phase, g.step_label.clone(), g.error_msg.clone())
        };

        let mem_dc = CreateCompatibleDC(Some(paint_dc));
        let bmi = BITMAPINFO {
            bmiHeader: BITMAPINFOHEADER {
                biSize: core::mem::size_of::<BITMAPINFOHEADER>() as u32,
                biWidth: bw as i32,
                biHeight: -(bh as i32), // top-down DIB
                biPlanes: 1,
                biBitCount: 32,
                biCompression: BI_RGB.0,
                ..Default::default()
            },
            ..Default::default()
        };
        let mut bits_ptr: *mut core::ffi::c_void = core::ptr::null_mut();
        let Ok(dib) = CreateDIBSection(Some(mem_dc), &bmi, DIB_RGB_COLORS, &mut bits_ptr, None, 0)
        else {
            let _ = DeleteDC(mem_dc);
            let _ = EndPaint(hwnd, &ps);
            return;
        };
        let Some(total_px) = bw.checked_mul(bh) else {
            let _ = DeleteObject(dib.into());
            let _ = DeleteDC(mem_dc);
            let _ = EndPaint(hwnd, &ps);
            return;
        };
        if bits_ptr.is_null() {
            let _ = DeleteObject(dib.into());
            let _ = DeleteDC(mem_dc);
            let _ = EndPaint(hwnd, &ps);
            return;
        }
        let old_bmp = SelectObject(mem_dc, dib.into());
        let pixels = core::slice::from_raw_parts_mut(bits_ptr as *mut u32, total_px);

        // 1. Background `#07070A` + warm gold ambient radial glow top-right & behind logo
        let gx1 = wf * 0.82;
        let gy1 = hf * 0.14;
        let gr1 = 290.0 * s;
        let gx2 = (lay.logo_rect.x0 + lay.logo_rect.x1) * 0.5;
        let gy2 = (lay.logo_rect.y0 + lay.logo_rect.y1) * 0.5;
        let gr2 = 95.0 * s;

        for y in 0..bh {
            let py = y as f32;
            let row = y * bw;
            let in_tb = py < lay.titlebar_h;
            for x in 0..bw {
                let px = x as f32;
                let mut r = if in_tb { 12.0 } else { 7.0 };
                let mut g = if in_tb { 13.0 } else { 7.0 };
                let mut b = if in_tb { 18.0 } else { 10.0 };

                let d1 = ((px - gx1).powi(2) + (py - gy1).powi(2)).sqrt() / gr1;
                if d1 < 1.0 {
                    let k = (1.0 - d1).powi(2) * 0.11;
                    r += 240.0 * k;
                    g += 175.0 * k;
                    b += 85.0 * k;
                }
                let d2 = ((px - gx2).powi(2) + (py - gy2).powi(2)).sqrt() / gr2;
                if d2 < 1.0 {
                    let k = (1.0 - d2).powi(2) * 0.18;
                    r += 240.0 * k;
                    g += 175.0 * k;
                    b += 85.0 * k;
                }

                pixels[row + x] =
                    pack_bgra(r.min(255.0) as u8, g.min(255.0) as u8, b.min(255.0) as u8);
            }
        }

        // Subtle titlebar divider & outer window border
        let tb_row = (lay.titlebar_h.round() as usize).min(bh - 1);
        for x in 0..bw {
            pixels[tb_row * bw + x] = blend_pixel(pixels[tb_row * bw + x], 255, 255, 255, 0.07);
        }
        draw_rounded_box(
            pixels,
            bw,
            bh,
            RectF {
                x0: 0.5,
                y0: 0.5,
                x1: wf - 0.5,
                y1: hf - 0.5,
            },
            8.0 * s,
            (0, 0, 0, 0.0),
            Some((255, 255, 255, 0.13)),
        );

        // 2. Apple 3-dot traffic lights
        let close_col = if st.hover == HitZone::CloseDot {
            (255, 118, 110)
        } else {
            (255, 95, 87)
        };
        let min_col = if st.hover == HitZone::MinDot {
            (255, 206, 84)
        } else {
            (254, 188, 46)
        };
        draw_circle(
            pixels,
            bw,
            bh,
            lay.close_dot.0,
            lay.close_dot.1,
            lay.close_dot.2,
            close_col,
            if phase == InstallPhase::Running {
                0.35
            } else {
                1.0
            },
        );
        draw_circle(
            pixels,
            bw,
            bh,
            lay.min_dot.0,
            lay.min_dot.1,
            lay.min_dot.2,
            min_col,
            1.0,
        );
        draw_circle(
            pixels,
            bw,
            bh,
            lay.dis_dot.0,
            lay.dis_dot.1,
            lay.dis_dot.2,
            (255, 255, 255),
            0.14,
        );

        // 3. Studio Brand Logo + Version Pill (measured dynamically with DT_CALCRECT)
        blit_logo_bilinear(pixels, bw, bh, lay.logo_rect);

        let f_h1 = make_font(21.0 * s, FW_BOLD.0 as i32, false);
        let hx0 = lay.logo_rect.x1 + 18.0 * s;
        let h1_width_px = {
            let old_f = SelectObject(mem_dc, f_h1.into());
            let mut h1_wide: Vec<u16> = "Singularity Browser".encode_utf16().collect();
            let mut mrc = RECT::default();
            let _ = DrawTextW(
                mem_dc,
                &mut h1_wide,
                &mut mrc,
                DT_CALCRECT | DT_SINGLELINE | DT_NOPREFIX,
            );
            let _ = SelectObject(mem_dc, old_f);
            (mrc.right - mrc.left).max((180.0 * s) as i32) as f32
        };
        let pill_x0 = (hx0 + h1_width_px + 10.0 * s).min(wf - 90.0 * s);
        let ver_pill = RectF {
            x0: pill_x0,
            y0: lay.logo_rect.y0 + 3.0 * s,
            x1: pill_x0 + 58.0 * s,
            y1: lay.logo_rect.y0 + 24.0 * s,
        };
        draw_rounded_box(
            pixels,
            bw,
            bh,
            ver_pill,
            10.0 * s,
            (240, 179, 90, 0.15),
            Some((240, 179, 90, 0.38)),
        );

        // 4. Main Configuration Card
        draw_rounded_box(
            pixels,
            bw,
            bh,
            lay.card_rect,
            12.0 * s,
            (16, 17, 24, 0.96),
            Some((255, 255, 255, 0.09)),
        );

        // Install directory box + "Parcourir…" button
        let dir_hover = st.hover == HitZone::BrowseBtn;
        draw_rounded_box(
            pixels,
            bw,
            bh,
            lay.dir_box,
            7.5 * s,
            (9, 10, 15, 1.0),
            Some(if dir_hover {
                (240, 179, 90, 0.55)
            } else {
                (255, 255, 255, 0.13)
            }),
        );
        draw_rounded_box(
            pixels,
            bw,
            bh,
            lay.browse_btn,
            7.5 * s,
            (255, 255, 255, if dir_hover { 0.11 } else { 0.06 }),
            Some((255, 255, 255, 0.14)),
        );

        // Encrypted Roaming\.singularity hint box + vector padlock
        draw_rounded_box(
            pixels,
            bw,
            bh,
            lay.roaming_box,
            7.5 * s,
            (240, 179, 90, 0.07),
            Some((240, 179, 90, 0.22)),
        );
        let lx = lay.roaming_box.x0 + 14.0 * s;
        let ly = (lay.roaming_box.y0 + lay.roaming_box.y1) * 0.5;
        draw_rounded_box(
            pixels,
            bw,
            bh,
            RectF {
                x0: lx - 5.0 * s,
                y0: ly - 1.0 * s,
                x1: lx + 5.0 * s,
                y1: ly + 6.5 * s,
            },
            2.0 * s,
            (240, 179, 90, 0.95),
            None,
        );
        draw_rounded_box(
            pixels,
            bw,
            bh,
            RectF {
                x0: lx - 3.2 * s,
                y0: ly - 6.2 * s,
                x1: lx + 3.2 * s,
                y1: ly,
            },
            3.0 * s,
            (0, 0, 0, 0.0),
            Some((240, 179, 90, 0.95)),
        );

        // 5. Four Interactive Checkboxes
        let checks = [
            (st.chk_desktop, HitZone::ChkDesktop),
            (st.chk_start_menu, HitZone::ChkStartMenu),
            (st.chk_roaming, HitZone::ChkRoaming),
            (st.chk_launch, HitZone::ChkLaunch),
        ];
        for (i, &(checked, zone)) in checks.iter().enumerate() {
            let b = lay.chk_boxes[i];
            let hov = st.hover == zone;
            if checked {
                draw_rounded_box(
                    pixels,
                    bw,
                    bh,
                    b,
                    4.2 * s,
                    (240, 179, 90, if hov { 1.0 } else { 0.93 }),
                    None,
                );
                let bw_box = b.x1 - b.x0;
                let bh_box = b.y1 - b.y0;
                draw_segment_aa(
                    pixels,
                    bw,
                    bh,
                    b.x0 + bw_box * 0.24,
                    b.y0 + bh_box * 0.53,
                    b.x0 + bw_box * 0.44,
                    b.y0 + bh_box * 0.74,
                    1.9 * s,
                    (12, 12, 16),
                );
                draw_segment_aa(
                    pixels,
                    bw,
                    bh,
                    b.x0 + bw_box * 0.44,
                    b.y0 + bh_box * 0.74,
                    b.x0 + bw_box * 0.78,
                    b.y0 + bh_box * 0.28,
                    1.9 * s,
                    (12, 12, 16),
                );
            } else {
                draw_rounded_box(
                    pixels,
                    bw,
                    bh,
                    b,
                    4.2 * s,
                    (9, 10, 15, 1.0),
                    Some(if hov {
                        (240, 179, 90, 0.65)
                    } else {
                        (255, 255, 255, 0.24)
                    }),
                );
            }
        }

        // 6. Progress Bar Track & Smooth Animated Gold Fill
        draw_rounded_box(
            pixels,
            bw,
            bh,
            lay.prog_bar,
            4.5 * s,
            (255, 255, 255, 0.08),
            None,
        );
        let pct_clamped = (st.visual_pct / 100.0).clamp(0.0, 1.0);
        if pct_clamped > 0.005 {
            let fill_w = ((lay.prog_bar.x1 - lay.prog_bar.x0) * pct_clamped).max(9.0 * s);
            let fill_rect = RectF {
                x0: lay.prog_bar.x0,
                y0: lay.prog_bar.y0,
                x1: (lay.prog_bar.x0 + fill_w).min(lay.prog_bar.x1),
                y1: lay.prog_bar.y1,
            };
            draw_gradient_button(
                pixels,
                bw,
                bh,
                fill_rect,
                4.5 * s,
                (246, 196, 120),
                (218, 138, 44),
                1.0,
            );
        }

        // 7. Footer Buttons ("Annuler" + Primary Gold CTA)
        if phase == InstallPhase::Idle || phase == InstallPhase::Error {
            let canc_hov = st.hover == HitZone::CancelBtn;
            draw_rounded_box(
                pixels,
                bw,
                bh,
                lay.cancel_btn,
                8.5 * s,
                (255, 255, 255, if canc_hov { 0.11 } else { 0.05 }),
                Some((255, 255, 255, 0.12)),
            );
        }

        let prim_hov = st.hover == HitZone::PrimaryBtn;
        let prim_top = if prim_hov {
            (250, 200, 122)
        } else {
            (243, 186, 103)
        };
        let prim_bot = if prim_hov {
            (232, 152, 58)
        } else {
            (221, 140, 46)
        };
        draw_gradient_button(
            pixels,
            bw,
            bh,
            lay.primary_btn,
            8.5 * s,
            prim_top,
            prim_bot,
            if phase == InstallPhase::Running {
                0.45
            } else {
                1.0
            },
        );

        // 8. ClearType Typography Overlay
        let _ = SetBkMode(mem_dc, TRANSPARENT);

        let f_titlebar = make_font(12.0 * s, FW_MEDIUM.0 as i32, false);
        let f_badge = make_font(11.5 * s, FW_SEMIBOLD.0 as i32, false);
        let f_sub = make_font(12.5 * s, FW_NORMAL.0 as i32, false);
        let f_label = make_font(11.0 * s, FW_SEMIBOLD.0 as i32, false);
        let f_mono = make_font(12.5 * s, FW_NORMAL.0 as i32, true);
        let f_body = make_font(12.5 * s, FW_NORMAL.0 as i32, false);
        let f_btn = make_font(13.0 * s, FW_SEMIBOLD.0 as i32, false);

        let c_white = rgb_colorref(245, 246, 250);
        let c_muted = rgb_colorref(148, 153, 172);
        let c_gold = rgb_colorref(240, 179, 90);
        let c_dark = rgb_colorref(12, 12, 16);
        let c_soft = rgb_colorref(218, 222, 235);
        let c_err = rgb_colorref(255, 118, 110);

        draw_str(
            mem_dc,
            f_titlebar,
            c_muted,
            "Singularity Official Setup Wizard",
            RectF {
                x0: 84.0 * s,
                y0: 0.0,
                x1: wf - 20.0 * s,
                y1: lay.titlebar_h,
            },
            DT_LEFT | DT_VCENTER | DT_SINGLELINE,
        );

        draw_str(
            mem_dc,
            f_h1,
            c_white,
            "Singularity Browser",
            RectF {
                x0: hx0,
                y0: lay.logo_rect.y0 - 2.0 * s,
                x1: ver_pill.x0 - 4.0 * s,
                y1: lay.logo_rect.y0 + 28.0 * s,
            },
            DT_LEFT | DT_VCENTER | DT_SINGLELINE,
        );
        draw_str(
            mem_dc,
            f_badge,
            c_gold,
            &format!("v{APP_VERSION}"),
            ver_pill,
            windows::Win32::Graphics::Gdi::DT_CENTER | DT_VCENTER | DT_SINGLELINE,
        );
        draw_str(
            mem_dc,
            f_sub,
            c_muted,
            "Native Rust desktop browser with Pure Chromium (CEF), built-in ad & tracker shield, Argon2id vault, and DPAPI-encrypted sessions.",
            RectF {
                x0: hx0,
                y0: lay.logo_rect.y0 + 30.0 * s,
                x1: wf - 30.0 * s,
                y1: lay.logo_rect.y1 + 6.0 * s,
            },
            DT_LEFT | DT_WORDBREAK,
        );

        // Card header labels
        let payload_mb = detect_payload_size_bytes() as f64 / (1024.0 * 1024.0);
        draw_str(
            mem_dc,
            f_label,
            c_muted,
            "INSTALLATION DIRECTORY",
            RectF {
                x0: lay.dir_box.x0,
                y0: lay.card_rect.y0 + 13.0 * s,
                x1: lay.browse_btn.x0,
                y1: lay.dir_box.y0 - 4.0 * s,
            },
            DT_LEFT | DT_VCENTER | DT_SINGLELINE,
        );
        draw_str(
            mem_dc,
            f_label,
            c_muted,
            &format!("{payload_mb:.1} MB • native x64"),
            RectF {
                x0: lay.browse_btn.x0 - 80.0 * s,
                y0: lay.card_rect.y0 + 13.0 * s,
                x1: lay.browse_btn.x1,
                y1: lay.dir_box.y0 - 4.0 * s,
            },
            DT_RIGHT | DT_VCENTER | DT_SINGLELINE,
        );

        draw_str(
            mem_dc,
            f_mono,
            c_white,
            &st.install_dir,
            RectF {
                x0: lay.dir_box.x0 + 11.0 * s,
                y0: lay.dir_box.y0,
                x1: lay.dir_box.x1 - 10.0 * s,
                y1: lay.dir_box.y1,
            },
            DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS,
        );
        draw_str(
            mem_dc,
            f_body,
            c_soft,
            "Browse…",
            lay.browse_btn,
            windows::Win32::Graphics::Gdi::DT_CENTER | DT_VCENTER | DT_SINGLELINE,
        );

        draw_str(
            mem_dc,
            f_body,
            c_soft,
            &format!(
                "Encrypted session store (DPAPI + XChaCha20): {}",
                st.roaming_dir
            ),
            RectF {
                x0: lay.roaming_box.x0 + 28.0 * s,
                y0: lay.roaming_box.y0,
                x1: lay.roaming_box.x1 - 10.0 * s,
                y1: lay.roaming_box.y1,
            },
            DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS,
        );

        let chk_labels = [
            "Desktop shortcut",
            "Start Menu & Installed Apps",
            "Initialize encrypted Roaming\\.singularity",
            "Launch Singularity after setup",
        ];
        for (i, lbl) in chk_labels.iter().enumerate() {
            let r = lay.chk_rects[i];
            draw_str(
                mem_dc,
                f_body,
                c_soft,
                lbl,
                RectF {
                    x0: lay.chk_boxes[i].x1 + 9.0 * s,
                    y0: r.y0,
                    x1: r.x1,
                    y1: r.y1,
                },
                DT_LEFT | DT_VCENTER | DT_SINGLELINE,
            );
        }

        // Progress status line
        let status_line = if phase == InstallPhase::Error {
            &err_msg
        } else {
            &step_label
        };
        let status_col = if phase == InstallPhase::Error {
            c_err
        } else if phase == InstallPhase::Done {
            c_gold
        } else {
            c_soft
        };
        draw_str(
            mem_dc,
            f_body,
            status_col,
            status_line,
            RectF {
                x0: lay.prog_bar.x0,
                y0: lay.prog_bar.y0 - 22.0 * s,
                x1: lay.prog_bar.x1 - 52.0 * s,
                y1: lay.prog_bar.y0 - 3.0 * s,
            },
            DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS,
        );
        draw_str(
            mem_dc,
            f_btn,
            c_gold,
            &format!("{}%", st.visual_pct.round() as u32),
            RectF {
                x0: lay.prog_bar.x1 - 50.0 * s,
                y0: lay.prog_bar.y0 - 22.0 * s,
                x1: lay.prog_bar.x1,
                y1: lay.prog_bar.y0 - 3.0 * s,
            },
            DT_RIGHT | DT_VCENTER | DT_SINGLELINE,
        );

        // Footer text + buttons
        draw_str(
            mem_dc,
            f_body,
            c_muted,
            "Native per-user install (no UAC elevation) • Clean uninstaller",
            RectF {
                x0: lay.card_rect.x0,
                y0: lay.primary_btn.y0,
                x1: lay.cancel_btn.x0 - 10.0 * s,
                y1: lay.primary_btn.y1,
            },
            DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS,
        );

        if phase == InstallPhase::Idle || phase == InstallPhase::Error {
            draw_str(
                mem_dc,
                f_btn,
                c_soft,
                "Cancel",
                lay.cancel_btn,
                windows::Win32::Graphics::Gdi::DT_CENTER | DT_VCENTER | DT_SINGLELINE,
            );
        }

        let primary_label = match phase {
            InstallPhase::Idle | InstallPhase::Error => "Install Singularity",
            InstallPhase::Running => "Installing…",
            InstallPhase::Done => {
                if st.chk_launch {
                    "Finish & Launch"
                } else {
                    "Finish"
                }
            }
        };
        draw_str(
            mem_dc,
            f_btn,
            c_dark,
            primary_label,
            lay.primary_btn,
            windows::Win32::Graphics::Gdi::DT_CENTER | DT_VCENTER | DT_SINGLELINE,
        );

        // Single tear-free BitBlt to window DC
        let _ = BitBlt(
            paint_dc,
            0,
            0,
            bw as i32,
            bh as i32,
            Some(mem_dc),
            0,
            0,
            SRCCOPY,
        );

        for f in [
            f_titlebar, f_h1, f_badge, f_sub, f_label, f_mono, f_body, f_btn,
        ] {
            let _ = DeleteObject(f.into());
        }
        let _ = SelectObject(mem_dc, old_bmp);
        let _ = DeleteObject(dib.into());
        let _ = DeleteDC(mem_dc);
        let _ = EndPaint(hwnd, &ps);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        let b = s.as_bytes();
        assert_eq!(b.len() % 2, 0);
        (0..b.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(std::str::from_utf8(&b[i..i + 2]).unwrap(), 16).unwrap())
            .collect()
    }

    fn bytes_to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn build_sgx1_trailer(zip_bytes: &[u8], flags: u8, sig: [u8; 64]) -> [u8; SFX_TRAILER_LEN] {
        let mut h = crypto_verify::Sha256::new();
        h.update(zip_bytes);
        let digest = h.finalize();
        let mut trailer = [0u8; SFX_TRAILER_LEN];
        trailer[0..4].copy_from_slice(SFX_TRAILER_MAGIC);
        trailer[4..12].copy_from_slice(&(zip_bytes.len() as u64).to_le_bytes());
        trailer[12..44].copy_from_slice(&digest);
        trailer[44] = flags;
        trailer[45..48].copy_from_slice(&[0u8; 3]);
        trailer[48..112].copy_from_slice(&sig);
        trailer[112..116].copy_from_slice(SFX_TRAILER_MAGIC);
        trailer
    }

    fn make_synthetic_zip() -> Vec<u8> {
        let mut zip_buf = std::io::Cursor::new(Vec::new());
        {
            let mut zw = zip::ZipWriter::new(&mut zip_buf);
            let opts = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated);
            zw.start_file("singularity.exe", opts).expect("start exe");
            zw.write_all(b"MZ-singularity-test").expect("write exe");
            zw.start_file("libcef.dll", opts).expect("start dll");
            zw.write_all(b"MZ-libcef-test").expect("write dll");
            zw.start_file("locales/fr.pak", opts).expect("start locale");
            zw.write_all(b"PAK-fr").expect("write locale");
            zw.start_file("../escape.txt", opts).expect("start evil");
            zw.write_all(b"evil").expect("write evil");
            zw.finish().expect("finish zip");
        }
        zip_buf.into_inner()
    }

    #[test]
    fn test_sha256_and_sha512_fips_vectors() {
        let mut h256 = crypto_verify::Sha256::new();
        h256.update(b"");
        assert_eq!(
            bytes_to_hex(&h256.finalize()),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );

        let mut h256_abc = crypto_verify::Sha256::new();
        h256_abc.update(b"abc");
        assert_eq!(
            bytes_to_hex(&h256_abc.finalize()),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );

        let mut h512 = crypto_verify::Sha512::new();
        h512.update(b"abc");
        assert_eq!(
            bytes_to_hex(&h512.finalize()),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
    }

    #[test]
    fn test_ed25519_rfc8032_test_vectors_and_tamper_rejection() {
        // RFC 8032 Section 7.1 TEST 1 (empty message)
        let pk1: [u8; 32] = crypto_verify::decode_hex_32(
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        )
        .unwrap();
        let sig1: [u8; 64] = hex_to_bytes(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155\
             5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        )
        .try_into()
        .unwrap();
        assert!(crypto_verify::ed25519_verify(&pk1, b"", &sig1).is_ok());
        assert!(crypto_verify::ed25519_verify(&pk1, b"x", &sig1).is_err());

        // RFC 8032 Section 7.1 TEST 2 (1-byte message 0x72)
        let pk2: [u8; 32] = crypto_verify::decode_hex_32(
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        )
        .unwrap();
        let sig2: [u8; 64] = hex_to_bytes(
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da\
             085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        )
        .try_into()
        .unwrap();
        assert!(crypto_verify::ed25519_verify(&pk2, &[0x72], &sig2).is_ok());

        // RFC 8032 Section 7.1 TEST 3 (2-byte message 0xaf82)
        let pk3: [u8; 32] = crypto_verify::decode_hex_32(
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        )
        .unwrap();
        let sig3: [u8; 64] = hex_to_bytes(
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac\
             18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
        )
        .try_into()
        .unwrap();
        assert!(crypto_verify::ed25519_verify(&pk3, &[0xaf, 0x82], &sig3).is_ok());

        // Tampered signature byte must fail
        let mut bad_sig = sig3;
        bad_sig[63] ^= 0x01;
        assert!(crypto_verify::ed25519_verify(&pk3, &[0xaf, 0x82], &bad_sig).is_err());

        // Non-canonical S >= L must fail
        let mut non_canonical = sig1;
        non_canonical[32..64].fill(0xFF);
        assert!(crypto_verify::ed25519_verify(&pk1, b"", &non_canonical).is_err());
    }

    #[test]
    fn test_sfx_zip_overlay_extraction_preserves_nested_locales_and_rejects_zip_slip() {
        let stub_prefix = vec![0x4Du8; 65_536];
        let zip_bytes = make_synthetic_zip();
        let trailer = build_sgx1_trailer(&zip_bytes, 0x00, [0u8; 64]);

        let mut sfx_bytes = stub_prefix.clone();
        sfx_bytes.extend_from_slice(&zip_bytes);
        sfx_bytes.extend_from_slice(&trailer);

        let (mut archive, payload_len) =
            open_verified_sfx_zip(std::io::Cursor::new(sfx_bytes), None)
                .expect("verified SGX1 SFX must open cleanly")
                .expect("SGX1 SFX archive present");
        assert_eq!(payload_len, zip_bytes.len() as u64);

        let out_dir = std::env::temp_dir().join(format!(
            "singularity_sfx_test_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&out_dir);
        std::fs::create_dir_all(&out_dir).expect("mkdir");

        let prog = Arc::new(Mutex::new(SharedProgress {
            phase: InstallPhase::Idle,
            target_pct: 0.0,
            step_label: String::new(),
            installed_exe: String::new(),
            error_msg: String::new(),
        }));
        extract_zip_archive_to_dir(&mut archive, &out_dir, &prog, &|| {})
            .expect("extract SFX zip");

        assert_eq!(
            std::fs::read(out_dir.join("singularity.exe")).expect("read exe"),
            b"MZ-singularity-test"
        );
        assert_eq!(
            std::fs::read(out_dir.join("libcef.dll")).expect("read dll"),
            b"MZ-libcef-test"
        );
        assert_eq!(
            std::fs::read(out_dir.join("locales").join("fr.pak")).expect("read fr.pak"),
            b"PAK-fr"
        );
        assert!(
            !out_dir.parent().unwrap().join("escape.txt").exists(),
            "zip-slip entry must never escape target_dir"
        );
        let _ = std::fs::remove_dir_all(&out_dir);
    }

    #[test]
    fn test_sfx_rejects_unsealed_raw_zip_and_tampered_or_unsigned_sgx1() {
        let stub_prefix = vec![0x4Du8; 65_536];
        let zip_bytes = make_synthetic_zip();

        // 1. Unsealed raw ZIP overlay (missing SGX1 trailer) MUST be rejected!
        let mut unsealed = stub_prefix.clone();
        unsealed.extend_from_slice(&zip_bytes);
        let err = open_verified_sfx_zip(std::io::Cursor::new(unsealed), None)
            .err()
            .expect("unsealed ZIP overlay must be rejected");
        assert!(err.contains("SGX1"), "unexpected error: {err}");

        // 2. Sealed SGX1 with flipped payload byte MUST fail SHA-256 verification!
        let trailer = build_sgx1_trailer(&zip_bytes, 0x00, [0u8; 64]);
        let mut tampered = stub_prefix.clone();
        tampered.extend_from_slice(&zip_bytes);
        tampered.extend_from_slice(&trailer);
        tampered[stub_prefix.len() + 10] ^= 0xFF;
        let err = open_verified_sfx_zip(std::io::Cursor::new(tampered), None)
            .err()
            .expect("tampered SGX1 ZIP must fail SHA-256");
        assert!(err.contains("SHA-256"), "unexpected error: {err}");

        // 3. Unsigned SGX1 when Ed25519 pubkey is configured MUST be rejected!
        let mut unsigned = stub_prefix.clone();
        unsigned.extend_from_slice(&zip_bytes);
        unsigned.extend_from_slice(&trailer);
        let pubkey_hex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
        let err = open_verified_sfx_zip(std::io::Cursor::new(unsigned), Some(pubkey_hex))
            .err()
            .expect("unsigned SGX1 must fail when pubkey is configured");
        assert!(err.contains("unsigned"), "unexpected error: {err}");

        // 4. Forged Ed25519 signature on SGX1 MUST be rejected!
        let forged_trailer = build_sgx1_trailer(&zip_bytes, SFX_FLAG_ED25519_SIGNED, [0x11u8; 64]);
        let mut forged = stub_prefix.clone();
        forged.extend_from_slice(&zip_bytes);
        forged.extend_from_slice(&forged_trailer);
        let err = open_verified_sfx_zip(std::io::Cursor::new(forged), Some(pubkey_hex))
            .err()
            .expect("forged Ed25519 signature must be rejected");
        assert!(err.contains("Ed25519"), "unexpected error: {err}");

        // 5. Valid Ed25519-signed SGX1 trailer generated by scripts/package-windows-cef.py MUST pass!
        let signed_zip = hex_to_bytes(
            "504b0304140000000000000021002b5463af0e0000000e0000000f00000073696e67756c61726974792e6578654d5a2d7369676e65642d74657374504b01021403140000000000000021002b5463af0e0000000e0000000f000000000000000000000080010000000073696e67756c61726974792e657865504b050600000000010001003d0000003b0000000000",
        );
        let valid_sig: [u8; 64] = hex_to_bytes(
            "393f885c9414b25ccb7acc3596eb6a50ae76eb2104215a8f43be678f948fc1f9\
             ef8da186a56b6449dd3c3d9a4b9b3429e9e727bd7ab964db29579a8623e7390f",
        )
        .try_into()
        .unwrap();
        let signed_trailer = build_sgx1_trailer(&signed_zip, SFX_FLAG_ED25519_SIGNED, valid_sig);
        let mut valid_sfx = stub_prefix;
        valid_sfx.extend_from_slice(&signed_zip);
        valid_sfx.extend_from_slice(&signed_trailer);
        let (mut verified_archive, verified_len) =
            open_verified_sfx_zip(std::io::Cursor::new(valid_sfx), Some(pubkey_hex))
                .expect("valid Ed25519-signed SGX1 SFX must verify")
                .expect("signed SFX archive present");
        assert_eq!(verified_len, signed_zip.len() as u64);
        assert!(verified_archive.by_name("singularity.exe").is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn test_extraction_rejects_symlinks_in_target_dir() {
        use std::os::unix::fs::symlink;

        let base = std::env::temp_dir().join(format!(
            "singularity_symlink_test_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&base);
        let target_dir_case = base.join("install_dir_symlink");
        let target_file_case = base.join("install_file_symlink");
        let outside = base.join("outside");
        std::fs::create_dir_all(&target_dir_case).expect("mkdir target_dir_case");
        std::fs::create_dir_all(&target_file_case).expect("mkdir target_file_case");
        std::fs::create_dir_all(&outside).expect("mkdir outside");

        // Plant a symlinked `locales` directory pointing outside `target_dir_case`
        symlink(&outside, target_dir_case.join("locales")).expect("create dir symlink");

        let zip_bytes = make_synthetic_zip();
        let mut archive = zip::ZipArchive::new(std::io::Cursor::new(&zip_bytes)).unwrap();
        let prog = Arc::new(Mutex::new(SharedProgress {
            phase: InstallPhase::Idle,
            target_pct: 0.0,
            step_label: String::new(),
            installed_exe: String::new(),
            error_msg: String::new(),
        }));
        let res = extract_zip_archive_to_dir(&mut archive, &target_dir_case, &prog, &|| {});
        assert!(res.is_err(), "extraction must reject symlinked subdirectory");
        assert!(
            !outside.join("fr.pak").exists(),
            "must never write through symlink outside install dir"
        );

        // Now test a symlinked destination file (`singularity.exe` -> outside file)
        let outside_file = outside.join("victim.bin");
        std::fs::write(&outside_file, b"original").unwrap();
        symlink(&outside_file, target_file_case.join("singularity.exe"))
            .expect("create file symlink");

        let mut archive2 = zip::ZipArchive::new(std::io::Cursor::new(&zip_bytes)).unwrap();
        let res2 = extract_zip_archive_to_dir(&mut archive2, &target_file_case, &prog, &|| {});
        assert!(res2.is_err(), "extraction must reject symlinked target file");
        assert_eq!(std::fs::read(&outside_file).unwrap(), b"original");

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn test_parse_custom_dir_arg_forms() {
        let a1 = vec!["setup".into(), "--dir".into(), "/opt/singularity".into()];
        assert_eq!(parse_custom_dir_arg(&a1).as_deref(), Some("/opt/singularity"));
        let a2 = vec!["setup".into(), "-d".into(), "C:\\My Apps\\Singularity".into()];
        assert_eq!(
            parse_custom_dir_arg(&a2).as_deref(),
            Some("C:\\My Apps\\Singularity")
        );
        let a3 = vec!["setup".into(), "--dir=/custom/path".into()];
        assert_eq!(parse_custom_dir_arg(&a3).as_deref(), Some("/custom/path"));
        let a4 = vec!["setup".into(), "--silent".into()];
        assert_eq!(parse_custom_dir_arg(&a4), None);
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn test_unix_default_dirs_never_use_tmp() {
        let install = default_install_dir().expect("resolve default install dir");
        assert!(
            !install.starts_with("/tmp"),
            "default_install_dir must never fall back to /tmp: {}",
            install.display()
        );
        let roam = roaming_singularity_dir().expect("resolve roaming dir");
        assert!(
            !roam.starts_with("/tmp"),
            "roaming_singularity_dir must never fall back to /tmp: {}",
            roam.display()
        );
    }
}
