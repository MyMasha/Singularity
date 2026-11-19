//! RFC 6238 TOTP (Time-Based One-Time Password) & RFC 4226 HOTP Generator.

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::Sha256;
use thiserror::Error;
use zeroize::Zeroize;

type HmacSha1 = Hmac<Sha1>;
type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TotpError {
    #[error("Invalid Base32 character '{0}' in TOTP secret")]
    InvalidBase32Char(char),
    #[error("TOTP secret cannot be empty")]
    EmptySecret,
    #[error("Invalid TOTP digits count {0} (must be 6, 7, or 8)")]
    InvalidDigits(u32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TotpAlgorithm {
    Sha1,
    Sha256,
}

/// Decodes an RFC 4648 Base32 TOTP secret (ignoring spaces/hyphens and accepting trailing `=` padding).
pub fn decode_base32_secret(secret_b32: &str) -> Result<Vec<u8>, TotpError> {
    let mut bit_buffer: u32 = 0;
    let mut bit_count: u8 = 0;
    let mut output = Vec::new();
    let mut seen_padding = false;

    for ch in secret_b32.chars() {
        if ch == ' ' || ch == '-' {
            continue;
        }
        if ch == '=' {
            seen_padding = true;
            continue;
        }
        if seen_padding {
            output.zeroize();
            return Err(TotpError::InvalidBase32Char(ch));
        }
        let val: u32 = match ch.to_ascii_uppercase() {
            'A'..='Z' => (ch.to_ascii_uppercase() as u32) - ('A' as u32),
            '2'..='7' => (ch as u32) - ('2' as u32) + 26,
            _ => {
                output.zeroize();
                return Err(TotpError::InvalidBase32Char(ch));
            }
        };

        bit_buffer = (bit_buffer << 5) | val;
        bit_count += 5;

        if bit_count >= 8 {
            bit_count -= 8;
            output.push(((bit_buffer >> bit_count) & 0xFF) as u8);
        }
    }

    if output.is_empty() {
        return Err(TotpError::EmptySecret);
    }

    Ok(output)
}

/// Generates an RFC 6238 TOTP code at `unix_timestamp_sec` with remaining seconds until rotation.
pub fn generate_totp_code(
    secret_base32: &str,
    unix_timestamp_sec: u64,
    period_sec: u64,
    digits: u32,
    algorithm: TotpAlgorithm,
) -> Result<(String, u64), TotpError> {
    if !(6..=8).contains(&digits) {
        return Err(TotpError::InvalidDigits(digits));
    }

    let mut secret_bytes = decode_base32_secret(secret_base32)?;
    let period = period_sec.max(1);
    let counter = unix_timestamp_sec / period;
    let seconds_remaining = period - (unix_timestamp_sec % period);
    let counter_be = counter.to_be_bytes();

    let mut digest: Vec<u8> = match algorithm {
        TotpAlgorithm::Sha1 => {
            let mut mac = HmacSha1::new_from_slice(&secret_bytes).expect("HMAC accepts any key size");
            mac.update(&counter_be);
            mac.finalize().into_bytes().to_vec()
        }
        TotpAlgorithm::Sha256 => {
            let mut mac = HmacSha256::new_from_slice(&secret_bytes).expect("HMAC accepts any key size");
            mac.update(&counter_be);
            mac.finalize().into_bytes().to_vec()
        }
    };
    secret_bytes.zeroize();

    // Dynamic truncation per RFC 4226 Section 5.3
    let offset = (digest[digest.len() - 1] & 0x0F) as usize;
    let binary_code = ((u32::from(digest[offset]) & 0x7F) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);
    digest.zeroize();

    let modulus = 10u32.pow(digits);
    let otp = binary_code % modulus;
    let formatted = format!("{:0width$}", otp, width = digits as usize);

    Ok((formatted, seconds_remaining))
}
