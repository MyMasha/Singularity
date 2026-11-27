//! RFC 6238 TOTP (SHA-1 / SHA-256 / SHA-512), RFC 4226 HOTP, Steam Guard 5-Char OTP,
//! Full `otpauth://` URI Parser/Formatter, and Pure-Rust Google Authenticator
//! `otpauth-migration://offline?data=...` Protobuf Importer.

use base64::{
    engine::general_purpose::{STANDARD as BASE64_STD, STANDARD_NO_PAD as BASE64_STD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
    Engine as _,
};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use std::fmt;
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

type HmacSha1 = Hmac<Sha1>;
type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;

const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const STEAM_ALPHABET: &[u8; 26] = b"23456789BCDFGHJKMNPQRTVWXY";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TotpError {
    #[error("Invalid Base32 character '{0}' in TOTP secret")]
    InvalidBase32Char(char),
    #[error("TOTP secret cannot be empty")]
    EmptySecret,
    #[error("Invalid TOTP digits count {0} (must be 6, 7, or 8)")]
    InvalidDigits(u32),
    #[error("Invalid otpauth URI: {0}")]
    InvalidOtpAuthUri(String),
    #[error("Invalid otpauth-migration protobuf payload: {0}")]
    InvalidMigrationPayload(String),
    #[error("Unsupported OTP algorithm: {0}")]
    UnsupportedAlgorithm(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum TotpAlgorithm {
    #[default]
    Sha1,
    Sha256,
    Sha512,
}

impl TotpAlgorithm {
    pub fn as_otpauth_str(self) -> &'static str {
        match self {
            TotpAlgorithm::Sha1 => "SHA1",
            TotpAlgorithm::Sha256 => "SHA256",
            TotpAlgorithm::Sha512 => "SHA512",
        }
    }

    pub fn from_otpauth_str(s: &str) -> Result<Self, TotpError> {
        match s.trim().to_ascii_uppercase().as_str() {
            "SHA1" | "SHA-1" => Ok(TotpAlgorithm::Sha1),
            "SHA256" | "SHA-256" => Ok(TotpAlgorithm::Sha256),
            "SHA512" | "SHA-512" => Ok(TotpAlgorithm::Sha512),
            other => Err(TotpError::UnsupportedAlgorithm(other.to_string())),
        }
    }
}

/// Type of One-Time Password generator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(tag = "otp_type", rename_all = "snake_case")]
pub enum OtpKind {
    #[default]
    Totp,
    Hotp { counter: u64 },
    Steam,
}

/// Parsed representation of an `otpauth://` or Google Authenticator migration OTP account.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OtpAuthConfig {
    pub kind: OtpKind,
    pub issuer: Option<String>,
    pub account_name: String,
    pub secret_base32: String,
    pub algorithm: TotpAlgorithm,
    pub digits: u32,
    pub period_sec: u64,
}

impl fmt::Debug for OtpAuthConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OtpAuthConfig")
            .field("kind", &self.kind)
            .field("issuer", &self.issuer)
            .field("account_name", &self.account_name)
            .field("secret_base32", &"[REDACTED]")
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("period_sec", &self.period_sec)
            .finish()
    }
}

impl Drop for OtpAuthConfig {
    fn drop(&mut self) {
        self.secret_base32.zeroize();
    }
}

/// Encodes raw secret bytes into unpadded RFC 4648 uppercase Base32.
pub fn encode_base32_secret(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    let mut out = String::with_capacity((bytes.len() * 8).div_ceil(5));
    let mut bit_buffer: u32 = 0;
    let mut bit_count: u8 = 0;

    for &b in bytes {
        bit_buffer = (bit_buffer << 8) | u32::from(b);
        bit_count += 8;
        while bit_count >= 5 {
            bit_count -= 5;
            let idx = ((bit_buffer >> bit_count) & 0x1F) as usize;
            out.push(BASE32_ALPHABET[idx] as char);
        }
    }
    if bit_count > 0 {
        let idx = ((bit_buffer << (5 - bit_count)) & 0x1F) as usize;
        out.push(BASE32_ALPHABET[idx] as char);
    }
    out
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

fn compute_hmac_dynamic_truncation(
    secret_bytes: &[u8],
    counter: u64,
    algorithm: TotpAlgorithm,
) -> u32 {
    let counter_be = counter.to_be_bytes();
    let mut digest: Vec<u8> = match algorithm {
        TotpAlgorithm::Sha1 => {
            let mut mac =
                HmacSha1::new_from_slice(secret_bytes).expect("HMAC accepts any key size");
            mac.update(&counter_be);
            mac.finalize().into_bytes().to_vec()
        }
        TotpAlgorithm::Sha256 => {
            let mut mac =
                HmacSha256::new_from_slice(secret_bytes).expect("HMAC accepts any key size");
            mac.update(&counter_be);
            mac.finalize().into_bytes().to_vec()
        }
        TotpAlgorithm::Sha512 => {
            let mut mac =
                HmacSha512::new_from_slice(secret_bytes).expect("HMAC accepts any key size");
            mac.update(&counter_be);
            mac.finalize().into_bytes().to_vec()
        }
    };

    // Dynamic truncation per RFC 4226 Section 5.3
    let offset = (digest[digest.len() - 1] & 0x0F) as usize;
    let binary_code = ((u32::from(digest[offset]) & 0x7F) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);
    digest.zeroize();
    binary_code
}

fn format_numeric_otp(binary_code: u32, digits: u32) -> String {
    let modulus = 10u32.pow(digits);
    let otp = binary_code % modulus;
    format!("{:0width$}", otp, width = digits as usize)
}

fn format_steam_otp(mut binary_code: u32) -> String {
    let mut code = String::with_capacity(5);
    for _ in 0..5 {
        let idx = (binary_code % 26) as usize;
        code.push(STEAM_ALPHABET[idx] as char);
        binary_code /= 26;
    }
    code
}

/// Generates an RFC 4226 HOTP code for `counter`.
pub fn generate_hotp_code(
    secret_base32: &str,
    counter: u64,
    digits: u32,
    algorithm: TotpAlgorithm,
) -> Result<String, TotpError> {
    if !(6..=8).contains(&digits) {
        return Err(TotpError::InvalidDigits(digits));
    }
    let mut secret_bytes = decode_base32_secret(secret_base32)?;
    let binary_code = compute_hmac_dynamic_truncation(&secret_bytes, counter, algorithm);
    secret_bytes.zeroize();
    Ok(format_numeric_otp(binary_code, digits))
}

/// Generates a 5-character alphanumeric Steam Guard TOTP code (30s period, HMAC-SHA1).
pub fn generate_steam_code(
    secret_base32: &str,
    unix_timestamp_sec: u64,
) -> Result<(String, u64), TotpError> {
    let mut secret_bytes = decode_base32_secret(secret_base32)?;
    let period = 30u64;
    let counter = unix_timestamp_sec / period;
    let remaining = period - (unix_timestamp_sec % period);
    let binary_code = compute_hmac_dynamic_truncation(&secret_bytes, counter, TotpAlgorithm::Sha1);
    secret_bytes.zeroize();
    Ok((format_steam_otp(binary_code), remaining))
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
    let binary_code = compute_hmac_dynamic_truncation(&secret_bytes, counter, algorithm);
    secret_bytes.zeroize();

    Ok((format_numeric_otp(binary_code, digits), seconds_remaining))
}

/// Generates `(current_code, next_code_at_t_plus_1, seconds_remaining)` for smooth UI preview.
pub fn generate_totp_with_next(
    secret_base32: &str,
    unix_timestamp_sec: u64,
    period_sec: u64,
    digits: u32,
    algorithm: TotpAlgorithm,
) -> Result<(String, String, u64), TotpError> {
    if !(6..=8).contains(&digits) {
        return Err(TotpError::InvalidDigits(digits));
    }
    let mut secret_bytes = decode_base32_secret(secret_base32)?;
    let period = period_sec.max(1);
    let counter = unix_timestamp_sec / period;
    let seconds_remaining = period - (unix_timestamp_sec % period);

    let curr_bin = compute_hmac_dynamic_truncation(&secret_bytes, counter, algorithm);
    let next_bin =
        compute_hmac_dynamic_truncation(&secret_bytes, counter.saturating_add(1), algorithm);
    secret_bytes.zeroize();

    Ok((
        format_numeric_otp(curr_bin, digits),
        format_numeric_otp(next_bin, digits),
        seconds_remaining,
    ))
}

/// Generates `(current_code, next_code, seconds_remaining)` for any `OtpAuthConfig` (TOTP, HOTP, or Steam).
pub fn generate_otp_with_next(
    config: &OtpAuthConfig,
    unix_timestamp_sec: u64,
) -> Result<(String, String, u64), TotpError> {
    match config.kind {
        OtpKind::Totp => generate_totp_with_next(
            &config.secret_base32,
            unix_timestamp_sec,
            config.period_sec,
            config.digits,
            config.algorithm,
        ),
        OtpKind::Hotp { counter } => {
            let curr = generate_hotp_code(
                &config.secret_base32,
                counter,
                config.digits,
                config.algorithm,
            )?;
            let next = generate_hotp_code(
                &config.secret_base32,
                counter.saturating_add(1),
                config.digits,
                config.algorithm,
            )?;
            Ok((curr, next, 0))
        }
        OtpKind::Steam => {
            let mut secret_bytes = decode_base32_secret(&config.secret_base32)?;
            let period = 30u64;
            let counter = unix_timestamp_sec / period;
            let remaining = period - (unix_timestamp_sec % period);
            let curr_bin =
                compute_hmac_dynamic_truncation(&secret_bytes, counter, TotpAlgorithm::Sha1);
            let next_bin = compute_hmac_dynamic_truncation(
                &secret_bytes,
                counter.saturating_add(1),
                TotpAlgorithm::Sha1,
            );
            secret_bytes.zeroize();
            Ok((
                format_steam_otp(curr_bin),
                format_steam_otp(next_bin),
                remaining,
            ))
        }
    }
}

/// Verifies a candidate TOTP code with +/- `clock_skew_steps` tolerance in constant time.
pub fn verify_totp_code_with_skew(
    secret_base32: &str,
    candidate_code: &str,
    unix_timestamp_sec: u64,
    period_sec: u64,
    digits: u32,
    algorithm: TotpAlgorithm,
    clock_skew_steps: u64,
) -> Result<bool, TotpError> {
    if !(6..=8).contains(&digits) {
        return Err(TotpError::InvalidDigits(digits));
    }
    let mut secret_bytes = decode_base32_secret(secret_base32)?;
    let period = period_sec.max(1);
    let center = unix_timestamp_sec / period;
    let start = center.saturating_sub(clock_skew_steps);
    let end = center.saturating_add(clock_skew_steps);
    let candidate_trimmed = candidate_code.trim();

    let mut matched = false;
    for step in start..=end {
        let bin = compute_hmac_dynamic_truncation(&secret_bytes, step, algorithm);
        let expected = format_numeric_otp(bin, digits);
        if expected.len() == candidate_trimmed.len()
            && bool::from(expected.as_bytes().ct_eq(candidate_trimmed.as_bytes()))
        {
            matched = true;
        }
    }
    secret_bytes.zeroize();
    Ok(matched)
}

fn percent_decode(input: &str) -> Result<String, TotpError> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex_str = std::str::from_utf8(&bytes[i + 1..i + 3])
                    .map_err(|_| TotpError::InvalidOtpAuthUri("Invalid UTF-8 in percent escape".into()))?;
                let val = u8::from_str_radix(hex_str, 16)
                    .map_err(|_| TotpError::InvalidOtpAuthUri(format!("Invalid percent escape %{}", hex_str)))?;
                out.push(val);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out)
        .map_err(|_| TotpError::InvalidOtpAuthUri("Invalid UTF-8 in decoded URI".into()))
}

fn percent_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{:02X}", byte));
        }
    }
    out
}

/// Parses a complete `otpauth://totp/...`, `otpauth://hotp/...`, or `otpauth://steam/...` URI.
pub fn parse_otpauth_uri(uri: &str) -> Result<OtpAuthConfig, TotpError> {
    let trimmed = uri.trim();
    let rest = trimmed
        .strip_prefix("otpauth://")
        .ok_or_else(|| TotpError::InvalidOtpAuthUri("URI must start with otpauth://".into()))?;

    let (otp_type_raw, after_type) = rest
        .split_once('/')
        .ok_or_else(|| TotpError::InvalidOtpAuthUri("Missing label path".into()))?;
    let otp_type = otp_type_raw.to_ascii_lowercase();

    let (label_raw, query_raw) = after_type
        .split_once('?')
        .ok_or_else(|| TotpError::InvalidOtpAuthUri("Missing query parameters".into()))?;

    let label_decoded = percent_decode(label_raw)?;
    let (label_issuer, account_name) = if let Some((iss, acc)) = label_decoded.split_once(':') {
        (Some(iss.trim().to_string()), acc.trim().to_string())
    } else {
        (None, label_decoded.trim().to_string())
    };

    let mut secret: Option<String> = None;
    let mut query_issuer: Option<String> = None;
    let mut algorithm = TotpAlgorithm::Sha1;
    let mut digits: Option<u32> = None;
    let mut period_sec: u64 = 30;
    let mut counter: Option<u64> = None;
    let mut encoder_steam = false;

    for pair in query_raw.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k_raw, v_raw) = pair.split_once('=').unwrap_or((pair, ""));
        let key = percent_decode(k_raw)?.to_ascii_lowercase();
        let val = percent_decode(v_raw)?;
        match key.as_str() {
            "secret" => secret = Some(val.trim().to_ascii_uppercase()),
            "issuer" if !val.trim().is_empty() => query_issuer = Some(val.trim().to_string()),
            "algorithm" => algorithm = TotpAlgorithm::from_otpauth_str(&val)?,
            "digits" => {
                let d: u32 = val
                    .trim()
                    .parse()
                    .map_err(|_| TotpError::InvalidOtpAuthUri(format!("Invalid digits '{}'", val)))?;
                digits = Some(d);
            }
            "period" => {
                let p: u64 = val
                    .trim()
                    .parse()
                    .map_err(|_| TotpError::InvalidOtpAuthUri(format!("Invalid period '{}'", val)))?;
                if p == 0 {
                    return Err(TotpError::InvalidOtpAuthUri("Period must be > 0".into()));
                }
                period_sec = p;
            }
            "counter" => {
                let c: u64 = val
                    .trim()
                    .parse()
                    .map_err(|_| TotpError::InvalidOtpAuthUri(format!("Invalid counter '{}'", val)))?;
                counter = Some(c);
            }
            "encoder" if val.eq_ignore_ascii_case("steam") => {
                encoder_steam = true;
            }
            _ => {}
        }
    }

    let secret_base32 = secret
        .filter(|s| !s.is_empty())
        .ok_or(TotpError::EmptySecret)?;
    // Validate Base32 secret immediately
    let mut decoded_secret = decode_base32_secret(&secret_base32)?;
    decoded_secret.zeroize();

    let kind = if otp_type == "steam" || encoder_steam {
        OtpKind::Steam
    } else if otp_type == "totp" {
        OtpKind::Totp
    } else if otp_type == "hotp" {
        let c = counter.ok_or_else(|| {
            TotpError::InvalidOtpAuthUri("HOTP URI missing required 'counter' parameter".into())
        })?;
        OtpKind::Hotp { counter: c }
    } else {
        return Err(TotpError::InvalidOtpAuthUri(format!(
            "Unsupported OTP type '{}'",
            otp_type
        )));
    };

    let final_digits = match kind {
        OtpKind::Steam => 5,
        OtpKind::Totp | OtpKind::Hotp { .. } => {
            let d = digits.unwrap_or(6);
            if !(6..=8).contains(&d) {
                return Err(TotpError::InvalidDigits(d));
            }
            d
        }
    };

    let issuer = query_issuer.or(label_issuer).filter(|s| !s.is_empty());

    Ok(OtpAuthConfig {
        kind,
        issuer,
        account_name,
        secret_base32,
        algorithm,
        digits: final_digits,
        period_sec: if matches!(kind, OtpKind::Steam) {
            30
        } else {
            period_sec
        },
    })
}

/// Formats an `OtpAuthConfig` into a canonical `otpauth://` URI.
pub fn format_otpauth_uri(config: &OtpAuthConfig) -> Result<String, TotpError> {
    let mut check = decode_base32_secret(&config.secret_base32)?;
    check.zeroize();

    let type_segment = match config.kind {
        OtpKind::Totp => "totp",
        OtpKind::Hotp { .. } => "hotp",
        OtpKind::Steam => "steam",
    };

    let label = match &config.issuer {
        Some(iss) if !iss.is_empty() => {
            format!("{}:{}", percent_encode(iss), percent_encode(&config.account_name))
        }
        _ => percent_encode(&config.account_name),
    };

    let mut params = Vec::new();
    params.push(format!("secret={}", percent_encode(&config.secret_base32)));
    if let Some(iss) = &config.issuer {
        if !iss.is_empty() {
            params.push(format!("issuer={}", percent_encode(iss)));
        }
    }
    params.push(format!("algorithm={}", config.algorithm.as_otpauth_str()));
    match config.kind {
        OtpKind::Totp => {
            if !(6..=8).contains(&config.digits) {
                return Err(TotpError::InvalidDigits(config.digits));
            }
            params.push(format!("digits={}", config.digits));
            params.push(format!("period={}", config.period_sec.max(1)));
        }
        OtpKind::Hotp { counter } => {
            if !(6..=8).contains(&config.digits) {
                return Err(TotpError::InvalidDigits(config.digits));
            }
            params.push(format!("digits={}", config.digits));
            params.push(format!("counter={}", counter));
        }
        OtpKind::Steam => {
            params.push("digits=5".to_string());
            params.push("period=30".to_string());
            params.push("encoder=steam".to_string());
        }
    }

    Ok(format!(
        "otpauth://{}/{}?{}",
        type_segment,
        label,
        params.join("&")
    ))
}

// --- Minimal Pure-Rust Protobuf Wire Decoder for Google Authenticator Export ---

fn read_protobuf_varint(buf: &[u8], pos: &mut usize) -> Result<u64, TotpError> {
    let mut value: u64 = 0;
    let mut shift: u32 = 0;
    loop {
        if *pos >= buf.len() {
            return Err(TotpError::InvalidMigrationPayload(
                "Unexpected EOF reading protobuf varint".into(),
            ));
        }
        let byte = buf[*pos];
        *pos += 1;
        if shift >= 64 || (shift == 63 && (byte & 0x7F) > 1) {
            return Err(TotpError::InvalidMigrationPayload(
                "Protobuf varint overflow".into(),
            ));
        }
        value |= u64::from(byte & 0x7F) << shift;
        if (byte & 0x80) == 0 {
            return Ok(value);
        }
        shift += 7;
    }
}

fn read_protobuf_len_delimited<'a>(
    buf: &'a [u8],
    pos: &mut usize,
    field_label: &str,
) -> Result<&'a [u8], TotpError> {
    let raw_len = read_protobuf_varint(buf, pos)?;
    let len = usize::try_from(raw_len).map_err(|_| {
        TotpError::InvalidMigrationPayload(format!("Overflowing length in {}", field_label))
    })?;
    let end = pos
        .checked_add(len)
        .filter(|&end| end <= buf.len())
        .ok_or_else(|| {
            TotpError::InvalidMigrationPayload(format!("Truncated {}", field_label))
        })?;
    let slice = &buf[*pos..end];
    *pos = end;
    Ok(slice)
}

fn skip_protobuf_field(buf: &[u8], pos: &mut usize, wire_type: u64) -> Result<(), TotpError> {
    match wire_type {
        0 => {
            let _ = read_protobuf_varint(buf, pos)?;
            Ok(())
        }
        1 => {
            let end = pos
                .checked_add(8)
                .filter(|&end| end <= buf.len())
                .ok_or_else(|| {
                    TotpError::InvalidMigrationPayload("Truncated 64-bit protobuf field".into())
                })?;
            *pos = end;
            Ok(())
        }
        2 => {
            let _ = read_protobuf_len_delimited(buf, pos, "length-delimited protobuf field")?;
            Ok(())
        }
        5 => {
            let end = pos
                .checked_add(4)
                .filter(|&end| end <= buf.len())
                .ok_or_else(|| {
                    TotpError::InvalidMigrationPayload("Truncated 32-bit protobuf field".into())
                })?;
            *pos = end;
            Ok(())
        }
        other => Err(TotpError::InvalidMigrationPayload(format!(
            "Unsupported protobuf wire type {}",
            other
        ))),
    }
}

fn decode_migration_otp_parameters(buf: &[u8]) -> Result<OtpAuthConfig, TotpError> {
    let mut pos = 0usize;
    let mut secret_bytes: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
    let mut name = String::new();
    let mut issuer = String::new();
    let mut algorithm = TotpAlgorithm::Sha1;
    let mut digits: u32 = 6;
    let mut otp_type_enum: u64 = 2; // default TOTP
    let mut counter: u64 = 0;

    while pos < buf.len() {
        let tag = read_protobuf_varint(buf, &mut pos)?;
        let field_number = tag >> 3;
        let wire_type = tag & 0x07;

        match (field_number, wire_type) {
            (1, 2) => {
                let slice = read_protobuf_len_delimited(buf, &mut pos, "secret bytes")?;
                secret_bytes.zeroize();
                secret_bytes.extend_from_slice(slice);
            }
            (2, 2) => {
                let slice = read_protobuf_len_delimited(buf, &mut pos, "account name")?;
                name = std::str::from_utf8(slice)
                    .map_err(|_| {
                        TotpError::InvalidMigrationPayload("Invalid UTF-8 in account name".into())
                    })?
                    .to_string();
            }
            (3, 2) => {
                let slice = read_protobuf_len_delimited(buf, &mut pos, "issuer")?;
                issuer = std::str::from_utf8(slice)
                    .map_err(|_| {
                        TotpError::InvalidMigrationPayload("Invalid UTF-8 in issuer".into())
                    })?
                    .to_string();
            }
            (4, 0) => {
                let alg = read_protobuf_varint(buf, &mut pos)?;
                algorithm = match alg {
                    0 | 1 => TotpAlgorithm::Sha1,
                    2 => TotpAlgorithm::Sha256,
                    3 => TotpAlgorithm::Sha512,
                    other => {
                        return Err(TotpError::UnsupportedAlgorithm(format!(
                            "Google Authenticator algorithm enum {}",
                            other
                        )));
                    }
                };
            }
            (5, 0) => {
                let d = read_protobuf_varint(buf, &mut pos)?;
                digits = match d {
                    0 | 1 => 6,
                    2 => 8,
                    other => {
                        return Err(TotpError::InvalidDigits(
                            u32::try_from(other).unwrap_or(u32::MAX),
                        ));
                    }
                };
            }
            (6, 0) => {
                otp_type_enum = read_protobuf_varint(buf, &mut pos)?;
            }
            (7, 0) => {
                counter = read_protobuf_varint(buf, &mut pos)?;
            }
            _ => skip_protobuf_field(buf, &mut pos, wire_type)?,
        }
    }

    if secret_bytes.is_empty() {
        return Err(TotpError::EmptySecret);
    }
    let secret_base32 = encode_base32_secret(&secret_bytes);
    secret_bytes.zeroize();

    // Google Authenticator sometimes encodes "Issuer:account" in `name` with empty `issuer`
    let (final_issuer, final_account) = if issuer.trim().is_empty() {
        if let Some((iss, acc)) = name.split_once(':') {
            (Some(iss.trim().to_string()), acc.trim().to_string())
        } else {
            (None, name.trim().to_string())
        }
    } else {
        let trimmed_acc = name
            .strip_prefix(&format!("{}:", issuer))
            .unwrap_or(&name)
            .trim()
            .to_string();
        (Some(issuer.trim().to_string()), trimmed_acc)
    };

    let kind = match otp_type_enum {
        1 => OtpKind::Hotp { counter },
        _ => OtpKind::Totp,
    };

    Ok(OtpAuthConfig {
        kind,
        issuer: final_issuer.filter(|s| !s.is_empty()),
        account_name: final_account,
        secret_base32,
        algorithm,
        digits,
        period_sec: 30,
    })
}

/// Decodes a Google Authenticator export URI (`otpauth-migration://offline?data=...`) using a
/// pure-Rust minimal protobuf wire decoder.
pub fn parse_otpauth_migration_uri(uri: &str) -> Result<Vec<OtpAuthConfig>, TotpError> {
    let trimmed = uri.trim();
    let rest = trimmed
        .strip_prefix("otpauth-migration://")
        .ok_or_else(|| {
            TotpError::InvalidMigrationPayload(
                "URI must start with otpauth-migration://".into(),
            )
        })?;

    let (_, query) = rest.split_once('?').ok_or_else(|| {
        TotpError::InvalidMigrationPayload("Missing query string in migration URI".into())
    })?;

    let mut data_b64: Option<String> = None;
    for pair in query.split('&') {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        if k.eq_ignore_ascii_case("data") {
            // In otpauth-migration, '+' may appear literally or as %2B; avoid turning '+' into space
            let decoded_pct = percent_decode_preserve_plus(v)?;
            data_b64 = Some(decoded_pct);
            break;
        }
    }

    let b64_str = data_b64.ok_or_else(|| {
        TotpError::InvalidMigrationPayload("Missing 'data' query parameter".into())
    })?;
    let cleaned: String = b64_str.chars().filter(|c| !c.is_whitespace()).collect();

    let proto_bytes = Zeroizing::new(
        BASE64_STD
            .decode(&cleaned)
            .or_else(|_| BASE64_STD_NO_PAD.decode(&cleaned))
            .or_else(|_| URL_SAFE.decode(&cleaned))
            .or_else(|_| URL_SAFE_NO_PAD.decode(&cleaned))
            .map_err(|_| {
                TotpError::InvalidMigrationPayload("Invalid Base64 data parameter".into())
            })?,
    );

    let mut pos = 0usize;
    let mut accounts = Vec::new();
    while pos < proto_bytes.len() {
        let tag = read_protobuf_varint(&proto_bytes, &mut pos)?;
        let field_number = tag >> 3;
        let wire_type = tag & 0x07;
        match (field_number, wire_type) {
            (1, 2) => {
                let entry_bytes =
                    read_protobuf_len_delimited(&proto_bytes, &mut pos, "OtpParameters entry")?;
                let entry = decode_migration_otp_parameters(entry_bytes)?;
                accounts.push(entry);
            }
            _ => skip_protobuf_field(&proto_bytes, &mut pos, wire_type)?,
        }
    }

    if accounts.is_empty() {
        return Err(TotpError::InvalidMigrationPayload(
            "Migration payload contained zero OTP accounts".into(),
        ));
    }

    Ok(accounts)
}

fn percent_decode_preserve_plus(input: &str) -> Result<String, TotpError> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex_str = std::str::from_utf8(&bytes[i + 1..i + 3]).map_err(|_| {
                TotpError::InvalidMigrationPayload("Invalid UTF-8 in percent escape".into())
            })?;
            let val = u8::from_str_radix(hex_str, 16).map_err(|_| {
                TotpError::InvalidMigrationPayload(format!("Invalid percent escape %{}", hex_str))
            })?;
            out.push(val);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| {
        TotpError::InvalidMigrationPayload("Invalid UTF-8 in migration data".into())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_varint(mut v: u64, out: &mut Vec<u8>) {
        loop {
            let mut b = (v & 0x7F) as u8;
            v >>= 7;
            if v != 0 {
                b |= 0x80;
            }
            out.push(b);
            if v == 0 {
                break;
            }
        }
    }

    fn encode_len_delim(field: u64, data: &[u8], out: &mut Vec<u8>) {
        encode_varint((field << 3) | 2, out);
        encode_varint(data.len() as u64, out);
        out.extend_from_slice(data);
    }

    fn encode_varint_field(field: u64, val: u64, out: &mut Vec<u8>) {
        encode_varint(field << 3, out);
        encode_varint(val, out);
    }

    #[test]
    fn test_rfc6238_official_vectors_sha1_sha256_sha512() {
        let s1 = encode_base32_secret(b"12345678901234567890");
        let s256 = encode_base32_secret(b"12345678901234567890123456789012");
        let s512 = encode_base32_secret(
            b"1234567890123456789012345678901234567890123456789012345678901234",
        );

        let (c1, rem) = generate_totp_code(&s1, 59, 30, 8, TotpAlgorithm::Sha1).unwrap();
        assert_eq!(c1, "94287082");
        assert_eq!(rem, 1);

        let (c256, _) = generate_totp_code(&s256, 59, 30, 8, TotpAlgorithm::Sha256).unwrap();
        assert_eq!(c256, "46119246");

        let (c512, _) = generate_totp_code(&s512, 59, 30, 8, TotpAlgorithm::Sha512).unwrap();
        assert_eq!(c512, "90693936");
    }

    #[test]
    fn test_totp_with_next_clock_skew_hotp_and_steam_guard() {
        let secret = "JBSWY3DPEHPK3PXP";
        let (curr, next, rem) =
            generate_totp_with_next(secret, 1_700_000_000, 30, 6, TotpAlgorithm::Sha1).unwrap();
        let (expected_next, _) =
            generate_totp_code(secret, 1_700_000_030, 30, 6, TotpAlgorithm::Sha1).unwrap();
        assert_eq!(next, expected_next);
        assert!(rem >= 1 && rem <= 30);

        // Clock skew tolerance accepts T+1 with skew=1, rejects with skew=0
        assert!(verify_totp_code_with_skew(
            secret,
            &next,
            1_700_000_000,
            30,
            6,
            TotpAlgorithm::Sha1,
            1
        )
        .unwrap());
        assert!(!verify_totp_code_with_skew(
            secret,
            &next,
            1_700_000_000,
            30,
            6,
            TotpAlgorithm::Sha1,
            0
        )
        .unwrap());
        assert!(verify_totp_code_with_skew(
            secret,
            &curr,
            1_700_000_000,
            30,
            6,
            TotpAlgorithm::Sha1,
            0
        )
        .unwrap());

        // RFC 4226 Appendix D HOTP vector (counter 0 -> 755224, counter 1 -> 287082)
        let hotp_secret = encode_base32_secret(b"12345678901234567890");
        assert_eq!(
            generate_hotp_code(&hotp_secret, 0, 6, TotpAlgorithm::Sha1).unwrap(),
            "755224"
        );
        assert_eq!(
            generate_hotp_code(&hotp_secret, 1, 6, TotpAlgorithm::Sha1).unwrap(),
            "287082"
        );

        // Steam Guard 5-char alphanumeric output
        let (steam_code, steam_rem) = generate_steam_code(secret, 1_700_000_000).unwrap();
        assert_eq!(steam_code.len(), 5);
        assert!(steam_code
            .bytes()
            .all(|b| STEAM_ALPHABET.contains(&b)));
        assert!(steam_rem >= 1 && steam_rem <= 30);
    }

    #[test]
    fn test_otpauth_uri_parse_and_format_roundtrip() {
        let uri = "otpauth://totp/GitHub:alice%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA512&digits=8&period=60";
        let cfg = parse_otpauth_uri(uri).expect("parse otpauth");
        assert_eq!(cfg.kind, OtpKind::Totp);
        assert_eq!(cfg.issuer.as_deref(), Some("GitHub"));
        assert_eq!(cfg.account_name, "alice@example.com");
        assert_eq!(cfg.algorithm, TotpAlgorithm::Sha512);
        assert_eq!(cfg.digits, 8);
        assert_eq!(cfg.period_sec, 60);

        let formatted = format_otpauth_uri(&cfg).expect("format otpauth");
        let reparsed = parse_otpauth_uri(&formatted).expect("reparse otpauth");
        assert_eq!(reparsed, cfg);

        // Steam URI roundtrip
        let steam_uri = "otpauth://totp/Steam:gaben?secret=JBSWY3DPEHPK3PXP&encoder=steam";
        let steam_cfg = parse_otpauth_uri(steam_uri).expect("parse steam");
        assert_eq!(steam_cfg.kind, OtpKind::Steam);
        assert_eq!(steam_cfg.digits, 5);
    }

    #[test]
    fn test_google_authenticator_migration_protobuf_decoder() {
        // Build a MigrationPayload with 2 accounts: SHA256 TOTP + SHA1 HOTP
        let mut entry1 = Vec::new();
        encode_len_delim(1, b"Hello!\xDE\xAD\xBE\xEF", &mut entry1);
        encode_len_delim(2, b"GitHub:alice@singularity.dev", &mut entry1);
        encode_len_delim(3, b"GitHub", &mut entry1);
        encode_varint_field(4, 2, &mut entry1); // SHA256
        encode_varint_field(5, 2, &mut entry1); // 8 digits
        encode_varint_field(6, 2, &mut entry1); // TOTP

        let mut entry2 = Vec::new();
        encode_len_delim(1, b"12345678901234567890", &mut entry2);
        encode_len_delim(2, b"bob@corp.example", &mut entry2);
        encode_len_delim(3, b"CorpVPN", &mut entry2);
        encode_varint_field(4, 1, &mut entry2); // SHA1
        encode_varint_field(5, 1, &mut entry2); // 6 digits
        encode_varint_field(6, 1, &mut entry2); // HOTP
        encode_varint_field(7, 42, &mut entry2); // counter = 42

        let mut payload = Vec::new();
        encode_len_delim(1, &entry1, &mut payload);
        encode_len_delim(1, &entry2, &mut payload);
        encode_varint_field(2, 1, &mut payload); // version = 1
        encode_varint_field(3, 1, &mut payload); // batch_size = 1

        let b64 = percent_encode(&BASE64_STD.encode(&payload));
        let migration_uri = format!("otpauth-migration://offline?data={}", b64);

        let imported = parse_otpauth_migration_uri(&migration_uri).expect("decode migration URI");
        assert_eq!(imported.len(), 2);
        assert_eq!(imported[0].issuer.as_deref(), Some("GitHub"));
        assert_eq!(imported[0].account_name, "alice@singularity.dev");
        assert_eq!(imported[0].algorithm, TotpAlgorithm::Sha256);
        assert_eq!(imported[0].digits, 8);
        assert_eq!(imported[0].kind, OtpKind::Totp);
        assert_eq!(
            decode_base32_secret(&imported[0].secret_base32).unwrap(),
            b"Hello!\xDE\xAD\xBE\xEF"
        );

        assert_eq!(imported[1].issuer.as_deref(), Some("CorpVPN"));
        assert_eq!(imported[1].account_name, "bob@corp.example");
        assert_eq!(imported[1].kind, OtpKind::Hotp { counter: 42 });
        assert_eq!(imported[1].digits, 6);
    }

    #[test]
    fn test_migration_protobuf_rejects_varint_length_overflow_without_panic() {
        // 0x0A (field 1, wire type 2) + 10-byte varint encoding u64::MAX
        let poc_uri = "otpauth-migration://offline?data=Cv//////////AQ==";
        assert!(matches!(
            parse_otpauth_migration_uri(poc_uri),
            Err(TotpError::InvalidMigrationPayload(_))
        ));

        // Unknown length-delimited field (0x12) with u64::MAX length exercises skip_protobuf_field
        let mut unknown_overflow = vec![0x12];
        encode_varint(u64::MAX, &mut unknown_overflow);
        let skip_uri = format!(
            "otpauth-migration://offline?data={}",
            percent_encode(&BASE64_STD.encode(&unknown_overflow))
        );
        assert!(matches!(
            parse_otpauth_migration_uri(&skip_uri),
            Err(TotpError::InvalidMigrationPayload(_))
        ));

        // Truncated 64-bit (wire type 1) and 32-bit (wire type 5) unknown fields
        for raw in [vec![0x11, 0x01], vec![0x15, 0x01]] {
            let uri = format!(
                "otpauth-migration://offline?data={}",
                percent_encode(&BASE64_STD.encode(&raw))
            );
            assert!(matches!(
                parse_otpauth_migration_uri(&uri),
                Err(TotpError::InvalidMigrationPayload(_))
            ));
        }

        // Overflowing secret length inside an OtpParameters submessage
        let mut inner = vec![0x0A];
        encode_varint(u64::MAX, &mut inner);
        let mut outer = Vec::new();
        encode_len_delim(1, &inner, &mut outer);
        let inner_uri = format!(
            "otpauth-migration://offline?data={}",
            percent_encode(&BASE64_STD.encode(&outer))
        );
        assert!(matches!(
            parse_otpauth_migration_uri(&inner_uri),
            Err(TotpError::InvalidMigrationPayload(_))
        ));
    }
}
