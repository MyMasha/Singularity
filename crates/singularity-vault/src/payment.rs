//! Payment Card Validation (Luhn), Brand Detection (including Cartes Bancaires),
//! Number Masking, and 60-Second Step-Up Reauthentication Token Guard.

use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::fmt;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Default TTL (in seconds) for step-up reauthentication tokens gating sensitive vault reveals.
pub const DEFAULT_REAUTH_TTL_SECS: u64 = 60;

/// Supported payment card networks / brands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum CardBrand {
    Visa,
    Mastercard,
    Amex,
    CartesBancaires,
    Discover,
    UnionPay,
    Diners,
    #[default]
    Unknown,
}

impl CardBrand {
    pub fn display_name(self) -> &'static str {
        match self {
            CardBrand::Visa => "Visa",
            CardBrand::Mastercard => "Mastercard",
            CardBrand::Amex => "American Express",
            CardBrand::CartesBancaires => "Cartes Bancaires (CB)",
            CardBrand::Discover => "Discover",
            CardBrand::UnionPay => "UnionPay",
            CardBrand::Diners => "Diners Club",
            CardBrand::Unknown => "Unknown",
        }
    }

    pub fn from_name(name: &str) -> Self {
        match name.trim().to_ascii_lowercase().as_str() {
            "visa" => CardBrand::Visa,
            "mastercard" | "master card" | "mc" => CardBrand::Mastercard,
            "amex" | "american express" => CardBrand::Amex,
            "cb" | "cartes bancaires" | "cartesbancaires" | "carte bleue" => {
                CardBrand::CartesBancaires
            }
            "discover" => CardBrand::Discover,
            "unionpay" | "union pay" | "cup" => CardBrand::UnionPay,
            "diners" | "diners club" => CardBrand::Diners,
            _ => CardBrand::Unknown,
        }
    }
}

/// Strips spaces and hyphens from a raw card number.
pub fn normalize_card_digits(number: &str) -> String {
    number
        .chars()
        .filter(|c| !c.is_ascii_whitespace() && *c != '-')
        .collect()
}

/// Validates a payment card number using the ISO/IEC 7812 Luhn (Mod-10) algorithm.
pub fn validate_luhn(number: &str) -> bool {
    let cleaned = normalize_card_digits(number);
    if !(12..=19).contains(&cleaned.len()) || !cleaned.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }

    let mut sum: u32 = 0;
    let mut double = false;
    for byte in cleaned.bytes().rev() {
        let mut digit = u32::from(byte - b'0');
        if double {
            digit *= 2;
            if digit > 9 {
                digit -= 9;
            }
        }
        sum += digit;
        double = !double;
    }
    sum % 10 == 0
}

/// Detects the payment network / brand from the card BIN/IIN prefix.
pub fn detect_card_brand(number: &str) -> CardBrand {
    let cleaned = normalize_card_digits(number);
    if cleaned.len() < 4 || !cleaned.bytes().all(|b| b.is_ascii_digit()) {
        return CardBrand::Unknown;
    }

    let p2: u32 = cleaned[..2].parse().unwrap_or(0);
    let p3: u32 = cleaned[..3].parse().unwrap_or(0);
    let p4: u32 = cleaned[..4].parse().unwrap_or(0);
    let p6: u32 = if cleaned.len() >= 6 {
        cleaned[..6].parse().unwrap_or(0)
    } else {
        0
    };

    // French Cartes Bancaires (CB) co-badged BIN ranges (checked before generic Visa/Mastercard)
    if matches!(p4, 4970..=4979 | 4990 | 4561 | 4398 | 5131 | 5132) {
        return CardBrand::CartesBancaires;
    }

    // American Express: 34, 37
    if p2 == 34 || p2 == 37 {
        return CardBrand::Amex;
    }

    // Diners Club: 300-305, 3095, 36, 38, 39
    if (300..=305).contains(&p3) || p4 == 3095 || matches!(p2, 36 | 38 | 39) {
        return CardBrand::Diners;
    }

    // Discover: 6011, 644-649, 65, 622126-622925
    if p4 == 6011
        || (644..=649).contains(&p3)
        || p2 == 65
        || (622126..=622925).contains(&p6)
    {
        return CardBrand::Discover;
    }

    // UnionPay: 62 (after Discover 622126-622925 range)
    if p2 == 62 {
        return CardBrand::UnionPay;
    }

    // Mastercard: 51-55 or 2221-2720
    if (51..=55).contains(&p2) || (2221..=2720).contains(&p4) {
        return CardBrand::Mastercard;
    }

    // Visa: starts with 4
    if cleaned.starts_with('4') {
        return CardBrand::Visa;
    }

    CardBrand::Unknown
}

/// Masks a payment card number displaying only the last 4 digits (`•••• •••• •••• 4242`).
pub fn mask_card_number(number: &str) -> String {
    let digits: String = number.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() < 4 {
        return "••••".to_string();
    }
    let last4 = &digits[digits.len() - 4..];
    format!("•••• •••• •••• {}", last4)
}

/// Checks whether a card with `(exp_month, exp_year)` is expired at `(current_year, current_month)`.
pub fn is_card_expired(
    exp_month: u8,
    exp_year: u16,
    current_year: u16,
    current_month: u8,
) -> bool {
    if !(1..=12).contains(&exp_month) {
        return true;
    }
    let full_exp_year = if exp_year < 100 {
        2000 + exp_year
    } else {
        exp_year
    };
    (full_exp_year, exp_month) < (current_year, current_month)
}

/// Short-lived (default 60 s) constant-time reauthentication token guard protecting
/// sensitive vault operations (e.g., revealing payment card PAN/CVV, exporting plaintext,
/// or viewing SSH private keys).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ReauthTokenGuard {
    token_bytes: [u8; 32],
    #[zeroize(skip)]
    issued_at_unix: u64,
    #[zeroize(skip)]
    ttl_secs: u64,
    #[zeroize(skip)]
    revoked: bool,
}

impl fmt::Debug for ReauthTokenGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReauthTokenGuard")
            .field("token_bytes", &"[REDACTED]")
            .field("issued_at_unix", &self.issued_at_unix)
            .field("ttl_secs", &self.ttl_secs)
            .field("revoked", &self.revoked)
            .finish()
    }
}

impl ReauthTokenGuard {
    /// Issues a new reauthentication token with the default 60-second TTL.
    pub fn issue(now_unix: u64) -> Self {
        Self::issue_with_ttl(now_unix, DEFAULT_REAUTH_TTL_SECS)
    }

    /// Issues a new reauthentication token with an explicit TTL in seconds.
    pub fn issue_with_ttl(now_unix: u64, ttl_secs: u64) -> Self {
        let mut token_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut token_bytes);
        Self {
            token_bytes,
            issued_at_unix: now_unix,
            ttl_secs: ttl_secs.max(1),
            revoked: false,
        }
    }

    /// Returns the hex-encoded token string for presentation by the authenticated UI session.
    pub fn token_hex(&self) -> String {
        hex::encode(self.token_bytes)
    }

    /// Returns the Unix timestamp at which this token expires.
    pub fn expires_at_unix(&self) -> u64 {
        self.issued_at_unix.saturating_add(self.ttl_secs)
    }

    /// Returns `true` if the token has expired or been revoked.
    pub fn is_expired(&self, now_unix: u64) -> bool {
        self.revoked
            || now_unix < self.issued_at_unix
            || now_unix.saturating_sub(self.issued_at_unix) >= self.ttl_secs
    }

    /// Verifies `presented_token_hex` in constant time and enforces TTL and non-revocation.
    pub fn verify(&self, presented_token_hex: &str, now_unix: u64) -> bool {
        if self.is_expired(now_unix) {
            return false;
        }
        let Ok(decoded) = hex::decode(presented_token_hex.trim()) else {
            return false;
        };
        if decoded.len() != 32 {
            return false;
        }
        bool::from(decoded.as_slice().ct_eq(&self.token_bytes))
    }

    /// One-shot verification that immediately revokes and zeroizes the token upon successful match.
    pub fn verify_and_consume(&mut self, presented_token_hex: &str, now_unix: u64) -> bool {
        let ok = self.verify(presented_token_hex, now_unix);
        if ok {
            self.revoke();
        }
        ok
    }

    /// Immediately revokes and zeroizes the token material.
    pub fn revoke(&mut self) {
        self.token_bytes.zeroize();
        self.revoked = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_luhn_and_brand_detection_and_masking() {
        // Valid Visa test card (4242...)
        assert!(validate_luhn("4242 4242 4242 4242"));
        assert!(!validate_luhn("4242 4242 4242 4243"));
        assert_eq!(detect_card_brand("4242 4242 4242 4242"), CardBrand::Visa);
        assert_eq!(
            mask_card_number("4242 4242 4242 4242"),
            "•••• •••• •••• 4242"
        );

        // Cartes Bancaires French BIN
        assert_eq!(
            detect_card_brand("4970-1234-5678-9012"),
            CardBrand::CartesBancaires
        );
        // Mastercard 51..55 and 2221..2720
        assert_eq!(
            detect_card_brand("5555 5555 5555 4444"),
            CardBrand::Mastercard
        );
        assert!(validate_luhn("5555555555554444"));
        assert_eq!(
            detect_card_brand("2221 0000 0000 0009"),
            CardBrand::Mastercard
        );
        // Amex
        assert_eq!(detect_card_brand("3782 822463 10005"), CardBrand::Amex);
        assert!(validate_luhn("378282246310005"));
        // Discover, UnionPay, Diners
        assert_eq!(detect_card_brand("6011 1111 1111 1117"), CardBrand::Discover);
        assert!(validate_luhn("6011111111111117"));
        assert_eq!(detect_card_brand("6221 2500 0000 0000"), CardBrand::UnionPay);
        assert_eq!(detect_card_brand("3056 9309 0259 04"), CardBrand::Diners);
        assert_eq!(detect_card_brand("9999 0000 0000 0000"), CardBrand::Unknown);
    }

    #[test]
    fn test_reauth_token_guard_ttl_60s_and_consume() {
        let mut guard = ReauthTokenGuard::issue(1_000);
        let tok = guard.token_hex();
        assert!(guard.verify(&tok, 1_000));
        assert!(guard.verify(&tok, 1_059));
        assert!(!guard.verify(&tok, 1_060)); // expired at exactly 60s
        assert!(!guard.verify("deadbeef", 1_010));
        assert!(!format!("{:?}", guard).contains(&tok));

        // One-shot consume revokes token immediately
        assert!(guard.verify_and_consume(&tok, 1_030));
        assert!(!guard.verify(&tok, 1_031));
    }
}
