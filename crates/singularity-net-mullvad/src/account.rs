//! Strict 16-Digit Mullvad Account Authentication & Public Key Registration Protocol.
//! Zero email, zero password, zero PII.

use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum MullvadAccountError {
    #[error("Invalid Mullvad account number: must contain exactly 16 numeric digits (got {0} digits)")]
    InvalidDigitLength(usize),
    #[error("Invalid Mullvad account number: contains non-numeric character '{0}'")]
    NonNumericCharacter(char),
    #[error("Mullvad account number cannot be all zeros")]
    AllZeroAccountNumber,
}

/// Validated, zeroize-on-drop 16-digit Mullvad account credential.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct MullvadAccountToken {
    digits: String,
}

impl MullvadAccountToken {
    /// Parses a 16-digit Mullvad account number (allowing spaces or hyphens like `1234 5678 9012 3456`).
    pub fn parse(raw_input: &str) -> Result<Self, MullvadAccountError> {
        let mut cleaned = String::with_capacity(16);
        for ch in raw_input.chars() {
            if ch == ' ' || ch == '-' {
                continue;
            }
            if !ch.is_ascii_digit() {
                return Err(MullvadAccountError::NonNumericCharacter(ch));
            }
            cleaned.push(ch);
        }

        if cleaned.len() != 16 {
            return Err(MullvadAccountError::InvalidDigitLength(cleaned.len()));
        }

        if cleaned.chars().all(|c| c == '0') {
            return Err(MullvadAccountError::AllZeroAccountNumber);
        }

        Ok(Self { digits: cleaned })
    }

    /// Returns masked display string for the UI toolbar (`•••• •••• •••• 3456`).
    pub fn masked_display(&self) -> String {
        let tail = &self.digits[12..16];
        format!("•••• •••• •••• {}", tail)
    }

    pub fn raw_digits(&self) -> &str {
        &self.digits
    }
}

/// JSON payload sent to `POST https://api.mullvad.net/app/v1/devices` to register a local WireGuard key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireGuardDeviceRegistrationRequest {
    pub account_token: String,
    pub pubkey_base64: String,
    pub hijack_dns: bool,
    pub enable_pq_psk: bool,
}

/// Assigned internal tunnel addresses returned by Mullvad after registering the local X25519 public key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MullvadDeviceAssignment {
    pub device_name: String,
    pub pubkey_base64: String,
    pub ipv4_address: String,
    pub ipv6_address: String,
    pub in_tunnel_dns_v4: String,
    pub socks5_exit_proxy: String,
}
