//! Offline Zero-Knowledge k-Anonymity Bloom Filter, HIBP Range Response Parser,
//! Shannon Entropy & Weak Pattern Analyzer (AZERTY/QWERTY, Dates, Leetspeak),
//! Ephemeral-Key HMAC-SHA256 Reuse Detector, Embedded 2FA/Passkey Directory,
//! and Complete `VaultHealthReport`.

use crate::format::{VaultItem, VaultItemKind};
use crate::matcher::{extract_etld_plus_one, parse_uri_components};
use crate::passkey::StoredPasskeyCredential;
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

/// Threshold in seconds (180 days) after which a login password is flagged as stale/old.
pub const PASSWORD_MAX_AGE_SECONDS: u64 = 180 * 24 * 60 * 60;

/// Offline k-anonymity Bloom Filter storing breached password SHA-256 digests
/// so password audits never transmit a single byte over the network.
pub struct OfflineBreachBloomFilter {
    bits: Vec<u64>,
    bit_count: usize,
    k_hashes: u32,
}

const COMMON_BREACHED_PASSWORDS: &[&str] = &[
    "password", "password1", "password123", "password1234", "password!", "p@ssword", "p@ssw0rd",
    "passw0rd", "123456", "1234567", "12345678", "123456789", "1234567890", "12345", "1234",
    "123123", "111111", "000000", "654321", "987654321", "qwerty", "qwerty123", "qwertyuiop",
    "azerty", "azerty123", "azertyuiop", "zxcvbnm", "asdfghjkl", "1q2w3e4r", "1qaz2wsx",
    "qazwsx", "admin", "admin123", "administrator", "root", "toor", "letmein", "welcome",
    "welcome1", "welcome123", "iloveyou", "monkey", "dragon", "sunshine", "princess", "football",
    "charlie", "aa123456", "donald", "trustno1", "master", "shadow", "superman", "batman",
    "michael", "jennifer", "jessica", "ashley", "bailey", "baseball", "basketball", "soccer",
    "hockey", "freedom", "whatever", "mustang", "access", "secret", "pass", "test", "test123",
    "guest", "changeme", "default", "login", "starwars", "pokemon", "naruto", "matrix",
    "minecraft", "fortnite", "roblox", "discord", "google", "facebook", "instagram", "twitter",
    "apple", "microsoft", "windows", "ubuntu", "linux", "paris", "france", "marseille", "lyon",
    "bonjour", "bonjour123", "soleil", "amour", "chocolat", "motdepasse", "motdepasse123",
    "doudou", "loulou", "maison", "voiture", "famille", "papa", "maman", "toto", "tata",
    "azerty1", "abc123", "abcdef", "abcdefg", "abcd1234", "a1b2c3d4", "qwerty1", "00000000",
    "11111111", "22222222", "88888888", "99999999", "666666", "7777777", "121212", "131313",
    "2020", "2021", "2022", "2023", "2024", "2025", "2026", "summer", "winter", "spring",
    "autumn", "january", "december", "flower", "killer", "hacker", "lovely", "angel", "cookie",
    "coffee", "pepper", "ginger", "hunter", "ranger", "buster", "thomas", "robert", "daniel",
    "matthew", "andrew", "jordan", "george", "anthony", "nicole", "hannah", "amanda", "rachel",
    "taylor", "morgan", "alex", "alex123", "kevin", "david", "sarah", "laura", "sophie",
    "camille", "lucas", "thomas123", "nicolas", "julien", "antoine", "maxime", "claire",
    "marie", "paul", "pierre", "jean", "marc", "eric", "bruno", "laurent", "olivier",
    "singularity", "mullvad", "bitcoin", "crypto", "wallet", "qwerty12345", "123456789a",
    "password2024", "password2025", "password2026", "admin2024", "admin2025", "admin2026",
];

impl Default for OfflineBreachBloomFilter {
    fn default() -> Self {
        let mut filter = Self::new(131072, 5);
        for &common_breached in COMMON_BREACHED_PASSWORDS {
            filter.insert_breached_password(common_breached);
        }
        filter
    }
}

impl OfflineBreachBloomFilter {
    pub fn new(bit_count: usize, k_hashes: u32) -> Self {
        let words = (bit_count.max(64) + 63) / 64;
        Self {
            bits: vec![0u64; words],
            bit_count: words * 64,
            k_hashes: k_hashes.max(1),
        }
    }

    pub fn insert_breached_password(&mut self, password: &str) {
        let normalized = password.trim().to_ascii_lowercase();
        for idx in self.compute_bit_indices(&normalized) {
            let word = idx / 64;
            let bit = idx % 64;
            self.bits[word] |= 1u64 << bit;
        }
    }

    /// Checks in O(k) time whether `password` (exact or case-normalized) appears in the
    /// offline breached bloom filter or matches trivial repeated/sequential patterns.
    pub fn is_likely_breached(&self, password: &str) -> bool {
        let trimmed = password.trim();
        if trimmed.is_empty() {
            return true;
        }
        // Trivial single-character repetition (e.g. "aaaaaaaa")
        let mut chars = trimmed.chars();
        if let Some(first) = chars.next() {
            if chars.all(|c| c == first) {
                return true;
            }
        }
        let normalized = trimmed.to_ascii_lowercase();
        for idx in self.compute_bit_indices(&normalized) {
            let word = idx / 64;
            let bit = idx % 64;
            if (self.bits[word] & (1u64 << bit)) == 0 {
                return false;
            }
        }
        true
    }

    /// Computes the 5-character uppercase SHA-1 k-anonymity prefix for offline HIBP range matching.
    pub fn k_anonymity_sha1_prefix(password: &str) -> (String, String) {
        let digest = Sha1::digest(password.as_bytes());
        let full_hex = hex::encode_upper(digest);
        (full_hex[0..5].to_string(), full_hex[5..].to_string())
    }

    fn compute_bit_indices(&self, password: &str) -> Vec<usize> {
        let digest: [u8; 32] = Sha256::digest(password.as_bytes()).into();
        let h1 = u64::from_le_bytes(digest[0..8].try_into().unwrap());
        let h2 = u64::from_le_bytes(digest[8..16].try_into().unwrap()).max(1);

        (0..self.k_hashes)
            .map(|i| {
                let combined = h1.wrapping_add((i as u64).wrapping_mul(h2));
                (combined as usize) % self.bit_count
            })
            .collect()
    }
}

/// Parses an HIBP Pwned Passwords k-anonymity range response body (`SUFFIX:COUNT` lines)
/// against `full_sha1_hex` (40-char full SHA-1 hex or 35-char suffix) in constant time.
/// Returns the reported breach occurrence count (`0` if not found).
pub fn parse_hibp_range_response(full_sha1_hex: &str, range_body: &str) -> u64 {
    let normalized = full_sha1_hex.trim().to_ascii_uppercase();
    let target_suffix = if normalized.len() == 40 {
        &normalized[5..]
    } else if normalized.len() == 35 {
        normalized.as_str()
    } else {
        return 0;
    };

    let mut found_count: u64 = 0;
    for line in range_body.lines() {
        let trimmed = line.trim();
        if let Some((suffix, count_str)) = trimmed.split_once(':') {
            let candidate = suffix.trim().to_ascii_uppercase();
            if candidate.len() == target_suffix.len()
                && bool::from(candidate.as_bytes().ct_eq(target_suffix.as_bytes()))
            {
                if let Ok(c) = count_str.trim().parse::<u64>() {
                    found_count = c;
                }
            }
        }
    }
    found_count
}

/// Estimates effective password entropy in bits using actual Shannon symbol distribution
/// combined with character pool cardinality and penalties for adjacent repetitions/sequences.
pub fn estimate_password_entropy_bits(password: &str) -> f64 {
    let chars: Vec<char> = password.chars().collect();
    let n = chars.len();
    if n == 0 {
        return 0.0;
    }

    let mut freq: HashMap<char, usize> = HashMap::new();
    let mut has_lower = false;
    let mut has_upper = false;
    let mut has_digit = false;
    let mut has_symbol = false;

    for &ch in &chars {
        *freq.entry(ch).or_insert(0) += 1;
        if ch.is_ascii_lowercase() {
            has_lower = true;
        } else if ch.is_ascii_uppercase() {
            has_upper = true;
        } else if ch.is_ascii_digit() {
            has_digit = true;
        } else {
            has_symbol = true;
        }
    }

    // True Shannon entropy per symbol: H = -sum(p_i * log2(p_i))
    let nf = n as f64;
    let mut shannon_per_char = 0.0_f64;
    for &count in freq.values() {
        let p = (count as f64) / nf;
        shannon_per_char -= p * p.log2();
    }
    if shannon_per_char <= 0.0 {
        // All characters identical (e.g. "aaaaaaaaaaaa")
        return (nf.log2()).min(4.0);
    }

    let mut pool_size: f64 = 0.0;
    if has_lower {
        pool_size += 26.0;
    }
    if has_upper {
        pool_size += 26.0;
    }
    if has_digit {
        pool_size += 10.0;
    }
    if has_symbol {
        pool_size += 32.0;
    }

    // Penalize adjacent repeats and simple +/-1 ASCII sequences (e.g. "abcd", "1234")
    let mut sequential_or_repeat = 0usize;
    for w in chars.windows(2) {
        let a = w[0] as i64;
        let b = w[1] as i64;
        if a == b || (b - a).abs() == 1 {
            sequential_or_repeat += 1;
        }
    }
    let effective_len = (n.saturating_sub(sequential_or_repeat / 2)).max(1) as f64;
    let diversity_ratio = (shannon_per_char / nf.log2().max(1.0)).clamp(0.0, 1.0);
    let pool_bits = effective_len * pool_size.max(2.0).log2() * diversity_ratio;
    let shannon_bits = effective_len * shannon_per_char;

    // Conservative estimate bounded by pool cardinality scaled by Shannon diversity
    pool_bits.max(shannon_bits)
}

// ============================================================================
// EMBEDDED OFFLINE 2FA.DIRECTORY & PASSKEYS.DIRECTORY TABLE
// ============================================================================

/// Offline site authentication capability entry (sourced from 2fa.directory / passkeys.directory).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SiteSecuritySupport {
    pub domain: &'static str,
    pub supports_totp: bool,
    pub supports_passkey: bool,
    pub supports_hardware_key: bool,
    pub documentation_url: &'static str,
}

const OFFLINE_SITE_SECURITY_DIRECTORY: &[SiteSecuritySupport] = &[
    SiteSecuritySupport { domain: "github.com", supports_totp: true, supports_passkey: true, supports_hardware_key: true, documentation_url: "https://docs.github.com/en/authentication" },
    SiteSecuritySupport { domain: "google.com", supports_totp: true, supports_passkey: true, supports_hardware_key: true, documentation_url: "https://myaccount.google.com/security" },
    SiteSecuritySupport { domain: "apple.com", supports_totp: true, supports_passkey: true, supports_hardware_key: true, documentation_url: "https://support.apple.com/en-us/102660" },
    SiteSecuritySupport { domain: "microsoft.com", supports_totp: true, supports_passkey: true, supports_hardware_key: true, documentation_url: "https://account.microsoft.com/security" },
    SiteSecuritySupport { domain: "amazon.com", supports_totp: true, supports_passkey: true, supports_hardware_key: false, documentation_url: "https://www.amazon.com/a/settings/approval" },
    SiteSecuritySupport { domain: "amazon.fr", supports_totp: true, supports_passkey: true, supports_hardware_key: false, documentation_url: "https://www.amazon.fr/a/settings/approval" },
    SiteSecuritySupport { domain: "cloudflare.com", supports_totp: true, supports_passkey: true, supports_hardware_key: true, documentation_url: "https://developers.cloudflare.com/fundamentals/setup/account/account-security/2fa/" },
    SiteSecuritySupport { domain: "discord.com", supports_totp: true, supports_passkey: true, supports_hardware_key: true, documentation_url: "https://support.discord.com/hc/en-us/articles/219576828" },
    SiteSecuritySupport { domain: "paypal.com", supports_totp: true, supports_passkey: true, supports_hardware_key: true, documentation_url: "https://www.paypal.com/myaccount/security/" },
    SiteSecuritySupport { domain: "stripe.com", supports_totp: true, supports_passkey: true, supports_hardware_key: true, documentation_url: "https://stripe.com/docs/dashboard/two-step-authentication" },
    SiteSecuritySupport { domain: "gitlab.com", supports_totp: true, supports_passkey: true, supports_hardware_key: true, documentation_url: "https://docs.gitlab.com/ee/user/profile/account/two_factor_authentication.html" },
    SiteSecuritySupport { domain: "bitbucket.org", supports_totp: true, supports_passkey: true, supports_hardware_key: true, documentation_url: "https://support.atlassian.com/bitbucket-cloud/docs/enable-two-step-verification/" },
    SiteSecuritySupport { domain: "proton.me", supports_totp: true, supports_passkey: true, supports_hardware_key: true, documentation_url: "https://proton.me/support/two-factor-authentication-2fa" },
    SiteSecuritySupport { domain: "protonmail.com", supports_totp: true, supports_passkey: true, supports_hardware_key: true, documentation_url: "https://proton.me/support/two-factor-authentication-2fa" },
    SiteSecuritySupport { domain: "fastmail.com", supports_totp: true, supports_passkey: true, supports_hardware_key: true, documentation_url: "https://www.fastmail.help/hc/en-us/articles/360060591073" },
    SiteSecuritySupport { domain: "dropbox.com", supports_totp: true, supports_passkey: true, supports_hardware_key: true, documentation_url: "https://help.dropbox.com/account-access/enable-two-step-verification" },
    SiteSecuritySupport { domain: "slack.com", supports_totp: true, supports_passkey: false, supports_hardware_key: false, documentation_url: "https://slack.com/help/articles/204509068" },
    SiteSecuritySupport { domain: "notion.so", supports_totp: true, supports_passkey: true, supports_hardware_key: true, documentation_url: "https://www.notion.so/help/two-step-verification" },
    SiteSecuritySupport { domain: "linear.app", supports_totp: true, supports_passkey: true, supports_hardware_key: true, documentation_url: "https://linear.app/docs" },
    SiteSecuritySupport { domain: "figma.com", supports_totp: true, supports_passkey: false, supports_hardware_key: false, documentation_url: "https://help.figma.com/hc/en-us/articles/360039822974" },
    SiteSecuritySupport { domain: "npmjs.com", supports_totp: true, supports_passkey: true, supports_hardware_key: true, documentation_url: "https://docs.npmjs.com/configuring-two-factor-authentication" },
    SiteSecuritySupport { domain: "pypi.org", supports_totp: true, supports_passkey: true, supports_hardware_key: true, documentation_url: "https://pypi.org/help/#twofa" },
    SiteSecuritySupport { domain: "docker.com", supports_totp: true, supports_passkey: false, supports_hardware_key: false, documentation_url: "https://docs.docker.com/security/for-admins/2fa/" },
    SiteSecuritySupport { domain: "digitalocean.com", supports_totp: true, supports_passkey: true, supports_hardware_key: true, documentation_url: "https://docs.digitalocean.com/products/accounts/security/2fa/" },
    SiteSecuritySupport { domain: "hetzner.com", supports_totp: true, supports_passkey: true, supports_hardware_key: true, documentation_url: "https://docs.hetzner.com/accounts/accounts/two-factor-authentication/" },
    SiteSecuritySupport { domain: "ovhcloud.com", supports_totp: true, supports_passkey: false, supports_hardware_key: true, documentation_url: "https://help.ovhcloud.com/csm/en-account-secure-account-2fa" },
    SiteSecuritySupport { domain: "reddit.com", supports_totp: true, supports_passkey: false, supports_hardware_key: false, documentation_url: "https://support.reddithelp.com/hc/en-us/articles/360043470031" },
    SiteSecuritySupport { domain: "x.com", supports_totp: true, supports_passkey: true, supports_hardware_key: true, documentation_url: "https://help.x.com/en/managing-your-account/two-factor-authentication" },
    SiteSecuritySupport { domain: "twitter.com", supports_totp: true, supports_passkey: true, supports_hardware_key: true, documentation_url: "https://help.x.com/en/managing-your-account/two-factor-authentication" },
    SiteSecuritySupport { domain: "instagram.com", supports_totp: true, supports_passkey: false, supports_hardware_key: false, documentation_url: "https://help.instagram.com/566810106808145" },
    SiteSecuritySupport { domain: "facebook.com", supports_totp: true, supports_passkey: true, supports_hardware_key: true, documentation_url: "https://www.facebook.com/help/148233965247823" },
    SiteSecuritySupport { domain: "linkedin.com", supports_totp: true, supports_passkey: true, supports_hardware_key: false, documentation_url: "https://www.linkedin.com/help/linkedin/answer/a1381088" },
    SiteSecuritySupport { domain: "twitch.tv", supports_totp: true, supports_passkey: false, supports_hardware_key: false, documentation_url: "https://help.twitch.tv/s/article/two-factor-authentication" },
    SiteSecuritySupport { domain: "steampowered.com", supports_totp: true, supports_passkey: false, supports_hardware_key: false, documentation_url: "https://help.steampowered.com/en/faqs/view/7EFD-3CAE-64D3-1C31" },
    SiteSecuritySupport { domain: "epicgames.com", supports_totp: true, supports_passkey: false, supports_hardware_key: false, documentation_url: "https://www.epicgames.com/help/en-US/c-Category_EpicAccount/c-AccountSecurity/two-factor-authentication-2fa" },
    SiteSecuritySupport { domain: "nintendo.com", supports_totp: true, supports_passkey: true, supports_hardware_key: false, documentation_url: "https://en-americas-support.nintendo.com/app/answers/detail/a_id/27496" },
    SiteSecuritySupport { domain: "playstation.com", supports_totp: true, supports_passkey: true, supports_hardware_key: false, documentation_url: "https://www.playstation.com/en-us/passkey/" },
    SiteSecuritySupport { domain: "ebay.com", supports_totp: true, supports_passkey: true, supports_hardware_key: false, documentation_url: "https://www.ebay.com/help/account/protecting-account/2-step-verification" },
    SiteSecuritySupport { domain: "shopify.com", supports_totp: true, supports_passkey: true, supports_hardware_key: true, documentation_url: "https://help.shopify.com/en/manual/your-account/logging-in/two-step-authentication" },
    SiteSecuritySupport { domain: "binance.com", supports_totp: true, supports_passkey: true, supports_hardware_key: true, documentation_url: "https://www.binance.com/en/support/faq/two-factor-authentication" },
    SiteSecuritySupport { domain: "coinbase.com", supports_totp: true, supports_passkey: true, supports_hardware_key: true, documentation_url: "https://help.coinbase.com/en/coinbase/getting-started/getting-started-with-coinbase/2-step-verification" },
    SiteSecuritySupport { domain: "kraken.com", supports_totp: true, supports_passkey: true, supports_hardware_key: true, documentation_url: "https://support.kraken.com/hc/en-us/articles/360000426923" },
    SiteSecuritySupport { domain: "wise.com", supports_totp: true, supports_passkey: true, supports_hardware_key: false, documentation_url: "https://wise.com/help/articles/2977959" },
    SiteSecuritySupport { domain: "revolut.com", supports_totp: false, supports_passkey: true, supports_hardware_key: false, documentation_url: "https://help.revolut.com/" },
    SiteSecuritySupport { domain: "adobe.com", supports_totp: true, supports_passkey: true, supports_hardware_key: false, documentation_url: "https://helpx.adobe.com/manage-account/using/two-step-verification.html" },
    SiteSecuritySupport { domain: "1password.com", supports_totp: true, supports_passkey: true, supports_hardware_key: true, documentation_url: "https://support.1password.com/two-factor-authentication/" },
    SiteSecuritySupport { domain: "bitwarden.com", supports_totp: true, supports_passkey: true, supports_hardware_key: true, documentation_url: "https://bitwarden.com/help/setup-two-step-login/" },
    SiteSecuritySupport { domain: "vercel.com", supports_totp: true, supports_passkey: true, supports_hardware_key: true, documentation_url: "https://vercel.com/docs/accounts/account-security" },
    SiteSecuritySupport { domain: "supabase.com", supports_totp: true, supports_passkey: false, supports_hardware_key: false, documentation_url: "https://supabase.com/docs/guides/auth/auth-mfa" },
    SiteSecuritySupport { domain: "openai.com", supports_totp: true, supports_passkey: true, supports_hardware_key: false, documentation_url: "https://help.openai.com/" },
    SiteSecuritySupport { domain: "anthropic.com", supports_totp: true, supports_passkey: false, supports_hardware_key: false, documentation_url: "https://support.anthropic.com/" },
    SiteSecuritySupport { domain: "huggingface.co", supports_totp: true, supports_passkey: true, supports_hardware_key: true, documentation_url: "https://huggingface.co/docs/hub/security-mfa" },
    SiteSecuritySupport { domain: "tailscale.com", supports_totp: true, supports_passkey: true, supports_hardware_key: true, documentation_url: "https://tailscale.com/kb/1013/sso-providers" },
    SiteSecuritySupport { domain: "mullvad.net", supports_totp: false, supports_passkey: false, supports_hardware_key: false, documentation_url: "https://mullvad.net/en/help" },
    SiteSecuritySupport { domain: "whatsapp.com", supports_totp: false, supports_passkey: true, supports_hardware_key: false, documentation_url: "https://faq.whatsapp.com/" },
    SiteSecuritySupport { domain: "tiktok.com", supports_totp: true, supports_passkey: true, supports_hardware_key: false, documentation_url: "https://support.tiktok.com/" },
    SiteSecuritySupport { domain: "uber.com", supports_totp: true, supports_passkey: true, supports_hardware_key: false, documentation_url: "https://help.uber.com/" },
    SiteSecuritySupport { domain: "booking.com", supports_totp: false, supports_passkey: true, supports_hardware_key: false, documentation_url: "https://www.booking.com/security" },
    SiteSecuritySupport { domain: "impots.gouv.fr", supports_totp: false, supports_passkey: false, supports_hardware_key: false, documentation_url: "https://www.impots.gouv.fr/" },
    SiteSecuritySupport { domain: "sncf-connect.com", supports_totp: false, supports_passkey: true, supports_hardware_key: false, documentation_url: "https://www.sncf-connect.com/" },
];

/// Looks up offline 2FA / Passkey support for a domain (accepts `eTLD+1`, subdomain, or full URL).
pub fn lookup_site_security_support(etld_plus_1_or_uri: &str) -> Option<SiteSecuritySupport> {
    let normalized = extract_etld_plus_one(etld_plus_1_or_uri)
        .unwrap_or_else(|| etld_plus_1_or_uri.trim().to_ascii_lowercase());
    OFFLINE_SITE_SECURITY_DIRECTORY
        .iter()
        .copied()
        .find(|entry| entry.domain == normalized)
}

// ============================================================================
// WEAK PASSWORD PATTERN ANALYZER (AZERTY/QWERTY, DATES, LEETSPEAK, DICTIONARY)
// ============================================================================

/// Specific structural weakness detected in a password.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum WeakPasswordReason {
    TooShort { length: usize },
    LowEntropy { entropy_bits: u32 },
    CommonBreached,
    KeyboardPattern { pattern: String },
    DatePattern { pattern: String },
    LeetspeakDictionaryWord { word: String },
    RepeatedPattern,
}

const KEYBOARD_SEQUENCES: &[&str] = &[
    // AZERTY rows & diagonals
    "azertyuiop",
    "qsdfghjklm",
    "wxcvbn",
    "1a2z3e4r5t6y",
    "a1z2e3r4",
    // QWERTY rows & diagonals
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "1qaz2wsx3edc4rfv",
    "qazwsxedcrfvtgb",
    "1q2w3e4r5t6y",
    // Sequential digits and alphabet
    "01234567890",
    "abcdefghijklmnopqrstuvwxyz",
];

fn detect_keyboard_pattern(password_lower: &str) -> Option<String> {
    let chars: Vec<char> = password_lower.chars().collect();
    if chars.len() < 4 {
        return None;
    }
    for &seq in KEYBOARD_SEQUENCES {
        let rev: String = seq.chars().rev().collect();
        for start in 0..=chars.len().saturating_sub(4) {
            let sub: String = chars[start..start + 4].iter().collect();
            if seq.contains(&sub) || rev.contains(&sub) {
                return Some(sub);
            }
        }
    }
    None
}

fn detect_date_pattern(password: &str) -> Option<String> {
    // Check explicit separators like YYYY-MM-DD or DD/MM/YYYY
    let bytes = password.as_bytes();
    for i in 0..bytes.len() {
        // 4-digit year in 1900..=2099
        if i + 4 <= bytes.len() && bytes[i..i + 4].iter().all(|b| b.is_ascii_digit()) {
            let s = &password[i..i + 4];
            if let Ok(year) = s.parse::<u32>() {
                if (1900..=2099).contains(&year) {
                    // Check if preceded/followed by separators or part of YYYYMMDD / DDMMYYYY
                    let before_is_digit = i > 0 && bytes[i - 1].is_ascii_digit();
                    let after_is_digit = i + 4 < bytes.len() && bytes[i + 4].is_ascii_digit();
                    if !before_is_digit && !after_is_digit {
                        return Some(s.to_string());
                    }
                    // YYYYMMDD (8 digits)
                    if !before_is_digit
                        && i + 8 <= bytes.len()
                        && bytes[i + 4..i + 8].iter().all(|b| b.is_ascii_digit())
                    {
                        let mm: u32 = password[i + 4..i + 6].parse().unwrap_or(0);
                        let dd: u32 = password[i + 6..i + 8].parse().unwrap_or(0);
                        if (1..=12).contains(&mm) && (1..=31).contains(&dd) {
                            return Some(password[i..i + 8].to_string());
                        }
                    }
                    // DDMMYYYY (8 digits ending at i+4)
                    if !after_is_digit
                        && i >= 4
                        && bytes[i - 4..i].iter().all(|b| b.is_ascii_digit())
                    {
                        let dd: u32 = password[i - 4..i - 2].parse().unwrap_or(0);
                        let mm: u32 = password[i - 2..i].parse().unwrap_or(0);
                        if (1..=31).contains(&dd) && (1..=12).contains(&mm) {
                            return Some(password[i - 4..i + 4].to_string());
                        }
                    }
                }
            }
        }
    }
    None
}

fn decode_leetspeak(input: &str) -> String {
    input
        .chars()
        .map(|c| match c.to_ascii_lowercase() {
            '@' | '4' => 'a',
            '8' => 'b',
            '3' => 'e',
            '1' | '!' | '|' => 'i',
            '0' => 'o',
            '5' | '$' => 's',
            '7' => 't',
            '2' => 'z',
            '9' => 'g',
            other => other,
        })
        .collect()
}

fn detect_leetspeak_dictionary_word(password: &str) -> Option<String> {
    let deleeted = decode_leetspeak(password);
    // Extract contiguous alphabetic tokens (len >= 5) from de-leeted string
    let mut best_match: Option<String> = None;
    for token in deleeted.split(|c: char| !c.is_ascii_alphabetic()) {
        if token.len() < 5 {
            continue;
        }
        for &word in COMMON_BREACHED_PASSWORDS {
            if word.len() >= 5
                && word.bytes().all(|b| b.is_ascii_alphabetic())
                && token.contains(word)
            {
                best_match = Some(word.to_string());
                break;
            }
        }
        if best_match.is_some() {
            break;
        }
    }
    best_match
}

fn detect_repeated_pattern(password: &str) -> bool {
    let chars: Vec<char> = password.chars().collect();
    if chars.len() < 4 {
        return false;
    }
    // 4+ identical consecutive characters (e.g. "aaaa")
    let mut run = 1usize;
    for w in chars.windows(2) {
        if w[0] == w[1] {
            run += 1;
            if run >= 4 {
                return true;
            }
        } else {
            run = 1;
        }
    }
    // Exact half repetition (e.g. "abc123abc123")
    if chars.len() >= 6 && chars.len() % 2 == 0 {
        let half = chars.len() / 2;
        if chars[..half] == chars[half..] {
            return true;
        }
    }
    false
}

/// Analyzes `password` for structural weaknesses: short length, low entropy, Bloom breach hits,
/// AZERTY/QWERTY keyboard walks, date patterns, leetspeak dictionary words, and repeats.
pub fn analyze_password_weaknesses(
    password: &str,
    bloom: &OfflineBreachBloomFilter,
) -> Vec<WeakPasswordReason> {
    let mut reasons = Vec::new();
    let len = password.chars().count();
    if len < 12 {
        reasons.push(WeakPasswordReason::TooShort { length: len });
    }
    let entropy = estimate_password_entropy_bits(password);
    if entropy < 50.0 {
        reasons.push(WeakPasswordReason::LowEntropy {
            entropy_bits: entropy.max(0.0).round() as u32,
        });
    }
    if bloom.is_likely_breached(password) {
        reasons.push(WeakPasswordReason::CommonBreached);
    }
    let lower = password.to_ascii_lowercase();
    if let Some(pat) = detect_keyboard_pattern(&lower) {
        reasons.push(WeakPasswordReason::KeyboardPattern { pattern: pat });
    }
    if let Some(date) = detect_date_pattern(password) {
        reasons.push(WeakPasswordReason::DatePattern { pattern: date });
    }
    if let Some(word) = detect_leetspeak_dictionary_word(password) {
        reasons.push(WeakPasswordReason::LeetspeakDictionaryWord { word });
    }
    if detect_repeated_pattern(password) {
        reasons.push(WeakPasswordReason::RepeatedPattern);
    }
    reasons
}

// ============================================================================
// FULL VAULT HEALTH REPORT
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthSeverity {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthIssueCategory {
    Breached,
    WeakPassword,
    ReusedPassword,
    OldPassword,
    InsecureHttp,
    Missing2fa,
    MissingPasskey,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultHealthIssue {
    pub item_id: String,
    pub item_name: String,
    pub severity: HealthSeverity,
    pub category: HealthIssueCategory,
    pub detail: String,
}

/// Complete offline vault security health audit report with 0-100 global score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultHealthReport {
    pub global_score: u8,
    pub total_logins_audited: usize,
    pub breached_count: usize,
    pub weak_count: usize,
    pub reused_groups: Vec<Vec<String>>,
    pub old_password_count: usize,
    pub insecure_http_count: usize,
    pub missing_2fa_count: usize,
    pub missing_passkey_count: usize,
    pub issues: Vec<VaultHealthIssue>,
}

/// Runs a comprehensive offline zero-knowledge security health audit over unlocked vault items
/// and passkeys using an ephemeral per-audit HMAC-SHA256 key for password reuse detection.
pub fn generate_vault_health_report(
    items: &[VaultItem],
    passkeys: &[StoredPasskeyCredential],
    bloom: &OfflineBreachBloomFilter,
    now_unix: u64,
) -> VaultHealthReport {
    let mut ephemeral_hmac_key = [0u8; 32];
    OsRng.fill_bytes(&mut ephemeral_hmac_key);

    let mut total_logins = 0usize;
    let mut breached_count = 0usize;
    let mut weak_count = 0usize;
    let mut old_password_count = 0usize;
    let mut insecure_http_count = 0usize;
    let mut missing_2fa_count = 0usize;
    let mut missing_passkey_count = 0usize;
    let mut issues: Vec<VaultHealthIssue> = Vec::new();

    // Map ephemeral HMAC-SHA256(password) -> Vec<(item_id, item_name, domain)>
    let mut reuse_buckets: HashMap<[u8; 32], Vec<(String, String, Option<String>)>> = HashMap::new();

    let active_passkey_rps: Vec<String> = passkeys
        .iter()
        .filter(|pk| !pk.is_trashed())
        .map(|pk| pk.rp_id.to_ascii_lowercase())
        .collect();

    for item in items {
        if item.is_trashed() {
            continue;
        }
        let VaultItemKind::Login(ref login) = item.kind else {
            continue;
        };
        total_logins += 1;

        // 1. Breach + weak password pattern analysis
        let weaknesses = analyze_password_weaknesses(&login.password, bloom);
        let is_breached = weaknesses
            .iter()
            .any(|w| matches!(w, WeakPasswordReason::CommonBreached));
        if is_breached {
            breached_count += 1;
            issues.push(VaultHealthIssue {
                item_id: item.id.clone(),
                item_name: item.name.clone(),
                severity: HealthSeverity::Critical,
                category: HealthIssueCategory::Breached,
                detail: "Password matches offline breached credential database".into(),
            });
        }
        let non_breach_weak = weaknesses
            .iter()
            .any(|w| !matches!(w, WeakPasswordReason::CommonBreached));
        if non_breach_weak {
            weak_count += 1;
            issues.push(VaultHealthIssue {
                item_id: item.id.clone(),
                item_name: item.name.clone(),
                severity: HealthSeverity::High,
                category: HealthIssueCategory::WeakPassword,
                detail: format!("Weak password indicators: {:?}", weaknesses),
            });
        }

        // 2. Ephemeral HMAC-SHA256 reuse fingerprinting (never stores raw password as key)
        if !login.password.is_empty() {
            let mut mac = HmacSha256::new_from_slice(&ephemeral_hmac_key)
                .expect("HMAC-SHA256 accepts 32-byte key");
            mac.update(login.password.as_bytes());
            let mut tag = [0u8; 32];
            tag.copy_from_slice(&mac.finalize().into_bytes());
            let primary_domain = login
                .primary_uri()
                .and_then(extract_etld_plus_one);
            reuse_buckets.entry(tag).or_default().push((
                item.id.clone(),
                item.name.clone(),
                primary_domain,
            ));
        }

        // 3. Old password (> 180 days)
        let pwd_ts = item.password_updated_at_unix.unwrap_or(item.updated_at_unix);
        if now_unix > 0
            && pwd_ts > 0
            && now_unix.saturating_sub(pwd_ts) > PASSWORD_MAX_AGE_SECONDS
        {
            old_password_count += 1;
            let days = now_unix.saturating_sub(pwd_ts) / 86_400;
            issues.push(VaultHealthIssue {
                item_id: item.id.clone(),
                item_name: item.name.clone(),
                severity: HealthSeverity::Low,
                category: HealthIssueCategory::OldPassword,
                detail: format!("Password has not been rotated for {} days (>180d)", days),
            });
        }

        // 4. Insecure HTTP URLs
        let has_insecure_http = login.uris.iter().any(|u| {
            parse_uri_components(&u.uri)
                .map(|p| p.scheme.as_deref() == Some("http") && !p.is_secure)
                .unwrap_or(false)
        });
        if has_insecure_http {
            insecure_http_count += 1;
            issues.push(VaultHealthIssue {
                item_id: item.id.clone(),
                item_name: item.name.clone(),
                severity: HealthSeverity::Medium,
                category: HealthIssueCategory::InsecureHttp,
                detail: "Login URI uses unencrypted http:// transport".into(),
            });
        }

        // 5. Offline 2fa.directory & passkeys.directory checks
        let primary_domain = login.primary_uri().and_then(extract_etld_plus_one);
        if let Some(ref domain) = primary_domain {
            if let Some(support) = lookup_site_security_support(domain) {
                let has_totp = login
                    .totp_secret_base32
                    .as_deref()
                    .map(|s| !s.trim().is_empty())
                    .unwrap_or(false);
                if support.supports_totp && !has_totp {
                    missing_2fa_count += 1;
                    issues.push(VaultHealthIssue {
                        item_id: item.id.clone(),
                        item_name: item.name.clone(),
                        severity: HealthSeverity::Medium,
                        category: HealthIssueCategory::Missing2fa,
                        detail: format!(
                            "{} supports TOTP 2FA (docs: {})",
                            support.domain, support.documentation_url
                        ),
                    });
                }

                let has_passkey = !login.passkey_ids.is_empty()
                    || active_passkey_rps
                        .iter()
                        .any(|rp| rp == domain || rp.ends_with(&format!(".{}", domain)));
                if support.supports_passkey && !has_passkey {
                    missing_passkey_count += 1;
                    issues.push(VaultHealthIssue {
                        item_id: item.id.clone(),
                        item_name: item.name.clone(),
                        severity: HealthSeverity::Low,
                        category: HealthIssueCategory::MissingPasskey,
                        detail: format!(
                            "{} supports Passkeys (WebAuthn FIDO2)",
                            support.domain
                        ),
                    });
                }
            }
        }
    }

    ephemeral_hmac_key.zeroize();

    // Collect reused password groups
    let mut reused_groups: Vec<Vec<String>> = Vec::new();
    let mut reused_item_count = 0usize;
    for group in reuse_buckets.values() {
        if group.len() > 1 {
            reused_item_count += group.len();
            let ids: Vec<String> = group.iter().map(|(id, _, _)| id.clone()).collect();
            for (id, name, _) in group {
                issues.push(VaultHealthIssue {
                    item_id: id.clone(),
                    item_name: name.clone(),
                    severity: HealthSeverity::High,
                    category: HealthIssueCategory::ReusedPassword,
                    detail: format!(
                        "Password is reused across {} accounts in the vault",
                        group.len()
                    ),
                });
            }
            reused_groups.push(ids);
        }
    }
    reused_groups.sort();

    // Compute normalized 0..=100 health score
    let global_score: u8 = if total_logins == 0 {
        100
    } else {
        let denom = total_logins as f64;
        let penalty = (breached_count as f64 / denom) * 45.0
            + (weak_count as f64 / denom) * 25.0
            + (reused_item_count as f64 / denom) * 25.0
            + (insecure_http_count as f64 / denom) * 10.0
            + (old_password_count as f64 / denom) * 8.0
            + (missing_2fa_count as f64 / denom) * 10.0
            + (missing_passkey_count as f64 / denom) * 4.0;
        (100.0 - penalty).clamp(0.0, 100.0).round() as u8
    };

    VaultHealthReport {
        global_score,
        total_logins_audited: total_logins,
        breached_count,
        weak_count,
        reused_groups,
        old_password_count,
        insecure_http_count,
        missing_2fa_count,
        missing_passkey_count,
        issues,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::LoginPayload;
    use crate::matcher::VaultUriEntry;

    #[test]
    fn test_hibp_range_response_parser() {
        let (prefix, suffix) = OfflineBreachBloomFilter::k_anonymity_sha1_prefix("password123");
        let full_sha1 = format!("{}{}", prefix, suffix);
        let mock_body = format!(
            "00000000000000000000000000000000001:4\r\n{}:123456\r\nFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:1\r\n",
            suffix
        );
        assert_eq!(parse_hibp_range_response(&full_sha1, &mock_body), 123_456);
        assert_eq!(parse_hibp_range_response(&suffix, &mock_body), 123_456);
        assert_eq!(
            parse_hibp_range_response("00000AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", &mock_body),
            0
        );
    }

    #[test]
    fn test_weak_password_patterns_azerty_qwerty_dates_leetspeak() {
        let bloom = OfflineBreachBloomFilter::default();

        let r_azerty = analyze_password_weaknesses("MyAzerty!#99", &bloom);
        assert!(r_azerty
            .iter()
            .any(|r| matches!(r, WeakPasswordReason::KeyboardPattern { .. })));

        let r_qwerty = analyze_password_weaknesses("XxQwerty!99Zz", &bloom);
        assert!(r_qwerty
            .iter()
            .any(|r| matches!(r, WeakPasswordReason::KeyboardPattern { .. })));

        let r_date = analyze_password_weaknesses("VeloParis1998!#", &bloom);
        assert!(r_date
            .iter()
            .any(|r| matches!(r, WeakPasswordReason::DatePattern { pattern } if pattern == "1998")));

        let r_leet = analyze_password_weaknesses("M3g@P@ssw0rd!#", &bloom);
        assert!(r_leet
            .iter()
            .any(|r| matches!(r, WeakPasswordReason::LeetspeakDictionaryWord { word } if word == "password")));

        let r_strong = analyze_password_weaknesses("k9#Vx!mP4$qL8&nR2*wZ7^cB", &bloom);
        assert!(r_strong.is_empty(), "Strong random password should have no weaknesses: {:?}", r_strong);
    }

    #[test]
    fn test_vault_health_report_and_offline_directory() {
        let bloom = OfflineBreachBloomFilter::default();
        let gh_support = lookup_site_security_support("https://gist.github.com/alice").unwrap();
        assert!(gh_support.supports_totp);
        assert!(gh_support.supports_passkey);

        let now = 2_000_000_000u64;
        let old_ts = now - (200 * 86_400);

        let mut l1 = LoginPayload::default();
        l1.username = "alice".into();
        l1.password = "SharedStrong#Password!X9".into();
        l1.uris = vec![VaultUriEntry::base_domain("https://github.com")];
        let item1 = VaultItem::new("id-1", "GitHub", VaultItemKind::Login(l1), old_ts);

        let mut l2 = LoginPayload::default();
        l2.username = "alice".into();
        l2.password = "SharedStrong#Password!X9".into(); // reused!
        l2.uris = vec![VaultUriEntry::base_domain("http://legacy.corp.example")];
        let item2 = VaultItem::new("id-2", "Insecure Corp", VaultItemKind::Login(l2), now);

        let mut l3 = LoginPayload::default();
        l3.username = "alice".into();
        l3.password = "password123".into(); // breached + weak!
        l3.uris = vec![VaultUriEntry::base_domain("https://example.org")];
        let item3 = VaultItem::new("id-3", "Breached Site", VaultItemKind::Login(l3), now);

        let report = generate_vault_health_report(&[item1, item2, item3], &[], &bloom, now);
        assert_eq!(report.total_logins_audited, 3);
        assert_eq!(report.breached_count, 1);
        assert_eq!(report.reused_groups.len(), 1);
        assert_eq!(report.reused_groups[0].len(), 2);
        assert_eq!(report.old_password_count, 1);
        assert_eq!(report.insecure_http_count, 1);
        assert_eq!(report.missing_2fa_count, 1);
        assert_eq!(report.missing_passkey_count, 1);
        assert!(report.global_score < 70);
    }
}
