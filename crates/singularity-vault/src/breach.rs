//! Offline Zero-Knowledge k-Anonymity Bloom Filter Breached Password Checker
//! and Shannon Entropy Analyzer.

use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

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
