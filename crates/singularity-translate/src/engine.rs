//! Offline DOM batch translation engine, user translation preferences, and
//! Ed25519 + SHA-256 verified local language packs stored in `<root>/models/translate/`.

use crate::detect::{detect_language, DetectionResult};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use thiserror::Error;

const PACK_SIGNING_DOMAIN: &[u8] = b"SINGULARITY-TRANSLATE-PACK-V1";
const MAX_PACK_MANIFEST_BYTES: u64 = 1024 * 1024; // 1 MiB
const MAX_PACK_PAYLOAD_BYTES: u64 = 16 * 1024 * 1024; // 16 MiB

fn read_regular_file_bounded(path: &Path, max_bytes: u64) -> Result<Vec<u8>, TranslateError> {
    let meta = fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() || !meta.file_type().is_file() {
        return Err(TranslateError::InvalidPackJson(
            "Refused symlink or non-regular translation pack file".to_string(),
        ));
    }
    if meta.len() > max_bytes {
        return Err(TranslateError::PackSizeMismatch {
            expected: max_bytes,
            actual: meta.len(),
        });
    }
    let file = fs::File::open(path)?;
    let mut buf = Vec::new();
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut buf)?;
    if (buf.len() as u64) > max_bytes {
        return Err(TranslateError::PackSizeMismatch {
            expected: max_bytes,
            actual: buf.len() as u64,
        });
    }
    Ok(buf)
}

#[derive(Debug, Error)]
pub enum TranslateError {
    #[error("Invalid language code '{0}' (expected 2-8 ASCII letters/hyphens)")]
    InvalidLanguageCode(String),
    #[error("Unsupported offline language pair '{src}' -> '{dst}' (no local pack installed)")]
    UnsupportedLanguagePair { src: String, dst: String },
    #[error("Pack size mismatch: manifest declares {expected} bytes, payload has {actual} bytes")]
    PackSizeMismatch { expected: u64, actual: u64 },
    #[error("Pack SHA-256 integrity check failed: expected {expected}, computed {actual}")]
    PackHashMismatch { expected: String, actual: String },
    #[error("Pack signer public key does not match trusted key")]
    UntrustedSigner,
    #[error("Pack Ed25519 signature verification failed: {0}")]
    InvalidSignature(String),
    #[error("Invalid translation pack JSON: {0}")]
    InvalidPackJson(String),
    #[error("Filesystem I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Action recommended by `TranslationPrefs::evaluate_page_policy` for a loaded web page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PageTranslationAction {
    Disabled,
    AlreadyTargetLanguage,
    NeverTranslateSite,
    NeverTranslateLanguage,
    AutoTranslate,
    PromptUser,
    ManualOnly,
}

/// Persistent local user preferences for offline page and selection translation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TranslationPrefs {
    pub enabled: bool,
    pub target_lang: String,
    pub auto_prompt_on_foreign_page: bool,
    pub always_translate_langs: BTreeSet<String>,
    pub never_translate_langs: BTreeSet<String>,
    pub never_translate_sites: BTreeSet<String>,
    pub selection_popup_enabled: bool,
}

impl Default for TranslationPrefs {
    fn default() -> Self {
        Self {
            enabled: true,
            target_lang: "en".to_string(),
            auto_prompt_on_foreign_page: true,
            always_translate_langs: BTreeSet::new(),
            never_translate_langs: BTreeSet::new(),
            never_translate_sites: BTreeSet::new(),
            selection_popup_enabled: true,
        }
    }
}

impl TranslationPrefs {
    pub fn add_always_translate_lang(&mut self, lang: &str) {
        let code = normalize_lang(lang);
        self.never_translate_langs.remove(&code);
        self.always_translate_langs.insert(code);
    }

    pub fn add_never_translate_lang(&mut self, lang: &str) {
        let code = normalize_lang(lang);
        self.always_translate_langs.remove(&code);
        self.never_translate_langs.insert(code);
    }

    pub fn add_never_translate_site(&mut self, host: &str) {
        let normalized = normalize_host(host);
        if !normalized.is_empty() {
            self.never_translate_sites.insert(normalized);
        }
    }

    pub fn remove_never_translate_site(&mut self, host: &str) -> bool {
        self.never_translate_sites.remove(&normalize_host(host))
    }

    /// Evaluates per-site and per-language rules to decide whether to auto-translate, prompt, or skip.
    pub fn evaluate_page_policy(
        &self,
        detected_lang: &str,
        site_host: &str,
    ) -> PageTranslationAction {
        if !self.enabled {
            return PageTranslationAction::Disabled;
        }
        let detected = normalize_lang(detected_lang);
        let target = normalize_lang(&self.target_lang);
        if detected.is_empty() || detected == "und" || detected == target {
            return PageTranslationAction::AlreadyTargetLanguage;
        }

        let host = normalize_host(site_host);
        if !host.is_empty()
            && self.never_translate_sites.iter().any(|blocked| {
                host == *blocked
                    || host
                        .strip_suffix(blocked.as_str())
                        .is_some_and(|prefix| prefix.ends_with('.'))
            })
        {
            return PageTranslationAction::NeverTranslateSite;
        }

        if self.never_translate_langs.contains(&detected) {
            return PageTranslationAction::NeverTranslateLanguage;
        }

        if self.always_translate_langs.contains(&detected) {
            return PageTranslationAction::AutoTranslate;
        }

        if self.auto_prompt_on_foreign_page {
            PageTranslationAction::PromptUser
        } else {
            PageTranslationAction::ManualOnly
        }
    }
}

/// Cryptographically signed metadata for an offline `<src>-<dst>` language pack stored in
/// `<root>/models/translate/`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfflineLanguagePack {
    pub id: String,
    pub source_lang: String,
    pub target_lang: String,
    pub version: String,
    pub size_bytes: u64,
    pub sha256_hex: String,
    pub ed25519_signature_hex: String,
    pub signer_pubkey_hex: String,
}

impl OfflineLanguagePack {
    /// Returns the canonical local storage directory `<root>/models/translate/`.
    pub fn models_translate_dir(root: &Path) -> PathBuf {
        root.join("models").join("translate")
    }

    /// Returns the payload path `<root>/models/translate/<src>-<dst>.json`.
    pub fn payload_path(&self, root: &Path) -> Result<PathBuf, TranslateError> {
        validate_lang_code(&self.source_lang)?;
        validate_lang_code(&self.target_lang)?;
        Ok(Self::models_translate_dir(root)
            .join(format!("{}-{}.json", self.source_lang, self.target_lang)))
    }

    /// Returns the manifest path `<root>/models/translate/<src>-<dst>.pack.json`.
    pub fn manifest_path(&self, root: &Path) -> Result<PathBuf, TranslateError> {
        validate_lang_code(&self.source_lang)?;
        validate_lang_code(&self.target_lang)?;
        Ok(Self::models_translate_dir(root)
            .join(format!("{}-{}.pack.json", self.source_lang, self.target_lang)))
    }

    /// Creates a signed `OfflineLanguagePack` manifest over `payload_bytes` using `signing_key`.
    pub fn create_signed(
        source_lang: &str,
        target_lang: &str,
        version: impl Into<String>,
        payload_bytes: &[u8],
        signing_key: &SigningKey,
    ) -> Result<Self, TranslateError> {
        let src = normalize_lang(source_lang);
        let dst = normalize_lang(target_lang);
        validate_lang_code(&src)?;
        validate_lang_code(&dst)?;

        let id = format!("{src}-{dst}");
        let version = version.into();
        let size_bytes = payload_bytes.len() as u64;
        let sha256_hex = hex::encode(Sha256::digest(payload_bytes));
        let signer_pubkey_hex = hex::encode(signing_key.verifying_key().as_bytes());

        let msg = canonical_pack_signing_bytes(&id, &version, size_bytes, &sha256_hex);
        let signature: Signature = signing_key.sign(&msg);

        Ok(Self {
            id,
            source_lang: src,
            target_lang: dst,
            version,
            size_bytes,
            sha256_hex,
            ed25519_signature_hex: hex::encode(signature.to_bytes()),
            signer_pubkey_hex,
        })
    }

    /// Verifies exact payload byte length, SHA-256 digest, trusted signer public key,
    /// and Ed25519 cryptographic signature via `ed25519-dalek`.
    pub fn verify_payload(
        &self,
        payload_bytes: &[u8],
        trusted_pubkey_hex: &str,
    ) -> Result<(), TranslateError> {
        validate_lang_code(&self.source_lang)?;
        validate_lang_code(&self.target_lang)?;

        let expected_id = format!("{}-{}", self.source_lang, self.target_lang);
        if self.id != expected_id {
            return Err(TranslateError::InvalidSignature(format!(
                "Pack id '{}' does not match '{expected_id}'",
                self.id
            )));
        }

        if payload_bytes.len() as u64 != self.size_bytes {
            return Err(TranslateError::PackSizeMismatch {
                expected: self.size_bytes,
                actual: payload_bytes.len() as u64,
            });
        }

        let computed_hash = hex::encode(Sha256::digest(payload_bytes));
        if computed_hash != self.sha256_hex.to_ascii_lowercase() {
            return Err(TranslateError::PackHashMismatch {
                expected: self.sha256_hex.clone(),
                actual: computed_hash,
            });
        }

        if !self
            .signer_pubkey_hex
            .eq_ignore_ascii_case(trusted_pubkey_hex)
        {
            return Err(TranslateError::UntrustedSigner);
        }

        let pubkey_vec = hex::decode(trusted_pubkey_hex)
            .map_err(|e| TranslateError::InvalidSignature(e.to_string()))?;
        let pubkey_arr: [u8; 32] = pubkey_vec
            .try_into()
            .map_err(|_| TranslateError::InvalidSignature("public key must be 32 bytes".into()))?;
        let verifying_key = VerifyingKey::from_bytes(&pubkey_arr)
            .map_err(|e| TranslateError::InvalidSignature(e.to_string()))?;

        let sig_vec = hex::decode(&self.ed25519_signature_hex)
            .map_err(|e| TranslateError::InvalidSignature(e.to_string()))?;
        let sig_arr: [u8; 64] = sig_vec
            .try_into()
            .map_err(|_| TranslateError::InvalidSignature("signature must be 64 bytes".into()))?;
        let signature = Signature::from_bytes(&sig_arr);

        let msg = canonical_pack_signing_bytes(
            &self.id,
            &self.version,
            self.size_bytes,
            &computed_hash,
        );
        verifying_key
            .verify(&msg, &signature)
            .map_err(|e| TranslateError::InvalidSignature(e.to_string()))?;

        Ok(())
    }

    /// Verifies `payload_bytes` cryptographically and installs both the payload and manifest
    /// under `<root>/models/translate/`.
    pub fn install_verified(
        &self,
        root: &Path,
        payload_bytes: &[u8],
        trusted_pubkey_hex: &str,
    ) -> Result<PathBuf, TranslateError> {
        self.verify_payload(payload_bytes, trusted_pubkey_hex)?;
        let dir = Self::models_translate_dir(root);
        fs::create_dir_all(&dir)?;

        let payload_path = self.payload_path(root)?;
        let manifest_path = self.manifest_path(root)?;

        fs::write(&payload_path, payload_bytes)?;
        let manifest_json = serde_json::to_vec_pretty(self)
            .map_err(|e| TranslateError::InvalidPackJson(e.to_string()))?;
        fs::write(&manifest_path, manifest_json)?;

        Ok(payload_path)
    }
}

fn canonical_pack_signing_bytes(
    id: &str,
    version: &str,
    size_bytes: u64,
    sha256_hex: &str,
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(128 + id.len() + version.len() + sha256_hex.len());
    msg.extend_from_slice(PACK_SIGNING_DOMAIN);
    msg.push(0x00);
    msg.extend_from_slice(id.as_bytes());
    msg.push(0x00);
    msg.extend_from_slice(version.as_bytes());
    msg.push(0x00);
    msg.extend_from_slice(&size_bytes.to_be_bytes());
    msg.push(0x00);
    msg.extend_from_slice(sha256_hex.as_bytes());
    msg
}

/// JSON schema for local offline translation packs loaded from `<root>/models/translate/`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalTranslationTable {
    pub source_lang: String,
    pub target_lang: String,
    #[serde(default)]
    pub phrases: BTreeMap<String, String>,
    #[serde(default)]
    pub words: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default)]
struct LexiconPair {
    phrases: BTreeMap<String, String>,
    words: BTreeMap<String, String>,
    max_phrase_words: usize,
}

impl LexiconPair {
    fn from_slices(phrases: &[(&str, &str)], words: &[(&str, &str)]) -> Self {
        let mut pair = Self::default();
        for &(src, dst) in phrases {
            pair.insert_phrase(src, dst);
        }
        for &(src, dst) in words {
            pair.insert_word(src, dst);
        }
        pair
    }

    fn insert_phrase(&mut self, src: &str, dst: &str) {
        let key = normalize_phrase_key(src);
        let wc = key.split_whitespace().count();
        if wc > self.max_phrase_words {
            self.max_phrase_words = wc;
        }
        self.phrases.insert(key, dst.to_string());
    }

    fn insert_word(&mut self, src: &str, dst: &str) {
        self.words.insert(src.to_lowercase(), dst.to_string());
    }

    fn merge_table(&mut self, table: &LocalTranslationTable) {
        for (k, v) in &table.phrases {
            self.insert_phrase(k, v);
        }
        for (k, v) in &table.words {
            self.insert_word(k, v);
        }
    }
}

/// 100% offline DOM batch translation engine with built-in FR↔EN, ES↔EN, DE↔EN dictionaries
/// and cryptographically verified local JSON pack loading.
pub struct OfflineTranslationEngine {
    prefs: TranslationPrefs,
    lexicons: BTreeMap<(String, String), LexiconPair>,
    installed_packs: BTreeMap<String, OfflineLanguagePack>,
}

impl Default for OfflineTranslationEngine {
    fn default() -> Self {
        Self::new(TranslationPrefs::default())
    }
}

impl OfflineTranslationEngine {
    /// Creates an offline translation engine preloaded with built-in FR↔EN, ES↔EN, and DE↔EN packs.
    pub fn new(prefs: TranslationPrefs) -> Self {
        let mut lexicons = BTreeMap::new();
        lexicons.insert(("fr".into(), "en".into()), builtin_fr_en());
        lexicons.insert(("en".into(), "fr".into()), builtin_en_fr());
        lexicons.insert(("es".into(), "en".into()), builtin_es_en());
        lexicons.insert(("en".into(), "es".into()), builtin_en_es());
        lexicons.insert(("de".into(), "en".into()), builtin_de_en());
        lexicons.insert(("en".into(), "de".into()), builtin_en_de());

        Self {
            prefs,
            lexicons,
            installed_packs: BTreeMap::new(),
        }
    }

    pub fn prefs(&self) -> &TranslationPrefs {
        &self.prefs
    }

    pub fn prefs_mut(&mut self) -> &mut TranslationPrefs {
        &mut self.prefs
    }

    pub fn installed_packs(&self) -> Vec<&OfflineLanguagePack> {
        self.installed_packs.values().collect()
    }

    /// Lists all directly available `(source_lang, target_lang)` pairs.
    pub fn available_pairs(&self) -> Vec<(String, String)> {
        self.lexicons.keys().cloned().collect()
    }

    /// Merges a local `LocalTranslationTable` into the engine without touching any network.
    pub fn load_table(&mut self, table: LocalTranslationTable) -> Result<(), TranslateError> {
        let src = normalize_lang(&table.source_lang);
        let dst = normalize_lang(&table.target_lang);
        validate_lang_code(&src)?;
        validate_lang_code(&dst)?;
        self.lexicons
            .entry((src, dst))
            .or_default()
            .merge_table(&table);
        Ok(())
    }

    /// Parses and loads a local JSON translation table payload directly into memory.
    pub fn load_table_json(&mut self, json_bytes: &[u8]) -> Result<(), TranslateError> {
        let table: LocalTranslationTable = serde_json::from_slice(json_bytes)
            .map_err(|e| TranslateError::InvalidPackJson(e.to_string()))?;
        self.load_table(table)
    }

    /// Verifies an `OfflineLanguagePack` (SHA-256 + Ed25519), saves it under
    /// `<root>/models/translate/`, and immediately loads its lexicon into the engine.
    pub fn install_and_load_verified_pack(
        &mut self,
        root: &Path,
        pack: OfflineLanguagePack,
        payload_bytes: &[u8],
        trusted_pubkey_hex: &str,
    ) -> Result<PathBuf, TranslateError> {
        let saved_path = pack.install_verified(root, payload_bytes, trusted_pubkey_hex)?;
        self.load_table_json(payload_bytes)?;
        self.installed_packs.insert(pack.id.clone(), pack);
        Ok(saved_path)
    }

    /// Scans `<root>/models/translate/` and loads all `.pack.json` packs that pass
    /// strict Ed25519 + SHA-256 verification against `trusted_pubkey_hex`.
    /// Symlinks, oversized files, and individually corrupted/untrusted packs are skipped
    /// without aborting loading of remaining valid packs.
    pub fn load_verified_packs_from_disk(
        &mut self,
        root: &Path,
        trusted_pubkey_hex: &str,
    ) -> Result<usize, TranslateError> {
        let dir = OfflineLanguagePack::models_translate_dir(root);
        let dir_meta = match fs::symlink_metadata(&dir) {
            Ok(meta) => meta,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(TranslateError::Io(e)),
        };
        if dir_meta.file_type().is_symlink() || !dir_meta.file_type().is_dir() {
            return Ok(0);
        }

        let mut loaded = 0usize;
        for entry_res in fs::read_dir(&dir)? {
            let Ok(entry) = entry_res else {
                continue;
            };
            let path = entry.path();
            let is_manifest = path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.ends_with(".pack.json"));
            if !is_manifest {
                continue;
            }
            let Ok(manifest_bytes) = read_regular_file_bounded(&path, MAX_PACK_MANIFEST_BYTES)
            else {
                continue;
            };
            let Ok(pack) = serde_json::from_slice::<OfflineLanguagePack>(&manifest_bytes) else {
                continue;
            };
            let Ok(payload_path) = pack.payload_path(root) else {
                continue;
            };
            let Ok(payload_bytes) =
                read_regular_file_bounded(&payload_path, MAX_PACK_PAYLOAD_BYTES)
            else {
                continue;
            };
            if pack.verify_payload(&payload_bytes, trusted_pubkey_hex).is_err() {
                continue;
            }
            if self.load_table_json(&payload_bytes).is_err() {
                continue;
            }
            self.installed_packs.insert(pack.id.clone(), pack);
            loaded += 1;
        }
        Ok(loaded)
    }

    /// Convenience helper to detect the source language of a sample text offline.
    pub fn detect_language(&self, text: &str) -> DetectionResult {
        detect_language(text)
    }

    /// Translates a batch of DOM text / inline-HTML nodes completely offline,
    /// preserving inline tags, numbers, URLs, punctuation, whitespace, and capitalization.
    pub fn translate_batch(
        &self,
        src: &str,
        dst: &str,
        nodes: &[String],
    ) -> Result<Vec<String>, TranslateError> {
        let src_norm = normalize_lang(src);
        let dst_norm = normalize_lang(dst);
        validate_lang_code(&src_norm)?;
        validate_lang_code(&dst_norm)?;

        if src_norm == dst_norm {
            return Ok(nodes.to_vec());
        }

        if let Some(direct) = self.lexicons.get(&(src_norm.clone(), dst_norm.clone())) {
            return Ok(nodes
                .iter()
                .map(|node| translate_node_preserving_markup(node, direct, &src_norm, &dst_norm))
                .collect());
        }

        // Offline pivot via English if both legs exist (e.g. fr -> en -> de)
        if src_norm != "en" && dst_norm != "en" {
            if let (Some(leg1), Some(leg2)) = (
                self.lexicons.get(&(src_norm.clone(), "en".to_string())),
                self.lexicons.get(&("en".to_string(), dst_norm.clone())),
            ) {
                return Ok(nodes
                    .iter()
                    .map(|node| {
                        let mid = translate_node_preserving_markup(node, leg1, &src_norm, "en");
                        translate_node_preserving_markup(&mid, leg2, "en", &dst_norm)
                    })
                    .collect());
            }
        }

        Err(TranslateError::UnsupportedLanguagePair {
            src: src_norm,
            dst: dst_norm,
        })
    }

    /// Translates a single text/HTML node offline.
    pub fn translate_text(
        &self,
        src: &str,
        dst: &str,
        text: &str,
    ) -> Result<String, TranslateError> {
        let mut out = self.translate_batch(src, dst, &[text.to_string()])?;
        Ok(out.pop().unwrap_or_default())
    }
}

#[derive(Debug)]
enum MarkupSegment<'a> {
    Tag(&'a str),
    Text(&'a str),
}

fn split_inline_markup(input: &str) -> Vec<MarkupSegment<'_>> {
    let mut segments = Vec::new();
    let bytes = input.as_bytes();
    let mut i = 0usize;
    let mut text_start = 0usize;

    while i < bytes.len() {
        if bytes[i] == b'<' {
            // Pre-check that the character after optional '/' is ASCII alphabetic before scanning
            // for '>' so inputs like `"<<<<<...>"` stay strictly O(N).
            let maybe_tag_start = input[i + 1..]
                .trim_start_matches('/')
                .bytes()
                .next()
                .is_some_and(|b| b.is_ascii_alphabetic());
            if maybe_tag_start {
                // Check if this looks like an inline HTML/XML tag: `<tag...>` or `</tag>`
                if let Some(rel_end) = input[i + 1..].find('>') {
                    let candidate = &input[i..=i + 1 + rel_end];
                    if is_inline_html_tag(candidate) {
                        if i > text_start {
                            segments.push(MarkupSegment::Text(&input[text_start..i]));
                        }
                        segments.push(MarkupSegment::Tag(candidate));
                        i = i + 1 + rel_end + 1;
                        text_start = i;
                        continue;
                    }
                } else {
                    // No closing '>' remains anywhere in the input: consume the rest in O(N).
                    break;
                }
            }
        }
        i += 1;
    }

    if text_start < input.len() {
        segments.push(MarkupSegment::Text(&input[text_start..]));
    }
    segments
}

fn is_inline_html_tag(candidate: &str) -> bool {
    let inner = candidate
        .strip_prefix('<')
        .and_then(|s| s.strip_suffix('>'))
        .unwrap_or("");
    let trimmed = inner.trim_start_matches('/');
    trimmed
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic())
}

#[derive(Debug, Clone)]
enum TextToken {
    Word(String),
    Literal(String),
}

fn tokenize_text_preserving_punctuation(text: &str) -> Vec<TextToken> {
    let mut tokens = Vec::new();
    let mut chars = text.char_indices().peekable();

    while let Some(&(start, ch)) = chars.peek() {
        // Keep URLs / placeholders / numbers completely verbatim as Literal tokens
        let rest = &text[start..];
        if rest.starts_with("https://")
            || rest.starts_with("http://")
            || rest.starts_with("mailto:")
        {
            let mut end = start;
            while let Some(&(idx, c)) = chars.peek() {
                if c.is_whitespace() || matches!(c, ')' | ']' | '"' | '\'') {
                    break;
                }
                end = idx + c.len_utf8();
                chars.next();
            }
            tokens.push(TextToken::Literal(text[start..end].to_string()));
            continue;
        }

        // Preserve `{0}` / `{{var}}` placeholders verbatim
        if ch == '{' {
            let mut end = start;
            let mut closed = false;
            while let Some(&(idx, c)) = chars.peek() {
                end = idx + c.len_utf8();
                chars.next();
                if c == '}' {
                    closed = true;
                    if chars.peek().is_some_and(|&(_, next_c)| next_c == '}') {
                        let (idx2, c2) = chars.next().unwrap();
                        end = idx2 + c2.len_utf8();
                    }
                    break;
                }
                if c.is_whitespace() {
                    break;
                }
            }
            if closed {
                tokens.push(TextToken::Literal(text[start..end].to_string()));
                continue;
            }
            tokens.push(TextToken::Literal(text[start..end].to_string()));
            continue;
        }

        // Preserve printf-style `%s`, `%d`, `%.2f`
        if ch == '%' {
            let mut end = start + ch.len_utf8();
            chars.next();
            while let Some(&(idx, c)) = chars.peek() {
                if c.is_ascii_alphanumeric() || c == '.' {
                    end = idx + c.len_utf8();
                    chars.next();
                } else {
                    break;
                }
            }
            tokens.push(TextToken::Literal(text[start..end].to_string()));
            continue;
        }

        if ch.is_alphabetic() {
            let mut end = start;
            while let Some(&(idx, c)) = chars.peek() {
                if c.is_alphabetic() || c == '\'' || c == '’' {
                    end = idx + c.len_utf8();
                    chars.next();
                } else {
                    break;
                }
            }
            let slice = &text[start..end];
            // Strip trailing apostrophe back to literal if word ended with one
            let trimmed = slice.trim_end_matches(['\'', '’']);
            if !trimmed.is_empty() {
                tokens.push(TextToken::Word(trimmed.to_string()));
                if trimmed.len() < slice.len() {
                    tokens.push(TextToken::Literal(slice[trimmed.len()..].to_string()));
                }
            } else {
                tokens.push(TextToken::Literal(slice.to_string()));
            }
        } else {
            let mut end = start;
            while let Some(&(idx, c)) = chars.peek() {
                if c.is_alphabetic() || c == '{' || c == '%' {
                    break;
                }
                end = idx + c.len_utf8();
                chars.next();
            }
            tokens.push(TextToken::Literal(text[start..end].to_string()));
        }
    }

    tokens
}

fn translate_node_preserving_markup(
    node: &str,
    lexicon: &LexiconPair,
    src_lang: &str,
    dst_lang: &str,
) -> String {
    let mut out = String::with_capacity(node.len() + 16);
    let mut at_sentence_start = true;
    for seg in split_inline_markup(node) {
        match seg {
            MarkupSegment::Tag(tag) => out.push_str(tag),
            MarkupSegment::Text(text) => {
                out.push_str(&translate_text_segment(
                    text,
                    lexicon,
                    src_lang,
                    dst_lang,
                    &mut at_sentence_start,
                ));
            }
        }
    }
    out
}

fn translate_text_segment(
    text: &str,
    lexicon: &LexiconPair,
    src_lang: &str,
    dst_lang: &str,
    at_sentence_start: &mut bool,
) -> String {
    let tokens = tokenize_text_preserving_punctuation(text);
    let mut out = String::with_capacity(text.len() + 16);
    let mut i = 0usize;

    while i < tokens.len() {
        match &tokens[i] {
            TextToken::Literal(lit) => {
                if lit
                    .chars()
                    .any(|c| matches!(c, '.' | '!' | '?' | '\n' | ':' | '—'))
                {
                    *at_sentence_start = true;
                }
                out.push_str(lit);
                i += 1;
            }
            TextToken::Word(first_word) => {
                // Attempt longest greedy multi-word phrase match (words separated by single ASCII space)
                let max_window = lexicon.max_phrase_words.clamp(1, 5);
                let mut matched_phrase: Option<(usize, String, Vec<&str>)> = None;

                if max_window > 1 {
                    for word_count in (2..=max_window).rev() {
                        if let Some((end_token_idx, orig_words)) =
                            collect_consecutive_space_words(&tokens, i, word_count)
                        {
                            let key = orig_words
                                .iter()
                                .map(|w| w.replace('’', "'").to_lowercase())
                                .collect::<Vec<_>>()
                                .join(" ");
                            if let Some(translated) = lexicon.phrases.get(&key) {
                                matched_phrase =
                                    Some((end_token_idx, translated.clone(), orig_words));
                                break;
                            }
                        }
                    }
                }

                if let Some((next_idx, translated, orig_words)) = matched_phrase {
                    let styled = apply_phrase_casing(&orig_words, &translated);
                    out.push_str(&styled);
                    *at_sentence_start = false;
                    i = next_idx;
                    continue;
                }

                // Single-word translation (including French elisions like `l'utilisateur`, `d'accord`)
                let translated_word = translate_single_word(
                    first_word,
                    lexicon,
                    src_lang,
                    dst_lang,
                    *at_sentence_start,
                );
                out.push_str(&translated_word);
                *at_sentence_start = false;
                i += 1;
            }
        }
    }

    out
}

fn collect_consecutive_space_words(
    tokens: &[TextToken],
    start: usize,
    word_count: usize,
) -> Option<(usize, Vec<&str>)> {
    let mut words = Vec::with_capacity(word_count);
    let mut idx = start;
    for k in 0..word_count {
        match tokens.get(idx) {
            Some(TextToken::Word(w)) => words.push(w.as_str()),
            _ => return None,
        }
        idx += 1;
        if k + 1 < word_count {
            match tokens.get(idx) {
                Some(TextToken::Literal(lit)) if lit == " " => idx += 1,
                _ => return None,
            }
        }
    }
    Some((idx, words))
}

fn translate_single_word(
    word: &str,
    lexicon: &LexiconPair,
    src_lang: &str,
    dst_lang: &str,
    at_sentence_start: bool,
) -> String {
    let suppress_mid_sentence_title = src_lang == "de" && dst_lang != "de" && !at_sentence_start;
    let normalized = word.replace('’', "'").to_lowercase();
    if let Some(direct) = lexicon
        .words
        .get(&normalized)
        .or_else(|| lexicon.phrases.get(&normalized))
    {
        return apply_word_casing(word, direct, suppress_mid_sentence_title);
    }

    // Handle French elisions (l', d', qu', n', c', j', s') cleanly
    if src_lang == "fr" {
        if let Some((prefix, stem)) = normalized.split_once('\'') {
            let translated_prefix = match prefix {
                "l" => Some("the"),
                "d" => Some("of"),
                "qu" => Some("that"),
                "n" => Some("not"),
                "c" => Some("it"),
                "j" => Some("I"),
                "s" => Some("if"),
                _ => None,
            };
            if let Some(p_tr) = translated_prefix {
                let stem_tr = lexicon
                    .words
                    .get(stem)
                    .map(|s| s.as_str())
                    .unwrap_or(stem);
                let combined = format!("{p_tr} {stem_tr}");
                return apply_word_casing(word, &combined, false);
            }
        }
    }

    // Unknown proper noun / technical term preserved verbatim
    word.to_string()
}

fn apply_word_casing(
    original: &str,
    translated: &str,
    suppress_mid_sentence_title: bool,
) -> String {
    let alpha_chars: Vec<char> = original.chars().filter(|c| c.is_alphabetic()).collect();
    if alpha_chars.is_empty() {
        return translated.to_string();
    }
    if alpha_chars.len() > 1 && alpha_chars.iter().all(|c| c.is_uppercase()) {
        return translated.to_uppercase();
    }
    if alpha_chars[0].is_uppercase() && !suppress_mid_sentence_title {
        return capitalize_first(translated);
    }
    translated.to_string()
}

fn apply_phrase_casing(orig_words: &[&str], translated: &str) -> String {
    let all_upper = orig_words.iter().all(|w| {
        let alphas: Vec<char> = w.chars().filter(|c| c.is_alphabetic()).collect();
        !alphas.is_empty() && alphas.iter().all(|c| c.is_uppercase())
    });
    if all_upper {
        return translated.to_uppercase();
    }
    if let Some(first) = orig_words.first() {
        if first
            .chars()
            .find(|c| c.is_alphabetic())
            .is_some_and(|c| c.is_uppercase())
        {
            return capitalize_first(translated);
        }
    }
    translated.to_string()
}

fn capitalize_first(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        None => String::new(),
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
    }
}

fn normalize_lang(lang: &str) -> String {
    lang.trim().to_ascii_lowercase()
}

fn normalize_host(host: &str) -> String {
    host.trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("")
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

fn normalize_phrase_key(phrase: &str) -> String {
    phrase
        .replace('’', "'")
        .split_whitespace()
        .map(|w| w.to_lowercase())
        .collect::<Vec<_>>()
        .join(" ")
}

fn validate_lang_code(code: &str) -> Result<(), TranslateError> {
    if code.len() < 2
        || code.len() > 8
        || !code
            .chars()
            .all(|c| c.is_ascii_lowercase() || c == '-')
        || code.starts_with('-')
        || code.ends_with('-')
    {
        return Err(TranslateError::InvalidLanguageCode(code.to_string()));
    }
    Ok(())
}

fn builtin_fr_en() -> LexiconPair {
    LexiconPair::from_slices(
        &[
            ("bonjour le monde", "hello world"),
            ("s'il vous plaît", "please"),
            ("merci beaucoup", "thank you very much"),
            ("comment allez-vous", "how are you"),
            ("vie privée", "privacy"),
            ("navigation privée", "private browsing"),
            ("mot de passe", "password"),
            ("mots de passe", "passwords"),
            ("nouvel onglet", "new tab"),
            ("hors ligne", "offline"),
            ("en ligne", "online"),
            ("sans compte", "without an account"),
            ("mise à jour", "update"),
            ("traduire cette page", "translate this page"),
            ("mode sombre", "dark mode"),
            ("mode clair", "light mode"),
            ("tout sélectionner", "select all"),
            ("enregistrer sous", "save as"),
            ("ouvrir le lien", "open link"),
            ("copier le lien", "copy link"),
            ("ce navigateur", "this browser"),
        ],
        &[
            ("bonjour", "hello"),
            ("bonsoir", "good evening"),
            ("salut", "hi"),
            ("merci", "thank you"),
            ("oui", "yes"),
            ("non", "no"),
            ("le", "the"),
            ("la", "the"),
            ("les", "the"),
            ("un", "a"),
            ("une", "a"),
            ("des", "some"),
            ("du", "of the"),
            ("de", "of"),
            ("et", "and"),
            ("ou", "or"),
            ("mais", "but"),
            ("avec", "with"),
            ("sans", "without"),
            ("pour", "for"),
            ("dans", "in"),
            ("sur", "on"),
            ("par", "by"),
            ("ce", "this"),
            ("cet", "this"),
            ("cette", "this"),
            ("ces", "these"),
            ("votre", "your"),
            ("vos", "your"),
            ("notre", "our"),
            ("mon", "my"),
            ("ma", "my"),
            ("est", "is"),
            ("sont", "are"),
            ("être", "be"),
            ("avoir", "have"),
            ("protège", "protects"),
            ("protéger", "protect"),
            ("fonctionne", "works"),
            ("entièrement", "completely"),
            ("toujours", "always"),
            ("jamais", "never"),
            ("rapidement", "quickly"),
            ("rapide", "fast"),
            ("sécurisé", "secure"),
            ("sécurité", "security"),
            ("localement", "locally"),
            ("local", "local"),
            ("navigateur", "browser"),
            ("paramètres", "settings"),
            ("favoris", "bookmarks"),
            ("historique", "history"),
            ("téléchargements", "downloads"),
            ("onglet", "tab"),
            ("onglets", "tabs"),
            ("fenêtre", "window"),
            ("page", "page"),
            ("site", "site"),
            ("recherche", "search"),
            ("rechercher", "search"),
            ("données", "data"),
            ("fichier", "file"),
            ("fichiers", "files"),
            ("dossier", "folder"),
            ("clé", "key"),
            ("clés", "keys"),
            ("synchronisation", "synchronization"),
            ("traduction", "translation"),
            ("traduire", "translate"),
            ("langue", "language"),
            ("langues", "languages"),
            ("réseau", "network"),
            ("appareil", "device"),
            ("appareils", "devices"),
            ("monde", "world"),
            ("utilisateur", "user"),
            ("bienvenue", "welcome"),
            ("fermer", "close"),
            ("ouvrir", "open"),
            ("enregistrer", "save"),
            ("supprimer", "delete"),
            ("annuler", "cancel"),
            ("confirmer", "confirm"),
            ("activer", "enable"),
            ("désactiver", "disable"),
            ("aucun", "no"),
            ("aucune", "no"),
            ("tout", "all"),
            ("tous", "all"),
            ("toutes", "all"),
            ("plus", "more"),
            ("moins", "less"),
            ("très", "very"),
            ("bien", "well"),
            ("nouveau", "new"),
            ("nouvelle", "new"),
            ("ici", "here"),
            ("maintenant", "now"),
            ("aujourd'hui", "today"),
            ("chiffré", "encrypted"),
            ("chiffrée", "encrypted"),
            ("chiffrés", "encrypted"),
        ],
    )
}

fn builtin_en_fr() -> LexiconPair {
    LexiconPair::from_slices(
        &[
            ("hello world", "bonjour le monde"),
            ("thank you very much", "merci beaucoup"),
            ("thank you", "merci"),
            ("how are you", "comment allez-vous"),
            ("private browsing", "navigation privée"),
            ("new tab", "nouvel onglet"),
            ("dark mode", "mode sombre"),
            ("light mode", "mode clair"),
            ("translate this page", "traduire cette page"),
            ("open link", "ouvrir le lien"),
            ("copy link", "copier le lien"),
            ("save as", "enregistrer sous"),
            ("select all", "tout sélectionner"),
            ("this browser", "ce navigateur"),
        ],
        &[
            ("hello", "bonjour"),
            ("hi", "salut"),
            ("please", "s'il vous plaît"),
            ("thanks", "merci"),
            ("yes", "oui"),
            ("no", "non"),
            ("the", "le"),
            ("a", "un"),
            ("an", "un"),
            ("and", "et"),
            ("or", "ou"),
            ("but", "mais"),
            ("with", "avec"),
            ("without", "sans"),
            ("for", "pour"),
            ("in", "dans"),
            ("on", "sur"),
            ("of", "de"),
            ("to", "à"),
            ("this", "ce"),
            ("these", "ces"),
            ("your", "votre"),
            ("our", "notre"),
            ("my", "mon"),
            ("is", "est"),
            ("are", "sont"),
            ("protects", "protège"),
            ("protect", "protéger"),
            ("works", "fonctionne"),
            ("completely", "entièrement"),
            ("offline", "hors ligne"),
            ("online", "en ligne"),
            ("always", "toujours"),
            ("never", "jamais"),
            ("fast", "rapide"),
            ("quickly", "rapidement"),
            ("secure", "sécurisé"),
            ("security", "sécurité"),
            ("privacy", "vie privée"),
            ("locally", "localement"),
            ("local", "local"),
            ("browser", "navigateur"),
            ("settings", "paramètres"),
            ("bookmarks", "favoris"),
            ("history", "historique"),
            ("downloads", "téléchargements"),
            ("password", "mot de passe"),
            ("passwords", "mots de passe"),
            ("tab", "onglet"),
            ("tabs", "onglets"),
            ("window", "fenêtre"),
            ("page", "page"),
            ("site", "site"),
            ("search", "recherche"),
            ("data", "données"),
            ("file", "fichier"),
            ("files", "fichiers"),
            ("folder", "dossier"),
            ("key", "clé"),
            ("keys", "clés"),
            ("synchronization", "synchronisation"),
            ("translation", "traduction"),
            ("translate", "traduire"),
            ("language", "langue"),
            ("languages", "langues"),
            ("network", "réseau"),
            ("device", "appareil"),
            ("devices", "appareils"),
            ("world", "monde"),
            ("user", "utilisateur"),
            ("welcome", "bienvenue"),
            ("close", "fermer"),
            ("open", "ouvrir"),
            ("save", "enregistrer"),
            ("delete", "supprimer"),
            ("cancel", "annuler"),
            ("confirm", "confirmer"),
            ("enable", "activer"),
            ("disable", "désactiver"),
            ("all", "tous"),
            ("more", "plus"),
            ("less", "moins"),
            ("very", "très"),
            ("new", "nouveau"),
            ("here", "ici"),
            ("now", "maintenant"),
            ("today", "aujourd'hui"),
            ("encrypted", "chiffré"),
            ("update", "mise à jour"),
        ],
    )
}

fn builtin_es_en() -> LexiconPair {
    LexiconPair::from_slices(
        &[
            ("hola mundo", "hello world"),
            ("muchas gracias", "thank you very much"),
            ("por favor", "please"),
            ("sin conexión", "offline"),
            ("nueva pestaña", "new tab"),
            ("modo oscuro", "dark mode"),
            ("traducir esta página", "translate this page"),
            ("este navegador", "this browser"),
        ],
        &[
            ("hola", "hello"),
            ("gracias", "thank you"),
            ("sí", "yes"),
            ("no", "no"),
            ("el", "the"),
            ("la", "the"),
            ("los", "the"),
            ("las", "the"),
            ("un", "a"),
            ("una", "a"),
            ("y", "and"),
            ("o", "or"),
            ("pero", "but"),
            ("con", "with"),
            ("sin", "without"),
            ("para", "for"),
            ("en", "in"),
            ("de", "of"),
            ("este", "this"),
            ("esta", "this"),
            ("tu", "your"),
            ("su", "your"),
            ("es", "is"),
            ("son", "are"),
            ("protege", "protects"),
            ("funciona", "works"),
            ("completamente", "completely"),
            ("siempre", "always"),
            ("nunca", "never"),
            ("rápido", "fast"),
            ("seguro", "secure"),
            ("seguridad", "security"),
            ("privacidad", "privacy"),
            ("navegador", "browser"),
            ("configuración", "settings"),
            ("configuraciones", "settings"),
            ("marcadores", "bookmarks"),
            ("historial", "history"),
            ("descargas", "downloads"),
            ("contraseña", "password"),
            ("pestaña", "tab"),
            ("ventana", "window"),
            ("página", "page"),
            ("buscar", "search"),
            ("datos", "data"),
            ("archivo", "file"),
            ("carpeta", "folder"),
            ("traducción", "translation"),
            ("traducir", "translate"),
            ("idioma", "language"),
            ("mundo", "world"),
            ("bienvenido", "welcome"),
            ("cerrar", "close"),
            ("abrir", "open"),
            ("guardar", "save"),
            ("eliminar", "delete"),
            ("cifrado", "encrypted"),
        ],
    )
}

fn builtin_en_es() -> LexiconPair {
    LexiconPair::from_slices(
        &[
            ("hello world", "hola mundo"),
            ("thank you very much", "muchas gracias"),
            ("thank you", "gracias"),
            ("new tab", "nueva pestaña"),
            ("dark mode", "modo oscuro"),
            ("translate this page", "traducir esta página"),
            ("this browser", "este navegador"),
        ],
        &[
            ("hello", "hola"),
            ("please", "por favor"),
            ("yes", "sí"),
            ("no", "no"),
            ("the", "el"),
            ("a", "un"),
            ("and", "y"),
            ("or", "o"),
            ("but", "pero"),
            ("with", "con"),
            ("without", "sin"),
            ("for", "para"),
            ("in", "en"),
            ("of", "de"),
            ("this", "este"),
            ("your", "tu"),
            ("is", "es"),
            ("are", "son"),
            ("protects", "protege"),
            ("works", "funciona"),
            ("completely", "completamente"),
            ("offline", "sin conexión"),
            ("always", "siempre"),
            ("never", "nunca"),
            ("fast", "rápido"),
            ("secure", "seguro"),
            ("security", "seguridad"),
            ("privacy", "privacidad"),
            ("browser", "navegador"),
            ("settings", "configuración"),
            ("bookmarks", "marcadores"),
            ("history", "historial"),
            ("downloads", "descargas"),
            ("password", "contraseña"),
            ("tab", "pestaña"),
            ("window", "ventana"),
            ("page", "página"),
            ("search", "buscar"),
            ("data", "datos"),
            ("file", "archivo"),
            ("folder", "carpeta"),
            ("translation", "traducción"),
            ("translate", "traducir"),
            ("language", "idioma"),
            ("world", "mundo"),
            ("welcome", "bienvenido"),
            ("close", "cerrar"),
            ("open", "abrir"),
            ("save", "guardar"),
            ("delete", "eliminar"),
            ("encrypted", "cifrado"),
        ],
    )
}

fn builtin_de_en() -> LexiconPair {
    LexiconPair::from_slices(
        &[
            ("hallo welt", "hello world"),
            ("vielen dank", "thank you very much"),
            ("neuer tab", "new tab"),
            ("dunkler modus", "dark mode"),
            ("diese seite übersetzen", "translate this page"),
            ("dieser browser", "this browser"),
        ],
        &[
            ("hallo", "hello"),
            ("danke", "thank you"),
            ("bitte", "please"),
            ("ja", "yes"),
            ("nein", "no"),
            ("der", "the"),
            ("die", "the"),
            ("das", "the"),
            ("ein", "a"),
            ("eine", "a"),
            ("und", "and"),
            ("oder", "or"),
            ("aber", "but"),
            ("mit", "with"),
            ("ohne", "without"),
            ("für", "for"),
            ("in", "in"),
            ("von", "of"),
            ("dieser", "this"),
            ("diese", "this"),
            ("ihre", "your"),
            ("ist", "is"),
            ("sind", "are"),
            ("schützt", "protects"),
            ("funktioniert", "works"),
            ("vollständig", "completely"),
            ("offline", "offline"),
            ("immer", "always"),
            ("niemals", "never"),
            ("schnell", "fast"),
            ("sicher", "secure"),
            ("sicherheit", "security"),
            ("datenschutz", "privacy"),
            ("privatsphäre", "privacy"),
            ("lokal", "locally"),
            ("browser", "browser"),
            ("einstellungen", "settings"),
            ("lesezeichen", "bookmarks"),
            ("verlauf", "history"),
            ("passwort", "password"),
            ("fenster", "window"),
            ("seite", "page"),
            ("suche", "search"),
            ("daten", "data"),
            ("datei", "file"),
            ("ordner", "folder"),
            ("übersetzung", "translation"),
            ("übersetzen", "translate"),
            ("sprache", "language"),
            ("welt", "world"),
            ("willkommen", "welcome"),
            ("schließen", "close"),
            ("öffnen", "open"),
            ("speichern", "save"),
            ("löschen", "delete"),
            ("verschlüsselt", "encrypted"),
        ],
    )
}

fn builtin_en_de() -> LexiconPair {
    LexiconPair::from_slices(
        &[
            ("hello world", "hallo Welt"),
            ("thank you very much", "vielen Dank"),
            ("thank you", "danke"),
            ("new tab", "neuer Tab"),
            ("dark mode", "dunkler Modus"),
            ("translate this page", "diese Seite übersetzen"),
            ("this browser", "dieser Browser"),
        ],
        &[
            ("hello", "hallo"),
            ("please", "bitte"),
            ("yes", "ja"),
            ("no", "nein"),
            ("the", "die"),
            ("a", "ein"),
            ("and", "und"),
            ("or", "oder"),
            ("but", "aber"),
            ("with", "mit"),
            ("without", "ohne"),
            ("for", "für"),
            ("in", "in"),
            ("of", "von"),
            ("this", "dieser"),
            ("your", "ihre"),
            ("is", "ist"),
            ("are", "sind"),
            ("protects", "schützt"),
            ("works", "funktioniert"),
            ("completely", "vollständig"),
            ("offline", "offline"),
            ("always", "immer"),
            ("never", "niemals"),
            ("fast", "schnell"),
            ("secure", "sicher"),
            ("security", "sicherheit"),
            ("privacy", "datenschutz"),
            ("locally", "lokal"),
            ("browser", "browser"),
            ("settings", "einstellungen"),
            ("bookmarks", "lesezeichen"),
            ("history", "verlauf"),
            ("password", "passwort"),
            ("window", "fenster"),
            ("page", "seite"),
            ("search", "suche"),
            ("data", "daten"),
            ("file", "datei"),
            ("folder", "ordner"),
            ("translation", "übersetzung"),
            ("translate", "übersetzen"),
            ("language", "sprache"),
            ("world", "welt"),
            ("welcome", "willkommen"),
            ("close", "schließen"),
            ("open", "öffnen"),
            ("save", "speichern"),
            ("delete", "löschen"),
            ("encrypted", "verschlüsselt"),
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_temp_root(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "singularity_translate_engine_{label}_{}_{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    #[test]
    fn split_inline_markup_handles_unclosed_angle_brackets_in_linear_time() {
        let unclosed_tags = "<a".repeat(25_000);
        let segs = split_inline_markup(&unclosed_tags);
        assert_eq!(segs.len(), 1);
        assert!(matches!(segs[0], MarkupSegment::Text(t) if t.len() == 50_000));

        let repeated_lt_then_gt = format!("{}>", "<".repeat(25_000));
        let segs2 = split_inline_markup(&repeated_lt_then_gt);
        assert_eq!(segs2.len(), 1);
        assert!(matches!(segs2[0], MarkupSegment::Text(t) if t.len() == 25_001));

        let mixed = "Bonjour <b>monde</b> <unclosed <still unclosed";
        let segs3 = split_inline_markup(mixed);
        assert_eq!(segs3.len(), 5);
        assert!(matches!(segs3[1], MarkupSegment::Tag("<b>")));
        assert!(matches!(segs3[3], MarkupSegment::Tag("</b>")));
        assert!(matches!(segs3[4], MarkupSegment::Text(" <unclosed <still unclosed")));
    }

    #[test]
    fn load_verified_packs_skips_corrupted_and_oversized_packs_individually() {
        let root = unique_temp_root("skip_bad");
        let signing_key = SigningKey::from_bytes(&[0x42u8; 32]);
        let trusted_pub = hex::encode(signing_key.verifying_key().as_bytes());
        let untrusted_key = SigningKey::from_bytes(&[0x99u8; 32]);

        let mut words = BTreeMap::new();
        words.insert("ciao".to_string(), "hello".to_string());
        let valid_table = LocalTranslationTable {
            source_lang: "it".to_string(),
            target_lang: "en".to_string(),
            phrases: BTreeMap::new(),
            words,
        };
        let valid_payload = serde_json::to_vec(&valid_table).unwrap();
        let valid_pack = OfflineLanguagePack::create_signed(
            "it",
            "en",
            "1.0.0",
            &valid_payload,
            &signing_key,
        )
        .unwrap();

        // Install a valid pack first
        let mut installer = OfflineTranslationEngine::default();
        installer
            .install_and_load_verified_pack(&root, valid_pack, &valid_payload, &trusted_pub)
            .unwrap();

        let dir = OfflineLanguagePack::models_translate_dir(&root);

        // Drop a corrupted JSON manifest
        fs::write(dir.join("00-corrupt.pack.json"), b"{not valid json").unwrap();

        // Drop an untrusted signed pack
        let mut bad_words = BTreeMap::new();
        bad_words.insert("ola".to_string(), "hi".to_string());
        let bad_table = LocalTranslationTable {
            source_lang: "pt".to_string(),
            target_lang: "en".to_string(),
            phrases: BTreeMap::new(),
            words: bad_words,
        };
        let bad_payload = serde_json::to_vec(&bad_table).unwrap();
        let bad_pack = OfflineLanguagePack::create_signed(
            "pt",
            "en",
            "1.0.0",
            &bad_payload,
            &untrusted_key,
        )
        .unwrap();
        fs::write(dir.join("pt-en.json"), &bad_payload).unwrap();
        fs::write(
            dir.join("pt-en.pack.json"),
            serde_json::to_vec(&bad_pack).unwrap(),
        )
        .unwrap();

        // Drop an oversized manifest (> 1 MiB)
        fs::write(
            dir.join("zz-oversized.pack.json"),
            vec![b' '; (MAX_PACK_MANIFEST_BYTES as usize) + 64],
        )
        .unwrap();

        let mut reloaded = OfflineTranslationEngine::default();
        let count = reloaded
            .load_verified_packs_from_disk(&root, &trusted_pub)
            .expect("must skip invalid packs and load valid ones");
        assert_eq!(count, 1);
        assert_eq!(reloaded.translate_text("it", "en", "ciao").unwrap(), "hello");
        assert!(reloaded.translate_text("pt", "en", "ola").is_err());

        let _ = fs::remove_dir_all(&root);
    }
}
