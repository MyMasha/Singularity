//! `singularity-translate` — 100% Offline Language Detection and Local DOM Batch Translation.
//!
//! Zero cloud requests, zero external API keys:
//! - Ultra-fast (< 0.2 ms) local language detector supporting 20+ languages via Unicode script
//!   blocks + stopword/trigram profiling.
//! - Cryptographically verified (`Ed25519` + `SHA-256`) offline language packs stored locally
//!   under `<root>/models/translate/`.
//! - Markup-safe DOM batch translation (`translate_batch`) preserving inline HTML tags,
//!   numbers, URLs, placeholders, punctuation, and letter casing.

pub mod detect;
pub mod engine;

pub use detect::{detect_language, DetectedScript, DetectionResult, SUPPORTED_LANGUAGES};
pub use engine::{
    LocalTranslationTable, OfflineLanguagePack, OfflineTranslationEngine, PageTranslationAction,
    TranslateError, TranslationPrefs,
};

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use std::collections::BTreeMap;

    fn temp_models_root(label: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "singularity_translate_{label}_{}_{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    #[test]
    fn ed25519_and_sha256_language_pack_verification_and_disk_loading() {
        let signing_key = SigningKey::from_bytes(&[0x5Au8; 32]);
        let trusted_pub_hex = hex::encode(signing_key.verifying_key().as_bytes());
        let untrusted_pub_hex = hex::encode(SigningKey::from_bytes(&[0xA5u8; 32]).verifying_key().as_bytes());

        let mut phrases = BTreeMap::new();
        phrases.insert("buongiorno mondo".to_string(), "good morning world".to_string());
        let mut words = BTreeMap::new();
        words.insert("ciao".to_string(), "hello".to_string());
        words.insert("impostazioni".to_string(), "settings".to_string());

        let table = LocalTranslationTable {
            source_lang: "it".to_string(),
            target_lang: "en".to_string(),
            phrases,
            words,
        };
        let payload_bytes = serde_json::to_vec_pretty(&table).unwrap();

        let pack = OfflineLanguagePack::create_signed(
            "it",
            "en",
            "1.0.0",
            &payload_bytes,
            &signing_key,
        )
        .expect("Sign pack");

        // Valid verification succeeds
        assert!(pack.verify_payload(&payload_bytes, &trusted_pub_hex).is_ok());

        // Untrusted signer public key is rejected
        assert!(matches!(
            pack.verify_payload(&payload_bytes, &untrusted_pub_hex),
            Err(TranslateError::UntrustedSigner)
        ));

        // Tampered payload byte fails SHA-256 integrity check
        let mut tampered = payload_bytes.clone();
        tampered[0] ^= 0x01;
        assert!(matches!(
            pack.verify_payload(&tampered, &trusted_pub_hex),
            Err(TranslateError::PackHashMismatch { .. })
        ));

        // Truncated payload fails size check
        assert!(matches!(
            pack.verify_payload(&payload_bytes[..10], &trusted_pub_hex),
            Err(TranslateError::PackSizeMismatch { .. })
        ));

        // Install verified pack into <root>/models/translate/ and reload into a fresh engine
        let root = temp_models_root("pack_verify");
        let mut engine = OfflineTranslationEngine::default();
        let saved_path = engine
            .install_and_load_verified_pack(&root, pack, &payload_bytes, &trusted_pub_hex)
            .expect("Install & load verified pack");
        assert!(saved_path.ends_with("models/translate/it-en.json"));

        let translated = engine
            .translate_text("it", "en", "Buongiorno mondo! Ciao, impostazioni.")
            .expect("Translate using installed IT->EN pack");
        assert_eq!(translated, "Good morning world! Hello, settings.");

        // A brand-new engine reloads verified packs from disk cleanly
        let mut reloaded_engine = OfflineTranslationEngine::default();
        let loaded_count = reloaded_engine
            .load_verified_packs_from_disk(&root, &trusted_pub_hex)
            .expect("Reload verified packs from disk");
        assert_eq!(loaded_count, 1);
        assert_eq!(
            reloaded_engine.translate_text("it", "en", "CIAO").unwrap(),
            "HELLO"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn batch_translation_fr_en_es_de_preserves_markup_numbers_punctuation_and_casing() {
        let engine = OfflineTranslationEngine::default();

        let nodes = vec![
            "Bonjour le monde! <b>Ce navigateur</b> protège votre vie privée (100% hors ligne)."
                .to_string(),
            "PARAMÈTRES: <a href=\"https://singularity.local/docs\">Ouvrir le lien</a> — 2026"
                .to_string(),
            "Merci beaucoup pour votre sécurité.".to_string(),
        ];

        let translated = engine
            .translate_batch("fr", "en", &nodes)
            .expect("FR -> EN batch translation");
        assert_eq!(translated.len(), 3);
        assert_eq!(
            translated[0],
            "Hello world! <b>This browser</b> protects your privacy (100% offline)."
        );
        assert_eq!(
            translated[1],
            "SETTINGS: <a href=\"https://singularity.local/docs\">Open link</a> — 2026"
        );
        assert_eq!(
            translated[2],
            "Thank you very much for your security."
        );

        // EN -> FR roundtrip check
        let en_to_fr = engine
            .translate_text("en", "fr", "Hello world! <span>New tab</span> — Dark mode")
            .unwrap();
        assert_eq!(
            en_to_fr,
            "Bonjour le monde! <span>Nouvel onglet</span> — Mode sombre"
        );

        // ES -> EN & DE -> EN built-in packs
        assert_eq!(
            engine
                .translate_text("es", "en", "Hola mundo! Este navegador protege tu privacidad.")
                .unwrap(),
            "Hello world! This browser protects your privacy."
        );
        assert_eq!(
            engine
                .translate_text("de", "en", "Hallo Welt! Dieser Browser schützt Ihre Privatsphäre.")
                .unwrap(),
            "Hello world! This browser protects your privacy."
        );

        // Same-language is an exact no-op
        assert_eq!(
            engine.translate_text("fr", "fr", "Texte inchangé 42").unwrap(),
            "Texte inchangé 42"
        );
    }

    #[test]
    fn translation_prefs_always_never_language_and_site_rules() {
        let mut prefs = TranslationPrefs {
            enabled: true,
            target_lang: "en".to_string(),
            auto_prompt_on_foreign_page: true,
            selection_popup_enabled: true,
            ..Default::default()
        };

        // Foreign page triggers prompt by default
        assert_eq!(
            prefs.evaluate_page_policy("fr", "news.example.fr"),
            PageTranslationAction::PromptUser
        );
        // Same language skips translation
        assert_eq!(
            prefs.evaluate_page_policy("en", "docs.example.org"),
            PageTranslationAction::AlreadyTargetLanguage
        );

        // Always-translate language rule
        prefs.add_always_translate_lang("fr");
        assert_eq!(
            prefs.evaluate_page_policy("fr", "news.example.fr"),
            PageTranslationAction::AutoTranslate
        );

        // Never-translate site overrides always-translate language (including subdomains!)
        prefs.add_never_translate_site("https://example.fr/articles");
        assert_eq!(
            prefs.evaluate_page_policy("fr", "news.example.fr"),
            PageTranslationAction::NeverTranslateSite
        );
        assert_eq!(
            prefs.evaluate_page_policy("fr", "example.fr"),
            PageTranslationAction::NeverTranslateSite
        );
        // Non-matching domain suffix must NOT match `example.fr`
        assert_eq!(
            prefs.evaluate_page_policy("fr", "notexample.fr"),
            PageTranslationAction::AutoTranslate
        );

        // Never-translate language rule
        prefs.add_never_translate_lang("de");
        assert_eq!(
            prefs.evaluate_page_policy("de", "wiki.org"),
            PageTranslationAction::NeverTranslateLanguage
        );

        // Switching a language from always -> never keeps sets mutually exclusive
        prefs.add_never_translate_lang("fr");
        assert!(!prefs.always_translate_langs.contains("fr"));
        assert!(prefs.never_translate_langs.contains("fr"));

        // Global disable
        prefs.enabled = false;
        assert_eq!(
            prefs.evaluate_page_policy("es", "site.es"),
            PageTranslationAction::Disabled
        );
    }

    #[test]
    fn offline_pivot_translation_and_url_placeholder_preservation() {
        let engine = OfflineTranslationEngine::default();
        // Pivot FR -> EN -> DE without a direct fr-de table
        let pivoted = engine
            .translate_text("fr", "de", "Bonjour le monde! Ce navigateur protège votre sécurité.")
            .expect("Offline pivot FR -> DE");
        assert!(pivoted.contains("Hallo Welt!"));
        assert!(pivoted.contains("Dieser Browser"));

        // Preserve URLs and formatting placeholders untouched
        let kept = engine
            .translate_text(
                "fr",
                "en",
                "Bienvenue {0} sur https://example.org/fr/page (%s)!",
            )
            .unwrap();
        assert_eq!(
            kept,
            "Welcome {0} on https://example.org/fr/page (%s)!"
        );
    }
}
