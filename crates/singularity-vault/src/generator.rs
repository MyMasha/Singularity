//! Cryptographically Unbiased Password & Diceware/EFF Passphrase Generator
//! using `OsRng` Rejection Sampling and Fisher-Yates Shuffling.

use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const MIN_PASSWORD_LENGTH: usize = 8;
pub const MAX_PASSWORD_LENGTH: usize = 128;
pub const MIN_PASSPHRASE_WORDS: usize = 3;
pub const MAX_PASSPHRASE_WORDS: usize = 12;

const UPPERCASE_CHARS: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWERCASE_CHARS: &str = "abcdefghijklmnopqrstuvwxyz";
const DIGIT_CHARS: &str = "0123456789";
const DEFAULT_SYMBOL_CHARS: &str = "!@#$%^&*()-_=+[]{}|;:,.<>?/~";
const AMBIGUOUS_CHARS: &str = "0O1lI|";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum GeneratorError {
    #[error("Password length {0} is out of allowed bounds ({MIN_PASSWORD_LENGTH}..={MAX_PASSWORD_LENGTH})")]
    InvalidLength(usize),
    #[error("Conflicting HTML length constraints: minlength={min} > maxlength={max}")]
    ConflictingHtmlConstraints { min: usize, max: usize },
    #[error("At least one character class must be enabled and non-empty")]
    EmptyAlphabet,
    #[error("Sum of required character minimums ({required}) exceeds effective length ({effective_length})")]
    MinimumsExceedLength {
        required: usize,
        effective_length: usize,
    },
    #[error("Passphrase word_count {0} is out of allowed bounds ({MIN_PASSPHRASE_WORDS}..={MAX_PASSPHRASE_WORDS})")]
    InvalidWordCount(usize),
}

/// Generated secret value paired with its exact theoretical entropy in bits.
/// Automatically zeroized on drop and redacted in `Debug`.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct GeneratedSecret {
    pub value: String,
    #[zeroize(skip)]
    pub entropy_bits: f64,
}

impl fmt::Debug for GeneratedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GeneratedSecret")
            .field("value", &"[REDACTED]")
            .field("entropy_bits", &self.entropy_bits)
            .finish()
    }
}

/// Configuration for cryptographically uniform random password generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasswordGeneratorConfig {
    pub length: usize,
    pub uppercase: bool,
    pub lowercase: bool,
    pub digits: bool,
    pub symbols: bool,
    pub min_uppercase: usize,
    pub min_lowercase: usize,
    pub min_digits: usize,
    pub min_symbols: usize,
    pub exclude_ambiguous: bool,
    #[serde(default)]
    pub custom_symbols: Option<String>,
    #[serde(default)]
    pub html_minlength: Option<usize>,
    #[serde(default)]
    pub html_maxlength: Option<usize>,
}

impl Default for PasswordGeneratorConfig {
    fn default() -> Self {
        Self {
            length: 20,
            uppercase: true,
            lowercase: true,
            digits: true,
            symbols: true,
            min_uppercase: 1,
            min_lowercase: 1,
            min_digits: 1,
            min_symbols: 1,
            exclude_ambiguous: false,
            custom_symbols: None,
            html_minlength: None,
            html_maxlength: None,
        }
    }
}

/// Unbiased uniform random index in `0..bound` using `OsRng` rejection sampling (no modulo bias).
fn random_index_unbiased(bound: usize) -> usize {
    debug_assert!(bound > 0);
    if bound <= 1 {
        return 0;
    }
    let bound_u64 = bound as u64;
    let zone = u64::MAX - (u64::MAX % bound_u64);
    loop {
        let sample = OsRng.next_u64();
        if sample < zone {
            return (sample % bound_u64) as usize;
        }
    }
}

/// Uniform unbiased Fisher-Yates shuffle over `slice` using `OsRng` rejection sampling.
fn fisher_yates_shuffle<T>(slice: &mut [T]) {
    if slice.len() <= 1 {
        return;
    }
    for i in (1..slice.len()).rev() {
        let j = random_index_unbiased(i + 1);
        slice.swap(i, j);
    }
}

fn filter_pool(raw: &str, exclude_ambiguous: bool) -> Vec<char> {
    let mut chars = Vec::new();
    for ch in raw.chars() {
        if exclude_ambiguous && AMBIGUOUS_CHARS.contains(ch) {
            continue;
        }
        if !chars.contains(&ch) {
            chars.push(ch);
        }
    }
    chars
}

/// Generates a random password strictly satisfying `cfg` (including HTML `minlength`/`maxlength`
/// constraints and per-class minimums) using unbiased rejection sampling + Fisher-Yates shuffle.
pub fn generate_password(cfg: &PasswordGeneratorConfig) -> Result<GeneratedSecret, GeneratorError> {
    if !(MIN_PASSWORD_LENGTH..=MAX_PASSWORD_LENGTH).contains(&cfg.length) {
        return Err(GeneratorError::InvalidLength(cfg.length));
    }

    if let (Some(min_h), Some(max_h)) = (cfg.html_minlength, cfg.html_maxlength) {
        if min_h > max_h {
            return Err(GeneratorError::ConflictingHtmlConstraints {
                min: min_h,
                max: max_h,
            });
        }
    }

    // Reconcile effective length with HTML form input constraints
    let mut effective_length = cfg.length;
    if let Some(min_h) = cfg.html_minlength {
        if effective_length < min_h {
            effective_length = min_h.min(MAX_PASSWORD_LENGTH);
        }
    }
    if let Some(max_h) = cfg.html_maxlength {
        if max_h == 0 {
            return Err(GeneratorError::InvalidLength(0));
        }
        if effective_length > max_h {
            effective_length = max_h;
        }
    }

    let upper_pool = if cfg.uppercase {
        filter_pool(UPPERCASE_CHARS, cfg.exclude_ambiguous)
    } else {
        Vec::new()
    };
    let lower_pool = if cfg.lowercase {
        filter_pool(LOWERCASE_CHARS, cfg.exclude_ambiguous)
    } else {
        Vec::new()
    };
    let digit_pool = if cfg.digits {
        filter_pool(DIGIT_CHARS, cfg.exclude_ambiguous)
    } else {
        Vec::new()
    };
    let symbol_pool = if cfg.symbols {
        let raw_syms = cfg
            .custom_symbols
            .as_deref()
            .unwrap_or(DEFAULT_SYMBOL_CHARS);
        filter_pool(raw_syms, cfg.exclude_ambiguous)
    } else {
        Vec::new()
    };

    let mut combined_pool: Vec<char> = Vec::new();
    for ch in upper_pool
        .iter()
        .chain(lower_pool.iter())
        .chain(digit_pool.iter())
        .chain(symbol_pool.iter())
    {
        if !combined_pool.contains(ch) {
            combined_pool.push(*ch);
        }
    }
    if combined_pool.is_empty() {
        return Err(GeneratorError::EmptyAlphabet);
    }

    let req_upper = if upper_pool.is_empty() {
        0
    } else {
        cfg.min_uppercase
    };
    let req_lower = if lower_pool.is_empty() {
        0
    } else {
        cfg.min_lowercase
    };
    let req_digits = if digit_pool.is_empty() {
        0
    } else {
        cfg.min_digits
    };
    let req_symbols = if symbol_pool.is_empty() {
        0
    } else {
        cfg.min_symbols
    };

    let total_required = req_upper + req_lower + req_digits + req_symbols;
    if total_required > effective_length {
        return Err(GeneratorError::MinimumsExceedLength {
            required: total_required,
            effective_length,
        });
    }

    let mut output_chars: Vec<char> = Vec::with_capacity(effective_length);

    for _ in 0..req_upper {
        output_chars.push(upper_pool[random_index_unbiased(upper_pool.len())]);
    }
    for _ in 0..req_lower {
        output_chars.push(lower_pool[random_index_unbiased(lower_pool.len())]);
    }
    for _ in 0..req_digits {
        output_chars.push(digit_pool[random_index_unbiased(digit_pool.len())]);
    }
    for _ in 0..req_symbols {
        output_chars.push(symbol_pool[random_index_unbiased(symbol_pool.len())]);
    }

    while output_chars.len() < effective_length {
        output_chars.push(combined_pool[random_index_unbiased(combined_pool.len())]);
    }

    fisher_yates_shuffle(&mut output_chars);

    let value: String = output_chars.iter().collect();
    // Scrub temporary char buffer
    for c in &mut output_chars {
        *c = '\0';
    }

    let entropy_bits = (effective_length as f64) * (combined_pool.len() as f64).log2();
    Ok(GeneratedSecret {
        value,
        entropy_bits,
    })
}

/// Embedded Diceware wordlist language.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WordlistLanguage {
    #[default]
    English,
    French,
}

/// Capitalization mode for generated passphrases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WordCapitalization {
    Lowercase,
    #[default]
    TitleCase,
    Uppercase,
    RandomWordUppercase,
}

/// Configuration for Diceware / EFF-style passphrase generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PassphraseConfig {
    pub word_count: usize,
    #[serde(default)]
    pub language: WordlistLanguage,
    #[serde(default = "default_separator")]
    pub separator: String,
    #[serde(default)]
    pub capitalization: WordCapitalization,
    #[serde(default)]
    pub include_number: bool,
}

fn default_separator() -> String {
    "-".to_string()
}

impl Default for PassphraseConfig {
    fn default() -> Self {
        Self {
            word_count: 6,
            language: WordlistLanguage::English,
            separator: "-".to_string(),
            capitalization: WordCapitalization::TitleCase,
            include_number: true,
        }
    }
}

/// Returns the embedded Diceware wordlist slice for `language` (512 unique words each = 9.0 bits/word).
pub fn embedded_wordlist(language: WordlistLanguage) -> &'static [&'static str] {
    match language {
        WordlistLanguage::English => WORDLIST_EN,
        WordlistLanguage::French => WORDLIST_FR,
    }
}

/// Computes exact passphrase entropy in bits for `cfg`.
pub fn calculate_passphrase_entropy_bits(cfg: &PassphraseConfig) -> f64 {
    let dict_size = embedded_wordlist(cfg.language).len() as f64;
    let mut bits = (cfg.word_count as f64) * dict_size.log2();
    if cfg.include_number {
        // Uniform random digit 0..=9 placed on a uniformly chosen word among word_count
        bits += ((cfg.word_count * 10) as f64).log2();
    }
    if cfg.capitalization == WordCapitalization::RandomWordUppercase && cfg.word_count > 1 {
        bits += (cfg.word_count as f64).log2();
    }
    bits
}

fn title_case(word: &str) -> String {
    let mut chars = word.chars();
    match chars.next() {
        Some(first) => {
            let mut out = String::with_capacity(word.len());
            for up in first.to_uppercase() {
                out.push(up);
            }
            out.push_str(chars.as_str());
            out
        }
        None => String::new(),
    }
}

/// Generates a Diceware / EFF-style passphrase with unbiased `OsRng` word selection
/// and exact entropy reporting.
pub fn generate_passphrase(cfg: &PassphraseConfig) -> Result<GeneratedSecret, GeneratorError> {
    if !(MIN_PASSPHRASE_WORDS..=MAX_PASSPHRASE_WORDS).contains(&cfg.word_count) {
        return Err(GeneratorError::InvalidWordCount(cfg.word_count));
    }

    let dict = embedded_wordlist(cfg.language);
    let random_upper_idx = if cfg.capitalization == WordCapitalization::RandomWordUppercase {
        Some(random_index_unbiased(cfg.word_count))
    } else {
        None
    };
    let number_word_idx = if cfg.include_number {
        Some(random_index_unbiased(cfg.word_count))
    } else {
        None
    };
    let random_digit = if cfg.include_number {
        random_index_unbiased(10)
    } else {
        0
    };

    let mut words = Vec::with_capacity(cfg.word_count);
    for i in 0..cfg.word_count {
        let raw = dict[random_index_unbiased(dict.len())];
        let mut word = match cfg.capitalization {
            WordCapitalization::Lowercase => raw.to_string(),
            WordCapitalization::TitleCase => title_case(raw),
            WordCapitalization::Uppercase => raw.to_ascii_uppercase(),
            WordCapitalization::RandomWordUppercase => {
                if random_upper_idx == Some(i) {
                    raw.to_ascii_uppercase()
                } else {
                    raw.to_string()
                }
            }
        };
        if number_word_idx == Some(i) {
            word.push_str(&random_digit.to_string());
        }
        words.push(word);
    }

    let value = words.join(&cfg.separator);
    for w in &mut words {
        w.zeroize();
    }

    let entropy_bits = calculate_passphrase_entropy_bits(cfg);
    Ok(GeneratedSecret {
        value,
        entropy_bits,
    })
}

/// Embedded English Diceware / EFF-inspired wordlist (512 distinct memorable words = 9.0 bits/word).
const WORDLIST_EN: &[&str] = &[
    "abacus", "abbey", "acorn", "acre", "acrobat", "actor", "admiral", "agate",
    "agenda", "albatross", "alchemy", "alder", "alibi", "alley", "almond", "alpaca",
    "alpine", "amber", "ambush", "amethyst", "amulet", "anchor", "anemone", "angler",
    "ankle", "anthem", "anvil", "apex", "apricot", "apron", "aqueduct", "arbor",
    "arcade", "archer", "arctic", "arena", "argon", "armada", "armor", "aroma",
    "arrow", "artichoke", "aspen", "asphalt", "asteroid", "astrolabe", "atlas", "atoll",
    "atom", "atrium", "aurora", "autumn", "avalanche", "avocado", "awning", "axis",
    "azalea", "azure", "baboon", "backdrop", "badge", "badger", "bagel", "bakery",
    "balance", "balcony", "ballad", "balloon", "bamboo", "banjo", "banner", "banyan",
    "barley", "barnacle", "barometer", "baron", "barrel", "basalt", "basil", "basket",
    "bassoon", "bastion", "battery", "bayonet", "bayou", "beacon", "beaker", "beaver",
    "beehive", "beetle", "belfry", "bellows", "beret", "beryl", "bicycle", "bison",
    "bistro", "blackberry", "blizzard", "blossom", "bluebird", "bobcat", "bonfire", "bonsai",
    "bookmark", "boomerang", "botany", "boulder", "boulevard", "bouquet", "boxcar", "bracelet",
    "bramble", "brass", "breeze", "brewery", "brigade", "brimstone", "bristle", "broccoli",
    "bronze", "brook", "brownie", "brush", "bubble", "bucket", "buckle", "buffalo",
    "bugle", "bulwark", "bunker", "bunting", "burdock", "burlap", "burrow", "bushel",
    "buttercup", "button", "cabana", "cabin", "cabinet", "cactus", "cadence", "cairn",
    "caldera", "calico", "calliope", "camel", "cameo", "campfire", "canal", "canary",
    "candle", "canister", "cannon", "canoe", "canopy", "cantata", "canteen", "canvas",
    "canyon", "capstan", "capsule", "caramel", "caravan", "carbon", "cardamom", "cardinal",
    "caribou", "carnation", "carousel", "carpet", "carriage", "carrot", "carton", "cascade",
    "cashew", "cassette", "castle", "catapult", "cathedral", "cauldron", "cavern", "cedar",
    "celery", "cellar", "cello", "celsius", "cement", "centaur", "ceramic", "chalice",
    "chalk", "chamber", "chamois", "chapel", "charcoal", "chariot", "chassis", "checkers",
    "cheddar", "cheetah", "cherry", "chess", "chestnut", "chiffon", "chimney", "chipmunk",
    "chisel", "chorus", "chowder", "chrome", "chrysalis", "cider", "cilantro", "cinder",
    "cinema", "cinnamon", "cipher", "circuit", "circus", "cistern", "citadel", "citron",
    "citrus", "clarinet", "clavicle", "claymore", "cleaver", "cliff", "clipper", "cloister",
    "cloud", "clover", "cluster", "cobbler", "cobalt", "cobra", "coconut", "cocoon",
    "codex", "coffee", "coffer", "cognac", "colander", "collage", "collie", "column",
    "comet", "compass", "concerto", "condor", "conduit", "confetti", "conifer", "console",
    "consul", "copper", "coral", "cordial", "coriander", "cork", "cornet", "cornice",
    "corona", "corral", "corsair", "cortex", "cosmos", "cottage", "cotton", "cougar",
    "courier", "courtyard", "covenant", "cowboy", "coyote", "cradle", "cranberry", "crane",
    "crater", "crayon", "credenza", "creek", "crescent", "crest", "cricket", "crimson",
    "crocus", "croissant", "crossbow", "crouton", "crowbar", "crucible", "cruiser", "crumpet",
    "crystal", "cuckoo", "cucumber", "culvert", "cumin", "cupboard", "cupola", "curlew",
    "currant", "curtain", "cushion", "custard", "cutlass", "cyclone", "cylinder", "cymbal",
    "cypress", "daffodil", "dagger", "dahlia", "dairy", "daisy", "damask", "dandelion",
    "dart", "dashboard", "daybreak", "deacon", "decibel", "decoy", "delphinium", "delta",
    "denim", "depot", "derby", "desert", "desk", "detour", "diadem", "dial",
    "diamond", "diaphragm", "diorama", "dipper", "dirigible", "discus", "distaff", "divan",
    "dockyard", "dolphin", "domino", "donkey", "doormat", "dormer", "dovetail", "dragonfly",
    "drapery", "drawbridge", "dredger", "driftwood", "droplet", "drumstick", "dryad", "duckling",
    "duet", "dugong", "dulcimer", "dumpling", "dune", "dungeon", "dynamo", "eagle",
    "earring", "easel", "eclipse", "edelweiss", "edifice", "egret", "eider", "elbow",
    "elder", "elephant", "elevator", "elixir", "emerald", "emblem", "ember", "empire",
    "enamel", "enclave", "encore", "engine", "enigma", "ensign", "envelope", "epilogue",
    "epoch", "equinox", "ermine", "escalator", "espresso", "estuary", "etching", "ether",
    "eucalyptus", "eureka", "evergreen", "fable", "fabric", "facade", "facet", "falcon",
    "fandango", "fanfare", "fathom", "faucet", "feather", "fedora", "fennel", "ferret",
    "ferry", "festival", "fiddle", "fiesta", "figment", "filbert", "filigree", "finch",
    "firefly", "fireplace", "firewood", "fjord", "flagon", "flamingo", "flannel", "flask",
    "flax", "fleece", "flicker", "flint", "florence", "flotsam", "flounder", "flourish",
    "flute", "flywheel", "foal", "fodder", "foghorn", "foliage", "folio", "fondue",
    "foothill", "footprint", "forage", "forecastle", "forest", "forge", "formula", "fortress",
    "fossil", "fountain", "foxhound", "foxglove", "fractal", "fragment", "fragrance", "fresco",
    "frigate", "fringe", "fritter", "frontier", "frost", "fructose", "fuchsia", "fulcrum",
    "furlong", "furnace", "furrow", "fuselage", "gadget", "galapagos", "galaxy", "gale",
    "galleon", "gallery", "galley", "gallop", "gambit", "gannet", "gantry", "garage",
    "gardenia", "gargoyle", "garland", "garlic", "garnet", "garrison", "garter", "gaslight",
    "gauntlet", "gazebo", "gazelle", "gearbox", "gecko", "gelato", "gemini", "generator",
    "gentian", "geode", "geranium", "geyser", "gherkin", "gibbon", "ginger", "gingham",
];

/// Embedded French Diceware wordlist (512 distinct ASCII-friendly French words = 9.0 bits/word).
const WORDLIST_FR: &[&str] = &[
    "abeille", "abricot", "acacia", "accord", "acier", "acrobate", "adresse", "agate",
    "agenda", "agneau", "agrafe", "aigle", "aiguille", "aileron", "aimant", "airelle",
    "alambic", "albatros", "album", "alchimie", "alize", "alliance", "allumette", "alouette",
    "alpaga", "alphabet", "altitude", "amande", "amarre", "amateur", "ambre", "amethyste",
    "amiral", "amitie", "ammonite", "amphore", "ampoule", "amulette", "ananas", "ancetre",
    "anchois", "ancolie", "ancre", "ardoise", "arene", "argent", "argile", "armada",
    "armoire", "armure", "arobase", "arome", "arpent", "arquebuse", "arsenal", "artichaut",
    "artisan", "artiste", "asphalte", "asteroide", "astrolabe", "atelier", "atlas", "atoll",
    "atome", "aubade", "aubaine", "auberge", "aubier", "audience", "augure", "aulne",
    "aurore", "automne", "autruche", "avalanche", "avenir", "avenue", "averse", "aviateur",
    "aviron", "avocat", "avoine", "azalee", "azimut", "azote", "azur", "babouin",
    "bache", "badge", "bagage", "bagatelle", "baguette", "bahut", "baignade", "bain",
    "baionnette", "balade", "balance", "balcon", "baleine", "balise", "ballade", "ballast",
    "ballon", "ballot", "balustrade", "bambou", "banane", "bambin", "bandeau", "banderole",
    "banian", "banjo", "banquise", "baobab", "bapteme", "baraque", "barbe", "barcarolle",
    "bardeau", "baril", "barometre", "baron", "barque", "barrage", "barreau", "basalte",
    "bascule", "basilic", "basilique", "basket", "bassin", "basson", "bastide", "bastion",
    "bataille", "bateau", "batelier", "batiment", "baton", "batterie", "baudrier", "baume",
    "bavard", "bazar", "becasse", "beffroi", "begonia", "beignet", "belette", "belier",
    "beluga", "belvedere", "benne", "berceau", "beret", "bergamote", "berge", "berger",
    "berline", "bermuda", "beryl", "besace", "beton", "betterave", "beurre", "biberon",
    "biche", "bicyclette", "bidon", "bielle", "bigorne", "bijou", "bilan", "billard",
    "billet", "billot", "binocle", "biologie", "biplan", "biquet", "bisbille", "biscotte",
    "biscuit", "biseau", "bison", "bisou", "bistouri", "bistrot", "bitume", "bivouac",
    "blaireau", "blason", "bleuet", "blindage", "blizzard", "blocage", "blocus", "blondin",
    "blouse", "blouson", "bobine", "bocage", "bocal", "boheme", "boiserie", "boisson",
    "boite", "boitier", "bolero", "bolide", "bombance", "bombe", "bonbon", "bonheur",
    "boniface", "bonjour", "bonnet", "bonsai", "bonsoir", "bordelais", "bordereau", "bordure",
    "boreal", "borgne", "borne", "bosquet", "bosse", "botanique", "botte", "bottine",
    "bouc", "boucan", "bouche", "boucle", "bouclier", "boudoir", "bouee", "bouffon",
    "bougeoir", "bougie", "bougran", "bouillon", "bouleau", "boulet", "boulevard", "boulier",
    "boulingrin", "boulon", "bouquet", "bouquetin", "bouquin", "bourbe", "bourdon", "bourg",
    "bourgade", "bourgeon", "bourrasque", "bourrelier", "bourse", "boussole", "boutade", "bouteille",
    "boutique", "bouton", "bouture", "bovin", "boxeur", "boyau", "bracelet", "braguette",
    "braise", "brancard", "branche", "brandade", "brandon", "branle", "braquemart", "brasier",
    "brassard", "brasse", "brasserie", "bravade", "bravoure", "brebis", "breche", "bredouille",
    "breloque", "bretelle", "bretzel", "breuvage", "brevet", "bribe", "bricole", "bride",
    "bridge", "brigade", "brigand", "brigantin", "brillant", "brimade", "brin", "brindille",
    "brioche", "brique", "briquet", "brisant", "brise", "bristol", "broc", "brocante",
    "brocard", "brocart", "broche", "brochet", "brochure", "brocoli", "broderie", "brodequin",
    "bronze", "brosse", "brouet", "brouette", "brouhaha", "brouillard", "brouillon", "brousse",
    "broyeur", "brugnon", "bruine", "bruit", "brulot", "brulure", "brume", "brunette",
    "brusque", "bruyere", "buanderie", "bube", "buche", "bucher", "bucheron", "bucolique",
    "budget", "buee", "buffet", "buffle", "buggy", "bugle", "buis", "buisson",
    "bulbe", "bulldozer", "bulle", "bulletin", "bunker", "buraliste", "bure", "bureau",
    "burette", "burin", "burlesque", "burnous", "buse", "busard", "buste", "butin",
    "butoir", "butor", "butte", "buvard", "buvette", "cabale", "cabane", "cabaret",
    "cabas", "cabestan", "cabillaud", "cabine", "cabinet", "cable", "cabochon", "cabotage",
    "cabri", "cabriole", "cacao", "cacatoes", "cache", "cachemire", "cachet", "cachot",
    "cactus", "cadastre", "cadavre", "cadeau", "cadenas", "cadence", "cadet", "cadran",
    "cadre", "cafard", "cafe", "cafeier", "cafetiere", "caftan", "cage", "cageot",
    "cagnotte", "cagoule", "cahier", "cahot", "cahute", "caille", "caillou", "caiman",
    "cairn", "caisse", "caisson", "cajou", "calabash", "calamar", "calamine", "calanque",
    "calcaire", "calcul", "caldera", "caleche", "calendrier", "calepin", "calibre", "calice",
    "calicot", "calife", "calin", "calisson", "calmant", "calmar", "calme", "calomel",
    "calotte", "calque", "calumet", "calvaire", "calvitie", "camaieu", "camarade", "cambuse",
    "came", "camee", "cameleon", "camelia", "camembert", "camera", "camion", "camisole",
    "camomille", "campagne", "campanile", "campeur", "camphre", "camping", "campus", "canaille",
    "canal", "canape", "canard", "canari", "canasta", "cancan", "cancre", "cancrelat",
    "candeur", "candidat", "candide", "cane", "caneton", "canevas", "caniche", "canicule",
    "canif", "caniveau", "canne", "cannelle", "cannelure", "canette", "cannibale", "canoe",
    "canon", "canot", "canotier", "cantate", "cantine", "cantique", "canton", "canule",
    "caoutchouc", "capable", "caparacon", "cape", "capeline", "capillaire", "capitaine", "capital",
    "capitole", "capon", "caporal", "capot", "capote", "capre", "caprice", "capsule",
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_embedded_wordlists_size_and_uniqueness() {
        assert_eq!(WORDLIST_EN.len(), 512);
        assert_eq!(WORDLIST_FR.len(), 512);

        let en_set: HashSet<&str> = WORDLIST_EN.iter().copied().collect();
        let fr_set: HashSet<&str> = WORDLIST_FR.iter().copied().collect();
        assert_eq!(en_set.len(), 512, "English wordlist must have 512 unique words");
        assert_eq!(fr_set.len(), 512, "French wordlist must have 512 unique words");
    }

    #[test]
    fn test_password_generator_minimums_ambiguous_exclusion_and_html_constraints() {
        let cfg = PasswordGeneratorConfig {
            length: 24,
            uppercase: true,
            lowercase: true,
            digits: true,
            symbols: true,
            min_uppercase: 3,
            min_lowercase: 3,
            min_digits: 3,
            min_symbols: 3,
            exclude_ambiguous: true,
            custom_symbols: Some("!@#$%".into()),
            html_minlength: None,
            html_maxlength: None,
        };

        for _ in 0..25 {
            let gen = generate_password(&cfg).expect("generate password");
            assert_eq!(gen.value.chars().count(), 24);
            assert!(gen.entropy_bits > 130.0);
            assert!(!format!("{:?}", gen).contains(&gen.value));

            let uppers = gen.value.chars().filter(|c| c.is_ascii_uppercase()).count();
            let lowers = gen.value.chars().filter(|c| c.is_ascii_lowercase()).count();
            let digits = gen.value.chars().filter(|c| c.is_ascii_digit()).count();
            let syms = gen.value.chars().filter(|c| "!@#$%".contains(*c)).count();
            assert!(uppers >= 3);
            assert!(lowers >= 3);
            assert!(digits >= 3);
            assert!(syms >= 3);
            for amb in AMBIGUOUS_CHARS.chars() {
                assert!(!gen.value.contains(amb), "Ambiguous char {} leaked", amb);
            }
        }

        // HTML maxlength clamps length automatically
        let constrained = PasswordGeneratorConfig {
            length: 32,
            html_minlength: Some(10),
            html_maxlength: Some(14),
            ..Default::default()
        };
        let p = generate_password(&constrained).unwrap();
        assert_eq!(p.value.len(), 14);

        // Conflicting HTML constraints rejected
        let bad_html = PasswordGeneratorConfig {
            length: 16,
            html_minlength: Some(20),
            html_maxlength: Some(12),
            ..Default::default()
        };
        assert!(matches!(
            generate_password(&bad_html),
            Err(GeneratorError::ConflictingHtmlConstraints { .. })
        ));
    }

    #[test]
    fn test_diceware_passphrase_en_and_fr_and_exact_entropy() {
        let en_cfg = PassphraseConfig {
            word_count: 6,
            language: WordlistLanguage::English,
            separator: "-".into(),
            capitalization: WordCapitalization::TitleCase,
            include_number: true,
        };
        let en = generate_passphrase(&en_cfg).expect("EN passphrase");
        let parts: Vec<&str> = en.value.split('-').collect();
        assert_eq!(parts.len(), 6);
        assert!(parts.iter().any(|w| w.chars().any(|c| c.is_ascii_digit())));
        // 6 * 9.0 bits + log2(60) = 54 + ~5.9069 = ~59.9069 bits
        let expected_bits = 54.0 + (60.0_f64).log2();
        assert!((en.entropy_bits - expected_bits).abs() < 1e-6);

        let fr_cfg = PassphraseConfig {
            word_count: 8,
            language: WordlistLanguage::French,
            separator: ".".into(),
            capitalization: WordCapitalization::RandomWordUppercase,
            include_number: false,
        };
        let fr = generate_passphrase(&fr_cfg).expect("FR passphrase");
        let fr_parts: Vec<&str> = fr.value.split('.').collect();
        assert_eq!(fr_parts.len(), 8);
        assert_eq!(
            fr_parts
                .iter()
                .filter(|w| w.chars().all(|c| c.is_ascii_uppercase()))
                .count(),
            1
        );
        // 8 * 9.0 + log2(8) = 72 + 3 = 75.0 bits
        assert!((fr.entropy_bits - 75.0).abs() < 1e-6);

        // Bounds check (3..=12)
        assert!(generate_passphrase(&PassphraseConfig {
            word_count: 2,
            ..Default::default()
        })
        .is_err());
        assert!(generate_passphrase(&PassphraseConfig {
            word_count: 13,
            ..Default::default()
        })
        .is_err());
    }
}
