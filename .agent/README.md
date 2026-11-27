# Singularity Browser — Contexte Agent & Reprise Locale (`.agent/`)

> **Version actuelle :** `v3.0.3` (commit `fca7960` sur `main`)
> **Stack :** 100 % Rust (workspace 11 crates, ~135 000 lignes) · Pure Chromium CEF 150 (OBS 7871, codecs H.264/AAC) · Hybrid DRM Windows WebView2 · UI embarquée OLED cosmique (Vanilla HTML/CSS/JS + WebGL2)
> **Tests :** `283 / 283` tests Rust validés (`cargo test --workspace --locked`) sur Linux & Windows MSVC + smoke tests CEF Windows end-to-end.

---

## Index du dossier `.agent/`

| Fichier | Contenu |
| :--- | :--- |
| [`ARCHITECTURE_TREE.md`](./ARCHITECTURE_TREE.md) | Arborescence complète du projet, rôle de chaque crate/fichier, métriques LOC et flux IPC/rendu. |
| [`ART_DIRECTION.md`](./ART_DIRECTION.md) | Direction artistique OLED cosmique, 6 thèmes 3D, architecture deux barres (`80px`), motion design 120–200Hz et règles visuelles. |
| [`CODE_DIRECTION.md`](./CODE_DIRECTION.md) | Conventions Rust/JS/CSS, invariants de sécurité, règles CEF/Win32 et procédure stricte de release. |
| [`ROADMAP_TODO.md`](./ROADMAP_TODO.md) | Ce qu'il reste à faire, priorisé de `P0` à `P3` (UX, ponts CEF natifs, Linux GUI, refactoring). |
| [`KNOWN_ISSUES.md`](./KNOWN_ISSUES.md) | Problèmes connus, limites actuelles, pièges techniques CEF/Win32/CSS et régressions à éviter. |

---

## Démarrage rapide en local (Copie / Reprise du projet)

### 1. Cloner et vérifier l'environnement
```bash
git clone https://github.com/MyMasha/Singularity.git
cd Singularity
git status
```

### 2. Lancer la suite complète de tests (Linux ou Windows)
```bash
cargo test --workspace --locked
```

### 3. Vérifier la syntaxe JS/CSS embarquée dans `ui_app.rs`
```bash
python3 -c '
import re, subprocess, tempfile
src = open("crates/singularity-ui/src/ui_app.rs", encoding="utf-8").read()
js = re.search(r"<script>(.*)</script>", src, re.S).group(1)
f = tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8")
f.write(js); f.close()
subprocess.run(["node", "--check", f.name], check=True)
css = re.sub(r"/\*.*?\*/", "", re.search(r"<style>(.*)</style>", src, re.S).group(1), flags=re.S)
assert css.count("{") == css.count("}"), "CSS braces unbalanced"
print("JS & CSS OK")
'
```

### 4. Compiler sous Windows (Pure Chromium CEF 150)
```powershell
# 1. Préparer le SDK CEF 150 (OBS 7871 avec codecs propriétaires H.264/AAC)
python scripts/prepare-cef-win64.py

# 2. Compiler le navigateur + l'installeur SFX
cargo build --release --locked --bin singularity --bin singularity-installer

# 3. Empaqueter le bundle CEF Windows
python scripts/package-windows-cef.py
```

### 5. Compiler sous Linux (binaire statique musl)
```bash
rustup target add x86_64-unknown-linux-musl
cargo build --release --locked --target x86_64-unknown-linux-musl --bin singularity
```

---

## Règles projet importantes (Préférences du mainteneur)

1. **Release systématique** : à chaque grosse modification fonctionnelle ou visuelle, incrémenter la version (`v3.0.x`), mettre à jour `Cargo.lock` + RC Windows + UI + tests, pousser le tag sur GitHub et suivre le pipeline `.github/workflows/release.yml` jusqu'à publication complète.
2. **Identité visuelle conservée** : navigateur classique à **deux barres** (`38px` onglets pleine largeur + `42px` navigation/omnibar/outils) mais en gardant impérativement le style OLED cosmique sombre, les 6 thèmes 3D, les feux tricolores Apple et les animations fluides à ressort.
3. **Zéro régression de tests** : ne jamais supprimer ou affaiblir les assertions d'invariants dans `crates/singularity-ui/src/lib.rs` (sécurité sandbox, drag frameless, onglets stables, motion, deux barres).
