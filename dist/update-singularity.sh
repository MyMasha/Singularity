#!/usr/bin/env bash
# Singularity Browser — Official Public Linux Self-Updater (SHA-256 Verified)
# Downloads directly from https://github.com/MyMasha/Singularity/releases (zero embedded tokens)
set -euo pipefail

REPO="MyMasha/Singularity"
INSTALL_DIR="$(cd "$(dirname "$0")" && pwd)"
TARGET_BIN="$INSTALL_DIR/singularity-linux-x86_64"
NEW_BIN="$INSTALL_DIR/singularity.new"
SUMS_FILE="$INSTALL_DIR/SHA256SUMS.new.txt"
TOKEN="${SINGULARITY_GITHUB_TOKEN:-}"
UA="Singularity-Updater/1.0"

echo "=========================================================="
echo "  SINGULARITY BROWSER — VERIFIED AUTO-UPDATER (SHA-256)"
echo "=========================================================="

api_fetch() {
  local tok="$1"
  local cfg
  cfg="header = \"User-Agent: ${UA}\""$'\n'"header = \"Accept: application/vnd.github+json\""$'\n'
  if [ -n "$tok" ]; then
    local clean_tok
    clean_tok="$(printf '%s' "$tok" | tr -d '\r\n"\\')"
    cfg+="header = \"Authorization: Bearer ${clean_tok}\""$'\n'
  fi
  printf '%s' "$cfg" | curl -fsS --proto '=https' --max-time 15 -K - "https://api.github.com/repos/${REPO}/releases/latest"
}

echo "[1/4] Checking latest public release at https://github.com/${REPO} ..."
REL_JSON=""
if [ -n "$TOKEN" ]; then
  REL_JSON="$(api_fetch "$TOKEN" 2>/dev/null || api_fetch "")"
else
  REL_JSON="$(api_fetch "")"
fi

TAG="$(printf '%s' "$REL_JSON" | python3 -c 'import sys, json; print(json.load(sys.stdin).get("tag_name", ""))')"
if ! printf '%s' "$TAG" | grep -Eq '^[A-Za-z0-9._-]+$'; then
  echo "[ERROR] Invalid GitHub release tag: $TAG" >&2
  exit 1
fi
echo "      Release found: $TAG"

read -r BIN_URL SUMS_URL <<EOF
$(printf '%s' "$REL_JSON" | python3 -c '
import sys, json
d = json.load(sys.stdin)
assets = {a["name"]: a.get("browser_download_url", "") for a in d.get("assets", [])}
print(assets.get("singularity-linux-x86_64", ""), assets.get("SHA256SUMS.txt", ""))
')
EOF

if [ -z "$BIN_URL" ] || [ -z "$SUMS_URL" ]; then
  echo "[ERROR] Required release assets (singularity-linux-x86_64 and SHA256SUMS.txt) are missing on release $TAG." >&2
  exit 1
fi

echo "[2/4] Downloading singularity-linux-x86_64 and SHA256SUMS.txt..."
curl -fsSL --proto '=https' --proto-redir '=https' -A "$UA" "$BIN_URL" -o "$NEW_BIN"
curl -fsSL --proto '=https' --proto-redir '=https' -A "$UA" "$SUMS_URL" -o "$SUMS_FILE"

echo "[3/4] Verifying SHA-256 cryptographic integrity..."
EXPECTED="$(awk '$2 == "singularity-linux-x86_64" || $2 == "*singularity-linux-x86_64" {print tolower($1); exit}' "$SUMS_FILE")"
rm -f "$SUMS_FILE"
if [ -z "$EXPECTED" ] || [ "${#EXPECTED}" -ne 64 ]; then
  rm -f "$NEW_BIN"
  echo "[ERROR] SHA-256 checksum for singularity-linux-x86_64 not found." >&2
  exit 1
fi

ACTUAL="$(sha256sum "$NEW_BIN" | awk '{print tolower($1)}')"
if [ "$ACTUAL" != "$EXPECTED" ]; then
  rm -f "$NEW_BIN"
  echo "[ERROR] SHA-256 mismatch! Expected=$EXPECTED Actual=$ACTUAL" >&2
  exit 1
fi
echo "      SHA-256 verified: $ACTUAL"

echo "[4/4] Installing updated binary..."
chmod +x "$NEW_BIN"
mv -f "$NEW_BIN" "$TARGET_BIN"
echo "[OK] Singularity $TAG installed and verified at $TARGET_BIN"
