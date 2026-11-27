#!/usr/bin/env bash
# Singularity Browser - Official Public Linux Self-Updater (Ed25519 + SHA-256 Verified)
# Downloads directly from https://github.com/MyMasha/Singularity/releases (zero embedded tokens)
set -euo pipefail
umask 077

REPO="MyMasha/Singularity"
INSTALL_DIR="$(cd "$(dirname "$0")" && pwd)"
TARGET_BIN="${INSTALL_DIR}/singularity-linux-x86_64"
TOKEN="${SINGULARITY_GITHUB_TOKEN:-}"
UA="Singularity-Updater/3.0.1"

# Optional pinned 64-hex-character Ed25519 release signing public key (can be configured via
# SINGULARITY_RELEASE_SIGNING_PUBKEY_HEX). Required by default in production.
DEFAULT_RELEASE_SIGNING_PUBKEY_HEX="3af87c325effee5f8f23e1ba7d9b8c5e7cebda70388718e87cf308237e70c155"
RELEASE_SIGNING_PUBKEY_HEX="${SINGULARITY_RELEASE_SIGNING_PUBKEY_HEX:-$DEFAULT_RELEASE_SIGNING_PUBKEY_HEX}"
ALLOW_UNSIGNED="${SINGULARITY_ALLOW_UNSIGNED:-0}"

echo "================================================================="
echo "  SINGULARITY BROWSER - VERIFIED AUTO-UPDATER (Ed25519 + SHA-256)"
echo "================================================================="

if [ -z "${RELEASE_SIGNING_PUBKEY_HEX}" ]; then
  if [ "${ALLOW_UNSIGNED}" != "1" ]; then
    echo "[ERROR] Ed25519 release signing public key is not configured (required by default in production)." >&2
    echo "        Set SINGULARITY_RELEASE_SIGNING_PUBKEY_HEX (64 hex chars) to verify SHA256SUMS.txt.sig" >&2
    echo "        (or set SINGULARITY_ALLOW_UNSIGNED=1 only for non-production testing)." >&2
    exit 1
  fi
  echo "[WARN] SINGULARITY_ALLOW_UNSIGNED=1 set: skipping Ed25519 signature check (non-production only)." >&2
elif [[ ! "${RELEASE_SIGNING_PUBKEY_HEX}" =~ ^[0-9a-fA-F]{64}$ ]]; then
  echo "[ERROR] Invalid SINGULARITY_RELEASE_SIGNING_PUBKEY_HEX (expected 64 hexadecimal characters)." >&2
  exit 1
fi

if [ -z "${HOME:-}" ] || [[ "${HOME}" != /* ]]; then
  echo "[ERROR] HOME environment variable is unset or not absolute; refusing insecure /tmp fallback." >&2
  exit 1
fi

CACHE_ROOT="${XDG_CACHE_HOME:-${HOME}/.cache}"
SINGULARITY_CACHE_DIR="${CACHE_ROOT}/singularity"
UPDATES_BASE="${SINGULARITY_CACHE_DIR}/updates"
for d in "${CACHE_ROOT}" "${SINGULARITY_CACHE_DIR}" "${UPDATES_BASE}"; do
  if [ -L "${d}" ]; then
    echo "[ERROR] Refusing symbolic link in private update path: ${d}" >&2
    exit 1
  fi
done
mkdir -p -- "${UPDATES_BASE}"
chmod 700 -- "${SINGULARITY_CACHE_DIR}" "${UPDATES_BASE}"
WORK_DIR="$(mktemp -d "${UPDATES_BASE}/update.XXXXXXXXXX")"
chmod 700 -- "${WORK_DIR}"
STAGE_DEST=""
trap 'rm -rf -- "${WORK_DIR}" "${STAGE_DEST}"' EXIT

NEW_BIN="${WORK_DIR}/singularity-linux-x86_64"
SUMS_FILE="${WORK_DIR}/SHA256SUMS.txt"
SIG_FILE="${WORK_DIR}/SHA256SUMS.txt.sig"

MAX_REDIRECTS=5

validate_github_https_url() {
  local url="$1"
  local label="$2"
  python3 - "$url" "$label" <<'PY'
import sys
from urllib.parse import urlparse

url, label = sys.argv[1], sys.argv[2]
allowed_hosts = {
    "github.com",
    "api.github.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
    "github-releases.githubusercontent.com",
}
if not url or any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in url):
    print(f"[ERROR] Refused malformed URL for {label}", file=sys.stderr)
    sys.exit(1)
parsed = urlparse(url)
if parsed.scheme != "https":
    print(f"[ERROR] Refused non-HTTPS URL for {label}: {url}", file=sys.stderr)
    sys.exit(1)
if parsed.port is not None and parsed.port != 443:
    print(f"[ERROR] Refused non-443 HTTPS port for {label}: {url}", file=sys.stderr)
    sys.exit(1)
if parsed.username is not None or parsed.password is not None:
    print(f"[ERROR] Refused URL containing credentials for {label}", file=sys.stderr)
    sys.exit(1)
host = (parsed.hostname or "").lower()
if host not in allowed_hosts:
    print(f"[ERROR] Refused untrusted download host '{host}' for {label}", file=sys.stderr)
    sys.exit(1)
PY
}

resolve_and_validate_redirect_url() {
  local base_url="$1"
  local location="$2"
  local label="$3"
  python3 - "$base_url" "$location" "$label" <<'PY'
import sys
from urllib.parse import urljoin, urlparse

base_url, location, label = sys.argv[1], sys.argv[2], sys.argv[3]
allowed_hosts = {
    "github.com",
    "api.github.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
    "github-releases.githubusercontent.com",
}
loc = location.strip()
if not loc or any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in loc):
    print(f"[ERROR] Refused malformed redirect Location for {label}", file=sys.stderr)
    sys.exit(1)
resolved = urljoin(base_url, loc)
parsed = urlparse(resolved)
if parsed.scheme != "https":
    print(f"[ERROR] Refused non-HTTPS redirect URL for {label}: {resolved}", file=sys.stderr)
    sys.exit(1)
if parsed.port is not None and parsed.port != 443:
    print(f"[ERROR] Refused non-443 HTTPS redirect port for {label}: {resolved}", file=sys.stderr)
    sys.exit(1)
if parsed.username is not None or parsed.password is not None:
    print(f"[ERROR] Refused redirect URL containing credentials for {label}", file=sys.stderr)
    sys.exit(1)
host = (parsed.hostname or "").lower()
if host not in allowed_hosts:
    print(f"[ERROR] Refused redirect to untrusted host '{host}' for {label}", file=sys.stderr)
    sys.exit(1)
print(resolved)
PY
}

is_same_https_origin() {
  local url_a="$1"
  local url_b="$2"
  python3 - "$url_a" "$url_b" <<'PY'
import sys
from urllib.parse import urlparse

a, b = urlparse(sys.argv[1]), urlparse(sys.argv[2])
same = (
    a.scheme == b.scheme
    and (a.hostname or "").lower() == (b.hostname or "").lower()
    and (a.port or 443) == (b.port or 443)
)
sys.exit(0 if same else 1)
PY
}

download_allowed_https() {
  local start_url="$1"
  local out_file="$2"
  local max_time="$3"
  local label="$4"
  local current_url="$start_url"
  local hop=0

  validate_github_https_url "${current_url}" "${label}"

  while [ "${hop}" -le "${MAX_REDIRECTS}" ]; do
    local hdr_file="${WORK_DIR}/.hdr.$$.${hop}"
    local http_code
    rm -f -- "${hdr_file}"
    http_code="$(curl -sS --proto '=https' --tlsv1.2 --max-time "${max_time}" -A "${UA}" -D "${hdr_file}" -o "${out_file}" -w '%{http_code}' -- "${current_url}")"

    case "${http_code}" in
      200|201|202|203|204|206)
        rm -f -- "${hdr_file}"
        return 0
        ;;
      301|302|303|307|308)
        local raw_loc
        raw_loc="$(awk 'BEGIN{IGNORECASE=1} /^location:[[:space:]]*/ {sub(/^[^:]*:[[:space:]]*/, ""); sub(/\r$/, ""); loc=$0} END{print loc}' "${hdr_file}")"
        rm -f -- "${hdr_file}"
        rm -f -- "${out_file}"
        if [ -z "${raw_loc}" ]; then
          echo "[ERROR] Redirect response (${http_code}) missing Location header for ${label}." >&2
          return 1
        fi
        if [ "${hop}" -ge "${MAX_REDIRECTS}" ]; then
          echo "[ERROR] Too many HTTP redirects (exceeded maximum of ${MAX_REDIRECTS} hops) for ${label}." >&2
          return 1
        fi
        current_url="$(resolve_and_validate_redirect_url "${current_url}" "${raw_loc}" "${label}")"
        hop=$((hop + 1))
        ;;
      *)
        rm -f -- "${hdr_file}" "${out_file}"
        echo "[ERROR] Download failed with HTTP status ${http_code} for ${label}." >&2
        return 1
        ;;
    esac
  done

  echo "[ERROR] Too many HTTP redirects (exceeded maximum of ${MAX_REDIRECTS} hops) for ${label}." >&2
  return 1
}

verify_ed25519_sig() {
  local sums_path="$1"
  local sig_b64_path="$2"
  local pubkey_hex="$3"

  # Try OpenSSL first if available with -rawin support, otherwise use built-in pure-Python RFC 8032 verifier
  if command -v openssl >/dev/null 2>&1; then
    local pub_pem="${WORK_DIR}/release_pubkey.pem"
    local sig_raw="${WORK_DIR}/SHA256SUMS.sig.bin"
    if python3 - "$pubkey_hex" "$pub_pem" "$sig_b64_path" "$sig_raw" <<'PY'
import base64, sys
pk_hex, pub_pem_path, sig_b64_path, sig_raw_path = sys.argv[1:5]
pk_bytes = bytes.fromhex(pk_hex)
if len(pk_bytes) != 32:
    sys.exit(1)
spki_der = bytes.fromhex("302a300506032b6570032100") + pk_bytes
b64 = base64.b64encode(spki_der).decode("ascii")
pem = "-----BEGIN PUBLIC KEY-----\n" + b64 + "\n-----END PUBLIC KEY-----\n"
with open(pub_pem_path, "w", encoding="ascii") as f:
    f.write(pem)
sig_raw = base64.b64decode(open(sig_b64_path, "r", encoding="ascii").read().strip(), validate=True)
if len(sig_raw) != 64:
    sys.exit(1)
with open(sig_raw_path, "wb") as f:
    f.write(sig_raw)
PY
    then
      if openssl pkeyutl -verify -pubin -inkey "${pub_pem}" -rawin -in "${sums_path}" -sigfile "${sig_raw}" >/dev/null 2>&1; then
        rm -f -- "${pub_pem}" "${sig_raw}"
        return 0
      fi
      rm -f -- "${pub_pem}" "${sig_raw}"
      # Double-check via pure-Python RFC 8032 verifier in case older OpenSSL lacks -rawin
    fi
  fi

  python3 - "$sums_path" "$sig_b64_path" "$pubkey_hex" <<'PY'
import base64, hashlib, hmac, sys

sums_path, sig_b64_path, pubkey_hex = sys.argv[1:4]
P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, P - 2, P)) % P
I = pow(2, (P - 1) // 4, P)

def xrecover(y):
    xx = (y * y - 1) * pow(D * y * y + 1, P - 2, P) % P
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P != 0:
        x = (x * I) % P
    if (x * x - xx) % P != 0:
        raise ValueError("point not on curve")
    if x % 2 != 0:
        x = P - x
    return x

BY = 4 * pow(5, P - 2, P) % P
BX = xrecover(BY)
B = (BX % P, BY % P, 1, (BX * BY) % P)

def point_add(p1, p2):
    x1, y1, z1, t1 = p1
    x2, y2, z2, t2 = p2
    a = ((y1 - x1) * (y2 - x2)) % P
    b = ((y1 + x1) * (y2 + x2)) % P
    c = (2 * D * t1 * t2) % P
    d = (2 * z1 * z2) % P
    e = (b - a) % P
    f = (d - c) % P
    g = (d + c) % P
    h = (b + a) % P
    return ((e * f) % P, (g * h) % P, (f * g) % P, (e * h) % P)

def scalarmult(pt, e):
    q = (0, 1, 1, 0)
    while e > 0:
        if e & 1:
            q = point_add(q, pt)
        pt = point_add(pt, pt)
        e >>= 1
    return q

def encodepoint(pt):
    x, y, z, _ = pt
    zi = pow(z, P - 2, P)
    ax = (x * zi) % P
    ay = (y * zi) % P
    enc = bytearray(ay.to_bytes(32, "little"))
    enc[31] |= (ax & 1) << 7
    return bytes(enc)

def decodepoint(b):
    if len(b) != 32:
        raise ValueError("bad length")
    y = int.from_bytes(b, "little") & ((1 << 255) - 1)
    if y >= P:
        raise ValueError("y >= P")
    sign = (b[31] >> 7) & 1
    x = xrecover(y)
    if x == 0 and sign == 1:
        raise ValueError("non-canonical zero")
    if (x & 1) != sign:
        x = P - x
    return (x, y, 1, (x * y) % P)

try:
    pub = bytes.fromhex(pubkey_hex.strip())
    msg = open(sums_path, "rb").read()
    sig = base64.b64decode(open(sig_b64_path, "r", encoding="ascii").read().strip(), validate=True)
    if len(pub) != 32 or len(sig) != 64:
        sys.exit(1)
    r_bytes, s_bytes = sig[:32], sig[32:]
    s = int.from_bytes(s_bytes, "little")
    if s >= L:
        sys.exit(1)
    a_pt = decodepoint(pub)
    r_pt = decodepoint(r_bytes)
    k = int.from_bytes(hashlib.sha512(r_bytes + pub + msg).digest(), "little") % L
    lhs = encodepoint(scalarmult(B, s))
    rhs = encodepoint(point_add(r_pt, scalarmult(a_pt, k)))
    if not hmac.compare_digest(lhs, rhs):
        sys.exit(1)
except Exception:
    sys.exit(1)
PY
}

api_fetch() {
  local tok="$1"
  local initial_url="https://api.github.com/repos/${REPO}/releases/latest"
  local current_url="${initial_url}"
  local hop=0
  validate_github_https_url "${current_url}" "GitHub Releases API"

  while [ "${hop}" -le "${MAX_REDIRECTS}" ]; do
    local hdr_file="${WORK_DIR}/.api_hdr.$$.${hop}"
    local body_file="${WORK_DIR}/.api_body.$$.${hop}"
    local cfg
    cfg="header = \"User-Agent: ${UA}\""$'\n'"header = \"Accept: application/vnd.github+json\""$'\n'
    if [ -n "$tok" ] && is_same_https_origin "${initial_url}" "${current_url}"; then
      local clean_tok
      clean_tok="$(printf '%s' "$tok" | tr -d '\r\n"\\')"
      cfg+="header = \"Authorization: Bearer ${clean_tok}\""$'\n'
    fi
    rm -f -- "${hdr_file}" "${body_file}"
    local http_code
    http_code="$(printf '%s' "$cfg" | curl -sS --proto '=https' --tlsv1.2 --max-time 15 -D "${hdr_file}" -o "${body_file}" -w '%{http_code}' -K - -- "${current_url}")"

    case "${http_code}" in
      200|201|202|203|204|206)
        cat -- "${body_file}"
        rm -f -- "${hdr_file}" "${body_file}"
        return 0
        ;;
      301|302|303|307|308)
        local raw_loc
        raw_loc="$(awk 'BEGIN{IGNORECASE=1} /^location:[[:space:]]*/ {sub(/^[^:]*:[[:space:]]*/, ""); sub(/\r$/, ""); loc=$0} END{print loc}' "${hdr_file}")"
        rm -f -- "${hdr_file}" "${body_file}"
        if [ -z "${raw_loc}" ]; then
          echo "[ERROR] Redirect response (${http_code}) missing Location header for GitHub Releases API." >&2
          return 1
        fi
        if [ "${hop}" -ge "${MAX_REDIRECTS}" ]; then
          echo "[ERROR] Too many HTTP redirects (exceeded maximum of ${MAX_REDIRECTS} hops) for GitHub Releases API." >&2
          return 1
        fi
        current_url="$(resolve_and_validate_redirect_url "${current_url}" "${raw_loc}" "GitHub Releases API")"
        hop=$((hop + 1))
        ;;
      *)
        rm -f -- "${hdr_file}" "${body_file}"
        return 1
        ;;
    esac
  done

  return 1
}

echo "[1/5] Checking latest public release at https://github.com/${REPO} ..."
REL_JSON=""
if [ -n "$TOKEN" ]; then
  REL_JSON="$(api_fetch "$TOKEN" 2>/dev/null || api_fetch "")"
else
  REL_JSON="$(api_fetch "")"
fi

TAG="$(printf '%s' "$REL_JSON" | python3 -c 'import sys, json; print(json.load(sys.stdin).get("tag_name", ""))')"
if [[ ! "$TAG" =~ ^v?[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$ ]]; then
  echo "[ERROR] Invalid GitHub release SemVer tag: $TAG" >&2
  exit 1
fi
echo "      Release found: $TAG"

# Strict SemVer 2.0 anti-downgrade check against installed binary (or SINGULARITY_CURRENT_VERSION)
CURRENT_VER="${SINGULARITY_CURRENT_VERSION:-}"
if [ -z "${CURRENT_VER}" ] && [ -x "${TARGET_BIN}" ] && [ ! -L "${TARGET_BIN}" ]; then
  CURRENT_VER="$("${TARGET_BIN}" --version 2>/dev/null || true)"
fi
if [ -n "${CURRENT_VER}" ]; then
  if ! python3 - "${CURRENT_VER}" "${TAG}" <<'PY'
import re, sys

cur_raw, new_raw = sys.argv[1], sys.argv[2]
strict_pat = re.compile(
    r"^v?([0-9]+)\.([0-9]+)\.([0-9]+)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)
search_pat = re.compile(
    r"v?([0-9]+)\.([0-9]+)\.([0-9]+)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
)

def parse_semver_match(m):
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)), m.group(4))

def cmp_prerelease(a, b):
    pa, pb = a.split("."), b.split(".")
    for i in range(max(len(pa), len(pb))):
        if i >= len(pa):
            return -1
        if i >= len(pb):
            return 1
        sa, sb = pa[i], pb[i]
        a_num, b_num = sa.isdigit(), sb.isdigit()
        if a_num and b_num:
            ia, ib = int(sa), int(sb)
            if ia != ib:
                return -1 if ia < ib else 1
        elif a_num and not b_num:
            return -1
        elif not a_num and b_num:
            return 1
        elif sa != sb:
            return -1 if sa < sb else 1
    return 0

def cmp_semver(a, b):
    if a[:3] != b[:3]:
        return -1 if a[:3] < b[:3] else 1
    if a[3] is None and b[3] is None:
        return 0
    if a[3] is None:
        return 1
    if b[3] is None:
        return -1
    return cmp_prerelease(a[3], b[3])

m_new = strict_pat.fullmatch(new_raw.strip())
if not m_new:
    print(f"[ERROR] Invalid release SemVer tag: {new_raw}", file=sys.stderr)
    sys.exit(1)
m_cur = search_pat.search(cur_raw)
if m_cur:
    v_new = parse_semver_match(m_new)
    v_cur = parse_semver_match(m_cur)
    if cmp_semver(v_new, v_cur) < 0:
        print(
            f"[ERROR] Refusing downgrade from installed version v{v_cur[0]}.{v_cur[1]}.{v_cur[2]} to older release {new_raw}.",
            file=sys.stderr,
        )
        sys.exit(1)
PY
  then
    exit 1
  fi
fi

IFS=$'\t' read -r BIN_URL SUMS_URL SIG_URL <<EOF
$(printf '%s' "$REL_JSON" | python3 -c '
import sys, json
d = json.load(sys.stdin)
assets = {a["name"]: a.get("browser_download_url", "") for a in d.get("assets", [])}
print("\t".join([
    assets.get("singularity-linux-x86_64", ""),
    assets.get("SHA256SUMS.txt", ""),
    assets.get("SHA256SUMS.txt.sig", ""),
]))
')
EOF

if [ -z "$BIN_URL" ] || [ -z "$SUMS_URL" ]; then
  echo "[ERROR] Required release assets (singularity-linux-x86_64 and SHA256SUMS.txt) are missing on release $TAG." >&2
  exit 1
fi
if [ -n "${RELEASE_SIGNING_PUBKEY_HEX}" ] && [ -z "$SIG_URL" ]; then
  echo "[ERROR] Required Ed25519 signature asset (SHA256SUMS.txt.sig) is missing on release $TAG. Update aborted." >&2
  exit 1
fi

validate_github_https_url "$BIN_URL" "singularity-linux-x86_64"
validate_github_https_url "$SUMS_URL" "SHA256SUMS.txt"
if [ -n "$SIG_URL" ]; then
  validate_github_https_url "$SIG_URL" "SHA256SUMS.txt.sig"
fi

echo "[2/5] Downloading release artifacts into private staging directory..."
download_allowed_https "$BIN_URL" "$NEW_BIN" 180 "singularity-linux-x86_64"
download_allowed_https "$SUMS_URL" "$SUMS_FILE" 30 "SHA256SUMS.txt"
if [ -n "${RELEASE_SIGNING_PUBKEY_HEX}" ]; then
  download_allowed_https "$SIG_URL" "$SIG_FILE" 30 "SHA256SUMS.txt.sig"
fi

if [ -n "${RELEASE_SIGNING_PUBKEY_HEX}" ]; then
  echo "[3/5] Verifying Ed25519 cryptographic signature (SHA256SUMS.txt.sig)..."
  if ! verify_ed25519_sig "$SUMS_FILE" "$SIG_FILE" "$RELEASE_SIGNING_PUBKEY_HEX"; then
    echo "[ERROR] Ed25519 cryptographic signature verification FAILED for SHA256SUMS.txt. Update aborted." >&2
    exit 1
  fi
  echo "      Ed25519 signature verified."
else
  echo "[3/5] Skipping Ed25519 check (SINGULARITY_ALLOW_UNSIGNED=1 explicitly set)."
fi

# Verify signed '# Singularity-Release:' version binding header (anti-rollback guard)
if ! python3 - "$SUMS_FILE" "$TAG" "${CURRENT_VER}" "$([ -n "${RELEASE_SIGNING_PUBKEY_HEX}" ] && echo 1 || echo 0)" <<'PY'
import re, sys

sums_path, tag_raw, cur_raw, signed_mode = sys.argv[1], sys.argv[2].strip(), sys.argv[3], sys.argv[4] == "1"
strict_pat = re.compile(
    r"^v?([0-9]+)\.([0-9]+)\.([0-9]+)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)
search_pat = re.compile(
    r"v?([0-9]+)\.([0-9]+)\.([0-9]+)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
)
header_pat = re.compile(r"^#\s*Singularity-Release\s*:\s*(.*)$", re.IGNORECASE)

def parse_strict(ver):
    m = strict_pat.fullmatch(ver.strip())
    if not m:
        return None
    norm = ver.strip()[1:] if ver.strip().startswith("v") else ver.strip()
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)), m.group(4), norm)

def cmp_prerelease(a, b):
    pa, pb = a.split("."), b.split(".")
    for i in range(max(len(pa), len(pb))):
        if i >= len(pa):
            return -1
        if i >= len(pb):
            return 1
        sa, sb = pa[i], pb[i]
        a_num, b_num = sa.isdigit(), sb.isdigit()
        if a_num and b_num:
            ia, ib = int(sa), int(sb)
            if ia != ib:
                return -1 if ia < ib else 1
        elif a_num and not b_num:
            return -1
        elif not a_num and b_num:
            return 1
        elif sa != sb:
            return -1 if sa < sb else 1
    return 0

def cmp_semver(a, b):
    if a[:3] != b[:3]:
        return -1 if a[:3] < b[:3] else 1
    if a[3] is None and b[3] is None:
        return 0
    if a[3] is None:
        return 1
    if b[3] is None:
        return -1
    return cmp_prerelease(a[3], b[3])

tag_v = parse_strict(tag_raw)
if not tag_v:
    print(f"[ERROR] Invalid release SemVer tag: {tag_raw}", file=sys.stderr)
    sys.exit(1)

found = None
with open(sums_path, "r", encoding="utf-8", errors="replace") as f:
    for line in f:
        m = header_pat.match(line.strip())
        if m:
            if found is not None:
                print("[ERROR] Duplicate '# Singularity-Release:' header in SHA256SUMS.txt. Update aborted.", file=sys.stderr)
                sys.exit(1)
            raw_val = m.group(1).strip()
            parsed = parse_strict(raw_val)
            if not parsed:
                print(f"[ERROR] Malformed '# Singularity-Release:' SemVer header '{raw_val}' in SHA256SUMS.txt. Update aborted.", file=sys.stderr)
                sys.exit(1)
            found = (raw_val, parsed)

cutoff_v = parse_strict("3.0.3")
if found is not None:
    signed_raw, signed_v = found
    if cmp_semver(signed_v, tag_v) != 0 or signed_v[4] != tag_v[4]:
        print(
            f"[ERROR] Signed SHA256SUMS.txt release version '{signed_raw}' does not match advertised GitHub release tag '{tag_raw}' (possible rollback attack). Update aborted.",
            file=sys.stderr,
        )
        sys.exit(1)
    if cur_raw:
        m_cur = search_pat.search(cur_raw)
        if m_cur:
            cur_v = (int(m_cur.group(1)), int(m_cur.group(2)), int(m_cur.group(3)), m_cur.group(4), "")
            if cmp_semver(signed_v, cur_v) < 0:
                print(
                    f"[ERROR] Refusing downgrade from installed version v{cur_v[0]}.{cur_v[1]}.{cur_v[2]} to signed release {signed_raw}.",
                    file=sys.stderr,
                )
                sys.exit(1)
    print(f"      Signed release version verified: {signed_raw}")
elif signed_mode and cmp_semver(tag_v, cutoff_v) > 0:
    print(
        f"[ERROR] Signed SHA256SUMS.txt is missing mandatory '# Singularity-Release:' version header for release {tag_raw} (possible rollback attack). Update aborted.",
        file=sys.stderr,
    )
    sys.exit(1)
PY
then
  exit 1
fi

echo "[4/5] Verifying SHA-256 cryptographic integrity..."
EXPECTED="$(awk '!/^[[:space:]]*#/ && ($2 == "singularity-linux-x86_64" || $2 == "*singularity-linux-x86_64") {print tolower($1); exit}' "$SUMS_FILE")"
if [ -z "$EXPECTED" ] || [[ ! "$EXPECTED" =~ ^[0-9a-f]{64}$ ]]; then
  echo "[ERROR] SHA-256 checksum for singularity-linux-x86_64 not found in SHA256SUMS.txt." >&2
  exit 1
fi

ACTUAL="$(sha256sum -- "$NEW_BIN" | awk '{print tolower($1)}')"
if [ "$ACTUAL" != "$EXPECTED" ]; then
  echo "[ERROR] SHA-256 mismatch! Expected=$EXPECTED Actual=$ACTUAL" >&2
  exit 1
fi
echo "      SHA-256 verified: $ACTUAL"

echo "[5/5] Installing verified binary..."
if [ -L "$TARGET_BIN" ]; then
  echo "[ERROR] Refusing to overwrite symbolic link at $TARGET_BIN" >&2
  exit 1
fi
STAGE_DEST="$(mktemp "${INSTALL_DIR}/.singularity.new.XXXXXXXXXX")"
cp -- "$NEW_BIN" "$STAGE_DEST"
chmod 0755 -- "$STAGE_DEST"
mv -f -- "$STAGE_DEST" "$TARGET_BIN"
STAGE_DEST=""
echo "[OK] Singularity $TAG installed and verified at $TARGET_BIN"
