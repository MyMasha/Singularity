#!/usr/bin/env bash
# Package Singularity Browser for Debian, Ubuntu, Linux Mint (.deb) and Bazzite / Fedora Atomic (.rpm).
# Usage: scripts/package-linux.sh <binary_path> <version> <output_dir>
set -euo pipefail

BIN_PATH="${1:?Usage: $0 <binary_path> <version> <output_dir>}"
RAW_VER="${2:?Missing version (e.g. 1.0.0)}"
OUT_DIR="${3:?Missing output directory}"

VERSION="${RAW_VER#v}"
if [[ ! "${VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z]+)?$ ]]; then
  echo "[ERROR] Invalid version '${RAW_VER}' (expected X.Y.Z or X.Y.Z-prerelease)." >&2
  exit 1
fi
RPM_VERSION="${VERSION//-/\~}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ICON_SRC="${REPO_ROOT}/assets/logo.png"

if [ ! -f "${BIN_PATH}" ]; then
  echo "[ERROR] Binary not found: ${BIN_PATH}" >&2
  exit 1
fi
if [ ! -f "${ICON_SRC}" ]; then
  echo "[ERROR] Icon not found: ${ICON_SRC}" >&2
  exit 1
fi

mkdir -p -- "${OUT_DIR}"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf -- "${WORK_DIR}"' EXIT

DESKTOP_ENTRY="[Desktop Entry]
Type=Application
Name=Singularity Browser
GenericName=Web Browser
Comment=Privacy-first desktop browser written in Rust
Exec=/usr/bin/singularity %U
Icon=singularity
Terminal=false
Categories=Network;WebBrowser;
MimeType=text/html;text/xml;application/xhtml+xml;x-scheme-handler/http;x-scheme-handler/https;
StartupNotify=true
"

build_deb() {
  local distro_label="$1"
  local out_file="$2"
  local pkg_root="${WORK_DIR}/deb-${distro_label}"

  mkdir -p \
    "${pkg_root}/DEBIAN" \
    "${pkg_root}/usr/bin" \
    "${pkg_root}/usr/share/applications" \
    "${pkg_root}/usr/share/icons/hicolor/512x512/apps"

  install -m 0755 "${BIN_PATH}" "${pkg_root}/usr/bin/singularity"
  printf '%s' "${DESKTOP_ENTRY}" > "${pkg_root}/usr/share/applications/singularity.desktop"
  chmod 0644 "${pkg_root}/usr/share/applications/singularity.desktop"
  install -m 0644 "${ICON_SRC}" "${pkg_root}/usr/share/icons/hicolor/512x512/apps/singularity.png"

  local installed_kb
  installed_kb="$(du -sk "${pkg_root}/usr" | awk '{print $1}')"

  cat > "${pkg_root}/DEBIAN/control" <<EOF
Package: singularity-browser
Version: ${VERSION}
Section: web
Priority: optional
Architecture: amd64
Installed-Size: ${installed_kb}
Maintainer: Singularity Browser Team <https://github.com/MyMasha/Singularity>
Homepage: https://github.com/MyMasha/Singularity
Description: Singularity Browser (${distro_label} build)
 Privacy-first desktop browser written in Rust with encrypted local storage,
 real-time 3D WebGL2 themes, crash-proof session recovery, and native Chrome
 extension support.
EOF

  find "${pkg_root}" -type d -exec chmod 0755 {} +
  chmod 0644 "${pkg_root}/DEBIAN/control"

  dpkg-deb --root-owner-group --build "${pkg_root}" "${out_file}"
  echo "[OK] Built ${out_file}"
}

build_rpm() {
  local out_file="$1"
  local rpm_top="${WORK_DIR}/rpmbuild"
  mkdir -p "${rpm_top}"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

  cp -- "${BIN_PATH}" "${rpm_top}/SOURCES/singularity"
  cp -- "${ICON_SRC}" "${rpm_top}/SOURCES/singularity.png"
  printf '%s' "${DESKTOP_ENTRY}" > "${rpm_top}/SOURCES/singularity.desktop"

  cat > "${rpm_top}/SPECS/singularity-browser.spec" <<EOF
%global debug_package %{nil}
%global _build_id_links none

Name:           singularity-browser
Version:        ${RPM_VERSION}
Release:        1
Summary:        Privacy-first desktop browser written in Rust (Bazzite / Fedora Atomic)
License:        MPL-2.0
URL:            https://github.com/MyMasha/Singularity
BuildArch:      x86_64
AutoReqProv:    no

%description
Privacy-first desktop browser written in Rust with encrypted local storage,
real-time 3D WebGL2 themes, crash-proof session recovery, and native Chrome
extension support. Built as a self-contained static x86_64 package for Bazzite
and Fedora Atomic desktops.

%install
mkdir -p %{buildroot}/usr/bin
mkdir -p %{buildroot}/usr/share/applications
mkdir -p %{buildroot}/usr/share/icons/hicolor/512x512/apps
install -m 0755 %{_sourcedir}/singularity %{buildroot}/usr/bin/singularity
install -m 0644 %{_sourcedir}/singularity.desktop %{buildroot}/usr/share/applications/singularity.desktop
install -m 0644 %{_sourcedir}/singularity.png %{buildroot}/usr/share/icons/hicolor/512x512/apps/singularity.png

%files
/usr/bin/singularity
/usr/share/applications/singularity.desktop
/usr/share/icons/hicolor/512x512/apps/singularity.png
EOF

  mkdir -p "${rpm_top}/tmp"
  rpmbuild --quiet \
    --define "_topdir ${rpm_top}" \
    --define "_tmppath ${rpm_top}/tmp" \
    -bb "${rpm_top}/SPECS/singularity-browser.spec"
  local built_rpm
  built_rpm="$(find "${rpm_top}/RPMS" -name '*.rpm' | head -n 1)"
  if [ -z "${built_rpm}" ] || [ ! -f "${built_rpm}" ]; then
    echo "[ERROR] rpmbuild did not produce an .rpm package" >&2
    exit 1
  fi
  cp "${built_rpm}" "${out_file}"
  echo "[OK] Built ${out_file}"
}

build_deb "Debian" "${OUT_DIR}/Singularity-Debian.deb"
build_deb "Ubuntu" "${OUT_DIR}/Singularity-Ubuntu.deb"
build_deb "Mint"   "${OUT_DIR}/Singularity-Mint.deb"
build_rpm          "${OUT_DIR}/Singularity-Bazzite.rpm"
