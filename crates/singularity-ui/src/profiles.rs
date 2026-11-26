//! Isolated Multi-Profiles, Container Tabs, Workspaces & Named Sessions,
//! Hardened Per-Site Permissions, and Advanced Customization (WCAG 2.1 Themes,
//! Pure-Rust NOAA Solar Scheduling, Site Boosts, Web Panels, OLED Dark Reader, Zoom).
//!
//! 100% pure Rust, atomic JSON persistence, zero external network dependencies.

use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

/// Maximum retained entries in [`ClosedSessionStack`].
pub const MAX_CLOSED_SESSION_ENTRIES: usize = 100;

/// Errors returned by profile, container, workspace, permission, and customization stores.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ProfileError {
    #[error("Invalid identifier '{0}': must contain only ASCII alphanumeric, '-' or '_'")]
    InvalidIdentifier(String),
    #[error("Profile '{0}' not found")]
    ProfileNotFound(String),
    #[error("Cannot delete the last remaining non-guest profile")]
    CannotDeleteLastProfile,
    #[error("Container '{0}' not found")]
    ContainerNotFound(String),
    #[error("Cannot delete built-in container '{0}'")]
    CannotDeleteBuiltinContainer(String),
    #[error("Workspace '{0}' not found")]
    WorkspaceNotFound(String),
    #[error("Session snapshot '{0}' not found")]
    SnapshotNotFound(String),
    #[error("Invalid hex color: '{0}'")]
    InvalidHexColor(String),
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("I/O error: {0}")]
    Io(String),
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn random_hex_id(prefix: &str, bytes_len: usize) -> String {
    let mut buf = vec![0u8; bytes_len.clamp(4, 32)];
    OsRng.fill_bytes(&mut buf);
    format!("{}-{}", prefix, hex::encode(buf))
}

/// Validates safe filesystem identifiers (no path traversal, no separators, no control chars).
pub fn validate_safe_id(id: &str) -> Result<(), ProfileError> {
    if id.is_empty()
        || id.len() > 64
        || id.starts_with('.')
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(ProfileError::InvalidIdentifier(id.to_string()));
    }
    Ok(())
}

/// Matches a domain/host pattern (`example.com`, `*.example.com`, `*bank*`) against a hostname.
pub fn domain_pattern_matches(pattern: &str, host: &str) -> bool {
    let p = pattern.trim().trim_start_matches('.').to_ascii_lowercase();
    let h = host
        .trim()
        .split(':')
        .next()
        .unwrap_or("")
        .trim_end_matches('.')
        .to_ascii_lowercase();

    if p.is_empty() || h.is_empty() {
        return false;
    }
    if p == "*" {
        return true;
    }
    if let Some(base) = p.strip_prefix("*.") {
        return h == base || h.ends_with(&format!(".{}", base));
    }
    if p.contains('*') {
        return wildcard_glob_match(&p, &h);
    }
    h == p || h.ends_with(&format!(".{}", p))
}

fn wildcard_glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let mut star_pi: Option<usize> = None;
    let mut star_ti = 0usize;

    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star_pi = Some(pi);
            pi += 1;
            star_ti = ti;
        } else if let Some(sp) = star_pi {
            pi = sp + 1;
            star_ti += 1;
            ti = star_ti;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

fn atomic_write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), ProfileError> {
    let json = serde_json::to_string_pretty(value)
        .map_err(|e| ProfileError::Serialization(e.to_string()))?;
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|e| ProfileError::Io(e.to_string()))?;
        }
    }
    let tmp_name = format!(
        ".{}.tmp.{}",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("store"),
        std::process::id()
    );
    let tmp = path.with_file_name(tmp_name);
    {
        let mut f = fs::File::create(&tmp).map_err(|e| ProfileError::Io(e.to_string()))?;
        f.write_all(json.as_bytes())
            .map_err(|e| ProfileError::Io(e.to_string()))?;
        f.sync_all().map_err(|e| ProfileError::Io(e.to_string()))?;
    }
    fs::rename(&tmp, path).map_err(|e| ProfileError::Io(e.to_string()))
}

fn sanitize_desktop_field(input: &str) -> String {
    input
        .chars()
        .filter(|&c| c != '\r' && c != '\n' && !c.is_control())
        .collect()
}

// ============================================================================
// 1. Multi-Profiles Isolés (ProfileRegistry)
// ============================================================================

/// Descriptor of an isolated user profile stored under `<roaming_root>/profiles/<id>/`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileDescriptor {
    pub id: String,
    pub name: String,
    pub avatar: String,
    pub accent_hex: String,
    pub theme_id: String,
    pub is_guest: bool,
    pub created_unix: u64,
    pub last_used_unix: u64,
}

/// Automatic domain-to-profile routing rule (e.g. `*.corp.example` -> Work profile).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileRoutingRule {
    pub domain_pattern: String,
    pub target_profile_id: String,
    pub auto_switch: bool,
}

/// Manages isolated browser profiles, Guest Mode, domain routing, and OS shortcuts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileRegistry {
    pub profiles: Vec<ProfileDescriptor>,
    pub active_profile_id: String,
    pub show_picker_on_startup: bool,
    #[serde(default)]
    pub routing_rules: Vec<ProfileRoutingRule>,
}

impl Default for ProfileRegistry {
    fn default() -> Self {
        Self::new_default()
    }
}

impl ProfileRegistry {
    pub fn new_default() -> Self {
        let now = unix_now();
        Self {
            profiles: vec![ProfileDescriptor {
                id: "default".into(),
                name: "Default".into(),
                avatar: "singularity".into(),
                accent_hex: "#F0B254".into(),
                theme_id: "singularity".into(),
                is_guest: false,
                created_unix: now,
                last_used_unix: now,
            }],
            active_profile_id: "default".into(),
            show_picker_on_startup: false,
            routing_rules: Vec::new(),
        }
    }

    /// Resolves strictly isolated storage path `<roaming_root>/profiles/<id>/`.
    pub fn profile_data_dir(roaming_root: &Path, profile_id: &str) -> Result<PathBuf, ProfileError> {
        validate_safe_id(profile_id)?;
        Ok(roaming_root.join("profiles").join(profile_id))
    }

    pub fn get(&self, profile_id: &str) -> Option<&ProfileDescriptor> {
        self.profiles.iter().find(|p| p.id == profile_id)
    }

    pub fn create_profile(
        &mut self,
        id: Option<&str>,
        name: &str,
        avatar: &str,
        accent_hex: &str,
        theme_id: &str,
    ) -> Result<ProfileDescriptor, ProfileError> {
        let final_id = match id {
            Some(explicit) => {
                validate_safe_id(explicit)?;
                explicit.to_string()
            }
            None => random_hex_id("prof", 6),
        };
        if self.profiles.iter().any(|p| p.id == final_id) {
            return Err(ProfileError::InvalidIdentifier(format!(
                "duplicate profile id '{}'",
                final_id
            )));
        }
        let now = unix_now();
        let desc = ProfileDescriptor {
            id: final_id,
            name: name.trim().to_string(),
            avatar: avatar.to_string(),
            accent_hex: accent_hex.to_string(),
            theme_id: theme_id.to_string(),
            is_guest: false,
            created_unix: now,
            last_used_unix: now,
        };
        self.profiles.push(desc.clone());
        Ok(desc)
    }

    /// Creates an ephemeral Guest Mode profile intended to be wiped completely on exit.
    pub fn create_guest_profile(&mut self) -> ProfileDescriptor {
        let now = unix_now();
        let guest = ProfileDescriptor {
            id: random_hex_id("guest", 8),
            name: "Guest".into(),
            avatar: "guest".into(),
            accent_hex: "#5C5E65".into(),
            theme_id: "singularity".into(),
            is_guest: true,
            created_unix: now,
            last_used_unix: now,
        };
        self.profiles.push(guest.clone());
        guest
    }

    /// Removes an ephemeral guest profile from the registry and deletes its isolated directory.
    pub fn cleanup_guest_profile(
        &mut self,
        roaming_root: &Path,
        guest_id: &str,
    ) -> Result<bool, ProfileError> {
        let is_guest = self
            .get(guest_id)
            .map(|p| p.is_guest)
            .unwrap_or(false);
        if !is_guest {
            return Ok(false);
        }
        let dir = Self::profile_data_dir(roaming_root, guest_id)?;
        if dir.exists() {
            fs::remove_dir_all(&dir).map_err(|e| ProfileError::Io(e.to_string()))?;
        }
        self.profiles.retain(|p| p.id != guest_id);
        if self.active_profile_id == guest_id {
            if let Some(first) = self.profiles.iter().find(|p| !p.is_guest) {
                self.active_profile_id = first.id.clone();
            }
        }
        Ok(true)
    }

    pub fn delete_profile(&mut self, profile_id: &str) -> Result<ProfileDescriptor, ProfileError> {
        let idx = self
            .profiles
            .iter()
            .position(|p| p.id == profile_id)
            .ok_or_else(|| ProfileError::ProfileNotFound(profile_id.to_string()))?;

        let non_guest_count = self.profiles.iter().filter(|p| !p.is_guest).count();
        if !self.profiles[idx].is_guest && non_guest_count <= 1 {
            return Err(ProfileError::CannotDeleteLastProfile);
        }

        let removed = self.profiles.remove(idx);
        self.routing_rules
            .retain(|r| r.target_profile_id != profile_id);
        if self.active_profile_id == profile_id {
            if let Some(next) = self.profiles.iter().find(|p| !p.is_guest) {
                self.active_profile_id = next.id.clone();
            }
        }
        Ok(removed)
    }

    pub fn switch_profile(&mut self, profile_id: &str) -> Result<&ProfileDescriptor, ProfileError> {
        let now = unix_now();
        let idx = self
            .profiles
            .iter()
            .position(|p| p.id == profile_id)
            .ok_or_else(|| ProfileError::ProfileNotFound(profile_id.to_string()))?;
        self.profiles[idx].last_used_unix = now;
        self.active_profile_id = profile_id.to_string();
        Ok(&self.profiles[idx])
    }

    /// Resolves the most specific profile routing rule matching `host`.
    pub fn resolve_route_for_host(&self, host: &str) -> Option<&ProfileRoutingRule> {
        self.routing_rules
            .iter()
            .filter(|r| {
                domain_pattern_matches(&r.domain_pattern, host)
                    && self.get(&r.target_profile_id).is_some()
            })
            .max_by_key(|r| r.domain_pattern.len())
    }

    /// Generates a Linux XDG `.desktop` launcher entry dedicated to a specific profile.
    pub fn generate_linux_desktop_entry(
        &self,
        profile_id: &str,
        executable_path: &str,
    ) -> Result<String, ProfileError> {
        validate_safe_id(profile_id)?;
        let prof = self
            .get(profile_id)
            .ok_or_else(|| ProfileError::ProfileNotFound(profile_id.to_string()))?;
        let safe_name = sanitize_desktop_field(&prof.name);
        let safe_exe = sanitize_desktop_field(executable_path);
        Ok(format!(
            "[Desktop Entry]\n\
             Version=1.0\n\
             Type=Application\n\
             Name=Singularity ({name})\n\
             Comment=Singularity Browser isolated profile: {name}\n\
             Exec=\"{exe}\" --profile={id} %U\n\
             Icon=singularity\n\
             Terminal=false\n\
             Categories=Network;WebBrowser;\n\
             StartupWMClass=singularity-profile-{id}\n",
            name = safe_name,
            exe = safe_exe,
            id = prof.id
        ))
    }

    /// Generates a profile launcher script (`.cmd` for Windows or POSIX `.sh` for Linux/macOS).
    pub fn generate_shortcut_script(
        &self,
        profile_id: &str,
        executable_path: &str,
        windows_cmd: bool,
    ) -> Result<String, ProfileError> {
        validate_safe_id(profile_id)?;
        let prof = self
            .get(profile_id)
            .ok_or_else(|| ProfileError::ProfileNotFound(profile_id.to_string()))?;
        let safe_exe = sanitize_desktop_field(executable_path);
        if windows_cmd {
            Ok(format!(
                "@echo off\r\nstart \"Singularity - {name}\" \"{exe}\" --profile={id} %*\r\n",
                name = sanitize_desktop_field(&prof.name).replace('"', ""),
                exe = safe_exe.replace('"', ""),
                id = prof.id
            ))
        } else {
            Ok(format!(
                "#!/usr/bin/env sh\nexec \"{exe}\" --profile={id} \"$@\"\n",
                exe = safe_exe.replace('"', "\\\""),
                id = prof.id
            ))
        }
    }

    pub fn save_to_path(&self, path: &Path) -> Result<(), ProfileError> {
        // Persist non-guest profiles only so ephemeral guest profiles never survive restarts
        let mut to_save = self.clone();
        to_save.profiles.retain(|p| !p.is_guest);
        if !to_save
            .profiles
            .iter()
            .any(|p| p.id == to_save.active_profile_id)
        {
            if let Some(first) = to_save.profiles.first() {
                to_save.active_profile_id = first.id.clone();
            }
        }
        atomic_write_json(path, &to_save)
    }

    pub fn load_from_path(path: &Path) -> Result<Self, ProfileError> {
        let raw = fs::read_to_string(path).map_err(|e| ProfileError::Io(e.to_string()))?;
        serde_json::from_str(&raw).map_err(|e| ProfileError::Serialization(e.to_string()))
    }
}

// ============================================================================
// 2. Onglets Conteneurs (ContainerRegistry)
// ============================================================================

/// Multi-Account Container isolation descriptor (separate cookie jar, storage, optional relay/proxy).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainerTabProfile {
    pub id: String,
    pub name: String,
    pub color_hex: String,
    pub icon: String,
    pub ephemeral: bool,
    pub proxy_profile_id: Option<String>,
    pub mullvad_relay: Option<String>,
}

/// Always-open-in-container domain assignment rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainerDomainRule {
    pub domain_pattern: String,
    pub container_id: String,
    pub ask_before_switch: bool,
}

/// Built-in and custom container tab registry with host-based auto-assignment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainerRegistry {
    pub containers: Vec<ContainerTabProfile>,
    #[serde(default)]
    pub domain_rules: Vec<ContainerDomainRule>,
}

impl Default for ContainerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ContainerRegistry {
    pub const BUILTIN_IDS: &'static [&'static str] = &[
        "personal",
        "work",
        "banking",
        "shopping",
        "ephemeral",
    ];

    /// Initializes the 5 built-in containers (`Personal`, `Work`, `Banking`, `Shopping`, `Ephemeral`).
    pub fn new() -> Self {
        Self {
            containers: vec![
                ContainerTabProfile {
                    id: "personal".into(),
                    name: "Personal".into(),
                    color_hex: "#38D9F5".into(),
                    icon: "user".into(),
                    ephemeral: false,
                    proxy_profile_id: None,
                    mullvad_relay: None,
                },
                ContainerTabProfile {
                    id: "work".into(),
                    name: "Work".into(),
                    color_hex: "#F0B254".into(),
                    icon: "briefcase".into(),
                    ephemeral: false,
                    proxy_profile_id: None,
                    mullvad_relay: None,
                },
                ContainerTabProfile {
                    id: "banking".into(),
                    name: "Banking".into(),
                    color_hex: "#22C55E".into(),
                    icon: "shield-lock".into(),
                    ephemeral: false,
                    proxy_profile_id: None,
                    mullvad_relay: Some("ch".into()),
                },
                ContainerTabProfile {
                    id: "shopping".into(),
                    name: "Shopping".into(),
                    color_hex: "#EC4899".into(),
                    icon: "shopping-bag".into(),
                    ephemeral: false,
                    proxy_profile_id: None,
                    mullvad_relay: None,
                },
                ContainerTabProfile {
                    id: "ephemeral".into(),
                    name: "Ephemeral".into(),
                    color_hex: "#B975FF".into(),
                    icon: "flame".into(),
                    ephemeral: true,
                    proxy_profile_id: None,
                    mullvad_relay: None,
                },
            ],
            domain_rules: Vec::new(),
        }
    }

    pub fn get(&self, id: &str) -> Option<&ContainerTabProfile> {
        self.containers.iter().find(|c| c.id == id)
    }

    pub fn add_custom(&mut self, container: ContainerTabProfile) -> Result<(), ProfileError> {
        validate_safe_id(&container.id)?;
        if self.containers.iter().any(|c| c.id == container.id) {
            return Err(ProfileError::InvalidIdentifier(format!(
                "container '{}' already exists",
                container.id
            )));
        }
        self.containers.push(container);
        Ok(())
    }

    pub fn remove_custom(&mut self, id: &str) -> Result<ContainerTabProfile, ProfileError> {
        if Self::BUILTIN_IDS.contains(&id) {
            return Err(ProfileError::CannotDeleteBuiltinContainer(id.to_string()));
        }
        let idx = self
            .containers
            .iter()
            .position(|c| c.id == id)
            .ok_or_else(|| ProfileError::ContainerNotFound(id.to_string()))?;
        let removed = self.containers.remove(idx);
        self.domain_rules.retain(|r| r.container_id != id);
        Ok(removed)
    }

    pub fn add_domain_rule(&mut self, rule: ContainerDomainRule) -> Result<(), ProfileError> {
        if self.get(&rule.container_id).is_none() {
            return Err(ProfileError::ContainerNotFound(rule.container_id));
        }
        self.domain_rules
            .retain(|r| !r.domain_pattern.eq_ignore_ascii_case(&rule.domain_pattern));
        self.domain_rules.push(rule);
        Ok(())
    }

    /// Resolves the assigned container and `ask_before_switch` preference for `host`,
    /// preferring the longest/most specific matching pattern.
    pub fn resolve_container_for_host(&self, host: &str) -> Option<(&ContainerTabProfile, bool)> {
        let rule = self
            .domain_rules
            .iter()
            .filter(|r| domain_pattern_matches(&r.domain_pattern, host))
            .max_by_key(|r| r.domain_pattern.len())?;
        let container = self.get(&rule.container_id)?;
        Some((container, rule.ask_before_switch))
    }

    /// Computes a deterministic storage/cookie partition key isolating a container inside a profile.
    pub fn storage_partition_key(profile_id: &str, container_id: &str) -> Result<String, ProfileError> {
        validate_safe_id(profile_id)?;
        validate_safe_id(container_id)?;
        Ok(format!("profile:{}:container:{}", profile_id, container_id))
    }

    pub fn save_to_path(&self, path: &Path) -> Result<(), ProfileError> {
        atomic_write_json(path, self)
    }

    pub fn load_from_path(path: &Path) -> Result<Self, ProfileError> {
        let raw = fs::read_to_string(path).map_err(|e| ProfileError::Io(e.to_string()))?;
        serde_json::from_str(&raw).map_err(|e| ProfileError::Serialization(e.to_string()))
    }
}

// ============================================================================
// 3. Workspaces, Essentials, Saved Groups, Named Sessions & Closed Stack
// ============================================================================

/// Serialized tab record persisted inside a workspace, group, or closed window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceTabRecord {
    pub id: String,
    pub title: String,
    pub url: String,
    #[serde(default)]
    pub favicon_url: Option<String>,
    #[serde(default)]
    pub pinned: bool,
    #[serde(default)]
    pub muted: bool,
    #[serde(default)]
    pub container_id: Option<String>,
    #[serde(default)]
    pub group_id: Option<String>,
    #[serde(default)]
    pub scroll_y: Option<u32>,
    #[serde(default)]
    pub media_time_sec: Option<u32>,
}

/// Split-view pane layout configuration attached to a workspace.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum SplitLayoutConfig {
    Single,
    Vertical {
        left_tab_id: String,
        right_tab_id: String,
        ratio: f32,
    },
    Horizontal {
        top_tab_id: String,
        bottom_tab_id: String,
        ratio: f32,
    },
    Grid {
        tab_ids: Vec<String>,
    },
}

/// Arc/Vivaldi-style Workspace holding independent tabs, groups, theme, container & relay.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WorkspaceRecord {
    pub id: String,
    pub name: String,
    pub icon: String,
    pub accent_hex: String,
    pub theme_override: Option<String>,
    pub container_id: Option<String>,
    pub mullvad_relay_override: Option<String>,
    #[serde(default)]
    pub routing_domains: Vec<String>,
    pub active_tab_index: usize,
    #[serde(default)]
    pub tabs: Vec<WorkspaceTabRecord>,
    #[serde(default)]
    pub groups: Vec<PersistedTabGroup>,
    pub split_layout: Option<SplitLayoutConfig>,
}

/// Arc-style globally pinned Essential Tab shared across workspaces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EssentialTab {
    pub id: String,
    pub title: String,
    pub url: String,
    pub pinned_home_url: String,
    pub favicon_url: Option<String>,
}

/// Saved tab group optionally pinned to the bookmarks/tab bar.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedTabGroup {
    pub id: String,
    pub title: String,
    pub color: String,
    pub pinned_to_bar: bool,
    pub tabs: Vec<WorkspaceTabRecord>,
    pub updated_unix: u64,
}

/// Named session snapshot supporting tags, automatic crash/daily backups, and export.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamedSessionSnapshot {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub tags: Vec<String>,
    pub auto_generated: bool,
    pub created_unix: u64,
    pub windows_json: String,
}

/// Entry stored inside the 100-item persistent [`ClosedSessionStack`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ClosedSessionEntry {
    Tab {
        id: String,
        url: String,
        title: String,
        nav_stack: Vec<String>,
        nav_index: usize,
        group_id: Option<String>,
        closed_index: usize,
        closed_unix: u64,
    },
    Group {
        id: String,
        title: String,
        color: String,
        tabs: Vec<WorkspaceTabRecord>,
        closed_unix: u64,
    },
    Window {
        id: String,
        workspace_id: Option<String>,
        tabs: Vec<WorkspaceTabRecord>,
        groups: Vec<PersistedTabGroup>,
        closed_unix: u64,
    },
}

impl ClosedSessionEntry {
    pub fn id(&self) -> &str {
        match self {
            Self::Tab { id, .. } | Self::Group { id, .. } | Self::Window { id, .. } => id,
        }
    }
}

/// Persistent 100-entry LIFO ring buffer for recently closed tabs, groups, and windows.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClosedSessionStack {
    entries: Vec<ClosedSessionEntry>,
}

impl ClosedSessionStack {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Pushes a closed entry onto the top of the stack, evicting the oldest if > 100 entries.
    pub fn push(&mut self, entry: ClosedSessionEntry) {
        self.entries.push(entry);
        if self.entries.len() > MAX_CLOSED_SESSION_ENTRIES {
            let excess = self.entries.len() - MAX_CLOSED_SESSION_ENTRIES;
            self.entries.drain(0..excess);
        }
    }

    /// Pops the most recently closed entry (`Ctrl+Shift+T`).
    pub fn pop(&mut self) -> Option<ClosedSessionEntry> {
        self.entries.pop()
    }

    /// Removes and returns a specific closed entry by its unique ID.
    pub fn reopen_by_id(&mut self, id: &str) -> Option<ClosedSessionEntry> {
        let pos = self.entries.iter().rposition(|e| e.id() == id)?;
        Some(self.entries.remove(pos))
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns entries ordered oldest-to-newest (top of stack is last).
    pub fn as_slice(&self) -> &[ClosedSessionEntry] {
        &self.entries
    }

    /// Iterates entries from most recently closed to oldest.
    pub fn recent_first(&self) -> impl Iterator<Item = &ClosedSessionEntry> {
        self.entries.iter().rev()
    }
}

/// Unified store for workspaces, essentials, saved tab groups, named sessions, and closed stack.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WorkspaceSessionStore {
    pub workspaces: Vec<WorkspaceRecord>,
    pub active_workspace_id: String,
    #[serde(default)]
    pub essentials: Vec<EssentialTab>,
    #[serde(default)]
    pub saved_groups: Vec<PersistedTabGroup>,
    #[serde(default)]
    pub named_sessions: Vec<NamedSessionSnapshot>,
    #[serde(default)]
    pub closed_stack: ClosedSessionStack,
}

impl Default for WorkspaceSessionStore {
    fn default() -> Self {
        Self {
            workspaces: vec![WorkspaceRecord {
                id: "ws-main".into(),
                name: "Main".into(),
                icon: "orbit".into(),
                accent_hex: "#F0B254".into(),
                theme_override: None,
                container_id: None,
                mullvad_relay_override: None,
                routing_domains: Vec::new(),
                active_tab_index: 0,
                tabs: Vec::new(),
                groups: Vec::new(),
                split_layout: None,
            }],
            active_workspace_id: "ws-main".into(),
            essentials: Vec::new(),
            saved_groups: Vec::new(),
            named_sessions: Vec::new(),
            closed_stack: ClosedSessionStack::new(),
        }
    }
}

impl WorkspaceSessionStore {
    pub fn get_workspace(&self, id: &str) -> Option<&WorkspaceRecord> {
        self.workspaces.iter().find(|w| w.id == id)
    }

    pub fn get_workspace_mut(&mut self, id: &str) -> Option<&mut WorkspaceRecord> {
        self.workspaces.iter_mut().find(|w| w.id == id)
    }

    pub fn upsert_workspace(&mut self, ws: WorkspaceRecord) -> Result<(), ProfileError> {
        validate_safe_id(&ws.id)?;
        if let Some(existing) = self.workspaces.iter_mut().find(|w| w.id == ws.id) {
            *existing = ws;
        } else {
            self.workspaces.push(ws);
        }
        Ok(())
    }

    pub fn resolve_workspace_for_host(&self, host: &str) -> Option<&WorkspaceRecord> {
        self.workspaces
            .iter()
            .filter_map(|ws| {
                ws.routing_domains
                    .iter()
                    .filter(|pat| domain_pattern_matches(pat, host))
                    .map(|pat| (ws, pat.len()))
                    .max_by_key(|(_, len)| *len)
            })
            .max_by_key(|(_, len)| *len)
            .map(|(ws, _)| ws)
    }

    pub fn add_named_snapshot(
        &mut self,
        name: &str,
        tags: Vec<String>,
        auto_generated: bool,
        windows_json: String,
    ) -> NamedSessionSnapshot {
        let snap = NamedSessionSnapshot {
            id: random_hex_id("sess", 6),
            name: name.to_string(),
            tags,
            auto_generated,
            created_unix: unix_now(),
            windows_json,
        };
        self.named_sessions.push(snap.clone());
        snap
    }

    /// Exports a named session snapshot as raw pretty JSON.
    pub fn export_snapshot_json(&self, snapshot_id: &str) -> Result<String, ProfileError> {
        let snap = self
            .named_sessions
            .iter()
            .find(|s| s.id == snapshot_id)
            .ok_or_else(|| ProfileError::SnapshotNotFound(snapshot_id.to_string()))?;
        serde_json::to_string_pretty(snap).map_err(|e| ProfileError::Serialization(e.to_string()))
    }

    /// Exports all URLs contained in a named session snapshot (one URL per line).
    pub fn export_snapshot_urls(&self, snapshot_id: &str) -> Result<String, ProfileError> {
        let snap = self
            .named_sessions
            .iter()
            .find(|s| s.id == snapshot_id)
            .ok_or_else(|| ProfileError::SnapshotNotFound(snapshot_id.to_string()))?;
        let items = extract_title_urls_from_windows_json(&snap.windows_json);
        let urls: Vec<String> = items.into_iter().map(|(_, u)| u).collect();
        Ok(urls.join("\n"))
    }

    /// Exports a named session snapshot as a Markdown checklist with clickable links.
    pub fn export_snapshot_markdown(&self, snapshot_id: &str) -> Result<String, ProfileError> {
        let snap = self
            .named_sessions
            .iter()
            .find(|s| s.id == snapshot_id)
            .ok_or_else(|| ProfileError::SnapshotNotFound(snapshot_id.to_string()))?;
        let items = extract_title_urls_from_windows_json(&snap.windows_json);
        let mut md = format!("# {}\n\n", snap.name);
        if !snap.tags.is_empty() {
            md.push_str(&format!("Tags: `{}`\n\n", snap.tags.join("`, `")));
        }
        for (title, url) in items {
            let safe_title = if title.trim().is_empty() {
                url.as_str()
            } else {
                title.as_str()
            };
            md.push_str(&format!("- [{}]({})\n", safe_title.replace(']', "\\]"), url));
        }
        Ok(md)
    }

    pub fn save_to_path(&self, path: &Path) -> Result<(), ProfileError> {
        atomic_write_json(path, self)
    }

    pub fn load_from_path(path: &Path) -> Result<Self, ProfileError> {
        let raw = fs::read_to_string(path).map_err(|e| ProfileError::Io(e.to_string()))?;
        serde_json::from_str(&raw).map_err(|e| ProfileError::Serialization(e.to_string()))
    }
}

fn extract_title_urls_from_windows_json(windows_json: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let Ok(val) = serde_json::from_str::<serde_json::Value>(windows_json) else {
        return out;
    };
    collect_url_objects(&val, &mut out);
    out
}

fn collect_url_objects(val: &serde_json::Value, out: &mut Vec<(String, String)>) {
    match val {
        serde_json::Value::Array(arr) => {
            for item in arr {
                collect_url_objects(item, out);
            }
        }
        serde_json::Value::Object(map) => {
            if let Some(url) = map.get("url").and_then(|v| v.as_str()) {
                let title = map
                    .get("title")
                    .and_then(|v| v.as_str())
                    .unwrap_or(url)
                    .to_string();
                out.push((title, url.to_string()));
            }
            for (k, v) in map {
                if k != "url" && k != "title" {
                    collect_url_objects(v, out);
                }
            }
        }
        _ => {}
    }
}

// ============================================================================
// 4. Permissions par site (SitePermissionsStore)
// ============================================================================

/// Complete set of privacy-sensitive web platform permissions governed per origin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionKind {
    Camera,
    Microphone,
    Geolocation,
    ClipboardRead,
    ClipboardWrite,
    Notifications,
    Popups,
    Autoplay,
    Sensors,
    WebUsb,
    WebBluetooth,
    WebHid,
    WebSerial,
    WebMidi,
    PersistentStorage,
    WindowManagement,
    LocalNetworkAccess,
    ScreenShare,
    LocalFonts,
}

impl PermissionKind {
    pub const ALL: &'static [PermissionKind] = &[
        Self::Camera,
        Self::Microphone,
        Self::Geolocation,
        Self::ClipboardRead,
        Self::ClipboardWrite,
        Self::Notifications,
        Self::Popups,
        Self::Autoplay,
        Self::Sensors,
        Self::WebUsb,
        Self::WebBluetooth,
        Self::WebHid,
        Self::WebSerial,
        Self::WebMidi,
        Self::PersistentStorage,
        Self::WindowManagement,
        Self::LocalNetworkAccess,
        Self::ScreenShare,
        Self::LocalFonts,
    ];

    /// LibreWolf / Mullvad Browser hardened privacy-first default decision.
    pub fn hardened_default(&self) -> PermissionDecision {
        match self {
            // High-fingerprinting / hardware / LAN / nuisance capabilities denied by default
            Self::Popups
            | Self::Autoplay
            | Self::Sensors
            | Self::WebUsb
            | Self::WebBluetooth
            | Self::WebHid
            | Self::WebSerial
            | Self::WebMidi
            | Self::WindowManagement
            | Self::LocalNetworkAccess
            | Self::LocalFonts
            | Self::ClipboardRead => PermissionDecision::Deny,
            // Interactive capabilities prompt explicitly per origin
            Self::Camera
            | Self::Microphone
            | Self::Geolocation
            | Self::ClipboardWrite
            | Self::Notifications
            | Self::PersistentStorage
            | Self::ScreenShare => PermissionDecision::Ask,
        }
    }
}

/// Access decision for a site permission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionDecision {
    Allow,
    Deny,
    Ask,
}

/// Lifetime scope of a permission grant or denial.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum PermissionScope {
    Permanent,
    Session,
    UntilUnix(u64),
}

/// Single origin-permission entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SitePermissionGrant {
    pub decision: PermissionDecision,
    pub scope: PermissionScope,
    pub updated_unix: u64,
}

/// Per-origin permission store with hardened defaults, temporary grants, and expiration purge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SitePermissionsStore {
    pub default_policies: BTreeMap<PermissionKind, PermissionDecision>,
    /// Origin (normalized lowercase, e.g. `"https://meet.example.com"`) -> (Kind -> Grant).
    #[serde(default)]
    pub grants: BTreeMap<String, BTreeMap<PermissionKind, SitePermissionGrant>>,
}

impl Default for SitePermissionsStore {
    fn default() -> Self {
        Self::new_hardened()
    }
}

impl SitePermissionsStore {
    pub fn new_hardened() -> Self {
        let mut default_policies = BTreeMap::new();
        for &kind in PermissionKind::ALL {
            default_policies.insert(kind, kind.hardened_default());
        }
        Self {
            default_policies,
            grants: BTreeMap::new(),
        }
    }

    fn normalize_origin(origin: &str) -> String {
        origin.trim().trim_end_matches('/').to_ascii_lowercase()
    }

    pub fn set_default_policy(&mut self, kind: PermissionKind, decision: PermissionDecision) {
        self.default_policies.insert(kind, decision);
    }

    pub fn set_permission(
        &mut self,
        origin: &str,
        kind: PermissionKind,
        decision: PermissionDecision,
        scope: PermissionScope,
        now_unix: u64,
    ) {
        let key = Self::normalize_origin(origin);
        self.grants.entry(key).or_default().insert(
            kind,
            SitePermissionGrant {
                decision,
                scope,
                updated_unix: now_unix,
            },
        );
    }

    /// Evaluates the effective decision for `(origin, kind)` at `now_unix`, automatically
    /// falling back to the hardened default when a temporary grant has expired.
    pub fn get_effective_decision(
        &self,
        origin: &str,
        kind: PermissionKind,
        now_unix: u64,
    ) -> PermissionDecision {
        let key = Self::normalize_origin(origin);
        if let Some(grant) = self.grants.get(&key).and_then(|m| m.get(&kind)) {
            let expired = match grant.scope {
                PermissionScope::UntilUnix(deadline) => now_unix >= deadline,
                PermissionScope::Permanent | PermissionScope::Session => false,
            };
            if !expired {
                return grant.decision;
            }
        }
        self.default_policies
            .get(&kind)
            .copied()
            .unwrap_or_else(|| kind.hardened_default())
    }

    /// Purges all expired `UntilUnix` permission entries strictly before/at `now_unix`.
    pub fn purge_expired(&mut self, now_unix: u64) -> usize {
        let mut purged = 0usize;
        for per_origin in self.grants.values_mut() {
            let before = per_origin.len();
            per_origin.retain(|_, grant| match grant.scope {
                PermissionScope::UntilUnix(deadline) => now_unix < deadline,
                PermissionScope::Permanent | PermissionScope::Session => true,
            });
            purged += before - per_origin.len();
        }
        self.grants.retain(|_, m| !m.is_empty());
        purged
    }

    /// Removes all session-scoped grants (called on browser shutdown).
    pub fn clear_session_permissions(&mut self) -> usize {
        let mut removed = 0usize;
        for per_origin in self.grants.values_mut() {
            let before = per_origin.len();
            per_origin.retain(|_, g| g.scope != PermissionScope::Session);
            removed += before - per_origin.len();
        }
        self.grants.retain(|_, m| !m.is_empty());
        removed
    }

    /// Resets all customized permissions for a single origin back to global defaults.
    pub fn reset_origin(&mut self, origin: &str) -> usize {
        let key = Self::normalize_origin(origin);
        self.grants.remove(&key).map(|m| m.len()).unwrap_or(0)
    }

    pub fn list_for_origin(&self, origin: &str) -> BTreeMap<PermissionKind, SitePermissionGrant> {
        let key = Self::normalize_origin(origin);
        self.grants.get(&key).cloned().unwrap_or_default()
    }

    /// Persists grants atomically while stripping ephemeral `Session` grants.
    pub fn save_to_path(&self, path: &Path) -> Result<(), ProfileError> {
        let mut persisted = self.clone();
        persisted.clear_session_permissions();
        atomic_write_json(path, &persisted)
    }

    pub fn load_from_path(path: &Path) -> Result<Self, ProfileError> {
        let raw = fs::read_to_string(path).map_err(|e| ProfileError::Io(e.to_string()))?;
        serde_json::from_str(&raw).map_err(|e| ProfileError::Serialization(e.to_string()))
    }
}

// ============================================================================
// 5. Personnalisation Avancée (CustomizationStore)
// ============================================================================

/// Theme color mode (Light, Dark, Auto OS, or OLED Pure Black `#000000`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThemeAppearanceMode {
    Light,
    Dark,
    AutoOs,
    OledPureBlack,
}

/// 8-bit RGBA color token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RgbaToken {
    pub r: u8,
    pub g: u8,
    pub b: u8,
    pub a: u8,
}

impl RgbaToken {
    /// Parses `#RGB`, `#RRGGBB`, or `#RRGGBBAA` hex color strings.
    pub fn from_hex(raw: &str) -> Result<Self, ProfileError> {
        let s = raw.trim().trim_start_matches('#');
        match s.len() {
            3 => {
                let r = u8::from_str_radix(&s[0..1], 16)
                    .map_err(|_| ProfileError::InvalidHexColor(raw.to_string()))?;
                let g = u8::from_str_radix(&s[1..2], 16)
                    .map_err(|_| ProfileError::InvalidHexColor(raw.to_string()))?;
                let b = u8::from_str_radix(&s[2..3], 16)
                    .map_err(|_| ProfileError::InvalidHexColor(raw.to_string()))?;
                Ok(Self {
                    r: r * 17,
                    g: g * 17,
                    b: b * 17,
                    a: 255,
                })
            }
            6 => {
                let r = u8::from_str_radix(&s[0..2], 16)
                    .map_err(|_| ProfileError::InvalidHexColor(raw.to_string()))?;
                let g = u8::from_str_radix(&s[2..4], 16)
                    .map_err(|_| ProfileError::InvalidHexColor(raw.to_string()))?;
                let b = u8::from_str_radix(&s[4..6], 16)
                    .map_err(|_| ProfileError::InvalidHexColor(raw.to_string()))?;
                Ok(Self { r, g, b, a: 255 })
            }
            8 => {
                let r = u8::from_str_radix(&s[0..2], 16)
                    .map_err(|_| ProfileError::InvalidHexColor(raw.to_string()))?;
                let g = u8::from_str_radix(&s[2..4], 16)
                    .map_err(|_| ProfileError::InvalidHexColor(raw.to_string()))?;
                let b = u8::from_str_radix(&s[4..6], 16)
                    .map_err(|_| ProfileError::InvalidHexColor(raw.to_string()))?;
                let a = u8::from_str_radix(&s[6..8], 16)
                    .map_err(|_| ProfileError::InvalidHexColor(raw.to_string()))?;
                Ok(Self { r, g, b, a })
            }
            _ => Err(ProfileError::InvalidHexColor(raw.to_string())),
        }
    }

    pub fn to_hex(&self) -> String {
        if self.a == 255 {
            format!("#{:02X}{:02X}{:02X}", self.r, self.g, self.b)
        } else {
            format!("#{:02X}{:02X}{:02X}{:02X}", self.r, self.g, self.b, self.a)
        }
    }

    /// Relative luminance $L \in [0, 1]$ per WCAG 2.1 specification.
    pub fn relative_luminance(&self) -> f64 {
        fn lin(channel: u8) -> f64 {
            let s = (channel as f64) / 255.0;
            if s <= 0.04045 {
                s / 12.92
            } else {
                ((s + 0.055) / 1.055).powf(2.4)
            }
        }
        0.2126 * lin(self.r) + 0.7152 * lin(self.g) + 0.0722 * lin(self.b)
    }
}

/// WCAG 2.1 contrast ratio between two hex colors (`#RGB`, `#RRGGBB`, `#RRGGBBAA`),
/// returning a value in `1.0..=21.0` (or `0.0` if either color string is malformed).
pub fn contrast_ratio_hex(fg: &str, bg: &str) -> f64 {
    try_contrast_ratio_hex(fg, bg).unwrap_or(0.0)
}

/// Checked WCAG 2.1 contrast ratio helper returning an error on invalid hex syntax.
pub fn try_contrast_ratio_hex(fg: &str, bg: &str) -> Result<f64, ProfileError> {
    let fg_c = RgbaToken::from_hex(fg)?;
    let bg_c = RgbaToken::from_hex(bg)?;
    // Alpha-composite fg over bg when fg has transparency
    let alpha = (fg_c.a as f64) / 255.0;
    let eff_fg = RgbaToken {
        r: ((fg_c.r as f64) * alpha + (bg_c.r as f64) * (1.0 - alpha)).round() as u8,
        g: ((fg_c.g as f64) * alpha + (bg_c.g as f64) * (1.0 - alpha)).round() as u8,
        b: ((fg_c.b as f64) * alpha + (bg_c.b as f64) * (1.0 - alpha)).round() as u8,
        a: 255,
    };
    let l1 = eff_fg.relative_luminance();
    let l2 = bg_c.relative_luminance();
    let (lighter, darker) = if l1 >= l2 { (l1, l2) } else { (l2, l1) };
    Ok((lighter + 0.05) / (darker + 0.05))
}

/// WCAG 2.1 conformance tier for normal text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WcagContrastGrade {
    Fail,
    AaLarge,
    Aa,
    Aaa,
}

pub fn evaluate_wcag_grade(ratio: f64) -> WcagContrastGrade {
    if ratio >= 7.0 {
        WcagContrastGrade::Aaa
    } else if ratio >= 4.5 {
        WcagContrastGrade::Aa
    } else if ratio >= 3.0 {
        WcagContrastGrade::AaLarge
    } else {
        WcagContrastGrade::Fail
    }
}

/// Full user-editable theme manifest with RGBA tokens and built-in WCAG verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustomThemeManifest {
    pub id: String,
    pub name: String,
    pub mode: ThemeAppearanceMode,
    pub background: RgbaToken,
    pub surface: RgbaToken,
    pub border: RgbaToken,
    pub text_primary: RgbaToken,
    pub text_muted: RgbaToken,
    pub accent_primary: RgbaToken,
    pub accent_secondary: RgbaToken,
    pub corner_radius_px: u8,
    pub ui_font_family: String,
}

impl Default for CustomThemeManifest {
    fn default() -> Self {
        Self {
            id: "oled-singularity".into(),
            name: "Singularity OLED Pure Black".into(),
            mode: ThemeAppearanceMode::OledPureBlack,
            background: RgbaToken { r: 0, g: 0, b: 0, a: 255 },
            surface: RgbaToken { r: 12, g: 13, b: 18, a: 255 },
            border: RgbaToken { r: 26, g: 27, b: 32, a: 255 },
            text_primary: RgbaToken { r: 245, g: 243, b: 238, a: 255 },
            text_muted: RgbaToken { r: 152, g: 155, b: 165, a: 255 },
            accent_primary: RgbaToken { r: 240, g: 178, b: 84, a: 255 },
            accent_secondary: RgbaToken { r: 56, g: 217, b: 245, a: 255 },
            corner_radius_px: 10,
            ui_font_family: "system-ui, -apple-system, 'Segoe UI', sans-serif".into(),
        }
    }
}

impl CustomThemeManifest {
    pub fn primary_text_contrast(&self) -> f64 {
        contrast_ratio_hex(&self.text_primary.to_hex(), &self.background.to_hex())
    }

    pub fn accent_contrast(&self) -> f64 {
        contrast_ratio_hex(&self.accent_primary.to_hex(), &self.background.to_hex())
    }
}

/// Computed astronomical sunrise/sunset times in local minutes from midnight (`0..1440`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SolarDayPhase {
    Normal {
        sunrise_minute: u16,
        sunset_minute: u16,
    },
    PolarDay,
    PolarNight,
}

/// Pure-Rust NOAA solar sunrise/sunset algorithm (zero GPS, zero network).
///
/// - `day_of_year`: `1..=366`
/// - `latitude_deg`: `-90.0..=90.0` (North positive)
/// - `longitude_deg`: `-180.0..=180.0` (East positive)
/// - `utc_offset_minutes`: local timezone offset from UTC in minutes (e.g. `+120` for CEST)
pub fn compute_noaa_sunrise_sunset(
    day_of_year: u16,
    latitude_deg: f64,
    longitude_deg: f64,
    utc_offset_minutes: i16,
) -> SolarDayPhase {
    let doy = (day_of_year.clamp(1, 366) - 1) as f64;
    let lat_deg = latitude_deg.clamp(-89.9, 89.9);
    let lon_deg = longitude_deg.clamp(-180.0, 180.0);

    // Fractional year gamma (radians) at solar noon
    let gamma = (2.0 * std::f64::consts::PI / 365.0) * doy;

    // Equation of time (minutes)
    let eqtime = 229.18
        * (0.000075
            + 0.001868 * gamma.cos()
            - 0.032077 * gamma.sin()
            - 0.014615 * (2.0 * gamma).cos()
            - 0.040849 * (2.0 * gamma).sin());

    // Solar declination angle (radians)
    let decl = 0.006918
        - 0.399912 * gamma.cos()
        + 0.070257 * gamma.sin()
        - 0.006758 * (2.0 * gamma).cos()
        + 0.000907 * (2.0 * gamma).sin()
        - 0.002697 * (3.0 * gamma).cos()
        + 0.00148 * (3.0 * gamma).sin();

    let lat_rad = lat_deg.to_radians();
    let zenith_rad = 90.833_f64.to_radians();
    let cos_ha = (zenith_rad.cos() / (lat_rad.cos() * decl.cos())) - lat_rad.tan() * decl.tan();

    if cos_ha > 1.0 {
        return SolarDayPhase::PolarNight;
    }
    if cos_ha < -1.0 {
        return SolarDayPhase::PolarDay;
    }

    let ha_deg = cos_ha.acos().to_degrees();
    let solar_noon_utc = 720.0 - 4.0 * lon_deg - eqtime;
    let sunrise_local = (solar_noon_utc - 4.0 * ha_deg + (utc_offset_minutes as f64))
        .rem_euclid(1440.0)
        .round() as u16;
    let sunset_local = (solar_noon_utc + 4.0 * ha_deg + (utc_offset_minutes as f64))
        .rem_euclid(1440.0)
        .round() as u16;

    SolarDayPhase::Normal {
        sunrise_minute: sunrise_local % 1440,
        sunset_minute: sunset_local % 1440,
    }
}

/// Trigger strategy for automatic day/night theme switching.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ThemeScheduleTrigger {
    FixedHours {
        light_start_minute: u16,
        dark_start_minute: u16,
    },
    SolarNoaa {
        latitude_deg: f64,
        longitude_deg: f64,
        utc_offset_minutes: i16,
    },
}

/// Automated theme schedule rule (fixed clock window or NOAA astronomical sunrise/sunset).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ThemeScheduleRule {
    pub enabled: bool,
    pub day_theme_id: String,
    pub night_theme_id: String,
    pub trigger: ThemeScheduleTrigger,
}

impl ThemeScheduleRule {
    /// Resolves whether the day or night theme should be active at `(day_of_year, local_minute)`.
    pub fn active_theme_id(&self, day_of_year: u16, local_minute_of_day: u16) -> &str {
        if !self.enabled {
            return &self.night_theme_id;
        }
        let minute = local_minute_of_day % 1440;
        match self.trigger {
            ThemeScheduleTrigger::FixedHours {
                light_start_minute,
                dark_start_minute,
            } => {
                let start = light_start_minute % 1440;
                let end = dark_start_minute % 1440;
                let is_day = if start < end {
                    minute >= start && minute < end
                } else {
                    minute >= start || minute < end
                };
                if is_day {
                    &self.day_theme_id
                } else {
                    &self.night_theme_id
                }
            }
            ThemeScheduleTrigger::SolarNoaa {
                latitude_deg,
                longitude_deg,
                utc_offset_minutes,
            } => match compute_noaa_sunrise_sunset(
                day_of_year,
                latitude_deg,
                longitude_deg,
                utc_offset_minutes,
            ) {
                SolarDayPhase::PolarDay => &self.day_theme_id,
                SolarDayPhase::PolarNight => &self.night_theme_id,
                SolarDayPhase::Normal {
                    sunrise_minute,
                    sunset_minute,
                } => {
                    let is_day = if sunrise_minute < sunset_minute {
                        minute >= sunrise_minute && minute < sunset_minute
                    } else {
                        minute >= sunrise_minute || minute < sunset_minute
                    };
                    if is_day {
                        &self.day_theme_id
                    } else {
                        &self.night_theme_id
                    }
                }
            },
        }
    }
}

/// Arc Boosts-style per-site CSS/JS injection, Element Zapper, font & palette override.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SiteBoostRule {
    pub id: String,
    pub domain_pattern: String,
    pub enabled: bool,
    #[serde(default)]
    pub custom_css: String,
    #[serde(default)]
    pub custom_js: String,
    #[serde(default)]
    pub zapped_selectors: Vec<String>,
    #[serde(default)]
    pub font_family_override: Option<String>,
    #[serde(default)]
    pub palette_overrides: BTreeMap<String, String>,
}

impl SiteBoostRule {
    /// Compiles palette overrides, font override, zapped selectors, and custom CSS into one sheet.
    pub fn compile_css(&self) -> String {
        if !self.enabled {
            return String::new();
        }
        let mut css = String::new();
        if !self.palette_overrides.is_empty() {
            css.push_str(":root {\n");
            for (var, val) in &self.palette_overrides {
                let clean_var = var.trim();
                let clean_val = val.replace([';', '{', '}'], "");
                if clean_var.starts_with("--") {
                    css.push_str(&format!("  {}: {} !important;\n", clean_var, clean_val));
                }
            }
            css.push_str("}\n");
        }
        if let Some(font) = &self.font_family_override {
            let clean_font = font.replace([';', '{', '}'], "");
            if !clean_font.trim().is_empty() {
                css.push_str(&format!(
                    "html, body, p, li, span, div {{ font-family: {} !important; }}\n",
                    clean_font
                ));
            }
        }
        for sel in &self.zapped_selectors {
            let trimmed = sel.trim();
            if !trimmed.is_empty() && !trimmed.contains('{') && !trimmed.contains('}') {
                css.push_str(&format!("{} {{ display: none !important; }}\n", trimmed));
            }
        }
        if !self.custom_css.trim().is_empty() {
            css.push_str(&self.custom_css);
            css.push('\n');
        }
        css
    }
}

/// Vivaldi-style persistent sidebar Web Panel configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebPanelConfig {
    pub id: String,
    pub title: String,
    pub url: String,
    pub width_px: u32,
    pub mobile_user_agent: bool,
    pub floating: bool,
    pub auto_reload_secs: Option<u64>,
    pub muted: bool,
}

/// Customizable toolbar button ordering and density.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolbarLayout {
    pub left_items: Vec<String>,
    pub center_items: Vec<String>,
    pub right_items: Vec<String>,
    pub compact_density: bool,
    pub show_bookmarks_bar: bool,
}

impl Default for ToolbarLayout {
    fn default() -> Self {
        Self {
            left_items: vec!["back".into(), "forward".into(), "reload".into()],
            center_items: vec!["omnibox".into()],
            right_items: vec![
                "shield".into(),
                "mullvad".into(),
                "vault".into(),
                "extensions".into(),
                "profile".into(),
            ],
            compact_density: true,
            show_bookmarks_bar: false,
        }
    }
}

/// Customizable bottom status bar telemetry and quick controls.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusBarConfig {
    pub visible: bool,
    pub show_zoom_slider: bool,
    pub show_mullvad_latency: bool,
    pub show_ram_usage: bool,
    pub show_clock: bool,
    pub show_capture_button: bool,
    pub show_break_mode_button: bool,
}

impl Default for StatusBarConfig {
    fn default() -> Self {
        Self {
            visible: false,
            show_zoom_slider: true,
            show_mullvad_latency: true,
            show_ram_usage: true,
            show_clock: true,
            show_capture_button: true,
            show_break_mode_button: true,
        }
    }
}

/// Single tile or folder entry inside the New Tab Speed Dial.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpeedDialEntry {
    pub id: String,
    pub title: String,
    pub url: Option<String>,
    pub folder_children: Vec<SpeedDialEntry>,
}

/// New Tab Page (Speed Dial + Widgets + Wallpaper) configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewTabConfig {
    pub speed_dial_columns: u8,
    #[serde(default)]
    pub speed_dial_entries: Vec<SpeedDialEntry>,
    pub widget_clock: bool,
    pub widget_weather: bool,
    pub widget_notes: bool,
    pub widget_privacy_stats: bool,
    pub widget_rss_feed: bool,
    pub wallpaper_url: Option<String>,
    pub wallpaper_dim_percent: u8,
    pub wallpaper_blur_px: u8,
}

impl Default for NewTabConfig {
    fn default() -> Self {
        Self {
            speed_dial_columns: 6,
            speed_dial_entries: Vec::new(),
            widget_clock: true,
            widget_weather: false,
            widget_notes: true,
            widget_privacy_stats: true,
            widget_rss_feed: false,
            wallpaper_url: None,
            wallpaper_dim_percent: 35,
            wallpaper_blur_px: 0,
        }
    }
}

/// Native OLED Dark Reader algorithm per domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DarkReaderMode {
    Off,
    DynamicOled,
    FilterInvert,
    AutoDetect,
}

/// Per-domain native OLED Dark Reader policy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SiteDarkModePolicy {
    pub mode: DarkReaderMode,
    /// `50..=150` percent (default `100`).
    pub brightness: u16,
    /// `50..=150` percent (default `105`).
    pub contrast: u16,
    /// `0..=100` percent (default `0`).
    pub sepia: u16,
    pub skip_already_dark: bool,
    pub true_black_oled: bool,
}

impl Default for SiteDarkModePolicy {
    fn default() -> Self {
        Self {
            mode: DarkReaderMode::AutoDetect,
            brightness: 100,
            contrast: 105,
            sepia: 0,
            skip_already_dark: true,
            true_black_oled: true,
        }
    }
}

/// Per-origin persistent zoom factor store (`0.25` to `5.0`, discrete Chromium-compatible steps).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PerOriginZoomStore {
    pub default_zoom: f64,
    #[serde(default)]
    pub per_origin: BTreeMap<String, f64>,
}

impl Default for PerOriginZoomStore {
    fn default() -> Self {
        Self {
            default_zoom: 1.0,
            per_origin: BTreeMap::new(),
        }
    }
}

impl PerOriginZoomStore {
    pub const ZOOM_STEPS: &'static [f64] = &[
        0.25, 0.33, 0.50, 0.67, 0.75, 0.80, 0.90, 1.00, 1.10, 1.25, 1.50, 1.75, 2.00, 2.50, 3.00,
        4.00, 5.00,
    ];

    fn norm(origin: &str) -> String {
        origin.trim().trim_end_matches('/').to_ascii_lowercase()
    }

    pub fn get(&self, origin: &str) -> f64 {
        self.per_origin
            .get(&Self::norm(origin))
            .copied()
            .unwrap_or(self.default_zoom)
    }

    pub fn set(&mut self, origin: &str, factor: f64) -> f64 {
        let clamped = factor.clamp(0.25, 5.0);
        let key = Self::norm(origin);
        if (clamped - self.default_zoom).abs() < 1e-4 {
            self.per_origin.remove(&key);
        } else {
            self.per_origin.insert(key, clamped);
        }
        clamped
    }

    pub fn zoom_in(&mut self, origin: &str) -> f64 {
        let cur = self.get(origin);
        let next = Self::ZOOM_STEPS
            .iter()
            .copied()
            .find(|&s| s > cur + 1e-4)
            .unwrap_or(5.0);
        self.set(origin, next)
    }

    pub fn zoom_out(&mut self, origin: &str) -> f64 {
        let cur = self.get(origin);
        let prev = Self::ZOOM_STEPS
            .iter()
            .rev()
            .copied()
            .find(|&s| s < cur - 1e-4)
            .unwrap_or(0.25);
        self.set(origin, prev)
    }

    pub fn reset(&mut self, origin: &str) -> f64 {
        self.per_origin.remove(&Self::norm(origin));
        self.default_zoom
    }
}

/// Complete advanced customization aggregate store persisted per profile.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CustomizationStore {
    pub active_theme: CustomThemeManifest,
    #[serde(default)]
    pub saved_themes: Vec<CustomThemeManifest>,
    pub theme_schedule: Option<ThemeScheduleRule>,
    #[serde(default)]
    pub site_boosts: Vec<SiteBoostRule>,
    #[serde(default)]
    pub web_panels: Vec<WebPanelConfig>,
    pub toolbar: ToolbarLayout,
    pub status_bar: StatusBarConfig,
    pub new_tab: NewTabConfig,
    pub global_dark_mode: SiteDarkModePolicy,
    #[serde(default)]
    pub per_domain_dark_mode: BTreeMap<String, SiteDarkModePolicy>,
    #[serde(default)]
    pub zoom: PerOriginZoomStore,
}

impl Default for CustomizationStore {
    fn default() -> Self {
        Self {
            active_theme: CustomThemeManifest::default(),
            saved_themes: Vec::new(),
            theme_schedule: None,
            site_boosts: Vec::new(),
            web_panels: Vec::new(),
            toolbar: ToolbarLayout::default(),
            status_bar: StatusBarConfig::default(),
            new_tab: NewTabConfig::default(),
            global_dark_mode: SiteDarkModePolicy::default(),
            per_domain_dark_mode: BTreeMap::new(),
            zoom: PerOriginZoomStore::default(),
        }
    }
}

impl CustomizationStore {
    /// Returns all active [`SiteBoostRule`]s matching `host`.
    pub fn boosts_for_host(&self, host: &str) -> Vec<&SiteBoostRule> {
        self.site_boosts
            .iter()
            .filter(|b| b.enabled && domain_pattern_matches(&b.domain_pattern, host))
            .collect()
    }

    /// Resolves effective OLED Dark Reader policy for `host` (domain override or global policy).
    pub fn dark_mode_for_host(&self, host: &str) -> &SiteDarkModePolicy {
        self.per_domain_dark_mode
            .iter()
            .filter(|(pat, _)| domain_pattern_matches(pat, host))
            .max_by_key(|(pat, _)| pat.len())
            .map(|(_, policy)| policy)
            .unwrap_or(&self.global_dark_mode)
    }

    pub fn save_to_path(&self, path: &Path) -> Result<(), ProfileError> {
        atomic_write_json(path, self)
    }

    pub fn load_from_path(path: &Path) -> Result<Self, ProfileError> {
        let raw = fs::read_to_string(path).map_err(|e| ProfileError::Io(e.to_string()))?;
        serde_json::from_str(&raw).map_err(|e| ProfileError::Serialization(e.to_string()))
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_profile_registry_isolation_guest_routing_and_shortcuts() {
        let mut reg = ProfileRegistry::new_default();
        let work = reg
            .create_profile(Some("work"), "Work", "briefcase", "#38D9F5", "nebuleuse")
            .expect("create work profile");
        assert_eq!(work.id, "work");

        // Path traversal blocked strictly
        let root = std::env::temp_dir().join(format!("singularity_prof_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        assert!(ProfileRegistry::profile_data_dir(&root, "../evil").is_err());
        assert!(ProfileRegistry::profile_data_dir(&root, "a/b").is_err());
        let work_dir = ProfileRegistry::profile_data_dir(&root, "work").expect("valid dir");
        assert!(work_dir.ends_with(Path::new("profiles").join("work")));

        // Routing rules
        reg.routing_rules.push(ProfileRoutingRule {
            domain_pattern: "*.corp.example".into(),
            target_profile_id: "work".into(),
            auto_switch: true,
        });
        let matched = reg.resolve_route_for_host("jira.corp.example").expect("route");
        assert_eq!(matched.target_profile_id, "work");
        assert!(reg.resolve_route_for_host("other.org").is_none());

        // .desktop and launcher script generation
        let desktop = reg
            .generate_linux_desktop_entry("work", "/usr/bin/singularity")
            .expect("desktop");
        assert!(desktop.contains("--profile=work"));
        assert!(desktop.contains("Name=Singularity (Work)"));

        let win_script = reg
            .generate_shortcut_script("work", r"C:\Program Files\Singularity\singularity.exe", true)
            .expect("win cmd");
        assert!(win_script.contains("--profile=work"));

        // Guest profile creation & directory cleanup
        let guest = reg.create_guest_profile();
        assert!(guest.is_guest);
        let guest_dir = ProfileRegistry::profile_data_dir(&root, &guest.id).unwrap();
        fs::create_dir_all(&guest_dir).unwrap();
        fs::write(guest_dir.join("temp.dat"), b"secret").unwrap();
        assert!(reg.cleanup_guest_profile(&root, &guest.id).unwrap());
        assert!(!guest_dir.exists());

        // Cannot delete last remaining non-guest profile
        reg.delete_profile("work").expect("delete work");
        assert!(matches!(
            reg.delete_profile("default"),
            Err(ProfileError::CannotDeleteLastProfile)
        ));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn test_container_registry_builtins_and_host_resolution() {
        let mut reg = ContainerRegistry::new();
        assert_eq!(reg.containers.len(), 5);
        assert!(reg.get("ephemeral").unwrap().ephemeral);
        assert!(matches!(
            reg.remove_custom("banking"),
            Err(ProfileError::CannotDeleteBuiltinContainer(_))
        ));

        reg.add_custom(ContainerTabProfile {
            id: "dev-staging".into(),
            name: "Staging".into(),
            color_hex: "#A855F7".into(),
            icon: "terminal".into(),
            ephemeral: false,
            proxy_profile_id: Some("socks-dev".into()),
            mullvad_relay: Some("se".into()),
        })
        .expect("add custom");

        reg.add_domain_rule(ContainerDomainRule {
            domain_pattern: "*.mybank.fr".into(),
            container_id: "banking".into(),
            ask_before_switch: false,
        })
        .unwrap();
        reg.add_domain_rule(ContainerDomainRule {
            domain_pattern: "shop.mybank.fr".into(),
            container_id: "shopping".into(),
            ask_before_switch: true,
        })
        .unwrap();

        let (c1, ask1) = reg.resolve_container_for_host("app.mybank.fr").unwrap();
        assert_eq!(c1.id, "banking");
        assert!(!ask1);

        // Most-specific rule wins
        let (c2, ask2) = reg.resolve_container_for_host("shop.mybank.fr").unwrap();
        assert_eq!(c2.id, "shopping");
        assert!(ask2);
    }

    #[test]
    fn test_workspace_sessions_closed_ring_buffer_and_exports() {
        let mut store = WorkspaceSessionStore::default();

        // Push 120 closed tabs -> ring buffer retains exact last 100
        for i in 0..120usize {
            store.closed_stack.push(ClosedSessionEntry::Tab {
                id: format!("closed-{}", i),
                url: format!("https://example.org/{}", i),
                title: format!("Page {}", i),
                nav_stack: vec![format!("https://example.org/{}", i)],
                nav_index: 0,
                group_id: None,
                closed_index: i,
                closed_unix: 1000 + i as u64,
            });
        }
        assert_eq!(store.closed_stack.len(), MAX_CLOSED_SESSION_ENTRIES);
        assert_eq!(store.closed_stack.pop().unwrap().id(), "closed-119");
        assert!(store.closed_stack.reopen_by_id("closed-5").is_none()); // evicted
        let reopened = store.closed_stack.reopen_by_id("closed-50").unwrap();
        assert_eq!(reopened.id(), "closed-50");

        // Named session snapshot exports (Markdown, URLs, JSON)
        let windows_json = serde_json::json!([
            {
                "window_id": "w1",
                "tabs": [
                    { "title": "Rust Lang", "url": "https://www.rust-lang.org" },
                    { "title": "Mullvad", "url": "https://mullvad.net" }
                ]
            }
        ])
        .to_string();
        let snap = store.add_named_snapshot(
            "Evening Research",
            vec!["rust".into(), "privacy".into()],
            false,
            windows_json,
        );
        let md = store.export_snapshot_markdown(&snap.id).unwrap();
        assert!(md.contains("# Evening Research"));
        assert!(md.contains("- [Rust Lang](https://www.rust-lang.org)"));

        let urls = store.export_snapshot_urls(&snap.id).unwrap();
        assert_eq!(urls, "https://www.rust-lang.org\nhttps://mullvad.net");

        let json = store.export_snapshot_json(&snap.id).unwrap();
        assert!(json.contains("Evening Research"));
    }

    #[test]
    fn test_site_permissions_hardened_defaults_expiration_and_reset() {
        let mut perms = SitePermissionsStore::new_hardened();
        assert_eq!(PermissionKind::ALL.len(), 19);

        // Hardened defaults deny WebUSB/LocalNetworkAccess/Sensors/Autoplay
        assert_eq!(
            perms.get_effective_decision("https://random.test", PermissionKind::WebUsb, 100),
            PermissionDecision::Deny
        );
        assert_eq!(
            perms.get_effective_decision("https://random.test", PermissionKind::LocalNetworkAccess, 100),
            PermissionDecision::Deny
        );
        assert_eq!(
            perms.get_effective_decision("https://random.test", PermissionKind::Camera, 100),
            PermissionDecision::Ask
        );

        // Temporary UntilUnix grant
        perms.set_permission(
            "https://meet.example.com",
            PermissionKind::Camera,
            PermissionDecision::Allow,
            PermissionScope::UntilUnix(2000),
            1000,
        );
        perms.set_permission(
            "https://meet.example.com",
            PermissionKind::Microphone,
            PermissionDecision::Allow,
            PermissionScope::Session,
            1000,
        );
        assert_eq!(
            perms.get_effective_decision("https://meet.example.com", PermissionKind::Camera, 1500),
            PermissionDecision::Allow
        );
        // Expired at t=2000 -> reverts to Ask
        assert_eq!(
            perms.get_effective_decision("https://meet.example.com", PermissionKind::Camera, 2000),
            PermissionDecision::Ask
        );
        assert_eq!(perms.purge_expired(2000), 1);
        assert_eq!(perms.reset_origin("https://meet.example.com"), 1);
    }

    #[test]
    fn test_wcag_contrast_noaa_solar_schedule_boosts_and_zoom() {
        // Pure white on pure OLED black = exact 21.0:1 (AAA)
        let ratio_bw = contrast_ratio_hex("#FFFFFF", "#000000");
        assert!((ratio_bw - 21.0).abs() < 0.01);
        assert_eq!(evaluate_wcag_grade(ratio_bw), WcagContrastGrade::Aaa);

        // Default OLED manifest passes AAA for primary text
        let manifest = CustomThemeManifest::default();
        assert!(manifest.primary_text_contrast() > 15.0);

        // NOAA solar calculation for Paris (48.8566N, 2.3522E) on June 21 (day 172, CEST UTC+120)
        let summer = compute_noaa_sunrise_sunset(172, 48.8566, 2.3522, 120);
        match summer {
            SolarDayPhase::Normal {
                sunrise_minute,
                sunset_minute,
            } => {
                // Expected ~05:46 (346 min) and ~21:58 (1318 min)
                assert!(
                    (330..=365).contains(&sunrise_minute),
                    "unexpected Paris summer sunrise minute: {}",
                    sunrise_minute
                );
                assert!(
                    (1300..=1335).contains(&sunset_minute),
                    "unexpected Paris summer sunset minute: {}",
                    sunset_minute
                );
            }
            other => panic!("expected Normal solar phase for Paris, got {:?}", other),
        }

        // Polar summer at 80N on day 172 -> PolarDay
        assert_eq!(
            compute_noaa_sunrise_sunset(172, 80.0, 15.0, 120),
            SolarDayPhase::PolarDay
        );

        let sched = ThemeScheduleRule {
            enabled: true,
            day_theme_id: "soleil".into(),
            night_theme_id: "singularity".into(),
            trigger: ThemeScheduleTrigger::SolarNoaa {
                latitude_deg: 48.8566,
                longitude_deg: 2.3522,
                utc_offset_minutes: 120,
            },
        };
        assert_eq!(sched.active_theme_id(172, 12 * 60), "soleil");
        assert_eq!(sched.active_theme_id(172, 23 * 60), "singularity");

        // SiteBoost CSS compiler & PerOriginZoomStore
        let mut custom = CustomizationStore::default();
        custom.site_boosts.push(SiteBoostRule {
            id: "clean-news".into(),
            domain_pattern: "*.news.test".into(),
            enabled: true,
            custom_css: "article { max-width: 72ch; }".into(),
            custom_js: String::new(),
            zapped_selectors: vec![".paywall-banner".into(), "#cookie-nag".into()],
            font_family_override: Some("Inter, sans-serif".into()),
            palette_overrides: BTreeMap::from([("--bg".into(), "#000000".into())]),
        });
        let boosts = custom.boosts_for_host("www.news.test");
        assert_eq!(boosts.len(), 1);
        let css = boosts[0].compile_css();
        assert!(css.contains(".paywall-banner { display: none !important; }"));
        assert!(css.contains("--bg: #000000 !important;"));

        assert_eq!(custom.zoom.zoom_in("https://docs.rs"), 1.10);
        assert_eq!(custom.zoom.zoom_in("https://docs.rs"), 1.25);
        assert_eq!(custom.zoom.zoom_out("https://docs.rs"), 1.10);
        assert_eq!(custom.zoom.reset("https://docs.rs"), 1.0);
    }
}
