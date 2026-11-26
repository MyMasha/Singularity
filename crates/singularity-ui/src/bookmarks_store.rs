//! Singularity Unlimited Hierarchical Bookmarks Store — 100% Pure Rust.
//!
//! Features:
//! - Unlimited tree model (`BookmarkNode` with `Folder | Url | Separator`) and 4 protected system
//!   roots (`bookmark_bar`, `other_bookmarks`, `mobile_bookmarks`, `trash`)
//! - Atomic persistent storage (`bookmarks_store.json` + `.bak` fallback)
//! - Full tree operations (`add_node`, `update_node`, `move_node` with strict cycle detection,
//!   `soft_delete`, `restore_from_trash`, `empty_trash`, `purge_expired_trash`,
//!   `sort_folder_by_name`, `bookmark_all_tabs`)
//! - 100-operation Undo / Redo history stack (`undo()`, `redo()`)
//! - Instant multi-criteria search (`tag:`, `folder:`, `domain:`, `has:note`), dynamic
//!   `SmartFolderRule` evaluation, and nickname resolution (`resolve_nickname` with `%s`)
//! - URL canonicalization (`http`/`https`, `www.`, slash, tracking params) + duplicate detection
//!   (`find_duplicate_groups`) and merging (`merge_duplicates`)
//! - High-fidelity Import / Export:
//!   - Netscape HTML state machine (`parse_netscape_html_tree` + `export_netscape_html_tree`)
//!     preserving nested folders, timestamps, tags, nicknames, `<DD>` descriptions, `<HR>` separators
//!   - Structured JSON tree (`export_json_tree` + `import_json_tree`)
//!   - Safari XML Plist (`parse_safari_bookmarks_plist_xml`) supporting `WebBookmarkTypeList`
//!     and `WebBookmarkTypeLeaf`.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

pub const BOOKMARKS_STORE_FILENAME: &str = "bookmarks_store.json";
pub const ROOT_BOOKMARK_BAR: &str = "bookmark_bar";
pub const ROOT_OTHER_BOOKMARKS: &str = "other_bookmarks";
pub const ROOT_MOBILE_BOOKMARKS: &str = "mobile_bookmarks";
pub const ROOT_TRASH: &str = "trash";
pub const MAX_UNDO_HISTORY: usize = 100;
const BOOKMARKS_SCHEMA_VERSION: u32 = 1;

// ============================================================================
// Errors
// ============================================================================

#[derive(Debug, Error)]
pub enum BookmarkError {
    #[error("bookmark node '{0}' not found")]
    NotFound(String),
    #[error("parent node '{0}' is not a folder")]
    ParentNotFolder(String),
    #[error("cannot modify or move protected system root '{0}'")]
    ProtectedSystemRoot(String),
    #[error("cycle detected: cannot move folder '{0}' into its descendant '{1}'")]
    CycleDetected(String, String),
    #[error("node '{0}' is not in the trash")]
    NotInTrash(String),
    #[error("invalid bookmark import data: {0}")]
    InvalidImport(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

// ============================================================================
// Core Tree Model
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BookmarkNodeKind {
    Folder,
    Url,
    Separator,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BookmarkNode {
    pub id: String,
    pub parent_id: Option<String>,
    pub position: usize,
    pub kind: BookmarkNodeKind,
    pub title: String,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub nickname: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub icon_only: bool,
    #[serde(default)]
    pub custom_icon: Option<String>,
    pub created_unix: u64,
    pub updated_unix: u64,
    #[serde(default)]
    pub last_visited_unix: Option<u64>,
    #[serde(default)]
    pub visit_count: u32,
    #[serde(default)]
    pub trashed_from: Option<String>,
    #[serde(default)]
    pub trashed_unix: Option<u64>,
}

/// Input payload for creating a new node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewBookmarkNode {
    pub parent_id: String,
    pub position: Option<usize>,
    pub kind: BookmarkNodeKind,
    pub title: String,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub nickname: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub icon_only: bool,
    #[serde(default)]
    pub custom_icon: Option<String>,
}

/// Partial update patch for an existing node.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BookmarkNodeUpdate {
    pub title: Option<String>,
    pub url: Option<Option<String>>,
    pub nickname: Option<Option<String>>,
    pub description: Option<Option<String>>,
    pub tags: Option<Vec<String>>,
    pub icon_only: Option<bool>,
    pub custom_icon: Option<Option<String>>,
}

/// Dynamic saved query rule for virtual Smart Folders.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SmartFolderRule {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub query: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub domain_contains: Option<String>,
    #[serde(default)]
    pub min_visits: Option<u32>,
    #[serde(default)]
    pub created_after_unix: Option<u64>,
    #[serde(default)]
    pub has_note: bool,
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DuplicateGroup {
    pub canonical_url: String,
    pub node_ids: Vec<String>,
}

/// Recursive portable representation used for JSON/Netscape/Safari tree import & export.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BookmarkTreeNode {
    pub kind: BookmarkNodeKind,
    pub title: String,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub nickname: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub icon_only: bool,
    #[serde(default)]
    pub custom_icon: Option<String>,
    #[serde(default)]
    pub created_unix: Option<u64>,
    #[serde(default)]
    pub updated_unix: Option<u64>,
    #[serde(default)]
    pub is_bookmark_bar: bool,
    #[serde(default)]
    pub children: Vec<BookmarkTreeNode>,
}

// ============================================================================
// BookmarksStore
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BookmarksDiskFormat {
    schema_version: u32,
    next_id: u64,
    nodes: Vec<BookmarkNode>,
    #[serde(default)]
    smart_folders: Vec<SmartFolderRule>,
}

#[derive(Debug, Clone)]
pub struct BookmarksStore {
    nodes: HashMap<String, BookmarkNode>,
    next_id: u64,
    pub smart_folders: Vec<SmartFolderRule>,
    undo_stack: VecDeque<HashMap<String, BookmarkNode>>,
    redo_stack: Vec<HashMap<String, BookmarkNode>>,
}

impl Default for BookmarksStore {
    fn default() -> Self {
        Self::new()
    }
}

impl BookmarksStore {
    pub fn new() -> Self {
        let mut store = Self {
            nodes: HashMap::new(),
            next_id: 1,
            smart_folders: Vec::new(),
            undo_stack: VecDeque::new(),
            redo_stack: Vec::new(),
        };
        store.ensure_system_roots(now_unix_secs());
        store
    }

    pub fn is_system_root(id: &str) -> bool {
        matches!(
            id,
            ROOT_BOOKMARK_BAR | ROOT_OTHER_BOOKMARKS | ROOT_MOBILE_BOOKMARKS | ROOT_TRASH
        )
    }

    pub fn ensure_system_roots(&mut self, ts: u64) {
        let roots = [
            (ROOT_BOOKMARK_BAR, "Bookmarks Bar", 0usize),
            (ROOT_OTHER_BOOKMARKS, "Other Bookmarks", 1usize),
            (ROOT_MOBILE_BOOKMARKS, "Mobile Bookmarks", 2usize),
            (ROOT_TRASH, "Trash", 3usize),
        ];
        for (id, title, pos) in roots {
            self.nodes.entry(id.to_string()).or_insert_with(|| BookmarkNode {
                id: id.to_string(),
                parent_id: None,
                position: pos,
                kind: BookmarkNodeKind::Folder,
                title: title.to_string(),
                url: None,
                nickname: None,
                description: None,
                tags: Vec::new(),
                icon_only: false,
                custom_icon: None,
                created_unix: ts,
                updated_unix: ts,
                last_visited_unix: None,
                visit_count: 0,
                trashed_from: None,
                trashed_unix: None,
            });
        }
    }

    // ------------------------------------------------------------------------
    // Persistence (Atomic write + .bak fallback)
    // ------------------------------------------------------------------------

    pub fn load_from_dir(dir: &Path) -> Result<Self, BookmarkError> {
        Self::load_from_path(&dir.join(BOOKMARKS_STORE_FILENAME))
    }

    pub fn load_from_path(path: &Path) -> Result<Self, BookmarkError> {
        let backup = backup_path_for(path);
        if path.exists() {
            match Self::read_file(path) {
                Ok(s) => return Ok(s),
                Err(_) if backup.exists() => return Self::read_file(&backup),
                Err(e) => return Err(e),
            }
        }
        if backup.exists() {
            return Self::read_file(&backup);
        }
        Ok(Self::new())
    }

    fn read_file(path: &Path) -> Result<Self, BookmarkError> {
        let raw = std::fs::read_to_string(path)?;
        let disk: BookmarksDiskFormat = serde_json::from_str(&raw)?;
        let mut nodes = HashMap::with_capacity(disk.nodes.len());
        for node in disk.nodes {
            nodes.insert(node.id.clone(), node);
        }
        let mut store = Self {
            nodes,
            next_id: disk.next_id.max(1),
            smart_folders: disk.smart_folders,
            undo_stack: VecDeque::new(),
            redo_stack: Vec::new(),
        };
        store.ensure_system_roots(now_unix_secs());
        Ok(store)
    }

    pub fn save_to_dir(&self, dir: &Path) -> Result<PathBuf, BookmarkError> {
        std::fs::create_dir_all(dir)?;
        let path = dir.join(BOOKMARKS_STORE_FILENAME);
        self.save_to_path(&path)?;
        Ok(path)
    }

    pub fn save_to_path(&self, path: &Path) -> Result<(), BookmarkError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut nodes_sorted: Vec<BookmarkNode> = self.nodes.values().cloned().collect();
        nodes_sorted.sort_by(|a, b| a.id.cmp(&b.id));
        let disk = BookmarksDiskFormat {
            schema_version: BOOKMARKS_SCHEMA_VERSION,
            next_id: self.next_id,
            nodes: nodes_sorted,
            smart_folders: self.smart_folders.clone(),
        };
        let bytes = serde_json::to_vec_pretty(&disk)?;
        atomic_write_with_backup(path, &bytes)?;
        Ok(())
    }

    // ------------------------------------------------------------------------
    // Accessors & Undo / Redo (100 operations)
    // ------------------------------------------------------------------------

    pub fn get_node(&self, id: &str) -> Option<&BookmarkNode> {
        self.nodes.get(id)
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    pub fn children_of(&self, parent_id: &str) -> Vec<&BookmarkNode> {
        let mut children: Vec<&BookmarkNode> = self
            .nodes
            .values()
            .filter(|n| n.parent_id.as_deref() == Some(parent_id))
            .collect();
        children.sort_by(|a, b| a.position.cmp(&b.position).then_with(|| a.id.cmp(&b.id)));
        children
    }

    pub fn can_undo(&self) -> bool {
        !self.undo_stack.is_empty()
    }

    pub fn can_redo(&self) -> bool {
        !self.redo_stack.is_empty()
    }

    pub fn undo_len(&self) -> usize {
        self.undo_stack.len()
    }

    pub fn redo_len(&self) -> usize {
        self.redo_stack.len()
    }

    fn push_undo_snapshot(&mut self) {
        if self.undo_stack.len() >= MAX_UNDO_HISTORY {
            self.undo_stack.pop_front();
        }
        self.undo_stack.push_back(self.nodes.clone());
        self.redo_stack.clear();
    }

    pub fn undo(&mut self) -> bool {
        if let Some(prev) = self.undo_stack.pop_back() {
            self.redo_stack.push(self.nodes.clone());
            self.nodes = prev;
            true
        } else {
            false
        }
    }

    pub fn redo(&mut self) -> bool {
        if let Some(next) = self.redo_stack.pop() {
            if self.undo_stack.len() >= MAX_UNDO_HISTORY {
                self.undo_stack.pop_front();
            }
            self.undo_stack.push_back(self.nodes.clone());
            self.nodes = next;
            true
        } else {
            false
        }
    }

    fn alloc_id(&mut self) -> String {
        loop {
            let candidate = format!("bm_{}", self.next_id);
            self.next_id += 1;
            if !self.nodes.contains_key(&candidate) {
                return candidate;
            }
        }
    }

    fn normalize_sibling_positions(&mut self, parent_id: &str) {
        let mut child_ids: Vec<(usize, String)> = self
            .nodes
            .values()
            .filter(|n| n.parent_id.as_deref() == Some(parent_id))
            .map(|n| (n.position, n.id.clone()))
            .collect();
        child_ids.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
        for (idx, (_, cid)) in child_ids.into_iter().enumerate() {
            if let Some(node) = self.nodes.get_mut(&cid) {
                node.position = idx;
            }
        }
    }

    /// Checks whether `candidate_descendant` is `ancestor` or a descendant of `ancestor`.
    fn is_descendant_or_self(&self, ancestor: &str, candidate_descendant: &str) -> bool {
        let mut cursor = Some(candidate_descendant);
        let mut guard = 0usize;
        while let Some(curr) = cursor {
            if curr == ancestor {
                return true;
            }
            guard += 1;
            if guard > self.nodes.len() + 2 {
                return true; // defensive cycle guard
            }
            cursor = self.nodes.get(curr).and_then(|n| n.parent_id.as_deref());
        }
        false
    }

    pub fn is_in_trash(&self, node_id: &str) -> bool {
        node_id != ROOT_TRASH && self.is_descendant_or_self(ROOT_TRASH, node_id)
    }

    // ------------------------------------------------------------------------
    // CRUD, Move (Anti-Cycle), Trash, Sort, Bookmark All Tabs
    // ------------------------------------------------------------------------

    pub fn add_node(&mut self, input: NewBookmarkNode, now_unix: u64) -> Result<String, BookmarkError> {
        let parent = self
            .nodes
            .get(&input.parent_id)
            .ok_or_else(|| BookmarkError::NotFound(input.parent_id.clone()))?;
        if parent.kind != BookmarkNodeKind::Folder {
            return Err(BookmarkError::ParentNotFolder(input.parent_id));
        }

        self.push_undo_snapshot();
        let id = self.insert_node_unchecked(input, now_unix);
        Ok(id)
    }

    fn insert_node_unchecked(&mut self, input: NewBookmarkNode, now_unix: u64) -> String {
        let existing_count = self
            .nodes
            .values()
            .filter(|n| n.parent_id.as_deref() == Some(input.parent_id.as_str()))
            .count();
        let target_pos = input.position.unwrap_or(existing_count).min(existing_count);

        // Shift siblings at >= target_pos
        for node in self.nodes.values_mut() {
            if node.parent_id.as_deref() == Some(input.parent_id.as_str())
                && node.position >= target_pos
            {
                node.position += 1;
            }
        }

        let id = self.alloc_id();
        let clean_tags = normalize_tags(&input.tags);
        let clean_nick = input
            .nickname
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        let node = BookmarkNode {
            id: id.clone(),
            parent_id: Some(input.parent_id.clone()),
            position: target_pos,
            kind: input.kind,
            title: input.title,
            url: input.url,
            nickname: clean_nick,
            description: input.description.filter(|d| !d.trim().is_empty()),
            tags: clean_tags,
            icon_only: input.icon_only,
            custom_icon: input.custom_icon,
            created_unix: now_unix,
            updated_unix: now_unix,
            last_visited_unix: None,
            visit_count: 0,
            trashed_from: None,
            trashed_unix: None,
        };
        self.nodes.insert(id.clone(), node);
        self.normalize_sibling_positions(&input.parent_id);
        id
    }

    pub fn update_node(
        &mut self,
        node_id: &str,
        patch: BookmarkNodeUpdate,
        now_unix: u64,
    ) -> Result<(), BookmarkError> {
        if Self::is_system_root(node_id) {
            return Err(BookmarkError::ProtectedSystemRoot(node_id.to_string()));
        }
        if !self.nodes.contains_key(node_id) {
            return Err(BookmarkError::NotFound(node_id.to_string()));
        }

        self.push_undo_snapshot();
        let node = self.nodes.get_mut(node_id).unwrap();
        if let Some(title) = patch.title {
            node.title = title;
        }
        if let Some(url) = patch.url {
            node.url = url;
        }
        if let Some(nick) = patch.nickname {
            node.nickname = nick.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
        }
        if let Some(desc) = patch.description {
            node.description = desc.filter(|d| !d.trim().is_empty());
        }
        if let Some(tags) = patch.tags {
            node.tags = normalize_tags(&tags);
        }
        if let Some(icon_only) = patch.icon_only {
            node.icon_only = icon_only;
        }
        if let Some(custom_icon) = patch.custom_icon {
            node.custom_icon = custom_icon;
        }
        node.updated_unix = now_unix;
        Ok(())
    }

    /// Moves `node_id` into `new_parent_id` at `new_position`, strictly rejecting cycles
    /// (moving a folder into itself or any of its descendants) and moves of system roots.
    pub fn move_node(
        &mut self,
        node_id: &str,
        new_parent_id: &str,
        new_position: usize,
        now_unix: u64,
    ) -> Result<(), BookmarkError> {
        if Self::is_system_root(node_id) {
            return Err(BookmarkError::ProtectedSystemRoot(node_id.to_string()));
        }
        let node = self
            .nodes
            .get(node_id)
            .ok_or_else(|| BookmarkError::NotFound(node_id.to_string()))?;
        let old_parent_id = node.parent_id.clone();

        let target_parent = self
            .nodes
            .get(new_parent_id)
            .ok_or_else(|| BookmarkError::NotFound(new_parent_id.to_string()))?;
        if target_parent.kind != BookmarkNodeKind::Folder {
            return Err(BookmarkError::ParentNotFolder(new_parent_id.to_string()));
        }

        // Strict anti-cycle check
        if node.kind == BookmarkNodeKind::Folder
            && self.is_descendant_or_self(node_id, new_parent_id)
        {
            return Err(BookmarkError::CycleDetected(
                node_id.to_string(),
                new_parent_id.to_string(),
            ));
        }

        self.push_undo_snapshot();

        // Reorder target siblings excluding `node_id`
        let mut target_siblings: Vec<(usize, String)> = self
            .nodes
            .values()
            .filter(|n| n.parent_id.as_deref() == Some(new_parent_id) && n.id != node_id)
            .map(|n| (n.position, n.id.clone()))
            .collect();
        target_siblings.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
        let insert_idx = new_position.min(target_siblings.len());

        let mut ordered_ids: Vec<String> = target_siblings.into_iter().map(|(_, id)| id).collect();
        ordered_ids.insert(insert_idx, node_id.to_string());

        let target_in_trash =
            new_parent_id == ROOT_TRASH || self.is_descendant_or_self(ROOT_TRASH, new_parent_id);
        if let Some(n) = self.nodes.get_mut(node_id) {
            n.parent_id = Some(new_parent_id.to_string());
            n.updated_unix = now_unix;
            if !target_in_trash {
                n.trashed_from = None;
                n.trashed_unix = None;
            }
        }

        for (pos, cid) in ordered_ids.into_iter().enumerate() {
            if let Some(c) = self.nodes.get_mut(&cid) {
                c.position = pos;
            }
        }

        if let Some(old_p) = old_parent_id {
            if old_p != new_parent_id {
                self.normalize_sibling_positions(&old_p);
            }
        }
        Ok(())
    }

    /// Moves a bookmark or folder into the `trash` root without destroying its subtree.
    pub fn soft_delete(&mut self, node_id: &str, now_unix: u64) -> Result<(), BookmarkError> {
        if Self::is_system_root(node_id) {
            return Err(BookmarkError::ProtectedSystemRoot(node_id.to_string()));
        }
        let old_parent = self
            .nodes
            .get(node_id)
            .ok_or_else(|| BookmarkError::NotFound(node_id.to_string()))?
            .parent_id
            .clone();

        if old_parent.as_deref() == Some(ROOT_TRASH) {
            return Ok(());
        }

        self.push_undo_snapshot();
        let trash_len = self.children_of(ROOT_TRASH).len();
        if let Some(n) = self.nodes.get_mut(node_id) {
            n.trashed_from = old_parent.clone();
            n.trashed_unix = Some(now_unix);
            n.parent_id = Some(ROOT_TRASH.to_string());
            n.position = trash_len;
            n.updated_unix = now_unix;
        }
        if let Some(old_p) = old_parent {
            self.normalize_sibling_positions(&old_p);
        }
        self.normalize_sibling_positions(ROOT_TRASH);
        Ok(())
    }

    /// Restores a trashed node back to its `trashed_from` parent (or `other_bookmarks` if unavailable).
    pub fn restore_from_trash(
        &mut self,
        node_id: &str,
        now_unix: u64,
    ) -> Result<String, BookmarkError> {
        let node = self
            .nodes
            .get(node_id)
            .ok_or_else(|| BookmarkError::NotFound(node_id.to_string()))?;
        if !self.is_in_trash(node_id) {
            return Err(BookmarkError::NotInTrash(node_id.to_string()));
        }

        let target_parent = node
            .trashed_from
            .as_deref()
            .filter(|pid| {
                self.nodes
                    .get(*pid)
                    .map_or(false, |p| p.kind == BookmarkNodeKind::Folder)
                    && !self.is_in_trash(pid)
                    && *pid != ROOT_TRASH
            })
            .unwrap_or(ROOT_OTHER_BOOKMARKS)
            .to_string();

        let old_parent = node.parent_id.clone();
        self.push_undo_snapshot();

        let pos = self.children_of(&target_parent).len();
        if let Some(n) = self.nodes.get_mut(node_id) {
            n.parent_id = Some(target_parent.clone());
            n.position = pos;
            n.trashed_from = None;
            n.trashed_unix = None;
            n.updated_unix = now_unix;
        }
        if let Some(old_p) = old_parent {
            self.normalize_sibling_positions(&old_p);
        }
        self.normalize_sibling_positions(&target_parent);
        Ok(target_parent)
    }

    /// Permanently removes all nodes currently inside `trash` (including nested subtrees).
    pub fn empty_trash(&mut self) -> usize {
        let doomed = self.collect_subtree_ids_under(ROOT_TRASH);
        if doomed.is_empty() {
            return 0;
        }
        self.push_undo_snapshot();
        for id in &doomed {
            self.nodes.remove(id);
        }
        doomed.len()
    }

    /// Permanently removes top-level trashed nodes (and their subtrees) older than `max_age_days`.
    pub fn purge_expired_trash(&mut self, max_age_days: u32, now_unix: u64) -> usize {
        let cutoff = now_unix.saturating_sub((max_age_days as u64) * 86_400);
        let expired_roots: Vec<String> = self
            .nodes
            .values()
            .filter(|n| {
                n.parent_id.as_deref() == Some(ROOT_TRASH)
                    && n.trashed_unix.unwrap_or(n.updated_unix) < cutoff
            })
            .map(|n| n.id.clone())
            .collect();

        if expired_roots.is_empty() {
            return 0;
        }

        let mut doomed = HashSet::new();
        for root_id in expired_roots {
            doomed.insert(root_id.clone());
            for sub in self.collect_subtree_ids_under(&root_id) {
                doomed.insert(sub);
            }
        }

        self.push_undo_snapshot();
        for id in &doomed {
            self.nodes.remove(id);
        }
        self.normalize_sibling_positions(ROOT_TRASH);
        doomed.len()
    }

    fn collect_subtree_ids_under(&self, folder_id: &str) -> Vec<String> {
        let mut out = Vec::new();
        let mut stack = vec![folder_id.to_string()];
        let mut visited = HashSet::new();
        while let Some(curr) = stack.pop() {
            if !visited.insert(curr.clone()) {
                continue;
            }
            for node in self.nodes.values() {
                if node.parent_id.as_deref() == Some(curr.as_str()) {
                    out.push(node.id.clone());
                    if node.kind == BookmarkNodeKind::Folder {
                        stack.push(node.id.clone());
                    }
                }
            }
        }
        out
    }

    /// Sorts children of `folder_id` alphabetically by title (optionally placing folders first).
    pub fn sort_folder_by_name(
        &mut self,
        folder_id: &str,
        folders_first: bool,
    ) -> Result<(), BookmarkError> {
        let folder = self
            .nodes
            .get(folder_id)
            .ok_or_else(|| BookmarkError::NotFound(folder_id.to_string()))?;
        if folder.kind != BookmarkNodeKind::Folder {
            return Err(BookmarkError::ParentNotFolder(folder_id.to_string()));
        }

        self.push_undo_snapshot();
        let mut children: Vec<(BookmarkNodeKind, String, String)> = self
            .nodes
            .values()
            .filter(|n| n.parent_id.as_deref() == Some(folder_id))
            .map(|n| (n.kind, n.title.to_lowercase(), n.id.clone()))
            .collect();

        children.sort_by(|a, b| {
            if folders_first {
                let rank = |k: BookmarkNodeKind| match k {
                    BookmarkNodeKind::Folder => 0u8,
                    BookmarkNodeKind::Url => 1u8,
                    BookmarkNodeKind::Separator => 2u8,
                };
                rank(a.0)
                    .cmp(&rank(b.0))
                    .then_with(|| a.1.cmp(&b.1))
                    .then_with(|| a.2.cmp(&b.2))
            } else {
                a.1.cmp(&b.1).then_with(|| a.2.cmp(&b.2))
            }
        });

        for (pos, (_, _, cid)) in children.into_iter().enumerate() {
            if let Some(n) = self.nodes.get_mut(&cid) {
                n.position = pos;
            }
        }
        Ok(())
    }

    /// Creates a new folder under `parent_id` and bookmarks every `(title, url)` tab inside it
    /// in a single undoable transaction.
    pub fn bookmark_all_tabs(
        &mut self,
        folder_title: &str,
        parent_id: &str,
        tabs: &[(String, String)],
        now_unix: u64,
    ) -> Result<String, BookmarkError> {
        let parent = self
            .nodes
            .get(parent_id)
            .ok_or_else(|| BookmarkError::NotFound(parent_id.to_string()))?;
        if parent.kind != BookmarkNodeKind::Folder {
            return Err(BookmarkError::ParentNotFolder(parent_id.to_string()));
        }

        self.push_undo_snapshot();
        let folder_id = self.insert_node_unchecked(
            NewBookmarkNode {
                parent_id: parent_id.to_string(),
                position: None,
                kind: BookmarkNodeKind::Folder,
                title: folder_title.to_string(),
                url: None,
                nickname: None,
                description: None,
                tags: Vec::new(),
                icon_only: false,
                custom_icon: None,
            },
            now_unix,
        );

        for (idx, (title, url)) in tabs.iter().enumerate() {
            if url.trim().is_empty() {
                continue;
            }
            self.insert_node_unchecked(
                NewBookmarkNode {
                    parent_id: folder_id.clone(),
                    position: Some(idx),
                    kind: BookmarkNodeKind::Url,
                    title: if title.trim().is_empty() {
                        url.clone()
                    } else {
                        title.clone()
                    },
                    url: Some(url.clone()),
                    nickname: None,
                    description: None,
                    tags: Vec::new(),
                    icon_only: false,
                    custom_icon: None,
                },
                now_unix,
            );
        }
        Ok(folder_id)
    }

    pub fn record_visit(&mut self, node_id: &str, now_unix: u64) -> bool {
        if let Some(n) = self.nodes.get_mut(node_id) {
            if n.kind == BookmarkNodeKind::Url {
                n.visit_count = n.visit_count.saturating_add(1);
                n.last_visited_unix = Some(now_unix);
                return true;
            }
        }
        false
    }

    // ------------------------------------------------------------------------
    // Instant Multi-Criteria Search, Smart Folders & Nicknames
    // ------------------------------------------------------------------------

    /// Searches bookmarks using operators `tag:`, `folder:`, `domain:`, `has:note`, `in:trash`
    /// plus free-text matching across title, URL, nickname, description, and tags.
    pub fn search(&self, query: &str) -> Vec<&BookmarkNode> {
        let mut req_tags: Vec<String> = Vec::new();
        let mut req_folder: Option<String> = None;
        let mut req_domain: Option<String> = None;
        let mut req_has_note = false;
        let mut include_trash = false;
        let mut terms: Vec<String> = Vec::new();

        for tok in query.split_whitespace() {
            let lower = tok.to_ascii_lowercase();
            if let Some(t) = lower.strip_prefix("tag:") {
                if !t.is_empty() {
                    req_tags.push(t.to_string());
                }
            } else if let Some(f) = lower.strip_prefix("folder:") {
                if !f.is_empty() {
                    req_folder = Some(f.to_string());
                }
            } else if let Some(d) = lower.strip_prefix("domain:") {
                if !d.is_empty() {
                    req_domain = Some(d.trim_start_matches('.').to_string());
                }
            } else if lower == "has:note" || lower == "has:description" {
                req_has_note = true;
            } else if lower == "in:trash" {
                include_trash = true;
            } else {
                terms.push(lower);
            }
        }

        let mut results: Vec<(i64, &BookmarkNode)> = Vec::new();

        for node in self.nodes.values() {
            if Self::is_system_root(&node.id) || node.kind == BookmarkNodeKind::Separator {
                continue;
            }
            let in_trash = self.is_in_trash(&node.id);
            if in_trash && !include_trash {
                continue;
            }
            if !in_trash && include_trash {
                continue;
            }

            if req_has_note
                && node
                    .description
                    .as_deref()
                    .map_or(true, |d| d.trim().is_empty())
            {
                continue;
            }

            if !req_tags.is_empty() {
                let ok = req_tags.iter().all(|rt| {
                    node.tags
                        .iter()
                        .any(|nt| nt.to_ascii_lowercase() == *rt)
                });
                if !ok {
                    continue;
                }
            }

            if let Some(ref f_filter) = req_folder {
                if !self.has_ancestor_matching_folder(&node.id, f_filter) {
                    continue;
                }
            }

            if let Some(ref d_filter) = req_domain {
                let dom = node
                    .url
                    .as_deref()
                    .map(extract_url_host)
                    .unwrap_or_default();
                if dom != *d_filter && !dom.ends_with(&format!(".{}", d_filter)) {
                    continue;
                }
            }

            let mut score = (node.visit_count as i64) * 5;
            if !terms.is_empty() {
                let title_l = node.title.to_lowercase();
                let url_l = node.url.as_deref().unwrap_or("").to_lowercase();
                let nick_l = node.nickname.as_deref().unwrap_or("").to_lowercase();
                let desc_l = node.description.as_deref().unwrap_or("").to_lowercase();
                let tags_l = node.tags.join(" ").to_lowercase();

                let mut matched_all = true;
                for term in &terms {
                    if nick_l == *term {
                        score += 200;
                    } else if title_l.contains(term) {
                        score += 100;
                    } else if url_l.contains(term) {
                        score += 65;
                    } else if tags_l.contains(term) {
                        score += 55;
                    } else if desc_l.contains(term) {
                        score += 40;
                    } else {
                        matched_all = false;
                        break;
                    }
                }
                if !matched_all {
                    continue;
                }
            }

            results.push((score, node));
        }

        results.sort_by(|a, b| {
            b.0.cmp(&a.0)
                .then_with(|| b.1.visit_count.cmp(&a.1.visit_count))
                .then_with(|| a.1.title.cmp(&b.1.title))
        });
        results.into_iter().map(|(_, n)| n).collect()
    }

    fn has_ancestor_matching_folder(&self, node_id: &str, filter_lower: &str) -> bool {
        let mut cursor = self.nodes.get(node_id).and_then(|n| n.parent_id.as_deref());
        let mut guard = 0usize;
        while let Some(pid) = cursor {
            if let Some(folder) = self.nodes.get(pid) {
                if folder.id.to_ascii_lowercase() == filter_lower
                    || folder.title.to_lowercase().contains(filter_lower)
                {
                    return true;
                }
                cursor = folder.parent_id.as_deref();
            } else {
                break;
            }
            guard += 1;
            if guard > 256 {
                break;
            }
        }
        false
    }

    /// Evaluates a dynamic `SmartFolderRule` over non-trashed URL bookmarks.
    pub fn evaluate_smart_folder(&self, rule: &SmartFolderRule) -> Vec<&BookmarkNode> {
        let base = if rule.query.trim().is_empty() {
            self.nodes
                .values()
                .filter(|n| n.kind == BookmarkNodeKind::Url && !self.is_in_trash(&n.id))
                .collect::<Vec<_>>()
        } else {
            self.search(&rule.query)
                .into_iter()
                .filter(|n| n.kind == BookmarkNodeKind::Url)
                .collect()
        };

        let mut filtered: Vec<&BookmarkNode> = base
            .into_iter()
            .filter(|n| {
                if rule.has_note
                    && n.description
                        .as_deref()
                        .map_or(true, |d| d.trim().is_empty())
                {
                    return false;
                }
                if let Some(min_v) = rule.min_visits {
                    if n.visit_count < min_v {
                        return false;
                    }
                }
                if let Some(after) = rule.created_after_unix {
                    if n.created_unix < after {
                        return false;
                    }
                }
                if let Some(ref dom_sub) = rule.domain_contains {
                    let dom = n.url.as_deref().map(extract_url_host).unwrap_or_default();
                    if !dom.contains(&dom_sub.to_ascii_lowercase()) {
                        return false;
                    }
                }
                if !rule.tags.is_empty() {
                    let ok = rule.tags.iter().all(|rt| {
                        let rtl = rt.to_ascii_lowercase();
                        n.tags.iter().any(|t| t.to_ascii_lowercase() == rtl)
                    });
                    if !ok {
                        return false;
                    }
                }
                true
            })
            .collect();

        filtered.sort_by(|a, b| {
            b.visit_count
                .cmp(&a.visit_count)
                .then_with(|| b.updated_unix.cmp(&a.updated_unix))
        });
        if let Some(limit) = rule.limit {
            filtered.truncate(limit);
        }
        filtered
    }

    /// Resolves a bookmark nickname query such as `"gh"` or `"rs HashMap"` (substituting
    /// `%s` or `{searchTerms}` with percent-encoded query arguments).
    pub fn resolve_nickname(&self, query: &str) -> Option<String> {
        let trimmed = query.trim();
        if trimmed.is_empty() {
            return None;
        }
        let (nick_token, arg) = match trimmed.split_once(char::is_whitespace) {
            Some((k, rest)) => (k.trim(), Some(rest.trim())),
            None => (trimmed, None),
        };

        for node in self.nodes.values() {
            if node.kind != BookmarkNodeKind::Url || self.is_in_trash(&node.id) {
                continue;
            }
            let Some(ref nick) = node.nickname else {
                continue;
            };
            if nick.eq_ignore_ascii_case(nick_token) {
                let url = node.url.as_deref()?;
                if let Some(arg_str) = arg {
                    let encoded = percent_encode_arg(arg_str);
                    if url.contains("%s") {
                        return Some(url.replace("%s", &encoded));
                    } else if url.contains("{searchTerms}") {
                        return Some(url.replace("{searchTerms}", &encoded));
                    }
                    // Bookmark has no placeholder; only match if no extra argument was provided
                    return None;
                } else {
                    return Some(url.to_string());
                }
            }
        }
        None
    }

    // ------------------------------------------------------------------------
    // Duplicate Detection & Merging (with URL Canonicalization)
    // ------------------------------------------------------------------------

    /// Finds groups of 2+ non-trashed URL bookmarks sharing the same canonical URL.
    pub fn find_duplicate_groups(&self) -> Vec<DuplicateGroup> {
        let mut by_canon: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for node in self.nodes.values() {
            if node.kind != BookmarkNodeKind::Url || self.is_in_trash(&node.id) {
                continue;
            }
            if let Some(ref url) = node.url {
                let canon = canonicalize_bookmark_url(url);
                if !canon.is_empty() {
                    by_canon.entry(canon).or_default().push(node.id.clone());
                }
            }
        }

        by_canon
            .into_iter()
            .filter_map(|(canonical_url, mut node_ids)| {
                if node_ids.len() >= 2 {
                    node_ids.sort();
                    Some(DuplicateGroup {
                        canonical_url,
                        node_ids,
                    })
                } else {
                    None
                }
            })
            .collect()
    }

    /// Merges all duplicate bookmark groups in a single undoable transaction, preserving tags,
    /// nickname, description, and combined visit counts on the highest-priority survivor.
    /// Returns the number of duplicate nodes removed.
    pub fn merge_duplicates(&mut self, now_unix: u64) -> usize {
        let groups = self.find_duplicate_groups();
        if groups.is_empty() {
            return 0;
        }

        self.push_undo_snapshot();
        let mut affected_parents: HashSet<String> = HashSet::new();
        let mut removed_count = 0usize;

        for group in groups {
            // Choose survivor: prefer bookmark_bar, then highest visit_count, then earliest created
            let mut candidates: Vec<&BookmarkNode> = group
                .node_ids
                .iter()
                .filter_map(|id| self.nodes.get(id))
                .collect();
            if candidates.len() < 2 {
                continue;
            }
            candidates.sort_by(|a, b| {
                let a_bar = u8::from(self.is_descendant_or_self(ROOT_BOOKMARK_BAR, &a.id));
                let b_bar = u8::from(self.is_descendant_or_self(ROOT_BOOKMARK_BAR, &b.id));
                b_bar
                    .cmp(&a_bar)
                    .then_with(|| b.visit_count.cmp(&a.visit_count))
                    .then_with(|| a.created_unix.cmp(&b.created_unix))
                    .then_with(|| a.id.cmp(&b.id))
            });

            let keeper_id = candidates[0].id.clone();
            let dup_ids: Vec<String> = candidates[1..].iter().map(|n| n.id.clone()).collect();

            let mut merged_tags: Vec<String> = candidates[0].tags.clone();
            let mut merged_nick = candidates[0].nickname.clone();
            let mut merged_desc = candidates[0].description.clone();
            let mut merged_visits = candidates[0].visit_count;
            let mut merged_last_visit = candidates[0].last_visited_unix;

            for dup_id in &dup_ids {
                if let Some(dup) = self.nodes.remove(dup_id) {
                    if let Some(pid) = dup.parent_id {
                        affected_parents.insert(pid);
                    }
                    merged_tags.extend(dup.tags);
                    if merged_nick.is_none() && dup.nickname.is_some() {
                        merged_nick = dup.nickname;
                    }
                    if merged_desc.is_none() && dup.description.is_some() {
                        merged_desc = dup.description;
                    }
                    merged_visits = merged_visits.saturating_add(dup.visit_count);
                    merged_last_visit = match (merged_last_visit, dup.last_visited_unix) {
                        (Some(a), Some(b)) => Some(a.max(b)),
                        (a, b) => a.or(b),
                    };
                    removed_count += 1;
                }
            }

            if let Some(keeper) = self.nodes.get_mut(&keeper_id) {
                keeper.tags = normalize_tags(&merged_tags);
                keeper.nickname = merged_nick;
                keeper.description = merged_desc;
                keeper.visit_count = merged_visits;
                keeper.last_visited_unix = merged_last_visit;
                keeper.updated_unix = now_unix;
            }
        }

        for pid in affected_parents {
            self.normalize_sibling_positions(&pid);
        }
        removed_count
    }

    // ------------------------------------------------------------------------
    // High-Fidelity Export & Import (Netscape HTML, JSON Tree, Safari Plist XML)
    // ------------------------------------------------------------------------

    /// Recursively exports the bookmark tree (excluding `trash`) to Netscape Bookmark File 1 HTML,
    /// preserving folders, `PERSONAL_TOOLBAR_FOLDER`, `ADD_DATE`, `LAST_MODIFIED`, `TAGS`,
    /// `SHORTCUTURL` (nickname), `ICON`, `<DD>` descriptions, and `<HR>` separators.
    pub fn export_netscape_html_tree(&self) -> String {
        let mut out = String::from(
            "<!DOCTYPE NETSCAPE-Bookmark-file-1>\n\
             <!-- This is an automatically generated file. -->\n\
             <META HTTP-EQUIV=\"Content-Type\" CONTENT=\"text/html; charset=UTF-8\">\n\
             <TITLE>Bookmarks</TITLE>\n\
             <H1>Bookmarks</H1>\n\
             <DL><p>\n",
        );

        // Export Bookmark Bar as PERSONAL_TOOLBAR_FOLDER="true"
        if let Some(bar) = self.nodes.get(ROOT_BOOKMARK_BAR) {
            out.push_str(&format!(
                "    <DT><H3 ADD_DATE=\"{}\" LAST_MODIFIED=\"{}\" PERSONAL_TOOLBAR_FOLDER=\"true\">{}</H3>\n",
                bar.created_unix,
                bar.updated_unix,
                html_escape(&bar.title)
            ));
            out.push_str("    <DL><p>\n");
            self.write_netscape_children(ROOT_BOOKMARK_BAR, 2, &mut out);
            out.push_str("    </DL><p>\n");
        }

        // Export Other Bookmarks directly inside root DL
        self.write_netscape_children(ROOT_OTHER_BOOKMARKS, 1, &mut out);

        // Export Mobile Bookmarks folder if non-empty
        if !self.children_of(ROOT_MOBILE_BOOKMARKS).is_empty() {
            if let Some(mob) = self.nodes.get(ROOT_MOBILE_BOOKMARKS) {
                out.push_str(&format!(
                    "    <DT><H3 ADD_DATE=\"{}\" LAST_MODIFIED=\"{}\">{}</H3>\n",
                    mob.created_unix,
                    mob.updated_unix,
                    html_escape(&mob.title)
                ));
                out.push_str("    <DL><p>\n");
                self.write_netscape_children(ROOT_MOBILE_BOOKMARKS, 2, &mut out);
                out.push_str("    </DL><p>\n");
            }
        }

        out.push_str("</DL><p>\n");
        out
    }

    fn write_netscape_children(&self, parent_id: &str, depth: usize, out: &mut String) {
        let indent = "    ".repeat(depth);
        for child in self.children_of(parent_id) {
            match child.kind {
                BookmarkNodeKind::Separator => {
                    out.push_str(&format!("{}<HR>\n", indent));
                }
                BookmarkNodeKind::Folder => {
                    out.push_str(&format!(
                        "{}<DT><H3 ADD_DATE=\"{}\" LAST_MODIFIED=\"{}\">{}</H3>\n",
                        indent,
                        child.created_unix,
                        child.updated_unix,
                        html_escape(&child.title)
                    ));
                    if let Some(ref desc) = child.description {
                        out.push_str(&format!("{}<DD>{}\n", indent, html_escape(desc)));
                    }
                    out.push_str(&format!("{}<DL><p>\n", indent));
                    self.write_netscape_children(&child.id, depth + 1, out);
                    out.push_str(&format!("{}</DL><p>\n", indent));
                }
                BookmarkNodeKind::Url => {
                    let href = child.url.as_deref().unwrap_or("");
                    out.push_str(&format!(
                        "{}<DT><A HREF=\"{}\" ADD_DATE=\"{}\" LAST_MODIFIED=\"{}\"",
                        indent,
                        html_escape(href),
                        child.created_unix,
                        child.updated_unix
                    ));
                    if !child.tags.is_empty() {
                        out.push_str(&format!(
                            " TAGS=\"{}\"",
                            html_escape(&child.tags.join(","))
                        ));
                    }
                    if let Some(ref nick) = child.nickname {
                        out.push_str(&format!(" SHORTCUTURL=\"{}\"", html_escape(nick)));
                    }
                    if let Some(ref icon) = child.custom_icon {
                        out.push_str(&format!(" ICON=\"{}\"", html_escape(icon)));
                    }
                    out.push_str(&format!(">{}</A>\n", html_escape(&child.title)));
                    if let Some(ref desc) = child.description {
                        out.push_str(&format!("{}<DD>{}\n", indent, html_escape(desc)));
                    }
                }
            }
        }
    }

    /// Exports the non-trashed bookmark hierarchy as a pretty-printed portable JSON tree.
    pub fn export_json_tree(&self) -> Result<String, BookmarkError> {
        let mut roots = Vec::new();
        for &(rid, is_bar) in &[
            (ROOT_BOOKMARK_BAR, true),
            (ROOT_OTHER_BOOKMARKS, false),
            (ROOT_MOBILE_BOOKMARKS, false),
        ] {
            if let Some(r) = self.nodes.get(rid) {
                roots.push(self.build_tree_node(r, is_bar));
            }
        }
        Ok(serde_json::to_string_pretty(&roots)?)
    }

    fn build_tree_node(&self, node: &BookmarkNode, is_bookmark_bar: bool) -> BookmarkTreeNode {
        let children = if node.kind == BookmarkNodeKind::Folder {
            self.children_of(&node.id)
                .into_iter()
                .map(|c| self.build_tree_node(c, false))
                .collect()
        } else {
            Vec::new()
        };
        BookmarkTreeNode {
            kind: node.kind,
            title: node.title.clone(),
            url: node.url.clone(),
            nickname: node.nickname.clone(),
            description: node.description.clone(),
            tags: node.tags.clone(),
            icon_only: node.icon_only,
            custom_icon: node.custom_icon.clone(),
            created_unix: Some(node.created_unix),
            updated_unix: Some(node.updated_unix),
            is_bookmark_bar,
            children,
        }
    }

    /// Imports a JSON tree (produced by `export_json_tree`) under `target_parent_id`.
    pub fn import_json_tree(
        &mut self,
        json: &str,
        target_parent_id: &str,
        now_unix: u64,
    ) -> Result<usize, BookmarkError> {
        let trees: Vec<BookmarkTreeNode> = serde_json::from_str(json)?;
        self.import_tree_nodes(&trees, target_parent_id, now_unix)
    }

    /// Imports parsed Netscape HTML bookmarks into `target_parent_id` (routing
    /// `PERSONAL_TOOLBAR_FOLDER="true"` folders to `bookmark_bar` when `route_toolbar` is true).
    pub fn import_netscape_html(
        &mut self,
        html: &str,
        target_parent_id: &str,
        route_toolbar: bool,
        now_unix: u64,
    ) -> Result<usize, BookmarkError> {
        let trees = parse_netscape_html_tree(html)?;
        if !self.nodes.contains_key(target_parent_id) {
            return Err(BookmarkError::NotFound(target_parent_id.to_string()));
        }
        self.push_undo_snapshot();
        let mut count = 0usize;
        for node in &trees {
            if route_toolbar && node.is_bookmark_bar && node.kind == BookmarkNodeKind::Folder {
                for child in &node.children {
                    count += self.insert_tree_recursive(child, ROOT_BOOKMARK_BAR, now_unix);
                }
            } else {
                count += self.insert_tree_recursive(node, target_parent_id, now_unix);
            }
        }
        Ok(count)
    }

    /// Imports Safari XML Plist bookmarks under `target_parent_id`.
    pub fn import_safari_plist_xml(
        &mut self,
        xml: &str,
        target_parent_id: &str,
        now_unix: u64,
    ) -> Result<usize, BookmarkError> {
        let trees = parse_safari_bookmarks_plist_xml(xml)?;
        self.import_tree_nodes(&trees, target_parent_id, now_unix)
    }

    pub fn import_tree_nodes(
        &mut self,
        trees: &[BookmarkTreeNode],
        target_parent_id: &str,
        now_unix: u64,
    ) -> Result<usize, BookmarkError> {
        let parent = self
            .nodes
            .get(target_parent_id)
            .ok_or_else(|| BookmarkError::NotFound(target_parent_id.to_string()))?;
        if parent.kind != BookmarkNodeKind::Folder {
            return Err(BookmarkError::ParentNotFolder(target_parent_id.to_string()));
        }

        self.push_undo_snapshot();
        let mut count = 0usize;
        for tree in trees {
            count += self.insert_tree_recursive(tree, target_parent_id, now_unix);
        }
        Ok(count)
    }

    fn insert_tree_recursive(
        &mut self,
        tree: &BookmarkTreeNode,
        parent_id: &str,
        now_unix: u64,
    ) -> usize {
        let created = tree.created_unix.unwrap_or(now_unix);
        let updated = tree.updated_unix.unwrap_or(created);
        let id = self.insert_node_unchecked(
            NewBookmarkNode {
                parent_id: parent_id.to_string(),
                position: None,
                kind: tree.kind,
                title: tree.title.clone(),
                url: tree.url.clone(),
                nickname: tree.nickname.clone(),
                description: tree.description.clone(),
                tags: tree.tags.clone(),
                icon_only: tree.icon_only,
                custom_icon: tree.custom_icon.clone(),
            },
            created,
        );
        if let Some(n) = self.nodes.get_mut(&id) {
            n.updated_unix = updated;
        }
        let mut total = 1usize;
        if tree.kind == BookmarkNodeKind::Folder {
            for child in &tree.children {
                total += self.insert_tree_recursive(child, &id, now_unix);
            }
        }
        total
    }
}

// ============================================================================
// URL Canonicalization (for Duplicate Detection)
// ============================================================================

/// Canonicalizes a URL for duplicate detection:
/// - Normalizes `http://` -> `https://`
/// - Lowercases scheme & host, strips leading `www.`
/// - Strips default ports `:80` / `:443`
/// - Removes trailing `/` on non-root paths
/// - Removes common tracking query parameters (`utm_*`, `fbclid`, `gclid`, etc.) and sorts remaining params.
pub fn canonicalize_bookmark_url(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    let (scheme, rest) = match trimmed.split_once("://") {
        Some((s, r)) => (s.to_ascii_lowercase(), r),
        None => ("https".to_string(), trimmed),
    };
    let norm_scheme = if scheme == "http" {
        "https".to_string()
    } else {
        scheme
    };

    // Strip fragment
    let before_hash = rest.split('#').next().unwrap_or(rest);
    let (before_query, query_opt) = match before_hash.split_once('?') {
        Some((bq, q)) => (bq, Some(q)),
        None => (before_hash, None),
    };

    let (authority, path_raw) = match before_query.find('/') {
        Some(idx) => (&before_query[..idx], &before_query[idx..]),
        None => (before_query, "/"),
    };

    let host_port = authority
        .rsplit_once('@')
        .map(|(_, hp)| hp)
        .unwrap_or(authority);
    let (host, port_opt) = if host_port.starts_with('[') {
        match host_port.find(']') {
            Some(end) => (
                host_port[..=end].to_ascii_lowercase(),
                host_port[end + 1..].strip_prefix(':'),
            ),
            None => (host_port.to_ascii_lowercase(), None),
        }
    } else {
        match host_port.rsplit_once(':') {
            Some((h, p)) if p.parse::<u16>().is_ok() => (h.to_ascii_lowercase(), Some(p)),
            _ => (host_port.to_ascii_lowercase(), None),
        }
    };

    let clean_host = host.trim_start_matches("www.");
    let clean_port = match port_opt {
        Some("80") | Some("443") | None => String::new(),
        Some(p) => format!(":{}", p),
    };

    let mut clean_path = path_raw.to_string();
    while clean_path.len() > 1 && clean_path.ends_with('/') {
        clean_path.pop();
    }
    if clean_path.is_empty() {
        clean_path.push('/');
    }

    let clean_query = if let Some(q) = query_opt {
        let mut pairs: Vec<(&str, &str)> = q
            .split('&')
            .filter(|p| !p.is_empty())
            .map(|p| p.split_once('=').unwrap_or((p, "")))
            .filter(|(k, _)| !is_tracking_param(k))
            .collect();
        pairs.sort();
        if pairs.is_empty() {
            String::new()
        } else {
            let joined = pairs
                .into_iter()
                .map(|(k, v)| {
                    if v.is_empty() {
                        k.to_string()
                    } else {
                        format!("{}={}", k, v)
                    }
                })
                .collect::<Vec<_>>()
                .join("&");
            format!("?{}", joined)
        }
    } else {
        String::new()
    };

    format!(
        "{}://{}{}{}{}",
        norm_scheme, clean_host, clean_port, clean_path, clean_query
    )
}

fn is_tracking_param(key: &str) -> bool {
    let k = key.to_ascii_lowercase();
    k.starts_with("utm_")
        || matches!(
            k.as_str(),
            "fbclid"
                | "gclid"
                | "dclid"
                | "gbraid"
                | "wbraid"
                | "msclkid"
                | "mc_cid"
                | "mc_eid"
                | "igshid"
                | "igsh"
                | "si"
                | "yclid"
                | "_hsenc"
                | "_hsmi"
                | "ref_src"
                | "ref_url"
                | "spm"
                | "mkt_tok"
        )
}

// ============================================================================
// Netscape HTML Bookmarks State-Machine Parser
// ============================================================================

#[derive(Debug)]
enum HtmlToken<'a> {
    OpenTag { name: String, raw: &'a str },
    CloseTag { name: String },
    Text(&'a str),
}

fn tokenize_html_loose(html: &str) -> Vec<HtmlToken<'_>> {
    let mut tokens = Vec::new();
    let bytes = html.as_bytes();
    let mut i = 0;
    let mut text_start = 0;

    while i < bytes.len() {
        if bytes[i] == b'<' {
            if i > text_start {
                tokens.push(HtmlToken::Text(&html[text_start..i]));
            }
            // Comment <!-- ... -->
            if html[i..].starts_with("<!--") {
                if let Some(end_rel) = html[i + 4..].find("-->") {
                    i = i + 4 + end_rel + 3;
                    text_start = i;
                    continue;
                } else {
                    break;
                }
            }
            // Find closing '>' respecting quotes
            let tag_start = i;
            let mut j = i + 1;
            let mut in_quote: Option<u8> = None;
            while j < bytes.len() {
                let b = bytes[j];
                if let Some(q) = in_quote {
                    if b == q {
                        in_quote = None;
                    }
                } else if b == b'"' || b == b'\'' {
                    in_quote = Some(b);
                } else if b == b'>' {
                    break;
                }
                j += 1;
            }
            if j >= bytes.len() {
                break;
            }
            let raw_tag = &html[tag_start..=j];
            let inner = raw_tag[1..raw_tag.len() - 1].trim();
            if let Some(close_rest) = inner.strip_prefix('/') {
                let name = close_rest
                    .split(|c: char| c.is_whitespace() || c == '/')
                    .next()
                    .unwrap_or("")
                    .to_ascii_lowercase();
                if !name.is_empty() {
                    tokens.push(HtmlToken::CloseTag { name });
                }
            } else if !inner.starts_with('!') && !inner.starts_with('?') {
                let name = inner
                    .split(|c: char| c.is_whitespace() || c == '/')
                    .next()
                    .unwrap_or("")
                    .to_ascii_lowercase();
                if !name.is_empty() {
                    tokens.push(HtmlToken::OpenTag { name, raw: raw_tag });
                }
            }
            i = j + 1;
            text_start = i;
        } else {
            i += 1;
        }
    }
    if text_start < bytes.len() {
        tokens.push(HtmlToken::Text(&html[text_start..]));
    }
    tokens
}

/// Parses a Netscape Bookmark File 1 HTML document into a full recursive `BookmarkTreeNode` forest.
/// Preserves 100% of folders, dates (`ADD_DATE`, `LAST_MODIFIED`), `TAGS`, `SHORTCUTURL` nicknames,
/// `ICON`, `<DD>` descriptions, and `<HR>` separators.
pub fn parse_netscape_html_tree(html: &str) -> Result<Vec<BookmarkTreeNode>, BookmarkError> {
    if html.len() > 32 * 1024 * 1024 {
        return Err(BookmarkError::InvalidImport(
            "Netscape HTML file exceeds 32 MiB limit".into(),
        ));
    }

    let tokens = tokenize_html_loose(html);
    let mut stack: Vec<Vec<BookmarkTreeNode>> = vec![Vec::new()];
    let mut pending_folder: Option<BookmarkTreeNode> = None;
    let mut in_h3 = false;
    let mut h3_buf = String::new();
    let mut in_a = false;
    let mut a_buf = String::new();
    let mut current_a_node: Option<BookmarkTreeNode> = None;
    let mut in_dd = false;
    let mut dd_buf = String::new();

    let flush_dd = |in_dd: &mut bool,
                    dd_buf: &mut String,
                    pending_folder: &mut Option<BookmarkTreeNode>,
                    stack: &mut [Vec<BookmarkTreeNode>]| {
        if *in_dd {
            let desc = html_unescape(dd_buf.trim());
            if !desc.is_empty() {
                if let Some(ref mut pf) = pending_folder {
                    pf.description = Some(desc);
                } else if let Some(top) = stack.last_mut() {
                    if let Some(last_node) = top.last_mut() {
                        last_node.description = Some(desc);
                    }
                }
            }
            dd_buf.clear();
            *in_dd = false;
        }
    };

    for tok in tokens {
        match tok {
            HtmlToken::OpenTag { name, raw } => match name.as_str() {
                "dl" => {
                    flush_dd(&mut in_dd, &mut dd_buf, &mut pending_folder, &mut stack);
                    if let Some(folder) = pending_folder.take() {
                        if let Some(top) = stack.last_mut() {
                            top.push(folder);
                        }
                        stack.push(Vec::new());
                    }
                }
                "dt" => {
                    flush_dd(&mut in_dd, &mut dd_buf, &mut pending_folder, &mut stack);
                    // Flush orphan empty folder if another <DT> appeared before <DL>
                    if let Some(orphan_folder) = pending_folder.take() {
                        if let Some(top) = stack.last_mut() {
                            top.push(orphan_folder);
                        }
                    }
                }
                "hr" => {
                    flush_dd(&mut in_dd, &mut dd_buf, &mut pending_folder, &mut stack);
                    if let Some(orphan_folder) = pending_folder.take() {
                        if let Some(top) = stack.last_mut() {
                            top.push(orphan_folder);
                        }
                    }
                    if let Some(top) = stack.last_mut() {
                        top.push(BookmarkTreeNode {
                            kind: BookmarkNodeKind::Separator,
                            title: String::new(),
                            url: None,
                            nickname: None,
                            description: None,
                            tags: Vec::new(),
                            icon_only: false,
                            custom_icon: None,
                            created_unix: None,
                            updated_unix: None,
                            is_bookmark_bar: false,
                            children: Vec::new(),
                        });
                    }
                }
                "h3" => {
                    flush_dd(&mut in_dd, &mut dd_buf, &mut pending_folder, &mut stack);
                    let add_date = extract_html_attr(raw, "add_date")
                        .and_then(|v| v.parse::<u64>().ok());
                    let last_mod = extract_html_attr(raw, "last_modified")
                        .and_then(|v| v.parse::<u64>().ok());
                    let is_bar = extract_html_attr(raw, "personal_toolbar_folder")
                        .map_or(false, |v| v.eq_ignore_ascii_case("true"));
                    pending_folder = Some(BookmarkTreeNode {
                        kind: BookmarkNodeKind::Folder,
                        title: String::new(),
                        url: None,
                        nickname: None,
                        description: None,
                        tags: Vec::new(),
                        icon_only: false,
                        custom_icon: None,
                        created_unix: add_date,
                        updated_unix: last_mod,
                        is_bookmark_bar: is_bar,
                        children: Vec::new(),
                    });
                    in_h3 = true;
                    h3_buf.clear();
                }
                "a" => {
                    flush_dd(&mut in_dd, &mut dd_buf, &mut pending_folder, &mut stack);
                    let href = extract_html_attr(raw, "href").map(|s| html_unescape(&s));
                    let add_date = extract_html_attr(raw, "add_date")
                        .and_then(|v| v.parse::<u64>().ok());
                    let last_mod = extract_html_attr(raw, "last_modified")
                        .and_then(|v| v.parse::<u64>().ok());
                    let tags: Vec<String> = extract_html_attr(raw, "tags")
                        .map(|t| {
                            html_unescape(&t)
                                .split(',')
                                .map(|x| x.trim().to_string())
                                .filter(|x| !x.is_empty())
                                .collect()
                        })
                        .unwrap_or_default();
                    let nickname = extract_html_attr(raw, "shortcuturl")
                        .map(|s| html_unescape(&s))
                        .filter(|s| !s.trim().is_empty());
                    let custom_icon = extract_html_attr(raw, "icon")
                        .or_else(|| extract_html_attr(raw, "icon_uri"))
                        .map(|s| html_unescape(&s))
                        .filter(|s| !s.trim().is_empty());

                    current_a_node = Some(BookmarkTreeNode {
                        kind: BookmarkNodeKind::Url,
                        title: String::new(),
                        url: href,
                        nickname,
                        description: None,
                        tags: normalize_tags(&tags),
                        icon_only: false,
                        custom_icon,
                        created_unix: add_date,
                        updated_unix: last_mod,
                        is_bookmark_bar: false,
                        children: Vec::new(),
                    });
                    in_a = true;
                    a_buf.clear();
                }
                "dd" => {
                    flush_dd(&mut in_dd, &mut dd_buf, &mut pending_folder, &mut stack);
                    in_dd = true;
                    dd_buf.clear();
                }
                "p" => {
                    // <p> terminates any open <DD>
                    flush_dd(&mut in_dd, &mut dd_buf, &mut pending_folder, &mut stack);
                }
                _ => {}
            },
            HtmlToken::CloseTag { name } => match name.as_str() {
                "h3" => {
                    if in_h3 {
                        if let Some(ref mut pf) = pending_folder {
                            pf.title = html_unescape(h3_buf.trim());
                        }
                        in_h3 = false;
                        h3_buf.clear();
                    }
                }
                "a" => {
                    if in_a {
                        if let Some(mut node) = current_a_node.take() {
                            node.title = html_unescape(a_buf.trim());
                            if node.title.is_empty() {
                                node.title = node.url.clone().unwrap_or_default();
                            }
                            if let Some(top) = stack.last_mut() {
                                top.push(node);
                            }
                        }
                        in_a = false;
                        a_buf.clear();
                    }
                }
                "dd" => {
                    flush_dd(&mut in_dd, &mut dd_buf, &mut pending_folder, &mut stack);
                }
                "dl" => {
                    flush_dd(&mut in_dd, &mut dd_buf, &mut pending_folder, &mut stack);
                    if let Some(orphan) = pending_folder.take() {
                        if let Some(top) = stack.last_mut() {
                            top.push(orphan);
                        }
                    }
                    if stack.len() > 1 {
                        let children = stack.pop().unwrap_or_default();
                        if let Some(parent_list) = stack.last_mut() {
                            if let Some(parent_folder) = parent_list.last_mut() {
                                if parent_folder.kind == BookmarkNodeKind::Folder {
                                    parent_folder.children = children;
                                } else {
                                    parent_list.extend(children);
                                }
                            }
                        }
                    }
                }
                _ => {}
            },
            HtmlToken::Text(txt) => {
                if in_h3 {
                    h3_buf.push_str(txt);
                } else if in_a {
                    a_buf.push_str(txt);
                } else if in_dd {
                    dd_buf.push_str(txt);
                }
            }
        }
    }

    flush_dd(&mut in_dd, &mut dd_buf, &mut pending_folder, &mut stack);
    if let Some(orphan) = pending_folder.take() {
        if let Some(top) = stack.last_mut() {
            top.push(orphan);
        }
    }
    while stack.len() > 1 {
        let children = stack.pop().unwrap_or_default();
        if let Some(parent_list) = stack.last_mut() {
            if let Some(pf) = parent_list.last_mut() {
                pf.children = children;
            }
        }
    }

    Ok(stack.pop().unwrap_or_default())
}

// ============================================================================
// Safari Bookmarks XML Plist Parser
// ============================================================================

#[derive(Debug, Clone)]
enum PlistValue {
    Dict(HashMap<String, PlistValue>),
    Array(Vec<PlistValue>),
    String(String),
    Other,
}

impl PlistValue {
    fn as_dict(&self) -> Option<&HashMap<String, PlistValue>> {
        match self {
            Self::Dict(d) => Some(d),
            _ => None,
        }
    }
    fn as_array(&self) -> Option<&[PlistValue]> {
        match self {
            Self::Array(a) => Some(a),
            _ => None,
        }
    }
    fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(s.as_str()),
            _ => None,
        }
    }
}

/// Parses a Safari `Bookmarks.plist` XML file (`WebBookmarkTypeList` & `WebBookmarkTypeLeaf`)
/// into a recursive `BookmarkTreeNode` forest.
pub fn parse_safari_bookmarks_plist_xml(xml: &str) -> Result<Vec<BookmarkTreeNode>, BookmarkError> {
    if xml.len() > 32 * 1024 * 1024 {
        return Err(BookmarkError::InvalidImport(
            "Safari plist XML exceeds 32 MiB limit".into(),
        ));
    }
    if xml.to_ascii_uppercase().contains("<!ENTITY") {
        return Err(BookmarkError::InvalidImport(
            "XML ENTITY declarations are rejected for security".into(),
        ));
    }

    let plist_start = xml
        .find("<plist")
        .ok_or_else(|| BookmarkError::InvalidImport("missing <plist> root element".into()))?;
    let body_start = plist_start
        + xml[plist_start..]
            .find('>')
            .ok_or_else(|| BookmarkError::InvalidImport("malformed <plist> tag".into()))?
        + 1;
    let body = &xml[body_start..];

    let mut parser = PlistXmlParser {
        src: body,
        pos: 0,
        depth: 0,
    };
    let root_val = parser.parse_next_value()?;
    let root_dict = root_val
        .as_dict()
        .ok_or_else(|| BookmarkError::InvalidImport("plist root is not a <dict>".into()))?;

    let mut out = Vec::new();
    if let Some(children) = root_dict.get("Children").and_then(PlistValue::as_array) {
        for item in children {
            if let Some(node) = convert_safari_plist_node(item) {
                out.push(node);
            }
        }
    } else if let Some(node) = convert_safari_plist_node(&root_val) {
        out.push(node);
    }
    Ok(out)
}

fn convert_safari_plist_node(val: &PlistValue) -> Option<BookmarkTreeNode> {
    let dict = val.as_dict()?;
    let bm_type = dict.get("WebBookmarkType").and_then(PlistValue::as_str)?;
    match bm_type {
        "WebBookmarkTypeList" => {
            let title = dict
                .get("Title")
                .and_then(PlistValue::as_str)
                .unwrap_or("Folder")
                .to_string();
            let is_bar = title == "BookmarksBar"
                || dict
                    .get("WebBookmarkIdentifier")
                    .and_then(PlistValue::as_str)
                    == Some("BookmarksBar");
            let mut children = Vec::new();
            if let Some(arr) = dict.get("Children").and_then(PlistValue::as_array) {
                for ch in arr {
                    if let Some(node) = convert_safari_plist_node(ch) {
                        children.push(node);
                    }
                }
            }
            Some(BookmarkTreeNode {
                kind: BookmarkNodeKind::Folder,
                title,
                url: None,
                nickname: None,
                description: None,
                tags: Vec::new(),
                icon_only: false,
                custom_icon: None,
                created_unix: None,
                updated_unix: None,
                is_bookmark_bar: is_bar,
                children,
            })
        }
        "WebBookmarkTypeLeaf" => {
            let url = dict.get("URLString").and_then(PlistValue::as_str)?.to_string();
            let title = dict
                .get("URIDictionary")
                .and_then(PlistValue::as_dict)
                .and_then(|d| d.get("title"))
                .and_then(PlistValue::as_str)
                .unwrap_or(&url)
                .to_string();
            let description = dict
                .get("ReadingList")
                .and_then(PlistValue::as_dict)
                .and_then(|d| d.get("PreviewText"))
                .and_then(PlistValue::as_str)
                .map(|s| s.to_string());
            Some(BookmarkTreeNode {
                kind: BookmarkNodeKind::Url,
                title,
                url: Some(url),
                nickname: None,
                description,
                tags: Vec::new(),
                icon_only: false,
                custom_icon: None,
                created_unix: None,
                updated_unix: None,
                is_bookmark_bar: false,
                children: Vec::new(),
            })
        }
        _ => None, // Skip WebBookmarkTypeProxy (History, ReadingList proxy etc.)
    }
}

struct PlistXmlParser<'a> {
    src: &'a str,
    pos: usize,
    depth: usize,
}

impl<'a> PlistXmlParser<'a> {
    fn skip_ws_and_comments(&mut self) {
        loop {
            while self.pos < self.src.len()
                && self.src.as_bytes()[self.pos].is_ascii_whitespace()
            {
                self.pos += 1;
            }
            if self.src[self.pos..].starts_with("<!--") {
                if let Some(end) = self.src[self.pos + 4..].find("-->") {
                    self.pos += 4 + end + 3;
                    continue;
                }
            }
            break;
        }
    }

    fn read_tag(&mut self) -> Result<(String, bool, bool), BookmarkError> {
        self.skip_ws_and_comments();
        if !self.src[self.pos..].starts_with('<') {
            return Err(BookmarkError::InvalidImport(format!(
                "expected '<' at byte {}",
                self.pos
            )));
        }
        let end_rel = self.src[self.pos..]
            .find('>')
            .ok_or_else(|| BookmarkError::InvalidImport("unterminated XML tag".into()))?;
        let raw = &self.src[self.pos + 1..self.pos + end_rel];
        self.pos += end_rel + 1;

        let trimmed = raw.trim();
        let is_close = trimmed.starts_with('/');
        let is_self_close = trimmed.ends_with('/');
        let core = trimmed.trim_start_matches('/').trim_end_matches('/').trim();
        let name = core
            .split(char::is_whitespace)
            .next()
            .unwrap_or("")
            .to_string();
        Ok((name, is_close, is_self_close))
    }

    fn peek_close_tag(&mut self, expected: &str) -> bool {
        self.skip_ws_and_comments();
        let rest = &self.src[self.pos..];
        if let Some(after) = rest.strip_prefix("</") {
            let name = after
                .split(|c: char| c.is_whitespace() || c == '>')
                .next()
                .unwrap_or("");
            return name == expected;
        }
        false
    }

    fn read_text_until_close(&mut self, tag: &str) -> Result<String, BookmarkError> {
        let close_pat = format!("</{}>", tag);
        let rel = self.src[self.pos..]
            .find(&close_pat)
            .ok_or_else(|| BookmarkError::InvalidImport(format!("missing </{}>", tag)))?;
        let text = &self.src[self.pos..self.pos + rel];
        self.pos += rel + close_pat.len();
        Ok(html_unescape(text))
    }

    fn parse_next_value(&mut self) -> Result<PlistValue, BookmarkError> {
        self.depth += 1;
        if self.depth > 64 {
            return Err(BookmarkError::InvalidImport(
                "plist nesting depth exceeded".into(),
            ));
        }

        let (tag, is_close, is_self_close) = self.read_tag()?;
        if is_close {
            return Err(BookmarkError::InvalidImport(format!(
                "unexpected closing tag </{}>",
                tag
            )));
        }

        let val = match tag.as_str() {
            "dict" => {
                let mut map = HashMap::new();
                if !is_self_close {
                    while !self.peek_close_tag("dict") {
                        let (ktag, kclose, kself) = self.read_tag()?;
                        if ktag != "key" || kclose || kself {
                            return Err(BookmarkError::InvalidImport(format!(
                                "expected <key> inside <dict>, found <{}>",
                                ktag
                            )));
                        }
                        let key = self.read_text_until_close("key")?;
                        let v = self.parse_next_value()?;
                        map.insert(key, v);
                    }
                    let _ = self.read_tag()?; // consume </dict>
                }
                PlistValue::Dict(map)
            }
            "array" => {
                let mut arr = Vec::new();
                if !is_self_close {
                    while !self.peek_close_tag("array") {
                        arr.push(self.parse_next_value()?);
                    }
                    let _ = self.read_tag()?; // consume </array>
                }
                PlistValue::Array(arr)
            }
            "string" => {
                if is_self_close {
                    PlistValue::String(String::new())
                } else {
                    PlistValue::String(self.read_text_until_close("string")?)
                }
            }
            "true" | "false" => {
                if !is_self_close {
                    let _ = self.read_text_until_close(&tag)?;
                }
                PlistValue::Other
            }
            "integer" | "real" | "date" | "data" => {
                if !is_self_close {
                    let _ = self.read_text_until_close(&tag)?;
                }
                PlistValue::Other
            }
            other => {
                return Err(BookmarkError::InvalidImport(format!(
                    "unsupported plist tag <{}>",
                    other
                )));
            }
        };

        self.depth -= 1;
        Ok(val)
    }
}

// ============================================================================
// Internal Helpers
// ============================================================================

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn normalize_tags(tags: &[String]) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for t in tags {
        let clean = t.trim().to_string();
        if clean.is_empty() {
            continue;
        }
        let key = clean.to_lowercase();
        if seen.insert(key) {
            out.push(clean);
        }
    }
    out
}

fn extract_url_host(url: &str) -> String {
    let after = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let auth = after.split(['/', '?', '#']).next().unwrap_or("");
    let hp = auth.rsplit_once('@').map(|(_, x)| x).unwrap_or(auth);
    let host = if hp.starts_with('[') {
        hp.find(']').map(|e| &hp[..=e]).unwrap_or(hp)
    } else {
        hp.split(':').next().unwrap_or(hp)
    };
    host.trim_start_matches("www.").to_ascii_lowercase()
}

fn percent_encode_arg(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 8);
    for b in input.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            b' ' => out.push_str("%20"),
            _ => {
                let hi = (b >> 4) as usize;
                let lo = (b & 0x0F) as usize;
                const HEX: &[u8; 16] = b"0123456789ABCDEF";
                out.push('%');
                out.push(HEX[hi] as char);
                out.push(HEX[lo] as char);
            }
        }
    }
    out
}

fn html_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

fn html_unescape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        let after = &rest[amp + 1..];
        if let Some(semi) = after.find(';') {
            let ent = &after[..semi];
            match ent {
                "amp" => out.push('&'),
                "lt" => out.push('<'),
                "gt" => out.push('>'),
                "quot" => out.push('"'),
                "apos" | "#39" | "#x27" => out.push('\''),
                "nbsp" => out.push(' '),
                _ if ent.starts_with("#x") || ent.starts_with("#X") => {
                    if let Some(ch) = u32::from_str_radix(&ent[2..], 16)
                        .ok()
                        .and_then(char::from_u32)
                    {
                        out.push(ch);
                    }
                }
                _ if ent.starts_with('#') => {
                    if let Some(ch) = ent[1..].parse::<u32>().ok().and_then(char::from_u32) {
                        out.push(ch);
                    }
                }
                _ => {
                    out.push('&');
                    out.push_str(ent);
                    out.push(';');
                }
            }
            rest = &after[semi + 1..];
        } else {
            out.push('&');
            rest = after;
        }
    }
    out.push_str(rest);
    out
}

fn extract_html_attr(tag: &str, attr_name: &str) -> Option<String> {
    let lower_tag = tag.to_ascii_lowercase();
    let lower_attr = attr_name.to_ascii_lowercase();
    let bytes = lower_tag.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let Some(rel) = lower_tag[i..].find(&lower_attr) else {
            break;
        };
        let abs = i + rel;
        let before_ok = abs == 0 || bytes[abs - 1].is_ascii_whitespace();
        let after = abs + lower_attr.len();
        if before_ok && after < bytes.len() {
            let mut eq = after;
            while eq < bytes.len() && bytes[eq].is_ascii_whitespace() {
                eq += 1;
            }
            if eq < bytes.len() && bytes[eq] == b'=' {
                eq += 1;
                while eq < bytes.len() && bytes[eq].is_ascii_whitespace() {
                    eq += 1;
                }
                if eq < bytes.len() && (bytes[eq] == b'"' || bytes[eq] == b'\'') {
                    let quote = bytes[eq];
                    let start = eq + 1;
                    if let Some(end_rel) = tag[start..].find(quote as char) {
                        return Some(tag[start..start + end_rel].to_string());
                    }
                } else if eq < bytes.len() {
                    let start = eq;
                    let end_rel = tag[start..]
                        .find(|c: char| c.is_whitespace() || c == '>')
                        .unwrap_or(tag.len() - start);
                    return Some(tag[start..start + end_rel].to_string());
                }
            }
        }
        i = after;
    }
    None
}

fn backup_path_for(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|s| s.to_os_string())
        .unwrap_or_default();
    name.push(".bak");
    path.with_file_name(name)
}

fn atomic_write_with_backup(path: &Path, data: &[u8]) -> Result<(), std::io::Error> {
    let mut tmp_name = path
        .file_name()
        .map(|s| s.to_os_string())
        .unwrap_or_default();
    tmp_name.push(".tmp");
    let tmp_path = path.with_file_name(tmp_name);
    let bak_path = backup_path_for(path);

    {
        let mut f = std::fs::File::create(&tmp_path)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    if path.exists() {
        let _ = std::fs::copy(path, &bak_path);
    }
    std::fs::rename(&tmp_path, path)?;
    Ok(())
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tree_operations_cycle_detection_trash_and_undo_redo() {
        let mut store = BookmarksStore::new();
        let now = 1_760_000_000;

        let f_dev = store
            .add_node(
                NewBookmarkNode {
                    parent_id: ROOT_BOOKMARK_BAR.into(),
                    position: None,
                    kind: BookmarkNodeKind::Folder,
                    title: "Dev".into(),
                    url: None,
                    nickname: None,
                    description: None,
                    tags: vec![],
                    icon_only: false,
                    custom_icon: None,
                },
                now,
            )
            .unwrap();
        let f_rust = store
            .add_node(
                NewBookmarkNode {
                    parent_id: f_dev.clone(),
                    position: None,
                    kind: BookmarkNodeKind::Folder,
                    title: "Rust".into(),
                    url: None,
                    nickname: None,
                    description: None,
                    tags: vec![],
                    icon_only: false,
                    custom_icon: None,
                },
                now,
            )
            .unwrap();

        // Cycle detection: moving Dev into its child Rust MUST fail
        let cycle_err = store.move_node(&f_dev, &f_rust, 0, now);
        assert!(matches!(cycle_err, Err(BookmarkError::CycleDetected(_, _))));
        // Moving system root MUST fail
        assert!(matches!(
            store.move_node(ROOT_BOOKMARK_BAR, ROOT_OTHER_BOOKMARKS, 0, now),
            Err(BookmarkError::ProtectedSystemRoot(_))
        ));

        // Soft delete & restore
        store.soft_delete(&f_rust, now).unwrap();
        assert!(store.is_in_trash(&f_rust));
        let restored_to = store.restore_from_trash(&f_rust, now + 10).unwrap();
        assert_eq!(restored_to, f_dev);
        assert!(!store.is_in_trash(&f_rust));

        // Undo restores back to trash, Redo restores out of trash
        assert!(store.undo());
        assert!(store.is_in_trash(&f_rust));
        assert!(store.redo());
        assert!(!store.is_in_trash(&f_rust));

        // Test 100-operation cap on Undo stack
        for i in 0..120 {
            store
                .add_node(
                    NewBookmarkNode {
                        parent_id: ROOT_OTHER_BOOKMARKS.into(),
                        position: None,
                        kind: BookmarkNodeKind::Url,
                        title: format!("Item {}", i),
                        url: Some(format!("https://example.org/{}", i)),
                        nickname: None,
                        description: None,
                        tags: vec![],
                        icon_only: false,
                        custom_icon: None,
                    },
                    now + i,
                )
                .unwrap();
        }
        assert_eq!(store.undo_len(), MAX_UNDO_HISTORY);

        // Trash expiration purge
        store.soft_delete(&f_dev, now).unwrap();
        assert_eq!(store.purge_expired_trash(30, now + 10 * 86_400), 0);
        assert!(store.purge_expired_trash(30, now + 45 * 86_400) >= 2);
        assert!(store.get_node(&f_dev).is_none());
    }

    #[test]
    fn test_search_smart_folders_nicknames_and_duplicates() {
        let mut store = BookmarksStore::new();
        let now = 1_760_000_000;

        let b1 = store
            .add_node(
                NewBookmarkNode {
                    parent_id: ROOT_BOOKMARK_BAR.into(),
                    position: None,
                    kind: BookmarkNodeKind::Url,
                    title: "Rust Docs".into(),
                    url: Some("https://doc.rust-lang.org/std/?search=%s".into()),
                    nickname: Some("rs".into()),
                    description: Some("Official standard library documentation".into()),
                    tags: vec!["rust".into(), "docs".into()],
                    icon_only: false,
                    custom_icon: None,
                },
                now,
            )
            .unwrap();
        store.record_visit(&b1, now + 5);

        // Add duplicate with http://, www., trailing slash, and utm_source
        store
            .add_node(
                NewBookmarkNode {
                    parent_id: ROOT_OTHER_BOOKMARKS.into(),
                    position: None,
                    kind: BookmarkNodeKind::Url,
                    title: "Rust Docs Mirror".into(),
                    url: Some("http://www.doc.rust-lang.org/std/?utm_source=twitter&search=%s".into()),
                    nickname: None,
                    description: None,
                    tags: vec!["programming".into()],
                    icon_only: false,
                    custom_icon: None,
                },
                now + 10,
            )
            .unwrap();

        // Nickname substitution
        assert_eq!(
            store.resolve_nickname("rs HashMap new").as_deref(),
            Some("https://doc.rust-lang.org/std/?search=HashMap%20new")
        );

        // Multi-criteria search
        let found = store.search("tag:rust domain:rust-lang.org has:note");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].id, b1);

        // SmartFolderRule
        let rule = SmartFolderRule {
            id: "sf-1".into(),
            name: "Top Rust".into(),
            query: String::new(),
            tags: vec!["rust".into()],
            domain_contains: Some("rust-lang".into()),
            min_visits: Some(1),
            created_after_unix: None,
            has_note: true,
            limit: Some(10),
        };
        assert_eq!(store.evaluate_smart_folder(&rule).len(), 1);

        // Duplicate detection & merging
        let groups = store.find_duplicate_groups();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].node_ids.len(), 2);
        let merged = store.merge_duplicates(now + 20);
        assert_eq!(merged, 1);
        assert!(store.find_duplicate_groups().is_empty());
        let survivor = store.get_node(&b1).unwrap();
        assert!(survivor.tags.contains(&"programming".to_string()));
    }

    #[test]
    fn test_netscape_html_roundtrip_json_and_safari_plist() {
        let html = r#"<!DOCTYPE NETSCAPE-Bookmark-file-1>
<META HTTP-EQUIV="Content-Type" CONTENT="text/html; charset=UTF-8">
<TITLE>Bookmarks</TITLE>
<H1>Bookmarks</H1>
<DL><p>
    <DT><H3 ADD_DATE="1700000000" LAST_MODIFIED="1700000100" PERSONAL_TOOLBAR_FOLDER="true">Bookmarks Bar</H3>
    <DD>Main toolbar
    <DL><p>
        <DT><A HREF="https://rust-lang.org/" ADD_DATE="1700000010" TAGS="rust,lang" SHORTCUTURL="rl">Rust &amp; Cargo</A>
        <DD>Fast &amp; reliable systems language
        <HR>
        <DT><H3 ADD_DATE="1700000020">Nested Folder</H3>
        <DL><p>
            <DT><A HREF="https://crates.io/" ADD_DATE="1700000030">crates.io</A>
        </DL><p>
    </DL><p>
</DL><p>"#;

        let parsed = parse_netscape_html_tree(html).expect("parse Netscape HTML");
        assert_eq!(parsed.len(), 1);
        assert!(parsed[0].is_bookmark_bar);
        assert_eq!(parsed[0].description.as_deref(), Some("Main toolbar"));
        assert_eq!(parsed[0].children.len(), 3); // Url, Separator, Nested Folder
        assert_eq!(parsed[0].children[0].title, "Rust & Cargo");
        assert_eq!(parsed[0].children[0].nickname.as_deref(), Some("rl"));
        assert_eq!(parsed[0].children[0].tags, vec!["rust", "lang"]);
        assert_eq!(
            parsed[0].children[0].description.as_deref(),
            Some("Fast & reliable systems language")
        );
        assert_eq!(parsed[0].children[1].kind, BookmarkNodeKind::Separator);
        assert_eq!(parsed[0].children[2].children[0].title, "crates.io");

        let mut store = BookmarksStore::new();
        let imported = store
            .import_netscape_html(html, ROOT_OTHER_BOOKMARKS, true, 1_760_000_000)
            .unwrap();
        assert_eq!(imported, 4);

        let exported_html = store.export_netscape_html_tree();
        assert!(exported_html.contains("SHORTCUTURL=\"rl\""));
        assert!(exported_html.contains("TAGS=\"rust,lang\""));
        assert!(exported_html.contains("<HR>"));
        assert!(exported_html.contains("<DD>Fast &amp; reliable systems language"));

        // JSON tree round-trip
        let json_tree = store.export_json_tree().unwrap();
        let mut store2 = BookmarksStore::new();
        let imported_json = store2
            .import_json_tree(&json_tree, ROOT_OTHER_BOOKMARKS, 1_760_000_000)
            .unwrap();
        assert!(imported_json >= 4);

        // Safari Bookmarks.plist XML import
        let safari_plist = r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
    <key>Children</key>
    <array>
        <dict>
            <key>Title</key>
            <string>BookmarksBar</string>
            <key>WebBookmarkType</key>
            <string>WebBookmarkTypeList</string>
            <key>Children</key>
            <array>
                <dict>
                    <key>URLString</key>
                    <string>https://webkit.org/</string>
                    <key>URIDictionary</key>
                    <dict>
                        <key>title</key>
                        <string>WebKit</string>
                    </dict>
                    <key>WebBookmarkType</key>
                    <string>WebBookmarkTypeLeaf</string>
                </dict>
            </array>
        </dict>
    </array>
</dict>
</plist>"#;

        let safari_nodes = parse_safari_bookmarks_plist_xml(safari_plist).expect("parse Safari plist");
        assert_eq!(safari_nodes.len(), 1);
        assert!(safari_nodes[0].is_bookmark_bar);
        assert_eq!(safari_nodes[0].children[0].title, "WebKit");
        assert_eq!(
            safari_nodes[0].children[0].url.as_deref(),
            Some("https://webkit.org/")
        );
    }

    #[test]
    fn test_sort_and_bookmark_all_tabs() {
        let mut store = BookmarksStore::new();
        let now = 1_760_000_000;
        let folder_id = store
            .bookmark_all_tabs(
                "Research Session",
                ROOT_BOOKMARK_BAR,
                &[
                    ("Zeta".into(), "https://z.test".into()),
                    ("Alpha".into(), "https://a.test".into()),
                    ("Middle".into(), "https://m.test".into()),
                ],
                now,
            )
            .unwrap();
        store.sort_folder_by_name(&folder_id, true).unwrap();
        let titles: Vec<&str> = store
            .children_of(&folder_id)
            .into_iter()
            .map(|n| n.title.as_str())
            .collect();
        assert_eq!(titles, vec!["Alpha", "Middle", "Zeta"]);
    }

    #[test]
    fn test_atomic_persistence_folder_search_and_empty_trash() {
        let mut store = BookmarksStore::new();
        let now = 1_760_000_000;
        let f_id = store
            .bookmark_all_tabs(
                "Physics",
                ROOT_BOOKMARK_BAR,
                &[("Kerr Metric".into(), "https://physics.test/kerr".into())],
                now,
            )
            .unwrap();

        let found = store.search("folder:physics kerr");
        assert_eq!(found.len(), 1);

        let dir = std::env::temp_dir().join(format!(
            "singularity_bm_test_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let path = store.save_to_dir(&dir).unwrap();
        store.save_to_dir(&dir).unwrap();
        std::fs::write(&path, b"{broken").unwrap();

        let mut recovered = BookmarksStore::load_from_dir(&dir).unwrap();
        assert_eq!(recovered.search("folder:physics").len(), 1);

        recovered.soft_delete(&f_id, now + 5).unwrap();
        assert!(recovered.empty_trash() >= 2);
        assert!(recovered.children_of(ROOT_TRASH).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
