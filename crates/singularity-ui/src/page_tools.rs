//! Singularity Page Productivity, Reader Mode, Annotations & Pure-Rust Dev Viewers.
//!
//! Features:
//! - **Collections (`CollectionsStore`)**: `Collection` + `CollectionItemKind::{PageLink, TextExcerpt, ImageAsset, Note}`,
//!   CRUD, atomic persistence, Markdown & XSS-safe HTML export
//! - **Markdown Notes (`NotesStore`)**: folders, trash, `NoteEntry` tied to `source_url`, attachments,
//!   and XSS-safe pure-Rust GFM Markdown → HTML engine (`render_safe_markdown_html`)
//! - **Offline Reading List (`ReadingListStore`)**: `ReadingListEntry` with auto-read at >=90% scroll,
//!   word count, and sanitized offline HTML archiver (`sanitize_html_for_offline_archive`)
//! - **Reader Mode (`ReaderModeExtractor`)**: `is_probably_readerable`, pure-Rust Readability
//!   extractor (`extract_article` with `Vec<HeadingAnchor>` TOC), and full `singularity://reader`
//!   HTML generator with OLED/Slate/Sepia/Light/WCAG AAA themes, `OpenDyslexic`, and Line Focus 1/3/5
//! - **PDF & Capture Models**: `PdfAnnotationStore` (`Highlight`, `InkStroke`, `FreeText`,
//!   `StickyNote`, `Signature`), `PdfFormState`, `CaptureAnnotationDocument` (`Crop`, `Arrow`,
//!   `Rect`, `Pen`, `Blur`, `Pixelate`, `Text`, `StepBadge`) + SVG overlay generator
//! - **Text Fragments (`#:~:text=`)**: `build_text_fragment_url` with anti-ambiguity prefix/suffix
//! - **Pure-Rust Dev Viewers**:
//!   - `format_view_source_html` (syntax highlighting, `#L..` anchors, collapsible blocks, safe links)
//!   - `evaluate_jsonpath` (`$.a.b[0]`, `$..key`, `[*]`) + `render_json_viewer_html`
//!   - `parse_xml_tree` + `evaluate_xpath_simple` + `render_xml_viewer_html`
//!   - `compute_line_diff` (LCS/Myers) + `render_diff_viewer_html`
//!   - `extract_rss_feeds_from_html` & `format_smart_copy` (`Plain`, `Clean`, `Markdown`, `HtmlRich`).

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use thiserror::Error;

// ============================================================================
// Errors
// ============================================================================

#[derive(Debug, Error)]
pub enum PageToolsError {
    #[error("item '{0}' not found")]
    NotFound(String),
    #[error("invalid XML input: {0}")]
    InvalidXml(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

// ============================================================================
// 1. Collections (`CollectionsStore`)
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CollectionItemKind {
    PageLink {
        url: String,
        title: String,
        #[serde(default)]
        favicon_url: Option<String>,
    },
    TextExcerpt {
        text: String,
        #[serde(default)]
        source_url: Option<String>,
        #[serde(default)]
        source_title: Option<String>,
    },
    ImageAsset {
        image_url: String,
        #[serde(default)]
        alt: String,
        #[serde(default)]
        source_url: Option<String>,
    },
    Note {
        markdown: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollectionItem {
    pub id: String,
    pub kind: CollectionItemKind,
    pub created_unix: u64,
    pub updated_unix: u64,
    #[serde(default)]
    pub color_tag: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Collection {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub description: String,
    #[serde(default = "default_collection_color")]
    pub color: String,
    #[serde(default)]
    pub items: Vec<CollectionItem>,
    pub created_unix: u64,
    pub updated_unix: u64,
}

fn default_collection_color() -> String {
    "#38D9F5".to_string()
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CollectionsStore {
    pub collections: Vec<Collection>,
    next_id: u64,
}

impl CollectionsStore {
    pub fn new() -> Self {
        Self {
            collections: Vec::new(),
            next_id: 1,
        }
    }

    pub fn load_from_path(path: &Path) -> Result<Self, PageToolsError> {
        if !path.exists() {
            return Ok(Self::new());
        }
        let raw = std::fs::read_to_string(path)?;
        Ok(serde_json::from_str(&raw)?)
    }

    pub fn save_to_path(&self, path: &Path) -> Result<(), PageToolsError> {
        let bytes = serde_json::to_vec_pretty(self)?;
        atomic_write_with_backup(path, &bytes)?;
        Ok(())
    }

    fn alloc_id(&mut self, prefix: &str) -> String {
        let id = format!("{}_{}", prefix, self.next_id.max(1));
        self.next_id = self.next_id.max(1) + 1;
        id
    }

    pub fn create_collection(
        &mut self,
        title: &str,
        description: &str,
        color: Option<&str>,
        now_unix: u64,
    ) -> String {
        let id = self.alloc_id("col");
        self.collections.push(Collection {
            id: id.clone(),
            title: title.trim().to_string(),
            description: description.trim().to_string(),
            color: color.unwrap_or("#38D9F5").to_string(),
            items: Vec::new(),
            created_unix: now_unix,
            updated_unix: now_unix,
        });
        id
    }

    pub fn get_collection(&self, id: &str) -> Option<&Collection> {
        self.collections.iter().find(|c| c.id == id)
    }

    pub fn rename_collection(
        &mut self,
        id: &str,
        new_title: &str,
        new_description: Option<&str>,
        now_unix: u64,
    ) -> Result<(), PageToolsError> {
        let col = self
            .collections
            .iter_mut()
            .find(|c| c.id == id)
            .ok_or_else(|| PageToolsError::NotFound(id.to_string()))?;
        col.title = new_title.trim().to_string();
        if let Some(desc) = new_description {
            col.description = desc.trim().to_string();
        }
        col.updated_unix = now_unix;
        Ok(())
    }

    pub fn delete_collection(&mut self, id: &str) -> bool {
        let before = self.collections.len();
        self.collections.retain(|c| c.id != id);
        self.collections.len() != before
    }

    pub fn add_item(
        &mut self,
        collection_id: &str,
        kind: CollectionItemKind,
        color_tag: Option<String>,
        now_unix: u64,
    ) -> Result<String, PageToolsError> {
        let item_id = self.alloc_id("ci");
        let col = self
            .collections
            .iter_mut()
            .find(|c| c.id == collection_id)
            .ok_or_else(|| PageToolsError::NotFound(collection_id.to_string()))?;
        col.items.push(CollectionItem {
            id: item_id.clone(),
            kind,
            created_unix: now_unix,
            updated_unix: now_unix,
            color_tag,
        });
        col.updated_unix = now_unix;
        Ok(item_id)
    }

    pub fn remove_item(
        &mut self,
        collection_id: &str,
        item_id: &str,
        now_unix: u64,
    ) -> Result<bool, PageToolsError> {
        let col = self
            .collections
            .iter_mut()
            .find(|c| c.id == collection_id)
            .ok_or_else(|| PageToolsError::NotFound(collection_id.to_string()))?;
        let before = col.items.len();
        col.items.retain(|i| i.id != item_id);
        let removed = col.items.len() != before;
        if removed {
            col.updated_unix = now_unix;
        }
        Ok(removed)
    }

    pub fn export_collection_markdown(&self, collection_id: &str) -> Result<String, PageToolsError> {
        let col = self
            .get_collection(collection_id)
            .ok_or_else(|| PageToolsError::NotFound(collection_id.to_string()))?;
        let mut out = format!("# {}\n\n", col.title);
        if !col.description.is_empty() {
            out.push_str(&format!("{}\n\n", col.description));
        }
        for item in &col.items {
            match &item.kind {
                CollectionItemKind::PageLink { url, title, .. } => {
                    out.push_str(&format!("- [{}]({})\n", escape_md_label(title), url));
                }
                CollectionItemKind::TextExcerpt {
                    text,
                    source_url,
                    source_title,
                } => {
                    for line in text.lines() {
                        out.push_str(&format!("> {}\n", line));
                    }
                    if let Some(u) = source_url {
                        let lbl = source_title.as_deref().unwrap_or(u);
                        out.push_str(&format!("> — [{}]({})\n", escape_md_label(lbl), u));
                    }
                    out.push('\n');
                }
                CollectionItemKind::ImageAsset { image_url, alt, .. } => {
                    out.push_str(&format!("![{}]({})\n\n", escape_md_label(alt), image_url));
                }
                CollectionItemKind::Note { markdown } => {
                    out.push_str(markdown);
                    out.push_str("\n\n");
                }
            }
        }
        Ok(out)
    }

    pub fn export_collection_html(&self, collection_id: &str) -> Result<String, PageToolsError> {
        let col = self
            .get_collection(collection_id)
            .ok_or_else(|| PageToolsError::NotFound(collection_id.to_string()))?;
        let mut body = format!(
            "<h1>{}</h1>\n",
            html_escape(&col.title)
        );
        if !col.description.is_empty() {
            body.push_str(&format!("<p class=\"desc\">{}</p>\n", html_escape(&col.description)));
        }
        for item in &col.items {
            body.push_str("<article class=\"card\">");
            match &item.kind {
                CollectionItemKind::PageLink { url, title, .. } => {
                    if is_safe_link_url(url) {
                        body.push_str(&format!(
                            "<a href=\"{}\" rel=\"noopener noreferrer\">{}</a>",
                            html_escape(url),
                            html_escape(title)
                        ));
                    } else {
                        body.push_str(&html_escape(title));
                    }
                }
                CollectionItemKind::TextExcerpt {
                    text,
                    source_url,
                    source_title,
                } => {
                    body.push_str(&format!("<blockquote>{}</blockquote>", html_escape(text)));
                    if let Some(u) = source_url {
                        if is_safe_link_url(u) {
                            let lbl = source_title.as_deref().unwrap_or(u);
                            body.push_str(&format!(
                                "<cite><a href=\"{}\" rel=\"noopener noreferrer\">{}</a></cite>",
                                html_escape(u),
                                html_escape(lbl)
                            ));
                        }
                    }
                }
                CollectionItemKind::ImageAsset { image_url, alt, .. } => {
                    if is_safe_http_url(image_url) {
                        body.push_str(&format!(
                            "<img src=\"{}\" alt=\"{}\" loading=\"lazy\"/>",
                            html_escape(image_url),
                            html_escape(alt)
                        ));
                    }
                }
                CollectionItemKind::Note { markdown } => {
                    body.push_str(&render_safe_markdown_html(markdown));
                }
            }
            body.push_str("</article>\n");
        }

        Ok(format!(
            "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"UTF-8\"><title>{}</title>\
             <style>body{{background:#000;color:#F5F3EE;font-family:system-ui,sans-serif;max-width:780px;margin:2rem auto;padding:0 1rem;}}\
             .card{{background:#0C0D12;border:1px solid #1A1B20;border-radius:10px;padding:1rem;margin:1rem 0;}}\
             a{{color:#38D9F5;}}blockquote{{border-left:3px solid #B975FF;margin:0;padding-left:1rem;}}</style>\
             </head><body>{}</body></html>",
            html_escape(&col.title),
            body
        ))
    }
}

// ============================================================================
// 2. Markdown Notes (`NotesStore`) & Safe Pure-Rust GFM Markdown -> HTML
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoteFolder {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub parent_id: Option<String>,
    pub created_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoteAttachment {
    pub id: String,
    pub filename: String,
    pub mime_type: String,
    #[serde(default)]
    pub data_base64: Option<String>,
    pub size_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoteEntry {
    pub id: String,
    #[serde(default)]
    pub folder_id: Option<String>,
    pub title: String,
    pub markdown: String,
    #[serde(default)]
    pub source_url: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub attachments: Vec<NoteAttachment>,
    #[serde(default)]
    pub pinned: bool,
    #[serde(default)]
    pub trashed_unix: Option<u64>,
    pub created_unix: u64,
    pub updated_unix: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NotesStore {
    pub folders: Vec<NoteFolder>,
    pub notes: Vec<NoteEntry>,
    next_id: u64,
}

impl NotesStore {
    pub fn new() -> Self {
        Self {
            folders: Vec::new(),
            notes: Vec::new(),
            next_id: 1,
        }
    }

    pub fn load_from_path(path: &Path) -> Result<Self, PageToolsError> {
        if !path.exists() {
            return Ok(Self::new());
        }
        let raw = std::fs::read_to_string(path)?;
        Ok(serde_json::from_str(&raw)?)
    }

    pub fn save_to_path(&self, path: &Path) -> Result<(), PageToolsError> {
        let bytes = serde_json::to_vec_pretty(self)?;
        atomic_write_with_backup(path, &bytes)?;
        Ok(())
    }

    fn alloc_id(&mut self, prefix: &str) -> String {
        let id = format!("{}_{}", prefix, self.next_id.max(1));
        self.next_id = self.next_id.max(1) + 1;
        id
    }

    pub fn create_folder(
        &mut self,
        name: &str,
        parent_id: Option<String>,
        now_unix: u64,
    ) -> String {
        let id = self.alloc_id("nf");
        self.folders.push(NoteFolder {
            id: id.clone(),
            name: name.trim().to_string(),
            parent_id,
            created_unix: now_unix,
        });
        id
    }

    pub fn create_note(
        &mut self,
        title: &str,
        markdown: &str,
        folder_id: Option<String>,
        source_url: Option<String>,
        tags: Vec<String>,
        now_unix: u64,
    ) -> String {
        let id = self.alloc_id("note");
        self.notes.push(NoteEntry {
            id: id.clone(),
            folder_id,
            title: title.trim().to_string(),
            markdown: markdown.to_string(),
            source_url,
            tags,
            attachments: Vec::new(),
            pinned: false,
            trashed_unix: None,
            created_unix: now_unix,
            updated_unix: now_unix,
        });
        id
    }

    pub fn get_note(&self, id: &str) -> Option<&NoteEntry> {
        self.notes.iter().find(|n| n.id == id)
    }

    pub fn update_note(
        &mut self,
        id: &str,
        title: Option<&str>,
        markdown: Option<&str>,
        tags: Option<Vec<String>>,
        now_unix: u64,
    ) -> Result<(), PageToolsError> {
        let note = self
            .notes
            .iter_mut()
            .find(|n| n.id == id)
            .ok_or_else(|| PageToolsError::NotFound(id.to_string()))?;
        if let Some(t) = title {
            note.title = t.trim().to_string();
        }
        if let Some(md) = markdown {
            note.markdown = md.to_string();
        }
        if let Some(tg) = tags {
            note.tags = tg;
        }
        note.updated_unix = now_unix;
        Ok(())
    }

    pub fn attach_file(
        &mut self,
        note_id: &str,
        filename: &str,
        mime_type: &str,
        data_base64: Option<String>,
        size_bytes: usize,
        now_unix: u64,
    ) -> Result<String, PageToolsError> {
        let att_id = self.alloc_id("att");
        let note = self
            .notes
            .iter_mut()
            .find(|n| n.id == note_id)
            .ok_or_else(|| PageToolsError::NotFound(note_id.to_string()))?;
        note.attachments.push(NoteAttachment {
            id: att_id.clone(),
            filename: filename.to_string(),
            mime_type: mime_type.to_string(),
            data_base64,
            size_bytes,
        });
        note.updated_unix = now_unix;
        Ok(att_id)
    }

    pub fn trash_note(&mut self, id: &str, now_unix: u64) -> Result<(), PageToolsError> {
        let note = self
            .notes
            .iter_mut()
            .find(|n| n.id == id)
            .ok_or_else(|| PageToolsError::NotFound(id.to_string()))?;
        note.trashed_unix = Some(now_unix);
        note.updated_unix = now_unix;
        Ok(())
    }

    pub fn restore_note(&mut self, id: &str, now_unix: u64) -> Result<(), PageToolsError> {
        let note = self
            .notes
            .iter_mut()
            .find(|n| n.id == id)
            .ok_or_else(|| PageToolsError::NotFound(id.to_string()))?;
        note.trashed_unix = None;
        note.updated_unix = now_unix;
        Ok(())
    }

    pub fn empty_trash(&mut self) -> usize {
        let before = self.notes.len();
        self.notes.retain(|n| n.trashed_unix.is_none());
        before - self.notes.len()
    }

    pub fn notes_for_url(&self, url: &str) -> Vec<&NoteEntry> {
        let target = url.trim().to_ascii_lowercase();
        self.notes
            .iter()
            .filter(|n| {
                n.trashed_unix.is_none()
                    && n.source_url
                        .as_deref()
                        .map_or(false, |u| u.trim().to_ascii_lowercase() == target)
            })
            .collect()
    }

    pub fn search_notes(&self, query: &str, include_trash: bool) -> Vec<&NoteEntry> {
        let q = query.trim().to_lowercase();
        self.notes
            .iter()
            .filter(|n| {
                if !include_trash && n.trashed_unix.is_some() {
                    return false;
                }
                if q.is_empty() {
                    return true;
                }
                n.title.to_lowercase().contains(&q)
                    || n.markdown.to_lowercase().contains(&q)
                    || n.tags.iter().any(|t| t.to_lowercase().contains(&q))
                    || n.source_url
                        .as_deref()
                        .map_or(false, |u| u.to_lowercase().contains(&q))
            })
            .collect()
    }
}

/// Renders GFM Markdown into strictly XSS-safe HTML in 100% pure Rust.
///
/// Supports ATX headings, bold/italic/strikethrough/inline code, fenced code blocks,
/// ordered/unordered lists, GFM task lists (`[x]`/`[ ]`), blockquotes, GFM tables,
/// horizontal rules, and safe `http(s)`/`mailto:`/`#` links. All raw HTML is escaped.
pub fn render_safe_markdown_html(markdown: &str) -> String {
    let lines: Vec<&str> = markdown.lines().collect();
    let mut out = String::with_capacity(markdown.len() + 128);
    let mut i = 0usize;

    while i < lines.len() {
        let line = lines[i];
        let trimmed = line.trim();

        if trimmed.is_empty() {
            i += 1;
            continue;
        }

        // Fenced code block ```lang
        if trimmed.starts_with("```") {
            let lang = trimmed[3..].trim();
            let safe_lang: String = lang
                .chars()
                .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
                .take(32)
                .collect();
            i += 1;
            let mut code = String::new();
            while i < lines.len() && !lines[i].trim().starts_with("```") {
                code.push_str(lines[i]);
                code.push('\n');
                i += 1;
            }
            if i < lines.len() {
                i += 1; // consume closing ```
            }
            if safe_lang.is_empty() {
                out.push_str(&format!("<pre><code>{}</code></pre>\n", html_escape(&code)));
            } else {
                out.push_str(&format!(
                    "<pre><code class=\"language-{}\">{}</code></pre>\n",
                    safe_lang,
                    html_escape(&code)
                ));
            }
            continue;
        }

        // Horizontal rule
        if is_horizontal_rule(trimmed) {
            out.push_str("<hr/>\n");
            i += 1;
            continue;
        }

        // ATX heading (# .. ######)
        if let Some((level, text)) = parse_atx_heading(trimmed) {
            let slug = slugify_heading(text);
            out.push_str(&format!(
                "<h{lvl} id=\"{slug}\">{body}</h{lvl}>\n",
                lvl = level,
                slug = html_escape(&slug),
                body = render_inline_md(text)
            ));
            i += 1;
            continue;
        }

        // Blockquote (> ...)
        if trimmed.starts_with('>') {
            let mut q_lines = Vec::new();
            while i < lines.len() && lines[i].trim().starts_with('>') {
                let inner = lines[i]
                    .trim()
                    .strip_prefix('>')
                    .unwrap_or("")
                    .trim_start();
                q_lines.push(inner);
                i += 1;
            }
            let inner_html = render_safe_markdown_html(&q_lines.join("\n"));
            out.push_str(&format!("<blockquote>{}</blockquote>\n", inner_html.trim()));
            continue;
        }

        // GFM Table (header row + separator row `|---|---|`)
        if i + 1 < lines.len() && line.contains('|') && is_gfm_table_separator(lines[i + 1]) {
            let headers = split_table_cells(line);
            let aligns = parse_table_alignments(lines[i + 1]);
            i += 2;
            out.push_str("<table><thead><tr>");
            for (ci, h) in headers.iter().enumerate() {
                let align_attr = aligns
                    .get(ci)
                    .copied()
                    .flatten()
                    .map(|a| format!(" style=\"text-align:{}\"", a))
                    .unwrap_or_default();
                out.push_str(&format!("<th{}>{}</th>", align_attr, render_inline_md(h)));
            }
            out.push_str("</tr></thead><tbody>");
            while i < lines.len() && lines[i].contains('|') && !lines[i].trim().is_empty() {
                let cells = split_table_cells(lines[i]);
                out.push_str("<tr>");
                for (ci, cell) in cells.iter().enumerate() {
                    let align_attr = aligns
                        .get(ci)
                        .copied()
                        .flatten()
                        .map(|a| format!(" style=\"text-align:{}\"", a))
                        .unwrap_or_default();
                    out.push_str(&format!(
                        "<td{}>{}</td>",
                        align_attr,
                        render_inline_md(cell)
                    ));
                }
                out.push_str("</tr>");
                i += 1;
            }
            out.push_str("</tbody></table>\n");
            continue;
        }

        // Unordered list / Task list
        if is_ul_item(trimmed) {
            out.push_str("<ul>\n");
            while i < lines.len() && is_ul_item(lines[i].trim()) {
                let item_text = lines[i].trim()[2..].trim_start();
                if let Some(rest) = item_text
                    .strip_prefix("[x] ")
                    .or_else(|| item_text.strip_prefix("[X] "))
                {
                    out.push_str(&format!(
                        "<li class=\"task-item\"><input type=\"checkbox\" checked disabled/> {}</li>\n",
                        render_inline_md(rest)
                    ));
                } else if let Some(rest) = item_text.strip_prefix("[ ] ") {
                    out.push_str(&format!(
                        "<li class=\"task-item\"><input type=\"checkbox\" disabled/> {}</li>\n",
                        render_inline_md(rest)
                    ));
                } else {
                    out.push_str(&format!("<li>{}</li>\n", render_inline_md(item_text)));
                }
                i += 1;
            }
            out.push_str("</ul>\n");
            continue;
        }

        // Ordered list (`1. ...`)
        if parse_ol_item(trimmed).is_some() {
            out.push_str("<ol>\n");
            while i < lines.len() {
                if let Some(item_text) = parse_ol_item(lines[i].trim()) {
                    out.push_str(&format!("<li>{}</li>\n", render_inline_md(item_text)));
                    i += 1;
                } else {
                    break;
                }
            }
            out.push_str("</ol>\n");
            continue;
        }

        // Paragraph (collect contiguous plain lines)
        let mut para = Vec::new();
        while i < lines.len() {
            let t = lines[i].trim();
            if t.is_empty()
                || t.starts_with("```")
                || t.starts_with('>')
                || is_horizontal_rule(t)
                || parse_atx_heading(t).is_some()
                || is_ul_item(t)
                || parse_ol_item(t).is_some()
            {
                break;
            }
            para.push(t);
            i += 1;
        }
        if !para.is_empty() {
            out.push_str(&format!("<p>{}</p>\n", render_inline_md(&para.join(" "))));
        }
    }

    out
}

fn parse_atx_heading(trimmed: &str) -> Option<(usize, &str)> {
    let hashes = trimmed.bytes().take_while(|&b| b == b'#').count();
    if (1..=6).contains(&hashes) {
        let rest = &trimmed[hashes..];
        if rest.starts_with(' ') || rest.starts_with('\t') {
            return Some((hashes, rest.trim().trim_end_matches('#').trim()));
        }
    }
    None
}

fn is_horizontal_rule(trimmed: &str) -> bool {
    let compact: String = trimmed.chars().filter(|c| !c.is_whitespace()).collect();
    compact.len() >= 3
        && (compact.chars().all(|c| c == '-')
            || compact.chars().all(|c| c == '*')
            || compact.chars().all(|c| c == '_'))
}

fn is_ul_item(trimmed: &str) -> bool {
    trimmed.starts_with("- ") || trimmed.starts_with("* ") || trimmed.starts_with("+ ")
}

fn parse_ol_item(trimmed: &str) -> Option<&str> {
    let digits = trimmed.bytes().take_while(|b| b.is_ascii_digit()).count();
    if digits > 0 && digits <= 6 {
        let rest = &trimmed[digits..];
        if let Some(after) = rest.strip_prefix(". ").or_else(|| rest.strip_prefix(") ")) {
            return Some(after.trim_start());
        }
    }
    None
}

fn is_gfm_table_separator(line: &str) -> bool {
    let cells = split_table_cells(line);
    !cells.is_empty()
        && cells.iter().all(|c| {
            let t = c.trim();
            t.len() >= 2 && t.chars().all(|ch| matches!(ch, '-' | ':')) && t.contains('-')
        })
}

fn split_table_cells(line: &str) -> Vec<&str> {
    let t = line.trim().trim_start_matches('|').trim_end_matches('|');
    t.split('|').map(str::trim).collect()
}

fn parse_table_alignments(sep_line: &str) -> Vec<Option<&'static str>> {
    split_table_cells(sep_line)
        .into_iter()
        .map(|c| {
            let t = c.trim();
            match (t.starts_with(':'), t.ends_with(':')) {
                (true, true) => Some("center"),
                (false, true) => Some("right"),
                (true, false) => Some("left"),
                (false, false) => None,
            }
        })
        .collect()
}

fn render_inline_md(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 32);
    let chars: Vec<char> = input.chars().collect();
    let n = chars.len();
    let mut i = 0usize;

    while i < n {
        // Inline code `...`
        if chars[i] == '`' {
            if let Some(end) = (i + 1..n).find(|&j| chars[j] == '`') {
                let code: String = chars[i + 1..end].iter().collect();
                out.push_str(&format!("<code>{}</code>", html_escape(&code)));
                i = end + 1;
                continue;
            }
        }

        // Image ![alt](url)
        if chars[i] == '!' && i + 1 < n && chars[i + 1] == '[' {
            if let Some((alt, url, next_i)) = parse_md_bracket_link(&chars, i + 1) {
                if is_safe_http_url(&url) {
                    out.push_str(&format!(
                        "<img src=\"{}\" alt=\"{}\" loading=\"lazy\"/>",
                        html_escape(&url),
                        html_escape(&alt)
                    ));
                } else {
                    out.push_str(&html_escape(&alt));
                }
                i = next_i;
                continue;
            }
        }

        // Link [label](url)
        if chars[i] == '[' {
            if let Some((label, url, next_i)) = parse_md_bracket_link(&chars, i) {
                if is_safe_link_url(&url) {
                    out.push_str(&format!(
                        "<a href=\"{}\" rel=\"noopener noreferrer\">{}</a>",
                        html_escape(&url),
                        render_inline_md(&label)
                    ));
                } else {
                    // Neutralize unsafe schemes like javascript: or data:
                    out.push_str(&render_inline_md(&label));
                }
                i = next_i;
                continue;
            }
        }

        // Bold **...** or __...__
        if i + 1 < n && ((chars[i] == '*' && chars[i + 1] == '*') || (chars[i] == '_' && chars[i + 1] == '_')) {
            let delim = chars[i];
            if let Some(end) = (i + 2..n.saturating_sub(1))
                .find(|&j| chars[j] == delim && chars[j + 1] == delim)
            {
                let inner: String = chars[i + 2..end].iter().collect();
                out.push_str(&format!("<strong>{}</strong>", render_inline_md(&inner)));
                i = end + 2;
                continue;
            }
        }

        // Strikethrough ~~...~~
        if i + 1 < n && chars[i] == '~' && chars[i + 1] == '~' {
            if let Some(end) =
                (i + 2..n.saturating_sub(1)).find(|&j| chars[j] == '~' && chars[j + 1] == '~')
            {
                let inner: String = chars[i + 2..end].iter().collect();
                out.push_str(&format!("<del>{}</del>", render_inline_md(&inner)));
                i = end + 2;
                continue;
            }
        }

        // Italic *...* or _..._
        if chars[i] == '*' || chars[i] == '_' {
            let delim = chars[i];
            if let Some(end) = (i + 1..n).find(|&j| chars[j] == delim) {
                if end > i + 1 {
                    let inner: String = chars[i + 1..end].iter().collect();
                    out.push_str(&format!("<em>{}</em>", render_inline_md(&inner)));
                    i = end + 1;
                    continue;
                }
            }
        }

        // Plain character (HTML escaped!)
        push_html_escaped_char(&mut out, chars[i]);
        i += 1;
    }

    out
}

fn parse_md_bracket_link(chars: &[char], open_bracket: usize) -> Option<(String, String, usize)> {
    let n = chars.len();
    let close_bracket = (open_bracket + 1..n).find(|&j| chars[j] == ']')?;
    if close_bracket + 1 >= n || chars[close_bracket + 1] != '(' {
        return None;
    }
    let close_paren = (close_bracket + 2..n).find(|&j| chars[j] == ')')?;
    let label: String = chars[open_bracket + 1..close_bracket].iter().collect();
    let url: String = chars[close_bracket + 2..close_paren]
        .iter()
        .collect::<String>()
        .trim()
        .to_string();
    Some((label, url, close_paren + 1))
}

fn is_safe_http_url(url: &str) -> bool {
    let l = url.trim().to_ascii_lowercase();
    l.starts_with("https://") || l.starts_with("http://")
}

fn is_safe_link_url(url: &str) -> bool {
    let l = url.trim().to_ascii_lowercase();
    l.starts_with("https://")
        || l.starts_with("http://")
        || l.starts_with("mailto:")
        || l.starts_with('#')
}

// ============================================================================
// 3. Offline Reading List (`ReadingListStore`) & HTML Archiver Sanitizer
// ============================================================================

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReadingListEntry {
    pub id: String,
    pub url: String,
    pub title: String,
    #[serde(default)]
    pub excerpt: String,
    #[serde(default)]
    pub author: Option<String>,
    #[serde(default)]
    pub site_name: Option<String>,
    pub read: bool,
    pub scroll_percent: f32,
    pub word_count: usize,
    pub reading_time_minutes: u32,
    #[serde(default)]
    pub offline_html_sanitized: Option<String>,
    pub added_unix: u64,
    pub updated_unix: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReadingListStore {
    pub entries: Vec<ReadingListEntry>,
    next_id: u64,
}

impl ReadingListStore {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            next_id: 1,
        }
    }

    pub fn load_from_path(path: &Path) -> Result<Self, PageToolsError> {
        if !path.exists() {
            return Ok(Self::new());
        }
        let raw = std::fs::read_to_string(path)?;
        Ok(serde_json::from_str(&raw)?)
    }

    pub fn save_to_path(&self, path: &Path) -> Result<(), PageToolsError> {
        let bytes = serde_json::to_vec_pretty(self)?;
        atomic_write_with_backup(path, &bytes)?;
        Ok(())
    }

    /// Saves a page into the offline reading list, automatically sanitizing raw HTML
    /// (stripping `<script>`, `<iframe>`, `on*` handlers, and dangerous schemes).
    pub fn add_or_update(
        &mut self,
        url: &str,
        title: &str,
        raw_html: Option<&str>,
        now_unix: u64,
    ) -> String {
        let sanitized = raw_html.map(sanitize_html_for_offline_archive);
        let plain_text = sanitized
            .as_deref()
            .map(strip_all_html_tags)
            .unwrap_or_default();
        let word_count = count_words(&plain_text);
        let reading_time_minutes = ((word_count as f32) / 220.0).ceil().max(1.0) as u32;
        let excerpt: String = plain_text.chars().take(240).collect();

        if let Some(existing) = self
            .entries
            .iter_mut()
            .find(|e| e.url.eq_ignore_ascii_case(url.trim()))
        {
            if !title.trim().is_empty() {
                existing.title = title.trim().to_string();
            }
            if sanitized.is_some() {
                existing.offline_html_sanitized = sanitized;
                existing.word_count = word_count;
                existing.reading_time_minutes = reading_time_minutes;
                existing.excerpt = excerpt;
            }
            existing.updated_unix = now_unix;
            return existing.id.clone();
        }

        let id = format!("rl_{}", self.next_id.max(1));
        self.next_id = self.next_id.max(1) + 1;
        self.entries.push(ReadingListEntry {
            id: id.clone(),
            url: url.trim().to_string(),
            title: if title.trim().is_empty() {
                url.trim().to_string()
            } else {
                title.trim().to_string()
            },
            excerpt,
            author: None,
            site_name: None,
            read: false,
            scroll_percent: 0.0,
            word_count,
            reading_time_minutes,
            offline_html_sanitized: sanitized,
            added_unix: now_unix,
            updated_unix: now_unix,
        });
        id
    }

    pub fn get(&self, id: &str) -> Option<&ReadingListEntry> {
        self.entries.iter().find(|e| e.id == id)
    }

    /// Updates scroll progress (0.0..=100.0) and automatically marks the article as read at >= 90%.
    pub fn update_scroll_progress(
        &mut self,
        id: &str,
        scroll_percent: f32,
        now_unix: u64,
    ) -> Result<bool, PageToolsError> {
        let entry = self
            .entries
            .iter_mut()
            .find(|e| e.id == id)
            .ok_or_else(|| PageToolsError::NotFound(id.to_string()))?;
        let clamped = scroll_percent.clamp(0.0, 100.0);
        entry.scroll_percent = clamped;
        if clamped >= 90.0 {
            entry.read = true;
        }
        entry.updated_unix = now_unix;
        Ok(entry.read)
    }

    pub fn mark_read(&mut self, id: &str, read: bool, now_unix: u64) -> Result<(), PageToolsError> {
        let entry = self
            .entries
            .iter_mut()
            .find(|e| e.id == id)
            .ok_or_else(|| PageToolsError::NotFound(id.to_string()))?;
        entry.read = read;
        entry.updated_unix = now_unix;
        Ok(())
    }

    pub fn remove(&mut self, id: &str) -> bool {
        let before = self.entries.len();
        self.entries.retain(|e| e.id != id);
        self.entries.len() != before
    }

    pub fn list(&self, only_unread: bool) -> Vec<&ReadingListEntry> {
        self.entries
            .iter()
            .filter(|e| !only_unread || !e.read)
            .collect()
    }
}

/// Sanitizes HTML for safe offline archiving and Reader Mode rendering.
/// Removes dangerous elements (`<script>`, `<iframe>`, `<object>`, `<embed>`, `<applet>`,
/// `<form>`, `<base>`, `<style>`, `<noscript>`), strips all `on*` event handler attributes,
/// and neutralizes `javascript:` / `vbscript:` / `data:text/html` URLs.
pub fn sanitize_html_for_offline_archive(html: &str) -> String {
    let mut cleaned = strip_elements_with_body(
        html,
        &[
            "script", "iframe", "object", "embed", "applet", "style", "noscript", "form", "template",
        ],
    );
    // Remove HTML comments
    cleaned = strip_html_comments(&cleaned);

    // Filter tags & attributes safely
    let mut out = String::with_capacity(cleaned.len());
    let bytes = cleaned.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'<' {
            let Some(end_rel) = find_tag_end(&cleaned[i..]) else {
                out.push_str(&html_escape(&cleaned[i..]));
                break;
            };
            let raw_tag = &cleaned[i..=i + end_rel];
            out.push_str(&sanitize_single_tag(raw_tag));
            i += end_rel + 1;
        } else {
            let next_lt = cleaned[i..].find('<').unwrap_or(cleaned.len() - i);
            out.push_str(&cleaned[i..i + next_lt]);
            i += next_lt;
        }
    }
    out
}

fn sanitize_single_tag(raw_tag: &str) -> String {
    let inner = raw_tag[1..raw_tag.len() - 1].trim();
    if inner.is_empty() || inner.starts_with('!') || inner.starts_with('?') {
        return String::new();
    }
    let is_close = inner.starts_with('/');
    let is_self_close = inner.ends_with('/');
    let core = inner.trim_start_matches('/').trim_end_matches('/').trim();
    let mut parts = core.splitn(2, char::is_whitespace);
    let tag_name = parts.next().unwrap_or("").to_ascii_lowercase();
    let attrs_raw = parts.next().unwrap_or("");

    const ALLOWED_TAGS: &[&str] = &[
        "article", "section", "main", "div", "p", "br", "hr", "h1", "h2", "h3", "h4", "h5", "h6",
        "ul", "ol", "li", "dl", "dt", "dd", "blockquote", "pre", "code", "strong", "b", "em", "i",
        "u", "s", "del", "ins", "mark", "small", "sub", "sup", "a", "img", "figure", "figcaption",
        "table", "thead", "tbody", "tfoot", "tr", "th", "td", "caption", "span", "time", "cite",
        "abbr", "details", "summary",
    ];

    if !ALLOWED_TAGS.contains(&tag_name.as_str()) {
        return String::new();
    }
    if is_close {
        return format!("</{}>", tag_name);
    }

    let attrs = parse_tag_attributes(attrs_raw);
    let mut safe_attrs = String::new();
    for (k, v) in attrs {
        let kl = k.to_ascii_lowercase();
        // Never allow inline event handlers (`on*`) or style/srcdoc injection
        if kl.starts_with("on") || kl == "srcdoc" || kl == "style" {
            continue;
        }
        match kl.as_str() {
            "href" => {
                if is_safe_link_url(&v) {
                    safe_attrs.push_str(&format!(
                        " href=\"{}\" rel=\"noopener noreferrer\"",
                        html_escape(&v)
                    ));
                }
            }
            "src" => {
                if is_safe_http_url(&v) {
                    safe_attrs.push_str(&format!(" src=\"{}\"", html_escape(&v)));
                }
            }
            "alt" | "title" | "id" | "colspan" | "rowspan" | "datetime" | "lang" => {
                safe_attrs.push_str(&format!(" {}=\"{}\"", kl, html_escape(&v)));
            }
            _ => {}
        }
    }

    if is_self_close || matches!(tag_name.as_str(), "br" | "hr" | "img") {
        format!("<{}{}/>", tag_name, safe_attrs)
    } else {
        format!("<{}{}>", tag_name, safe_attrs)
    }
}

// ============================================================================
// 4. Reader Mode (`ReaderModeExtractor` & `singularity://reader` Generator)
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeadingAnchor {
    pub level: u8,
    pub id: String,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtractedArticle {
    pub url: String,
    pub title: String,
    #[serde(default)]
    pub byline: Option<String>,
    #[serde(default)]
    pub site_name: Option<String>,
    pub excerpt: String,
    pub content_html: String,
    pub text_content: String,
    pub word_count: usize,
    pub reading_time_minutes: u32,
    pub toc: Vec<HeadingAnchor>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReaderTheme {
    OledBlack,
    Slate,
    Sepia,
    Light,
    WcagAaa,
}

impl Default for ReaderTheme {
    fn default() -> Self {
        Self::OledBlack
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReaderRenderOptions {
    pub theme: ReaderTheme,
    pub font_family: String,
    pub use_open_dyslexic: bool,
    pub font_size_px: u8,
    pub line_height: f32,
    pub max_width_ch: u8,
    /// Optional Line Focus mode highlighting 1, 3, or 5 lines while dimming peripheral text.
    pub line_focus_lines: Option<u8>,
}

impl Default for ReaderRenderOptions {
    fn default() -> Self {
        Self {
            theme: ReaderTheme::OledBlack,
            font_family: "Georgia, 'Iowan Old Style', serif".into(),
            use_open_dyslexic: false,
            font_size_px: 19,
            line_height: 1.7,
            max_width_ch: 68,
            line_focus_lines: None,
        }
    }
}

pub struct ReaderModeExtractor;

impl ReaderModeExtractor {
    /// Heuristically determines whether `html` looks like a readable article rather than a web app
    /// or navigation portal.
    pub fn is_probably_readerable(html: &str) -> bool {
        if html.len() < 200 {
            return false;
        }
        let cleaned = strip_elements_with_body(
            html,
            &["script", "style", "nav", "header", "footer", "aside", "noscript", "svg"],
        );
        let lower = cleaned.to_ascii_lowercase();
        let has_article_tag = lower.contains("<article") || lower.contains("<main");

        // Count substantial <p> blocks (>= 60 chars)
        let mut substantial_p_chars = 0usize;
        let mut p_count = 0usize;
        let mut cursor = 0usize;
        while let Some(rel) = find_tag_ci(&cleaned[cursor..], "p") {
            let start = cursor + rel;
            let Some(open_end) = cleaned[start..].find('>') else {
                break;
            };
            let body_start = start + open_end + 1;
            let close_rel = find_close_tag_ci(&cleaned[body_start..], "p")
                .unwrap_or_else(|| (cleaned.len() - body_start).min(4000));
            let text = strip_all_html_tags(&cleaned[body_start..body_start + close_rel]);
            let char_len = text.trim().chars().count();
            if char_len >= 60 {
                substantial_p_chars += char_len;
                p_count += 1;
            }
            cursor = body_start + close_rel;
            if cursor >= cleaned.len() {
                break;
            }
        }

        substantial_p_chars >= 280 || (has_article_tag && substantial_p_chars >= 160 && p_count >= 2)
    }

    /// Pure-Rust Readability article extractor returning cleaned content HTML, metadata,
    /// reading time estimate, and an extracted Table of Contents (`Vec<HeadingAnchor>`).
    pub fn extract_article(url: &str, html: &str) -> ExtractedArticle {
        let title = extract_meta_content(html, "property", "og:title")
            .or_else(|| extract_tag_inner_text(html, "h1"))
            .or_else(|| extract_tag_inner_text(html, "title"))
            .unwrap_or_else(|| url.to_string())
            .trim()
            .to_string();

        let byline = extract_meta_content(html, "name", "author")
            .or_else(|| extract_meta_content(html, "property", "article:author"));
        let site_name = extract_meta_content(html, "property", "og:site_name");

        let stripped = strip_elements_with_body(
            html,
            &[
                "script", "style", "nav", "header", "footer", "aside", "noscript", "iframe",
                "form", "button", "svg",
            ],
        );

        // Prefer <article>, then <main>, then best-scoring <body>/<section>
        let raw_content = extract_best_container(&stripped).unwrap_or_else(|| stripped.clone());
        let sanitized = sanitize_html_for_offline_archive(&raw_content);
        let (content_with_anchors, toc) = inject_heading_anchors(&sanitized);
        let text_content = strip_all_html_tags(&content_with_anchors);
        let word_count = count_words(&text_content);
        let reading_time_minutes = ((word_count as f32) / 220.0).ceil().max(1.0) as u32;
        let excerpt: String = text_content.chars().take(240).collect();

        ExtractedArticle {
            url: url.to_string(),
            title,
            byline,
            site_name,
            excerpt,
            content_html: content_with_anchors,
            text_content,
            word_count,
            reading_time_minutes,
            toc,
        }
    }

    /// Generates a complete, self-contained `singularity://reader` HTML page supporting
    /// OLED / Slate / Sepia / Light / WCAG AAA themes, `OpenDyslexic`, and Line Focus (1/3/5 lines).
    pub fn render_reader_page_html(
        article: &ExtractedArticle,
        opts: &ReaderRenderOptions,
    ) -> String {
        let (bg, surface, fg, muted, accent, border) = match opts.theme {
            ReaderTheme::OledBlack => ("#000000", "#0C0D12", "#F5F3EE", "#8A8D96", "#38D9F5", "#1A1B20"),
            ReaderTheme::Slate => ("#141821", "#1B212E", "#E6ECF5", "#93A0B8", "#B975FF", "#2A3244"),
            ReaderTheme::Sepia => ("#F4ECD8", "#EBE0C5", "#3B2F21", "#705D46", "#8B4513", "#D8C9A8"),
            ReaderTheme::Light => ("#FFFFFF", "#F6F7F9", "#17181C", "#5B606B", "#005FCC", "#E1E4EA"),
            ReaderTheme::WcagAaa => ("#000000", "#0A0A0A", "#FFFFFF", "#FFEE00", "#00FFFF", "#FFFFFF"),
        };

        let font_stack = if opts.use_open_dyslexic {
            "'OpenDyslexic', 'OpenDyslexic3', 'Comic Sans MS', sans-serif".to_string()
        } else {
            opts.font_family.clone()
        };

        let focus_lines = opts
            .line_focus_lines
            .map(|n| match n {
                1 | 3 | 5 => n,
                n if n <= 2 => 1,
                n if n <= 4 => 3,
                _ => 5,
            });
        let focus_css = if let Some(lines) = focus_lines {
            let band_em = (lines as f32) * opts.line_height;
            format!(
                ".line-focus-mask{{position:fixed;inset:0;pointer-events:none;z-index:20;\
                 background:linear-gradient(to bottom,rgba(0,0,0,.78) calc(50vh - {half:.2}em),\
                 transparent calc(50vh - {half:.2}em),transparent calc(50vh + {half:.2}em),\
                 rgba(0,0,0,.78) calc(50vh + {half:.2}em));}}",
                half = band_em / 2.0
            )
        } else {
            String::new()
        };

        let mut toc_html = String::new();
        if !article.toc.is_empty() {
            toc_html.push_str("<nav class=\"toc\" aria-label=\"Table of Contents\"><strong>Contents</strong><ul>");
            for h in &article.toc {
                let indent = (h.level.saturating_sub(1) as usize) * 12;
                toc_html.push_str(&format!(
                    "<li style=\"margin-left:{}px\"><a href=\"#{}\">{}</a></li>",
                    indent,
                    html_escape(&h.id),
                    html_escape(&h.text)
                ));
            }
            toc_html.push_str("</ul></nav>");
        }

        let byline_html = article
            .byline
            .as_deref()
            .map(|b| format!("<span>{}</span> · ", html_escape(b)))
            .unwrap_or_default();
        let focus_div = if let Some(lines) = focus_lines {
            format!(
                "<div class=\"line-focus-mask\" data-line-focus=\"{}\"></div>",
                lines
            )
        } else {
            String::new()
        };

        format!(
            "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"UTF-8\">\
             <title>{title} — Singularity Reader</title>\
             <style>\
             :root{{--bg:{bg};--surface:{surface};--fg:{fg};--muted:{muted};--accent:{accent};--border:{border};}}\
             body{{margin:0;background:var(--bg);color:var(--fg);font-family:{font};font-size:{fs}px;line-height:{lh};}}\
             .reader-shell{{max-width:{mw}ch;margin:3rem auto;padding:0 1.5rem 6rem;}}\
             header{{border-bottom:1px solid var(--border);padding-bottom:1.25rem;margin-bottom:2rem;}}\
             h1{{line-height:1.2;margin:0 0 .75rem;}}\
             .meta{{color:var(--muted);font-size:.85em;}}\
             a{{color:var(--accent);}}\
             .toc{{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:1rem 1.25rem;margin-bottom:2rem;font-size:.85em;}}\
             .toc ul{{list-style:none;padding:0;margin:.5rem 0 0;}}\
             .toc li{{margin:.25rem 0;}}\
             blockquote{{border-left:3px solid var(--accent);margin:1.25rem 0;padding:.25rem 1rem;color:var(--muted);}}\
             pre,code{{background:var(--surface);border-radius:6px;}}\
             pre{{padding:1rem;overflow-x:auto;border:1px solid var(--border);}}\
             img{{max-width:100%;height:auto;border-radius:8px;}}\
             {focus_css}\
             </style></head><body data-theme=\"{theme_name}\">{focus_div}\
             <main class=\"reader-shell\">\
             <header><h1>{title}</h1><div class=\"meta\">{byline}<span>{words} words · {mins} min read</span></div></header>\
             {toc}\
             <article>{content}</article>\
             </main></body></html>",
            title = html_escape(&article.title),
            bg = bg,
            surface = surface,
            fg = fg,
            muted = muted,
            accent = accent,
            border = border,
            font = font_stack,
            fs = opts.font_size_px.clamp(12, 36),
            lh = opts.line_height.clamp(1.2, 2.6),
            mw = opts.max_width_ch.clamp(40, 100),
            focus_css = focus_css,
            theme_name = format!("{:?}", opts.theme),
            focus_div = focus_div,
            byline = byline_html,
            words = article.word_count,
            mins = article.reading_time_minutes,
            toc = toc_html,
            content = article.content_html,
        )
    }
}

fn extract_best_container(html: &str) -> Option<String> {
    for tag in ["article", "main"] {
        if let Some(body) = extract_tag_inner_html(html, tag) {
            if strip_all_html_tags(&body).trim().chars().count() >= 120 {
                return Some(body);
            }
        }
    }
    extract_tag_inner_html(html, "body")
}

fn inject_heading_anchors(sanitized_html: &str) -> (String, Vec<HeadingAnchor>) {
    let mut out = String::with_capacity(sanitized_html.len() + 128);
    let mut toc = Vec::new();
    let mut used_ids: HashSet<String> = HashSet::new();
    let mut i = 0usize;
    let bytes = sanitized_html.as_bytes();

    while i < bytes.len() {
        if bytes[i] == b'<'
            && i + 2 < bytes.len()
            && (bytes[i + 1] == b'h' || bytes[i + 1] == b'H')
            && (b'1'..=b'6').contains(&bytes[i + 2])
            && matches!(bytes.get(i + 3).copied(), Some(b'>' | b' ' | b'\t'))
        {
            let level = bytes[i + 2] - b'0';
            if let Some(open_end) = sanitized_html[i..].find('>') {
                let close_tag = format!("</h{}>", level);
                let after_open = i + open_end + 1;
                if let Some(close_rel) = find_substr_ci(&sanitized_html[after_open..], &close_tag) {
                    let inner = &sanitized_html[after_open..after_open + close_rel];
                    let plain = strip_all_html_tags(inner).trim().to_string();
                    let mut id = slugify_heading(&plain);
                    if id.is_empty() {
                        id = format!("section-{}", toc.len() + 1);
                    }
                    let base = id.clone();
                    let mut suffix = 2usize;
                    while !used_ids.insert(id.clone()) {
                        id = format!("{}-{}", base, suffix);
                        suffix += 1;
                    }
                    if !plain.is_empty() {
                        toc.push(HeadingAnchor {
                            level,
                            id: id.clone(),
                            text: plain,
                        });
                    }
                    out.push_str(&format!(
                        "<h{} id=\"{}\">{}</h{}>",
                        level,
                        html_escape(&id),
                        inner,
                        level
                    ));
                    i = after_open + close_rel + close_tag.len();
                    continue;
                }
            }
        }
        let ch = sanitized_html[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }

    (out, toc)
}

// ============================================================================
// 5. PDF Annotations (`PdfAnnotationStore`, `PdfFormState`) & Capture Annotations
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct PdfRect {
    pub x: f32,
    pub y: f32,
    pub width: f32,
    pub height: f32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PdfAnnotationKind {
    Highlight {
        rects: Vec<PdfRect>,
        color_hex: String,
        opacity: f32,
        #[serde(default)]
        quoted_text: Option<String>,
    },
    InkStroke {
        points: Vec<(f32, f32)>,
        stroke_width: f32,
        color_hex: String,
        opacity: f32,
    },
    FreeText {
        rect: PdfRect,
        text: String,
        font_size: f32,
        color_hex: String,
    },
    StickyNote {
        x: f32,
        y: f32,
        text: String,
        color_hex: String,
        #[serde(default)]
        resolved: bool,
    },
    Signature {
        rect: PdfRect,
        strokes: Vec<Vec<(f32, f32)>>,
        #[serde(default)]
        signer_name: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PdfAnnotation {
    pub id: String,
    pub page_index: u32,
    pub kind: PdfAnnotationKind,
    #[serde(default)]
    pub author: Option<String>,
    pub created_unix: u64,
    pub updated_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum PdfFormFieldValue {
    Text(String),
    Checkbox(bool),
    Radio(String),
    Choice(Vec<String>),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PdfFormField {
    pub name: String,
    pub page_index: u32,
    pub value: PdfFormFieldValue,
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub read_only: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PdfFormState {
    pub document_id: String,
    pub fields: HashMap<String, PdfFormField>,
    pub updated_unix: u64,
}

impl PdfFormState {
    pub fn set_field(&mut self, field: PdfFormField, now_unix: u64) {
        self.fields.insert(field.name.clone(), field);
        self.updated_unix = now_unix;
    }

    pub fn missing_required_fields(&self) -> Vec<&str> {
        self.fields
            .values()
            .filter(|f| {
                f.required
                    && match &f.value {
                        PdfFormFieldValue::Text(s) | PdfFormFieldValue::Radio(s) => {
                            s.trim().is_empty()
                        }
                        PdfFormFieldValue::Checkbox(b) => !b,
                        PdfFormFieldValue::Choice(v) => v.is_empty(),
                    }
            })
            .map(|f| f.name.as_str())
            .collect()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PdfDocumentAnnotations {
    pub document_id: String,
    pub annotations: Vec<PdfAnnotation>,
    pub form_state: PdfFormState,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PdfAnnotationStore {
    pub documents: HashMap<String, PdfDocumentAnnotations>,
    next_id: u64,
}

impl PdfAnnotationStore {
    pub fn new() -> Self {
        Self {
            documents: HashMap::new(),
            next_id: 1,
        }
    }

    pub fn add_annotation(
        &mut self,
        document_id: &str,
        page_index: u32,
        kind: PdfAnnotationKind,
        author: Option<String>,
        now_unix: u64,
    ) -> String {
        let id = format!("pdfa_{}", self.next_id.max(1));
        self.next_id = self.next_id.max(1) + 1;
        let doc = self
            .documents
            .entry(document_id.to_string())
            .or_insert_with(|| PdfDocumentAnnotations {
                document_id: document_id.to_string(),
                annotations: Vec::new(),
                form_state: PdfFormState {
                    document_id: document_id.to_string(),
                    fields: HashMap::new(),
                    updated_unix: now_unix,
                },
            });
        doc.annotations.push(PdfAnnotation {
            id: id.clone(),
            page_index,
            kind,
            author,
            created_unix: now_unix,
            updated_unix: now_unix,
        });
        id
    }

    pub fn remove_annotation(&mut self, document_id: &str, annotation_id: &str) -> bool {
        if let Some(doc) = self.documents.get_mut(document_id) {
            let before = doc.annotations.len();
            doc.annotations.retain(|a| a.id != annotation_id);
            return doc.annotations.len() != before;
        }
        false
    }

    pub fn annotations_on_page(&self, document_id: &str, page_index: u32) -> Vec<&PdfAnnotation> {
        self.documents
            .get(document_id)
            .map(|d| {
                d.annotations
                    .iter()
                    .filter(|a| a.page_index == page_index)
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn form_state_mut(&mut self, document_id: &str) -> &mut PdfFormState {
        &mut self
            .documents
            .entry(document_id.to_string())
            .or_insert_with(|| PdfDocumentAnnotations {
                document_id: document_id.to_string(),
                annotations: Vec::new(),
                form_state: PdfFormState {
                    document_id: document_id.to_string(),
                    fields: HashMap::new(),
                    updated_unix: 0,
                },
            })
            .form_state
    }
}

// --- Capture Annotation Document ---

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "tool", rename_all = "snake_case")]
pub enum CaptureToolKind {
    Crop {
        x: f32,
        y: f32,
        width: f32,
        height: f32,
    },
    Arrow {
        x1: f32,
        y1: f32,
        x2: f32,
        y2: f32,
        color_hex: String,
        stroke_width: f32,
    },
    Rect {
        x: f32,
        y: f32,
        width: f32,
        height: f32,
        color_hex: String,
        stroke_width: f32,
        #[serde(default)]
        fill_hex: Option<String>,
    },
    Pen {
        points: Vec<(f32, f32)>,
        color_hex: String,
        stroke_width: f32,
    },
    Blur {
        x: f32,
        y: f32,
        width: f32,
        height: f32,
        radius: f32,
    },
    Pixelate {
        x: f32,
        y: f32,
        width: f32,
        height: f32,
        block_size: u32,
    },
    Text {
        x: f32,
        y: f32,
        content: String,
        font_size: f32,
        color_hex: String,
        #[serde(default)]
        background_hex: Option<String>,
    },
    StepBadge {
        x: f32,
        y: f32,
        step_number: u32,
        radius: f32,
        color_hex: String,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CaptureAnnotationItem {
    pub id: String,
    pub tool: CaptureToolKind,
    pub z_index: i32,
    pub visible: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureAnnotationDocument {
    pub id: String,
    #[serde(default)]
    pub source_url: Option<String>,
    pub image_width: u32,
    pub image_height: u32,
    pub items: Vec<CaptureAnnotationItem>,
    next_id: u64,
    #[serde(skip)]
    undo_stack: Vec<Vec<CaptureAnnotationItem>>,
    #[serde(skip)]
    redo_stack: Vec<Vec<CaptureAnnotationItem>>,
}

impl CaptureAnnotationDocument {
    pub fn new(id: &str, source_url: Option<String>, width: u32, height: u32) -> Self {
        Self {
            id: id.to_string(),
            source_url,
            image_width: width,
            image_height: height,
            items: Vec::new(),
            next_id: 1,
            undo_stack: Vec::new(),
            redo_stack: Vec::new(),
        }
    }

    pub fn next_step_number(&self) -> u32 {
        self.items
            .iter()
            .filter_map(|i| match i.tool {
                CaptureToolKind::StepBadge { step_number, .. } => Some(step_number),
                _ => None,
            })
            .max()
            .unwrap_or(0)
            + 1
    }

    pub fn add_item(&mut self, tool: CaptureToolKind) -> String {
        self.undo_stack.push(self.items.clone());
        self.redo_stack.clear();
        let id = format!("cap_{}", self.next_id.max(1));
        self.next_id = self.next_id.max(1) + 1;
        let z = self.items.len() as i32;
        self.items.push(CaptureAnnotationItem {
            id: id.clone(),
            tool,
            z_index: z,
            visible: true,
        });
        id
    }

    pub fn remove_item(&mut self, id: &str) -> bool {
        if !self.items.iter().any(|i| i.id == id) {
            return false;
        }
        self.undo_stack.push(self.items.clone());
        self.redo_stack.clear();
        self.items.retain(|i| i.id != id);
        true
    }

    pub fn undo(&mut self) -> bool {
        if let Some(prev) = self.undo_stack.pop() {
            self.redo_stack.push(self.items.clone());
            self.items = prev;
            true
        } else {
            false
        }
    }

    pub fn redo(&mut self) -> bool {
        if let Some(next) = self.redo_stack.pop() {
            self.undo_stack.push(self.items.clone());
            self.items = next;
            true
        } else {
            false
        }
    }

    /// Renders all visible capture annotations to a standalone vector SVG overlay.
    pub fn render_overlay_svg(&self) -> String {
        let mut body = String::new();
        for item in &self.items {
            if !item.visible {
                continue;
            }
            match &item.tool {
                CaptureToolKind::Crop { x, y, width, height } => {
                    body.push_str(&format!(
                        "<rect x=\"{}\" y=\"{}\" width=\"{}\" height=\"{}\" fill=\"none\" stroke=\"#38D9F5\" stroke-dasharray=\"6 4\" stroke-width=\"2\"/>",
                        x, y, width, height
                    ));
                }
                CaptureToolKind::Arrow { x1, y1, x2, y2, color_hex, stroke_width } => {
                    body.push_str(&format!(
                        "<line x1=\"{}\" y1=\"{}\" x2=\"{}\" y2=\"{}\" stroke=\"{}\" stroke-width=\"{}\" stroke-linecap=\"round\"/>",
                        x1, y1, x2, y2, html_escape(color_hex), stroke_width
                    ));
                }
                CaptureToolKind::Rect { x, y, width, height, color_hex, stroke_width, fill_hex } => {
                    let fill = fill_hex.as_deref().unwrap_or("none");
                    body.push_str(&format!(
                        "<rect x=\"{}\" y=\"{}\" width=\"{}\" height=\"{}\" fill=\"{}\" stroke=\"{}\" stroke-width=\"{}\"/>",
                        x, y, width, height, html_escape(fill), html_escape(color_hex), stroke_width
                    ));
                }
                CaptureToolKind::Pen { points, color_hex, stroke_width } => {
                    if !points.is_empty() {
                        let pts: String = points
                            .iter()
                            .map(|(px, py)| format!("{},{}", px, py))
                            .collect::<Vec<_>>()
                            .join(" ");
                        body.push_str(&format!(
                            "<polyline points=\"{}\" fill=\"none\" stroke=\"{}\" stroke-width=\"{}\" stroke-linecap=\"round\" stroke-linejoin=\"round\"/>",
                            pts, html_escape(color_hex), stroke_width
                        ));
                    }
                }
                CaptureToolKind::Blur { x, y, width, height, radius } => {
                    body.push_str(&format!(
                        "<rect x=\"{}\" y=\"{}\" width=\"{}\" height=\"{}\" fill=\"rgba(0,0,0,0.45)\" data-blur-radius=\"{}\"/>",
                        x, y, width, height, radius
                    ));
                }
                CaptureToolKind::Pixelate { x, y, width, height, block_size } => {
                    body.push_str(&format!(
                        "<rect x=\"{}\" y=\"{}\" width=\"{}\" height=\"{}\" fill=\"rgba(0,0,0,0.65)\" data-pixel-block=\"{}\"/>",
                        x, y, width, height, block_size
                    ));
                }
                CaptureToolKind::Text { x, y, content, font_size, color_hex, .. } => {
                    body.push_str(&format!(
                        "<text x=\"{}\" y=\"{}\" font-size=\"{}\" fill=\"{}\" font-family=\"system-ui,sans-serif\">{}</text>",
                        x, y, font_size, html_escape(color_hex), html_escape(content)
                    ));
                }
                CaptureToolKind::StepBadge { x, y, step_number, radius, color_hex } => {
                    body.push_str(&format!(
                        "<g><circle cx=\"{x}\" cy=\"{y}\" r=\"{r}\" fill=\"{c}\"/><text x=\"{x}\" y=\"{y}\" text-anchor=\"middle\" dominant-baseline=\"central\" fill=\"#000000\" font-weight=\"700\" font-size=\"{fs}\">{n}</text></g>",
                        x = x,
                        y = y,
                        r = radius,
                        c = html_escape(color_hex),
                        fs = (radius * 1.1).max(10.0),
                        n = step_number
                    ));
                }
            }
        }
        format!(
            "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 {} {}\">{}</svg>",
            self.image_width, self.image_height, body
        )
    }
}

// ============================================================================
// 6. Text Fragments (`#:~:text=`) Builder (WICG Scroll-to-Text-Fragment)
// ============================================================================

/// Builds a WICG Scroll-to-Text-Fragment URL (`#:~:text=...`) with automatic anti-ambiguity
/// prefix/suffix context when `selected_text` appears multiple times in `page_text`,
/// and strict RFC 3986 + `-` (`%2D`) + `,` (`%2C`) encoding.
pub fn build_text_fragment_url(
    page_url: &str,
    page_text: &str,
    selected_text: &str,
) -> Option<String> {
    let base_url = page_url.trim().split('#').next()?.trim();
    let sel = selected_text.trim();
    if base_url.is_empty() || sel.is_empty() {
        return None;
    }

    // Locate occurrences of `sel` in `page_text`
    let occurrences: Vec<usize> = page_text.match_indices(sel).map(|(idx, _)| idx).collect();

    let (prefix_ctx, suffix_ctx) = if occurrences.len() > 1 {
        let first_pos = occurrences[0];
        let before = &page_text[..first_pos];
        let after = &page_text[first_pos + sel.len()..];

        let prev_words: Vec<&str> = before.split_whitespace().collect();
        let next_words: Vec<&str> = after.split_whitespace().collect();

        // Find minimal prefix/suffix context that uniquely disambiguates occurrence 0
        let mut chosen_prefix: Option<String> = None;
        let mut chosen_suffix: Option<String> = None;
        for w_count in 1..=4 {
            let p = if prev_words.len() >= w_count {
                Some(prev_words[prev_words.len() - w_count..].join(" "))
            } else if !prev_words.is_empty() {
                Some(prev_words.join(" "))
            } else {
                None
            };
            let s = if next_words.len() >= w_count {
                Some(next_words[..w_count].join(" "))
            } else if !next_words.is_empty() {
                Some(next_words.join(" "))
            } else {
                None
            };

            let unique = occurrences[1..].iter().all(|&other_pos| {
                let ob = page_text[..other_pos].trim_end();
                let oa = page_text[other_pos + sel.len()..].trim_start();
                let p_match = p.as_deref().map_or(true, |pw| ob.ends_with(pw));
                let s_match = s.as_deref().map_or(true, |sw| oa.starts_with(sw));
                !(p_match && s_match)
            });

            chosen_prefix = p;
            chosen_suffix = s;
            if unique {
                break;
            }
        }
        (chosen_prefix, chosen_suffix)
    } else {
        (None, None)
    };

    // Range encoding for very long selections (> 240 chars)
    let words: Vec<&str> = sel.split_whitespace().collect();
    let core_fragment = if sel.len() > 240 && words.len() >= 10 {
        let start_phrase = words[..4].join(" ");
        let end_phrase = words[words.len() - 4..].join(" ");
        format!(
            "{},{}",
            encode_text_fragment_term(&start_phrase),
            encode_text_fragment_term(&end_phrase)
        )
    } else {
        encode_text_fragment_term(sel)
    };

    let mut directive = String::new();
    if let Some(p) = prefix_ctx {
        directive.push_str(&encode_text_fragment_term(&p));
        directive.push_str("-,");
    }
    directive.push_str(&core_fragment);
    if let Some(s) = suffix_ctx {
        directive.push_str(",-");
        directive.push_str(&encode_text_fragment_term(&s));
    }

    Some(format!("{}#:~:text={}", base_url, directive))
}

fn encode_text_fragment_term(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 16);
    for b in input.bytes() {
        match b {
            // WICG requires '-' and ',' to be percent-encoded even though unreserved in RFC 3986
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                const HEX: &[u8; 16] = b"0123456789ABCDEF";
                out.push('%');
                out.push(HEX[(b >> 4) as usize] as char);
                out.push(HEX[(b & 0x0F) as usize] as char);
            }
        }
    }
    out
}

// ============================================================================
// 7. Pure-Rust Developer Viewers (View Source, JSONPath, XML/XPath, Diff, RSS, Smart Copy)
// ============================================================================

/// Formats raw HTML source into an OLED-themed syntax-highlighted viewer with clickable `#L<n>`
/// line anchors, collapsible `<details open>` regions for large blocks, and safe clickable links.
pub fn format_view_source_html(url: &str, raw_html: &str) -> String {
    let mut rows = String::with_capacity(raw_html.len() * 2 + 512);
    let mut in_comment = false;

    for (idx, line) in raw_html.lines().enumerate() {
        let ln = idx + 1;
        let highlighted = highlight_html_source_line(line, &mut in_comment);
        let lower_t = line.trim().to_ascii_lowercase();
        let is_collapsible_open = lower_t.starts_with("<head")
            || lower_t.starts_with("<style")
            || lower_t.starts_with("<script");
        let is_collapsible_close = lower_t.starts_with("</head>")
            || lower_t.starts_with("</style>")
            || lower_t.starts_with("</script>");

        if is_collapsible_open {
            rows.push_str("<details open class=\"fold\"><summary>");
        }
        rows.push_str(&format!(
            "<div class=\"src-line\" id=\"L{ln}\"><a class=\"ln\" href=\"#L{ln}\">{ln}</a><span class=\"code\">{hl}</span></div>\n",
            ln = ln,
            hl = highlighted
        ));
        if is_collapsible_open {
            rows.push_str("</summary>");
        }
        if is_collapsible_close {
            rows.push_str("</details>");
        }
    }

    format!(
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"UTF-8\">\
         <title>view-source:{title}</title>\
         <style>\
         body{{margin:0;background:#000000;color:#F5F3EE;font:13px/1.55 'SF Mono','Cascadia Code',ui-monospace,monospace;}}\
         .bar{{position:sticky;top:0;background:#0C0D12;border-bottom:1px solid #1A1B20;padding:8px 14px;color:#38D9F5;}}\
         .src-line{{display:flex;padding:0 12px;}}\
         .src-line:target{{background:#1B1F30;}}\
         .ln{{min-width:4ch;text-align:right;padding-right:14px;color:#5C5E65;text-decoration:none;user-select:none;}}\
         .code{{white-space:pre-wrap;word-break:break-all;}}\
         .hl-tag{{color:#38D9F5;}}.hl-attr{{color:#B975FF;}}.hl-str{{color:#F0B254;}}.hl-cmt{{color:#6A737D;font-style:italic;}}\
         .hl-link{{color:#FFDF9E;text-decoration:underline;}}\
         details.fold>summary{{list-style:disclosure-closed inside;cursor:pointer;}}\
         details.fold[open]>summary{{list-style:disclosure-open inside;}}\
         </style></head><body>\
         <div class=\"bar\">view-source:{title}</div>\
         <div class=\"src-wrap\">{rows}</div></body></html>",
        title = html_escape(url),
        rows = rows
    )
}

fn highlight_html_source_line(line: &str, in_comment: &mut bool) -> String {
    let mut out = String::with_capacity(line.len() + 64);
    let mut i = 0usize;
    let bytes = line.as_bytes();

    while i < bytes.len() {
        if *in_comment {
            if let Some(end_rel) = line[i..].find("-->") {
                let chunk = &line[i..i + end_rel + 3];
                out.push_str(&format!("<span class=\"hl-cmt\">{}</span>", html_escape(chunk)));
                i += end_rel + 3;
                *in_comment = false;
            } else {
                out.push_str(&format!("<span class=\"hl-cmt\">{}</span>", html_escape(&line[i..])));
                break;
            }
            continue;
        }

        if line[i..].starts_with("<!--") {
            *in_comment = true;
            if let Some(end_rel) = line[i + 4..].find("-->") {
                let chunk = &line[i..i + 4 + end_rel + 3];
                out.push_str(&format!("<span class=\"hl-cmt\">{}</span>", html_escape(chunk)));
                i += 4 + end_rel + 3;
                *in_comment = false;
            } else {
                out.push_str(&format!("<span class=\"hl-cmt\">{}</span>", html_escape(&line[i..])));
                break;
            }
            continue;
        }

        if bytes[i] == b'<' {
            let end_rel = find_tag_end(&line[i..]).unwrap_or(line.len() - i - 1);
            let tag_slice = &line[i..=i + end_rel];
            out.push_str(&highlight_tag_tokens(tag_slice));
            i += end_rel + 1;
        } else {
            let next_lt = line[i..].find('<').unwrap_or(line.len() - i);
            out.push_str(&html_escape(&line[i..i + next_lt]));
            i += next_lt;
        }
    }
    out
}

fn highlight_tag_tokens(tag: &str) -> String {
    let mut out = String::new();
    let chars: Vec<char> = tag.chars().collect();
    let n = chars.len();
    let mut i = 0;

    // Emit '<' + optional '/'/'!' + tag name
    let mut head = String::new();
    while i < n && !chars[i].is_whitespace() && chars[i] != '>' {
        head.push(chars[i]);
        i += 1;
    }
    out.push_str(&format!("<span class=\"hl-tag\">{}</span>", html_escape(&head)));

    let mut last_attr_name = String::new();
    while i < n {
        if chars[i] == '>' || (chars[i] == '/' && i + 1 < n && chars[i + 1] == '>') {
            let rest: String = chars[i..].iter().collect();
            out.push_str(&format!("<span class=\"hl-tag\">{}</span>", html_escape(&rest)));
            break;
        }
        if chars[i].is_whitespace() {
            out.push(chars[i]);
            i += 1;
            continue;
        }
        if chars[i] == '"' || chars[i] == '\'' {
            let q = chars[i];
            let start = i + 1;
            i += 1;
            while i < n && chars[i] != q {
                i += 1;
            }
            let val: String = chars[start..i.min(n)].iter().collect();
            if i < n {
                i += 1;
            }
            let is_url_attr = matches!(last_attr_name.as_str(), "href" | "src");
            if is_url_attr && is_safe_http_url(&val) {
                out.push_str(&format!(
                    "<span class=\"hl-str\">{q}<a class=\"hl-link\" href=\"{u}\" rel=\"noopener noreferrer\">{u}</a>{q}</span>",
                    q = html_escape(&q.to_string()),
                    u = html_escape(&val)
                ));
            } else {
                out.push_str(&format!(
                    "<span class=\"hl-str\">{q}{v}{q}</span>",
                    q = html_escape(&q.to_string()),
                    v = html_escape(&val)
                ));
            }
            continue;
        }
        if chars[i] == '=' {
            out.push('=');
            i += 1;
            continue;
        }
        let start = i;
        while i < n && !chars[i].is_whitespace() && !matches!(chars[i], '=' | '>' | '/') {
            i += 1;
        }
        let attr: String = chars[start..i].iter().collect();
        last_attr_name = attr.to_ascii_lowercase();
        out.push_str(&format!("<span class=\"hl-attr\">{}</span>", html_escape(&attr)));
    }
    out
}

// --- JSONPath Evaluator & Collapsible JSON Viewer ---

#[derive(Debug, Clone)]
enum JsonPathStep {
    Key(String),
    Index(isize),
    Slice(Option<isize>, Option<isize>),
    Wildcard,
    RecursiveKey(String),
    RecursiveWildcard,
}

/// Evaluates JSONPath expressions (`$.a.b[0]`, `$..key`, `[*]`, `['key']`, `[-1]`, `[0:2]`)
/// over a `serde_json::Value` in pure Rust.
pub fn evaluate_jsonpath(value: &serde_json::Value, expr: &str) -> Vec<serde_json::Value> {
    let steps = match parse_jsonpath(expr) {
        Some(s) => s,
        None => return Vec::new(),
    };
    let mut current: Vec<&serde_json::Value> = vec![value];

    for step in steps {
        let mut next: Vec<&serde_json::Value> = Vec::new();
        for node in current {
            match &step {
                JsonPathStep::Key(k) => {
                    if let Some(v) = node.as_object().and_then(|o| o.get(k)) {
                        next.push(v);
                    }
                }
                JsonPathStep::Index(idx) => {
                    if let Some(arr) = node.as_array() {
                        let resolved = if *idx < 0 {
                            (arr.len() as isize) + *idx
                        } else {
                            *idx
                        };
                        if resolved >= 0 && (resolved as usize) < arr.len() {
                            next.push(&arr[resolved as usize]);
                        }
                    }
                }
                JsonPathStep::Slice(start_opt, end_opt) => {
                    if let Some(arr) = node.as_array() {
                        let len = arr.len() as isize;
                        let s = start_opt
                            .map(|v| if v < 0 { (len + v).max(0) } else { v.min(len) })
                            .unwrap_or(0) as usize;
                        let e = end_opt
                            .map(|v| if v < 0 { (len + v).max(0) } else { v.min(len) })
                            .unwrap_or(len) as usize;
                        if s < e {
                            for item in &arr[s..e] {
                                next.push(item);
                            }
                        }
                    }
                }
                JsonPathStep::Wildcard => match node {
                    serde_json::Value::Array(arr) => next.extend(arr.iter()),
                    serde_json::Value::Object(obj) => next.extend(obj.values()),
                    _ => {}
                },
                JsonPathStep::RecursiveKey(k) => {
                    collect_recursive_key(node, k, &mut next, 0);
                }
                JsonPathStep::RecursiveWildcard => {
                    collect_recursive_all(node, &mut next, 0);
                }
            }
        }
        current = next;
    }

    current.into_iter().cloned().collect()
}

fn collect_recursive_key<'a>(
    node: &'a serde_json::Value,
    key: &str,
    out: &mut Vec<&'a serde_json::Value>,
    depth: usize,
) {
    if depth > 64 {
        return;
    }
    match node {
        serde_json::Value::Object(map) => {
            if let Some(v) = map.get(key) {
                out.push(v);
            }
            for v in map.values() {
                collect_recursive_key(v, key, out, depth + 1);
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                collect_recursive_key(item, key, out, depth + 1);
            }
        }
        _ => {}
    }
}

fn collect_recursive_all<'a>(
    node: &'a serde_json::Value,
    out: &mut Vec<&'a serde_json::Value>,
    depth: usize,
) {
    if depth > 64 {
        return;
    }
    match node {
        serde_json::Value::Object(map) => {
            for v in map.values() {
                out.push(v);
                collect_recursive_all(v, out, depth + 1);
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                out.push(item);
                collect_recursive_all(item, out, depth + 1);
            }
        }
        _ => {}
    }
}

fn parse_jsonpath(expr: &str) -> Option<Vec<JsonPathStep>> {
    let trimmed = expr.trim();
    if trimmed.is_empty() {
        return None;
    }
    let bytes = trimmed.as_bytes();
    let mut i = if bytes[0] == b'$' { 1 } else { 0 };
    let mut steps = Vec::new();

    while i < bytes.len() {
        if trimmed[i..].starts_with("..") {
            i += 2;
            if i < bytes.len() && bytes[i] == b'*' {
                steps.push(JsonPathStep::RecursiveWildcard);
                i += 1;
            } else if i < bytes.len() && bytes[i] == b'[' {
                // `$..[0]` or `$..['k']`
                let end = i + trimmed[i..].find(']')?;
                let inner = trimmed[i + 1..end].trim();
                if inner == "*" {
                    steps.push(JsonPathStep::RecursiveWildcard);
                } else if (inner.starts_with('\'') && inner.ends_with('\''))
                    || (inner.starts_with('"') && inner.ends_with('"'))
                {
                    steps.push(JsonPathStep::RecursiveKey(
                        inner[1..inner.len() - 1].to_string(),
                    ));
                } else {
                    return None;
                }
                i = end + 1;
            } else {
                let start = i;
                while i < bytes.len() && !matches!(bytes[i], b'.' | b'[') {
                    i += 1;
                }
                if i == start {
                    return None;
                }
                steps.push(JsonPathStep::RecursiveKey(trimmed[start..i].to_string()));
            }
        } else if bytes[i] == b'.' {
            i += 1;
            if i >= bytes.len() {
                return None;
            }
            if bytes[i] == b'*' {
                steps.push(JsonPathStep::Wildcard);
                i += 1;
            } else {
                let start = i;
                while i < bytes.len() && !matches!(bytes[i], b'.' | b'[') {
                    i += 1;
                }
                if i == start {
                    return None;
                }
                steps.push(JsonPathStep::Key(trimmed[start..i].to_string()));
            }
        } else if bytes[i] == b'[' {
            let end = i + trimmed[i..].find(']')?;
            let inner = trimmed[i + 1..end].trim();
            if inner == "*" {
                steps.push(JsonPathStep::Wildcard);
            } else if (inner.starts_with('\'') && inner.ends_with('\'') && inner.len() >= 2)
                || (inner.starts_with('"') && inner.ends_with('"') && inner.len() >= 2)
            {
                steps.push(JsonPathStep::Key(inner[1..inner.len() - 1].to_string()));
            } else if let Some((s_str, e_str)) = inner.split_once(':') {
                let s = if s_str.trim().is_empty() {
                    None
                } else {
                    Some(s_str.trim().parse::<isize>().ok()?)
                };
                let e = if e_str.trim().is_empty() {
                    None
                } else {
                    Some(e_str.trim().parse::<isize>().ok()?)
                };
                steps.push(JsonPathStep::Slice(s, e));
            } else {
                let idx = inner.parse::<isize>().ok()?;
                steps.push(JsonPathStep::Index(idx));
            }
            i = end + 1;
        } else {
            // Bare leading key without `$` or `.`
            let start = i;
            while i < bytes.len() && !matches!(bytes[i], b'.' | b'[') {
                i += 1;
            }
            steps.push(JsonPathStep::Key(trimmed[start..i].to_string()));
        }
    }
    Some(steps)
}

/// Renders a `serde_json::Value` into an interactive collapsible OLED HTML JSON Viewer.
pub fn render_json_viewer_html(title: &str, value: &serde_json::Value) -> String {
    let mut tree = String::new();
    render_json_node(value, "$", 0, &mut tree);
    format!(
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"UTF-8\"><title>{title}</title>\
         <style>body{{background:#000;color:#F5F3EE;font:13px/1.6 ui-monospace,monospace;padding:16px;}}\
         details{{margin-left:16px;}}summary{{cursor:pointer;color:#8A8D96;}}\
         .jk{{color:#B975FF;}}.js{{color:#F0B254;}}.jn{{color:#38D9F5;}}.jb{{color:#7EE787;}}.jnull{{color:#FF7B72;}}\
         </style></head><body><h1>{title}</h1><div class=\"json-root\">{tree}</div></body></html>",
        title = html_escape(title),
        tree = tree
    )
}

fn render_json_node(val: &serde_json::Value, path: &str, depth: usize, out: &mut String) {
    if depth > 48 {
        out.push_str("<span class=\"jnull\">[max depth]</span>");
        return;
    }
    match val {
        serde_json::Value::Null => out.push_str("<span class=\"jnull\">null</span>"),
        serde_json::Value::Bool(b) => out.push_str(&format!("<span class=\"jb\">{}</span>", b)),
        serde_json::Value::Number(n) => out.push_str(&format!("<span class=\"jn\">{}</span>", n)),
        serde_json::Value::String(s) => {
            out.push_str(&format!("<span class=\"js\">\"{}\"</span>", html_escape(s)))
        }
        serde_json::Value::Array(arr) => {
            out.push_str(&format!(
                "<details open data-path=\"{}\"><summary>[ {} items ]</summary>",
                html_escape(path),
                arr.len()
            ));
            for (idx, item) in arr.iter().enumerate() {
                let child_path = format!("{}[{}]", path, idx);
                out.push_str(&format!("<div><span class=\"jk\">[{}]</span>: ", idx));
                render_json_node(item, &child_path, depth + 1, out);
                out.push_str("</div>");
            }
            out.push_str("</details>");
        }
        serde_json::Value::Object(map) => {
            out.push_str(&format!(
                "<details open data-path=\"{}\"><summary>{{ {} keys }}</summary>",
                html_escape(path),
                map.len()
            ));
            for (k, v) in map {
                let child_path = format!("{}.{}", path, k);
                out.push_str(&format!(
                    "<div><span class=\"jk\">\"{}\"</span>: ",
                    html_escape(k)
                ));
                render_json_node(v, &child_path, depth + 1, out);
                out.push_str("</div>");
            }
            out.push_str("</details>");
        }
    }
}

// --- Pure-Rust XML Tree Parser, Simple XPath & XML Viewer ---

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct XmlElement {
    pub name: String,
    pub attributes: Vec<(String, String)>,
    pub children: Vec<XmlNode>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum XmlNode {
    Element(XmlElement),
    Text(String),
    Comment(String),
    CData(String),
}

impl XmlElement {
    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    pub fn text_content(&self) -> String {
        let mut out = String::new();
        for ch in &self.children {
            match ch {
                XmlNode::Text(t) | XmlNode::CData(t) => out.push_str(t),
                XmlNode::Element(el) => out.push_str(&el.text_content()),
                XmlNode::Comment(_) => {}
            }
        }
        out
    }
}

/// Parses an XML document into an `XmlElement` tree safely (rejects `<!ENTITY`, caps depth).
pub fn parse_xml_tree(xml: &str) -> Result<XmlElement, PageToolsError> {
    if xml.len() > 16 * 1024 * 1024 {
        return Err(PageToolsError::InvalidXml("XML exceeds 16 MiB".into()));
    }
    if xml.to_ascii_uppercase().contains("<!ENTITY") {
        return Err(PageToolsError::InvalidXml(
            "ENTITY declarations rejected".into(),
        ));
    }
    let mut parser = XmlTreeParser {
        src: xml,
        pos: 0,
        depth: 0,
    };
    parser.skip_prolog()?;
    parser.parse_element()
}

struct XmlTreeParser<'a> {
    src: &'a str,
    pos: usize,
    depth: usize,
}

impl<'a> XmlTreeParser<'a> {
    fn skip_ws(&mut self) {
        while self.pos < self.src.len() && self.src.as_bytes()[self.pos].is_ascii_whitespace() {
            self.pos += 1;
        }
    }

    fn skip_prolog(&mut self) -> Result<(), PageToolsError> {
        loop {
            self.skip_ws();
            let rest = &self.src[self.pos..];
            if rest.starts_with("<?") {
                let end = rest
                    .find("?>")
                    .ok_or_else(|| PageToolsError::InvalidXml("unterminated PI".into()))?;
                self.pos += end + 2;
            } else if rest.starts_with("<!--") {
                let end = rest[4..]
                    .find("-->")
                    .ok_or_else(|| PageToolsError::InvalidXml("unterminated comment".into()))?;
                self.pos += 4 + end + 3;
            } else if rest.starts_with("<!DOCTYPE") {
                let end = rest
                    .find('>')
                    .ok_or_else(|| PageToolsError::InvalidXml("unterminated DOCTYPE".into()))?;
                self.pos += end + 1;
            } else {
                break;
            }
        }
        Ok(())
    }

    fn parse_element(&mut self) -> Result<XmlElement, PageToolsError> {
        self.depth += 1;
        if self.depth > 96 {
            return Err(PageToolsError::InvalidXml("max nesting depth exceeded".into()));
        }
        self.skip_ws();
        if !self.src[self.pos..].starts_with('<') {
            return Err(PageToolsError::InvalidXml(format!(
                "expected '<' at byte {}",
                self.pos
            )));
        }
        let end_rel = find_tag_end(&self.src[self.pos..])
            .ok_or_else(|| PageToolsError::InvalidXml("unterminated opening tag".into()))?;
        let raw_tag = &self.src[self.pos + 1..self.pos + end_rel];
        self.pos += end_rel + 1;

        let self_closing = raw_tag.trim_end().ends_with('/');
        let core = raw_tag.trim().trim_end_matches('/').trim();
        let mut parts = core.splitn(2, char::is_whitespace);
        let name = parts.next().unwrap_or("").to_string();
        if name.is_empty() || name.starts_with('/') {
            return Err(PageToolsError::InvalidXml(format!("invalid tag name '{}'", name)));
        }
        let attributes = parse_tag_attributes(parts.next().unwrap_or(""));
        let mut children = Vec::new();

        if !self_closing {
            loop {
                if self.pos >= self.src.len() {
                    return Err(PageToolsError::InvalidXml(format!(
                        "unclosed element <{}>",
                        name
                    )));
                }
                let rest = &self.src[self.pos..];
                if rest.starts_with("</") {
                    let close_end = rest
                        .find('>')
                        .ok_or_else(|| PageToolsError::InvalidXml("unterminated close tag".into()))?;
                    let close_name = rest[2..close_end].trim();
                    self.pos += close_end + 1;
                    if close_name != name {
                        return Err(PageToolsError::InvalidXml(format!(
                            "mismatched closing tag </{}> for <{}>",
                            close_name, name
                        )));
                    }
                    break;
                } else if rest.starts_with("<!--") {
                    let end = rest[4..]
                        .find("-->")
                        .ok_or_else(|| PageToolsError::InvalidXml("unterminated comment".into()))?;
                    children.push(XmlNode::Comment(rest[4..4 + end].to_string()));
                    self.pos += 4 + end + 3;
                } else if rest.starts_with("<![CDATA[") {
                    let end = rest[9..]
                        .find("]]>")
                        .ok_or_else(|| PageToolsError::InvalidXml("unterminated CDATA".into()))?;
                    children.push(XmlNode::CData(rest[9..9 + end].to_string()));
                    self.pos += 9 + end + 3;
                } else if rest.starts_with('<') {
                    children.push(XmlNode::Element(self.parse_element()?));
                } else {
                    let next_lt = rest.find('<').unwrap_or(rest.len());
                    let text = html_unescape(&rest[..next_lt]);
                    if !text.trim().is_empty() {
                        children.push(XmlNode::Text(text));
                    }
                    self.pos += next_lt;
                }
            }
        }

        self.depth -= 1;
        Ok(XmlElement {
            name,
            attributes,
            children,
        })
    }
}

/// Evaluates simple XPath expressions (`/root/item`, `//item`, `//item[1]`, `//item[@id='2']`,
/// `//item/@href`, `//title/text()`) against a parsed `XmlElement`.
pub fn evaluate_xpath_simple(root: &XmlElement, expr: &str) -> Vec<String> {
    let trimmed = expr.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }

    // Tokenize into `(recursive: bool, segment: &str)`
    let mut steps: Vec<(bool, &str)> = Vec::new();
    let mut rest = trimmed;
    while !rest.is_empty() {
        let recursive = if let Some(r) = rest.strip_prefix("//") {
            rest = r;
            true
        } else if let Some(r) = rest.strip_prefix('/') {
            rest = r;
            false
        } else {
            false
        };
        if rest.is_empty() {
            break;
        }
        let next_slash = rest.find('/').unwrap_or(rest.len());
        steps.push((recursive, &rest[..next_slash]));
        rest = &rest[next_slash..];
    }

    if steps.is_empty() {
        return Vec::new();
    }

    let mut current: Vec<&XmlElement> = Vec::new();
    let mut start_step = 0usize;

    // Handle root step
    let (first_rec, first_seg) = steps[0];
    if first_rec {
        let mut all = Vec::new();
        collect_xml_descendants(root, &mut all);
        current = filter_xml_step(&all, first_seg);
        start_step = 1;
    } else if xml_matches_segment(root, first_seg) {
        current.push(root);
        start_step = 1;
    } else {
        // Relative to root children
        current.push(root);
    }

    for &(recursive, seg) in &steps[start_step..] {
        if let Some(attr_name) = seg.strip_prefix('@') {
            return current
                .into_iter()
                .filter_map(|el| el.attr(attr_name).map(|s| s.to_string()))
                .collect();
        }
        if seg == "text()" {
            return current
                .into_iter()
                .map(|el| el.text_content().trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }

        let mut next: Vec<&XmlElement> = Vec::new();
        for el in current {
            let candidates: Vec<&XmlElement> = if recursive {
                let mut desc = Vec::new();
                for ch in &el.children {
                    if let XmlNode::Element(cel) = ch {
                        collect_xml_descendants(cel, &mut desc);
                    }
                }
                desc
            } else {
                el.children
                    .iter()
                    .filter_map(|ch| match ch {
                        XmlNode::Element(cel) => Some(cel),
                        _ => None,
                    })
                    .collect()
            };
            next.extend(filter_xml_step(&candidates, seg));
        }
        current = next;
    }

    current
        .into_iter()
        .map(|el| el.text_content().trim().to_string())
        .collect()
}

fn collect_xml_descendants<'a>(el: &'a XmlElement, out: &mut Vec<&'a XmlElement>) {
    out.push(el);
    for ch in &el.children {
        if let XmlNode::Element(cel) = ch {
            collect_xml_descendants(cel, out);
        }
    }
}

fn parse_xpath_segment(seg: &str) -> (&str, Option<&str>) {
    if let Some(bracket) = seg.find('[') {
        if seg.ends_with(']') {
            return (&seg[..bracket], Some(&seg[bracket + 1..seg.len() - 1]));
        }
    }
    (seg, None)
}

fn xml_matches_segment(el: &XmlElement, seg: &str) -> bool {
    let (tag, pred) = parse_xpath_segment(seg);
    if tag != "*" && el.name != tag {
        return false;
    }
    if let Some(p) = pred {
        if let Some(attr_expr) = p.strip_prefix('@') {
            if let Some((ak, av)) = attr_expr.split_once('=') {
                let clean_v = av.trim().trim_matches('\'').trim_matches('"');
                return el.attr(ak.trim()) == Some(clean_v);
            }
            return el.attr(attr_expr.trim()).is_some();
        }
    }
    true
}

fn filter_xml_step<'a>(candidates: &[&'a XmlElement], seg: &str) -> Vec<&'a XmlElement> {
    let (tag, pred) = parse_xpath_segment(seg);
    let mut matched: Vec<&'a XmlElement> = candidates
        .iter()
        .copied()
        .filter(|el| tag == "*" || el.name == tag)
        .collect();

    if let Some(p) = pred {
        let pt = p.trim();
        if let Ok(one_based) = pt.parse::<usize>() {
            return if one_based >= 1 && one_based <= matched.len() {
                vec![matched[one_based - 1]]
            } else {
                Vec::new()
            };
        }
        if let Some(attr_expr) = pt.strip_prefix('@') {
            matched.retain(|el| {
                if let Some((ak, av)) = attr_expr.split_once('=') {
                    let clean_v = av.trim().trim_matches('\'').trim_matches('"');
                    el.attr(ak.trim()) == Some(clean_v)
                } else {
                    el.attr(attr_expr.trim()).is_some()
                }
            });
        }
    }
    matched
}

/// Renders a parsed `XmlElement` tree into a collapsible OLED HTML XML Viewer.
pub fn render_xml_viewer_html(title: &str, root: &XmlElement) -> String {
    let mut body = String::new();
    render_xml_el_html(root, 0, &mut body);
    format!(
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"UTF-8\"><title>{title}</title>\
         <style>body{{background:#000;color:#F5F3EE;font:13px/1.6 ui-monospace,monospace;padding:16px;}}\
         details{{margin-left:16px;}}summary{{cursor:pointer;}}\
         .xt{{color:#38D9F5;}}.xa{{color:#B975FF;}}.xv{{color:#F0B254;}}.xc{{color:#6A737D;}}\
         </style></head><body><h1>{title}</h1>{body}</body></html>",
        title = html_escape(title),
        body = body
    )
}

fn render_xml_el_html(el: &XmlElement, depth: usize, out: &mut String) {
    if depth > 48 {
        return;
    }
    let mut attrs = String::new();
    for (k, v) in &el.attributes {
        attrs.push_str(&format!(
            " <span class=\"xa\">{}</span>=<span class=\"xv\">\"{}\"</span>",
            html_escape(k),
            html_escape(v)
        ));
    }
    if el.children.is_empty() {
        out.push_str(&format!(
            "<div>&lt;<span class=\"xt\">{}</span>{}/&gt;</div>",
            html_escape(&el.name),
            attrs
        ));
    } else {
        out.push_str(&format!(
            "<details open><summary>&lt;<span class=\"xt\">{}</span>{}&gt;</summary>",
            html_escape(&el.name),
            attrs
        ));
        for ch in &el.children {
            match ch {
                XmlNode::Element(cel) => render_xml_el_html(cel, depth + 1, out),
                XmlNode::Text(t) | XmlNode::CData(t) => {
                    out.push_str(&format!("<div style=\"margin-left:16px\">{}</div>", html_escape(t)));
                }
                XmlNode::Comment(c) => {
                    out.push_str(&format!(
                        "<div class=\"xc\" style=\"margin-left:16px\">&lt;!--{}--&gt;</div>",
                        html_escape(c)
                    ));
                }
            }
        }
        out.push_str(&format!(
            "<div>&lt;/<span class=\"xt\">{}</span>&gt;</div></details>",
            html_escape(&el.name)
        ));
    }
}

// --- Line Diff Engine (LCS / Myers) & Diff Viewer ---

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiffLineKind {
    Equal,
    Added,
    Removed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffLine {
    pub kind: DiffLineKind,
    pub left_line: Option<usize>,
    pub right_line: Option<usize>,
    pub text: String,
}

/// Computes a minimal line-by-line diff between `left` and `right` using Myers' O(ND) algorithm
/// (with common prefix/suffix trimming and graceful fallback for huge files).
pub fn compute_line_diff(left: &str, right: &str) -> Vec<DiffLine> {
    let a: Vec<&str> = left.lines().collect();
    let b: Vec<&str> = right.lines().collect();

    // Trim common prefix and suffix for speed
    let mut prefix = 0usize;
    while prefix < a.len() && prefix < b.len() && a[prefix] == b[prefix] {
        prefix += 1;
    }
    let mut suffix = 0usize;
    while suffix + prefix < a.len()
        && suffix + prefix < b.len()
        && a[a.len() - 1 - suffix] == b[b.len() - 1 - suffix]
    {
        suffix += 1;
    }

    let mut out = Vec::with_capacity(a.len().max(b.len()));
    for i in 0..prefix {
        out.push(DiffLine {
            kind: DiffLineKind::Equal,
            left_line: Some(i + 1),
            right_line: Some(i + 1),
            text: a[i].to_string(),
        });
    }

    let a_mid = &a[prefix..a.len() - suffix];
    let b_mid = &b[prefix..b.len() - suffix];
    let n = a_mid.len();
    let m = b_mid.len();

    if n == 0 {
        for (j, &line) in b_mid.iter().enumerate() {
            out.push(DiffLine {
                kind: DiffLineKind::Added,
                left_line: None,
                right_line: Some(prefix + j + 1),
                text: line.to_string(),
            });
        }
    } else if m == 0 {
        for (i, &line) in a_mid.iter().enumerate() {
            out.push(DiffLine {
                kind: DiffLineKind::Removed,
                left_line: Some(prefix + i + 1),
                right_line: None,
                text: line.to_string(),
            });
        }
    } else if n * m <= 4_000_000 {
        // Exact Myers O(ND) shortest edit script
        let max_d = n + m;
        let offset = max_d as isize;
        let mut v = vec![0isize; 2 * max_d + 1];
        let mut trace: Vec<Vec<isize>> = Vec::new();

        'outer: for d in 0..=max_d {
            trace.push(v.clone());
            let d_i = d as isize;
            let mut k = -d_i;
            while k <= d_i {
                let mut x = if k == -d_i
                    || (k != d_i && v[(k - 1 + offset) as usize] < v[(k + 1 + offset) as usize])
                {
                    v[(k + 1 + offset) as usize]
                } else {
                    v[(k - 1 + offset) as usize] + 1
                };
                let mut y = x - k;
                while (x as usize) < n && (y as usize) < m && a_mid[x as usize] == b_mid[y as usize]
                {
                    x += 1;
                    y += 1;
                }
                v[(k + offset) as usize] = x;
                if (x as usize) >= n && (y as usize) >= m {
                    break 'outer;
                }
                k += 2;
            }
        }

        // Backtrack trace
        let mut mid_ops: Vec<DiffLine> = Vec::new();
        let mut x = n as isize;
        let mut y = m as isize;
        for (d, prev_v) in trace.iter().enumerate().rev() {
            let d_i = d as isize;
            let k = x - y;
            let prev_k = if k == -d_i
                || (k != d_i
                    && prev_v[(k - 1 + offset) as usize] < prev_v[(k + 1 + offset) as usize])
            {
                k + 1
            } else {
                k - 1
            };
            let prev_x = prev_v[(prev_k + offset) as usize];
            let prev_y = prev_x - prev_k;

            while x > prev_x && y > prev_y {
                x -= 1;
                y -= 1;
                mid_ops.push(DiffLine {
                    kind: DiffLineKind::Equal,
                    left_line: Some(prefix + x as usize + 1),
                    right_line: Some(prefix + y as usize + 1),
                    text: a_mid[x as usize].to_string(),
                });
            }
            if d > 0 {
                if x == prev_x {
                    y -= 1;
                    mid_ops.push(DiffLine {
                        kind: DiffLineKind::Added,
                        left_line: None,
                        right_line: Some(prefix + y as usize + 1),
                        text: b_mid[y as usize].to_string(),
                    });
                } else {
                    x -= 1;
                    mid_ops.push(DiffLine {
                        kind: DiffLineKind::Removed,
                        left_line: Some(prefix + x as usize + 1),
                        right_line: None,
                        text: a_mid[x as usize].to_string(),
                    });
                }
            }
        }
        mid_ops.reverse();
        out.extend(mid_ops);
    } else {
        // Bounded fallback for gigantic inputs
        for (i, &line) in a_mid.iter().enumerate() {
            out.push(DiffLine {
                kind: DiffLineKind::Removed,
                left_line: Some(prefix + i + 1),
                right_line: None,
                text: line.to_string(),
            });
        }
        for (j, &line) in b_mid.iter().enumerate() {
            out.push(DiffLine {
                kind: DiffLineKind::Added,
                left_line: None,
                right_line: Some(prefix + j + 1),
                text: line.to_string(),
            });
        }
    }

    for k in 0..suffix {
        let li = a.len() - suffix + k;
        let ri = b.len() - suffix + k;
        out.push(DiffLine {
            kind: DiffLineKind::Equal,
            left_line: Some(li + 1),
            right_line: Some(ri + 1),
            text: a[li].to_string(),
        });
    }

    out
}

/// Renders a `compute_line_diff` result as a styled OLED HTML Diff Viewer.
pub fn render_diff_viewer_html(left_title: &str, right_title: &str, diff: &[DiffLine]) -> String {
    let added = diff.iter().filter(|d| d.kind == DiffLineKind::Added).count();
    let removed = diff
        .iter()
        .filter(|d| d.kind == DiffLineKind::Removed)
        .count();

    let mut rows = String::with_capacity(diff.len() * 80);
    for d in diff {
        let (cls, sigil) = match d.kind {
            DiffLineKind::Equal => ("eq", " "),
            DiffLineKind::Added => ("add", "+"),
            DiffLineKind::Removed => ("rem", "-"),
        };
        let l_num = d
            .left_line
            .map(|n| n.to_string())
            .unwrap_or_default();
        let r_num = d
            .right_line
            .map(|n| n.to_string())
            .unwrap_or_default();
        rows.push_str(&format!(
            "<tr class=\"{cls}\"><td class=\"ln\">{l}</td><td class=\"ln\">{r}</td><td class=\"sg\">{sg}</td><td class=\"tx\">{tx}</td></tr>\n",
            cls = cls,
            l = l_num,
            r = r_num,
            sg = sigil,
            tx = html_escape(&d.text)
        ));
    }

    format!(
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"UTF-8\">\
         <title>Diff: {lt} vs {rt}</title>\
         <style>body{{margin:0;background:#000;color:#F5F3EE;font:13px/1.5 ui-monospace,monospace;}}\
         .hdr{{background:#0C0D12;border-bottom:1px solid #1A1B20;padding:10px 16px;display:flex;gap:16px;}}\
         .stat-a{{color:#7EE787;}}.stat-r{{color:#FF7B72;}}\
         table{{width:100%;border-collapse:collapse;}}\
         td{{padding:1px 8px;vertical-align:top;}}\
         .ln{{color:#5C5E65;text-align:right;width:4ch;user-select:none;}}\
         .sg{{width:2ch;user-select:none;}}.tx{{white-space:pre-wrap;}}\
         tr.add{{background:rgba(46,160,67,0.18);}}tr.rem{{background:rgba(248,81,73,0.18);}}\
         </style></head><body>\
         <div class=\"hdr\"><strong>{lt} → {rt}</strong><span class=\"stat-a\">+{added}</span><span class=\"stat-r\">-{removed}</span></div>\
         <table><tbody>{rows}</tbody></table></body></html>",
        lt = html_escape(left_title),
        rt = html_escape(right_title),
        added = added,
        removed = removed,
        rows = rows
    )
}

// --- RSS / Atom Feed Discovery & Smart Copy ---

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveredFeed {
    pub title: String,
    pub url: String,
    pub feed_type: String,
}

/// Discovers `<link rel="alternate" type="application/rss+xml|application/atom+xml|application/feed+json">`
/// feeds declared inside an HTML document.
pub fn extract_rss_feeds_from_html(html: &str) -> Vec<DiscoveredFeed> {
    extract_rss_feeds_from_html_with_base(html, None)
}

pub fn extract_rss_feeds_from_html_with_base(
    html: &str,
    base_url: Option<&str>,
) -> Vec<DiscoveredFeed> {
    let mut feeds = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut cursor = 0usize;

    while let Some(rel) = find_tag_ci(&html[cursor..], "link") {
        let start = cursor + rel;
        let Some(end_rel) = find_tag_end(&html[start..]) else {
            break;
        };
        let tag = &html[start..=start + end_rel];
        let inner = tag[1..tag.len() - 1].trim().trim_end_matches('/');
        let attrs_raw = inner
            .split_once(char::is_whitespace)
            .map(|(_, a)| a)
            .unwrap_or("");
        let attrs = parse_tag_attributes(attrs_raw);

        let mut rel_val = String::new();
        let mut type_val = String::new();
        let mut href_val = String::new();
        let mut title_val = String::new();

        for (k, v) in attrs {
            match k.to_ascii_lowercase().as_str() {
                "rel" => rel_val = v.to_ascii_lowercase(),
                "type" => type_val = v.to_ascii_lowercase(),
                "href" => href_val = v,
                "title" => title_val = v,
                _ => {}
            }
        }

        let is_alt = rel_val.split_whitespace().any(|w| w == "alternate");
        let is_feed = matches!(
            type_val.as_str(),
            "application/rss+xml"
                | "application/atom+xml"
                | "application/feed+json"
                | "application/json"
                | "text/xml"
        ) && (type_val.contains("rss")
            || type_val.contains("atom")
            || type_val.contains("feed"));

        if is_alt && is_feed && !href_val.trim().is_empty() {
            let resolved = resolve_relative_url(base_url, href_val.trim());
            if seen.insert(resolved.to_ascii_lowercase()) {
                feeds.push(DiscoveredFeed {
                    title: if title_val.trim().is_empty() {
                        resolved.clone()
                    } else {
                        title_val.trim().to_string()
                    },
                    url: resolved,
                    feed_type: type_val,
                });
            }
        }

        cursor = start + end_rel + 1;
    }

    feeds
}

fn resolve_relative_url(base_url: Option<&str>, href: &str) -> String {
    if href.starts_with("https://") || href.starts_with("http://") {
        return href.to_string();
    }
    if let Some(base) = base_url {
        if href.starts_with("//") {
            let scheme = base.split("://").next().unwrap_or("https");
            return format!("{}:{}", scheme, href);
        }
        if let Some((scheme, rest)) = base.split_once("://") {
            let origin = rest.split('/').next().unwrap_or(rest);
            if href.starts_with('/') {
                return format!("{}://{}{}", scheme, origin, href);
            }
            let dir = base.rsplit_once('/').map(|(d, _)| d).unwrap_or(base);
            return format!("{}/{}", dir.trim_end_matches('/'), href);
        }
    }
    href.to_string()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SmartCopyFormat {
    Plain,
    Clean,
    Markdown,
    HtmlRich,
}

/// Formats a page's title and URL for clipboard copying (`Plain`, `Clean` tracking-stripped,
/// `Markdown` `[title](url)`, or `HtmlRich` `<a href="...">title</a>`).
pub fn format_smart_copy(title: &str, url: &str, format: SmartCopyFormat) -> String {
    let raw_url = url.trim();
    let clean_url = strip_tracking_params(raw_url);
    let clean_title = if title.trim().is_empty() {
        clean_url.as_str()
    } else {
        title.trim()
    };

    match format {
        SmartCopyFormat::Plain => raw_url.to_string(),
        SmartCopyFormat::Clean => clean_url,
        SmartCopyFormat::Markdown => {
            format!("[{}]({})", escape_md_label(clean_title), clean_url)
        }
        SmartCopyFormat::HtmlRich => {
            let safe_href = if is_safe_link_url(&clean_url) {
                html_escape(&clean_url)
            } else {
                String::new()
            };
            format!(
                "<a href=\"{}\">{}</a>",
                safe_href,
                html_escape(clean_title)
            )
        }
    }
}

fn strip_tracking_params(url: &str) -> String {
    let (before_hash, hash_part) = match url.split_once('#') {
        Some((b, h)) => (b, Some(h)),
        None => (url, None),
    };
    let (base, query) = match before_hash.split_once('?') {
        Some((b, q)) => (b, q),
        None => return url.to_string(),
    };
    let kept: Vec<&str> = query
        .split('&')
        .filter(|pair| {
            let key = pair.split_once('=').map(|(k, _)| k).unwrap_or(pair);
            !is_tracking_param(key)
        })
        .collect();
    let mut out = base.to_string();
    if !kept.is_empty() {
        out.push('?');
        out.push_str(&kept.join("&"));
    }
    if let Some(h) = hash_part {
        out.push('#');
        out.push_str(h);
    }
    out
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
                | "mkt_tok"
        )
}

// ============================================================================
// Shared Internal HTML / String / Atomic Persistence Helpers
// ============================================================================

fn escape_md_label(s: &str) -> String {
    s.replace('[', "\\[").replace(']', "\\]")
}

fn slugify_heading(text: &str) -> String {
    let mut out = String::new();
    let mut prev_dash = false;
    for ch in text.chars() {
        if ch.is_alphanumeric() {
            for lc in ch.to_lowercase() {
                out.push(lc);
            }
            prev_dash = false;
        } else if !prev_dash && !out.is_empty() {
            out.push('-');
            prev_dash = true;
        }
    }
    out.trim_end_matches('-').to_string()
}

fn count_words(text: &str) -> usize {
    text.split_whitespace().count()
}

fn push_html_escaped_char(out: &mut String, c: char) {
    match c {
        '&' => out.push_str("&amp;"),
        '<' => out.push_str("&lt;"),
        '>' => out.push_str("&gt;"),
        '"' => out.push_str("&quot;"),
        '\'' => out.push_str("&#39;"),
        _ => out.push(c),
    }
}

fn html_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        push_html_escaped_char(&mut out, c);
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

fn find_tag_end(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut in_quote: Option<u8> = None;
    for (i, &b) in bytes.iter().enumerate() {
        if let Some(q) = in_quote {
            if b == q {
                in_quote = None;
            }
        } else if b == b'"' || b == b'\'' {
            in_quote = Some(b);
        } else if b == b'>' {
            return Some(i);
        }
    }
    None
}

fn find_substr_ci(haystack: &str, needle: &str) -> Option<usize> {
    let h = haystack.as_bytes();
    let n = needle.as_bytes();
    if n.is_empty() || n.len() > h.len() {
        return None;
    }
    for i in 0..=h.len() - n.len() {
        if h[i..i + n.len()].eq_ignore_ascii_case(n) {
            return Some(i);
        }
    }
    None
}

fn find_tag_ci(haystack: &str, tag_name: &str) -> Option<usize> {
    let h = haystack.as_bytes();
    let n = tag_name.as_bytes();
    let mut i = 0;
    while i + n.len() + 1 < h.len() {
        if h[i] == b'<'
            && h[i + 1..i + 1 + n.len()].eq_ignore_ascii_case(n)
            && matches!(
                h.get(i + 1 + n.len()).copied().unwrap_or(b' '),
                b' ' | b'\t' | b'\r' | b'\n' | b'>' | b'/'
            )
        {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn find_close_tag_ci(haystack: &str, tag_name: &str) -> Option<usize> {
    let needle = format!("</{}", tag_name);
    let h = haystack.as_bytes();
    let n = needle.as_bytes();
    let mut i = 0;
    while i + n.len() < h.len() {
        if h[i..i + n.len()].eq_ignore_ascii_case(n)
            && matches!(
                h.get(i + n.len()).copied().unwrap_or(b' '),
                b' ' | b'\t' | b'\r' | b'\n' | b'>'
            )
        {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn strip_html_comments(html: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let mut rest = html;
    while let Some(pos) = rest.find("<!--") {
        out.push_str(&rest[..pos]);
        if let Some(end) = rest[pos + 4..].find("-->") {
            rest = &rest[pos + 4 + end + 3..];
        } else {
            return out;
        }
    }
    out.push_str(rest);
    out
}

fn strip_elements_with_body(html: &str, tags: &[&str]) -> String {
    let mut current = html.to_string();
    for &tag in tags {
        let mut next = String::with_capacity(current.len());
        let mut i = 0usize;
        while i < current.len() {
            if let Some(rel) = find_tag_ci(&current[i..], tag) {
                next.push_str(&current[i..i + rel]);
                let open_start = i + rel;
                let Some(open_end_rel) = find_tag_end(&current[open_start..]) else {
                    break;
                };
                let open_tag = &current[open_start..=open_start + open_end_rel];
                let after_open = open_start + open_end_rel + 1;
                if open_tag.ends_with("/>") {
                    i = after_open;
                } else if let Some(close_rel) = find_close_tag_ci(&current[after_open..], tag) {
                    let close_start = after_open + close_rel;
                    if let Some(close_end_rel) = current[close_start..].find('>') {
                        i = close_start + close_end_rel + 1;
                    } else {
                        break;
                    }
                } else {
                    i = after_open;
                }
            } else {
                next.push_str(&current[i..]);
                break;
            }
        }
        current = next;
    }
    current
}

fn strip_all_html_tags(html: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let mut in_tag = false;
    for ch in html.chars() {
        match ch {
            '<' => {
                in_tag = true;
                if !out.ends_with(' ') && !out.is_empty() {
                    out.push(' ');
                }
            }
            '>' => in_tag = false,
            _ if !in_tag => out.push(ch),
            _ => {}
        }
    }
    let unescaped = html_unescape(&out);
    unescaped.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn parse_tag_attributes(raw: &str) -> Vec<(String, String)> {
    let mut attrs = Vec::new();
    let bytes = raw.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        while i < bytes.len() && (bytes[i].is_ascii_whitespace() || bytes[i] == b'/') {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        let name_start = i;
        while i < bytes.len()
            && !bytes[i].is_ascii_whitespace()
            && bytes[i] != b'='
            && bytes[i] != b'>'
            && bytes[i] != b'/'
        {
            i += 1;
        }
        let name = raw[name_start..i].to_string();
        if name.is_empty() {
            i += 1;
            continue;
        }
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        let value = if i < bytes.len() && bytes[i] == b'=' {
            i += 1;
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            if i < bytes.len() && (bytes[i] == b'"' || bytes[i] == b'\'') {
                let q = bytes[i];
                i += 1;
                let vs = i;
                while i < bytes.len() && bytes[i] != q {
                    i += 1;
                }
                let val = html_unescape(&raw[vs..i]);
                if i < bytes.len() {
                    i += 1;
                }
                val
            } else {
                let vs = i;
                while i < bytes.len() && !bytes[i].is_ascii_whitespace() && bytes[i] != b'>' {
                    i += 1;
                }
                html_unescape(&raw[vs..i])
            }
        } else {
            String::new()
        };
        attrs.push((name, value));
    }
    attrs
}

fn extract_tag_inner_html(html: &str, tag: &str) -> Option<String> {
    let open_start = find_tag_ci(html, tag)?;
    let open_end = open_start + find_tag_end(&html[open_start..])?;
    let body_start = open_end + 1;
    let close_rel = find_close_tag_ci(&html[body_start..], tag)?;
    Some(html[body_start..body_start + close_rel].to_string())
}

fn extract_tag_inner_text(html: &str, tag: &str) -> Option<String> {
    let inner = extract_tag_inner_html(html, tag)?;
    let txt = strip_all_html_tags(&inner);
    if txt.trim().is_empty() {
        None
    } else {
        Some(txt)
    }
}

fn extract_meta_content(html: &str, key_attr: &str, key_val: &str) -> Option<String> {
    let mut cursor = 0usize;
    while let Some(rel) = find_tag_ci(&html[cursor..], "meta") {
        let start = cursor + rel;
        let end_rel = find_tag_end(&html[start..])?;
        let tag = &html[start..=start + end_rel];
        let inner = tag[1..tag.len() - 1].trim().trim_end_matches('/');
        let attrs_raw = inner
            .split_once(char::is_whitespace)
            .map(|(_, a)| a)
            .unwrap_or("");
        let attrs = parse_tag_attributes(attrs_raw);
        let mut matched_key = false;
        let mut content = None;
        for (k, v) in attrs {
            if k.eq_ignore_ascii_case(key_attr) && v.eq_ignore_ascii_case(key_val) {
                matched_key = true;
            } else if k.eq_ignore_ascii_case("content") && !v.trim().is_empty() {
                content = Some(v.trim().to_string());
            }
        }
        if matched_key && content.is_some() {
            return content;
        }
        cursor = start + end_rel + 1;
    }
    None
}

fn atomic_write_with_backup(path: &Path, data: &[u8]) -> Result<(), std::io::Error> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut tmp_name = path
        .file_name()
        .map(|s| s.to_os_string())
        .unwrap_or_default();
    tmp_name.push(".tmp");
    let tmp_path = path.with_file_name(tmp_name);

    let mut bak_name = path
        .file_name()
        .map(|s| s.to_os_string())
        .unwrap_or_default();
    bak_name.push(".bak");
    let bak_path: PathBuf = path.with_file_name(bak_name);

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
    fn test_collections_and_markdown_notes_anti_xss() {
        let mut cols = CollectionsStore::new();
        let cid = cols.create_collection("Black Hole Research", "Papers & notes", None, 100);
        cols.add_item(
            &cid,
            CollectionItemKind::PageLink {
                url: "https://arxiv.org/abs/2601.00001".into(),
                title: "Event Horizon Optics".into(),
                favicon_url: None,
            },
            None,
            101,
        )
        .unwrap();
        cols.add_item(
            &cid,
            CollectionItemKind::TextExcerpt {
                text: "Kerr metric photon ring".into(),
                source_url: Some("https://arxiv.org/abs/2601.00001".into()),
                source_title: Some("arXiv".into()),
            },
            None,
            102,
        )
        .unwrap();
        let md = cols.export_collection_markdown(&cid).unwrap();
        assert!(md.contains("# Black Hole Research"));
        assert!(md.contains("> Kerr metric photon ring"));

        // Safe GFM Markdown renderer & XSS neutralization
        let unsafe_md = "# Hello <script>alert(1)</script>\n\n\
            - [x] Done task\n\
            - [ ] Pending **bold** and `code`\n\n\
            [Good](https://rust-lang.org) [Bad](javascript:alert(1))\n\n\
            | Name | Score |\n|---|---:|\n| Rust | 100 |\n";
        let html = render_safe_markdown_html(unsafe_md);
        assert!(!html.contains("<script>"));
        assert!(html.contains("&lt;script&gt;"));
        assert!(!html.contains("javascript:alert"));
        assert!(html.contains("href=\"https://rust-lang.org\""));
        assert!(html.contains("type=\"checkbox\" checked disabled"));
        assert!(html.contains("<table><thead>"));
        assert!(html.contains("<strong>bold</strong>"));

        // NotesStore CRUD + Trash
        let mut notes = NotesStore::new();
        let fid = notes.create_folder("Work", None, 100);
        let nid = notes.create_note(
            "Meeting",
            "Notes here",
            Some(fid),
            Some("https://example.org/spec".into()),
            vec!["spec".into()],
            100,
        );
        assert_eq!(notes.notes_for_url("https://example.org/spec").len(), 1);
        notes.trash_note(&nid, 110).unwrap();
        assert!(notes.notes_for_url("https://example.org/spec").is_empty());
        assert_eq!(notes.empty_trash(), 1);
    }

    #[test]
    fn test_reading_list_auto_read_and_reader_mode() {
        let article_html = r#"<!DOCTYPE html><html><head>
            <title>Singularity Architecture</title>
            <meta name="author" content="Ada Lovelace"/>
            <script>alert('xss')</script>
            </head><body>
            <nav>Home | About</nav>
            <article>
                <h1>Singularity Architecture</h1>
                <p onclick="evil()">This is a deep dive into building a pure-Rust zero-telemetry browser shell with OLED rendering, cryptographic vaults, and sandboxed page tools.</p>
                <h2>Performance Engine</h2>
                <p>By eliminating runtime overhead and leveraging deterministic memory management, every frame hits 200Hz cleanly across high-refresh displays without dropped frames or jitter.</p>
                <a href="javascript:alert(1)">Bad link</a>
                <iframe src="https://evil.test"></iframe>
            </article>
            <footer>Copyright</footer></body></html>"#;

        assert!(ReaderModeExtractor::is_probably_readerable(article_html));
        let extracted = ReaderModeExtractor::extract_article("https://singularity.dev/arch", article_html);
        assert_eq!(extracted.title, "Singularity Architecture");
        assert_eq!(extracted.byline.as_deref(), Some("Ada Lovelace"));
        assert!(!extracted.content_html.contains("<script"));
        assert!(!extracted.content_html.contains("<iframe"));
        assert!(!extracted.content_html.contains("onclick"));
        assert!(!extracted.content_html.contains("javascript:"));
        assert!(extracted.toc.iter().any(|h| h.text == "Performance Engine"));

        let reader_page = ReaderModeExtractor::render_reader_page_html(
            &extracted,
            &ReaderRenderOptions {
                theme: ReaderTheme::WcagAaa,
                use_open_dyslexic: true,
                line_focus_lines: Some(3),
                ..Default::default()
            },
        );
        assert!(reader_page.contains("OpenDyslexic"));
        assert!(reader_page.contains("data-line-focus=\"3\""));

        // Reading list auto-read at >= 90%
        let mut rl = ReadingListStore::new();
        let rid = rl.add_or_update("https://singularity.dev/arch", "Arch", Some(article_html), 100);
        assert!(!rl.get(&rid).unwrap().read);
        assert!(!rl.update_scroll_progress(&rid, 55.0, 105).unwrap());
        assert!(rl.update_scroll_progress(&rid, 92.5, 110).unwrap());
        assert!(rl.get(&rid).unwrap().read);
    }

    #[test]
    fn test_pdf_and_capture_annotations() {
        let mut pdf_store = PdfAnnotationStore::new();
        let aid = pdf_store.add_annotation(
            "doc-sha256-abc",
            0,
            PdfAnnotationKind::Highlight {
                rects: vec![PdfRect { x: 10.0, y: 20.0, width: 120.0, height: 14.0 }],
                color_hex: "#F0B254".into(),
                opacity: 0.45,
                quoted_text: Some("Important theorem".into()),
            },
            Some("Alice".into()),
            100,
        );
        assert_eq!(pdf_store.annotations_on_page("doc-sha256-abc", 0).len(), 1);
        pdf_store.form_state_mut("doc-sha256-abc").set_field(
            PdfFormField {
                name: "full_name".into(),
                page_index: 0,
                value: PdfFormFieldValue::Text(String::new()),
                required: true,
                read_only: false,
            },
            101,
        );
        assert_eq!(
            pdf_store.form_state_mut("doc-sha256-abc").missing_required_fields(),
            vec!["full_name"]
        );
        assert!(pdf_store.remove_annotation("doc-sha256-abc", &aid));

        let mut cap = CaptureAnnotationDocument::new("cap1", None, 1920, 1080);
        cap.add_item(CaptureToolKind::StepBadge {
            x: 100.0,
            y: 200.0,
            step_number: cap.next_step_number(),
            radius: 16.0,
            color_hex: "#38D9F5".into(),
        });
        assert_eq!(cap.next_step_number(), 2);
        cap.add_item(CaptureToolKind::Arrow {
            x1: 10.0,
            y1: 10.0,
            x2: 90.0,
            y2: 90.0,
            color_hex: "#FF5555".into(),
            stroke_width: 3.0,
        });
        let svg = cap.render_overlay_svg();
        assert!(svg.contains("<circle") && svg.contains("<line"));
        assert!(cap.undo());
        assert_eq!(cap.items.len(), 1);
        assert!(cap.redo());
        assert_eq!(cap.items.len(), 2);
    }

    #[test]
    fn test_text_fragments_view_source_jsonpath_xml_diff_rss_smart_copy() {
        // Text Fragment with disambiguation
        let page = "Alpha beta target gamma delta. Alpha epsilon target zeta eta.";
        let tf = build_text_fragment_url("https://example.org/p#old", page, "target").unwrap();
        assert!(tf.starts_with("https://example.org/p#:~:text="));
        assert!(tf.contains("-,target,-"));

        // View Source HTML
        let vs = format_view_source_html(
            "https://example.org",
            "<!-- hi -->\n<a href=\"https://rust-lang.org\">Rust</a>",
        );
        assert!(vs.contains("id=\"L1\"") && vs.contains("id=\"L2\""));
        assert!(vs.contains("hl-cmt") && vs.contains("hl-link"));

        // JSONPath
        let doc: serde_json::Value = serde_json::json!({
            "store": {
                "books": [
                    {"title": "Rust", "price": 30},
                    {"title": "WebGPU", "price": 45}
                ]
            }
        });
        assert_eq!(
            evaluate_jsonpath(&doc, "$.store.books[0].title"),
            vec![serde_json::json!("Rust")]
        );
        assert_eq!(
            evaluate_jsonpath(&doc, "$..price"),
            vec![serde_json::json!(30), serde_json::json!(45)]
        );
        assert_eq!(evaluate_jsonpath(&doc, "$.store.books[*].title").len(), 2);
        let jv = render_json_viewer_html("Books", &doc);
        assert!(jv.contains("json-root"));

        // XML tree & simple XPath
        let xml = r#"<catalog><book id="1"><title>Singularity</title></book><book id="2"><title>Event Horizon</title></book></catalog>"#;
        let tree = parse_xml_tree(xml).unwrap();
        assert_eq!(
            evaluate_xpath_simple(&tree, "//book[@id='2']/title"),
            vec!["Event Horizon"]
        );
        assert_eq!(evaluate_xpath_simple(&tree, "//book/@id"), vec!["1", "2"]);
        assert!(render_xml_viewer_html("Catalog", &tree).contains("Singularity"));

        // Line Diff (Myers)
        let diff = compute_line_diff("a\nb\nc\nd\n", "a\nx\nc\nd\ne\n");
        assert!(diff.iter().any(|d| d.kind == DiffLineKind::Removed && d.text == "b"));
        assert!(diff.iter().any(|d| d.kind == DiffLineKind::Added && d.text == "x"));
        assert!(diff.iter().any(|d| d.kind == DiffLineKind::Added && d.text == "e"));
        assert!(render_diff_viewer_html("old.rs", "new.rs", &diff).contains("+2"));

        // RSS discovery
        let rss_html = r#"<head>
            <link rel="alternate" type="application/rss+xml" title="Blog RSS" href="/feed.xml"/>
            <link rel="alternate" type="application/atom+xml" title="Releases" href="https://example.org/atom.xml"/>
        </head>"#;
        let feeds = extract_rss_feeds_from_html_with_base(rss_html, Some("https://example.org/post"));
        assert_eq!(feeds.len(), 2);
        assert_eq!(feeds[0].url, "https://example.org/feed.xml");
        assert_eq!(extract_rss_feeds_from_html(rss_html).len(), 2);

        // Smart Copy
        let tracked = "https://example.org/a?utm_source=x&id=42&fbclid=zzz#top";
        assert_eq!(
            format_smart_copy("Title", tracked, SmartCopyFormat::Clean),
            "https://example.org/a?id=42#top"
        );
        assert_eq!(
            format_smart_copy("Title", tracked, SmartCopyFormat::Markdown),
            "[Title](https://example.org/a?id=42#top)"
        );
        assert_eq!(
            format_smart_copy("A & B", tracked, SmartCopyFormat::HtmlRich),
            "<a href=\"https://example.org/a?id=42#top\">A &amp; B</a>"
        );
    }

    #[test]
    fn test_xml_xxe_jsonpath_slices_and_text_fragment_encoding() {
        // XXE must be rejected
        let xxe = r#"<!DOCTYPE a [<!ENTITY x SYSTEM "file:///etc/passwd">]><a>&x;</a>"#;
        assert!(parse_xml_tree(xxe).is_err());

        // JSONPath negative index and slice
        let v = serde_json::json!({"nums": [10, 20, 30, 40]});
        assert_eq!(evaluate_jsonpath(&v, "$.nums[-1]"), vec![serde_json::json!(40)]);
        assert_eq!(
            evaluate_jsonpath(&v, "$.nums[1:3]"),
            vec![serde_json::json!(20), serde_json::json!(30)]
        );

        // Text Fragment escapes '-' (%2D) and ',' (%2C) per WICG spec
        let tf = build_text_fragment_url(
            "https://example.org/doc",
            "Intro zero-knowledge, fast browser.",
            "zero-knowledge, fast",
        )
        .unwrap();
        assert_eq!(
            tf,
            "https://example.org/doc#:~:text=zero%2Dknowledge%2C%20fast"
        );
    }
}
