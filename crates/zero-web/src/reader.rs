//! Fetch reader: reader-mode Markdown and document formats (WEB-04, WEB-08,
//! WEB-10).
//!
//! [`read`] and [`read_file`] turn fetched bytes into a [`ReadDocument`] with
//! a small Markdown body that a later model pass can consume. The module is
//! deliberately dependency-light:
//!
//! - HTML is parsed by the same bounded tokenizer that
//!   [`crate::extract`] uses; there is no DOM, CSS selector engine, or tree
//!   repair. `<article>` (or `<main>`) wins over `<body>`, navigation and
//!   script-like elements are dropped, and the usual block elements map to
//!   Markdown.
//! - Markdown, plain text, code, CSV, and JSON are handled in-house.
//! - DOCX, XLSX, PPTX, and EPUB are ZIP containers read through the archive
//!   module's validated planner, so zip-slip names, oversized entries,
//!   compression bombs, links, and encrypted entries are refused before any
//!   document XML is opened.
//! - PDF uses [`lopdf`] for page-by-page text extraction. It is pure Rust,
//!   keeps the workspace MSRV (1.88), and is built with default features off
//!   because the reader is sequential and never needs timestamps or `rayon`.
//!
//! Nothing here touches the network. Every input and output is bounded by
//! [`ReaderLimits`]; exceeding a table, page, or output bound sets
//! [`ReadDocument::truncated`] instead of returning a partial success silently.
//! Encrypted PDFs and binary inputs are typed refusals, never empty documents.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Cursor, Read, Seek};
use std::path::Path;

use serde::{Deserialize, Serialize};
use zero_types::error::{ErrorCode, Result, ZeroError};

use crate::archive::{build_plan, ArchiveLimits};
use crate::crawl::decode_entities;
use crate::extract::{
    find_byte, find_ignore_ascii_case, is_void, normalize_text, parse_end_tag, parse_start_tag,
    skip_raw_text, StartTag,
};

/// Default input ceiling for one document (16 MiB).
pub const DEFAULT_MAX_INPUT_BYTES: usize = 16 * 1024 * 1024;
/// Default Markdown output ceiling (2 MiB).
pub const DEFAULT_MAX_OUTPUT_BYTES: usize = 2 * 1024 * 1024;
/// Default tag ceiling per HTML or XML document.
pub const DEFAULT_MAX_TAGS: usize = 100_000;
/// Default page ceiling for PDFs and chapter ceiling for EPUBs.
pub const DEFAULT_READER_MAX_PAGES: usize = 200;
/// Maximum rows emitted for one Markdown table (CSV, DOCX, XLSX).
pub const MAX_TABLE_ROWS: usize = 500;
/// Maximum columns emitted for one Markdown table.
pub const MAX_TABLE_COLS: usize = 50;
/// Maximum characters kept from one table cell.
pub const MAX_TABLE_CELL_CHARS: usize = 2_000;
/// Maximum characters kept in a document title.
pub const MAX_TITLE_CHARS: usize = 512;
/// Maximum links collected from one document.
pub const MAX_LINKS: usize = 1_024;
/// Marker appended when [`ReaderLimits::max_output_bytes`] cuts the body.
pub const READER_TRUNCATION_MARKER: &str = "\n\n[zero-web: reader output truncated]";

fn invalid(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::InvalidInput, message)
}

fn unsupported(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::Unsupported, message)
}

fn corrupt(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::Corrupt, message)
}

fn limit(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::LimitExceeded, message)
}

fn io_error(error: std::io::Error, what: &str) -> ZeroError {
    ZeroError::new(ErrorCode::Io, format!("{what}: {error}"))
}

// ---------------------------------------------------------------------------
// Formats and limits
// ---------------------------------------------------------------------------

/// One document format the reader understands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DocumentFormat {
    /// HTML or XHTML.
    Html,
    /// Markdown source.
    Markdown,
    /// Plain text.
    Text,
    /// Source code.
    Code,
    /// Comma- or tab-separated values.
    Csv,
    /// JSON.
    Json,
    /// PDF.
    Pdf,
    /// WordprocessingML (`.docx`).
    Docx,
    /// SpreadsheetML (`.xlsx`).
    Xlsx,
    /// PresentationML (`.pptx`).
    Pptx,
    /// EPUB.
    Epub,
    /// Not recognised, or binary.
    Unknown,
}

impl DocumentFormat {
    /// Stable lower-case name used in messages.
    pub const fn as_str(self) -> &'static str {
        match self {
            DocumentFormat::Html => "html",
            DocumentFormat::Markdown => "markdown",
            DocumentFormat::Text => "text",
            DocumentFormat::Code => "code",
            DocumentFormat::Csv => "csv",
            DocumentFormat::Json => "json",
            DocumentFormat::Pdf => "pdf",
            DocumentFormat::Docx => "docx",
            DocumentFormat::Xlsx => "xlsx",
            DocumentFormat::Pptx => "pptx",
            DocumentFormat::Epub => "epub",
            DocumentFormat::Unknown => "unknown",
        }
    }

    /// Map a file extension (with or without the leading dot) to a format.
    pub fn from_extension(extension: &str) -> Option<Self> {
        let extension = extension
            .trim()
            .trim_start_matches('.')
            .to_ascii_lowercase();
        Some(match extension.as_str() {
            "html" | "htm" | "xhtml" => DocumentFormat::Html,
            "md" | "markdown" | "mdown" | "mkd" | "mdx" => DocumentFormat::Markdown,
            "txt" | "text" | "log" => DocumentFormat::Text,
            "csv" | "tsv" => DocumentFormat::Csv,
            "json" => DocumentFormat::Json,
            // JSON Lines is not one JSON document; keep it as plain text.
            "jsonl" | "ndjson" => DocumentFormat::Text,
            "pdf" => DocumentFormat::Pdf,
            "docx" | "docm" => DocumentFormat::Docx,
            "xlsx" | "xlsm" => DocumentFormat::Xlsx,
            "pptx" | "pptm" => DocumentFormat::Pptx,
            "epub" => DocumentFormat::Epub,
            "rs" | "py" | "js" | "mjs" | "cjs" | "ts" | "tsx" | "jsx" | "go" | "java" | "kt"
            | "kts" | "c" | "h" | "cc" | "cpp" | "cxx" | "hpp" | "cs" | "rb" | "php" | "swift"
            | "m" | "mm" | "scala" | "lua" | "pl" | "r" | "jl" | "sh" | "bash" | "zsh" | "fish"
            | "ps1" | "bat" | "cmd" | "sql" | "toml" | "yaml" | "yml" | "ini" | "cfg" | "conf"
            | "xml" | "css" | "scss" | "less" | "vue" | "svelte" | "dockerfile" | "makefile" => {
                DocumentFormat::Code
            }
            _ => return None,
        })
    }

    /// Map a MIME type (parameters after `;` ignored) to a format.
    pub fn from_content_type(content_type: &str) -> Option<Self> {
        let essence = content_type
            .trim()
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        Some(match essence.as_str() {
            "text/html" | "application/xhtml+xml" => DocumentFormat::Html,
            "text/markdown" | "text/x-markdown" => DocumentFormat::Markdown,
            "text/csv" | "text/tab-separated-values" => DocumentFormat::Csv,
            "application/json" | "text/json" => DocumentFormat::Json,
            "application/pdf" => DocumentFormat::Pdf,
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document" => {
                DocumentFormat::Docx
            }
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" => {
                DocumentFormat::Xlsx
            }
            "application/vnd.openxmlformats-officedocument.presentationml.presentation" => {
                DocumentFormat::Pptx
            }
            "application/epub+zip" => DocumentFormat::Epub,
            _ if essence.ends_with("+json") => DocumentFormat::Json,
            _ if essence.starts_with("text/x-") => DocumentFormat::Code,
            _ if essence.starts_with("text/") => DocumentFormat::Text,
            _ => return None,
        })
    }
}

/// Bounds applied to one [`read`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReaderLimits {
    /// Maximum input size in bytes.
    pub max_input_bytes: usize,
    /// Maximum Markdown size in bytes, including the truncation marker.
    pub max_output_bytes: usize,
    /// Maximum tags parsed from one HTML or XML document.
    pub max_tags: usize,
    /// Maximum PDF pages or EPUB chapters.
    pub max_pages: usize,
}

impl Default for ReaderLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: DEFAULT_MAX_INPUT_BYTES,
            max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
            max_tags: DEFAULT_MAX_TAGS,
            max_pages: DEFAULT_READER_MAX_PAGES,
        }
    }
}

/// Detect a format from magic bytes, then from an extension or content type.
///
/// `hint` may be a file name, an extension (`.pdf`, `md`), or a MIME type.
/// Magic bytes win for PDF, ZIP containers, and HTML; otherwise the hint is
/// trusted, and without a hint the body is classified as JSON when it starts
/// with `{`/`[`, as text when it is valid UTF-8 without NUL bytes, and as
/// [`DocumentFormat::Unknown`] for binary data.
pub fn detect_format(bytes: &[u8], hint: Option<&str>) -> DocumentFormat {
    let hint = hint.and_then(hint_format);

    if bytes.starts_with(b"%PDF-") {
        return DocumentFormat::Pdf;
    }
    if bytes.starts_with(b"PK\x03\x04") {
        if let Some(format) = zip_container_format(bytes) {
            return format;
        }
        return hint.unwrap_or(DocumentFormat::Unknown);
    }
    if looks_like_html(bytes) {
        return DocumentFormat::Html;
    }
    if let Some(format) = hint {
        return format;
    }
    if is_text(bytes) {
        let text = decode_utf8_lenient(bytes);
        if text.trim_start().starts_with('{') || text.trim_start().starts_with('[') {
            return DocumentFormat::Json;
        }
        return DocumentFormat::Text;
    }
    DocumentFormat::Unknown
}

fn hint_format(hint: &str) -> Option<DocumentFormat> {
    let hint = hint.trim();
    if hint.is_empty() {
        return None;
    }
    if hint.contains('/') {
        return DocumentFormat::from_content_type(hint);
    }
    let extension = hint.rsplit('.').next().unwrap_or(hint);
    DocumentFormat::from_extension(extension)
}

fn looks_like_html(bytes: &[u8]) -> bool {
    let mut rest = bytes;
    if let Some(stripped) = rest.strip_prefix(&[0xEF, 0xBB, 0xBF]) {
        rest = stripped;
    }
    while rest.first().is_some_and(|byte| byte.is_ascii_whitespace()) {
        rest = &rest[1..];
    }
    let head: Vec<u8> = rest
        .iter()
        .take(64)
        .map(|byte| byte.to_ascii_lowercase())
        .collect();
    head.starts_with(b"<!doctype html") || head.starts_with(b"<html")
}

fn is_text(bytes: &[u8]) -> bool {
    !bytes.contains(&0) && std::str::from_utf8(bytes).is_ok()
}

fn decode_utf8_lenient(bytes: &[u8]) -> std::borrow::Cow<'_, str> {
    let bytes = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);
    String::from_utf8_lossy(bytes)
}

fn zip_container_format(bytes: &[u8]) -> Option<DocumentFormat> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).ok()?;
    let mut format = None;
    for index in 0..archive.len().min(4_096) {
        let Ok(entry) = archive.by_index_raw(index) else {
            continue;
        };
        let Ok(name) = entry.name() else {
            continue;
        };
        let name = name.as_ref();
        if name == "word/document.xml" {
            return Some(DocumentFormat::Docx);
        }
        if name == "xl/workbook.xml" {
            return Some(DocumentFormat::Xlsx);
        }
        if name == "ppt/presentation.xml" {
            return Some(DocumentFormat::Pptx);
        }
        if name == "META-INF/container.xml" {
            format = Some(DocumentFormat::Epub);
        }
    }
    format
}

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

/// One document converted to Markdown.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadDocument {
    /// Format that was read.
    pub format: DocumentFormat,
    /// Document title when one was found.
    pub title: Option<String>,
    /// Reader-mode Markdown body.
    pub markdown: String,
    /// Whether an output, table, or page bound cut the document.
    pub truncated: bool,
    /// Input size in bytes.
    pub bytes_in: usize,
    /// Links (`<a href>`) collected from HTML, EPUB, or XHTML.
    pub links: Vec<String>,
}

/// Convert document bytes to Markdown.
///
/// `format` is usually [`detect_format`]'s result. Passing
/// [`DocumentFormat::Unknown`] asks the reader to detect again; a body that is
/// still binary is refused with `zero.fnd.unsupported`. Input over
/// [`ReaderLimits::max_input_bytes`] is refused with `zero.fnd.limit_exceeded`,
/// and output is capped at [`ReaderLimits::max_output_bytes`] with
/// [`ReadDocument::truncated`] set.
pub fn read(bytes: &[u8], format: DocumentFormat, limits: &ReaderLimits) -> Result<ReadDocument> {
    if bytes.len() > limits.max_input_bytes {
        return Err(limit(format!(
            "document has {} bytes, reader input limit is {}",
            bytes.len(),
            limits.max_input_bytes
        )));
    }
    let format = if format == DocumentFormat::Unknown {
        detect_format(bytes, None)
    } else {
        format
    };
    let draft = match format {
        DocumentFormat::Html => {
            let html = utf8(bytes, "HTML")?;
            html_to_draft(html, limits)?
        }
        DocumentFormat::Markdown => {
            let text = utf8(bytes, "Markdown")?;
            Draft {
                title: markdown_title(text),
                markdown: text.to_string(),
                links: Vec::new(),
                truncated: false,
            }
        }
        DocumentFormat::Text => {
            let text = utf8(bytes, "text")?;
            Draft {
                title: None,
                markdown: text.to_string(),
                links: Vec::new(),
                truncated: false,
            }
        }
        DocumentFormat::Code => {
            let text = utf8(bytes, "code")?;
            let mut out = Out::new(limits.max_output_bytes);
            out.fenced("", text);
            let truncated = out.truncated;
            Draft {
                title: None,
                markdown: out.finish(),
                links: Vec::new(),
                truncated,
            }
        }
        DocumentFormat::Csv => {
            let text = utf8(bytes, "CSV")?;
            csv_to_draft(text)?
        }
        DocumentFormat::Json => json_to_draft(bytes)?,
        DocumentFormat::Pdf => pdf_to_draft(bytes, limits)?,
        DocumentFormat::Docx => docx_to_draft(bytes, limits)?,
        DocumentFormat::Xlsx => xlsx_to_draft(bytes, limits)?,
        DocumentFormat::Pptx => pptx_to_draft(bytes, limits)?,
        DocumentFormat::Epub => epub_to_draft(bytes, limits)?,
        DocumentFormat::Unknown => {
            return Err(unsupported(
                "input is binary or in an unsupported container; use the archive reader for \
                 plain ZIP archives",
            ));
        }
    };

    let mut truncated = draft.truncated;
    let markdown = cap_output(draft.markdown, limits.max_output_bytes, &mut truncated);
    Ok(ReadDocument {
        format,
        title: draft.title,
        markdown,
        truncated,
        bytes_in: bytes.len(),
        links: draft.links,
    })
}

/// Read a document from disk, detecting its format from the extension and
/// magic bytes.
///
/// The file size is checked before the read, so a large file is refused without
/// allocating it.
pub fn read_file(path: &Path, limits: &ReaderLimits) -> Result<ReadDocument> {
    let metadata = fs::metadata(path)
        .map_err(|error| io_error(error, &format!("failed to inspect `{}`", path.display())))?;
    if metadata.len() > limits.max_input_bytes as u64 {
        return Err(limit(format!(
            "`{}` has {} bytes, reader input limit is {}",
            path.display(),
            metadata.len(),
            limits.max_input_bytes
        )));
    }
    let bytes = fs::read(path)
        .map_err(|error| io_error(error, &format!("failed to read `{}`", path.display())))?;
    let extension = path.extension().and_then(|value| value.to_str());
    let format = detect_format(&bytes, extension);
    read(&bytes, format, limits)
}

fn utf8<'a>(bytes: &'a [u8], what: &str) -> Result<&'a str> {
    let bytes = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);
    std::str::from_utf8(bytes).map_err(|error| {
        invalid(format!(
            "{what} is not valid UTF-8 (invalid byte at offset {}); decode the fetch first",
            error.valid_up_to()
        ))
    })
}

struct Draft {
    title: Option<String>,
    markdown: String,
    links: Vec<String>,
    truncated: bool,
}

fn cap_output(markdown: String, max: usize, truncated: &mut bool) -> String {
    if markdown.len() <= max {
        return markdown;
    }
    *truncated = true;
    let keep = max.saturating_sub(READER_TRUNCATION_MARKER.len());
    let cut = floor_char_boundary(&markdown, keep);
    let mut capped = markdown;
    capped.truncate(cut);
    while capped.ends_with(['\n', ' ']) {
        capped.pop();
    }
    if max >= READER_TRUNCATION_MARKER.len() {
        capped.push_str(READER_TRUNCATION_MARKER);
    }
    capped
}

fn floor_char_boundary(text: &str, index: usize) -> usize {
    if index >= text.len() {
        return text.len();
    }
    let mut cut = index;
    while cut > 0 && !text.is_char_boundary(cut) {
        cut -= 1;
    }
    cut
}

fn markdown_title(text: &str) -> Option<String> {
    for line in text.lines().take(64) {
        let trimmed = line.trim();
        let hashes = trimmed
            .chars()
            .take_while(|character| *character == '#')
            .count();
        if (1..=6).contains(&hashes) {
            let title = trimmed[hashes..].trim();
            if !title.is_empty() {
                return Some(clip_chars(title, MAX_TITLE_CHARS));
            }
        }
    }
    None
}

fn clip_chars(text: &str, max: usize) -> String {
    let mut clipped = String::new();
    for (count, character) in text.chars().enumerate() {
        if count == max {
            break;
        }
        clipped.push(character);
    }
    clipped.trim().to_string()
}

// ---------------------------------------------------------------------------
// Text formats
// ---------------------------------------------------------------------------

fn csv_to_draft(text: &str) -> Result<Draft> {
    let first_line = text.lines().next().unwrap_or("");
    let delimiter = if first_line.contains('\t') { '\t' } else { ',' };
    let mut rows = Vec::new();
    let mut row = Vec::new();
    let mut field = String::new();
    let mut in_quotes = false;
    let mut at_field_start = true;
    let mut truncated = false;
    let mut chars = text.chars().peekable();

    'rows: loop {
        match chars.next() {
            None => {
                if !field.is_empty() || !row.is_empty() {
                    push_csv_field(&mut row, &mut field, &mut truncated);
                    push_csv_row(&mut rows, &mut row, &mut truncated);
                }
                break;
            }
            Some('"') if in_quotes => {
                if chars.peek() == Some(&'"') {
                    chars.next();
                    field.push('"');
                } else {
                    in_quotes = false;
                }
            }
            Some('"') if at_field_start => {
                in_quotes = true;
                at_field_start = false;
            }
            Some(character) if !in_quotes && character == delimiter => {
                push_csv_field(&mut row, &mut field, &mut truncated);
                at_field_start = true;
            }
            Some('\r') if !in_quotes => {}
            Some('\n') if !in_quotes => {
                push_csv_field(&mut row, &mut field, &mut truncated);
                push_csv_row(&mut rows, &mut row, &mut truncated);
                at_field_start = true;
                if truncated {
                    break 'rows;
                }
            }
            Some(character) => {
                field.push(character);
                at_field_start = false;
            }
        }
    }

    if rows.len() > MAX_TABLE_ROWS {
        rows.truncate(MAX_TABLE_ROWS);
        truncated = true;
    }
    let markdown = markdown_table(&rows, &mut truncated);
    Ok(Draft {
        title: None,
        markdown,
        links: Vec::new(),
        truncated,
    })
}

fn push_csv_field(row: &mut Vec<String>, field: &mut String, truncated: &mut bool) {
    if row.len() < MAX_TABLE_COLS {
        row.push(std::mem::take(field));
    } else {
        *truncated = true;
        field.clear();
    }
}

fn push_csv_row(rows: &mut Vec<Vec<String>>, row: &mut Vec<String>, truncated: &mut bool) {
    if rows.len() < MAX_TABLE_ROWS {
        rows.push(std::mem::take(row));
    } else {
        *truncated = true;
        row.clear();
    }
}

fn json_to_draft(bytes: &[u8]) -> Result<Draft> {
    let value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|error| invalid(format!("body is not valid JSON: {error}")))?;
    let pretty = serde_json::to_string_pretty(&value)
        .map_err(|error| invalid(format!("JSON could not be formatted: {error}")))?;
    let mut out = Out::new(usize::MAX);
    out.fenced("json", &pretty);
    let truncated = out.truncated;
    Ok(Draft {
        title: None,
        markdown: out.finish(),
        links: Vec::new(),
        truncated,
    })
}

/// Escape one Markdown table cell: pipes, newlines, and excessive length.
fn escape_cell(value: &str, truncated: &mut bool) -> String {
    let value = value.trim();
    let mut escaped = String::with_capacity(value.len());
    for (count, character) in value.chars().enumerate() {
        if count == MAX_TABLE_CELL_CHARS {
            *truncated = true;
            break;
        }
        match character {
            '|' => escaped.push_str("\\|"),
            '\n' | '\r' => escaped.push_str("<br>"),
            _ => escaped.push(character),
        }
    }
    escaped
}

fn markdown_table(rows: &[Vec<String>], truncated: &mut bool) -> String {
    if rows.is_empty() {
        return String::new();
    }
    let columns = rows
        .iter()
        .map(Vec::len)
        .max()
        .unwrap_or(0)
        .min(MAX_TABLE_COLS);
    if columns == 0 {
        return String::new();
    }
    let mut markdown = String::new();
    for (index, row) in rows.iter().take(MAX_TABLE_ROWS).enumerate() {
        markdown.push('|');
        for column in 0..columns {
            markdown.push(' ');
            markdown.push_str(&escape_cell(
                row.get(column).map(String::as_str).unwrap_or(""),
                truncated,
            ));
            markdown.push(' ');
            markdown.push('|');
        }
        markdown.push('\n');
        if index == 0 {
            markdown.push('|');
            for _ in 0..columns {
                markdown.push_str(" --- |");
            }
            markdown.push('\n');
        }
    }
    if rows.len() > MAX_TABLE_ROWS {
        *truncated = true;
    }
    markdown
}

// ---------------------------------------------------------------------------
// Markdown writer
// ---------------------------------------------------------------------------

struct Out {
    buf: String,
    limit: usize,
    truncated: bool,
    block_pending: bool,
    line_start: bool,
    pending_space: bool,
    quote_depth: usize,
}

impl Out {
    fn new(limit: usize) -> Self {
        Self {
            buf: String::new(),
            limit,
            truncated: false,
            block_pending: false,
            line_start: true,
            pending_space: false,
            quote_depth: 0,
        }
    }

    fn finish(self) -> String {
        self.buf
    }

    fn push_str(&mut self, text: &str) {
        if text.is_empty() || self.truncated {
            return;
        }
        let remaining = self.limit.saturating_sub(self.buf.len());
        if text.len() <= remaining {
            self.buf.push_str(text);
        } else {
            let cut = floor_char_boundary(text, remaining);
            self.buf.push_str(&text[..cut]);
            self.truncated = true;
        }
    }

    fn blank(&mut self) {
        if !self.buf.is_empty() {
            self.block_pending = true;
        }
        self.pending_space = false;
    }

    fn ensure_block(&mut self) {
        if self.block_pending {
            if !self.buf.is_empty() {
                while !self.buf.ends_with("\n\n") && !self.truncated {
                    self.push_str("\n");
                }
            }
            self.block_pending = false;
            self.line_start = true;
            self.pending_space = false;
        }
    }

    fn start_line(&mut self) {
        if self.line_start {
            for _ in 0..self.quote_depth {
                self.push_str("> ");
            }
            if !self.truncated {
                self.line_start = false;
            }
        }
    }

    fn newline(&mut self) {
        if !self.line_start && !self.buf.is_empty() {
            self.push_str("\n");
            self.line_start = true;
        }
        self.pending_space = false;
    }

    fn line(&mut self, text: &str) {
        self.ensure_block();
        self.start_line();
        self.push_str(text);
        self.newline();
    }

    fn inline_literal(&mut self, text: &str) {
        if text.is_empty() {
            return;
        }
        self.ensure_block();
        self.start_line();
        if self.pending_space && !self.buf.ends_with([' ', '\n']) {
            self.push_str(" ");
        }
        self.pending_space = false;
        self.push_str(text);
    }

    fn text(&mut self, raw: &str) {
        let leading = raw.chars().next().is_some_and(char::is_whitespace);
        let trailing = raw.chars().last().is_some_and(char::is_whitespace);
        let mut collapsed = String::new();
        let mut pending = false;
        for character in raw.chars() {
            if character.is_whitespace() {
                pending = !collapsed.is_empty();
            } else {
                if pending {
                    collapsed.push(' ');
                    pending = false;
                }
                collapsed.push(character);
            }
        }
        if collapsed.is_empty() {
            if leading || trailing {
                self.pending_space = true;
            }
            return;
        }
        if leading {
            self.pending_space = true;
        }
        self.inline_literal(&collapsed);
        self.pending_space = trailing || pending;
    }

    fn fenced(&mut self, language: &str, content: &str) {
        let fence = fence_for(content);
        self.ensure_block();
        self.start_line();
        self.push_str(&fence);
        self.push_str(language);
        self.newline();
        let body = content.strip_suffix('\n').unwrap_or(content);
        for line in body.split('\n') {
            self.start_line();
            self.push_str(line);
            self.newline();
        }
        self.start_line();
        self.push_str(&fence);
        self.newline();
        self.blank();
    }

    fn append_markdown(&mut self, markdown: &str) {
        if markdown.is_empty() {
            return;
        }
        if !self.buf.is_empty() && !self.buf.ends_with("\n\n") {
            if !self.buf.ends_with('\n') {
                self.push_str("\n");
            }
            self.push_str("\n");
        }
        self.push_str(markdown);
        self.line_start = self.buf.ends_with('\n');
        self.block_pending = false;
    }
}

fn fence_for(content: &str) -> String {
    let mut longest = 0usize;
    let mut run = 0usize;
    for character in content.chars() {
        if character == '`' {
            run += 1;
            longest = longest.max(run);
        } else {
            run = 0;
        }
    }
    "`".repeat((longest + 1).clamp(3, 16))
}

// ---------------------------------------------------------------------------
// HTML reader mode
// ---------------------------------------------------------------------------

const DROPPED: &[&str] = &[
    "nav", "header", "footer", "aside", "script", "style", "noscript", "template", "svg",
];

fn html_to_draft(html: &str, limits: &ReaderLimits) -> Result<Draft> {
    let title = html_title(html, limits.max_tags)?;
    let (start, end) = content_region(html, limits.max_tags)?;
    let mut reader = HtmlReader::new(&html[start..end], limits);
    reader.run()?;
    let first_heading = reader.first_heading.clone();
    Ok(Draft {
        title: title.or(first_heading),
        markdown: reader.out.finish(),
        links: reader.links,
        truncated: reader.truncated,
    })
}

/// Find the first `<article>`/`<main>` span, else the `<body>` span, else the
/// whole document.
fn content_region(html: &str, max_tags: usize) -> Result<(usize, usize)> {
    let bytes = html.as_bytes();
    let mut index = 0usize;
    let mut tags = 0usize;
    let mut target: Option<(String, usize, usize)> = None;
    let mut body_start: Option<usize> = None;
    let mut body_end: Option<usize> = None;

    while index < bytes.len() {
        if bytes[index] != b'<' {
            index = find_byte(bytes, index, b'<').unwrap_or(bytes.len());
            continue;
        }
        let rest = &html[index..];
        if rest.starts_with("<!--") {
            index = rest
                .find("-->")
                .map(|offset| index + offset + 3)
                .unwrap_or(bytes.len());
            continue;
        }
        if rest.starts_with("<!") || rest.starts_with("<?") {
            index = find_byte(bytes, index, b'>')
                .map(|position| position + 1)
                .unwrap_or(bytes.len());
            continue;
        }
        let is_end = bytes.get(index + 1) == Some(&b'/');
        let name_start = index + if is_end { 2 } else { 1 };
        if !bytes.get(name_start).is_some_and(u8::is_ascii_alphabetic) {
            index += 1;
            continue;
        }
        tags += 1;
        if tags > max_tags {
            return Err(limit(format!("document has more than {max_tags} tags")));
        }
        if is_end {
            let (name, next) = parse_end_tag(html, index);
            if let Some((target_name, content_start, depth)) = target.as_mut() {
                if name == *target_name {
                    *depth -= 1;
                    if *depth == 0 {
                        return Ok((*content_start, index));
                    }
                }
            }
            if name == "body" && body_start.take().is_some() {
                body_end = Some(index);
            }
            index = next;
            continue;
        }
        let tag = parse_start_tag(html, index)?;
        index = tag.next;
        if matches!(tag.name.as_str(), "script" | "style" | "title") && !tag.self_closing {
            index = skip_raw_text(html, index, &tag.name);
            continue;
        }
        if tag.name == "body" && body_start.is_none() {
            body_start = Some(tag.next);
        }
        match target.as_mut() {
            None => {
                if matches!(tag.name.as_str(), "article" | "main") && !tag.self_closing {
                    target = Some((tag.name.clone(), tag.next, 1));
                }
            }
            Some((target_name, _, depth)) => {
                if tag.name == *target_name && !tag.self_closing {
                    *depth += 1;
                }
            }
        }
    }

    if let Some((_, content_start, _)) = target {
        return Ok((content_start, html.len()));
    }
    if let Some(start) = body_start {
        return Ok((start, body_end.unwrap_or(html.len())));
    }
    Ok((0, html.len()))
}

fn html_title(html: &str, max_tags: usize) -> Result<Option<String>> {
    let bytes = html.as_bytes();
    let mut index = 0usize;
    let mut tags = 0usize;
    while index < bytes.len() {
        if bytes[index] != b'<' {
            index = find_byte(bytes, index, b'<').unwrap_or(bytes.len());
            continue;
        }
        let rest = &html[index..];
        if rest.starts_with("<!--") {
            index = rest
                .find("-->")
                .map(|offset| index + offset + 3)
                .unwrap_or(bytes.len());
            continue;
        }
        if rest.starts_with("<!") || rest.starts_with("<?") {
            index = find_byte(bytes, index, b'>')
                .map(|position| position + 1)
                .unwrap_or(bytes.len());
            continue;
        }
        let is_end = bytes.get(index + 1) == Some(&b'/');
        let name_start = index + if is_end { 2 } else { 1 };
        if !bytes.get(name_start).is_some_and(u8::is_ascii_alphabetic) {
            index += 1;
            continue;
        }
        tags += 1;
        if tags > max_tags {
            return Err(limit(format!("document has more than {max_tags} tags")));
        }
        if is_end {
            let (_, next) = parse_end_tag(html, index);
            index = next;
            continue;
        }
        let tag = parse_start_tag(html, index)?;
        index = tag.next;
        if tag.name == "title" && !tag.self_closing {
            let close = find_ignore_ascii_case(html, index, "</title").unwrap_or(html.len());
            let title = normalize_text(&decode_entities(&html[index..close]));
            if title.is_empty() {
                return Ok(None);
            }
            return Ok(Some(clip_chars(&title, MAX_TITLE_CHARS)));
        }
        if matches!(tag.name.as_str(), "script" | "style") && !tag.self_closing {
            index = skip_raw_text(html, index, &tag.name);
        }
    }
    Ok(None)
}

struct HtmlReader<'a> {
    html: &'a str,
    out: Out,
    links: Vec<String>,
    seen_links: BTreeSet<String>,
    max_tags: usize,
    skip_depth: usize,
    lists: Vec<ListState>,
    link: Option<(usize, String)>,
    table: Option<TableState>,
    first_heading: Option<String>,
    truncated: bool,
}

impl<'a> HtmlReader<'a> {
    fn new(html: &'a str, limits: &ReaderLimits) -> Self {
        Self {
            html,
            out: Out::new(limits.max_output_bytes),
            links: Vec::new(),
            seen_links: BTreeSet::new(),
            max_tags: limits.max_tags,
            skip_depth: 0,
            lists: Vec::new(),
            link: None,
            table: None,
            first_heading: None,
            truncated: false,
        }
    }

    fn run(&mut self) -> Result<()> {
        let bytes = self.html.as_bytes();
        let mut index = 0usize;
        let mut tags = 0usize;

        while index < bytes.len() {
            if self.out.truncated {
                self.truncated = true;
                break;
            }
            if bytes[index] != b'<' {
                let end = find_byte(bytes, index, b'<').unwrap_or(bytes.len());
                let text = decode_entities(&self.html[index..end]);
                self.accept_text(&text);
                index = end;
                continue;
            }
            let rest = &self.html[index..];
            if rest.starts_with("<!--") {
                index = rest
                    .find("-->")
                    .map(|offset| index + offset + 3)
                    .unwrap_or(bytes.len());
                continue;
            }
            if rest.starts_with("<!") || rest.starts_with("<?") {
                index = find_byte(bytes, index, b'>')
                    .map(|position| position + 1)
                    .unwrap_or(bytes.len());
                continue;
            }
            let is_end = bytes.get(index + 1) == Some(&b'/');
            let name_start = index + if is_end { 2 } else { 1 };
            if !bytes.get(name_start).is_some_and(u8::is_ascii_alphabetic) {
                self.accept_text("<");
                index += 1;
                continue;
            }
            tags += 1;
            if tags > self.max_tags {
                return Err(limit(format!(
                    "document has more than {} tags",
                    self.max_tags
                )));
            }

            if is_end {
                let (name, next) = parse_end_tag(self.html, index);
                index = next;
                self.end_tag(&name);
                continue;
            }
            let tag = parse_start_tag(self.html, index)?;
            index = tag.next;

            if self.skip_depth > 0 {
                if matches!(tag.name.as_str(), "script" | "style") && !tag.self_closing {
                    index = skip_raw_text(self.html, index, &tag.name);
                } else if !tag.self_closing && !is_void(&tag.name) {
                    self.skip_depth += 1;
                }
                continue;
            }

            if DROPPED.contains(&tag.name.as_str()) {
                if matches!(tag.name.as_str(), "script" | "style") && !tag.self_closing {
                    index = skip_raw_text(self.html, index, &tag.name);
                } else if !tag.self_closing && !is_void(&tag.name) {
                    self.skip_depth = 1;
                }
                continue;
            }

            if tag.name == "pre" && !tag.self_closing {
                let close =
                    find_ignore_ascii_case(self.html, index, "</pre").unwrap_or(self.html.len());
                let content = &self.html[index..close];
                let (language, body) = split_code_wrapper(content);
                self.out.blank();
                self.out.fenced(&language, &body);
                self.out.blank();
                index = find_byte(bytes, close, b'>')
                    .map(|position| position + 1)
                    .unwrap_or(bytes.len());
                continue;
            }

            if self.table.is_some() {
                self.table_start(&tag);
                continue;
            }

            self.start_tag(&tag);
        }
        if self.link.is_some() {
            self.close_link();
        }
        self.truncated |= self.out.truncated;
        Ok(())
    }

    fn accept_text(&mut self, text: &str) {
        if self.skip_depth > 0 {
            return;
        }
        if let Some(table) = self.table.as_mut() {
            if table.in_cell {
                table.push_text(text);
            }
            return;
        }
        self.out.text(text);
    }

    fn start_tag(&mut self, tag: &StartTag) {
        match tag.name.as_str() {
            "h1" | "h2" | "h3" | "h4" | "h5" | "h6" => {
                let level = tag.name[1..].parse::<usize>().unwrap_or(1);
                self.out.blank();
                self.out.ensure_block();
                self.out.start_line();
                self.out.push_str(&"#".repeat(level));
                self.out.push_str(" ");
                self.out.pending_space = false;
            }
            "p" | "div" | "section" | "article" | "main" | "figure" | "figcaption" => {
                self.out.blank();
            }
            "blockquote" => {
                self.out.blank();
                self.out.quote_depth += 1;
            }
            "ul" => self.begin_list(ListState::Unordered),
            "ol" => self.begin_list(ListState::Ordered(0)),
            "li" => self.list_item(),
            "hr" => {
                self.out.blank();
                self.out.line("---");
                self.out.blank();
            }
            "br" => self.out.newline(),
            "table" => {
                self.out.blank();
                self.table = Some(TableState::new());
            }
            "a" => {
                if let Some(href) = tag.attrs.get("href") {
                    if !href.is_empty() {
                        self.collect_link(href);
                        self.link = Some((self.out.buf.len(), href.clone()));
                    }
                }
            }
            "img" => {
                let alt = tag.attrs.get("alt").map(String::as_str).unwrap_or("");
                let source = tag.attrs.get("src").map(String::as_str).unwrap_or("");
                self.out
                    .inline_literal(&format!("![{}]({})", alt.trim(), source.trim()));
            }
            _ => {}
        }
    }

    fn end_tag(&mut self, name: &str) {
        if self.skip_depth > 0 {
            self.skip_depth -= 1;
            return;
        }
        if self.table.is_some() {
            self.table_end(name);
            return;
        }
        match name {
            "h1" | "h2" | "h3" | "h4" | "h5" | "h6" => {
                if name == "h1" && self.first_heading.is_none() {
                    let line = self
                        .out
                        .buf
                        .rsplit('\n')
                        .next()
                        .unwrap_or("")
                        .trim()
                        .trim_start_matches('#')
                        .trim()
                        .to_string();
                    if !line.is_empty() {
                        self.first_heading = Some(clip_chars(&line, MAX_TITLE_CHARS));
                    }
                }
                self.out.newline();
                self.out.blank();
            }
            "p" | "div" | "section" | "article" | "main" | "figure" | "figcaption" => {
                self.out.blank();
            }
            "blockquote" => {
                self.out.quote_depth = self.out.quote_depth.saturating_sub(1);
                self.out.blank();
            }
            "ul" | "ol" => {
                self.lists.pop();
                if self.lists.is_empty() {
                    self.out.blank();
                } else {
                    self.out.newline();
                }
            }
            "li" => self.out.newline(),
            "a" => self.close_link(),
            _ => {}
        }
    }

    fn begin_list(&mut self, kind: ListState) {
        if self.lists.is_empty() {
            self.out.blank();
        } else {
            self.out.newline();
        }
        self.lists.push(kind);
    }

    fn list_item(&mut self) {
        if !self.out.line_start {
            self.out.newline();
        }
        let depth = self.lists.len().max(1);
        let marker = match self.lists.last_mut() {
            Some(ListState::Ordered(item)) => {
                *item += 1;
                format!("{item}. ")
            }
            _ => "- ".to_string(),
        };
        self.out.ensure_block();
        self.out.start_line();
        self.out.push_str(&"  ".repeat(depth - 1));
        self.out.push_str(&marker);
        self.out.pending_space = false;
    }

    fn collect_link(&mut self, href: &str) {
        if self.links.len() >= MAX_LINKS {
            return;
        }
        if self.seen_links.insert(href.to_string()) {
            self.links.push(href.to_string());
        }
    }

    fn close_link(&mut self) {
        let Some((start, href)) = self.link.take() else {
            return;
        };
        if self.out.truncated || start > self.out.buf.len() {
            return;
        }
        let label = self.out.buf[start..].trim().to_string();
        self.out.buf.truncate(start);
        let label = if label.is_empty() {
            href.clone()
        } else {
            label
        };
        self.out.inline_literal(&format!("[{label}]({href})"));
    }

    fn table_start(&mut self, tag: &StartTag) {
        let Some(table) = self.table.as_mut() else {
            return;
        };
        match tag.name.as_str() {
            "table" => table.depth += 1,
            "tr" => {
                if table.depth == 1 {
                    table.row.clear();
                }
            }
            "td" | "th" => {
                if table.depth == 1 {
                    table.cell.clear();
                    table.in_cell = true;
                }
            }
            "br" => {
                if table.in_cell {
                    table.cell.push(' ');
                }
            }
            "a" => {
                if let Some(href) = tag.attrs.get("href") {
                    self.collect_link(href);
                }
            }
            _ => {}
        }
    }

    fn table_end(&mut self, name: &str) {
        let Some(table) = self.table.as_mut() else {
            return;
        };
        match name {
            "td" | "th" => {
                if table.depth == 1 {
                    table.end_cell(&mut self.truncated);
                }
            }
            "tr" => {
                if table.depth == 1 {
                    table.end_row(&mut self.truncated);
                }
            }
            "table" => {
                if table.depth > 1 {
                    table.depth -= 1;
                } else if let Some(table) = self.table.take() {
                    let rows = table.finish();
                    let markdown = markdown_table(&rows, &mut self.truncated);
                    if !markdown.is_empty() {
                        self.out.blank();
                        for line in markdown.lines() {
                            self.out.line(line);
                        }
                        self.out.blank();
                    }
                }
            }
            _ => {}
        }
    }
}

#[derive(Clone, Copy)]
enum ListState {
    Unordered,
    Ordered(u32),
}

struct TableState {
    depth: usize,
    rows: Vec<Vec<String>>,
    row: Vec<String>,
    cell: String,
    in_cell: bool,
}

impl TableState {
    fn new() -> Self {
        Self {
            depth: 1,
            rows: Vec::new(),
            row: Vec::new(),
            cell: String::new(),
            in_cell: false,
        }
    }

    fn push_text(&mut self, text: &str) {
        let normalized = normalize_text(text);
        if normalized.is_empty() {
            return;
        }
        if !self.cell.is_empty() && !self.cell.ends_with(' ') {
            self.cell.push(' ');
        }
        self.cell.push_str(&normalized);
    }

    fn end_cell(&mut self, truncated: &mut bool) {
        if !self.in_cell {
            return;
        }
        self.in_cell = false;
        if self.row.len() < MAX_TABLE_COLS {
            self.row.push(normalize_text(&self.cell));
        } else {
            *truncated = true;
        }
        self.cell.clear();
    }

    fn end_row(&mut self, truncated: &mut bool) {
        if self.row.is_empty() {
            return;
        }
        if self.rows.len() < MAX_TABLE_ROWS {
            let row = std::mem::take(&mut self.row);
            self.rows.push(row);
        } else {
            *truncated = true;
            self.row.clear();
        }
    }

    fn finish(mut self) -> Vec<Vec<String>> {
        if self.in_cell {
            let mut ignored = false;
            self.end_cell(&mut ignored);
        }
        if !self.row.is_empty() {
            let mut ignored = false;
            self.end_row(&mut ignored);
        }
        self.rows
    }
}

/// Split a `<pre>` body such as `<code class="language-rust">...</code>` into
/// an optional language and the code text.
fn split_code_wrapper(content: &str) -> (String, String) {
    let trimmed = content.trim_start();
    if trimmed.to_ascii_lowercase().starts_with("<code") {
        if let Some(open_end) = trimmed.find('>') {
            let open = &trimmed[..=open_end];
            let language = parse_start_tag(open, 0)
                .ok()
                .and_then(|tag| tag.attrs.get("class").cloned())
                .and_then(|class| {
                    class
                        .split_whitespace()
                        .find_map(|token| {
                            token
                                .strip_prefix("language-")
                                .or_else(|| token.strip_prefix("lang-"))
                        })
                        .map(|value| {
                            value
                                .chars()
                                .filter(|character| {
                                    character.is_ascii_alphanumeric()
                                        || matches!(character, '-' | '_' | '+')
                                })
                                .collect::<String>()
                        })
                })
                .unwrap_or_default();
            let rest = &trimmed[open_end + 1..];
            let close = find_ignore_ascii_case(rest, 0, "</code").unwrap_or(rest.len());
            let body = rest[..close].strip_prefix('\n').unwrap_or(&rest[..close]);
            return (language, decode_entities(body));
        }
    }
    let body = content.strip_prefix('\n').unwrap_or(content);
    (String::new(), decode_entities(body))
}

// ---------------------------------------------------------------------------
// ZIP containers
// ---------------------------------------------------------------------------

type ZipCursor<'a> = zip::ZipArchive<Cursor<&'a [u8]>>;

fn archive_limits(limits: &ReaderLimits) -> ArchiveLimits {
    ArchiveLimits {
        max_entries: 2_048,
        max_total_bytes: limits.max_input_bytes as u64,
        max_entry_bytes: limits.max_input_bytes as u64,
        // OOXML XML is highly repetitive; 200:1 still refuses real bombs while
        // accepting an ordinary document.
        max_compression_ratio: 200,
        max_path_depth: 16,
    }
}

fn open_planned<'a>(
    bytes: &'a [u8],
    limits: &ReaderLimits,
) -> Result<(ZipCursor<'a>, BTreeMap<String, usize>)> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).map_err(zip_error)?;
    let (_, plan) = build_plan(&mut archive, &archive_limits(limits))?;
    let mut index = BTreeMap::new();
    for entry in plan {
        if !entry.is_dir {
            index.insert(entry.name, entry.index);
        }
    }
    Ok((archive, index))
}

fn zip_error(error: zip::result::ZipError) -> ZeroError {
    match error {
        zip::result::ZipError::Io(error) => {
            ZeroError::new(ErrorCode::Io, format!("archive I/O failed: {error}"))
        }
        zip::result::ZipError::InvalidArchive(detail) => {
            corrupt(format!("malformed archive: {detail}"))
        }
        zip::result::ZipError::UnsupportedArchive(detail) => {
            unsupported(format!("unsupported archive feature: {detail}"))
        }
        zip::result::ZipError::InvalidPassword => {
            unsupported("archive entry is encrypted with a password")
        }
        zip::result::ZipError::FileNotFound => {
            corrupt("an archive entry named in the central directory is missing")
        }
        zip::result::ZipError::CompressionMethodNotSupported(method) => {
            unsupported(format!("archive uses unsupported compression: {method:?}"))
        }
        other => corrupt(format!("archive could not be read: {other}")),
    }
}

fn read_named<R: Read + Seek>(
    archive: &mut zip::ZipArchive<R>,
    index: &BTreeMap<String, usize>,
    name: &str,
    max: u64,
) -> Result<Option<Vec<u8>>> {
    let Some(&entry) = index.get(name) else {
        return Ok(None);
    };
    let file = archive.by_index(entry).map_err(zip_error)?;
    let mut bytes = Vec::new();
    file.take(max.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| io_error(error, &format!("failed to read archive entry `{name}`")))?;
    if bytes.len() as u64 > max {
        return Err(limit(format!(
            "archive entry `{name}` expands beyond {max} bytes"
        )));
    }
    Ok(Some(bytes))
}

fn read_required<R: Read + Seek>(
    archive: &mut zip::ZipArchive<R>,
    index: &BTreeMap<String, usize>,
    name: &str,
    max: u64,
) -> Result<Vec<u8>> {
    read_named(archive, index, name, max)?.ok_or_else(|| {
        corrupt(format!(
            "required archive entry `{name}` is missing from the container"
        ))
    })
}

// --- Minimal XML events -----------------------------------------------------

enum XmlEvent {
    Start(StartTag),
    End(String),
    Text(String),
}

struct XmlScanner<'a> {
    xml: &'a str,
    index: usize,
    tags: usize,
    max_tags: usize,
}

impl<'a> XmlScanner<'a> {
    fn new(xml: &'a str, max_tags: usize) -> Self {
        Self {
            xml,
            index: 0,
            tags: 0,
            max_tags,
        }
    }

    fn next(&mut self) -> Result<Option<XmlEvent>> {
        let bytes = self.xml.as_bytes();
        while self.index < bytes.len() {
            if bytes[self.index] != b'<' {
                let end = find_byte(bytes, self.index, b'<').unwrap_or(bytes.len());
                let text = decode_entities(&self.xml[self.index..end]);
                self.index = end;
                return Ok(Some(XmlEvent::Text(text)));
            }
            let rest = &self.xml[self.index..];
            if rest.starts_with("<!--") {
                self.index = rest
                    .find("-->")
                    .map(|offset| self.index + offset + 3)
                    .unwrap_or(bytes.len());
                continue;
            }
            if let Some(cdata) = rest.strip_prefix("<![CDATA[") {
                let end = cdata.find("]]>").map(|offset| self.index + 9 + offset);
                let text_end = end.unwrap_or(bytes.len());
                let text = self.xml[self.index + 9..text_end].to_string();
                self.index = end.map(|position| position + 3).unwrap_or(bytes.len());
                return Ok(Some(XmlEvent::Text(text)));
            }
            if rest.starts_with("<!") || rest.starts_with("<?") {
                self.index = find_byte(bytes, self.index, b'>')
                    .map(|position| position + 1)
                    .unwrap_or(bytes.len());
                continue;
            }
            let is_end = bytes.get(self.index + 1) == Some(&b'/');
            let name_start = self.index + if is_end { 2 } else { 1 };
            if !bytes.get(name_start).is_some_and(u8::is_ascii_alphabetic) {
                self.index += 1;
                continue;
            }
            self.tags += 1;
            if self.tags > self.max_tags {
                return Err(limit(format!(
                    "document has more than {} tags",
                    self.max_tags
                )));
            }
            if is_end {
                let (name, next) = parse_end_tag(self.xml, self.index);
                self.index = next;
                return Ok(Some(XmlEvent::End(name)));
            }
            let tag = parse_start_tag(self.xml, self.index)?;
            self.index = tag.next;
            return Ok(Some(XmlEvent::Start(tag)));
        }
        Ok(None)
    }
}

fn xml_capture_text(xml: &str, tag: &str, max_tags: usize) -> Result<Option<String>> {
    let mut scanner = XmlScanner::new(xml, max_tags);
    let mut capture = false;
    let mut text = String::new();
    while let Some(event) = scanner.next()? {
        match event {
            XmlEvent::Start(start) if start.name == tag => capture = true,
            XmlEvent::Text(chunk) if capture => text.push_str(&chunk),
            XmlEvent::End(end) if end == tag && capture => {
                let normalized = normalize_text(&text);
                if normalized.is_empty() {
                    return Ok(None);
                }
                return Ok(Some(clip_chars(&normalized, MAX_TITLE_CHARS)));
            }
            _ => {}
        }
    }
    Ok(None)
}

fn xml_first_attr(
    xml: &str,
    tag: &str,
    attribute: &str,
    max_tags: usize,
) -> Result<Option<String>> {
    let mut scanner = XmlScanner::new(xml, max_tags);
    while let Some(event) = scanner.next()? {
        if let XmlEvent::Start(start) = event {
            if start.name == tag {
                return Ok(start.attrs.get(attribute).cloned());
            }
        }
    }
    Ok(None)
}

// --- DOCX ------------------------------------------------------------------

fn docx_to_draft(bytes: &[u8], limits: &ReaderLimits) -> Result<Draft> {
    let (mut archive, index) = open_planned(bytes, limits)?;
    let max = limits.max_input_bytes as u64;
    let document = read_required(&mut archive, &index, "word/document.xml", max)?;
    let document =
        String::from_utf8(document).map_err(|_| corrupt("word/document.xml is not valid UTF-8"))?;

    let meta_title = match read_named(&mut archive, &index, "docProps/core.xml", max)? {
        Some(core) => {
            let core = String::from_utf8_lossy(&core);
            xml_capture_text(&core, "dc:title", limits.max_tags)?
        }
        None => None,
    };

    let mut out = Out::new(limits.max_output_bytes);
    let mut scanner = XmlScanner::new(&document, limits.max_tags);
    let mut paragraph = String::new();
    let mut heading: Option<u8> = None;
    let mut list_item = false;
    let mut in_text = false;
    let mut first_heading = None;
    let mut table: Option<DocxTable> = None;

    while let Some(event) = scanner.next()? {
        if out.truncated {
            break;
        }
        match event {
            XmlEvent::Start(tag) => match tag.name.as_str() {
                "w:tbl" => {
                    if let Some(active) = table.as_mut() {
                        active.depth += 1;
                    } else {
                        flush_docx_paragraph(
                            &mut out,
                            &mut paragraph,
                            heading,
                            list_item,
                            &mut first_heading,
                        );
                        table = Some(DocxTable::new());
                    }
                }
                "w:tr" => {
                    if let Some(active) = table.as_mut() {
                        if active.depth == 1 {
                            active.row.clear();
                        }
                    }
                }
                "w:tc" => {
                    if let Some(active) = table.as_mut() {
                        if active.depth == 1 {
                            active.cell.clear();
                            active.in_cell = true;
                        }
                    }
                }
                "w:p" => {
                    paragraph.clear();
                    heading = None;
                    list_item = false;
                }
                "w:pstyle" => {
                    if table.is_none() {
                        if let Some(value) = tag.attrs.get("w:val") {
                            heading = docx_heading_level(value);
                        }
                    }
                }
                "w:numpr" => {
                    if table.is_none() {
                        list_item = true;
                    }
                }
                "w:t" => in_text = true,
                "w:tab" => paragraph.push(' '),
                "w:br" => paragraph.push('\n'),
                _ => {}
            },
            XmlEvent::End(name) => match name.as_str() {
                "w:t" => in_text = false,
                "w:p" => {
                    if let Some(active) = table.as_mut() {
                        let text = normalize_text(&paragraph);
                        paragraph.clear();
                        if active.in_cell && !text.is_empty() {
                            active.push_text(&text);
                        }
                    } else {
                        flush_docx_paragraph(
                            &mut out,
                            &mut paragraph,
                            heading,
                            list_item,
                            &mut first_heading,
                        );
                    }
                }
                "w:tc" => {
                    if let Some(active) = table.as_mut() {
                        if active.depth == 1 {
                            active.end_cell(&mut out.truncated);
                        }
                    }
                }
                "w:tr" => {
                    if let Some(active) = table.as_mut() {
                        if active.depth == 1 {
                            active.end_row(&mut out.truncated);
                        }
                    }
                }
                "w:tbl" => {
                    let close = table
                        .as_mut()
                        .map(|active| {
                            if active.depth > 1 {
                                active.depth -= 1;
                                false
                            } else {
                                true
                            }
                        })
                        .unwrap_or(false);
                    if close {
                        if let Some(active) = table.take() {
                            let rows = active.finish();
                            emit_table(&mut out, &rows);
                        }
                    }
                }
                _ => {}
            },
            XmlEvent::Text(text) => {
                if in_text {
                    paragraph.push_str(&text);
                }
            }
        }
    }
    if let Some(active) = table.take() {
        let rows = active.finish();
        emit_table(&mut out, &rows);
    }

    let truncated = out.truncated;
    Ok(Draft {
        title: meta_title.or(first_heading),
        markdown: out.finish(),
        links: Vec::new(),
        truncated,
    })
}

fn flush_docx_paragraph(
    out: &mut Out,
    paragraph: &mut String,
    heading: Option<u8>,
    list_item: bool,
    first_heading: &mut Option<String>,
) {
    let text = normalize_text(paragraph);
    paragraph.clear();
    if text.is_empty() {
        return;
    }
    if let Some(level) = heading {
        if first_heading.is_none() {
            *first_heading = Some(clip_chars(&text, MAX_TITLE_CHARS));
        }
        out.blank();
        out.line(&format!("{} {}", "#".repeat(level as usize), text));
        out.blank();
    } else if list_item {
        out.line(&format!("- {text}"));
    } else {
        out.blank();
        out.line(&text);
    }
}

fn docx_heading_level(style: &str) -> Option<u8> {
    let style = style.trim();
    let lower = style.to_ascii_lowercase();
    if lower == "title" {
        return Some(1);
    }
    let digits = style
        .chars()
        .rev()
        .take_while(|character| character.is_ascii_digit());
    let digits: String = digits.collect::<Vec<_>>().into_iter().rev().collect();
    let level = digits.parse::<u8>().ok()?;
    if lower.contains("heading") && (1..=6).contains(&level) {
        Some(level)
    } else {
        None
    }
}

struct DocxTable {
    depth: usize,
    rows: Vec<Vec<String>>,
    row: Vec<String>,
    cell: String,
    in_cell: bool,
}

impl DocxTable {
    fn new() -> Self {
        Self {
            depth: 1,
            rows: Vec::new(),
            row: Vec::new(),
            cell: String::new(),
            in_cell: false,
        }
    }

    fn push_text(&mut self, text: &str) {
        if !self.cell.is_empty() && !self.cell.ends_with(' ') {
            self.cell.push(' ');
        }
        self.cell.push_str(text);
    }

    fn end_cell(&mut self, truncated: &mut bool) {
        if !self.in_cell {
            return;
        }
        self.in_cell = false;
        if self.row.len() < MAX_TABLE_COLS {
            self.row.push(normalize_text(&self.cell));
        } else {
            *truncated = true;
        }
        self.cell.clear();
    }

    fn end_row(&mut self, truncated: &mut bool) {
        if self.row.is_empty() {
            return;
        }
        if self.rows.len() < MAX_TABLE_ROWS {
            let row = std::mem::take(&mut self.row);
            self.rows.push(row);
        } else {
            *truncated = true;
            self.row.clear();
        }
    }

    fn finish(mut self) -> Vec<Vec<String>> {
        if self.in_cell {
            let mut ignored = false;
            self.end_cell(&mut ignored);
        }
        if !self.row.is_empty() {
            let mut ignored = false;
            self.end_row(&mut ignored);
        }
        self.rows
    }
}

fn emit_table(out: &mut Out, rows: &[Vec<String>]) {
    let mut truncated = false;
    let markdown = markdown_table(rows, &mut truncated);
    out.truncated |= truncated;
    if markdown.is_empty() {
        return;
    }
    out.blank();
    for line in markdown.lines() {
        out.line(line);
    }
    out.blank();
}

// --- PPTX ------------------------------------------------------------------

fn pptx_to_draft(bytes: &[u8], limits: &ReaderLimits) -> Result<Draft> {
    let (mut archive, index) = open_planned(bytes, limits)?;
    let mut slides: Vec<(u32, String)> = index
        .keys()
        .filter_map(|name| {
            let number = name
                .strip_prefix("ppt/slides/slide")?
                .strip_suffix(".xml")?
                .parse::<u32>()
                .ok()?;
            Some((number, name.clone()))
        })
        .collect();
    slides.sort_by_key(|(number, _)| *number);
    let mut truncated = slides.len() > limits.max_pages;
    slides.truncate(limits.max_pages);

    let mut out = Out::new(limits.max_output_bytes);
    let mut title = None;
    let max = limits.max_input_bytes as u64;
    for (position, (_, name)) in slides.iter().enumerate() {
        if out.truncated {
            truncated = true;
            break;
        }
        let xml = read_required(&mut archive, &index, name, max)?;
        let xml =
            String::from_utf8(xml).map_err(|_| corrupt(format!("`{name}` is not valid UTF-8")))?;
        let (slide_title, body) = parse_slide(&xml, limits.max_tags)?;
        if title.is_none() {
            title = slide_title.clone();
        }
        if position > 0 {
            out.blank();
            out.line("---");
            out.blank();
        }
        if let Some(slide_title) = slide_title {
            out.blank();
            out.line(&format!("## {slide_title}"));
            out.blank();
        }
        for paragraph in body {
            out.line(&paragraph);
        }
    }

    let truncated = truncated || out.truncated;
    Ok(Draft {
        title,
        markdown: out.finish(),
        links: Vec::new(),
        truncated,
    })
}

fn parse_slide(xml: &str, max_tags: usize) -> Result<(Option<String>, Vec<String>)> {
    struct Shape {
        is_title: bool,
        paragraphs: Vec<String>,
        current: String,
        in_text: bool,
    }
    let mut scanner = XmlScanner::new(xml, max_tags);
    let mut shape: Option<Shape> = None;
    let mut title = None;
    let mut body = Vec::new();

    while let Some(event) = scanner.next()? {
        match event {
            XmlEvent::Start(tag) => match tag.name.as_str() {
                "p:sp" => {
                    shape = Some(Shape {
                        is_title: false,
                        paragraphs: Vec::new(),
                        current: String::new(),
                        in_text: false,
                    });
                }
                "p:ph" => {
                    if let Some(active) = shape.as_mut() {
                        if tag
                            .attrs
                            .get("type")
                            .is_some_and(|value| matches!(value.as_str(), "title" | "ctrTitle"))
                        {
                            active.is_title = true;
                        }
                    }
                }
                "a:p" => {
                    if let Some(active) = shape.as_mut() {
                        active.current.clear();
                    }
                }
                "a:t" => {
                    if let Some(active) = shape.as_mut() {
                        active.in_text = true;
                    }
                }
                "a:br" => {
                    if let Some(active) = shape.as_mut() {
                        active.current.push(' ');
                    }
                }
                _ => {}
            },
            XmlEvent::End(name) => match name.as_str() {
                "a:t" => {
                    if let Some(active) = shape.as_mut() {
                        active.in_text = false;
                    }
                }
                "a:p" => {
                    if let Some(active) = shape.as_mut() {
                        let text = normalize_text(&active.current);
                        active.current.clear();
                        if !text.is_empty() {
                            active.paragraphs.push(text);
                        }
                    }
                }
                "p:sp" => {
                    if let Some(active) = shape.take() {
                        if active.is_title {
                            if title.is_none() {
                                title = active.paragraphs.into_iter().next();
                            }
                        } else {
                            body.extend(active.paragraphs);
                        }
                    }
                }
                _ => {}
            },
            XmlEvent::Text(text) => {
                if let Some(active) = shape.as_mut() {
                    if active.in_text {
                        active.current.push_str(&text);
                    }
                }
            }
        }
    }
    Ok((title, body))
}

// --- XLSX ------------------------------------------------------------------

fn xlsx_to_draft(bytes: &[u8], limits: &ReaderLimits) -> Result<Draft> {
    let (mut archive, index) = open_planned(bytes, limits)?;
    let max = limits.max_input_bytes as u64;

    let shared = match read_named(&mut archive, &index, "xl/sharedStrings.xml", max)? {
        Some(xml) => {
            let xml = String::from_utf8(xml)
                .map_err(|_| corrupt("xl/sharedStrings.xml is not valid UTF-8"))?;
            parse_shared_strings(&xml, limits.max_tags)?
        }
        None => Vec::new(),
    };

    let workbook = match read_named(&mut archive, &index, "xl/workbook.xml", max)? {
        Some(xml) => {
            String::from_utf8(xml).map_err(|_| corrupt("xl/workbook.xml is not valid UTF-8"))?
        }
        None => String::new(),
    };
    let relationships = match read_named(&mut archive, &index, "xl/_rels/workbook.xml.rels", max)? {
        Some(xml) => String::from_utf8(xml)
            .map_err(|_| corrupt("xl/_rels/workbook.xml.rels is not valid UTF-8"))?,
        None => String::new(),
    };
    let mut sheets = parse_workbook(&workbook, &relationships, limits.max_tags)?;

    if sheets.is_empty() {
        let mut fallback: Vec<(u32, String)> = index
            .keys()
            .filter_map(|name| {
                let number = name
                    .strip_prefix("xl/worksheets/sheet")?
                    .strip_suffix(".xml")?
                    .parse::<u32>()
                    .ok()?;
                Some((number, name.clone()))
            })
            .collect();
        fallback.sort_by_key(|(number, _)| *number);
        sheets = fallback
            .into_iter()
            .map(|(number, name)| (format!("Sheet {number}"), name))
            .collect();
    }

    let mut out = Out::new(limits.max_output_bytes);
    let mut truncated = false;
    for (sheet_name, path) in sheets {
        if out.truncated {
            truncated = true;
            break;
        }
        let Some(xml) = read_named(&mut archive, &index, &path, max)? else {
            continue;
        };
        let xml =
            String::from_utf8(xml).map_err(|_| corrupt(format!("`{path}` is not valid UTF-8")))?;
        let rows = parse_sheet(&xml, &shared, limits.max_tags, &mut truncated)?;
        out.blank();
        out.line(&format!("### {sheet_name}"));
        out.blank();
        let rows: Vec<Vec<String>> = rows.into_iter().map(|(_, cells)| cells).collect();
        emit_table(&mut out, &rows);
    }

    let truncated = truncated || out.truncated;
    Ok(Draft {
        title: None,
        markdown: out.finish(),
        links: Vec::new(),
        truncated,
    })
}

fn parse_shared_strings(xml: &str, max_tags: usize) -> Result<Vec<String>> {
    let mut scanner = XmlScanner::new(xml, max_tags);
    let mut strings = Vec::new();
    let mut current: Option<String> = None;
    let mut in_text = false;
    let mut phonetic = false;
    while let Some(event) = scanner.next()? {
        match event {
            XmlEvent::Start(tag) => match tag.name.as_str() {
                "si" => current = Some(String::new()),
                "rph" => phonetic = true,
                "t" => in_text = true,
                _ => {}
            },
            XmlEvent::End(name) => match name.as_str() {
                "t" => in_text = false,
                "rph" => phonetic = false,
                "si" => {
                    phonetic = false;
                    if let Some(text) = current.take() {
                        strings.push(text);
                    }
                }
                _ => {}
            },
            XmlEvent::Text(text) => {
                if in_text && !phonetic {
                    if let Some(active) = current.as_mut() {
                        active.push_str(&text);
                    }
                }
            }
        }
    }
    Ok(strings)
}

fn parse_workbook(
    workbook: &str,
    relationships: &str,
    max_tags: usize,
) -> Result<Vec<(String, String)>> {
    let mut rels = BTreeMap::new();
    let mut scanner = XmlScanner::new(relationships, max_tags);
    while let Some(event) = scanner.next()? {
        if let XmlEvent::Start(tag) = event {
            if tag.name == "relationship" {
                if let (Some(id), Some(target)) = (tag.attrs.get("id"), tag.attrs.get("target")) {
                    rels.insert(id.clone(), target.clone());
                }
            }
        }
    }

    let mut sheets = Vec::new();
    let mut scanner = XmlScanner::new(workbook, max_tags);
    while let Some(event) = scanner.next()? {
        if let XmlEvent::Start(tag) = event {
            if tag.name == "sheet" {
                let name = tag
                    .attrs
                    .get("name")
                    .cloned()
                    .unwrap_or_else(|| "Sheet".to_string());
                let target = tag
                    .attrs
                    .get("r:id")
                    .and_then(|id| rels.get(id))
                    .and_then(|target| resolve_zip_path("xl", target))
                    .unwrap_or_else(|| format!("xl/worksheets/sheet{}.xml", sheets.len() + 1));
                sheets.push((name, target));
            }
        }
    }
    Ok(sheets)
}

fn parse_sheet(
    xml: &str,
    shared: &[String],
    max_tags: usize,
    truncated: &mut bool,
) -> Result<Vec<(u32, Vec<String>)>> {
    let mut scanner = XmlScanner::new(xml, max_tags);
    let mut rows: Vec<(u32, Vec<String>)> = Vec::new();
    let mut row_number = 0u32;
    let mut current_row: Option<(u32, Vec<String>)> = None;
    let mut column = 0usize;
    let mut cell_type = String::new();
    let mut cell_value = String::new();
    let mut inline_value = String::new();
    let mut in_value = false;
    let mut in_inline_text = false;

    while let Some(event) = scanner.next()? {
        match event {
            XmlEvent::Start(tag) => match tag.name.as_str() {
                "row" => {
                    if rows.len() >= MAX_TABLE_ROWS {
                        *truncated = true;
                        break;
                    }
                    row_number += 1;
                    if let Some(value) = tag.attrs.get("r") {
                        if let Ok(parsed) = value.parse::<u32>() {
                            row_number = parsed;
                        }
                    }
                    column = 0;
                    current_row = Some((row_number, Vec::new()));
                }
                "c" => {
                    column = tag
                        .attrs
                        .get("r")
                        .and_then(|reference| column_index(reference))
                        .unwrap_or(column);
                    cell_type = tag.attrs.get("t").cloned().unwrap_or_default();
                    cell_value.clear();
                    inline_value.clear();
                }
                "v" => in_value = true,
                "t" => in_inline_text = true,
                _ => {}
            },
            XmlEvent::End(name) => match name.as_str() {
                "v" => in_value = false,
                "t" => in_inline_text = false,
                "c" => {
                    let value = if cell_type == "inlineStr" {
                        std::mem::take(&mut inline_value)
                    } else if cell_type == "s" {
                        cell_value
                            .trim()
                            .parse::<usize>()
                            .ok()
                            .and_then(|index| shared.get(index))
                            .cloned()
                            .unwrap_or_default()
                    } else if cell_type == "b" {
                        if cell_value.trim() == "1" {
                            "TRUE".to_string()
                        } else {
                            "FALSE".to_string()
                        }
                    } else {
                        std::mem::take(&mut cell_value)
                    };
                    if let Some((_, cells)) = current_row.as_mut() {
                        if column < MAX_TABLE_COLS {
                            if cells.len() <= column {
                                cells.resize(column + 1, String::new());
                            }
                            cells[column] = value;
                        } else {
                            *truncated = true;
                        }
                    }
                    column += 1;
                }
                "row" => {
                    if let Some(row) = current_row.take() {
                        rows.push(row);
                    }
                }
                _ => {}
            },
            XmlEvent::Text(text) => {
                if in_value {
                    cell_value.push_str(&text);
                }
                if in_inline_text {
                    inline_value.push_str(&text);
                }
            }
        }
    }
    if let Some(row) = current_row.take() {
        rows.push(row);
    }
    Ok(rows)
}

fn column_index(reference: &str) -> Option<usize> {
    let mut column = 0usize;
    let mut seen = false;
    for character in reference.chars() {
        if character.is_ascii_alphabetic() {
            seen = true;
            column = column * 26 + (character.to_ascii_uppercase() as usize - 'A' as usize + 1);
            if column > MAX_TABLE_COLS * 26 {
                return None;
            }
        } else {
            break;
        }
    }
    if seen {
        Some(column.saturating_sub(1))
    } else {
        None
    }
}

// --- EPUB ------------------------------------------------------------------

fn epub_to_draft(bytes: &[u8], limits: &ReaderLimits) -> Result<Draft> {
    let (mut archive, index) = open_planned(bytes, limits)?;
    let max = limits.max_input_bytes as u64;
    let container = read_required(&mut archive, &index, "META-INF/container.xml", max)?;
    let container = String::from_utf8(container)
        .map_err(|_| corrupt("META-INF/container.xml is not valid UTF-8"))?;
    let opf_path = xml_first_attr(&container, "rootfile", "full-path", limits.max_tags)?
        .ok_or_else(|| corrupt("EPUB container.xml has no rootfile full-path"))?;
    let opf = read_required(&mut archive, &index, &opf_path, max)?;
    let opf = String::from_utf8(opf).map_err(|_| corrupt("EPUB package document is not UTF-8"))?;

    let title = xml_capture_text(&opf, "dc:title", limits.max_tags)?;
    let manifest = parse_manifest(&opf, limits.max_tags)?;
    let mut spine = parse_spine(&opf, limits.max_tags)?;
    if spine.is_empty() {
        spine = index
            .keys()
            .filter(|name| name.ends_with(".xhtml") || name.ends_with(".html"))
            .cloned()
            .collect();
    }
    let base = opf_path.rsplit_once('/').map(|(dir, _)| dir).unwrap_or("");

    let mut out = Out::new(limits.max_output_bytes);
    let mut links = Vec::new();
    let mut seen = BTreeSet::new();
    let mut truncated = spine.len() > limits.max_pages;
    let mut first_title = None;

    for (position, idref) in spine.iter().take(limits.max_pages).enumerate() {
        if out.truncated {
            truncated = true;
            break;
        }
        let Some(href) = manifest.get(idref) else {
            continue;
        };
        let Some(path) = resolve_zip_path(base, href) else {
            continue;
        };
        let Some(chapter) = read_named(&mut archive, &index, &path, max)? else {
            continue;
        };
        let chapter = String::from_utf8(chapter)
            .map_err(|_| corrupt(format!("EPUB chapter `{path}` is not valid UTF-8")))?;
        let remaining = limits.max_output_bytes.saturating_sub(out.buf.len());
        if remaining == 0 {
            truncated = true;
            break;
        }
        let chapter_limits = ReaderLimits {
            max_output_bytes: remaining,
            ..*limits
        };
        let draft = html_to_draft(&chapter, &chapter_limits)?;
        truncated |= draft.truncated;
        if first_title.is_none() {
            first_title = draft.title;
        }
        if position > 0 {
            out.blank();
        }
        out.append_markdown(&draft.markdown);
        for link in draft.links {
            if links.len() >= MAX_LINKS {
                break;
            }
            if seen.insert(link.clone()) {
                links.push(link);
            }
        }
    }

    let truncated = truncated || out.truncated;
    Ok(Draft {
        title: title.or(first_title),
        markdown: out.finish(),
        links,
        truncated,
    })
}

fn parse_manifest(opf: &str, max_tags: usize) -> Result<BTreeMap<String, String>> {
    let mut manifest = BTreeMap::new();
    let mut scanner = XmlScanner::new(opf, max_tags);
    while let Some(event) = scanner.next()? {
        if let XmlEvent::Start(tag) = event {
            if tag.name == "item" {
                if let (Some(id), Some(href)) = (tag.attrs.get("id"), tag.attrs.get("href")) {
                    manifest.insert(id.clone(), href.clone());
                }
            }
        }
    }
    Ok(manifest)
}

fn parse_spine(opf: &str, max_tags: usize) -> Result<Vec<String>> {
    let mut spine = Vec::new();
    let mut scanner = XmlScanner::new(opf, max_tags);
    while let Some(event) = scanner.next()? {
        if let XmlEvent::Start(tag) = event {
            if tag.name == "itemref" {
                if let Some(idref) = tag.attrs.get("idref") {
                    spine.push(idref.clone());
                }
            }
        }
    }
    Ok(spine)
}

// ---------------------------------------------------------------------------
// PDF
// ---------------------------------------------------------------------------

fn pdf_to_draft(bytes: &[u8], limits: &ReaderLimits) -> Result<Draft> {
    let document = lopdf::Document::load_mem(bytes).map_err(pdf_error)?;
    if document.was_encrypted() || document.is_encrypted() {
        return Err(unsupported(
            "PDF is encrypted; decrypt it before reading (password-protected PDFs are not \
             supported)",
        ));
    }
    let pages = document.get_pages();
    if pages.is_empty() {
        return Err(corrupt("PDF has no pages"));
    }
    let mut numbers: Vec<u32> = pages.keys().copied().collect();
    let truncated = numbers.len() > limits.max_pages;
    numbers.truncate(limits.max_pages);

    let mut text = String::new();
    for (position, number) in numbers.iter().enumerate() {
        if position > 0 {
            text.push_str("\n\n---\n\n");
        }
        let page = document
            .extract_text_with_limit(&[*number], limits.max_input_bytes)
            .map_err(pdf_error)?;
        text.push_str(page.trim_matches(|character| character == '\n' || character == '\r'));
    }

    let mut out = Out::new(limits.max_output_bytes);
    if !text.trim().is_empty() {
        out.ensure_block();
        for line in text.split('\n') {
            out.start_line();
            out.push_str(line.trim_end_matches('\r'));
            out.newline();
        }
    }
    let title = text
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && *line != "---")
        .map(|line| clip_chars(line, MAX_TITLE_CHARS));

    let truncated = truncated || out.truncated;
    Ok(Draft {
        title,
        markdown: out.finish(),
        links: Vec::new(),
        truncated,
    })
}

fn pdf_error(error: lopdf::Error) -> ZeroError {
    let message = error.to_string();
    let lower = message.to_ascii_lowercase();
    if lower.contains("encrypt") || lower.contains("password") {
        unsupported(format!("encrypted PDF: {message}"))
    } else if lower.contains("limit") || lower.contains("memory") {
        limit(format!("PDF extraction exceeded a bound: {message}"))
    } else {
        corrupt(format!("PDF could not be parsed or read: {message}"))
    }
}

// ---------------------------------------------------------------------------
// Shared path helpers
// ---------------------------------------------------------------------------

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let high = (bytes[index + 1] as char).to_digit(16);
            let low = (bytes[index + 2] as char).to_digit(16);
            if let (Some(high), Some(low)) = (high, low) {
                decoded.push((high * 16 + low) as u8);
                index += 3;
                continue;
            }
        }
        decoded.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&decoded).into_owned()
}

fn resolve_zip_path(base: &str, target: &str) -> Option<String> {
    let target = target.split(['#', '?']).next().unwrap_or("");
    if target.is_empty() || target.contains("://") {
        return None;
    }
    let decoded = percent_decode(target);
    let combined = if let Some(absolute) = decoded.strip_prefix('/') {
        absolute.to_string()
    } else if base.is_empty() {
        decoded
    } else {
        format!("{base}/{decoded}")
    };
    let mut parts: Vec<&str> = Vec::new();
    for part in combined.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            value => parts.push(value),
        }
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join("/"))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    use zip::write::SimpleFileOptions;
    use zip::{CompressionMethod, ZipWriter};

    fn limits() -> ReaderLimits {
        ReaderLimits::default()
    }

    fn code(error: &ZeroError) -> ErrorCode {
        error.code()
    }

    fn zip_bytes(files: &[(&str, &str)]) -> Vec<u8> {
        let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
        for (name, content) in files {
            zip.start_file(name, SimpleFileOptions::default())
                .expect("start file");
            zip.write_all(content.as_bytes()).expect("write entry");
        }
        zip.finish().expect("finish zip").into_inner()
    }

    fn docx_fixture() -> Vec<u8> {
        let document = r#"<?xml version="1.0" encoding="UTF-8"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:body>
<w:p><w:pPr><w:pStyle w:val="Heading1"/></w:pPr><w:r><w:t>Guide Title</w:t></w:r></w:p>
<w:p><w:r><w:t>Intro paragraph.</w:t></w:r></w:p>
<w:p><w:pPr><w:numPr><w:ilvl w:val="0"/></w:numPr></w:pPr><w:r><w:t>First item</w:t></w:r></w:p>
<w:tbl>
<w:tr><w:tc><w:p><w:r><w:t>Name</w:t></w:r></w:p></w:tc><w:tc><w:p><w:r><w:t>Value</w:t></w:r></w:p></w:tc></w:tr>
<w:tr><w:tc><w:p><w:r><w:t>alpha</w:t></w:r></w:p></w:tc><w:tc><w:p><w:r><w:t>1</w:t></w:r></w:p></w:tc></w:tr>
</w:tbl>
</w:body></w:document>"#;
        zip_bytes(&[
            ("[Content_Types].xml", "<Types/>"),
            (
                "docProps/core.xml",
                r#"<cp:coreProperties xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:title>Guide Title</dc:title></cp:coreProperties>"#,
            ),
            ("word/document.xml", document),
        ])
    }

    fn xlsx_fixture() -> Vec<u8> {
        let workbook = r#"<workbook xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="People" sheetId="1" r:id="rId1"/><sheet name="Totals" sheetId="2" r:id="rId2"/></sheets></workbook>"#;
        let rels = r#"<Relationships><Relationship Id="rId1" Target="worksheets/sheet1.xml"/><Relationship Id="rId2" Target="worksheets/sheet2.xml"/></Relationships>"#;
        let shared = r#"<sst><si><t>Name</t></si><si><t>Alice</t></si><si><t>Score</t></si></sst>"#;
        let sheet1 = r#"<worksheet><sheetData><row r="1"><c r="A1" t="s"><v>0</v></c><c r="B1" t="s"><v>2</v></c></row><row r="2"><c r="A2" t="s"><v>1</v></c><c r="B2"><v>42</v></c></row></sheetData></worksheet>"#;
        let sheet2 = r#"<worksheet><sheetData><row r="1"><c r="A1" t="inlineStr"><is><t>Total</t></is></c></row></sheetData></worksheet>"#;
        zip_bytes(&[
            ("xl/workbook.xml", workbook),
            ("xl/_rels/workbook.xml.rels", rels),
            ("xl/sharedStrings.xml", shared),
            ("xl/worksheets/sheet1.xml", sheet1),
            ("xl/worksheets/sheet2.xml", sheet2),
        ])
    }

    fn slide(title: &str, body: &str) -> String {
        format!(
            r#"<p:sld xmlns:p="p" xmlns:a="a"><p:cSld><p:spTree>
<p:sp><p:nvSpPr><p:nvPr><p:ph type="title"/></p:nvPr></p:nvSpPr><p:txBody><a:p><a:r><a:t>{title}</a:t></a:r></a:p></p:txBody></p:sp>
<p:sp><p:nvSpPr><p:nvPr/></p:nvSpPr><p:txBody><a:p><a:r><a:t>{body}</a:t></a:r></a:p></p:txBody></p:sp>
</p:spTree></p:cSld></p:sld>"#
        )
    }

    fn pptx_fixture() -> Vec<u8> {
        let tenth = slide("Tenth Slide", "Beta body");
        let second = slide("First Slide", "Alpha body");
        zip_bytes(&[
            ("[Content_Types].xml", "<Types/>"),
            ("ppt/presentation.xml", "<p:presentation/>"),
            ("ppt/slides/slide10.xml", tenth.as_str()),
            ("ppt/slides/slide2.xml", second.as_str()),
        ])
    }

    fn epub_fixture() -> Vec<u8> {
        let opf = r#"<package xmlns:dc="http://purl.org/dc/elements/1.1/"><metadata><dc:title>EPUB Fixture</dc:title></metadata><manifest><item id="c1" href="chap1.xhtml" media-type="application/xhtml+xml"/><item id="c2" href="chap2.xhtml" media-type="application/xhtml+xml"/></manifest><spine><itemref idref="c2"/><itemref idref="c1"/></spine></package>"#;
        zip_bytes(&[
            ("mimetype", "application/epub+zip"),
            (
                "META-INF/container.xml",
                r#"<container><rootfiles><rootfile full-path="OEBPS/content.opf" media-type="application/oebps-package+xml"/></rootfiles></container>"#,
            ),
            ("OEBPS/content.opf", opf),
            (
                "OEBPS/chap1.xhtml",
                "<html><head><title>One</title></head><body><h1>Chapter One</h1><p>First chapter.</p></body></html>",
            ),
            (
                "OEBPS/chap2.xhtml",
                "<html><head><title>Two</title></head><body><h1>Chapter Two</h1><p>Second chapter.</p></body></html>",
            ),
        ])
    }

    fn escape_pdf(text: &str) -> String {
        text.replace('\\', "\\\\")
            .replace('(', "\\(")
            .replace(')', "\\)")
    }

    fn pdf_fixture(pages: &[&str]) -> Vec<u8> {
        let page_count = pages.len();
        let font_id = 3 + page_count * 2;
        let mut objects: Vec<String> = Vec::new();
        objects.push("<< /Type /Catalog /Pages 2 0 R >>".to_string());
        let kids: Vec<String> = (0..page_count)
            .map(|index| format!("{} 0 R", 3 + index * 2))
            .collect();
        objects.push(format!(
            "<< /Type /Pages /Kids [{}] /Count {page_count} >>",
            kids.join(" ")
        ));
        for (index, text) in pages.iter().enumerate() {
            let content_id = 4 + index * 2;
            objects.push(format!(
                "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents {content_id} 0 R /Resources << /Font << /F1 {font_id} 0 R >> >> >>"
            ));
            let stream = format!("BT /F1 18 Tf 72 720 Td ({}) Tj ET", escape_pdf(text));
            objects.push(format!(
                "<< /Length {} >>\nstream\n{}\nendstream",
                stream.len(),
                stream
            ));
        }
        objects.push("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_string());

        let mut output = String::from("%PDF-1.4\n");
        let mut offsets = Vec::new();
        for (index, object) in objects.iter().enumerate() {
            offsets.push(output.len());
            output.push_str(&format!("{} 0 obj\n{}\nendobj\n", index + 1, object));
        }
        let xref_start = output.len();
        output.push_str(&format!(
            "xref\n0 {}\n0000000000 65535 f \n",
            objects.len() + 1
        ));
        for offset in offsets {
            output.push_str(&format!("{offset:010} 00000 n \n"));
        }
        output.push_str(&format!(
            "trailer\n<< /Size {} /Root 1 0 R /ID [<0123456789abcdef0123456789abcdef><0123456789abcdef0123456789abcdef>] >>\nstartxref\n{xref_start}\n%%EOF\n",
            objects.len() + 1
        ));
        output.into_bytes()
    }

    fn encrypted_pdf_fixture() -> Vec<u8> {
        let plain = pdf_fixture(&["Secret"]);
        let mut document = lopdf::Document::load_mem(&plain).expect("load plain PDF");
        {
            let version = lopdf::encryption::EncryptionVersion::V1 {
                document: &document,
                owner_password: "owner",
                user_password: "",
                permissions: lopdf::encryption::Permissions::all(),
            };
            let state = lopdf::encryption::EncryptionState::try_from(version)
                .expect("build encryption state");
            document.encrypt(&state).expect("encrypt PDF");
        }
        let mut output = Vec::new();
        document.save_to(&mut output).expect("save encrypted PDF");
        output
    }

    #[test]
    fn format_detection_uses_magic_then_hint() {
        assert_eq!(
            detect_format(b"%PDF-1.7\n", Some("txt")),
            DocumentFormat::Pdf
        );
        assert_eq!(
            detect_format(b"<!DOCTYPE html><html></html>", None),
            DocumentFormat::Html
        );
        assert_eq!(
            detect_format(b"<html><body></body></html>", None),
            DocumentFormat::Html
        );
        assert_eq!(
            detect_format(b"# Title\n", Some("md")),
            DocumentFormat::Markdown
        );
        assert_eq!(
            detect_format(b"a,b\n1,2\n", Some("data.csv")),
            DocumentFormat::Csv
        );
        assert_eq!(detect_format(b"{\"a\":1}", None), DocumentFormat::Json);
        assert_eq!(detect_format(b"plain words", None), DocumentFormat::Text);
        assert_eq!(detect_format(b"\x00\xff", None), DocumentFormat::Unknown);
        assert_eq!(
            detect_format(b"body", Some("text/html; charset=utf-8")),
            DocumentFormat::Html
        );
        assert_eq!(detect_format(&docx_fixture(), None), DocumentFormat::Docx);
        assert_eq!(detect_format(&xlsx_fixture(), None), DocumentFormat::Xlsx);
        assert_eq!(detect_format(&pptx_fixture(), None), DocumentFormat::Pptx);
        assert_eq!(detect_format(&epub_fixture(), None), DocumentFormat::Epub);
    }

    #[test]
    fn html_reader_prefers_article_and_drops_navigation_and_scripts() {
        let html = r#"<!doctype html><html><head><title>Reader Fixture</title>
<script>alert("head")</script></head><body>
<nav><a href="/nav">Navigation</a></nav>
<header>Site header</header>
<article>
<h1>Main Heading</h1>
<p>First paragraph with <a href="https://example.test/source">a source</a>.</p>
<ul><li>One</li><li>Two</li></ul>
<pre><code class="language-rust">fn main() { println!("hi"); }</code></pre>
<blockquote>Quoted words.</blockquote>
<img alt="Diagram" src="https://example.test/diagram.png">
<table><tr><th>Name</th><th>Value</th></tr><tr><td>alpha</td><td>1|2</td></tr></table>
</article>
<footer>Footer text</footer>
<script>alert("body")</script>
</body></html>"#;
        let document = read(html.as_bytes(), DocumentFormat::Html, &limits()).expect("read HTML");
        assert_eq!(document.title.as_deref(), Some("Reader Fixture"));
        assert!(document.markdown.contains("# Main Heading"));
        assert!(document.markdown.contains("First paragraph with"));
        assert!(document
            .markdown
            .contains("[a source](https://example.test/source)"));
        assert!(document.markdown.contains("- One"));
        assert!(document.markdown.contains("> Quoted words."));
        assert!(document
            .markdown
            .contains("![Diagram](https://example.test/diagram.png)"));
        assert!(document.markdown.contains("| Name | Value |"));
        assert!(document.markdown.contains("1\\|2"));
        assert!(document.markdown.contains("```rust"));
        assert!(!document.markdown.contains("Navigation"));
        assert!(!document.markdown.contains("Site header"));
        assert!(!document.markdown.contains("Footer text"));
        assert!(!document.markdown.contains("alert"));
        assert_eq!(document.links, vec!["https://example.test/source"]);
    }

    #[test]
    fn html_reader_falls_back_to_body_and_h1_title() {
        let html = "<html><head></head><body><h1>Body Title</h1><p>Body text.</p></body></html>";
        let document = read(html.as_bytes(), DocumentFormat::Html, &limits()).expect("read HTML");
        assert_eq!(document.title.as_deref(), Some("Body Title"));
        assert!(document.markdown.contains("Body text."));
    }

    #[test]
    fn html_pre_entities_are_decoded_and_fenced() {
        let html = "<html><body><pre><code class=\"language-c\">a &lt; b &amp;&amp; c</code></pre></body></html>";
        let document = read(html.as_bytes(), DocumentFormat::Html, &limits()).expect("read HTML");
        assert!(document.markdown.contains("```c"));
        assert!(document.markdown.contains("a < b && c"));
    }

    #[test]
    fn markdown_passes_through_with_heading_title() {
        let bytes = b"# Notes\n\nBody text.\n";
        let document = read(bytes, DocumentFormat::Markdown, &limits()).expect("read Markdown");
        assert_eq!(document.title.as_deref(), Some("Notes"));
        assert_eq!(document.markdown, "# Notes\n\nBody text.\n");
    }

    #[test]
    fn code_is_fenced() {
        let bytes = b"fn main() {}\n";
        let document = read(bytes, DocumentFormat::Code, &limits()).expect("read code");
        assert!(document.markdown.starts_with("```\nfn main() {}"));
        assert!(document.markdown.trim_end().ends_with("```"));
        assert_eq!(document.title, None);
    }

    #[test]
    fn csv_becomes_table_with_escaped_pipes() {
        let bytes = b"Name,Note\nAlice,\"a|b\"\nBob,\"line1\nline2\"\n";
        let document = read(bytes, DocumentFormat::Csv, &limits()).expect("read CSV");
        assert!(document.markdown.contains("| Name | Note |"));
        assert!(document.markdown.contains("a\\|b"));
        assert!(document.markdown.contains("line1<br>line2"));
        assert!(!document.truncated);

        let tsv =
            read(b"Name\tNote\nAlice\tok\n", DocumentFormat::Csv, &limits()).expect("read TSV");
        assert!(tsv.markdown.contains("| Name | Note |"));
        assert!(tsv.markdown.contains("| Alice | ok |"));
    }

    #[test]
    fn csv_row_cap_sets_truncated() {
        let mut csv = String::from("id,value\n");
        for row in 0..(MAX_TABLE_ROWS + 20) {
            csv.push_str(&format!("{row},x\n"));
        }
        let document = read(csv.as_bytes(), DocumentFormat::Csv, &limits()).expect("read CSV");
        assert!(document.truncated);
        assert!(document.markdown.lines().count() <= MAX_TABLE_ROWS + 1);
    }

    #[test]
    fn json_is_pretty_fenced() {
        let bytes = b"{\"b\":1,\"a\":[true,null]}";
        let document = read(bytes, DocumentFormat::Json, &limits()).expect("read JSON");
        assert!(document.markdown.starts_with("```json"));
        assert!(document.markdown.contains("\"a\": ["));
        assert!(document.markdown.contains("\"b\": 1"));
    }

    #[test]
    fn binary_input_is_refused() {
        let error = read(b"\x00\xff\xfe", DocumentFormat::Unknown, &limits())
            .expect_err("binary must be refused");
        assert_eq!(code(&error), ErrorCode::Unsupported);

        let error = read(b"\xff\xfe", DocumentFormat::Text, &limits())
            .expect_err("invalid UTF-8 text must be refused");
        assert_eq!(code(&error), ErrorCode::InvalidInput);
    }

    #[test]
    fn input_over_limit_is_refused_before_parsing() {
        let small = ReaderLimits {
            max_input_bytes: 8,
            ..limits()
        };
        let error =
            read(b"0123456789", DocumentFormat::Text, &small).expect_err("input must be bounded");
        assert_eq!(code(&error), ErrorCode::LimitExceeded);
    }

    #[test]
    fn output_cap_sets_truncated_and_marker() {
        let text = "word ".repeat(200);
        let small = ReaderLimits {
            max_output_bytes: 80,
            ..limits()
        };
        let document = read(text.as_bytes(), DocumentFormat::Text, &small).expect("read text");
        assert!(document.truncated);
        assert!(document.markdown.len() <= 80);
        assert!(document.markdown.ends_with("truncated]"));
    }

    #[test]
    fn docx_paragraphs_headings_lists_and_tables() {
        let document = read(&docx_fixture(), DocumentFormat::Docx, &limits()).expect("read DOCX");
        assert_eq!(document.title.as_deref(), Some("Guide Title"));
        assert!(document.markdown.contains("# Guide Title"));
        assert!(document.markdown.contains("Intro paragraph."));
        assert!(document.markdown.contains("- First item"));
        assert!(document.markdown.contains("| Name | Value |"));
        assert!(document.markdown.contains("| alpha | 1 |"));
        assert!(!document.truncated);
    }

    #[test]
    fn pptx_slides_sort_numerically_and_separate_with_rule() {
        let document = read(&pptx_fixture(), DocumentFormat::Pptx, &limits()).expect("read PPTX");
        assert_eq!(document.title.as_deref(), Some("First Slide"));
        let first = document.markdown.find("First Slide").expect("first slide");
        let tenth = document.markdown.find("Tenth Slide").expect("tenth slide");
        assert!(first < tenth, "slide2 must precede slide10");
        assert!(document.markdown.contains("## First Slide"));
        assert!(document.markdown.contains("Alpha body"));
        assert!(document.markdown.contains("---"));
    }

    #[test]
    fn xlsx_sheet_order_shared_strings_and_inline_strings() {
        let document = read(&xlsx_fixture(), DocumentFormat::Xlsx, &limits()).expect("read XLSX");
        let people = document.markdown.find("### People").expect("People sheet");
        let totals = document.markdown.find("### Totals").expect("Totals sheet");
        assert!(people < totals, "workbook order must be preserved");
        assert!(document.markdown.contains("| Name | Score |"));
        assert!(document.markdown.contains("| Alice | 42 |"));
        assert!(document.markdown.contains("| Total |"));
    }

    #[test]
    fn epub_spine_order_is_followed() {
        let document = read(&epub_fixture(), DocumentFormat::Epub, &limits()).expect("read EPUB");
        assert_eq!(document.title.as_deref(), Some("EPUB Fixture"));
        let second = document.markdown.find("Chapter Two").expect("chapter two");
        let first = document.markdown.find("Chapter One").expect("chapter one");
        assert!(second < first, "spine c2 then c1 must be preserved");
    }

    #[test]
    fn pdf_text_is_extracted_page_by_page() {
        let pdf = pdf_fixture(&["Page One Alpha", "Page Two Beta"]);
        let document = read(&pdf, DocumentFormat::Pdf, &limits()).expect("read PDF");
        assert!(document.markdown.contains("Page One Alpha"));
        assert!(document.markdown.contains("Page Two Beta"));
        assert!(document.markdown.contains("---"));
        assert_eq!(document.title.as_deref(), Some("Page One Alpha"));
    }

    #[test]
    fn pdf_page_cap_sets_truncated() {
        let pdf = pdf_fixture(&["Page One Alpha", "Page Two Beta"]);
        let small = ReaderLimits {
            max_pages: 1,
            ..limits()
        };
        let document = read(&pdf, DocumentFormat::Pdf, &small).expect("read PDF");
        assert!(document.truncated);
        assert!(document.markdown.contains("Page One Alpha"));
        assert!(!document.markdown.contains("Page Two Beta"));
    }

    #[test]
    fn encrypted_pdf_is_a_typed_unsupported_error() {
        let error = read(&encrypted_pdf_fixture(), DocumentFormat::Pdf, &limits())
            .expect_err("encrypted PDF must be refused");
        assert_eq!(code(&error), ErrorCode::Unsupported);
    }

    #[test]
    fn zip_slip_entry_is_refused_before_reading() {
        let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
        let options = SimpleFileOptions::default();
        zip.start_file("word/document.xml", options).expect("start");
        zip.write_all(b"<w:document/>").expect("write");
        zip.start_file("../evil.xml", options)
            .expect("start hostile");
        zip.write_all(b"evil").expect("write hostile");
        let bytes = zip.finish().expect("finish").into_inner();
        let error =
            read(&bytes, DocumentFormat::Docx, &limits()).expect_err("zip-slip must be refused");
        assert_eq!(code(&error), ErrorCode::PolicyDenied);
    }

    #[test]
    fn read_file_detects_extension_and_content() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("notes.md");
        std::fs::write(&path, "# Disk Title\n\nBody.").expect("write fixture");
        let document = read_file(&path, &limits()).expect("read file");
        assert_eq!(document.format, DocumentFormat::Markdown);
        assert_eq!(document.title.as_deref(), Some("Disk Title"));
        assert_eq!(document.bytes_in, 19);
    }

    #[test]
    fn table_columns_are_capped() {
        let mut csv = String::new();
        for column in 0..(MAX_TABLE_COLS + 10) {
            if column > 0 {
                csv.push(',');
            }
            csv.push_str(&format!("c{column}"));
        }
        csv.push('\n');
        let document = read(csv.as_bytes(), DocumentFormat::Csv, &limits()).expect("read CSV");
        assert!(document.truncated);
        assert_eq!(
            document.markdown.lines().next().map(str::trim),
            Some(format!(
                "| {} |",
                (0..MAX_TABLE_COLS)
                    .map(|column| format!("c{column}"))
                    .collect::<Vec<_>>()
                    .join(" | ")
            ))
            .as_deref()
        );
    }

    #[test]
    fn compressed_entry_bomb_is_refused() {
        // A deflated entry whose declared size is far beyond the input cap.
        let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
        zip.start_file("word/document.xml", options).expect("start");
        let payload = vec![b'a'; 200_000];
        zip.write_all(&payload).expect("write");
        zip.start_file("[Content_Types].xml", SimpleFileOptions::default())
            .expect("start");
        zip.write_all(b"<Types/>").expect("write");
        let bytes = zip.finish().expect("finish").into_inner();
        let small = ReaderLimits {
            max_input_bytes: 4_096,
            ..limits()
        };
        let error = read(&bytes, DocumentFormat::Docx, &small)
            .expect_err("compressed bomb must be refused");
        assert!(matches!(
            code(&error),
            ErrorCode::LimitExceeded | ErrorCode::Unsupported
        ));
    }
}
