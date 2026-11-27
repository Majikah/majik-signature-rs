//! Port of `core/mjksmap.ts` — `MajikSignatureMap` and the `.mjksmap` binary container.
//!
//! One manifest mapping every file in a batch/zip to its detached envelope. Immutable:
//! `with_*` methods return a new map.

use std::collections::HashMap;
use std::io::{self, Write};

use serde_json::Value;

use crate::core::constants::*;
use crate::core::envelope::MajikSignatureEnvelope;
use crate::core::errors::{MajikSignatureError, MajikSignatureResult};
use crate::core::hash::{bytes_to_base64, hash_content};
use crate::core::time::now_iso;
use crate::core::types::*;
use crate::core::validator::MajikSignatureValidator;

type R<T> = MajikSignatureResult<T>;

/// Normalise a path: `\` → `/`, trim, drop a drive letter, drop leading slashes.
pub fn normalize_path(path: &str) -> String {
    let mut p = path.replace('\\', "/").trim().to_string();
    let b = p.as_bytes();
    if b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':' {
        p.drain(..2);
    }
    p.trim_start_matches('/').to_string()
}

fn validate_and_normalize_path(path: &str, field: &str) -> R<String> {
    let normalized = normalize_path(path);
    let has_control = path.chars().any(|ch| {
        let code = ch as u32;
        code <= 0x1f
            || code == 0x7f
            || (0x202a..=0x202e).contains(&code)
            || (0x2066..=0x2069).contains(&code)
    });
    if path.trim().is_empty() || path.encode_utf16().count() > MAX_MJKSMAP_PATH_CHARS || has_control {
        return Err(MajikSignatureError::validation(
            format!("{field} exceeds the supported path length or contains unsafe control characters"),
            Some(field),
        ));
    }
    if normalized.is_empty() || normalized.split('/').any(|part| part == "..") {
        return Err(MajikSignatureError::validation(
            format!("{field} must resolve to a non-traversing relative path"),
            Some(field),
        ));
    }
    Ok(normalized)
}

/// A Vec-backed writer that never allocates beyond the manifest payload ceiling.
struct BoundedWriter {
    bytes: Vec<u8>,
    limit: usize,
    exceeded: bool,
}

impl BoundedWriter {
    fn new(limit: usize) -> Self {
        Self { bytes: Vec::new(), limit, exceeded: false }
    }
}

impl Write for BoundedWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let next = self.bytes.len().checked_add(buffer.len())
            .ok_or_else(|| io::Error::other("serialized payload length overflow"))?;
        if next > self.limit {
            self.exceeded = true;
            return Err(io::Error::new(io::ErrorKind::InvalidData, "manifest payload exceeds limit"));
        }
        self.bytes.try_reserve(buffer.len())
            .map_err(|error| io::Error::other(format!("manifest allocation failed: {error}")))?;
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn serialize_map_payload(data: &MjksMapJSON) -> R<Vec<u8>> {
    let mut writer = BoundedWriter::new(MAX_MJKSMAP_BYTES);
    if let Err(error) = serde_json::to_writer(&mut writer, data) {
        let message = if writer.exceeded {
            format!("MJKSMAP payload exceeds the maximum supported size of {MAX_MJKSMAP_BYTES} bytes")
        } else {
            format!("Failed to serialize MJKSMAP payload: {error}")
        };
        return Err(MajikSignatureError::serialization_with_cause(message, error));
    }
    Ok(writer.bytes)
}

#[derive(Debug, Clone, PartialEq)]
pub struct MajikSignatureMap {
    version: u8,
    created_at: String,
    entries: Vec<MjksMapEntry>,
    by_path: HashMap<String, usize>,
    by_hash: HashMap<String, Vec<usize>>,
}

impl MajikSignatureMap {
    fn new(data: MjksMapJSON) -> Self {
        let entries: Vec<MjksMapEntry> = data
            .entries
            .into_iter()
            .map(|mut e| {
                e.path = normalize_path(&e.path);
                e
            })
            .collect();
        let mut by_path = HashMap::new();
        let mut by_hash: HashMap<String, Vec<usize>> = HashMap::new();
        for (i, e) in entries.iter().enumerate() {
            by_path.insert(e.path.clone(), i);
            by_hash.entry(e.content_hash.clone()).or_default().push(i);
        }
        Self { version: data.version, created_at: data.created_at, entries, by_path, by_hash }
    }

    // ── Getters ──────────────────────────────────────────────────────────────

    pub fn version(&self) -> u8 {
        self.version
    }
    pub fn created_at(&self) -> &str {
        &self.created_at
    }
    pub fn entries(&self) -> &[MjksMapEntry] {
        &self.entries
    }
    pub fn size(&self) -> usize {
        self.entries.len()
    }

    // ── Lookup ───────────────────────────────────────────────────────────────

    pub fn get_entry(&self, path: &str) -> Option<&MjksMapEntry> {
        self.by_path.get(&normalize_path(path)).map(|&i| &self.entries[i])
    }

    pub fn has_entry(&self, path: &str) -> bool {
        self.by_path.contains_key(&normalize_path(path))
    }

    /// Find an entry by path and report whether the file's hash matches.
    pub fn find_entry(&self, path: &str, file: &[u8]) -> MjksMapFindResult {
        match self.get_entry(path) {
            None => MjksMapFindResult { found: false, entry: None, hash_matches: None },
            Some(entry) => {
                let recomputed = bytes_to_base64(&hash_content(file));
                MjksMapFindResult {
                    found: true,
                    hash_matches: Some(recomputed == entry.content_hash),
                    entry: Some(entry.clone()),
                }
            }
        }
    }

    /// Entries whose recorded hash equals the file's hash (detects relocated files).
    pub fn find_entries_by_hash(&self, file: &[u8]) -> Vec<MjksMapEntry> {
        let hash = bytes_to_base64(&hash_content(file));
        self.by_hash
            .get(&hash)
            .map(|idx| idx.iter().map(|&i| self.entries[i].clone()).collect())
            .unwrap_or_default()
    }

    pub fn resolve_entry(&self, path: &str, file: &[u8]) -> MjksMapResolveResult {
        let direct = self.find_entry(path, file);
        if direct.found {
            return MjksMapResolveResult {
                status: if direct.hash_matches == Some(true) {
                    MjksMapResolveStatus::PathMatch
                } else {
                    MjksMapResolveStatus::PathTampered
                },
                entry: direct.entry,
                original_path: None,
            };
        }
        let by_hash = self.find_entries_by_hash(file);
        if let Some(first) = by_hash.into_iter().next() {
            return MjksMapResolveResult {
                status: MjksMapResolveStatus::Relocated,
                original_path: Some(first.path.clone()),
                entry: Some(first),
            };
        }
        MjksMapResolveResult { status: MjksMapResolveStatus::NotFound, entry: None, original_path: None }
    }

    pub fn get_envelope(&self, path: &str) -> R<Option<MajikSignatureEnvelope>> {
        match self.get_entry(path) {
            Some(e) => Ok(Some(MajikSignatureEnvelope::from_json(&e.envelope)?)),
            None => Ok(None),
        }
    }

    pub fn get_all_envelopes(&self) -> R<Vec<(String, MajikSignatureEnvelope)>> {
        self.entries
            .iter()
            .map(|e| Ok((e.path.clone(), MajikSignatureEnvelope::from_json(&e.envelope)?)))
            .collect()
    }

    // ── Immutable builders ───────────────────────────────────────────────────

    /// Add an entry, replacing any existing entry for the same (normalised) path.
    pub fn with_entry(&self, mut entry: MjksMapEntry) -> R<MajikSignatureMap> {
        entry.path = validate_and_normalize_path(&entry.path, "path")?;
        MajikSignatureValidator::validate_sha256_digest(&entry.content_hash, "contentHash")?;
        MajikSignatureValidator::validate_content_type(entry.mime_type.as_deref())?;
        MajikSignatureEnvelope::from_json(&entry.envelope)?;

        let mut entries: Vec<MjksMapEntry> =
            self.entries.iter().filter(|e| e.path != entry.path).cloned().collect();
        entries.push(entry);
        if entries.len() > MAX_MJKSMAP_ENTRIES {
            return Err(MajikSignatureError::validation(
                format!("MJKSMAP entries exceeds the limit of {MAX_MJKSMAP_ENTRIES}"),
                Some("entries"),
            ));
        }
        let data = MjksMapJSON { version: self.version, created_at: self.created_at.clone(), entries };
        serialize_map_payload(&data)?;
        Ok(Self::new(data))
    }

    pub fn without_entry(&self, path: &str) -> MajikSignatureMap {
        let normalized = normalize_path(path);
        Self::new(MjksMapJSON {
            version: self.version,
            created_at: self.created_at.clone(),
            entries: self.entries.iter().filter(|e| e.path != normalized).cloned().collect(),
        })
    }

    // ── Serialization ────────────────────────────────────────────────────────

    pub fn to_json(&self) -> MjksMapJSON {
        MjksMapJSON {
            version: self.version,
            created_at: self.created_at.clone(),
            entries: self.entries.clone(),
        }
    }

    /// `[magic(7)][version(1)][reserved(1)][payloadLen(4, BE u32)][payload JSON]`.
    pub fn to_mjksmap_bytes(&self) -> Vec<u8> {
        // All constructors enforce this bound; the capped writer protects this
        // final serialization from an unexpectedly oversized internal state.
        let payload = serialize_map_payload(&self.to_json()).expect("validated MJKSMAP payload size invariant");
        let mut out = Vec::with_capacity(MJKSMAP_HEADER_LEN + payload.len());
        out.extend_from_slice(&MJKSMAP_MAGIC);
        out.push(MJKSMAP_VERSION);
        out.push(0x00); // reserved — always 0 in v1
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&payload);
        out
    }

    /// TS `toMJKSMAP(): Blob` — the blob is the raw bytes (media type: [`MJKSMAP_MEDIA_TYPE`]).
    pub fn to_mjksmap(&self) -> Vec<u8> {
        self.to_mjksmap_bytes()
    }

    pub fn from_mjksmap(raw: &[u8]) -> R<MajikSignatureMap> {
        if raw.len() > MAX_MJKSMAP_BYTES + MJKSMAP_HEADER_LEN {
            return Err(MajikSignatureError::serialization(format!(
                "MJKSMAP input exceeds the maximum supported size of {} bytes",
                MAX_MJKSMAP_BYTES + MJKSMAP_HEADER_LEN
            )));
        }
        if raw.len() < MJKSMAP_HEADER_LEN + 1 {
            return Err(MajikSignatureError::serialization(
                "Malformed MJKSMAP: too short to contain a valid header",
            ));
        }
        if raw[..MJKSMAP_MAGIC_LEN] != MJKSMAP_MAGIC {
            return Err(MajikSignatureError::serialization(
                "Malformed MJKSMAP: missing \"MJKSMAP\" magic bytes",
            ));
        }
        let version = raw[MJKSMAP_MAGIC_LEN];
        if !MJKSMAP_SUPPORTED_VERSIONS.contains(&version) {
            return Err(MajikSignatureError::serialization(format!(
                "Unsupported MJKSMAP version: {version} (supported: {})",
                MJKSMAP_SUPPORTED_VERSIONS.iter().map(|v| v.to_string()).collect::<Vec<_>>().join(", ")
            )));
        }
        let reserved = raw[MJKSMAP_MAGIC_LEN + 1];
        if reserved != 0 {
            return Err(MajikSignatureError::serialization(format!(
                "Malformed MJKSMAP: reserved byte must be 0x00, got 0x{reserved:02x}"
            )));
        }
        let off = MJKSMAP_MAGIC_LEN + 2;
        let payload_len = u32::from_be_bytes([raw[off], raw[off + 1], raw[off + 2], raw[off + 3]]) as usize;
        if payload_len == 0 || payload_len > MAX_MJKSMAP_BYTES {
            return Err(MajikSignatureError::serialization("Malformed MJKSMAP: invalid or oversized payload length"));
        }
        let start = MJKSMAP_HEADER_LEN;
        let end = start.checked_add(payload_len)
            .ok_or_else(|| MajikSignatureError::serialization("Malformed MJKSMAP: payload length overflow"))?;
        if end > raw.len() {
            return Err(MajikSignatureError::serialization(
                "Malformed MJKSMAP: declared payload length exceeds buffer",
            ));
        }
        if end != raw.len() {
            return Err(MajikSignatureError::serialization(
                "Malformed MJKSMAP: trailing bytes after the declared payload",
            ));
        }
        let json = std::str::from_utf8(&raw[start..end]).map_err(|error| {
            MajikSignatureError::serialization_with_cause("Malformed MJKSMAP: payload is not valid UTF-8", error)
        })?;
        Self::from_json_str(json)
    }

    pub fn is_mjksmap(input: &[u8]) -> bool {
        input.len() >= MJKSMAP_MAGIC_LEN && input[..MJKSMAP_MAGIC_LEN] == MJKSMAP_MAGIC
    }

    // ── Factories ────────────────────────────────────────────────────────────

    pub fn empty() -> Self {
        Self::new(MjksMapJSON { version: MJKSMAP_VERSION, created_at: now_iso(), entries: Vec::new() })
    }

    pub fn from_json_str(json: &str) -> R<MajikSignatureMap> {
        if json.len() > MAX_MJKSMAP_BYTES {
            return Err(MajikSignatureError::serialization(format!(
                "MJKSMAP payload exceeds the maximum supported size of {MAX_MJKSMAP_BYTES} bytes"
            )));
        }
        let parsed: Value = serde_json::from_str(json).map_err(|e| {
            MajikSignatureError::serialization_with_cause("MJKSMAP payload is not valid JSON", e)
        })?;
        Self::from_json_value(parsed)
    }

    pub fn from_json_value(parsed: Value) -> R<MajikSignatureMap> {
        // Serialize through a bounded writer before constructing lookup indices.
        // This also protects callers that pass a large in-memory Value directly.
        let mut writer = BoundedWriter::new(MAX_MJKSMAP_BYTES);
        if let Err(error) = serde_json::to_writer(&mut writer, &parsed) {
            let message = if writer.exceeded {
                format!("MJKSMAP payload exceeds the maximum supported size of {MAX_MJKSMAP_BYTES} bytes")
            } else {
                format!("Failed to serialize MJKSMAP input: {error}")
            };
            return Err(MajikSignatureError::serialization_with_cause(message, error));
        }
        let Value::Object(obj) = &parsed else {
            return Err(MajikSignatureError::serialization("MJKSMAP payload must be a JSON object"));
        };
        let entries = validate_shape(obj)?;
        let created_at = obj.get("createdAt").and_then(Value::as_str).unwrap_or_default().to_string();
        let data = MjksMapJSON { version: MJKSMAP_VERSION, created_at, entries };
        serialize_map_payload(&data)?;
        Ok(Self::new(data))
    }

    pub fn from_json(json: &MjksMapJSON) -> R<MajikSignatureMap> {
        let v = serde_json::to_value(json)
            .map_err(|e| MajikSignatureError::serialization_with_cause("Failed to serialize MJKSMAP", e))?;
        Self::from_json_value(v)
    }

    pub fn validate(&self) -> R<()> {
        Self::from_json(&self.to_json()).map(|_| ())
    }

    pub fn is_valid(&self) -> bool {
        self.validate().is_ok()
    }
}

/// Validate the raw shape and return the typed entries (legacy single-signer envelopes inside an
/// entry are promoted, as `MajikSignatureEnvelope.fromJSON` does in TS).
fn validate_shape(obj: &serde_json::Map<String, Value>) -> R<Vec<MjksMapEntry>> {
    let verr = |m: String, f: &str| MajikSignatureError::validation(m, Some(f));

    if obj.get("version").and_then(Value::as_u64) != Some(MJKSMAP_VERSION as u64) {
        let shown = match obj.get("version") {
            Some(Value::String(s)) => s.clone(),
            Some(v) => v.to_string(),
            None => "undefined".to_string(),
        };
        return Err(verr(format!("Unsupported MJKSMAP schema version: {shown}"), "version"));
    }
    if obj.get("createdAt").and_then(Value::as_str).map(|s| s.is_empty()).unwrap_or(true) {
        return Err(verr("createdAt must be a non-empty ISO 8601 string".into(), "createdAt"));
    }
    let created_at = obj.get("createdAt").and_then(Value::as_str)
        .ok_or_else(|| verr("createdAt must be a valid ISO 8601 timestamp".into(), "createdAt"))?;
    MajikSignatureValidator::validate_timestamp_for_signing(created_at)?;
    let raw_entries = obj
        .get("entries")
        .and_then(Value::as_array)
        .ok_or_else(|| verr("entries must be an array".into(), "entries"))?;
    if raw_entries.len() > MAX_MJKSMAP_ENTRIES {
        return Err(verr(format!("MJKSMAP entries exceeds the limit of {MAX_MJKSMAP_ENTRIES}"), "entries"));
    }

    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::with_capacity(raw_entries.len());
    for (i, entry) in raw_entries.iter().enumerate() {
        let Some(e) = entry.as_object() else {
            return Err(verr(format!("entries[{i}] must be an object"), "entries"));
        };
        let path = e.get("path").and_then(Value::as_str)
            .ok_or_else(|| verr(format!("entries[{i}].path must be a non-empty string"), "path"))?;
        let normalized_path = validate_and_normalize_path(path, &format!("entries[{i}].path"))?;
        let hash = e.get("contentHash").and_then(Value::as_str)
            .ok_or_else(|| verr(format!("entries[{i}].contentHash must be a base64 SHA-256 digest"), "contentHash"))?;
        MajikSignatureValidator::validate_sha256_digest(hash, "contentHash")?;
        let size = match e.get("size") {
            None => None,
            Some(value) => Some(value.as_u64().ok_or_else(|| {
                verr(format!("entries[{i}].size must be a non-negative integer when present"), "size")
            })?),
        };
        let mime_type = match e.get("mimeType") {
            None => None,
            Some(value) => {
                let mime = value.as_str().ok_or_else(|| verr(
                    format!("entries[{i}].mimeType must be a string when present"), "mimeType"
                ))?;
                MajikSignatureValidator::validate_content_type(Some(mime))?;
                Some(mime.to_string())
            }
        };
        let Some(env) = e.get("envelope").filter(|v| v.is_object()) else {
            return Err(verr(format!("entries[{i}].envelope must be an object"), "envelope"));
        };
        let envelope = MajikSignatureEnvelope::from_json_value(env.clone())?.to_json();
        if !seen.insert(normalized_path.clone()) {
            return Err(verr(format!("Duplicate normalized path in entries: \"{normalized_path}\""), "path"));
        }
        out.push(MjksMapEntry {
            path: normalized_path,
            content_hash: hash.to_string(),
            size,
            mime_type,
            envelope,
        });
    }
    Ok(out)
}
