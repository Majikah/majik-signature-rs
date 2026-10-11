//! Port of `core/embed/utils.ts` — byte helpers, MIME sniffing and the universal trailer.
//!
//! `normalizeToBytes` / `normalizeToBlob` / `blobToBytes` / `bytesToBlob` have no Rust
//! counterpart: every `FileLike` is already `&[u8]`.

use crate::core::embed::constants::{TRAILER_MAGIC, TRAILER_SUFFIX_LENGTH};

pub fn text_encode(s: &str) -> Vec<u8> {
    s.as_bytes().to_vec()
}

/// UTF-8 decode with replacement characters (like `TextDecoder`).
pub fn text_decode(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

pub fn concat_bytes(arrays: &[&[u8]]) -> Vec<u8> {
    let total = arrays.iter().map(|a| a.len()).sum();
    let mut out = Vec::with_capacity(total);
    for a in arrays {
        out.extend_from_slice(a);
    }
    out
}

pub fn write_uint64_le(value: u64) -> [u8; 8] {
    value.to_le_bytes()
}

pub fn read_uint64_le(bytes: &[u8], offset: usize) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_le_bytes(b)
}

pub fn write_uint32_be(value: u32) -> [u8; 4] {
    value.to_be_bytes()
}

pub fn read_uint32_be(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3]])
}

pub fn write_uint32_le(value: u32) -> [u8; 4] {
    value.to_le_bytes()
}

pub fn read_uint32_le(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3]])
}

fn starts_with(bytes: &[u8], magic: &[u8]) -> bool {
    bytes.len() >= magic.len() && &bytes[..magic.len()] == magic
}

/// Sniff a MIME type from magic bytes; `blob_type` is the caller-declared type (TS `Blob.type`).
pub fn detect_mime_type(bytes: &[u8], blob_type: Option<&str>) -> String {
    if starts_with(bytes, &[0x25, 0x50, 0x44, 0x46]) {
        return "application/pdf".into(); // %PDF
    }
    if starts_with(bytes, &[0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]) {
        return "image/png".into();
    }
    if starts_with(bytes, &[0xff, 0xd8, 0xff]) {
        return "image/jpeg".into();
    }
    if starts_with(bytes, &[0x47, 0x49, 0x46, 0x38]) {
        return "image/gif".into();
    }
    if starts_with(bytes, &[0x52, 0x49, 0x46, 0x46]) && bytes.len() >= 12 && &bytes[8..12] == b"WEBP" {
        return "image/webp".into();
    }
    if starts_with(bytes, &[0x52, 0x49, 0x46, 0x46]) && bytes.len() >= 12 {
        let fmt = text_decode(&bytes[8..12]);
        if fmt == "WAVE" {
            return "audio/wav".into();
        }
        if fmt == "AVI " {
            return "video/avi".into();
        }
    }
    if starts_with(bytes, &[0x49, 0x44, 0x33]) {
        return "audio/mpeg".into(); // ID3
    }
    if bytes.len() >= 2 && bytes[0] == 0xff && (bytes[1] & 0xe0) == 0xe0 {
        return "audio/mpeg".into(); // MPEG frame sync
    }
    if starts_with(bytes, &[0x66, 0x4c, 0x61, 0x43]) {
        return "audio/flac".into(); // fLaC
    }
    if starts_with(bytes, &[0x4f, 0x67, 0x67, 0x53]) {
        return "audio/ogg".into();
    }
    if bytes.len() >= 12 {
        let box_type = text_decode(&bytes[4..8]);
        if box_type == "ftyp" {
            let brand = text_decode(&bytes[8..12]);
            if brand.starts_with("qt") || brand == "mooV" {
                return "video/quicktime".into();
            }
            return "video/mp4".into();
        }
        if box_type == "moov" || box_type == "mdat" {
            return "video/mp4".into();
        }
    }
    if starts_with(bytes, &[0x1a, 0x45, 0xdf, 0xa3]) {
        let header = text_decode(&bytes[..bytes.len().min(64)]);
        if header.contains("webm") {
            return "video/webm".into();
        }
        return "video/x-matroska".into();
    }
    if starts_with(bytes, &[0x50, 0x4b, 0x03, 0x04]) {
        if let Some(t) = blob_type {
            if t.contains("wordprocessingml") || t.contains("docx") {
                return "application/vnd.openxmlformats-officedocument.wordprocessingml.document".into();
            }
            if t.contains("spreadsheetml") || t.contains("xlsx") {
                return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet".into();
            }
            if t.contains("presentationml") || t.contains("pptx") {
                return "application/vnd.openxmlformats-officedocument.presentationml.presentation".into();
            }
        }
        return "application/zip".into();
    }
    if is_likely_text(bytes) {
        return "text/plain".into();
    }
    if let Some(t) = blob_type {
        if !t.is_empty() {
            return t.to_string();
        }
    }
    "application/octet-stream".into()
}

fn is_likely_text(bytes: &[u8]) -> bool {
    let sample = &bytes[..bytes.len().min(512)];
    let mut non_printable = 0usize;
    for &b in sample {
        if b == 0 {
            return false; // null byte = binary
        }
        if b < 0x09 || (b > 0x0d && b < 0x20 && b != 0x1b) {
            non_printable += 1;
        }
    }
    // Empty sample: 0/0 is NaN in JS and `NaN < 0.05` is false.
    !sample.is_empty() && (non_printable as f64 / sample.len() as f64) < 0.05
}

// ── Universal trailer ────────────────────────────────────────────────────────

/// Append `[payload][payloadLen(8, LE)][MAJIKSIG]` to `original`.
pub fn append_trailer(original: &[u8], signature_json: &str) -> Vec<u8> {
    let payload = signature_json.as_bytes();
    concat_bytes(&[original, payload, &write_uint64_le(payload.len() as u64), &TRAILER_MAGIC])
}

/// Split a trailer-bearing file into `(signatureJson, original)`.
pub fn extract_trailer(bytes: &[u8]) -> Option<(String, Vec<u8>)> {
    if bytes.len() < TRAILER_SUFFIX_LENGTH {
        return None;
    }
    if bytes[bytes.len() - 8..] != TRAILER_MAGIC {
        return None;
    }
    let payload_length = read_uint64_le(bytes, bytes.len() - 16);
    let available = (bytes.len() - 16) as u64;
    if payload_length > available {
        return None;
    }
    let payload_start = (available - payload_length) as usize;
    let payload = &bytes[payload_start..payload_start + payload_length as usize];
    Some((text_decode(payload), bytes[..payload_start].to_vec()))
}

pub fn buffer_equal(a: &[u8], b: &[u8]) -> bool {
    a == b
}

// ── CRC-32 (IEEE) ────────────────────────────────────────────────────────────

const fn make_crc_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut j = 0;
        while j < 8 {
            c = if c & 1 != 0 { 0xedb8_8320 ^ (c >> 1) } else { c >> 1 };
            j += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
}

static CRC_TABLE: [u32; 256] = make_crc_table();

pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &byte in data {
        crc = CRC_TABLE[((crc ^ byte as u32) & 0xff) as usize] ^ (crc >> 8);
    }
    crc ^ 0xffff_ffff
}

// ── Pattern helpers ──────────────────────────────────────────────────────────

pub fn matches_at(bytes: &[u8], pattern: &[u8], offset: usize) -> bool {
    offset.checked_add(pattern.len()).map(|end| end <= bytes.len()).unwrap_or(false)
        && &bytes[offset..offset + pattern.len()] == pattern
}

pub fn includes_bytes(bytes: &[u8], pattern: &[u8]) -> bool {
    if pattern.is_empty() {
        return true;
    }
    bytes.windows(pattern.len()).any(|w| w == pattern)
}

// ── JS-style slicing helpers (used by the hand-ported container parsers) ─────

/// `bytes.slice(start, end)` with JS semantics: both bounds clamp to the buffer and an inverted
/// range yields an empty slice (never panics).
pub fn slice(bytes: &[u8], start: usize, end: usize) -> &[u8] {
    let end = end.min(bytes.len());
    let start = start.min(end);
    &bytes[start..end]
}

/// `bytes.indexOf(value, from)` — `None` when absent or `from` is past the end.
pub fn index_of(bytes: &[u8], value: u8, from: usize) -> Option<usize> {
    if from >= bytes.len() {
        return None;
    }
    bytes[from..].iter().position(|&b| b == value).map(|p| p + from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_known_vector() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
    }

    #[test]
    fn trailer_roundtrip() {
        let t = append_trailer(b"hello", "{\"a\":1}");
        let (json, orig) = extract_trailer(&t).unwrap();
        assert_eq!(json, "{\"a\":1}");
        assert_eq!(orig, b"hello");
        assert!(extract_trailer(b"hello").is_none());
    }
}
