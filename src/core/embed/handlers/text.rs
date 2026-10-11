//! Port of `core/embed/handlers/text.ts` — base64 block in HTML-comment markers, appended
//! to text / markup / source files.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;

use crate::core::embed::utils::{concat_bytes, includes_bytes, matches_at, text_decode};
use crate::core::errors::{MajikSignatureError, MajikSignatureResult};
use crate::core::types::FormatHandler;

const BEGIN_MARKER: &str = "<!-- MAJIK-SIGNATURE-BEGIN -->";
const END_MARKER: &str = "<!-- MAJIK-SIGNATURE-END -->";

const TEXT_MIME_TYPES: &[&str] = &[
    "text/plain",
    "text/html",
    "text/xml",
    "application/xml",
    "text/markdown",
    "text/csv",
    "application/json",
    "application/javascript",
    "text/javascript",
    "application/typescript",
    "text/typescript",
    "text/css",
    "text/x-python",
    "text/x-java-source",
    "text/x-c",
    "text/x-c++",
    "application/x-sh",
    "text/x-shellscript",
    "application/x-yaml",
    "text/yaml",
    "text/x-toml",
    "application/toml",
];

fn is_base64_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'='
}

/// JS `btoa(str)`: every UTF-16 unit must fit in one byte (Latin-1), otherwise it throws.
fn btoa(s: &str) -> MajikSignatureResult<String> {
    let mut bytes = Vec::with_capacity(s.len());
    for c in s.chars() {
        let cp = c as u32;
        if cp > 0xff {
            return Err(MajikSignatureError::new(
                "Invalid character: signature contains characters outside Latin-1 and cannot be base64-embedded in text",
            ));
        }
        bytes.push(cp as u8);
    }
    Ok(B64.encode(bytes))
}

/// JS `atob(str)` → the "binary string" (each byte as one char).
fn atob(s: &str) -> Option<String> {
    let bytes = B64.decode(s).ok()?;
    Some(bytes.into_iter().map(|b| b as char).collect())
}

#[derive(Debug, Clone, Copy, Default)]
pub struct TextHandler;

impl TextHandler {
    fn head_bytes() -> Vec<u8> {
        format!("\n\n{BEGIN_MARKER}\n").into_bytes()
    }
    fn tail_bytes() -> Vec<u8> {
        format!("\n{END_MARKER}\n").into_bytes()
    }

    /// Split into `(payload, original)` when a well-formed block ends the file.
    pub fn split(&self, bytes: &[u8]) -> Option<(String, Vec<u8>)> {
        let tail = Self::tail_bytes();
        let head = Self::head_bytes();
        if bytes.len() < tail.len() {
            return None;
        }
        let tail_start = bytes.len() - tail.len();
        if !matches_at(bytes, &tail, tail_start) {
            return None;
        }
        let mut payload_start = tail_start;
        while payload_start > 0 && is_base64_byte(bytes[payload_start - 1]) {
            payload_start -= 1;
        }
        let payload_len = tail_start - payload_start;
        if payload_len == 0 || !payload_len.is_multiple_of(4) {
            return None;
        }
        if payload_start < head.len() {
            return None;
        }
        let head_start = payload_start - head.len();
        if !matches_at(bytes, &head, head_start) {
            return None;
        }
        let encoded = text_decode(&bytes[payload_start..tail_start]);
        let payload = atob(&encoded)?;
        // Reject non-canonical base64 (round-trip must reproduce the exact text).
        if btoa(&payload).ok()? != encoded {
            return None;
        }
        Some((payload, bytes[..head_start].to_vec()))
    }
}

impl FormatHandler for TextHandler {
    fn name(&self) -> &str {
        "Text/Markup/Source"
    }
    fn supported_mime_types(&self) -> &[&'static str] {
        TEXT_MIME_TYPES
    }
    fn can_handle(&self, _bytes: &[u8], mime_type: Option<&str>) -> bool {
        match mime_type {
            Some(m) if TEXT_MIME_TYPES.contains(&m) => true,
            None | Some("") | Some("application/octet-stream") => false,
            Some(m) => m.starts_with("text/"),
        }
    }
    fn embed(&self, bytes: &[u8], signature_json: &str) -> MajikSignatureResult<Vec<u8>> {
        let encoded = btoa(signature_json)?;
        let block = format!("\n\n{BEGIN_MARKER}\n{encoded}\n{END_MARKER}\n");
        Ok(concat_bytes(&[bytes, block.as_bytes()]))
    }
    fn extract(&self, bytes: &[u8]) -> MajikSignatureResult<Option<String>> {
        Ok(self.split(bytes).map(|(p, _)| p))
    }
    fn strip(&self, bytes: &[u8]) -> MajikSignatureResult<Vec<u8>> {
        Ok(match self.split(bytes) {
            Some((_, original)) => original,
            None => bytes.to_vec(),
        })
    }
    fn diagnose(&self, bytes: &[u8]) -> Option<String> {
        if self.split(bytes).is_some() {
            return None;
        }
        if !includes_bytes(bytes, BEGIN_MARKER.as_bytes()) && !includes_bytes(bytes, END_MARKER.as_bytes()) {
            return None;
        }
        Some(
            "A Majik signature marker was found, but no well-formed signature block ends the file. The file may have been modified after signing (for example, content appended after the signature block)."
                .into(),
        )
    }
}
