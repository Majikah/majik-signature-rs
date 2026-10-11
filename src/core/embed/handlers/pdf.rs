//! Port of `core/embed/handlers/pdf.ts` — signature appended after `%%EOF`:
//! `\n%%MajikSig%%\n` ‖ payload ‖ payloadLen (4, BE u32).

use crate::core::embed::utils::{concat_bytes, includes_bytes, matches_at};
use crate::core::errors::MajikSignatureResult;
use crate::core::types::FormatHandler;

const MAGIC: &[u8] = b"\n%%MajikSig%%\n";

#[derive(Debug, Clone, Copy, Default)]
pub struct PdfHandler;

impl PdfHandler {
    /// Split into `(payload, original)` when a well-formed signature block ends the file.
    pub fn split(&self, bytes: &[u8]) -> Option<(String, Vec<u8>)> {
        if bytes.len() < MAGIC.len() + 1 + 4 {
            return None;
        }
        let len_pos = bytes.len() - 4;
        let sig_len =
            u32::from_be_bytes([bytes[len_pos], bytes[len_pos + 1], bytes[len_pos + 2], bytes[len_pos + 3]])
                as usize;
        if sig_len == 0 || sig_len > len_pos {
            return None;
        }
        let sig_start = len_pos - sig_len;
        if sig_start < MAGIC.len() {
            return None;
        }
        let magic_start = sig_start - MAGIC.len();
        if !matches_at(bytes, MAGIC, magic_start) {
            return None;
        }
        // Strict UTF-8 (a decode failure means "not a signature block").
        let payload = std::str::from_utf8(&bytes[sig_start..len_pos]).ok()?.to_string();
        Some((payload, bytes[..magic_start].to_vec()))
    }
}

impl FormatHandler for PdfHandler {
    fn name(&self) -> &str {
        "PDF"
    }
    fn supported_mime_types(&self) -> &[&'static str] {
        &["application/pdf"]
    }
    fn can_handle(&self, bytes: &[u8], mime_type: Option<&str>) -> bool {
        if mime_type == Some("application/pdf") {
            return true;
        }
        bytes.len() >= 4 && bytes[..4] == [0x25, 0x50, 0x44, 0x46]
    }
    fn embed(&self, bytes: &[u8], signature_json: &str) -> MajikSignatureResult<Vec<u8>> {
        let sig = signature_json.as_bytes();
        Ok(concat_bytes(&[bytes, MAGIC, sig, &(sig.len() as u32).to_be_bytes()]))
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
        if self.split(bytes).is_some() || !includes_bytes(bytes, MAGIC) {
            return None;
        }
        Some(
            "A Majik signature marker was found, but no well-formed signature block ends the file. The file may have been modified after signing."
                .into(),
        )
    }
}
