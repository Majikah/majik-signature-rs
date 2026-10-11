//! Port of `core/embed/handlers/mkv.ts` — universal trailer on Matroska / WebM.

use crate::core::embed::utils::{append_trailer, extract_trailer};
use crate::core::errors::MajikSignatureResult;
use crate::core::types::FormatHandler;

const EBML_MAGIC: [u8; 4] = [0x1a, 0x45, 0xdf, 0xa3];
const MIME: &[&str] = &["video/x-matroska", "video/webm", "audio/webm", "audio/x-matroska"];

#[derive(Debug, Clone, Copy, Default)]
pub struct MkvHandler;

impl FormatHandler for MkvHandler {
    fn name(&self) -> &str {
        "MKV/WebM"
    }
    fn supported_mime_types(&self) -> &[&'static str] {
        MIME
    }
    fn can_handle(&self, bytes: &[u8], mime_type: Option<&str>) -> bool {
        if let Some(m) = mime_type {
            if MIME.contains(&m) {
                return true;
            }
        }
        bytes.len() >= 4 && bytes[..4] == EBML_MAGIC
    }
    fn embed(&self, bytes: &[u8], signature_json: &str) -> MajikSignatureResult<Vec<u8>> {
        let clean = self.strip(bytes)?;
        Ok(append_trailer(&clean, signature_json))
    }
    fn extract(&self, bytes: &[u8]) -> MajikSignatureResult<Option<String>> {
        Ok(extract_trailer(bytes).map(|(json, _)| json))
    }
    fn strip(&self, bytes: &[u8]) -> MajikSignatureResult<Vec<u8>> {
        Ok(match extract_trailer(bytes) {
            Some((_, original)) => original,
            None => bytes.to_vec(),
        })
    }
}
