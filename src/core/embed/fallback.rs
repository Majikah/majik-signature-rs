//! Port of `core/embed/fallback.ts` — universal trailer handler for unknown formats.

use crate::core::embed::utils::{append_trailer, extract_trailer};
use crate::core::errors::MajikSignatureResult;
use crate::core::types::FormatHandler;

#[derive(Debug, Clone, Copy, Default)]
pub struct FallbackHandler;

impl FormatHandler for FallbackHandler {
    fn name(&self) -> &str {
        "Fallback (Universal Trailer)"
    }
    fn supported_mime_types(&self) -> &[&'static str] {
        &["*/*"]
    }
    fn can_handle(&self, _bytes: &[u8], _mime_type: Option<&str>) -> bool {
        true
    }
    fn embed(&self, bytes: &[u8], signature_json: &str) -> MajikSignatureResult<Vec<u8>> {
        let stripped = self.strip(bytes)?;
        Ok(append_trailer(&stripped, signature_json))
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
