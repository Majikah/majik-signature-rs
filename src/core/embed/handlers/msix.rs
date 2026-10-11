//! Port of `core/embed/handlers/msix.ts` — detection only; MSIX/AppX packages must be
//! signed with *detached* envelopes to preserve package integrity.

use std::io::Cursor;

use crate::core::errors::{MajikSignatureError, MajikSignatureResult};
use crate::core::types::FormatHandler;

const MSIX_MIME_TYPES: &[&str] = &["application/msix", "application/appx"];

#[derive(Debug, Clone, Copy, Default)]
pub struct MsixHandler;

fn is_zip(bytes: &[u8]) -> bool {
    bytes.len() >= 4 && bytes[..4] == [0x50, 0x4b, 0x03, 0x04]
}

impl FormatHandler for MsixHandler {
    fn name(&self) -> &str {
        "MSIX / AppX"
    }
    fn supported_mime_types(&self) -> &[&'static str] {
        MSIX_MIME_TYPES
    }
    fn can_handle(&self, bytes: &[u8], mime_type: Option<&str>) -> bool {
        if !is_zip(bytes) {
            return false;
        }
        if let Some(m) = mime_type {
            if MSIX_MIME_TYPES.contains(&m) {
                return true;
            }
        }
        // Only the central directory is read; no entry is decompressed.
        match zip::ZipArchive::new(Cursor::new(bytes)) {
            Ok(archive) => {
                let names: Vec<&str> = archive.file_names().collect();
                names.contains(&"AppxManifest.xml") && names.contains(&"AppxBlockMap.xml")
            }
            Err(_) => false,
        }
    }
    fn embed(&self, _bytes: &[u8], _signature_json: &str) -> MajikSignatureResult<Vec<u8>> {
        Err(MajikSignatureError::new(
            "MsixHandler does not support embedded signatures. MSIX packages must be signed using detached Majik Signature artifacts to preserve package integrity.",
        ))
    }
    fn extract(&self, _bytes: &[u8]) -> MajikSignatureResult<Option<String>> {
        Ok(None)
    }
    fn strip(&self, bytes: &[u8]) -> MajikSignatureResult<Vec<u8>> {
        Ok(bytes.to_vec())
    }
}
