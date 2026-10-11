//! Port of `core/embed/handlers/office.ts` — `majik-signature.json` entry inside OOXML / ODF
//! ZIP containers. Re-zipping is stored (`level: 0`) with a pinned timestamp so output is
//! deterministic (see [`crate::core::embed::zipio`]).

use crate::core::embed::constants::OFFICE_ZIP_ENTRY;
use crate::core::embed::zipio::{list_names, unzip_bounded, unzip_filtered, zip_stored};
use crate::core::errors::{MajikSignatureError, MajikSignatureResult};
use crate::core::types::FormatHandler;

const OFFICE_MIME_TYPES: &[&str] = &[
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "application/vnd.ms-word.document.macroEnabled.12",
    "application/vnd.ms-excel.sheet.macroEnabled.12",
    "application/vnd.ms-powerpoint.presentation.macroEnabled.12",
    "application/vnd.oasis.opendocument.text",
    "application/vnd.oasis.opendocument.spreadsheet",
    "application/vnd.oasis.opendocument.presentation",
];

const ODF_MIME_TYPES: &[&str] = &[
    "application/vnd.oasis.opendocument.text",
    "application/vnd.oasis.opendocument.spreadsheet",
    "application/vnd.oasis.opendocument.presentation",
];

const MSIX_PACKAGE_ENTRIES: &[&str] = &["AppxManifest.xml", "AppxBlockMap.xml", "AppxSignature.p7x"];
const OOXML_ENTRIES: &[&str] = &["word/document.xml", "xl/workbook.xml", "ppt/presentation.xml"];

/// Largest single entry the sniffer / extractor is willing to inflate.
const MAX_SIGNATURE_ENTRY_BYTES: u64 = 8 * 1024 * 1024;

fn is_zip(bytes: &[u8]) -> bool {
    bytes.len() >= 4 && bytes[..4] == [0x50, 0x4b, 0x03, 0x04]
}

#[derive(Debug, Clone, Copy, Default)]
pub struct OfficeHandler;

impl FormatHandler for OfficeHandler {
    fn name(&self) -> &str {
        "Office (DOCX/XLSX/PPTX/ODF)"
    }
    fn supported_mime_types(&self) -> &[&'static str] {
        OFFICE_MIME_TYPES
    }

    fn can_handle(&self, bytes: &[u8], mime_type: Option<&str>) -> bool {
        if let Some(m) = mime_type {
            if OFFICE_MIME_TYPES.contains(&m) {
                return true;
            }
        }
        if !is_zip(bytes) {
            return false;
        }
        let sniff = |name: &str| {
            name == "[Content_Types].xml"
                || name == "mimetype"
                || MSIX_PACKAGE_ENTRIES.contains(&name)
                || OOXML_ENTRIES.contains(&name)
        };
        // Names first (cheap), then only the tiny entries we actually need.
        let Ok(names) = list_names(bytes) else { return false };
        if names.iter().any(|n| MSIX_PACKAGE_ENTRIES.contains(&n.as_str())) {
            return false;
        }
        if names.iter().any(|n| OOXML_ENTRIES.contains(&n.as_str())) {
            return true;
        }
        if names.iter().any(|n| n == "mimetype") {
            let Ok(files) = unzip_filtered(bytes, |n, size| sniff(n) && size <= MAX_SIGNATURE_ENTRY_BYTES)
            else {
                return false;
            };
            if let Some(data) = files.get("mimetype") {
                let detected = String::from_utf8_lossy(data);
                return ODF_MIME_TYPES.contains(&detected.trim());
            }
        }
        false
    }

    fn embed(&self, bytes: &[u8], signature_json: &str) -> MajikSignatureResult<Vec<u8>> {
        let attempt = || -> MajikSignatureResult<Vec<u8>> {
            let mut files = unzip_bounded(bytes)?;
            files.remove(OFFICE_ZIP_ENTRY);
            files.set(OFFICE_ZIP_ENTRY.to_string(), signature_json.as_bytes().to_vec());
            zip_stored(&files)
        };
        attempt()
            .map_err(|e| MajikSignatureError::new(format!("OfficeHandler.embed failed: {}", e.message())))
    }

    fn extract(&self, bytes: &[u8]) -> MajikSignatureResult<Option<String>> {
        if !self.can_handle(bytes, None) {
            return Ok(None);
        }
        let Ok(files) =
            unzip_filtered(bytes, |n, size| n == OFFICE_ZIP_ENTRY && size <= MAX_SIGNATURE_ENTRY_BYTES)
        else {
            return Ok(None);
        };
        Ok(files.get(OFFICE_ZIP_ENTRY).map(|d| String::from_utf8_lossy(d).into_owned()))
    }

    fn strip(&self, bytes: &[u8]) -> MajikSignatureResult<Vec<u8>> {
        if !self.can_handle(bytes, None) {
            return Ok(bytes.to_vec());
        }
        let attempt = || -> MajikSignatureResult<Vec<u8>> {
            let mut files = unzip_bounded(bytes)?;
            files.remove(OFFICE_ZIP_ENTRY);
            zip_stored(&files)
        };
        Ok(attempt().unwrap_or_else(|_| bytes.to_vec()))
    }
}
