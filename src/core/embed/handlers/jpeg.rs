//! Port of `core/embed/handlers/jpeg.ts` — APP15 (`0xFFEF`) segment right after SOI.

use crate::core::embed::utils::{concat_bytes, slice, text_decode};
use crate::core::errors::{MajikSignatureError, MajikSignatureResult};
use crate::core::types::FormatHandler;

const JPEG_SOI: [u8; 2] = [0xff, 0xd8];
const APP15_MARKER: [u8; 2] = [0xff, 0xef];
const MAJIK_IDENTIFIER: &[u8] = b"MAJIK\0";

#[derive(Debug, Clone, Copy, Default)]
pub struct JpegHandler;

impl JpegHandler {
    fn is_ours(seg_data: &[u8]) -> bool {
        seg_data.len() > MAJIK_IDENTIFIER.len() && &seg_data[..MAJIK_IDENTIFIER.len()] == MAJIK_IDENTIFIER
    }

    fn find_app15(bytes: &[u8]) -> Option<String> {
        let mut offset = 2usize; // skip SOI
        while offset + 1 < bytes.len() {
            if bytes[offset] != 0xff {
                break;
            }
            let marker = bytes[offset + 1];
            if marker == 0xd9 {
                break; // EOI
            }
            if marker == 0x01 || (0xd0..=0xd8).contains(&marker) {
                offset += 2;
                continue;
            }
            if offset + 4 > bytes.len() {
                break;
            }
            let seg_length = ((bytes[offset + 2] as usize) << 8) | bytes[offset + 3] as usize;
            let seg_data_start = offset + 4;
            let seg_data_end = offset + 2 + seg_length;
            if marker == 0xef {
                let seg_data = slice(bytes, seg_data_start, seg_data_end);
                if Self::is_ours(seg_data) {
                    return Some(text_decode(&seg_data[MAJIK_IDENTIFIER.len()..]));
                }
            }
            offset = seg_data_end;
        }
        None
    }

    fn remove_app15(bytes: &[u8]) -> Vec<u8> {
        let mut parts: Vec<&[u8]> = vec![&JPEG_SOI];
        let mut offset = 2usize;
        while offset + 1 < bytes.len() {
            if bytes[offset] != 0xff {
                parts.push(slice(bytes, offset, bytes.len()));
                break;
            }
            let marker = bytes[offset + 1];
            if marker == 0xd9 {
                parts.push(slice(bytes, offset, bytes.len()));
                break;
            }
            if marker == 0x01 || (0xd0..=0xd8).contains(&marker) {
                parts.push(slice(bytes, offset, offset + 2));
                offset += 2;
                continue;
            }
            if offset + 4 > bytes.len() {
                parts.push(slice(bytes, offset, bytes.len()));
                break;
            }
            let seg_length = ((bytes[offset + 2] as usize) << 8) | bytes[offset + 3] as usize;
            let seg_end = offset + 2 + seg_length;
            let seg_data_start = offset + 4;
            if marker == 0xef && Self::is_ours(slice(bytes, seg_data_start, seg_end)) {
                offset = seg_end;
                continue;
            }
            parts.push(slice(bytes, offset, seg_end));
            offset = seg_end;
        }
        concat_bytes(&parts)
    }
}

impl FormatHandler for JpegHandler {
    fn name(&self) -> &str {
        "JPEG"
    }
    fn supported_mime_types(&self) -> &[&'static str] {
        &["image/jpeg", "image/jpg"]
    }
    fn can_handle(&self, bytes: &[u8], mime_type: Option<&str>) -> bool {
        if matches!(mime_type, Some("image/jpeg") | Some("image/jpg")) {
            return true;
        }
        bytes.len() >= 3 && bytes[0] == 0xff && bytes[1] == 0xd8 && bytes[2] == 0xff
    }

    fn embed(&self, bytes: &[u8], signature_json: &str) -> MajikSignatureResult<Vec<u8>> {
        let clean = self.strip(bytes)?;
        let segment_data = concat_bytes(&[MAJIK_IDENTIFIER, signature_json.as_bytes()]);
        let length = segment_data.len() + 2; // +2 for the length field itself
        if length > 0xffff {
            return Err(MajikSignatureError::new("Signature too large for JPEG APP15 segment"));
        }
        let length_bytes = [((length >> 8) & 0xff) as u8, (length & 0xff) as u8];
        let segment = concat_bytes(&[&APP15_MARKER, &length_bytes, &segment_data]);
        let rest = slice(&clean, 2, clean.len());
        Ok(concat_bytes(&[&JPEG_SOI, &segment, rest]))
    }

    fn extract(&self, bytes: &[u8]) -> MajikSignatureResult<Option<String>> {
        if !self.can_handle(bytes, None) {
            return Ok(None);
        }
        Ok(Self::find_app15(bytes))
    }

    fn strip(&self, bytes: &[u8]) -> MajikSignatureResult<Vec<u8>> {
        if !self.can_handle(bytes, None) {
            return Ok(bytes.to_vec());
        }
        Ok(Self::remove_app15(bytes))
    }
}
