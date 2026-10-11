//! Port of `core/embed/handlers/flac.ts` — metadata `APPLICATION` block with id `"MAJK"`.

use crate::core::embed::utils::{concat_bytes, slice, text_decode};
use crate::core::errors::{MajikSignatureError, MajikSignatureResult};
use crate::core::types::FormatHandler;

const FLAC_MAGIC: &[u8] = b"fLaC";
const APPLICATION_ID: &[u8] = b"MAJK";
const BLOCK_APPLICATION: u8 = 2;

struct MetadataBlock<'a> {
    kind: u8,
    data: &'a [u8],
    raw: &'a [u8],
}

struct Parsed<'a> {
    blocks: Vec<MetadataBlock<'a>>,
    audio_data: &'a [u8],
    end_offset: usize,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct FlacHandler;

impl FlacHandler {
    fn parse_metadata(bytes: &[u8]) -> Result<Parsed<'_>, &'static str> {
        if bytes.len() < 4 || &bytes[..4] != FLAC_MAGIC {
            return Err("Invalid FLAC magic header");
        }
        let mut blocks = Vec::new();
        let mut offset = 4usize;
        while offset < bytes.len() {
            if offset + 4 > bytes.len() {
                return Err("Truncated metadata block header");
            }
            let header = bytes[offset];
            let is_last = header & 0x80 != 0;
            let kind = header & 0x7f;
            let length = ((bytes[offset + 1] as usize) << 16)
                | ((bytes[offset + 2] as usize) << 8)
                | bytes[offset + 3] as usize;
            if offset + 4 + length > bytes.len() {
                return Err("Truncated metadata block payload");
            }
            blocks.push(MetadataBlock {
                kind,
                data: slice(bytes, offset + 4, offset + 4 + length),
                raw: slice(bytes, offset, offset + 4 + length),
            });
            offset += 4 + length;
            if is_last {
                break;
            }
        }
        Ok(Parsed { blocks, audio_data: slice(bytes, offset, bytes.len()), end_offset: offset })
    }

    fn build_metadata_block(kind: u8, data: &[u8], is_last: bool) -> Vec<u8> {
        let header = [
            (if is_last { 0x80 } else { 0x00 }) | (kind & 0x7f),
            ((data.len() >> 16) & 0xff) as u8,
            ((data.len() >> 8) & 0xff) as u8,
            (data.len() & 0xff) as u8,
        ];
        concat_bytes(&[&header, data])
    }

    fn validate_audio_stream(audio: &[u8], expected: usize) -> bool {
        if audio.len() != expected {
            return false;
        }
        if audio.is_empty() {
            return true;
        }
        if audio.len() >= 2 && (audio[0] != 0xff || (audio[1] & 0xfc) != 0xf8) {
            return false;
        }
        true
    }

    fn is_majik_app_block(b: &MetadataBlock<'_>) -> bool {
        b.kind == BLOCK_APPLICATION && b.data.len() >= 4 && &b.data[..4] == APPLICATION_ID
    }
}

impl FormatHandler for FlacHandler {
    fn name(&self) -> &str {
        "FLAC"
    }
    fn supported_mime_types(&self) -> &[&'static str] {
        &["audio/flac", "audio/x-flac"]
    }
    fn can_handle(&self, bytes: &[u8], mime_type: Option<&str>) -> bool {
        if matches!(mime_type, Some("audio/flac") | Some("audio/x-flac")) {
            return true;
        }
        bytes.len() >= 4 && &bytes[..4] == FLAC_MAGIC
    }

    fn embed(&self, bytes: &[u8], signature_json: &str) -> MajikSignatureResult<Vec<u8>> {
        let clean = self.strip(bytes)?;
        let parsed = Self::parse_metadata(&clean).map_err(MajikSignatureError::new)?;
        let app_payload = concat_bytes(&[APPLICATION_ID, signature_json.as_bytes()]);
        let updated: Vec<Vec<u8>> = parsed
            .blocks
            .iter()
            .map(|b| {
                let mut nb = b.raw.to_vec();
                nb[0] &= 0x7f; // clear isLast
                nb
            })
            .collect();
        let sig_block = Self::build_metadata_block(BLOCK_APPLICATION, &app_payload, true);
        let mut parts: Vec<&[u8]> = vec![FLAC_MAGIC];
        parts.extend(updated.iter().map(|v| v.as_slice()));
        parts.push(&sig_block);
        parts.push(parsed.audio_data);
        Ok(concat_bytes(&parts))
    }

    fn extract(&self, bytes: &[u8]) -> MajikSignatureResult<Option<String>> {
        if !self.can_handle(bytes, None) {
            return Ok(None);
        }
        let Ok(parsed) = Self::parse_metadata(bytes) else { return Ok(None) };
        if !Self::validate_audio_stream(parsed.audio_data, bytes.len() - parsed.end_offset) {
            return Ok(None);
        }
        for block in &parsed.blocks {
            if Self::is_majik_app_block(block) {
                let json = text_decode(&block.data[4..]);
                return Ok(Some(json.trim_end_matches('\0').to_string()));
            }
        }
        Ok(None)
    }

    fn strip(&self, bytes: &[u8]) -> MajikSignatureResult<Vec<u8>> {
        if !self.can_handle(bytes, None) {
            return Ok(bytes.to_vec());
        }
        let Ok(parsed) = Self::parse_metadata(bytes) else { return Ok(bytes.to_vec()) };
        let kept: Vec<&MetadataBlock<'_>> =
            parsed.blocks.iter().filter(|b| !Self::is_majik_app_block(b)).collect();
        if kept.len() == parsed.blocks.len() {
            return Ok(bytes.to_vec());
        }
        let n = kept.len();
        let rebuilt: Vec<Vec<u8>> = kept
            .iter()
            .enumerate()
            .map(|(i, b)| {
                let mut header = slice(b.raw, 0, 4).to_vec();
                if i == n - 1 {
                    header[0] |= 0x80;
                } else {
                    header[0] &= 0x7f;
                }
                concat_bytes(&[&header, b.data])
            })
            .collect();
        let mut parts: Vec<&[u8]> = vec![FLAC_MAGIC];
        parts.extend(rebuilt.iter().map(|v| v.as_slice()));
        parts.push(parsed.audio_data);
        Ok(concat_bytes(&parts))
    }
}
