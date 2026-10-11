//! Port of `core/embed/handlers/png.ts` — `iTXt` chunk before `IEND`.

use crate::core::embed::constants::PNG_KEYWORD;
use crate::core::embed::utils::{
    concat_bytes, crc32, index_of, read_uint32_be, slice, text_decode, write_uint32_be,
};
use crate::core::errors::MajikSignatureResult;
use crate::core::types::FormatHandler;

const PNG_SIGNATURE: [u8; 8] = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];

struct Chunk<'a> {
    kind: String,
    data: &'a [u8],
    raw: &'a [u8],
}

#[derive(Debug, Clone, Copy, Default)]
pub struct PngHandler;

impl PngHandler {
    fn parse_chunks(bytes: &[u8]) -> Vec<Chunk<'_>> {
        let mut chunks = Vec::new();
        let mut offset = 8usize; // skip PNG signature
        while offset < bytes.len() {
            if offset + 8 > bytes.len() {
                break;
            }
            let length = read_uint32_be(bytes, offset) as usize;
            let kind = text_decode(slice(bytes, offset + 4, offset + 8));
            let data = slice(bytes, offset + 8, offset + 8 + length);
            let total = 4 + 4 + length + 4; // length + type + data + crc
            let raw = slice(bytes, offset, offset + total);
            chunks.push(Chunk { kind, data, raw });
            offset += total;
        }
        chunks
    }

    fn build_chunk(kind: &str, data: &[u8]) -> Vec<u8> {
        let crc_input = concat_bytes(&[kind.as_bytes(), data]);
        concat_bytes(&[
            &write_uint32_be(data.len() as u32),
            kind.as_bytes(),
            data,
            &write_uint32_be(crc32(&crc_input)),
        ])
    }

    fn build_itxt_data(keyword: &str, text: &str) -> Vec<u8> {
        concat_bytes(&[
            keyword.as_bytes(),
            &[0x00, 0x00, 0x00], // null, no_compression, method=0
            &[0x00],             // empty lang tag + null
            &[0x00],             // empty translated keyword + null
            text.as_bytes(),
        ])
    }

    fn read_itxt_data(data: &[u8]) -> Option<(String, String)> {
        let null_idx = index_of(data, 0x00, 0)?;
        let keyword = text_decode(&data[..null_idx]);
        let mut cursor = null_idx + 1 + 1 + 1; // past keyword null + 2 bytes
        let lang_end = index_of(data, 0x00, cursor)?;
        cursor = lang_end + 1;
        let tk_end = index_of(data, 0x00, cursor)?;
        cursor = tk_end + 1;
        Some((keyword, text_decode(slice(data, cursor, data.len()))))
    }
}

impl FormatHandler for PngHandler {
    fn name(&self) -> &str {
        "PNG"
    }
    fn supported_mime_types(&self) -> &[&'static str] {
        &["image/png"]
    }
    fn can_handle(&self, bytes: &[u8], mime_type: Option<&str>) -> bool {
        if mime_type == Some("image/png") {
            return true;
        }
        bytes.len() >= 8 && bytes[..8] == PNG_SIGNATURE
    }

    fn embed(&self, bytes: &[u8], signature_json: &str) -> MajikSignatureResult<Vec<u8>> {
        let clean = self.strip(bytes)?;
        let chunks = Self::parse_chunks(&clean);
        let sig_chunk = Self::build_chunk("iTXt", &Self::build_itxt_data(PNG_KEYWORD, signature_json));
        let insert_at = chunks.iter().position(|c| c.kind == "IEND").unwrap_or(chunks.len());

        let mut parts: Vec<&[u8]> = vec![&PNG_SIGNATURE];
        parts.extend(chunks[..insert_at].iter().map(|c| c.raw));
        parts.push(&sig_chunk);
        parts.extend(chunks[insert_at..].iter().map(|c| c.raw));
        Ok(concat_bytes(&parts))
    }

    fn extract(&self, bytes: &[u8]) -> MajikSignatureResult<Option<String>> {
        if !self.can_handle(bytes, None) {
            return Ok(None);
        }
        for chunk in Self::parse_chunks(bytes) {
            if chunk.kind == "iTXt" {
                if let Some((keyword, text)) = Self::read_itxt_data(chunk.data) {
                    if keyword == PNG_KEYWORD {
                        return Ok(Some(text));
                    }
                }
            }
        }
        Ok(None)
    }

    fn strip(&self, bytes: &[u8]) -> MajikSignatureResult<Vec<u8>> {
        if !self.can_handle(bytes, None) {
            return Ok(bytes.to_vec());
        }
        let chunks = Self::parse_chunks(bytes);
        let mut parts: Vec<&[u8]> = vec![&PNG_SIGNATURE];
        for c in &chunks {
            if c.kind == "iTXt" {
                if let Some((keyword, _)) = Self::read_itxt_data(c.data) {
                    if keyword == PNG_KEYWORD {
                        continue;
                    }
                }
            }
            parts.push(c.raw);
        }
        Ok(concat_bytes(&parts))
    }
}
