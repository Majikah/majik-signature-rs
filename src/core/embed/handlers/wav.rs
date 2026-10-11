//! Port of `core/embed/handlers/wav.ts` — `LIST/INFO/ISIG` RIFF chunk.

use crate::core::embed::utils::{concat_bytes, read_uint32_le, slice, text_decode, write_uint32_le};
use crate::core::errors::MajikSignatureResult;
use crate::core::types::FormatHandler;

struct Chunk<'a> {
    kind: String,
    data: &'a [u8],
    raw: &'a [u8],
}

#[derive(Debug, Clone, Copy, Default)]
pub struct WavHandler;

impl WavHandler {
    fn parse_riff_chunks(bytes: &[u8], start: usize) -> Vec<Chunk<'_>> {
        let mut chunks = Vec::new();
        let mut offset = start;
        while offset + 8 <= bytes.len() {
            let kind = text_decode(slice(bytes, offset, offset + 4));
            let size = read_uint32_le(bytes, offset + 4) as usize;
            let padded = size + (size % 2); // RIFF pads odd-sized chunks
            let data = slice(bytes, offset + 8, offset + 8 + size);
            let raw = slice(bytes, offset, offset + 8 + padded);
            chunks.push(Chunk { kind, data, raw });
            offset += 8 + padded;
        }
        chunks
    }

    fn rebuild(body: &[u8]) -> Vec<u8> {
        concat_bytes(&[b"RIFF", &write_uint32_le((4 + body.len()) as u32), b"WAVE", body])
    }
}

impl FormatHandler for WavHandler {
    fn name(&self) -> &str {
        "WAV"
    }
    fn supported_mime_types(&self) -> &[&'static str] {
        &["audio/wav", "audio/wave", "audio/x-wav"]
    }
    fn can_handle(&self, bytes: &[u8], mime_type: Option<&str>) -> bool {
        if let Some(m) = mime_type {
            if m.starts_with("audio/wav") || m == "audio/wave" || m == "audio/x-wav" {
                return true;
            }
        }
        if bytes.len() < 12 {
            return false;
        }
        &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WAVE"
    }

    fn embed(&self, bytes: &[u8], signature_json: &str) -> MajikSignatureResult<Vec<u8>> {
        let clean = self.strip(bytes)?;
        let payload = signature_json.as_bytes();
        let padded: Vec<u8> =
            if payload.len() % 2 == 1 { concat_bytes(&[payload, &[0x00]]) } else { payload.to_vec() };
        // actual (unpadded) length in the chunk header
        let isig = concat_bytes(&[b"ISIG", &write_uint32_le(payload.len() as u32), &padded]);
        let list_data = concat_bytes(&[b"INFO", &isig]);
        let list = concat_bytes(&[b"LIST", &write_uint32_le(list_data.len() as u32), &list_data]);
        let new_body = concat_bytes(&[slice(&clean, 12, clean.len()), &list]);
        Ok(Self::rebuild(&new_body))
    }

    fn extract(&self, bytes: &[u8]) -> MajikSignatureResult<Option<String>> {
        if !self.can_handle(bytes, None) {
            return Ok(None);
        }
        for chunk in Self::parse_riff_chunks(bytes, 12) {
            if chunk.kind == "LIST" && text_decode(slice(chunk.data, 0, 4)) == "INFO" {
                for ic in Self::parse_riff_chunks(chunk.data, 4) {
                    if ic.kind == "ISIG" {
                        return Ok(Some(text_decode(ic.data).trim_end_matches('\0').to_string()));
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
        let mut kept: Vec<Vec<u8>> = Vec::new();
        for chunk in Self::parse_riff_chunks(bytes, 12) {
            if chunk.kind == "LIST" && text_decode(slice(chunk.data, 0, 4)) == "INFO" {
                let info_chunks = Self::parse_riff_chunks(chunk.data, 4);
                let filtered: Vec<&Chunk<'_>> = info_chunks.iter().filter(|ic| ic.kind != "ISIG").collect();
                if filtered.is_empty() {
                    continue;
                }
                let mut parts: Vec<&[u8]> = vec![b"INFO"];
                parts.extend(filtered.iter().map(|ic| ic.raw));
                let info_body = concat_bytes(&parts);
                kept.push(concat_bytes(&[b"LIST", &write_uint32_le(info_body.len() as u32), &info_body]));
                continue;
            }
            kept.push(chunk.raw.to_vec());
        }
        let refs: Vec<&[u8]> = kept.iter().map(|v| v.as_slice()).collect();
        Ok(Self::rebuild(&concat_bytes(&refs)))
    }
}
