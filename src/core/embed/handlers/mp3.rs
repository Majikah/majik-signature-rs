//! Port of `core/embed/handlers/mp3.ts` — ID3v2 `TXXX` frame.

use crate::core::embed::constants::ID3_TXXX_DESCRIPTION;
use crate::core::embed::utils::{concat_bytes, index_of, slice, text_decode};
use crate::core::errors::MajikSignatureResult;
use crate::core::types::FormatHandler;

struct Frame<'a> {
    id: String,
    data: &'a [u8],
    raw: &'a [u8],
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Mp3Handler;

fn is_id3(bytes: &[u8]) -> bool {
    bytes.len() >= 3 && bytes[0] == 0x49 && bytes[1] == 0x44 && bytes[2] == 0x33
}

impl Mp3Handler {
    fn read_syncsafe_int(bytes: &[u8], offset: usize) -> usize {
        (((bytes[offset] & 0x7f) as usize) << 21)
            | (((bytes[offset + 1] & 0x7f) as usize) << 14)
            | (((bytes[offset + 2] & 0x7f) as usize) << 7)
            | ((bytes[offset + 3] & 0x7f) as usize)
    }

    fn write_syncsafe_int(value: usize) -> [u8; 4] {
        [
            ((value >> 21) & 0x7f) as u8,
            ((value >> 14) & 0x7f) as u8,
            ((value >> 7) & 0x7f) as u8,
            (value & 0x7f) as u8,
        ]
    }

    fn parse_id3v2_frames(bytes: &[u8]) -> Vec<Frame<'_>> {
        let major_version = bytes[3];
        let tag_size = Self::read_syncsafe_int(bytes, 6);
        let mut offset = 10usize;
        let mut frames = Vec::new();
        // TS: `while (offset < 10 + tagSize - 10)` — i.e. `offset < tagSize`.
        while offset < tag_size {
            if offset + 10 > bytes.len() {
                break;
            }
            let id_bytes = slice(bytes, offset, offset + 4);
            if id_bytes.first() == Some(&0) {
                break; // padding
            }
            let id = text_decode(id_bytes);
            let frame_size = if major_version == 4 {
                Self::read_syncsafe_int(bytes, offset + 4)
            } else {
                let v = ((bytes[offset + 4] as u32) << 24)
                    | ((bytes[offset + 5] as u32) << 16)
                    | ((bytes[offset + 6] as u32) << 8)
                    | bytes[offset + 7] as u32;
                // JS reads this as a signed 32-bit int; a "negative" size would never terminate.
                if v >= 0x8000_0000 {
                    break;
                }
                v as usize
            };
            let data = slice(bytes, offset + 10, offset + 10 + frame_size);
            let raw = slice(bytes, offset, offset + 10 + frame_size);
            frames.push(Frame { id, data, raw });
            offset += 10 + frame_size;
        }
        frames
    }

    fn build_txxx_frame(description: &str, value: &str) -> Vec<u8> {
        let frame_data = concat_bytes(&[&[0x03], description.as_bytes(), &[0x00], value.as_bytes()]);
        let n = frame_data.len() as u32;
        concat_bytes(&[b"TXXX", &n.to_be_bytes(), &[0x00, 0x00], &frame_data])
    }

    fn read_txxx_frame(data: &[u8]) -> Option<(String, String)> {
        let null_idx = index_of(data, 0x00, 1)?;
        Some((text_decode(slice(data, 1, null_idx)), text_decode(slice(data, null_idx + 1, data.len()))))
    }

    fn build_header_from_frames(frames_data: &[u8]) -> Vec<u8> {
        concat_bytes(&[
            b"ID3",
            &[0x03, 0x00],
            &[0x00],
            &Self::write_syncsafe_int(frames_data.len()),
            frames_data,
        ])
    }

    fn inject_frame(bytes: &[u8], frame: &[u8]) -> Vec<u8> {
        let tag_size = Self::read_syncsafe_int(bytes, 6);
        let audio = slice(bytes, 10 + tag_size, bytes.len());
        let existing = Self::parse_id3v2_frames(bytes);
        let mut parts: Vec<&[u8]> = existing.iter().map(|f| f.raw).collect();
        parts.push(frame);
        let frames_data = concat_bytes(&parts);
        concat_bytes(&[&Self::build_header_from_frames(&frames_data), audio])
    }
}

impl FormatHandler for Mp3Handler {
    fn name(&self) -> &str {
        "MP3"
    }
    fn supported_mime_types(&self) -> &[&'static str] {
        &["audio/mpeg", "audio/mp3"]
    }
    fn can_handle(&self, bytes: &[u8], mime_type: Option<&str>) -> bool {
        if matches!(mime_type, Some("audio/mpeg") | Some("audio/mp3")) {
            return true;
        }
        if is_id3(bytes) {
            return true;
        }
        bytes.len() >= 2 && bytes[0] == 0xff && (bytes[1] & 0xe0) == 0xe0
    }

    fn embed(&self, bytes: &[u8], signature_json: &str) -> MajikSignatureResult<Vec<u8>> {
        let clean = self.strip(bytes)?;
        let frame = Self::build_txxx_frame(ID3_TXXX_DESCRIPTION, signature_json);
        if clean.len() >= 10 && is_id3(&clean) {
            Ok(Self::inject_frame(&clean, &frame))
        } else {
            Ok(concat_bytes(&[&Self::build_header_from_frames(&frame), &clean]))
        }
    }

    fn extract(&self, bytes: &[u8]) -> MajikSignatureResult<Option<String>> {
        if !self.can_handle(bytes, None) || bytes.len() < 10 || !is_id3(bytes) {
            return Ok(None);
        }
        for frame in Self::parse_id3v2_frames(bytes) {
            if frame.id == "TXXX" {
                if let Some((desc, value)) = Self::read_txxx_frame(frame.data) {
                    if desc == ID3_TXXX_DESCRIPTION {
                        return Ok(Some(value));
                    }
                }
            }
        }
        Ok(None)
    }

    fn strip(&self, bytes: &[u8]) -> MajikSignatureResult<Vec<u8>> {
        if !self.can_handle(bytes, None) || bytes.len() < 10 || !is_id3(bytes) {
            return Ok(bytes.to_vec());
        }
        let tag_size = Self::read_syncsafe_int(bytes, 6);
        let audio = slice(bytes, 10 + tag_size, bytes.len());
        let frames = Self::parse_id3v2_frames(bytes);
        let kept: Vec<&Frame<'_>> = frames
            .iter()
            .filter(|f| {
                if f.id != "TXXX" {
                    return true;
                }
                match Self::read_txxx_frame(f.data) {
                    Some((desc, _)) => desc != ID3_TXXX_DESCRIPTION,
                    None => true,
                }
            })
            .collect();
        if kept.is_empty() {
            return Ok(audio.to_vec());
        }
        let raws: Vec<&[u8]> = kept.iter().map(|f| f.raw).collect();
        let frames_data = concat_bytes(&raws);
        Ok(concat_bytes(&[&Self::build_header_from_frames(&frames_data), audio]))
    }
}
