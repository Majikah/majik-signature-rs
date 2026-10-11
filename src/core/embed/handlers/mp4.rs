//! Port of `core/embed/handlers/mp4.ts` — `majk` box inside `moov/udta` (universal trailer
//! when the file has no `moov`).

use crate::core::embed::constants::MP4_BOX_TYPE;
use crate::core::embed::utils::{
    append_trailer, concat_bytes, extract_trailer, read_uint32_be, slice, text_decode,
};
use crate::core::errors::MajikSignatureResult;
use crate::core::types::FormatHandler;

const MIME: &[&str] = &["video/mp4", "video/quicktime", "audio/mp4", "audio/m4a", "video/x-m4v", "video/m4v"];

struct BoxRef<'a> {
    kind: String,
    data: &'a [u8],
    raw: &'a [u8],
}

struct Parsed<'a> {
    boxes: Vec<BoxRef<'a>>,
    trailing: &'a [u8],
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Mp4Handler;

impl Mp4Handler {
    fn parse_boxes(bytes: &[u8], start: usize, end: usize) -> Parsed<'_> {
        let mut boxes = Vec::new();
        let mut offset = start;
        while offset + 8 <= end {
            let mut size = read_uint32_be(bytes, offset) as u64;
            let kind = text_decode(slice(bytes, offset + 4, offset + 8));
            let mut header_size = 8usize;
            if size == 1 {
                if offset + 16 > bytes.len() {
                    break;
                }
                let hi = read_uint32_be(bytes, offset + 8) as u64;
                let lo = read_uint32_be(bytes, offset + 12) as u64;
                size = hi * 0x1_0000_0000 + lo;
                header_size = 16;
            } else if size == 0 {
                size = (end - offset) as u64;
            }
            if size < 8 || (offset as u64) + size > end as u64 {
                break;
            }
            let size = size as usize;
            boxes.push(BoxRef {
                kind,
                data: slice(bytes, offset + header_size, offset + size),
                raw: slice(bytes, offset, offset + size),
            });
            offset += size;
        }
        Parsed { boxes, trailing: slice(bytes, offset, end) }
    }

    fn build_box(kind: &str, data: &[u8]) -> Vec<u8> {
        concat_bytes(&[&((8 + data.len()) as u32).to_be_bytes(), kind.as_bytes(), data])
    }
}

impl FormatHandler for Mp4Handler {
    fn name(&self) -> &str {
        "MP4/MOV"
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
        if bytes.len() < 12 {
            return false;
        }
        matches!(text_decode(&bytes[4..8]).as_str(), "ftyp" | "moov" | "mdat")
    }

    fn embed(&self, bytes: &[u8], signature_json: &str) -> MajikSignatureResult<Vec<u8>> {
        let clean = self.strip(bytes)?;
        let majk_box = Self::build_box(MP4_BOX_TYPE, signature_json.as_bytes());
        let top = Self::parse_boxes(&clean, 0, clean.len());
        let Some(moov_idx) = top.boxes.iter().position(|b| b.kind == "moov") else {
            return Ok(append_trailer(&clean, signature_json));
        };
        let moov = &top.boxes[moov_idx];
        let moov_parsed = Self::parse_boxes(moov.data, 0, moov.data.len());
        let udta_idx = moov_parsed.boxes.iter().position(|b| b.kind == "udta");

        let (existing, udta_trailing): (Vec<&[u8]>, &[u8]) = match udta_idx {
            Some(i) => {
                let u = &moov_parsed.boxes[i];
                let p = Self::parse_boxes(u.data, 0, u.data.len());
                (p.boxes.iter().map(|b| b.raw).collect(), p.trailing)
            }
            None => (Vec::new(), &[][..]),
        };
        let mut udta_parts = existing;
        udta_parts.push(&majk_box); // box-aligned, right after the real children
        udta_parts.push(udta_trailing); // unparseable leftovers go to the very end
        let new_udta = Self::build_box("udta", &concat_bytes(&udta_parts));

        let mut new_children: Vec<&[u8]> = Vec::new();
        match udta_idx {
            Some(ui) => {
                for (i, c) in moov_parsed.boxes.iter().enumerate() {
                    new_children.push(if i == ui { &new_udta } else { c.raw });
                }
            }
            None => {
                new_children.extend(moov_parsed.boxes.iter().map(|c| c.raw));
                new_children.push(&new_udta);
            }
        }
        new_children.push(moov_parsed.trailing);
        let new_moov = Self::build_box("moov", &concat_bytes(&new_children));

        let mut parts: Vec<&[u8]> = Vec::new();
        for (i, b) in top.boxes.iter().enumerate() {
            parts.push(if i == moov_idx { &new_moov } else { b.raw });
        }
        parts.push(top.trailing);
        Ok(concat_bytes(&parts))
    }

    fn extract(&self, bytes: &[u8]) -> MajikSignatureResult<Option<String>> {
        if !self.can_handle(bytes, None) {
            return Ok(None);
        }
        let top = Self::parse_boxes(bytes, 0, bytes.len());
        let Some(moov) = top.boxes.iter().find(|b| b.kind == "moov") else {
            return Ok(extract_trailer(bytes).map(|(json, _)| json));
        };
        let moov_children = Self::parse_boxes(moov.data, 0, moov.data.len());
        let Some(udta) = moov_children.boxes.iter().find(|b| b.kind == "udta") else { return Ok(None) };
        let udta_children = Self::parse_boxes(udta.data, 0, udta.data.len());
        Ok(udta_children.boxes.iter().find(|b| b.kind == MP4_BOX_TYPE).map(|m| text_decode(m.data)))
    }

    fn strip(&self, bytes: &[u8]) -> MajikSignatureResult<Vec<u8>> {
        if !self.can_handle(bytes, None) {
            return Ok(bytes.to_vec());
        }
        let top = Self::parse_boxes(bytes, 0, bytes.len());
        let Some(moov_idx) = top.boxes.iter().position(|b| b.kind == "moov") else {
            return Ok(match extract_trailer(bytes) {
                Some((_, original)) => original,
                None => bytes.to_vec(),
            });
        };
        let moov = &top.boxes[moov_idx];
        let moov_parsed = Self::parse_boxes(moov.data, 0, moov.data.len());
        let Some(udta_idx) = moov_parsed.boxes.iter().position(|b| b.kind == "udta") else {
            return Ok(bytes.to_vec());
        };
        let udta = &moov_parsed.boxes[udta_idx];
        let udta_parsed = Self::parse_boxes(udta.data, 0, udta.data.len());
        let filtered: Vec<&BoxRef<'_>> =
            udta_parsed.boxes.iter().filter(|b| b.kind != MP4_BOX_TYPE).collect();

        let new_udta;
        let mut new_children: Vec<&[u8]> = Vec::new();
        if filtered.is_empty() && udta_parsed.trailing.is_empty() {
            for (i, c) in moov_parsed.boxes.iter().enumerate() {
                if i != udta_idx {
                    new_children.push(c.raw);
                }
            }
        } else {
            let mut parts: Vec<&[u8]> = filtered.iter().map(|b| b.raw).collect();
            parts.push(udta_parsed.trailing);
            new_udta = Self::build_box("udta", &concat_bytes(&parts));
            for (i, c) in moov_parsed.boxes.iter().enumerate() {
                new_children.push(if i == udta_idx { &new_udta } else { c.raw });
            }
        }
        new_children.push(moov_parsed.trailing);
        let new_moov = Self::build_box("moov", &concat_bytes(&new_children));

        let mut parts: Vec<&[u8]> = Vec::new();
        for (i, b) in top.boxes.iter().enumerate() {
            parts.push(if i == moov_idx { &new_moov } else { b.raw });
        }
        parts.push(top.trailing);
        Ok(concat_bytes(&parts))
    }
}
