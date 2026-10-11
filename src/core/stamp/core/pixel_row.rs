//! Port of `core/stamp/core/pixel-row.ts` — signature stored in extra pixel rows appended below
//! the image (RGB bytes, XOR-masked with the bottom-edge average colour).

use crate::core::errors::{MajikSignatureError, MajikSignatureResult};

const MAGIC: [u8; 4] = [0x4d, 0x52, 0x4f, 0x57]; // "MROW"
const VERSION: u32 = 1;
const HEADER_SIZE: usize = 20;
/// Sanity limit on appended rows.
const MAX_ROWS: usize = 32;

#[derive(Debug, Clone)]
pub struct PixelRowEmbedResult {
    pub pixels: Vec<u8>,
    pub width: usize,
    pub height: usize,
    pub rows_added: usize,
}

#[derive(Debug, Clone)]
pub struct PixelRowExtractResult {
    pub signature_json: String,
    pub rows_found: usize,
    pub original_pixels: Vec<u8>,
    pub original_width: usize,
    pub original_height: usize,
}

fn js_round_div(sum: u64, n: u64) -> u8 {
    // Math.round(sum / n) for non-negative values.
    ((sum as f64 / n as f64) + 0.5).floor() as u8
}

pub fn pixel_row_embed(
    pixels: &[u8],
    width: usize,
    height: usize,
    signature_json: &str,
) -> MajikSignatureResult<PixelRowEmbedResult> {
    let payload = signature_json.as_bytes();
    let bytes_per_row = width * 3; // RGB only
    let total_bytes = HEADER_SIZE + payload.len();
    let rows_needed = total_bytes.div_ceil(bytes_per_row);
    if rows_needed > MAX_ROWS {
        return Err(MajikSignatureError::new(format!(
            "Signature too large for pixel row embedding: needs {rows_needed} rows, max is {MAX_ROWS}. Payload is {} bytes, image width is {width}px.",
            payload.len()
        )));
    }

    let (edge_r, edge_g, edge_b) = sample_bottom_edge(pixels, width, height);
    let mut block = vec![0u8; rows_needed * bytes_per_row];
    let mut offset = 0;
    block[offset..offset + 4].copy_from_slice(&MAGIC);
    offset += 4;
    block[offset..offset + 4].copy_from_slice(&VERSION.to_be_bytes());
    offset += 4;
    block[offset..offset + 4].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    offset += 4;
    block[offset..offset + 4].copy_from_slice(&(rows_needed as u32).to_be_bytes());
    offset += 4;
    block[offset] = edge_r;
    block[offset + 1] = edge_g;
    block[offset + 2] = edge_b;
    block[offset + 3] = 0x00;
    offset += 4;

    let key = [edge_r, edge_g, edge_b];
    for (i, &b) in payload.iter().enumerate() {
        block[offset + i] = b ^ key[i % 3];
    }

    let new_height = height + rows_needed;
    let mut new_pixels = vec![0u8; width * new_height * 4];
    new_pixels[..pixels.len().min(width * height * 4)].copy_from_slice(&pixels[..width * height * 4]);
    let append_start = width * height * 4;
    let mut block_offset = 0;
    for row in 0..rows_needed {
        for x in 0..width {
            let po = append_start + (row * width + x) * 4;
            new_pixels[po] = block[block_offset];
            new_pixels[po + 1] = block[block_offset + 1];
            new_pixels[po + 2] = block[block_offset + 2];
            new_pixels[po + 3] = 255;
            block_offset += 3;
        }
    }
    Ok(PixelRowEmbedResult { pixels: new_pixels, width, height: new_height, rows_added: rows_needed })
}

pub fn pixel_row_extract(pixels: &[u8], width: usize, height: usize) -> Option<PixelRowExtractResult> {
    let bytes_per_row = width * 3;
    let max_candidates = MAX_ROWS.min(height.saturating_sub(1));
    for candidate_rows in 1..=max_candidates {
        let appended_start = height - candidate_rows;
        let first_row_offset = appended_start * width * 4;
        let mut header = [0u8; HEADER_SIZE];
        for (i, h) in header.iter_mut().enumerate() {
            let pixel_index = i / 3;
            let channel = i % 3;
            *h = *pixels.get(first_row_offset + pixel_index * 4 + channel)?;
        }
        if header[..4] != MAGIC {
            continue;
        }
        let rd =
            |o: usize| u32::from_be_bytes([header[o], header[o + 1], header[o + 2], header[o + 3]]) as usize;
        if rd(4) as u32 != VERSION {
            continue;
        }
        let payload_length = rd(8);
        let row_count = rd(12);
        let key = [header[16], header[17], header[18]];
        if row_count != candidate_rows {
            continue;
        }
        if payload_length > (row_count * bytes_per_row).saturating_sub(HEADER_SIZE) {
            continue;
        }
        if payload_length == 0 {
            continue;
        }
        let mut raw = vec![0u8; payload_length];
        let mut ok = true;
        for (i, r) in raw.iter_mut().enumerate() {
            let byte_index = HEADER_SIZE + i;
            let pixel_index = byte_index / 3;
            let channel = byte_index % 3;
            let row_index = pixel_index / width;
            let col_index = pixel_index % width;
            let po = (appended_start + row_index) * width * 4 + col_index * 4 + channel;
            match pixels.get(po) {
                Some(v) => *r = v ^ key[i % 3],
                None => {
                    ok = false;
                    break;
                }
            }
        }
        if !ok {
            continue;
        }
        let signature_json = String::from_utf8_lossy(&raw).into_owned();
        let parsed: serde_json::Value = match serde_json::from_str(&signature_json) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let truthy = |k: &str| {
            parsed
                .get(k)
                .map(|v| {
                    !matches!(v, serde_json::Value::Null | serde_json::Value::Bool(false))
                        && v != &serde_json::json!(0)
                        && v != &serde_json::json!("")
                })
                .unwrap_or(false)
        };
        if !truthy("version") || !truthy("edSignature") || !truthy("mlDsaSignature") {
            continue;
        }
        let original_height = appended_start;
        return Some(PixelRowExtractResult {
            signature_json,
            rows_found: candidate_rows,
            original_pixels: pixels[..width * original_height * 4].to_vec(),
            original_width: width,
            original_height,
        });
    }
    None
}

pub fn pixel_row_has_signature(pixels: &[u8], width: usize, height: usize) -> bool {
    pixel_row_extract(pixels, width, height).is_some()
}

/// `(pixels, width, height)` with any appended signature rows removed.
pub fn pixel_row_strip(pixels: &[u8], width: usize, height: usize) -> (Vec<u8>, usize, usize) {
    match pixel_row_extract(pixels, width, height) {
        Some(r) => (r.original_pixels, r.original_width, r.original_height),
        None => (pixels.to_vec(), width, height),
    }
}

fn sample_bottom_edge(pixels: &[u8], width: usize, height: usize) -> (u8, u8, u8) {
    if height == 0 || width == 0 {
        return (255, 255, 255);
    }
    let row_start = (height - 1) * width * 4;
    let (mut sr, mut sg, mut sb) = (0u64, 0u64, 0u64);
    for x in 0..width {
        let idx = row_start + x * 4;
        sr += pixels[idx] as u64;
        sg += pixels[idx + 1] as u64;
        sb += pixels[idx + 2] as u64;
    }
    (js_round_div(sr, width as u64), js_round_div(sg, width as u64), js_round_div(sb, width as u64))
}
