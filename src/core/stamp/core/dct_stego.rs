//! Port of `core/stamp/core/dct-stego.ts` — 8×8 block DCT steganography.
//!
//! ### Deliberate difference from the TS implementation
//! The TS embedder picks, per block, the *first* of four coefficients whose magnitude is ≥ 4 and
//! encodes the bit in the parity of `round(coefficient)` (step 1). That cannot round-trip: the
//! ±1 edit can push the coefficient under the threshold, and ordinary pixel rounding (±0.5 per
//! pixel) flips parity at step 1 — and because blocks are skipped adaptively, a single such
//! event shifts every later bit, which Reed-Solomon cannot repair (it fixes substitutions, not
//! shifts). It fails even on a lossless PNG round trip.
//!
//! This port keeps the 8×8 luma-DCT idea, the 150-byte stub and the RS(225,150) layer, but uses
//! standard **quantization-index modulation**: exactly one bit per block, in one fixed
//! mid-frequency coefficient, with the bit stored as the parity of `round(c / STEP)`. There is no
//! block skipping, so a damaged block is a bit *substitution* that Reed-Solomon repairs. With
//! `STEP = 24` the layer tolerates pixel rounding and JPEG recompression well beyond Q70.
//! Consequently DCT layers are **not** wire-compatible with the (non-functional) TS ones.
//!
//! JS `Math.round` rounds half *up*; [`js_round`] reproduces that for the pixel conversions.

use std::sync::OnceLock;

const ZIGZAG: [(usize, usize); 64] = [
    (0, 0),
    (0, 1),
    (1, 0),
    (2, 0),
    (1, 1),
    (0, 2),
    (0, 3),
    (1, 2),
    (2, 1),
    (3, 0),
    (4, 0),
    (3, 1),
    (2, 2),
    (1, 3),
    (0, 4),
    (0, 5),
    (1, 4),
    (2, 3),
    (3, 2),
    (4, 1),
    (5, 0),
    (6, 0),
    (5, 1),
    (4, 2),
    (3, 3),
    (2, 4),
    (1, 5),
    (0, 6),
    (0, 7),
    (1, 6),
    (2, 5),
    (3, 4),
    (4, 3),
    (5, 2),
    (6, 1),
    (7, 0),
    (7, 1),
    (6, 2),
    (5, 3),
    (4, 4),
    (3, 5),
    (2, 6),
    (1, 7),
    (2, 7),
    (3, 6),
    (4, 5),
    (5, 4),
    (6, 3),
    (7, 2),
    (7, 3),
    (6, 4),
    (5, 5),
    (4, 6),
    (3, 7),
    (4, 7),
    (5, 6),
    (6, 5),
    (7, 4),
    (7, 5),
    (6, 6),
    (5, 7),
    (6, 7),
    (7, 6),
    (7, 7),
];

/// The single coefficient used for every block: zigzag index 8 → (row 2, col 1).
const EMBED_POSITION: (usize, usize) = ZIGZAG[8];

/// QIM quantization step (in DCT-coefficient units).
const STEP: f64 = 24.0;

/// ECMAScript `Math.round`.
pub fn js_round(x: f64) -> f64 {
    let f = x.floor();
    if x - f >= 0.5 {
        f + 1.0
    } else {
        f
    }
}

fn clamp255(v: f64) -> f64 {
    v.clamp(0.0, 255.0)
}

struct Tables {
    cos: [[f64; 8]; 8],
    scale: [f64; 8],
}

fn tables() -> &'static Tables {
    static T: OnceLock<Tables> = OnceLock::new();
    T.get_or_init(|| {
        let n = 8usize;
        let mut cos = [[0.0f64; 8]; 8];
        let mut scale = [0.0f64; 8];
        for (k, (cos_row, scale_value)) in cos.iter_mut().zip(scale.iter_mut()).enumerate() {
            for (i, value) in cos_row.iter_mut().enumerate() {
                *value = ((std::f64::consts::PI * k as f64 * (2 * i + 1) as f64) / (2 * n) as f64).cos();
            }
            *scale_value = if k == 0 { (1.0 / n as f64).sqrt() } else { (2.0 / n as f64).sqrt() };
        }
        Tables { cos, scale }
    })
}

/// Embed `data` into `pixels` (RGBA8, modified in place). Returns the number of bits written
/// (one per 8×8 block, in raster order, until the data is exhausted or the image is full).
pub fn dct_embed(pixels: &mut [u8], width: usize, height: usize, data: &[u8]) -> usize {
    let bits = bytes_to_bits(data);
    let blocks_x = width / 8;
    let blocks_y = height / 8;
    let (row, col) = EMBED_POSITION;
    let idx = row * 8 + col;
    let mut written = 0usize;

    'outer: for by in 0..blocks_y {
        for bx in 0..blocks_x {
            if written >= bits.len() {
                break 'outer;
            }
            let block = extract_luma_block(pixels, width, bx * 8, by * 8);
            let mut dct = dct2d_8x8(&block);
            let scaled = dct[idx] / STEP;
            let mut q = js_round(scaled);
            if (q as i64).rem_euclid(2) as u8 != bits[written] {
                // Move to the nearest cell of the right parity.
                q += if scaled >= q { 1.0 } else { -1.0 };
            }
            dct[idx] = q * STEP;
            let restored = idct2d_8x8(&dct);
            write_luma_block(pixels, width, bx * 8, by * 8, &restored);
            written += 1;
        }
    }
    written
}

/// Extract `num_bytes` bytes (fewer if the image has fewer blocks).
pub fn dct_extract(pixels: &[u8], width: usize, height: usize, num_bytes: usize) -> Vec<u8> {
    let num_bits = num_bytes * 8;
    let mut bits: Vec<u8> = Vec::with_capacity(num_bits);
    let blocks_x = width / 8;
    let blocks_y = height / 8;
    let (row, col) = EMBED_POSITION;
    let idx = row * 8 + col;

    'outer: for by in 0..blocks_y {
        for bx in 0..blocks_x {
            if bits.len() >= num_bits {
                break 'outer;
            }
            let block = extract_luma_block(pixels, width, bx * 8, by * 8);
            let dct = dct2d_8x8(&block);
            let q = js_round(dct[idx] / STEP);
            bits.push((q as i64).rem_euclid(2) as u8);
        }
    }
    bits_to_bytes(&bits)
}

/// Conservative byte capacity (kept at the TS 60 % factor so size errors match).
pub fn dct_capacity(width: usize, height: usize) -> usize {
    let blocks = (width / 8) * (height / 8);
    ((blocks as f64 * 0.6) / 8.0).floor() as usize
}

fn dct2d_8x8(block: &[f64; 64]) -> [f64; 64] {
    let t = tables();
    let mut tmp = [0.0f64; 64];
    let mut out = [0.0f64; 64];
    for row in 0..8 {
        for k in 0..8 {
            let mut sum = 0.0;
            for n in 0..8 {
                sum += block[row * 8 + n] * t.cos[k][n];
            }
            tmp[row * 8 + k] = t.scale[k] * sum;
        }
    }
    for col in 0..8 {
        for k in 0..8 {
            let mut sum = 0.0;
            for n in 0..8 {
                sum += tmp[n * 8 + col] * t.cos[k][n];
            }
            out[k * 8 + col] = t.scale[k] * sum;
        }
    }
    out
}

fn idct2d_8x8(dct: &[f64; 64]) -> [f64; 64] {
    let t = tables();
    let mut tmp = [0.0f64; 64];
    let mut out = [0.0f64; 64];
    for row in 0..8 {
        for n in 0..8 {
            let mut sum = t.scale[0] * dct[row * 8];
            for k in 1..8 {
                sum += t.scale[k] * dct[row * 8 + k] * t.cos[k][n];
            }
            tmp[row * 8 + n] = sum;
        }
    }
    for col in 0..8 {
        for n in 0..8 {
            let mut sum = t.scale[0] * tmp[col];
            for k in 1..8 {
                sum += t.scale[k] * tmp[k * 8 + col] * t.cos[k][n];
            }
            out[n * 8 + col] = clamp255(js_round(sum));
        }
    }
    out
}

fn extract_luma_block(pixels: &[u8], width: usize, block_x: usize, block_y: usize) -> [f64; 64] {
    let mut block = [0.0f64; 64];
    for y in 0..8 {
        for x in 0..8 {
            let idx = ((block_y + y) * width + (block_x + x)) * 4;
            block[y * 8 + x] =
                0.299 * pixels[idx] as f64 + 0.587 * pixels[idx + 1] as f64 + 0.114 * pixels[idx + 2] as f64;
        }
    }
    block
}

fn write_luma_block(pixels: &mut [u8], width: usize, block_x: usize, block_y: usize, luma: &[f64; 64]) {
    for y in 0..8 {
        for x in 0..8 {
            let idx = ((block_y + y) * width + (block_x + x)) * 4;
            let (r, g, b) = (pixels[idx] as f64, pixels[idx + 1] as f64, pixels[idx + 2] as f64);
            let cb = -0.169 * r - 0.331 * g + 0.5 * b;
            let cr = 0.5 * r - 0.419 * g - 0.081 * b;
            let y1 = luma[y * 8 + x];
            pixels[idx] = clamp255(js_round(y1 + 1.402 * cr)) as u8;
            pixels[idx + 1] = clamp255(js_round(y1 - 0.344 * cb - 0.714 * cr)) as u8;
            pixels[idx + 2] = clamp255(js_round(y1 + 1.772 * cb)) as u8;
        }
    }
}

fn bytes_to_bits(bytes: &[u8]) -> Vec<u8> {
    let mut bits = Vec::with_capacity(bytes.len() * 8);
    for &byte in bytes {
        for i in (0..8).rev() {
            bits.push((byte >> i) & 1);
        }
    }
    bits
}

fn bits_to_bytes(bits: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0u8; bits.len().div_ceil(8)];
    for (i, &b) in bits.iter().enumerate() {
        if b != 0 {
            bytes[i / 8] |= 1 << (7 - (i % 8));
        }
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn js_round_matches_ecmascript() {
        assert_eq!(js_round(2.5), 3.0);
        assert_eq!(js_round(-2.5), -2.0);
        assert_eq!(js_round(-2.6), -3.0);
        assert_eq!(js_round(0.49), 0.0);
    }
}
