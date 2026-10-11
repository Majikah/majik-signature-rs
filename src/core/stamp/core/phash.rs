//! Port of `core/stamp/core/phash.ts` — 64-bit DCT perceptual hash.

use crate::core::errors::{MajikSignatureError, MajikSignatureResult};

/// 64-bit pHash as 16 hex chars. `pixels` is RGBA8.
pub fn compute_p_hash(pixels: &[u8], width: usize, height: usize) -> String {
    let small = resize_to_grayscale(pixels, width, height, 32, 32);
    let dct = dct2d(&small, 32, 32);

    let mut low_freq: Vec<f64> = Vec::with_capacity(63);
    for y in 0..8 {
        for x in 0..8 {
            if x == 0 && y == 0 {
                continue; // skip DC
            }
            low_freq.push(dct[y * 32 + x]);
        }
    }
    let mut sorted = low_freq.clone();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let median = sorted[sorted.len() / 2];

    let mut high: u32 = 0;
    let mut low: u32 = 0;
    for (i, v) in low_freq.iter().enumerate().take(63) {
        let bit = u32::from(*v > median);
        if i < 32 {
            high |= bit << i;
        } else {
            low |= bit << (i - 32);
        }
    }
    format!("{high:08x}{low:08x}")
}

pub fn hamming_distance(hash_a: &str, hash_b: &str) -> MajikSignatureResult<u32> {
    if hash_a.len() != 16 || hash_b.len() != 16 {
        return Err(MajikSignatureError::new("pHash must be a 16-character hex string"));
    }
    let mut dist = 0;
    for i in (0..16).step_by(4) {
        let a = u16::from_str_radix(&hash_a[i..i + 4], 16)
            .map_err(|_| MajikSignatureError::new("pHash must be a 16-character hex string"))?;
        let b = u16::from_str_radix(&hash_b[i..i + 4], 16)
            .map_err(|_| MajikSignatureError::new("pHash must be a 16-character hex string"))?;
        dist += (a ^ b).count_ones();
    }
    Ok(dist)
}

pub fn p_hash_matches(hash_a: &str, hash_b: &str, threshold: u32) -> MajikSignatureResult<bool> {
    Ok(hamming_distance(hash_a, hash_b)? <= threshold)
}

fn resize_to_grayscale(pixels: &[u8], src_w: usize, src_h: usize, dst_w: usize, dst_h: usize) -> Vec<f64> {
    let mut out = vec![0.0f64; dst_w * dst_h];
    let x_ratio = src_w as f64 / dst_w as f64;
    let y_ratio = src_h as f64 / dst_h as f64;
    for dy in 0..dst_h {
        for dx in 0..dst_w {
            let sx = (dx as f64 + 0.5) * x_ratio - 0.5;
            let sy = (dy as f64 + 0.5) * y_ratio - 0.5;
            let sx0 = sx.floor().max(0.0) as usize;
            let sy0 = sy.floor().max(0.0) as usize;
            let sx1 = (src_w - 1).min(sx0 + 1);
            let sy1 = (src_h - 1).min(sy0 + 1);
            let fx = sx - sx0 as f64;
            let fy = sy - sy0 as f64;
            let p00 = to_gray(pixels, sx0, sy0, src_w);
            let p10 = to_gray(pixels, sx1, sy0, src_w);
            let p01 = to_gray(pixels, sx0, sy1, src_w);
            let p11 = to_gray(pixels, sx1, sy1, src_w);
            out[dy * dst_w + dx] =
                p00 * (1.0 - fx) * (1.0 - fy) + p10 * fx * (1.0 - fy) + p01 * (1.0 - fx) * fy + p11 * fx * fy;
        }
    }
    out
}

fn to_gray(pixels: &[u8], x: usize, y: usize, width: usize) -> f64 {
    let idx = (y * width + x) * 4;
    0.2126 * pixels[idx] as f64 + 0.7152 * pixels[idx + 1] as f64 + 0.0722 * pixels[idx + 2] as f64
}

fn dct2d(data: &[f64], w: usize, h: usize) -> Vec<f64> {
    let mut result = vec![0.0f64; w * h];
    let mut row = vec![0.0f64; w];
    for y in 0..h {
        row.copy_from_slice(&data[y * w..y * w + w]);
        let d = dct1d(&row);
        result[y * w..y * w + w].copy_from_slice(&d);
    }
    let mut col = vec![0.0f64; h];
    for x in 0..w {
        for y in 0..h {
            col[y] = result[y * w + x];
        }
        let d = dct1d(&col);
        for y in 0..h {
            result[y * w + x] = d[y];
        }
    }
    result
}

fn dct1d(signal: &[f64]) -> Vec<f64> {
    let n = signal.len();
    let mut out = vec![0.0f64; n];
    let pi_over_2n = std::f64::consts::PI / (2 * n) as f64;
    for (k, value) in out.iter_mut().enumerate() {
        let mut sum = 0.0;
        for (i, s) in signal.iter().enumerate() {
            sum += s * (pi_over_2n * k as f64 * (2 * i + 1) as f64).cos();
        }
        let scale = if k == 0 { (1.0 / n as f64).sqrt() } else { (2.0 / n as f64).sqrt() };
        *value = scale * sum;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_images_have_zero_distance() {
        let (w, h) = (64usize, 64usize);
        let mut px = vec![255u8; w * h * 4];
        for y in 0..h {
            for x in 0..w {
                let v = ((x * 4) ^ (y * 3)) as u8;
                let i = (y * w + x) * 4;
                px[i] = v;
                px[i + 1] = v / 2;
                px[i + 2] = 255 - v;
            }
        }
        let a = compute_p_hash(&px, w, h);
        let b = compute_p_hash(&px, w, h);
        assert_eq!(a.len(), 16);
        assert_eq!(hamming_distance(&a, &b).unwrap(), 0);
    }
}
