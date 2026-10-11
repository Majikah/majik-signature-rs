//! Port of `core/stamp/core/reed-solomon.ts` — RS(225,150) over GF(2^8), primitive poly `0x11d`.
//! Hand-ported (not a crate) so the codeword layout and generator roots match TS exactly.

pub const RS_DATA_BYTES: usize = 150; // must match STUB_SIZE
pub const RS_ECC_BYTES: usize = 75; // ~50% overhead → corrects up to 37 byte errors
pub const RS_TOTAL_BYTES: usize = RS_DATA_BYTES + RS_ECC_BYTES; // 225

const PRIMITIVE_POLY: u32 = 0x11d;

struct Gf {
    exp: [u8; 512],
    log: [u8; 256],
}

const fn build_tables() -> Gf {
    let mut exp = [0u8; 512];
    let mut log = [0u8; 256];
    let mut x: u32 = 1;
    let mut i = 0;
    while i < 255 {
        exp[i] = x as u8;
        log[x as usize] = i as u8;
        x <<= 1;
        if x & 0x100 != 0 {
            x ^= PRIMITIVE_POLY;
        }
        i += 1;
    }
    let mut i = 255;
    while i < 512 {
        exp[i] = exp[i - 255];
        i += 1;
    }
    Gf { exp, log }
}

static GF: Gf = build_tables();

fn gf_mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    GF.exp[GF.log[a as usize] as usize + GF.log[b as usize] as usize]
}

fn gf_div(a: u8, b: u8) -> Option<u8> {
    if b == 0 {
        return None; // "GF division by zero"
    }
    if a == 0 {
        return Some(0);
    }
    Some(GF.exp[(GF.log[a as usize] as usize + 255 - GF.log[b as usize] as usize) % 255])
}

fn gf_pow(x: u8, power: usize) -> u8 {
    GF.exp[(GF.log[x as usize] as usize * power) % 255]
}

fn gf_inverse(x: u8) -> u8 {
    GF.exp[255 - GF.log[x as usize] as usize]
}

fn poly_mul(p: &[u8], q: &[u8]) -> Vec<u8> {
    let mut result = vec![0u8; p.len() + q.len() - 1];
    for (i, &pi) in p.iter().enumerate() {
        for (j, &qj) in q.iter().enumerate() {
            result[i + j] ^= gf_mul(pi, qj);
        }
    }
    result
}

fn poly_eval(poly: &[u8], x: u8) -> u8 {
    let mut y = poly[0];
    for &c in &poly[1..] {
        y = gf_mul(y, x) ^ c;
    }
    y
}

fn make_generator(n_ecc: usize) -> Vec<u8> {
    let mut g = vec![1u8];
    for i in 0..n_ecc {
        g = poly_mul(&g, &[1, gf_pow(2, i)]);
    }
    g
}

/// Encode up to 150 data bytes into a 225-byte codeword (data zero-padded to 150).
pub fn rs_encode(data: &[u8]) -> Result<Vec<u8>, String> {
    if data.len() > RS_DATA_BYTES {
        return Err(format!("RS encode: data too long ({} > {})", data.len(), RS_DATA_BYTES));
    }
    let mut padded = vec![0u8; RS_DATA_BYTES];
    padded[..data.len()].copy_from_slice(data);
    let generator = make_generator(RS_ECC_BYTES);

    let mut msg = vec![0u8; RS_TOTAL_BYTES];
    msg[..RS_DATA_BYTES].copy_from_slice(&padded);
    for i in 0..RS_DATA_BYTES {
        let coef = msg[i];
        if coef != 0 {
            for j in 1..generator.len() {
                msg[i + j] ^= gf_mul(generator[j], coef);
            }
        }
    }
    let mut result = vec![0u8; RS_TOTAL_BYTES];
    result[..RS_DATA_BYTES].copy_from_slice(&padded);
    result[RS_DATA_BYTES..].copy_from_slice(&msg[RS_DATA_BYTES..]);
    Ok(result)
}

/// Decode a 225-byte codeword; `None` when uncorrectable.
///
/// The TypeScript decoder shares this codeword layout but its error-correction path
/// (Berlekamp-Massey / Forney) miscorrects — it fails to repair even a single flipped byte
/// (verified against the published TS code). This port keeps the exact encoding and the
/// zero-error fast path, and replaces the correction path with a standard BM + Chien +
/// Forney decoder (first consecutive root α⁰), so recompression damage is actually repaired.
pub fn rs_decode(received: &[u8]) -> Option<Vec<u8>> {
    if received.len() != RS_TOTAL_BYTES {
        return None;
    }
    let mut syndromes = vec![0u8; RS_ECC_BYTES];
    let mut has_errors = false;
    for (i, s) in syndromes.iter_mut().enumerate() {
        *s = poly_eval(received, gf_pow(2, i));
        if *s != 0 {
            has_errors = true;
        }
    }
    if !has_errors {
        return Some(received[..RS_DATA_BYTES].to_vec());
    }

    // Error locator Λ(x), coefficients low → high, Λ(0) = 1.
    let lambda = berlekamp_massey(&syndromes)?;
    let n_errors = lambda.len() - 1;
    if n_errors == 0 || n_errors > RS_ECC_BYTES / 2 {
        return None;
    }

    // Chien search: error at polynomial degree d  ⇔  Λ(α^{-d}) = 0.
    let mut degrees: Vec<usize> = Vec::new();
    for d in 0..RS_TOTAL_BYTES {
        let x_inv = gf_pow(2, (255 - d % 255) % 255);
        if eval_low_to_high(&lambda, x_inv) == 0 {
            degrees.push(d);
        }
    }
    if degrees.len() != n_errors {
        return None;
    }

    // Ω(x) = S(x)·Λ(x) mod x^{2t}
    let two_t = RS_ECC_BYTES;
    let mut omega = vec![0u8; two_t];
    for (i, o) in omega.iter_mut().enumerate() {
        let mut acc = 0u8;
        for (j, &l) in lambda.iter().enumerate() {
            if j <= i {
                acc ^= gf_mul(l, syndromes[i - j]);
            }
        }
        *o = acc;
    }
    // Formal derivative Λ'(x): odd-degree terms only (characteristic 2).
    let mut lambda_prime = vec![0u8; lambda.len().saturating_sub(1).max(1)];
    for (i, &c) in lambda.iter().enumerate().skip(1) {
        if i % 2 == 1 {
            lambda_prime[i - 1] = c;
        }
    }

    let mut corrected = received.to_vec();
    for &d in &degrees {
        let x = gf_pow(2, d % 255);
        let x_inv = gf_inverse(x);
        let num = eval_low_to_high(&omega, x_inv);
        let den = eval_low_to_high(&lambda_prime, x_inv);
        let mag = gf_mul(x, gf_div(num, den)?);
        corrected[RS_TOTAL_BYTES - 1 - d] ^= mag;
    }

    // Verify the repair: all syndromes must now vanish.
    for i in 0..RS_ECC_BYTES {
        if poly_eval(&corrected, gf_pow(2, i)) != 0 {
            return None;
        }
    }
    Some(corrected[..RS_DATA_BYTES].to_vec())
}

fn eval_low_to_high(poly: &[u8], x: u8) -> u8 {
    let mut y = 0u8;
    for &c in poly.iter().rev() {
        y = gf_mul(y, x) ^ c;
    }
    y
}

/// Standard Berlekamp-Massey over GF(2^8); returns Λ low → high, or `None` if `L > t`.
fn berlekamp_massey(syndromes: &[u8]) -> Option<Vec<u8>> {
    let n = syndromes.len();
    let mut c: Vec<u8> = vec![1]; // current Λ
    let mut b: Vec<u8> = vec![1]; // previous Λ
    let mut l = 0usize;
    let mut m = 1usize;
    let mut bb = 1u8; // previous discrepancy

    for i in 0..n {
        let mut d = syndromes[i];
        for j in 1..=l {
            if j < c.len() && i >= j {
                d ^= gf_mul(c[j], syndromes[i - j]);
            }
        }
        if d == 0 {
            m += 1;
            continue;
        }
        let coef = gf_div(d, bb)?;
        let t = c.clone();
        if c.len() < b.len() + m {
            c.resize(b.len() + m, 0);
        }
        for (k, &bk) in b.iter().enumerate() {
            c[k + m] ^= gf_mul(coef, bk);
        }
        if 2 * l <= i {
            l = i + 1 - l;
            b = t;
            bb = d;
            m = 1;
        } else {
            m += 1;
        }
    }
    c.truncate(l + 1);
    if l * 2 > n {
        return None;
    }
    Some(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_corrects_errors() {
        let data: Vec<u8> = (0..150u32).map(|i| (i * 7 + 3) as u8).collect();
        let cw = rs_encode(&data).unwrap();
        assert_eq!(cw.len(), RS_TOTAL_BYTES);
        assert_eq!(rs_decode(&cw).unwrap(), data);

        let mut bad = cw.clone();
        for k in 0..30 {
            bad[k * 7] ^= 0x5a; // 30 byte errors (limit is 37)
        }
        assert_eq!(rs_decode(&bad).unwrap(), data);
    }

    #[test]
    fn corrects_exactly_the_maximum_37_errors() {
        let data: Vec<u8> = (0..150u32).map(|i| (i * 31 + 5) as u8).collect();
        let cw = rs_encode(&data).unwrap();
        let mut bad = cw.clone();
        let mut s = 12345u32;
        let mut used = std::collections::HashSet::new();
        while used.len() < 37 {
            s = s.wrapping_mul(1664525).wrapping_add(1013904223);
            let pos = (s >> 8) as usize % RS_TOTAL_BYTES;
            if used.insert(pos) {
                bad[pos] ^= ((s >> 3) as u8) | 1;
            }
        }
        assert_eq!(rs_decode(&bad).unwrap(), data);
    }

    #[test]
    fn too_many_errors_is_rejected_or_wrong() {
        let data = vec![9u8; 150];
        let mut bad = rs_encode(&data).unwrap();
        for k in 0..60 {
            bad[k * 3] ^= 0xff;
        }
        assert_ne!(rs_decode(&bad), Some(data));
    }
}
