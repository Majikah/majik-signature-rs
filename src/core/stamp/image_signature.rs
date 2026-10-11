//! Port of `core/stamp/image-signature.ts` — `MajikImageSignature`: dual-layer,
//! compression-resistant image signing. **Experimental** (as in TS — API not stable).
//!
//! Layer 1 (*DCT*): a 150-byte Ed25519-signed stub (pHash + signer + timestamp), Reed-Solomon
//! protected, hidden in mid-frequency DCT coefficients — survives recompression down to ≈ Q70.
//! Layer 2 (*pixel row*): the full hybrid [`MajikSignatureJSON`] in rows appended below the image.
//!
//! ### Deliberate difference from the TS implementation
//! TS hashes the *canvas-encoded PNG bytes* of the DCT image for the layer-2 signature, and on
//! verification re-encodes the pixels and calls `verifyFile` on a PNG that carries no embedded
//! envelope — which cannot succeed, and which would in any case depend on one specific PNG
//! encoder. Here the layer-2 signature covers the **raw RGBA pixel buffer** of the DCT image, so
//! signing and verification are encoder-independent and actually verifiable.

use ed25519_dalek::{Signature as EdSignature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use majik_key::{KeyId, MajikKey};
use zeroize::Zeroizing;

use crate::core::errors::MajikSignatureError;
use crate::core::hash::base64_to_bytes;
use crate::core::stamp::core::dct_stego::{dct_capacity, dct_embed, dct_extract};
use crate::core::stamp::core::image_utils::{
    decode_image, encode_image, pad_to_minimum, ImageEncodeOptions, ImagePixels, MIN_DIMENSION,
};
use crate::core::stamp::core::payload::build_image_signing_payload;
use crate::core::stamp::core::phash::{compute_p_hash, hamming_distance, p_hash_matches};
use crate::core::stamp::core::pixel_row::{pixel_row_embed, pixel_row_extract, pixel_row_strip};
use crate::core::stamp::core::reed_solomon::{rs_decode, rs_encode, RS_TOTAL_BYTES};
use crate::core::stamp::core::stub::{deserialize_stub, serialize_stub};
use crate::core::stamp::core::types::*;
use crate::core::time::now_iso;
use crate::core::types::{MajikSignatureJSON, MajikSignerPublicKeys};
use crate::majik_signature::MajikSignature;

/// Errors of the stamp subsystem (TS `MajikImageSignatureError` / `MajikImageCapacityError`).
#[derive(Debug, thiserror::Error)]
pub enum ImageSignatureError {
    #[error("{0}")]
    Generic(String),
    #[error("Image too small for DCT embedding. At {width}×{height}px, DCT capacity is ~{available} bytes but {needed} bytes needed. Minimum: {min}×{min}px.", min = MIN_DIMENSION)]
    Capacity { width: usize, height: usize, needed: usize, available: usize },
    #[error(transparent)]
    Signature(#[from] MajikSignatureError),
}

pub type ImageResult<T> = Result<T, ImageSignatureError>;

fn gen(msg: impl Into<String>) -> ImageSignatureError {
    ImageSignatureError::Generic(msg.into())
}

/// Result of [`MajikImageSignature::sign`].
#[derive(Debug, Clone)]
pub struct StampResult {
    pub blob: Vec<u8>,
    pub stub: ImageSignatureStub,
    pub full_envelope: MajikSignatureJSON,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PixelRowMeta {
    pub signer_id: String,
    pub timestamp: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DctMeta {
    pub signer_id: String,
    pub timestamp: String,
    pub p_hash: String,
}

#[derive(Debug, Clone, Default)]
pub struct InspectResult {
    pub has_pixel_row: bool,
    pub has_dct: bool,
    pub pixel_row_meta: Option<PixelRowMeta>,
    pub dct_meta: Option<DctMeta>,
}

pub struct MajikImageSignature;

impl MajikImageSignature {
    pub fn sign(
        image: &[u8],
        key: &MajikKey,
        options: Option<&ImageSignOptions>,
    ) -> ImageResult<StampResult> {
        let default_opts = ImageSignOptions::default();
        let options = options.unwrap_or(&default_opts);

        if key.is_locked() {
            return Err(gen("MajikKey is locked. Call unlock() before signing."));
        }
        if !key.has_keys(&[KeyId::Ed25519, KeyId::MlDsa87]) {
            return Err(gen("MajikKey has no signing keys. Re-import via importFromMnemonicBackup()."));
        }

        let decoded = decode_image(image)?;
        let (pixels, width, height) = pixel_row_strip(&decoded.pixels, decoded.width, decoded.height);
        let img = if width < MIN_DIMENSION || height < MIN_DIMENSION {
            pad_to_minimum(ImagePixels { pixels, width, height })
        } else {
            ImagePixels { pixels, width, height }
        };
        let (pixels, width, height) = (img.pixels, img.width, img.height);

        let capacity = dct_capacity(width, height);
        if capacity < RS_TOTAL_BYTES {
            return Err(ImageSignatureError::Capacity {
                width,
                height,
                needed: RS_TOTAL_BYTES,
                available: capacity,
            });
        }

        let p_hash = compute_p_hash(&pixels, width, height);
        let timestamp = options.timestamp.clone().unwrap_or_else(now_iso);
        // The stub has a 32-byte signerId field but a base64 SHA-256 fingerprint is 44 chars, so TS
        // signs the full id and then stores a truncated one — making the DCT signature
        // unverifiable. Here the DCT layer signs exactly what it stores (the 32-byte prefix); the
        // full id lives in layer 2.
        let signer_id = truncate_to_bytes(key.fingerprint(), 32);

        let payload = build_image_signing_payload(&ImageSigningPayloadFields {
            signer_id: &signer_id,
            timestamp: &timestamp,
            p_hash: &p_hash,
        });
        let (ed_sig, ed_pub) = ed25519_sign_with_key(key, &payload)?;

        let stub = ImageSignatureStub {
            p_hash,
            signer_ed_public_key: hex::encode(&ed_pub),
            ed_signature: hex::encode(ed_sig),
            signer_id,
            timestamp: timestamp.clone(),
        };

        // Layer 1 — DCT.
        let mut pixels_with_dct = pixels;
        let encoded = rs_encode(&serialize_stub(&stub).map_err(gen)?).map_err(gen)?;
        let bits_written = dct_embed(&mut pixels_with_dct, width, height, &encoded);
        if bits_written < RS_TOTAL_BYTES * 8 {
            return Err(gen(format!(
                "DCT embedding incomplete: {bits_written} bits written, {} needed. Image may lack sufficient high-magnitude DCT coefficients.",
                RS_TOTAL_BYTES * 8
            )));
        }

        // Layer 2 — full hybrid signature over the DCT image's pixels, stored in appended rows.
        let full_sig = MajikSignature::sign(
            &pixels_with_dct,
            key,
            Some(&crate::core::types::SignOptions {
                content_type: Some("image/majik-signed".into()),
                timestamp: Some(timestamp),
                ..Default::default()
            }),
        )?;
        let full_envelope = full_sig.to_json();
        let row = pixel_row_embed(
            &pixels_with_dct,
            width,
            height,
            &serde_json::to_string(&full_envelope).map_err(|e| gen(e.to_string()))?,
        )?;

        let blob = encode_image(
            &row.pixels,
            row.width,
            row.height,
            &ImageEncodeOptions {
                mime_type: options.output_mime_type,
                quality: Some(options.jpeg_quality.map(|q| q as f32 / 100.0).unwrap_or(0.92)),
            },
        )?;
        Ok(StampResult { blob, stub, full_envelope })
    }

    pub fn verify(image: &[u8], hamming_threshold: Option<u32>) -> ImageResult<ImageVerificationResult> {
        let threshold = hamming_threshold.unwrap_or(8);
        let decoded = decode_image(image)?;

        let row = pixel_row_extract(&decoded.pixels, decoded.width, decoded.height);
        let has_pixel_row = row.is_some();
        let (clean_pixels, clean_w, clean_h) = match &row {
            Some(r) => (r.original_pixels.clone(), r.original_width, r.original_height),
            None => (decoded.pixels, decoded.width, decoded.height),
        };
        let padded = if clean_w < MIN_DIMENSION || clean_h < MIN_DIMENSION {
            pad_to_minimum(ImagePixels { pixels: clean_pixels, width: clean_w, height: clean_h })
        } else {
            ImagePixels { pixels: clean_pixels, width: clean_w, height: clean_h }
        };
        let (clean_pixels, clean_w, clean_h) = (padded.pixels, padded.width, padded.height);

        let raw_dct = dct_extract(&clean_pixels, clean_w, clean_h, RS_TOTAL_BYTES);
        let dct_stub = rs_decode(&raw_dct).and_then(|c| deserialize_stub(&c));
        let has_dct = dct_stub.is_some();

        if !has_pixel_row && !has_dct {
            return Ok(ImageVerificationResult {
                valid: false,
                reason: Some(
                    "No MajikImageSignature found. Image was not signed, or both layers were destroyed (screenshot, heavy crop, or below-Q70 recompression)."
                        .into(),
                ),
                ..Default::default()
            });
        }

        let computed = compute_p_hash(&clean_pixels, clean_w, clean_h);

        // ── DCT layer ──
        let mut dct_valid = false;
        let mut dct_fail: Option<String> = None;
        if let Some(stub) = &dct_stub {
            let dist = hamming_distance(&stub.p_hash, &computed)?;
            if !p_hash_matches(&stub.p_hash, &computed, threshold)? {
                dct_fail =
                    Some(format!("DCT layer: pHash mismatch (Hamming {dist} > threshold {threshold})."));
            } else {
                let payload = build_image_signing_payload(&ImageSigningPayloadFields {
                    signer_id: &stub.signer_id,
                    timestamp: &stub.timestamp,
                    p_hash: &stub.p_hash,
                });
                match verify_ed_hex(&stub.signer_ed_public_key, &payload, &stub.ed_signature) {
                    Ok(true) => dct_valid = true,
                    Ok(false) => dct_fail = Some("DCT layer: Ed25519 signature invalid.".into()),
                    Err(()) => dct_fail = Some("DCT layer: Ed25519 verification error.".into()),
                }
            }
        }

        // ── Pixel-row layer ──
        let mut row_valid = false;
        let mut row_fail: Option<String> = None;
        let mut full_envelope: Option<MajikSignatureJSON> = None;
        let mut row_signer: Option<String> = None;
        let mut row_ts: Option<String> = None;
        let mut row_ed_pub: Option<String> = None;
        if let Some(r) = &row {
            let outcome = (|| -> Result<(), String> {
                let env: MajikSignatureJSON =
                    serde_json::from_str(&r.signature_json).map_err(|e| e.to_string())?;
                full_envelope = Some(env.clone());
                let keys = MajikSignerPublicKeys {
                    signer_id: env.signer_id.clone(),
                    ed_public_key: base64_to_bytes(&env.signer_ed_public_key).map_err(|e| e.to_string())?,
                    ml_dsa_public_key: base64_to_bytes(&env.signer_ml_dsa_public_key)
                        .map_err(|e| e.to_string())?,
                };
                let res =
                    MajikSignature::verify(&clean_pixels, &env, &keys, None).map_err(|e| e.to_string())?;
                if res.valid {
                    row_valid = true;
                    row_signer = Some(env.signer_id.clone());
                    row_ts = Some(env.timestamp.clone());
                    row_ed_pub = Some(hex::encode(&keys.ed_public_key));
                    if let Some(stub) = &dct_stub {
                        // The stub only carries a 32-byte prefix of the signer id.
                        if !stub.signer_id.is_empty()
                            && !row_signer.as_deref().unwrap_or_default().starts_with(stub.signer_id.as_str())
                        {
                            row_valid = false;
                            row_fail = Some(format!(
                                "Layer mismatch: pixel row signerId \"{}\" ≠ DCT signerId \"{}\". Image may be tampered.",
                                row_signer.clone().unwrap_or_default(),
                                stub.signer_id
                            ));
                        }
                    }
                } else {
                    row_fail = Some(format!(
                        "Pixel row layer: {}",
                        res.reason.unwrap_or_else(|| "verification failed.".into())
                    ));
                }
                Ok(())
            })();
            if let Err(e) = outcome {
                row_fail = Some(format!("Pixel row layer: failed to verify ({e})."));
            }
        }

        let dist = match &dct_stub {
            Some(s) => Some(hamming_distance(&s.p_hash, &computed)?),
            None => None,
        };
        let common = |mut r: ImageVerificationResult| {
            r.stored_p_hash = dct_stub.as_ref().map(|s| s.p_hash.clone());
            r.computed_p_hash = Some(computed.clone());
            r.hamming_distance = dist;
            r.full_envelope = full_envelope.clone();
            r
        };

        if has_pixel_row && has_dct {
            let stub = dct_stub.as_ref().expect("has_dct");
            if row_valid && dct_valid {
                return Ok(common(ImageVerificationResult {
                    valid: true,
                    layer: Some(VerificationLayer::Both),
                    signer_id: Some(row_signer.clone().unwrap_or_else(|| stub.signer_id.clone())),
                    timestamp: Some(row_ts.clone().unwrap_or_else(|| stub.timestamp.clone())),
                    signer_ed_public_key: Some(
                        row_ed_pub.clone().unwrap_or_else(|| stub.signer_ed_public_key.clone()),
                    ),
                    ..Default::default()
                }));
            }
            let reasons: Vec<String> = [
                (!row_valid).then(|| row_fail.clone()).flatten(),
                (!dct_valid).then(|| dct_fail.clone()).flatten(),
            ]
            .into_iter()
            .flatten()
            .collect();
            return Ok(common(ImageVerificationResult {
                valid: false,
                layer: Some(VerificationLayer::Both),
                reason: Some(format!("Both layers present but one or more failed: {}", reasons.join(" | "))),
                signer_id: Some(row_signer.clone().unwrap_or_else(|| stub.signer_id.clone())),
                timestamp: Some(row_ts.clone().unwrap_or_else(|| stub.timestamp.clone())),
                ..Default::default()
            }));
        }
        if has_pixel_row && !has_dct {
            return Ok(common(if row_valid {
                ImageVerificationResult {
                    valid: true,
                    layer: Some(VerificationLayer::PixelRow),
                    signer_id: row_signer,
                    timestamp: row_ts,
                    signer_ed_public_key: row_ed_pub,
                    ..Default::default()
                }
            } else {
                ImageVerificationResult {
                    valid: false,
                    layer: Some(VerificationLayer::PixelRow),
                    reason: Some(row_fail.unwrap_or_else(|| "Pixel row failed.".into())),
                    ..Default::default()
                }
            }));
        }
        let stub = dct_stub.as_ref().expect("dct-only branch");
        Ok(common(if dct_valid {
            ImageVerificationResult {
                valid: true,
                layer: Some(VerificationLayer::DctOnly),
                signer_id: Some(stub.signer_id.clone()),
                timestamp: Some(stub.timestamp.clone()),
                signer_ed_public_key: Some(stub.signer_ed_public_key.clone()),
                ..Default::default()
            }
        } else {
            ImageVerificationResult {
                valid: false,
                layer: Some(VerificationLayer::DctOnly),
                reason: Some(dct_fail.unwrap_or_else(|| "DCT verification failed.".into())),
                signer_id: Some(stub.signer_id.clone()),
                timestamp: Some(stub.timestamp.clone()),
                ..Default::default()
            }
        }))
    }

    /// Report which layers are present (never fails; errors yield "nothing found").
    pub fn inspect(image: &[u8]) -> InspectResult {
        let Ok(decoded) = decode_image(image) else { return InspectResult::default() };
        let row = pixel_row_extract(&decoded.pixels, decoded.width, decoded.height);
        let has_pixel_row = row.is_some();
        let (px, w, h) = match &row {
            Some(r) => (r.original_pixels.clone(), r.original_width, r.original_height),
            None => (decoded.pixels, decoded.width, decoded.height),
        };
        let padded = if w < MIN_DIMENSION || h < MIN_DIMENSION {
            pad_to_minimum(ImagePixels { pixels: px, width: w, height: h })
        } else {
            ImagePixels { pixels: px, width: w, height: h }
        };
        let raw = dct_extract(&padded.pixels, padded.width, padded.height, RS_TOTAL_BYTES);
        let dct_stub = rs_decode(&raw).and_then(|c| deserialize_stub(&c));
        let pixel_row_meta = row.and_then(|r| {
            serde_json::from_str::<MajikSignatureJSON>(&r.signature_json)
                .ok()
                .map(|e| PixelRowMeta { signer_id: e.signer_id, timestamp: e.timestamp })
        });
        InspectResult {
            has_pixel_row,
            has_dct: dct_stub.is_some(),
            pixel_row_meta,
            dct_meta: dct_stub.map(|s| DctMeta {
                signer_id: s.signer_id,
                timestamp: s.timestamp,
                p_hash: s.p_hash,
            }),
        }
    }

    pub fn is_signed(image: &[u8]) -> bool {
        let info = Self::inspect(image);
        info.has_pixel_row || info.has_dct
    }
}

fn ed25519_sign_with_key(key: &MajikKey, payload: &[u8]) -> Result<([u8; 64], Vec<u8>), MajikSignatureError> {
    let secret = key
        .get_private_key(KeyId::Ed25519)
        .map_err(|e| MajikSignatureError::key_with_cause("Failed to read Ed25519 secret key", e))?;
    crate::core::validator::MajikSignatureValidator::validate_ed_secret_key(&secret)?;
    let public = key
        .get_public_key(KeyId::Ed25519)
        .map_err(|e| MajikSignatureError::key_with_cause("Failed to read Ed25519 public key", e))?;
    let mut seed = Zeroizing::new([0u8; 32]);
    seed.copy_from_slice(&secret[..32]);
    let sig = SigningKey::from_bytes(&seed).sign(payload).to_bytes();
    Ok((sig, public))
}

fn truncate_to_bytes(s: &str, max: usize) -> String {
    let mut end = s.len().min(max);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

fn verify_ed_hex(pub_hex: &str, payload: &[u8], sig_hex: &str) -> Result<bool, ()> {
    let pk: [u8; 32] = hex::decode(pub_hex).map_err(|_| ())?.try_into().map_err(|_| ())?;
    let vk = VerifyingKey::from_bytes(&pk).map_err(|_| ())?;
    let sig = EdSignature::from_slice(&hex::decode(sig_hex).map_err(|_| ())?).map_err(|_| ())?;
    Ok(vk.verify(payload, &sig).is_ok())
}
