mod common;

use common::new_key;
use majik_signature::core::stamp::core::image_utils::{decode_image, encode_image, ImageEncodeOptions};
use majik_signature::*;

/// A textured 704×704 RGB test image (needs mid-frequency energy in most 8×8 blocks).
fn textured_png() -> Vec<u8> {
    let (w, h) = (704usize, 704usize);
    let mut px = vec![255u8; w * h * 4];
    let mut s: u32 = 0x1234_5678;
    for y in 0..h {
        for x in 0..w {
            s = s.wrapping_mul(1664525).wrapping_add(1013904223);
            let noise = ((s >> 24) as i32 - 128) / 2;
            let base = 128.0 + 70.0 * ((x as f64 / 23.0).sin() + (y as f64 / 31.0).cos());
            let v = (base as i32 + noise).clamp(0, 255) as u8;
            let i = (y * w + x) * 4;
            px[i] = v;
            px[i + 1] = v.wrapping_add((x % 64) as u8);
            px[i + 2] = 255 - v;
        }
    }
    encode_image(&px, w, h, &ImageEncodeOptions::default()).unwrap()
}

#[test]
fn stamp_png_roundtrip_both_layers() {
    let key = new_key("stamper");
    let src = textured_png();
    let res = MajikSignature::stamp_image(&src, &key, None).unwrap();
    assert!(MajikSignature::is_stamped(&res.blob));

    let info = MajikSignature::inspect_stamp(&res.blob);
    assert!(info.has_pixel_row && info.has_dct, "{info:?}");

    let v = MajikSignature::verify_stamp(&res.blob, None).unwrap();
    assert!(v.valid, "{:?}", v.reason);
    assert_eq!(v.layer, Some(VerificationLayer::Both));
    assert_eq!(v.signer_id.as_deref(), Some(key.fingerprint()));
    assert!(v.hamming_distance.unwrap() <= 8, "pHash drift {:?}", v.hamming_distance);
}

#[test]
fn stamp_survives_jpeg_recompression_via_dct_layer() {
    let key = new_key("stamper2");
    let res = MajikSignature::stamp_image(&textured_png(), &key, None).unwrap();
    let px = decode_image(&res.blob).unwrap();
    // Drop the pixel-row layer by re-encoding only the original 704 rows as JPEG.
    let rows = 704;
    for quality in [0.95f32, 0.85, 0.75] {
        let jpeg = encode_image(
            &px.pixels[..px.width * rows * 4],
            px.width,
            rows,
            &ImageEncodeOptions { mime_type: Some(ImageMimeType::Jpeg), quality: Some(quality) },
        )
        .unwrap();
        let v = MajikSignature::verify_stamp(&jpeg, None).unwrap();
        assert!(v.valid, "dct layer should survive Q{}: {:?}", (quality * 100.0) as u32, v.reason);
        assert_eq!(v.layer, Some(VerificationLayer::DctOnly));
    }
}

#[test]
fn unsigned_image_is_reported() {
    let v = MajikSignature::verify_stamp(&textured_png(), None).unwrap();
    assert!(!v.valid);
    assert!(v.reason.unwrap().contains("No MajikImageSignature"));
}
