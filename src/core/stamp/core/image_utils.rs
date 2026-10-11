//! Port of `core/stamp/core/image-utils.ts`.
//!
//! The TS version decodes/encodes through the browser canvas (`createImageBitmap` /
//! `OffscreenCanvas`) or `sharp` on Node. Here the `image` crate does the work, so the
//! `hasBrowserCanvas`/`*Node` variants disappear.

use std::io::Cursor;

use image::codecs::jpeg::JpegEncoder;
use image::{ColorType, ImageEncoder, ImageFormat};

use crate::core::errors::{MajikSignatureError, MajikSignatureResult};
use crate::core::stamp::core::types::ImageMimeType;

/// Minimum edge length (px) for DCT embedding capacity.
pub const MIN_DIMENSION: usize = 640;

#[derive(Debug, Clone)]
pub struct ImagePixels {
    /// RGBA8, row-major.
    pub pixels: Vec<u8>,
    pub width: usize,
    pub height: usize,
}

#[derive(Debug, Clone, Default)]
pub struct ImageEncodeOptions {
    pub mime_type: Option<ImageMimeType>,
    /// 0–1 for JPEG/WebP; default 0.92.
    pub quality: Option<f32>,
}

fn img_err(e: impl std::fmt::Display) -> MajikSignatureError {
    MajikSignatureError::new(format!("Image error: {e}"))
}

/// Decode PNG / JPEG / WebP bytes into RGBA8.
pub fn decode_image(bytes: &[u8]) -> MajikSignatureResult<ImagePixels> {
    let img = image::load_from_memory(bytes).map_err(img_err)?;
    let rgba = img.to_rgba8();
    Ok(ImagePixels { width: rgba.width() as usize, height: rgba.height() as usize, pixels: rgba.into_raw() })
}

/// Encode RGBA8 pixels. JPEG drops alpha; WebP output is lossless (the `image` crate has no lossy
/// WebP encoder), so `quality` only affects JPEG.
pub fn encode_image(
    pixels: &[u8],
    width: usize,
    height: usize,
    options: &ImageEncodeOptions,
) -> MajikSignatureResult<Vec<u8>> {
    let mime = options.mime_type.unwrap_or_default();
    let quality = options.quality.unwrap_or(0.92);
    let (w, h) = (width as u32, height as u32);
    let mut out = Vec::new();
    match mime {
        ImageMimeType::Png => {
            image::codecs::png::PngEncoder::new(&mut out)
                .write_image(pixels, w, h, ColorType::Rgba8.into())
                .map_err(img_err)?;
        }
        ImageMimeType::Jpeg => {
            let rgb: Vec<u8> = pixels.as_chunks::<4>().0.iter().flat_map(|p| [p[0], p[1], p[2]]).collect();
            let q = ((quality * 100.0).round() as i64).clamp(1, 100) as u8;
            JpegEncoder::new_with_quality(&mut out, q)
                .write_image(&rgb, w, h, ColorType::Rgb8.into())
                .map_err(img_err)?;
        }
        ImageMimeType::Webp => {
            let buf = image::RgbaImage::from_raw(w, h, pixels.to_vec())
                .ok_or_else(|| img_err("pixel buffer does not match dimensions"))?;
            buf.write_to(&mut Cursor::new(&mut out), ImageFormat::WebP).map_err(img_err)?;
        }
    }
    Ok(out)
}

/// Centre the image on a white canvas of at least [`MIN_DIMENSION`]² (no-op when large enough).
pub fn pad_to_minimum(img: ImagePixels) -> ImagePixels {
    let ImagePixels { pixels, width, height } = &img;
    if *width >= MIN_DIMENSION && *height >= MIN_DIMENSION {
        return img;
    }
    let new_w = (*width).max(MIN_DIMENSION);
    let new_h = (*height).max(MIN_DIMENSION);
    let mut new_pixels = vec![255u8; new_w * new_h * 4];
    let off_x = (new_w - width) / 2;
    let off_y = (new_h - height) / 2;
    for y in 0..*height {
        for x in 0..*width {
            let s = (y * width + x) * 4;
            let d = ((off_y + y) * new_w + (off_x + x)) * 4;
            new_pixels[d..d + 4].copy_from_slice(&pixels[s..s + 4]);
        }
    }
    ImagePixels { pixels: new_pixels, width: new_w, height: new_h }
}
