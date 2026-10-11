//! Port of `core/stamp/core/types.ts`.

use serde::{Deserialize, Serialize};

use crate::core::types::MajikSignatureJSON;

/// The 150-byte stub hidden in the DCT layer (hex fields as in TS).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImageSignatureStub {
    /// 16 hex chars (64-bit perceptual hash).
    pub p_hash: String,
    /// 64 hex chars.
    pub signer_ed_public_key: String,
    /// 128 hex chars.
    pub ed_signature: String,
    pub signer_id: String,
    pub timestamp: String,
}

#[derive(Debug, Clone)]
pub struct ImageSigningPayloadFields<'a> {
    pub signer_id: &'a str,
    pub timestamp: &'a str,
    pub p_hash: &'a str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ImageMimeType {
    #[default]
    Png,
    Jpeg,
    Webp,
}

impl ImageMimeType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Png => "image/png",
            Self::Jpeg => "image/jpeg",
            Self::Webp => "image/webp",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ImageSignOptions {
    pub timestamp: Option<String>,
    pub output_mime_type: Option<ImageMimeType>,
    /// 1–100 (TS `jpegQuality`); default 92.
    pub jpeg_quality: Option<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationLayer {
    Both,
    PixelRow,
    DctOnly,
}

#[derive(Debug, Clone, Default)]
pub struct ImageVerificationResult {
    pub valid: bool,
    pub reason: Option<String>,
    pub layer: Option<VerificationLayer>,
    pub signer_id: Option<String>,
    pub timestamp: Option<String>,
    pub stored_p_hash: Option<String>,
    pub computed_p_hash: Option<String>,
    pub hamming_distance: Option<u32>,
    pub signer_ed_public_key: Option<String>,
    pub full_envelope: Option<MajikSignatureJSON>,
}

#[derive(Debug, Clone)]
pub struct DctEmbedResult {
    pub pixels: Vec<u8>,
    pub width: usize,
    pub height: usize,
    pub bits_written: usize,
    pub capacity: usize,
}

#[derive(Debug, Clone)]
pub struct DctExtractResult {
    pub bits: Vec<u8>,
    pub capacity: usize,
}
