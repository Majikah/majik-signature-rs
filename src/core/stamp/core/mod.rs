//! Port of `core/stamp/core/` primitives.

/// DCT-domain steganographic embedding and extraction primitives for experimental image stamps.
pub mod dct_stego;
/// Browser-independent pixel and image-format helper interfaces used by the stamp core.
pub mod image_utils;
/// Canonical byte construction for compact image-stamp Ed25519 proofs.
pub mod payload;
/// Perceptual image hashing and Hamming-distance comparison helpers.
pub mod phash;
/// Full hybrid envelope embedding/extraction in appended image pixel rows.
pub mod pixel_row;
/// Error-correction encoder/decoder used by the compact image-stamp DCT layer.
pub mod reed_solomon;
/// Fixed-size serialization for the compact Ed25519-only image-stamp proof.
pub mod stub;
/// Public image-stamp proof, option, and result structures.
pub mod types;
