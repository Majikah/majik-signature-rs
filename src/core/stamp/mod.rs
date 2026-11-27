//! Port of `core/stamp/index.ts` — dual-layer, compression-resistant image signing
//! (experimental, as in TS).

/// DCT, perceptual-hash, pixel-row, and error-correction primitives for image stamping.
pub mod core;
/// Experimental dual-layer image-stamp signing and verification API.
pub mod image_signature;

pub use image_signature::*;
