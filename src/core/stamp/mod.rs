//! Port of `core/stamp/index.ts` — dual-layer, compression-resistant image signing
//! (experimental, as in TS).

pub mod core;
pub mod image_signature;

pub use image_signature::*;
