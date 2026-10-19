//! # majik-signature
//!
//! Pure-Rust port of the TypeScript `@majikah/majik-signature`: hybrid post-quantum content
//! signing (Ed25519 + ML-DSA-87) for the Majikah ecosystem, built on [`majik_key`].
//!
//! Layout mirrors the TS source tree: `index.ts` → this file / `mod.rs`,
//! `majik-signature.ts` → [`MajikSignature`], `core/**` → [`core`], `anchor/**` → [`anchor`].

pub mod anchor;
#[cfg(feature = "cli")]
pub mod cli_core;
pub mod core;
mod majik_signature;

// ── Main class ──────────────────────────────────────────────────────────────
pub use crate::majik_signature::*;

// ── Types / errors / constants ──────────────────────────────────────────────
pub use crate::anchor::types::*;
pub use crate::core::cbor::*;
pub use crate::core::constants::*;
pub use crate::core::errors::*;
pub use crate::core::types::*;

// ── Envelope / map / embed / order ──────────────────────────────────────────
pub use crate::core::embed::embedded_envelope_codec::{
    parse_embedded_envelope, serialize_embedded_envelope, EMBEDDED_CBOR_PREFIX,
};
pub use crate::core::embed::majik_embed::*;
pub use crate::core::envelope::*;
pub use crate::core::mjksmap::MajikSignatureMap;
pub use crate::core::order::*;
pub use crate::core::stamp::core::types::{
    ImageMimeType, ImageSignOptions, ImageSignatureStub, ImageVerificationResult, VerificationLayer,
};
pub use crate::core::stamp::{ImageSignatureError, MajikImageSignature, StampResult};

// ── Low-level utilities (opt-in) ────────────────────────────────────────────
pub use crate::core::hash::{base64_to_bytes, bytes_to_base64, hash_content};
pub use crate::core::payload::{build_signing_payload, build_tsa_canonical_bytes, PayloadFields};
pub use crate::core::validator::MajikSignatureValidator;
