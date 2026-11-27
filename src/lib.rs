//! # majik-signature
//!
//! Pure-Rust port of the TypeScript `@majikah/majik-signature`: hybrid post-quantum content
//! signing (Ed25519 + ML-DSA-87) for the Majikah ecosystem, built on [`majik_key`].
//!
//! The Rust crate follows the same protocol and conceptual layers as the TypeScript
//! implementation, while using Rust-native ownership, synchronous reader APIs,
//! and Rust-specific modules for streaming, format handling, and secret cleanup.

pub mod anchor;
#[cfg(feature = "cli")]
/// Internal CLI command implementations used by the `mjksig` binary.
pub mod cli_core;
/// Core signature, envelope, manifest, streaming, and serialization types and functions.
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
pub use crate::core::payload::build_signature_attestation_bytes;
pub use crate::core::payload::{build_signing_payload, build_tsa_canonical_bytes, PayloadFields};
pub use crate::core::session_context::{build_session_context_hash, MajikSessionSigningContext};
pub use crate::core::validator::MajikSignatureValidator;

// ── Streaming content hashing ────────────────────────────────────────────────
pub use crate::core::streaming::*;
