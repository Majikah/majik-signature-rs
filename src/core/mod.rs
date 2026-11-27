//! Port of `core/` (the files `index.ts` does not re-export individually are still public here).

/// CBOR codec and wire adapters for signature/envelope container formats.
pub mod cbor;
/// Locale-compatible Base64 ordering helpers shared with the TypeScript implementation.
pub mod collate;
/// Cryptographic protocol domains, wire versions, media types, and parser limits.
pub mod constants;
/// Format-specific file embedding/extraction and high-level orchestration.
pub mod embed;
/// Multi-signer envelope model, validation, and immutable builder operations.
pub mod envelope;
/// Typed error and result types used by the public crate API.
pub mod errors;
/// Hashing and Base64 conversion primitives used by signing and verification.
pub mod hash;
/// Path-indexed detached-signature batch manifest and MJKSMAP container codec.
pub mod mjksmap;
/// Chronological signing-order verification and result types.
pub mod order;
/// Canonical signing-payload builders shared by sign and verify operations.
pub mod payload;
/// SignRoom session-context schema and canonical context hash builder.
pub mod session_context;
/// Experimental dual-layer image stamping helpers; distinct from the core file-signature format.
pub mod stamp;
/// Bounded-memory reader-based hashing and batch signing/verification types.
pub mod streaming;
/// Timestamp parsing and normalization helpers used by verification.
pub mod time;
/// Shared protocol data models and option/result types.
pub mod types;
/// Input shape, size, encoding, and metadata validation helpers.
pub mod validator;
