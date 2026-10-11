//! Port of `core/hash.ts` — content hashing and base64 helpers.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use sha2::{Digest, Sha256};

use crate::core::errors::{MajikSignatureError, MajikSignatureResult};

/// SHA-256 hash of arbitrary bytes. Returns the raw 32-byte digest.
pub fn sha256_bytes(input: &[u8]) -> [u8; 32] {
    Sha256::digest(input).into()
}

/// Hash content (strings are hashed as their UTF-8 bytes — pass `s.as_bytes()`).
pub fn hash_content(content: &[u8]) -> [u8; 32] {
    sha256_bytes(content)
}

/// Encode raw bytes to standard (padded) base64.
pub fn bytes_to_base64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

/// Decode standard base64 to raw bytes.
pub fn base64_to_bytes(b64: &str) -> MajikSignatureResult<Vec<u8>> {
    STANDARD.decode(b64).map_err(|e| MajikSignatureError::with_cause("Invalid base64", e))
}
