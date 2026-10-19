//! Port of `core/constants.ts` — MajikSignature protocol constants.

/// Current per-signer envelope version. Increment when the signing payload format changes.
pub const MAJIK_SIGNATURE_VERSION: u8 = 1;

/// Current multi-sig envelope wrapper version.
/// Kept separate from [`MAJIK_SIGNATURE_VERSION`] so the two can evolve independently.
pub const MAJIK_ENVELOPE_VERSION: u8 = 1;

/// Domain separator prefix prepended to every canonical signing payload.
/// MUST NOT change — changing it invalidates all existing signatures.
pub const MAJIK_SIGNATURE_DOMAIN: &str = "majik-signature-v1:";

/// Domain separator for the seal hash payload.
pub const MAJIK_SEAL_DOMAIN: &str = "majik-seal-v1:";

/// Supported content type hints (advisory only — verification does not enforce them).
pub mod content_types {
    pub const BINARY: &str = "application/octet-stream";
    pub const JSON: &str = "application/json";
    pub const TEXT: &str = "text/plain";
    pub const PDF: &str = "application/pdf";
    pub const WAV: &str = "audio/wav";
    pub const MP3: &str = "audio/mpeg";
    pub const FLAC: &str = "audio/flac";
    pub const PNG: &str = "image/png";
    pub const JPEG: &str = "image/jpeg";
    pub const WEBP: &str = "image/webp";
}

/// TS `ContentType` is `known | string`; in Rust it is simply a string.
pub type ContentType = String;

/// Minimum base64 length sanity checks.
pub const MIN_ED_PUBLIC_KEY_B64_LEN: usize = 40;
pub const MIN_DSA_PUBLIC_KEY_B64_LEN: usize = 100;
pub const MIN_SIGNATURE_B64_LEN: usize = 80;
pub const CONTENT_HASH_B64_LEN: usize = 44;

/// Allowlist hash is also a SHA-256 output — identical length to [`CONTENT_HASH_B64_LEN`].
pub const ALLOWLIST_HASH_B64_LEN: usize = 44;

/// Seal hash is SHA3-512 → 64 bytes → 128 hex chars.
pub const SEAL_HASH_HEX_LEN: usize = 128;

pub const MAJIK_TIMESTAMP_VERSION: u8 = 1;
pub const MAJIK_TSA_DOMAIN: &str = "majikah-tsa-v-1:";

pub const MAJIK_NOTARY_VERSION: u8 = 1;
pub const MAJIK_NOTARY_MEMO_DOMAIN: &str = "majik-notary-v-1:";

// ─── Key / signature sizes (validated by `MajikSignatureValidator`) ──────────
pub const ED25519_PUBLIC_KEY_LEN: usize = 32;
pub const ED25519_SECRET_KEY_LEN: usize = 64;
pub const ML_DSA_87_PUBLIC_KEY_LEN: usize = 2592;
pub const ML_DSA_87_SECRET_KEY_LEN: usize = 4896;
pub const ML_DSA_87_SIGNATURE_LEN: usize = 4627;

// ─── MJKSIG binary format ────────────────────────────────────────────────────
//
// Layout: [magic(6)][version(1)][reserved(1)][payloadLen(4, BE u32)][payload]
//
// Version 1: UTF-8 JSON payload (legacy; read-only for backward compatibility).
// Version 2: CBOR payload (current).
// The header is a fixed 12 bytes across versions; the version byte selects the payload decoder.
pub const MJKSIG_MAGIC: [u8; 6] = [0x4d, 0x4a, 0x4b, 0x53, 0x49, 0x47]; // "MJKSIG"
pub const MJKSIG_MAGIC_LEN: usize = MJKSIG_MAGIC.len();
/// Legacy MJKSIG container encoding: UTF-8 JSON.
pub const MJKSIG_JSON_VERSION: u8 = 0x01;
/// Current MJKSIG container encoding: CBOR.
pub const MJKSIG_CBOR_VERSION: u8 = 0x02;
/// Version used when writing new MJKSIG containers.
pub const MJKSIG_VERSION: u8 = MJKSIG_CBOR_VERSION;
/// Versions accepted when reading MJKSIG containers.
pub const MJKSIG_SUPPORTED_VERSIONS: [u8; 2] = [MJKSIG_JSON_VERSION, MJKSIG_CBOR_VERSION];
pub const MJKSIG_HEADER_LEN: usize = MJKSIG_MAGIC_LEN + 1 + 1 + 4; // 12

pub const MJKSIG_MEDIA_TYPE: &str = "application/vnd.majikah.mjksig";
pub const MJKSIG_FILE_EXTENSION: &str = ".mjksig";

// ─── MJKSMAP binary format ───────────────────────────────────────────────────
//
// Layout: [magic(7)][version(1)][reserved(1)][payloadLen(4, BE u32)][payload JSON]
pub const MJKSMAP_MAGIC: [u8; 7] = [0x4d, 0x4a, 0x4b, 0x53, 0x4d, 0x41, 0x50]; // "MJKSMAP"
pub const MJKSMAP_MAGIC_LEN: usize = MJKSMAP_MAGIC.len();
pub const MJKSMAP_VERSION: u8 = 0x01;
pub const MJKSMAP_SUPPORTED_VERSIONS: [u8; 1] = [MJKSMAP_VERSION];
pub const MJKSMAP_HEADER_LEN: usize = MJKSMAP_MAGIC_LEN + 1 + 1 + 4; // 13

pub const MJKSMAP_MEDIA_TYPE: &str = "application/vnd.majikah.mjksmap";
pub const MJKSMAP_FILE_EXTENSION: &str = ".mjksmap";

/// Conventional name/location when packaged in a signed batch zip.
pub const MJKSMAP_DEFAULT_FILENAME: &str = "signatures.mjksmap";
