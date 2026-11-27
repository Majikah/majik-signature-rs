//! Port of `core/constants.ts` — MajikSignature protocol constants.

/// Current per-signer envelope version. Increment when the signing payload format changes.
pub const MAJIK_SIGNATURE_VERSION: u8 = 1;

/// Current multi-sig envelope wrapper version.
/// Kept separate from [`MAJIK_SIGNATURE_VERSION`] so the two can evolve independently.
pub const MAJIK_ENVELOPE_VERSION: u8 = 1;

/// Domain separator prefix prepended to every canonical signing payload.
/// MUST NOT change — changing it invalidates all existing signatures.
pub const MAJIK_SIGNATURE_DOMAIN: &str = "majik-signature-v1:";

/// Domain separator for TSA digests over unsigned signer records.
pub const MAJIK_SIGNATURE_ATTESTATION_DOMAIN: &str = "majik-signature-attestation-v1:";

/// Domain separator for canonical SignRoom session-context commitments.
pub const MAJIK_SESSION_CONTEXT_DOMAIN: &str = "majik-signature-session-context-v1:";

/// Domain separator for the seal hash payload.
pub const MAJIK_SEAL_DOMAIN: &str = "majik-seal-v1:";

/// Supported content type hints (advisory only — verification does not enforce them).
pub mod content_types {
    /// Generic binary stream MIME type.
    pub const BINARY: &str = "application/octet-stream";
    /// JSON document MIME type.
    pub const JSON: &str = "application/json";
    /// Plain-text document MIME type.
    pub const TEXT: &str = "text/plain";
    /// PDF document MIME type.
    pub const PDF: &str = "application/pdf";
    /// WAV audio MIME type.
    pub const WAV: &str = "audio/wav";
    /// MP3 audio MIME type.
    pub const MP3: &str = "audio/mpeg";
    /// FLAC audio MIME type.
    pub const FLAC: &str = "audio/flac";
    /// PNG image MIME type.
    pub const PNG: &str = "image/png";
    /// JPEG image MIME type.
    pub const JPEG: &str = "image/jpeg";
    /// WebP image MIME type.
    pub const WEBP: &str = "image/webp";
}

/// TS `ContentType` is `known | string`; in Rust it is simply a string.
pub type ContentType = String;

/// Minimum base64 length sanity checks.
pub const MIN_ED_PUBLIC_KEY_B64_LEN: usize = 40;
/// Minimum Base64 character count used for an early ML-DSA public-key shape check.
pub const MIN_DSA_PUBLIC_KEY_B64_LEN: usize = 100;
/// Minimum Base64 character count used for an early signature shape check.
pub const MIN_SIGNATURE_B64_LEN: usize = 80;
/// Canonical Base64 character count for a 32-byte SHA-256 digest.
pub const CONTENT_HASH_B64_LEN: usize = 44;

/// Allowlist hash is also a SHA-256 output — identical length to [`CONTENT_HASH_B64_LEN`].
pub const ALLOWLIST_HASH_B64_LEN: usize = 44;

/// Seal hash is SHA3-512 → 64 bytes → 128 hex chars.
pub const SEAL_HASH_HEX_LEN: usize = 128;

/// Logical version of the trusted timestamp token payload schema.
pub const MAJIK_TIMESTAMP_VERSION: u8 = 1;
/// Domain separator for canonical trusted timestamp authority signatures.
pub const MAJIK_TSA_DOMAIN: &str = "majikah-tsa-v-1:";

/// Logical version used by the Majik Notary memo format.
pub const MAJIK_NOTARY_VERSION: u8 = 1;
/// Prefix identifying version-1 Majik Notary memo strings.
pub const MAJIK_NOTARY_MEMO_DOMAIN: &str = "majik-notary-v-1:";

// ─── Key / signature sizes (validated by `MajikSignatureValidator`) ──────────
/// Raw Ed25519 public-key length in bytes.
pub const ED25519_PUBLIC_KEY_LEN: usize = 32;
/// Raw Ed25519 signature length in bytes.
pub const ED25519_SIGNATURE_LEN: usize = 64;
/// Secret-key length accepted by the Ed25519 signing adapter.
pub const ED25519_SECRET_KEY_LEN: usize = 64;
/// Raw ML-DSA-87 public-key length in bytes (FIPS 204 parameter set 87).
pub const ML_DSA_87_PUBLIC_KEY_LEN: usize = 2592;
/// Raw ML-DSA-87 secret-key length in bytes.
pub const ML_DSA_87_SECRET_KEY_LEN: usize = 4896;
/// Raw ML-DSA-87 signature length in bytes.
pub const ML_DSA_87_SIGNATURE_LEN: usize = 4627;

// ─── MJKSIG binary format ────────────────────────────────────────────────────
//
// Layout: [magic(6)][version(1)][reserved(1)][payloadLen(4, BE u32)][payload]
//
// Version 1: UTF-8 JSON payload (legacy; read-only for backward compatibility).
// Version 2: CBOR payload (current).
// The header is a fixed 12 bytes across versions; the version byte selects the payload decoder.
/// Six-byte magic prefix identifying a detached MJKSIG binary container.
pub const MJKSIG_MAGIC: [u8; 6] = [0x4d, 0x4a, 0x4b, 0x53, 0x49, 0x47]; // "MJKSIG"
/// Length of the MJKSIG magic prefix.
pub const MJKSIG_MAGIC_LEN: usize = MJKSIG_MAGIC.len();
/// Legacy MJKSIG container encoding: UTF-8 JSON.
pub const MJKSIG_JSON_VERSION: u8 = 0x01;
/// Current MJKSIG container encoding: CBOR.
pub const MJKSIG_CBOR_VERSION: u8 = 0x02;
/// Version used when writing new MJKSIG containers.
pub const MJKSIG_VERSION: u8 = MJKSIG_CBOR_VERSION;
/// Versions accepted when reading MJKSIG containers.
pub const MJKSIG_SUPPORTED_VERSIONS: [u8; 2] = [MJKSIG_JSON_VERSION, MJKSIG_CBOR_VERSION];
/// Total fixed MJKSIG container header length in bytes (12).
pub const MJKSIG_HEADER_LEN: usize = MJKSIG_MAGIC_LEN + 1 + 1 + 4; // 12

/// Registered media type for detached MJKSIG containers.
pub const MJKSIG_MEDIA_TYPE: &str = "application/vnd.majikah.mjksig";
/// Conventional filename extension for detached MJKSIG containers.
pub const MJKSIG_FILE_EXTENSION: &str = ".mjksig";

// ─── MJKSMAP binary format ───────────────────────────────────────────────────
//
// Layout: [magic(7)][version(1)][reserved(1)][payloadLen(4, BE u32)][payload]
//
// Version 1: UTF-8 JSON payload (legacy; read-only compatibility).
// Version 2: CBOR payload (current writer and preferred format).
//
// The manifest schema inside both payloads remains version 1. The container
// version selects only the payload encoding; it does not change map semantics.
/// Seven-byte magic prefix identifying a MJKSMAP binary container.
pub const MJKSMAP_MAGIC: [u8; 7] = [0x4d, 0x4a, 0x4b, 0x53, 0x4d, 0x41, 0x50]; // "MJKSMAP"
/// Length of the MJKSMAP magic prefix.
pub const MJKSMAP_MAGIC_LEN: usize = MJKSMAP_MAGIC.len();
/// Legacy MJKSMAP container encoding: UTF-8 JSON.
pub const MJKSMAP_JSON_VERSION: u8 = 0x01;
/// Current MJKSMAP container encoding: CBOR.
pub const MJKSMAP_CBOR_VERSION: u8 = 0x02;
/// Version emitted by new MJKSMAP writers.
pub const MJKSMAP_VERSION: u8 = MJKSMAP_CBOR_VERSION;
/// Schema version stored inside the JSON/CBOR manifest model.
pub const MJKSMAP_SCHEMA_VERSION: u8 = 0x01;
/// Versions accepted by MJKSMAP readers.
pub const MJKSMAP_SUPPORTED_VERSIONS: [u8; 2] = [MJKSMAP_JSON_VERSION, MJKSMAP_CBOR_VERSION];
/// Total fixed MJKSMAP container header length in bytes (13).
pub const MJKSMAP_HEADER_LEN: usize = MJKSMAP_MAGIC_LEN + 1 + 1 + 4; // 13

/// Registered media type for MJKSMAP batch manifests.
pub const MJKSMAP_MEDIA_TYPE: &str = "application/vnd.majikah.mjksmap";
/// Conventional filename extension for MJKSMAP batch manifests.
pub const MJKSMAP_FILE_EXTENSION: &str = ".mjksmap";

/// Conventional name/location when packaged in a signed batch zip.
pub const MJKSMAP_DEFAULT_FILENAME: &str = "signatures.mjksmap";

// ─── Untrusted envelope parsing limits ──────────────────────────────────────
/// Raw SHA-256 digest length in bytes.
pub const SHA256_DIGEST_LEN: usize = 32;
/// Maximum accepted character count for signer identity text fields.
pub const MAX_SIGNER_ID_CHARS: usize = 256;
/// Maximum accepted character count for advisory content-type metadata.
pub const MAX_CONTENT_TYPE_CHARS: usize = 1024;
/// Maximum accepted character count for timestamp strings.
pub const MAX_TIMESTAMP_CHARS: usize = 64;
/// Maximum accepted character count for TSA metadata text fields.
pub const MAX_TSA_FIELD_CHARS: usize = 256;
/// Maximum number of signer records accepted by one envelope.
pub const MAX_SIGNATURES_PER_ENVELOPE: usize = 1024;
/// Maximum number of entries accepted in a signer allowlist.
pub const MAX_ALLOWLIST_ENTRIES: usize = 1024;
/// Maximum serialized envelope JSON/CBOR/MJKSIG parser payload size (header excluded where applicable).
pub const MAX_ENVELOPE_BYTES: usize = 16 * 1024 * 1024;
/// Maximum serialized MJKSMAP binary payload (header excluded).
pub const MAX_MJKSMAP_BYTES: usize = 16 * 1024 * 1024;
/// Maximum JSON model input size. Base64 expands raw binary fields, so the
/// compatibility/API representation needs headroom over the CBOR wire limit.
pub const MAX_MJKSMAP_JSON_BYTES: usize = 24 * 1024 * 1024;
/// Maximum entries accepted in one MJKSMAP manifest.
pub const MAX_MJKSMAP_ENTRIES: usize = 10_000;
/// Maximum input path length before normalization, measured in UTF-16 code units.
pub const MAX_MJKSMAP_PATH_CHARS: usize = 4_096;
/// Maximum raw CBOR input accepted by the shared decoder.
pub const MAX_CBOR_INPUT_BYTES: usize = MAX_ENVELOPE_BYTES;
/// Maximum number of chain-anchor records accepted in an envelope.
pub const MAX_CHAIN_ANCHORS: usize = 256;
/// Maximum number of metadata entries accepted in one revision chain.
pub const MAX_FILE_VERSIONS: usize = 10_000;
/// Maximum UTF-16 character count accepted for one revision message.
pub const MAX_FILE_VERSION_MESSAGE_CHARS: usize = 4_096;

/// Maximum recursive nesting depth for embedded trusted timestamp signature records.
pub const MAX_TSA_SIGNATURE_NESTING: usize = 8;
