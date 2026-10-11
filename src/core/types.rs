//! Port of `core/types.ts`. TS interfaces become serde structs (camelCase on the wire, so
//! JSON is interchangeable with the TypeScript library); `undefined` → `Option` that is
//! skipped when `None`.

use serde::{Deserialize, Serialize};

use crate::anchor::types::MajikChainAnchor;
pub use crate::core::constants::ContentType;

/// ISO 8601 timestamp string (same alias as majik-key).
pub type ISODateString = String;
/// Base64-encoded SHA-256 of a MajikKey's X25519 public key (same alias as majik-key).
pub type MajikKeyFingerprint = String;

/// Base64-encoded Ed25519 signature.
pub type ED25519Signature = String;
/// Base64-encoded ML-DSA-87 signature.
pub type MLDSA87Signature = String;

/// Alias kept for parity with the TS name.
pub type MajikSignatureEnvelopeJSON = MultiSigEnvelope;

// ─── Per-signer envelope ─────────────────────────────────────────────────────

/// The serialized, self-describing form of one signer's signature (TS `MajikSignatureJSON`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MajikSignatureJSON {
    /// Always `1`.
    pub version: u8,
    pub signer_id: MajikKeyFingerprint,
    pub signer_ed_public_key: String,
    pub signer_ml_dsa_public_key: String,
    pub content_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    pub timestamp: ISODateString,
    pub ed_signature: ED25519Signature,
    pub ml_dsa_signature: MLDSA87Signature,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowlist_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<ISODateString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tsa: Option<MajikTimestamp>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_chain_hash: Option<String>,
}

/// Wire/storage-optimized form: public keys stripped (TS `MajikSignatureCompactJSON`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MajikSignatureCompactJSON {
    /// Always `1`.
    pub v: u8,
    pub signer_id: MajikKeyFingerprint,
    pub content_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    pub timestamp: ISODateString,
    pub ed_signature: ED25519Signature,
    pub ml_dsa_signature: MLDSA87Signature,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowlist_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<ISODateString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_chain_hash: Option<String>,
}

// ─── Trusted timestamps ──────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TsaDigest {
    /// Always `"SHA-256"`.
    pub algorithm: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MajikTsaIdentity {
    pub id: String,
    pub signer_fingerprint: String,
}

/// The payload a TSA signs (TS `MajikTSAPayload`). Field order is part of the canonical bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MajikTsaPayload {
    pub digest: TsaDigest,
    pub nonce: String,
    pub timestamp: String,
    pub tsa: MajikTsaIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MajikTsaRequest {
    pub digest: TsaDigest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MajikTimestamp {
    /// Always `1`.
    pub version: u8,
    pub id: String,
    pub payload: MajikTsaPayload,
    pub signature: Box<MajikSignatureJSON>,
}

// ─── Multi-sig envelope ──────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExpectedSigner {
    pub signer_id: MajikKeyFingerprint,
    pub ed_public_key: String,
    pub ml_dsa_public_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MultiSigEnvelope {
    /// Always `1`.
    pub version: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowlist: Option<Vec<ExpectedSigner>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowlist_signer_id: Option<MajikKeyFingerprint>,
    pub signatures: Vec<MajikSignatureJSON>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seal_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seal_timestamp: Option<ISODateString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sealed_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_anchors: Option<Vec<MajikChainAnchor>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_versions: Option<Vec<FileVersion>>,
}

/// A signer's raw public keys (TS `MajikSignerPublicKeys`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MajikSignerPublicKeys {
    pub signer_id: MajikKeyFingerprint,
    /// 32 bytes.
    pub ed_public_key: Vec<u8>,
    /// 2592 bytes.
    pub ml_dsa_public_key: Vec<u8>,
}

// ─── Options & results ───────────────────────────────────────────────────────

/// Options for signing (TS `SignOptions & { allowlistHash?, versionChainHash? }`).
///
/// `allowlist_hash` and `version_chain_hash` are injected internally by the embed layer.
#[derive(Debug, Clone, Default)]
pub struct SignOptions {
    pub content_type: Option<String>,
    pub timestamp: Option<ISODateString>,
    pub expected_signers: Option<Vec<ExpectedSigner>>,
    pub valid_until: Option<String>,
    pub allowlist_hash: Option<String>,
    pub version_chain_hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationResult {
    pub valid: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_id: Option<MajikKeyFingerprint>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<String>,
    pub timestamp: ISODateString,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handler: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expired: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SealVerificationResult {
    pub valid: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sealed_by: Option<MajikKeyFingerprint>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seal_timestamp: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SealInfo {
    pub seal_hash: String,
    pub seal_timestamp: ISODateString,
    pub sealed_by: MajikKeyFingerprint,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignatoryInfo {
    pub signer_id: MajikKeyFingerprint,
    pub ed_public_key: String,
    pub ml_dsa_public_key: String,
    pub has_signed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_at: Option<ISODateString>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SignatoriesResult {
    pub all: Vec<SignatoryInfo>,
    pub signed: Vec<SignatoryInfo>,
    pub pending: Vec<SignatoryInfo>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SignatoriesFilter {
    All,
    Signed,
    Pending,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnvelopeInfo {
    pub is_multi_sig: bool,
    pub has_multiple_signatories: bool,
    pub is_sealed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seal_info: Option<SealInfo>,
    pub issuer: Option<SignatoryInfo>,
    pub signatories: Option<SignatoriesResult>,
    pub allowlist: Option<Vec<ExpectedSigner>>,
    pub signature_count: usize,
}

// ─── Embed options / handler interface ───────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct EmbedOptions {
    pub mime_type: Option<String>,
    pub force_fallback: bool,
}

#[derive(Debug, Clone, Default)]
pub struct ExtractOptions {
    pub mime_type: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct VerifyEmbeddedOptions {
    pub mime_type: Option<String>,
    pub expected_signer_id: Option<String>,
}

/// A per-format embed handler (TS `FormatHandler`). Async methods become sync.
pub trait FormatHandler: Send + Sync {
    fn name(&self) -> &str;
    fn supported_mime_types(&self) -> &[&'static str];
    fn can_handle(&self, bytes: &[u8], mime_type: Option<&str>) -> bool;
    fn embed(&self, bytes: &[u8], signature_json: &str)
        -> crate::core::errors::MajikSignatureResult<Vec<u8>>;
    fn extract(&self, bytes: &[u8]) -> crate::core::errors::MajikSignatureResult<Option<String>>;
    fn strip(&self, bytes: &[u8]) -> crate::core::errors::MajikSignatureResult<Vec<u8>>;
    /// Optional human-readable diagnosis of why a file could not be handled.
    fn diagnose(&self, _bytes: &[u8]) -> Option<String> {
        None
    }
}

#[derive(Debug, Clone)]
pub struct EmbedResult {
    /// TS `Blob` → raw bytes.
    pub blob: Vec<u8>,
    pub handler: String,
    pub mime_type: String,
}

// ─── Batch / MJKSMAP ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MjksMapEntry {
    pub path: String,
    pub content_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    pub envelope: MajikSignatureEnvelopeJSON,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MjksMapJSON {
    /// Always `1`.
    pub version: u8,
    pub created_at: ISODateString,
    pub entries: Vec<MjksMapEntry>,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct MjksMapFindResult {
    pub found: bool,
    pub entry: Option<MjksMapEntry>,
    pub hash_matches: Option<bool>,
}

#[derive(Debug, Clone, Default)]
pub struct BatchFileInput {
    pub path: String,
    /// File bytes (TS `Blob`).
    pub blob: Vec<u8>,
    /// Declared MIME type (TS `Blob.type`); empty/`None` = unknown.
    pub mime_type: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BatchSignMode {
    #[default]
    Map,
    Separate,
}

#[derive(Debug, Clone, Default)]
pub struct BatchSignOptions {
    pub content_type: Option<String>,
    pub timestamp: Option<ISODateString>,
    pub expected_signers: Option<Vec<ExpectedSigner>>,
    pub valid_until: Option<ISODateString>,
    pub mode: Option<BatchSignMode>,
    pub continue_on_error: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchSignFailure {
    pub path: String,
    pub error: String,
}

#[derive(Debug, Clone, Default)]
pub struct BatchVerifyInput {
    pub path: String,
    pub blob: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileVerifyStatus {
    Verified,
    Invalid,
    Tampered,
    NotInMap,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileVerifyResult {
    pub path: String,
    pub status: FileVerifyStatus,
    pub results: Option<Vec<VerificationResult>>,
    pub reason: Option<String>,
    pub relocated_from: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct BatchVerifyOptions {
    pub expected_signer_id: Option<MajikKeyFingerprint>,
    pub now: Option<jiff::Timestamp>,
    pub require_all_present: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BatchVerifySummary {
    pub total: usize,
    pub verified: usize,
    pub invalid: usize,
    pub tampered: usize,
    pub not_in_map: usize,
    pub all_valid: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MjksMapResolveStatus {
    PathMatch,
    PathTampered,
    Relocated,
    NotFound,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MjksMapResolveResult {
    pub status: MjksMapResolveStatus,
    pub entry: Option<MjksMapEntry>,
    pub original_path: Option<String>,
}

// ─── Revisions ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileVersion {
    pub version: u32,
    pub timestamp: ISODateString,
    pub content_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_version_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_by: Option<MajikKeyFingerprint>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// `VerificationResult` + `commitmentOnly: true`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RevisionCommitmentResult {
    #[serde(flatten)]
    pub base: VerificationResult,
    pub commitment_only: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileChainVerification {
    pub latest: VerificationResult,
    pub history: Vec<RevisionCommitmentResult>,
    pub chain_valid: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevisionCheckStatus {
    Verified,
    Unmatched,
    ChainBroken,
    SignatureInvalid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevisionCheckResult {
    pub version: u32,
    pub status: RevisionCheckStatus,
    pub signer_id: Option<MajikKeyFingerprint>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevisionSetVerification {
    pub all_valid: bool,
    pub is_complete_set: bool,
    pub results: Vec<RevisionCheckResult>,
}

// ─── Results that embed other module types ───────────────────────────────────

use crate::core::envelope::MajikSignatureEnvelope;
use crate::core::mjksmap::MajikSignatureMap;

#[derive(Debug, Clone)]
pub struct ExtractResult {
    pub envelope: MajikSignatureEnvelope,
    pub handler: String,
}

/// TS `BatchSignResult` — a discriminated union on `mode`.
#[derive(Debug, Clone)]
pub enum BatchSignResult {
    Map {
        map: MajikSignatureMap,
        /// The `.mjksmap` bytes (TS `mapBlob`).
        map_blob: Vec<u8>,
        failures: Vec<BatchSignFailure>,
    },
    Separate {
        /// `(path, .mjksig bytes)` per file.
        signatures: Vec<SeparateSignature>,
        failures: Vec<BatchSignFailure>,
    },
}

#[derive(Debug, Clone)]
pub struct SeparateSignature {
    pub path: String,
    pub blob: Vec<u8>,
}

/// TS `FileLike` is `Blob | File | Uint8Array | ArrayBuffer`; in Rust it is just bytes.
pub type FileLike<'a> = &'a [u8];
