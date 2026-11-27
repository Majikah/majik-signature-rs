//! Port of `core/types.ts`. TS interfaces become serde structs (camelCase on the wire, so
//! JSON is interchangeable with the TypeScript library); `undefined` → `Option` that is
//! skipped when `None`.

use serde::{Deserialize, Serialize};

use crate::anchor::types::MajikChainAnchor;
pub use crate::core::constants::ContentType;
use crate::core::session_context::MajikSessionSigningContext;

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
/// JSON-compatible representation of one signer’s hybrid signature record.
///
/// Binary values use canonical Base64 strings in this logical model; CBOR wire
/// adapters convert those values to native byte strings for container v2.
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
    pub version_chain_hash: Option<String>,
    /// Base64 SHA-256 commitment to the SignRoom session, challenge, and policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_context_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tsa: Option<MajikTimestamp>,
}

/// Wire/storage-optimized form: public keys stripped (TS `MajikSignatureCompactJSON`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// Compact/abbreviated JSON representation used by the compatibility API.
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
    /// Optional signed SignRoom session-context commitment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_context_hash: Option<String>,
}

// ─── Trusted timestamps ──────────────────────────────────────────────────────

/// Scope of a Trusted Timestamp Authority digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TsaDigestScope {
    Content,
    Signature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
/// Algorithm and digest value requested from or returned by a timestamp authority.
pub struct TsaDigest {
    /// Always `"SHA-256"`.
    pub algorithm: String,
    pub value: String,
    /// Omitted for legacy content-hash timestamps.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<TsaDigestScope>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// Claimed timestamp-authority identity embedded in a signed TSA payload.
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
/// Digest descriptor sent by an application to its timestamp service.
pub struct MajikTsaRequest {
    pub digest: TsaDigest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
/// Timestamp token containing the TSA payload and its own hybrid Majik Signature record.
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
/// Public-key identity permitted by an envelope allowlist.
pub struct ExpectedSigner {
    pub signer_id: MajikKeyFingerprint,
    pub ed_public_key: String,
    pub ml_dsa_public_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// Logical multi-signer envelope containing signatures and optional allowlist, seal, anchors, and revision metadata.
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
    /// Optional SHA-256 commitment to a canonical SignRoom session context.
    pub session_context_hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// Result of checking one signature against content and an expected public-key identity.
pub struct VerificationResult {
    pub valid: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_id: Option<MajikKeyFingerprint>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<String>,
    pub timestamp: ISODateString,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    /// Signed SignRoom session-context commitment, when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_context_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handler: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expired: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// Structural result of recomputing and comparing an envelope seal commitment.
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
/// Read-only description of the seal currently attached to an envelope.
pub struct SealInfo {
    pub seal_hash: String,
    pub seal_timestamp: ISODateString,
    pub sealed_by: MajikKeyFingerprint,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// Display-oriented information about one signer in an envelope; it is not a verification result.
pub struct SignatoryInfo {
    pub signer_id: MajikKeyFingerprint,
    pub ed_public_key: String,
    pub ml_dsa_public_key: String,
    pub has_signed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_at: Option<ISODateString>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
/// Grouped signatory information for signed, pending, or filtered participants.
pub struct SignatoriesResult {
    pub all: Vec<SignatoryInfo>,
    pub signed: Vec<SignatoryInfo>,
    pub pending: Vec<SignatoryInfo>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
/// Selects which categories of signers are returned by envelope status queries.
pub enum SignatoriesFilter {
    All,
    Signed,
    Pending,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// Summary of envelope state, including signer counts, allowlist, seal, and revision metadata.
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
/// Format-handler options controlling embedded envelope encoding and fallback behavior.
pub struct EmbedOptions {
    pub mime_type: Option<String>,
    pub force_fallback: bool,
}

#[derive(Debug, Clone, Default)]
/// Format selection hints for extracting an embedded envelope from file bytes.
pub struct ExtractOptions {
    pub mime_type: Option<String>,
}

#[derive(Debug, Clone, Default)]
/// Options used when checking an envelope embedded in a file.
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
/// Embedded file bytes and the handler/MIME metadata used to produce them.
pub struct EmbedResult {
    /// TS `Blob` → raw bytes.
    pub blob: Vec<u8>,
    pub handler: String,
    pub mime_type: String,
}

// ─── Batch / MJKSMAP ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// One logical file entry in a MJKSMAP manifest.
///
/// `content_hash` is a canonical Base64 SHA-256 digest in the JSON model and
/// a 32-byte CBOR byte string in MJKSMAP v2.
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
/// Schema-v1 logical JSON model for a MJKSMAP batch manifest.
/// The binary container version is separate: writers emit v2 CBOR and readers also accept v1 JSON.
pub struct MjksMapJSON {
    /// Always `1`.
    pub version: u8,
    pub created_at: ISODateString,
    pub entries: Vec<MjksMapEntry>,
}

#[derive(Debug, Clone, PartialEq, Default)]
/// Path lookup result, including whether an optional supplied file hash matched.
pub struct MjksMapFindResult {
    pub found: bool,
    pub entry: Option<MjksMapEntry>,
    pub hash_matches: Option<bool>,
}

#[derive(Debug, Clone, Default)]
/// In-memory file input used by non-streaming batch detached signing.
pub struct BatchFileInput {
    pub path: String,
    /// File bytes (TS `Blob`).
    pub blob: Vec<u8>,
    /// Declared MIME type (TS `Blob.type`); empty/`None` = unknown.
    pub mime_type: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
/// Selects a single MJKSMAP result or one detached MJKSIG per input file.
pub enum BatchSignMode {
    #[default]
    Map,
    Separate,
}

#[derive(Debug, Clone, Default)]
/// Options shared by in-memory and streaming batch signing.
pub struct BatchSignOptions {
    pub content_type: Option<String>,
    pub timestamp: Option<ISODateString>,
    pub expected_signers: Option<Vec<ExpectedSigner>>,
    pub valid_until: Option<ISODateString>,
    pub mode: Option<BatchSignMode>,
    pub continue_on_error: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Per-file batch-signing failure returned when continue-on-error is enabled.
pub struct BatchSignFailure {
    pub path: String,
    pub error: String,
}

#[derive(Debug, Clone, Default)]
/// In-memory file input for resolving and verifying a MJKSMAP entry.
pub struct BatchVerifyInput {
    pub path: String,
    pub blob: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// Per-file resolution and verification outcome for MJKSMAP batch verification.
pub enum FileVerifyStatus {
    Verified,
    Invalid,
    Tampered,
    NotInMap,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Detailed result for one file processed against a MJKSMAP manifest.
pub struct FileVerifyResult {
    pub path: String,
    pub status: FileVerifyStatus,
    pub results: Option<Vec<VerificationResult>>,
    pub reason: Option<String>,
    pub relocated_from: Option<String>,
}

#[derive(Debug, Clone, Default)]
/// Controls missing-file handling and MIME hints during batch verification.
pub struct BatchVerifyOptions {
    pub expected_signer_id: Option<MajikKeyFingerprint>,
    pub now: Option<jiff::Timestamp>,
    pub require_all_present: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
/// Aggregate counts and overall validity derived from per-file verification results.
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
/// Describes whether a MJKSMAP file matched its path, was relocated by hash, was tampered, or was absent.
pub enum MjksMapResolveStatus {
    PathMatch,
    PathTampered,
    Relocated,
    NotFound,
}

#[derive(Debug, Clone, PartialEq)]
/// Entry resolution result, including the original path when a matching file was relocated.
pub struct MjksMapResolveResult {
    pub status: MjksMapResolveStatus,
    pub entry: Option<MjksMapEntry>,
    pub original_path: Option<String>,
}

// ─── Revisions ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// Metadata-only entry in an append-only document revision chain.
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
/// Structural and cryptographic verification summary for an embedded or detached revision chain.
pub struct FileChainVerification {
    pub latest: VerificationResult,
    pub history: Vec<RevisionCommitmentResult>,
    pub chain_valid: bool,
}

#[derive(Debug, Clone)]
/// Server-provided inputs used to sign a file for one SignRoom session attempt.
pub struct SessionFileSignOptions {
    pub session_context: MajikSessionSigningContext,
    pub content_type: Option<String>,
    pub timestamp: Option<ISODateString>,
    pub mime_type: Option<String>,
    pub expected_signers: Option<Vec<ExpectedSigner>>,
    pub valid_until: Option<ISODateString>,
    pub existing_envelope: Option<crate::core::envelope::EnvelopeInput>,
    pub tsa: Option<MajikTimestamp>,
    /// Exact FileVersion entry to append and commit in this signature.
    pub file_version: Option<FileVersion>,
    /// Exact prior document bytes before this participant's visual stamp.
    /// Mutually exclusive with file_version.
    pub prior_file: Option<Vec<u8>>,
    pub message: Option<String>,
}

impl SessionFileSignOptions {
    /// Create session signing options with every optional setting unset.
    pub fn new(session_context: MajikSessionSigningContext) -> Self {
        Self {
            session_context,
            content_type: None,
            timestamp: None,
            mime_type: None,
            expected_signers: None,
            valid_until: None,
            existing_envelope: None,
            tsa: None,
            file_version: None,
            prior_file: None,
            message: None,
        }
    }
}

/// Result of session-aware detached signing, including binary MJKSIG sidecar bytes.
#[derive(Debug, Clone)]
pub struct SessionFileSignResult {
    pub blob: Vec<u8>,
    pub envelope: crate::core::envelope::MajikSignatureEnvelope,
    pub signature: crate::majik_signature::MajikSignature,
    pub handler: String,
    pub mime_type: String,
    pub mjksig: Vec<u8>,
}

/// Strict verification options for a detached SignRoom document.
#[derive(Debug, Clone, Default)]
pub struct SessionFileVerifyOptions {
    /// Authoritative session/challenge/policy context, keyed by signer fingerprint.
    pub expected_session_contexts: std::collections::HashMap<String, MajikSessionSigningContext>,
    /// Trusted Ed25519 + ML-DSA-87 keys, keyed by signer fingerprint.
    pub expected_signer_public_keys: std::collections::HashMap<String, MajikSignerPublicKeys>,
    pub mime_type: Option<String>,
    pub now: Option<jiff::Timestamp>,
    /// Optional independently trusted TSA key. Without it, TSA self-consistency is checked only.
    pub trusted_tsa_public_keys: Option<MajikSignerPublicKeys>,
    pub require_tsa: bool,
    pub require_trusted_tsa: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Verification result for one timestamp token associated with a session signature.
pub struct SessionFileTsaVerificationResult {
    pub signer_id: MajikKeyFingerprint,
    pub present: bool,
    pub valid: bool,
    /// True only when verification was pinned to trusted_tsa_public_keys.
    pub trusted: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Combined result for SignRoom participant, revision-chain, and TSA verification.
pub struct SessionFileVerificationResult {
    pub valid: bool,
    pub results: Vec<VerificationResult>,
    pub chain: Option<FileChainVerification>,
    pub tsa_results: Vec<SessionFileTsaVerificationResult>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// Outcome when matching a supplied historical revision to a recorded file-version entry.
pub enum RevisionCheckStatus {
    Verified,
    Unmatched,
    ChainBroken,
    SignatureInvalid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Per-version outcome returned when checking an archived revision set.
pub struct RevisionCheckResult {
    pub version: u32,
    pub status: RevisionCheckStatus,
    pub signer_id: Option<MajikKeyFingerprint>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Complete verification result for the supplied historical revisions and final document.
pub struct RevisionSetVerification {
    pub all_valid: bool,
    pub is_complete_set: bool,
    pub results: Vec<RevisionCheckResult>,
}

// ─── Results that embed other module types ───────────────────────────────────

use crate::core::envelope::MajikSignatureEnvelope;
use crate::core::mjksmap::MajikSignatureMap;

#[derive(Debug, Clone)]
/// Extracted envelope and metadata describing the format handler that found it.
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
/// Detached MJKSIG sidecar bytes paired with their source file path.
pub struct SeparateSignature {
    pub path: String,
    pub blob: Vec<u8>,
}

/// TS `FileLike` is `Blob | File | Uint8Array | ArrayBuffer`; in Rust it is just bytes.
pub type FileLike<'a> = &'a [u8];
