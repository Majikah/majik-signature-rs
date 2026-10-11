//! Port of `core/envelope.ts` — `MajikSignatureEnvelope`.
//!
//! An immutable multi-signature container: per-signer signatures, an optional allowlist,
//! an optional seal, chain anchors and a file-revision chain. Every `with_*` method returns
//! a new envelope. Also owns the `.mjksig` binary container format.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use majik_key::MajikKey;
use serde_json::Value;
use sha3::{Digest, Sha3_512};

use crate::anchor::types::MajikChainAnchor;
use crate::core::collate::locale_compare;
use crate::core::constants::*;
use crate::core::errors::{MajikSignatureError, MajikSignatureResult};
use crate::core::hash::{bytes_to_base64, hash_content};
use crate::core::time::now_iso;
use crate::core::types::*;
use crate::majik_signature::signing_public_keys_b64;

type R<T> = MajikSignatureResult<T>;

/// Result of [`MajikSignatureEnvelope::check_allowlist`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowlistCheckResult {
    /// `true` when the key may sign according to the allowlist (always `true` for open signing).
    pub permitted: bool,
    /// Matching entry; `None` for open signing or when denied.
    pub entry: Option<ExpectedSigner>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanSignResult {
    pub permitted: bool,
    /// Human-readable explanation when `permitted` is `false` (diagnostic text, not a stable code).
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanAnchorResult {
    pub permitted: bool,
    pub reason: Option<String>,
}

/// Result of the structural integrity checks (`{ valid, reason? }` in TS).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntegrityResult {
    pub valid: bool,
    pub reason: Option<String>,
}

impl IntegrityResult {
    fn ok() -> Self {
        Self { valid: true, reason: None }
    }
    fn fail(reason: impl Into<String>) -> Self {
        Self { valid: false, reason: Some(reason.into()) }
    }
}

/// TS `EnvelopeInput`: an envelope, its JSON shape, or MJKSIG bytes.
#[derive(Debug, Clone)]
pub enum EnvelopeInput {
    Envelope(MajikSignatureEnvelope),
    Json(MajikSignatureEnvelopeJSON),
    Bytes(Vec<u8>),
}

impl From<MajikSignatureEnvelope> for EnvelopeInput {
    fn from(e: MajikSignatureEnvelope) -> Self {
        Self::Envelope(e)
    }
}
impl From<MajikSignatureEnvelopeJSON> for EnvelopeInput {
    fn from(e: MajikSignatureEnvelopeJSON) -> Self {
        Self::Json(e)
    }
}
impl From<Vec<u8>> for EnvelopeInput {
    fn from(e: Vec<u8>) -> Self {
        Self::Bytes(e)
    }
}
impl From<&[u8]> for EnvelopeInput {
    fn from(e: &[u8]) -> Self {
        Self::Bytes(e.to_vec())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct MajikSignatureEnvelope {
    data: MultiSigEnvelope,
}

impl MajikSignatureEnvelope {
    fn new(data: MultiSigEnvelope) -> Self {
        Self { data }
    }

    // ── Getters ──────────────────────────────────────────────────────────────

    pub fn version(&self) -> u8 {
        self.data.version
    }
    pub fn signatures(&self) -> &[MajikSignatureJSON] {
        &self.data.signatures
    }
    pub fn allowlist(&self) -> Option<&[ExpectedSigner]> {
        self.data.allowlist.as_deref()
    }
    /// Fingerprint of the signer who established the allowlist (the issuer).
    pub fn allowlist_signer_id(&self) -> Option<&str> {
        self.data.allowlist_signer_id.as_deref()
    }
    pub fn seal_hash(&self) -> Option<&str> {
        self.data.seal_hash.as_deref()
    }
    pub fn seal_timestamp(&self) -> Option<&str> {
        self.data.seal_timestamp.as_deref()
    }
    pub fn sealed_by(&self) -> Option<&str> {
        self.data.sealed_by.as_deref()
    }
    pub fn chain_anchors(&self) -> &[MajikChainAnchor] {
        self.data.chain_anchors.as_deref().unwrap_or(&[])
    }
    pub fn file_versions(&self) -> &[FileVersion] {
        self.data.file_versions.as_deref().unwrap_or(&[])
    }
    pub fn last_file_version(&self) -> Option<&FileVersion> {
        self.data.file_versions.as_ref().and_then(|v| v.last())
    }

    // ── Version chain hashing ────────────────────────────────────────────────

    /// Base64 SHA-256 of the JSON of one revision entry.
    pub fn hash_file_version_entry(entry: &FileVersion) -> String {
        bytes_to_base64(&hash_content(to_json_bytes(entry).as_slice()))
    }

    /// Base64 SHA-256 of the JSON of an entire revision chain.
    pub fn hash_file_version_chain(chain: &[FileVersion]) -> String {
        bytes_to_base64(&hash_content(to_json_bytes(&chain).as_slice()))
    }

    /// Append a revision entry; it must chain onto the current last entry.
    pub fn with_file_version(&self, entry: FileVersion) -> R<MajikSignatureEnvelope> {
        if self.is_sealed() {
            return Err(MajikSignatureError::new("Cannot add a file version to a sealed envelope."));
        }
        let chain = self.file_versions();
        let last = chain.last();
        let expected_version = last.map(|l| l.version + 1).unwrap_or(1);
        if entry.version != expected_version {
            return Err(MajikSignatureError::validation(
                format!("FileVersion.version must be {expected_version}, got {}", entry.version),
                Some("version"),
            ));
        }
        let expected_prev = last.map(Self::hash_file_version_entry);
        if entry.previous_version_hash != expected_prev {
            return Err(MajikSignatureError::validation(
                "FileVersion.previousVersionHash does not chain onto the current last entry.",
                Some("previousVersionHash"),
            ));
        }
        let mut next = self.data.clone();
        let mut versions = chain.to_vec();
        versions.push(entry);
        next.file_versions = Some(versions);
        Ok(Self::new(next))
    }

    /// Structural linkage check of `fileVersions` — touches no signature.
    pub fn verify_version_chain_integrity(&self) -> IntegrityResult {
        let chain = match &self.data.file_versions {
            Some(c) if !c.is_empty() => c,
            _ => return IntegrityResult::ok(),
        };
        for (i, entry) in chain.iter().enumerate() {
            if entry.version as usize != i + 1 {
                return IntegrityResult::fail(format!(
                    "fileVersions[{i}].version is {}, expected {}",
                    entry.version,
                    i + 1
                ));
            }
            if i == 0 {
                if entry.previous_version_hash.is_some() {
                    return IntegrityResult::fail("fileVersions[0] must not have a previousVersionHash");
                }
                continue;
            }
            let expected_prev = Self::hash_file_version_entry(&chain[i - 1]);
            if entry.previous_version_hash.as_deref() != Some(expected_prev.as_str()) {
                return IntegrityResult::fail(format!("fileVersions[{i}].previousVersionHash mismatch"));
            }
        }
        IntegrityResult::ok()
    }

    // ── State predicates ─────────────────────────────────────────────────────

    pub fn is_sealed(&self) -> bool {
        self.data.seal_hash.is_some()
    }
    pub fn has_allowlist(&self) -> bool {
        self.data.allowlist.as_ref().map(|a| !a.is_empty()).unwrap_or(false)
    }
    pub fn is_first_signer(&self) -> bool {
        self.data.signatures.is_empty()
    }
    /// Restricted multi-sig: an allowlist with more than one expected signer.
    pub fn is_multi_sig(&self) -> bool {
        self.data.allowlist.as_ref().map(|a| a.len() > 1).unwrap_or(false)
    }
    pub fn has_multiple_signatories(&self) -> bool {
        self.data.signatures.len() > 1
    }
    pub fn find_signature(&self, signer_id: &str) -> Option<&MajikSignatureJSON> {
        self.data.signatures.iter().find(|s| s.signer_id == signer_id)
    }

    pub fn is_issuer(&self, fingerprint: &str) -> bool {
        self.data
            .allowlist_signer_id
            .as_deref()
            .map(|id| !id.is_empty() && id == fingerprint)
            .unwrap_or(false)
    }
    pub fn is_issuer_key(&self, key: &MajikKey) -> bool {
        self.is_issuer(key.fingerprint())
    }

    // ── Allowlist ────────────────────────────────────────────────────────────

    /// Full three-field check: fingerprint + Ed25519 key + ML-DSA key must all match.
    pub fn check_allowlist(&self, key: &MajikKey) -> R<AllowlistCheckResult> {
        if !self.has_allowlist() {
            return Ok(AllowlistCheckResult { permitted: true, entry: None });
        }
        let (ed, ml) = signing_public_keys_b64(key)?;
        let found = self.data.allowlist.as_ref().and_then(|list| {
            list.iter().find(|e| {
                e.signer_id == key.fingerprint() && e.ed_public_key == ed && e.ml_dsa_public_key == ml
            })
        });
        Ok(match found {
            Some(e) => AllowlistCheckResult { permitted: true, entry: Some(e.clone()) },
            None => AllowlistCheckResult { permitted: false, entry: None },
        })
    }

    /// Throws if `key` may not add a signature (sealed, or not on the allowlist). The issuer
    /// always bypasses the allowlist.
    pub fn assert_can_sign(&self, key: &MajikKey) -> R<()> {
        if self.is_sealed() {
            return Err(MajikSignatureError::new(
                "Cannot sign a sealed envelope. The issuer has locked this file against further signatures.",
            ));
        }
        if self.is_issuer_key(key) {
            return Ok(());
        }
        if !self.check_allowlist(key)?.permitted {
            return Err(MajikSignatureError::allowlist(
                format!(
                    "Signer \"{}\" is not permitted to sign this file. The file has a signing allowlist established by \"{}\".",
                    key.fingerprint(),
                    self.data.allowlist_signer_id.as_deref().unwrap_or("undefined")
                ),
                key.fingerprint(),
            ));
        }
        Ok(())
    }

    pub fn can_sign(&self, key: &MajikKey) -> CanSignResult {
        match self.assert_can_sign(key) {
            Ok(()) => CanSignResult { permitted: true, reason: None },
            Err(e) => CanSignResult { permitted: false, reason: Some(e.message().to_string()) },
        }
    }

    /// Base64 SHA-256 of the canonical allowlist JSON (sorted by `signerId`).
    pub fn hash_allowlist(allowlist: &[ExpectedSigner]) -> String {
        let mut sorted = allowlist.to_vec();
        sorted.sort_by(|a, b| locale_compare(&a.signer_id, &b.signer_id));
        bytes_to_base64(&hash_content(to_json_bytes(&sorted).as_slice()))
    }

    pub fn computed_allowlist_hash(&self) -> Option<String> {
        if self.has_allowlist() {
            self.data.allowlist.as_deref().map(Self::hash_allowlist)
        } else {
            None
        }
    }

    /// The `allowlistHash` a signer must bake into its payload (if any).
    pub fn resolve_allowlist_hash_for(
        &self,
        key: &MajikKey,
        expected_signers: Option<&[ExpectedSigner]>,
    ) -> Option<String> {
        let establishing = self.is_first_signer() && expected_signers.map(|e| !e.is_empty()).unwrap_or(false);
        if establishing {
            return expected_signers.map(Self::hash_allowlist);
        }
        let issuer_resigning = !self.is_first_signer() && self.is_issuer_key(key) && self.has_allowlist();
        if issuer_resigning {
            return self.computed_allowlist_hash();
        }
        None
    }

    /// Verify the allowlist still matches what the establishing signer committed to.
    pub fn verify_allowlist_integrity(&self) -> IntegrityResult {
        let Some(signer_id) = self.data.allowlist_signer_id.as_deref().filter(|s| !s.is_empty()) else {
            return IntegrityResult::ok();
        };
        if !self.has_allowlist() {
            return IntegrityResult::ok();
        }
        let Some(sig) = self.find_signature(signer_id) else {
            return IntegrityResult::fail(format!(
                "Allowlist establisher \"{signer_id}\" has no signature in this envelope"
            ));
        };
        if sig.allowlist_hash != self.computed_allowlist_hash() {
            return IntegrityResult::fail(
                "Allowlist integrity check failed — allowlist may have been tampered with",
            );
        }
        IntegrityResult::ok()
    }

    // ── Immutable builders ───────────────────────────────────────────────────

    /// Add a signature, replacing any existing entry from the same signer.
    pub fn with_signature(&self, sig: MajikSignatureJSON) -> R<MajikSignatureEnvelope> {
        if self.is_sealed() {
            return Err(MajikSignatureError::new("Cannot add a signature to a sealed envelope."));
        }
        let mut next = self.data.clone();
        match next.signatures.iter().position(|s| s.signer_id == sig.signer_id) {
            Some(i) => next.signatures[i] = sig,
            None => next.signatures.push(sig),
        }
        Ok(Self::new(next))
    }

    /// Establish the allowlist. Only the first signer may do so, and only once.
    pub fn with_allowlist(&self, allowlist: &[ExpectedSigner], signer_id: &str) -> R<MajikSignatureEnvelope> {
        if self.has_allowlist() {
            return Err(MajikSignatureError::new(
                "This envelope already has an established allowlist. It cannot be replaced.",
            ));
        }
        if !self.is_first_signer() {
            return Err(MajikSignatureError::new(
                "An allowlist can only be established by the first signer on a file.",
            ));
        }
        if allowlist.is_empty() {
            return Err(MajikSignatureError::validation(
                "Allowlist must contain at least one entry.",
                Some("allowlist"),
            ));
        }
        let mut next = self.data.clone();
        next.allowlist = Some(allowlist.to_vec());
        next.allowlist_signer_id = Some(signer_id.to_string());
        Ok(Self::new(next))
    }

    /// Seal the envelope (SHA3-512 over the signatory set + timestamp). Issuer-only when an
    /// allowlist exists. Produces no new cryptographic signature.
    pub fn with_seal(&self, sealed_by: &str, seal_timestamp: Option<&str>) -> R<MajikSignatureEnvelope> {
        if self.is_sealed() {
            return Err(MajikSignatureError::new("This envelope is already sealed."));
        }
        if self.has_allowlist() && self.data.allowlist_signer_id.as_deref() != Some(sealed_by) {
            return Err(MajikSignatureError::key(format!(
                "Only the issuer (\"{}\") may seal this file. Provided fingerprint: \"{}\".",
                self.data.allowlist_signer_id.as_deref().unwrap_or("undefined"),
                sealed_by
            )));
        }
        let ts = seal_timestamp.map(str::to_string).unwrap_or_else(now_iso);
        let seal_hash = self.compute_seal_hash(&ts);
        let mut next = self.data.clone();
        next.seal_hash = Some(seal_hash);
        next.seal_timestamp = Some(ts);
        next.sealed_by = Some(sealed_by.to_string());
        Ok(Self::new(next))
    }

    /// Register a confirmed chain anchor (replaces one with the same `id`).
    pub fn with_chain_anchor(&self, anchor: MajikChainAnchor) -> R<MajikSignatureEnvelope> {
        if !self.is_sealed() {
            return Err(MajikSignatureError::new(
                "Cannot register a chain anchor — envelope must be sealed first.",
            ));
        }
        if Some(anchor.payload.digest.value.as_str()) != self.data.seal_hash.as_deref() {
            return Err(MajikSignatureError::new(
                "Chain anchor digest does not match the envelope's current seal hash.",
            ));
        }
        let mut anchors = self.chain_anchors().to_vec();
        match anchors.iter().position(|a| a.id == anchor.id) {
            Some(i) => anchors[i] = anchor,
            None => anchors.push(anchor),
        }
        let mut next = self.data.clone();
        next.chain_anchors = Some(anchors);
        Ok(Self::new(next))
    }

    // ── Seal ─────────────────────────────────────────────────────────────────

    fn compute_seal_hash(&self, seal_timestamp: &str) -> String {
        #[derive(serde::Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Signatory<'a> {
            signer_id: &'a str,
            ed_public_key: &'a str,
            ml_dsa_public_key: &'a str,
        }
        #[derive(serde::Serialize)]
        struct Body<'a> {
            ts: &'a str,
            signatories: Vec<Signatory<'a>>,
        }

        let mut sigs: Vec<&MajikSignatureJSON> = self.data.signatures.iter().collect();
        sigs.sort_by(|a, b| locale_compare(&a.signer_id, &b.signer_id));
        let body = to_json_bytes(&Body {
            ts: seal_timestamp,
            signatories: sigs
                .iter()
                .map(|s| Signatory {
                    signer_id: &s.signer_id,
                    ed_public_key: &s.signer_ed_public_key,
                    ml_dsa_public_key: &s.signer_ml_dsa_public_key,
                })
                .collect(),
        });
        let mut hasher = Sha3_512::new();
        hasher.update(MAJIK_SEAL_DOMAIN.as_bytes());
        hasher.update(&body);
        hex::encode(hasher.finalize())
    }

    /// Recompute the seal hash and compare. Does NOT verify individual signatures.
    pub fn verify_seal(&self) -> SealVerificationResult {
        let (Some(hash), Some(ts), Some(by)) = (
            self.data.seal_hash.as_deref().filter(|s| !s.is_empty()),
            self.data.seal_timestamp.as_deref().filter(|s| !s.is_empty()),
            self.data.sealed_by.as_deref().filter(|s| !s.is_empty()),
        ) else {
            return SealVerificationResult {
                valid: false,
                reason: Some("Envelope is not sealed".into()),
                ..Default::default()
            };
        };
        if self.compute_seal_hash(ts) != hash {
            return SealVerificationResult {
                valid: false,
                sealed_by: Some(by.to_string()),
                seal_timestamp: Some(ts.to_string()),
                reason: Some(
                    "Seal hash does not match — signatories or timestamp may have been tampered with".into(),
                ),
            };
        }
        SealVerificationResult {
            valid: true,
            sealed_by: Some(by.to_string()),
            seal_timestamp: Some(ts.to_string()),
            reason: None,
        }
    }

    pub fn get_seal_info(&self) -> Option<SealInfo> {
        match (
            self.data.seal_hash.as_deref().filter(|s| !s.is_empty()),
            self.data.seal_timestamp.as_deref().filter(|s| !s.is_empty()),
            self.data.sealed_by.as_deref().filter(|s| !s.is_empty()),
        ) {
            (Some(h), Some(t), Some(b)) => Some(SealInfo {
                seal_hash: h.to_string(),
                seal_timestamp: t.to_string(),
                sealed_by: b.to_string(),
            }),
            _ => None,
        }
    }

    pub fn can_anchor(&self) -> CanAnchorResult {
        if !self.is_sealed() {
            return CanAnchorResult {
                permitted: false,
                reason: Some("Envelope is not sealed. Anchoring requires a sealed envelope.".into()),
            };
        }
        CanAnchorResult { permitted: true, reason: None }
    }

    // ── Signatories / issuer / info ──────────────────────────────────────────

    pub fn resolve_issuer(&self) -> Option<SignatoryInfo> {
        if let Some(issuer_id) = self.data.allowlist_signer_id.as_deref().filter(|s| !s.is_empty()) {
            let entry =
                self.data.allowlist.as_ref().and_then(|l| l.iter().find(|e| e.signer_id == issuer_id));
            if let Some(entry) = entry {
                let sig = self.find_signature(issuer_id);
                return Some(SignatoryInfo {
                    signer_id: entry.signer_id.clone(),
                    ed_public_key: entry.ed_public_key.clone(),
                    ml_dsa_public_key: entry.ml_dsa_public_key.clone(),
                    has_signed: sig.is_some(),
                    signed_at: sig.map(|s| s.timestamp.clone()),
                });
            }
        }
        self.data.signatures.first().map(|first| SignatoryInfo {
            signer_id: first.signer_id.clone(),
            ed_public_key: first.signer_ed_public_key.clone(),
            ml_dsa_public_key: first.signer_ml_dsa_public_key.clone(),
            has_signed: true,
            signed_at: Some(first.timestamp.clone()),
        })
    }

    /// All / signed / pending signatories. `None` when there is no allowlist and no signature.
    ///
    /// As in TS, `filter` does not change which sets are returned — all three are always
    /// populated (the filtered views are provided by the `MajikSignature::get_*_signatories`
    /// conveniences).
    pub fn get_signatories(&self, _filter: Option<SignatoriesFilter>) -> Option<SignatoriesResult> {
        let all: Vec<SignatoryInfo> = if self.has_allowlist() {
            // Insertion-ordered map keyed by signerId (later duplicates overwrite in place).
            let mut by_id: Vec<SignatoryInfo> = Vec::new();
            for entry in self.data.allowlist.as_deref().unwrap_or(&[]) {
                let sig = self.find_signature(&entry.signer_id);
                let info = SignatoryInfo {
                    signer_id: entry.signer_id.clone(),
                    ed_public_key: entry.ed_public_key.clone(),
                    ml_dsa_public_key: entry.ml_dsa_public_key.clone(),
                    has_signed: sig.is_some(),
                    signed_at: sig.map(|s| s.timestamp.clone()),
                };
                match by_id.iter().position(|x| x.signer_id == entry.signer_id) {
                    Some(i) => by_id[i] = info,
                    None => by_id.push(info),
                }
            }
            for sig in &self.data.signatures {
                if !by_id.iter().any(|x| x.signer_id == sig.signer_id) {
                    by_id.push(SignatoryInfo {
                        signer_id: sig.signer_id.clone(),
                        ed_public_key: sig.signer_ed_public_key.clone(),
                        ml_dsa_public_key: sig.signer_ml_dsa_public_key.clone(),
                        has_signed: true,
                        signed_at: Some(sig.timestamp.clone()),
                    });
                }
            }
            by_id
        } else {
            if self.data.signatures.is_empty() {
                return None;
            }
            self.data
                .signatures
                .iter()
                .map(|sig| SignatoryInfo {
                    signer_id: sig.signer_id.clone(),
                    ed_public_key: sig.signer_ed_public_key.clone(),
                    ml_dsa_public_key: sig.signer_ml_dsa_public_key.clone(),
                    has_signed: true,
                    signed_at: Some(sig.timestamp.clone()),
                })
                .collect()
        };
        let signed = all.iter().filter(|s| s.has_signed).cloned().collect();
        let pending = all.iter().filter(|s| !s.has_signed).cloned().collect();
        Some(SignatoriesResult { all, signed, pending })
    }

    pub fn get_envelope_info(&self) -> EnvelopeInfo {
        EnvelopeInfo {
            is_multi_sig: self.has_allowlist() || self.has_multiple_signatories(),
            has_multiple_signatories: self.has_multiple_signatories(),
            is_sealed: self.is_sealed(),
            seal_info: self.get_seal_info(),
            issuer: self.resolve_issuer(),
            signatories: self.get_signatories(None),
            allowlist: self.data.allowlist.clone(),
            signature_count: self.data.signatures.len(),
        }
    }

    // ── Serialization ────────────────────────────────────────────────────────

    pub fn to_json(&self) -> MajikSignatureEnvelopeJSON {
        self.data.clone()
    }

    pub fn to_json_string(&self) -> String {
        String::from_utf8(to_json_bytes(&self.data)).expect("serde_json emits UTF-8")
    }

    /// Base64 of the UTF-8 JSON.
    pub fn serialize(&self) -> String {
        B64.encode(to_json_bytes(&self.data))
    }

    pub fn deserialize(base64: &str) -> R<MajikSignatureEnvelope> {
        let bytes = B64.decode(base64.trim()).map_err(|e| {
            MajikSignatureError::serialization_with_cause("Failed to deserialize envelope from base64", e)
        })?;
        let text = String::from_utf8(bytes).map_err(|e| {
            MajikSignatureError::serialization_with_cause("Failed to deserialize envelope from base64", e)
        })?;
        Self::from_json_str(&text)
    }

    // ── MJKSIG binary format ─────────────────────────────────────────────────

    /// `[magic(6)][version(1)][reserved(1)][payloadLen(4, BE u32)][payload JSON]`.
    pub fn to_mjksig_bytes(&self) -> Vec<u8> {
        let payload = to_json_bytes(&self.data);
        let mut out = Vec::with_capacity(MJKSIG_HEADER_LEN + payload.len());
        out.extend_from_slice(&MJKSIG_MAGIC);
        out.push(MJKSIG_VERSION);
        out.push(0x00); // reserved — always 0 in v1
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&payload);
        out
    }

    /// TS `toMJKSIG(): Blob` — the blob is the raw bytes (media type: [`MJKSIG_MEDIA_TYPE`]).
    pub fn to_mjksig(&self) -> Vec<u8> {
        self.to_mjksig_bytes()
    }

    pub fn from_mjksig(raw: &[u8]) -> R<MajikSignatureEnvelope> {
        if raw.len() < MJKSIG_HEADER_LEN + 1 {
            return Err(MajikSignatureError::serialization(
                "Malformed MJKSIG: too short to contain a valid header",
            ));
        }
        if raw[..MJKSIG_MAGIC_LEN] != MJKSIG_MAGIC {
            return Err(MajikSignatureError::serialization(
                "Malformed MJKSIG: missing \"MJKSIG\" magic bytes",
            ));
        }
        let version = raw[MJKSIG_MAGIC_LEN];
        if !MJKSIG_SUPPORTED_VERSIONS.contains(&version) {
            return Err(MajikSignatureError::serialization(format!(
                "Unsupported MJKSIG version: {version} (supported: {})",
                MJKSIG_SUPPORTED_VERSIONS.iter().map(|v| v.to_string()).collect::<Vec<_>>().join(", ")
            )));
        }
        let off = MJKSIG_MAGIC_LEN + 2;
        let payload_len = u32::from_be_bytes([raw[off], raw[off + 1], raw[off + 2], raw[off + 3]]);
        // TS reads the length as a signed 32-bit int: >= 2^31 comes out negative.
        if payload_len == 0 || payload_len >= 0x8000_0000 {
            return Err(MajikSignatureError::serialization("Malformed MJKSIG: invalid payload length"));
        }
        let start = MJKSIG_HEADER_LEN;
        let end = start + payload_len as usize;
        if end > raw.len() {
            return Err(MajikSignatureError::serialization(
                "Malformed MJKSIG: declared payload length exceeds buffer",
            ));
        }
        let json = String::from_utf8_lossy(&raw[start..end]);
        Self::from_json_str(&json)
    }

    pub fn is_mjksig(input: &[u8]) -> bool {
        input.len() >= MJKSIG_MAGIC_LEN && input[..MJKSIG_MAGIC_LEN] == MJKSIG_MAGIC
    }

    pub fn get_mjksig_version(input: &[u8]) -> Option<u8> {
        if !Self::is_mjksig(input) || input.len() < MJKSIG_MAGIC_LEN + 1 {
            return None;
        }
        Some(input[MJKSIG_MAGIC_LEN])
    }

    // ── Factories ────────────────────────────────────────────────────────────

    pub fn empty() -> Self {
        Self::new(MultiSigEnvelope {
            version: MAJIK_ENVELOPE_VERSION,
            allowlist: None,
            allowlist_signer_id: None,
            signatures: Vec::new(),
            seal_hash: None,
            seal_timestamp: None,
            sealed_by: None,
            chain_anchors: None,
            file_versions: None,
        })
    }

    /// Parse JSON text: either a multi-sig envelope or a legacy single-signer
    /// `MajikSignatureJSON` (promoted into a one-signature envelope).
    pub fn from_json_str(json: &str) -> R<MajikSignatureEnvelope> {
        let parsed: Value = serde_json::from_str(json).map_err(|e| {
            MajikSignatureError::serialization_with_cause("Embedded signature payload is not valid JSON", e)
        })?;
        Self::from_json_value(parsed)
    }

    pub fn from_json_value(parsed: Value) -> R<MajikSignatureEnvelope> {
        let Value::Object(obj) = &parsed else {
            return Err(MajikSignatureError::serialization(
                "Embedded signature payload must be a JSON object",
            ));
        };
        let promoted: Value = if obj.get("signatures").map(Value::is_array).unwrap_or(false) {
            parsed.clone()
        } else if obj.get("edSignature").map(Value::is_string).unwrap_or(false) {
            serde_json::json!({ "version": MAJIK_ENVELOPE_VERSION, "signatures": [parsed.clone()] })
        } else {
            return Err(MajikSignatureError::serialization(
                "Unrecognised signature envelope format — expected MajikSignatureEnvelopeJSON or MajikSignatureJSON",
            ));
        };
        validate_shape(&promoted)?;
        let data: MultiSigEnvelope = serde_json::from_value(promoted).map_err(|e| {
            MajikSignatureError::serialization_with_cause("Embedded signature payload is malformed", e)
        })?;
        Ok(Self::new(data))
    }

    /// Validate-and-wrap a typed envelope JSON.
    pub fn from_json(json: &MajikSignatureEnvelopeJSON) -> R<MajikSignatureEnvelope> {
        let v = serde_json::to_value(json)
            .map_err(|e| MajikSignatureError::serialization_with_cause("Failed to serialize envelope", e))?;
        Self::from_json_value(v)
    }

    /// Wrap a single signer's JSON into a one-signature envelope.
    pub fn from_signature_json(sig: &MajikSignatureJSON) -> R<MajikSignatureEnvelope> {
        Self::from_json(&MultiSigEnvelope {
            version: MAJIK_ENVELOPE_VERSION,
            allowlist: None,
            allowlist_signer_id: None,
            signatures: vec![sig.clone()],
            seal_hash: None,
            seal_timestamp: None,
            sealed_by: None,
            chain_anchors: None,
            file_versions: None,
        })
    }

    /// Normalise any [`EnvelopeInput`] into an envelope.
    pub fn from_input(input: EnvelopeInput) -> R<MajikSignatureEnvelope> {
        match input {
            EnvelopeInput::Envelope(e) => Ok(e),
            EnvelopeInput::Json(j) => Self::from_json(&j),
            EnvelopeInput::Bytes(b) => Self::from_mjksig(&b),
        }
    }

    // ── Validation ───────────────────────────────────────────────────────────

    pub fn validate(&self) -> R<()> {
        let v = serde_json::to_value(&self.data)
            .map_err(|e| MajikSignatureError::serialization_with_cause("Failed to serialize envelope", e))?;
        validate_shape(&v)
    }

    pub fn is_valid(&self) -> bool {
        self.validate().is_ok()
    }
}

/// Compact JSON bytes for any serializable value (TS `JSON.stringify`).
fn to_json_bytes<T: serde::Serialize + ?Sized>(v: &T) -> Vec<u8> {
    serde_json::to_vec(v).expect("serializing plain data to JSON is infallible")
}

fn validate_shape(obj: &Value) -> R<()> {
    let verr = |m: String, f: &str| MajikSignatureError::validation(m, Some(f));
    let o = obj.as_object().ok_or_else(|| {
        MajikSignatureError::serialization("Embedded signature payload must be a JSON object")
    })?;

    if o.get("version").and_then(Value::as_u64) != Some(MAJIK_ENVELOPE_VERSION as u64) {
        let shown = match o.get("version") {
            Some(Value::String(s)) => s.clone(),
            Some(v) => v.to_string(),
            None => "undefined".to_string(),
        };
        return Err(verr(format!("Unsupported envelope version: {shown}"), "version"));
    }
    let sigs = o
        .get("signatures")
        .and_then(Value::as_array)
        .ok_or_else(|| verr("Envelope.signatures must be an array".into(), "signatures"))?;
    for (i, sig) in sigs.iter().enumerate() {
        validate_signature_entry(sig, i)?;
    }

    let has_allowlist = o.contains_key("allowlist");
    let has_signer = o.contains_key("allowlistSignerId");
    if has_allowlist != has_signer {
        return Err(verr("allowlist and allowlistSignerId must be set together".into(), "allowlist"));
    }
    if has_allowlist {
        let list = o.get("allowlist").and_then(Value::as_array).filter(|a| !a.is_empty());
        let Some(list) = list else {
            return Err(verr("allowlist must be a non-empty array when present".into(), "allowlist"));
        };
        for (i, entry) in list.iter().enumerate() {
            validate_expected_signer_entry(entry, i)?;
        }
        let ok =
            o.get("allowlistSignerId").and_then(Value::as_str).map(|s| !s.trim().is_empty()).unwrap_or(false);
        if !ok {
            return Err(verr(
                "allowlistSignerId must be a non-empty string when allowlist is set".into(),
                "allowlistSignerId",
            ));
        }
    }

    let present = ["sealHash", "sealTimestamp", "sealedBy"].iter().filter(|f| o.contains_key(**f)).count();
    if present > 0 && present < 3 {
        return Err(verr(
            "sealHash, sealTimestamp, and sealedBy must all be present together, or all absent".into(),
            "sealHash",
        ));
    }
    if let Some(ca) = o.get("chainAnchors") {
        if !ca.is_array() {
            return Err(verr("chainAnchors must be an array when present".into(), "chainAnchors"));
        }
    }
    if let Some(fv) = o.get("fileVersions") {
        if !fv.is_array() {
            return Err(verr("fileVersions must be an array when present".into(), "fileVersions"));
        }
    }
    Ok(())
}

fn validate_signature_entry(sig: &Value, index: usize) -> R<()> {
    let Some(obj) = sig.as_object() else {
        return Err(MajikSignatureError::validation(
            format!("signatures[{index}] must be an object"),
            Some("signatures"),
        ));
    };
    for field in [
        "signerId",
        "signerEdPublicKey",
        "signerMlDsaPublicKey",
        "contentHash",
        "timestamp",
        "edSignature",
        "mlDsaSignature",
    ] {
        let ok = obj.get(field).and_then(Value::as_str).map(|s| !s.is_empty()).unwrap_or(false);
        if !ok {
            return Err(MajikSignatureError::validation(
                format!("signatures[{index}].{field} must be a non-empty string"),
                Some(field),
            ));
        }
    }
    Ok(())
}

fn validate_expected_signer_entry(entry: &Value, index: usize) -> R<()> {
    let Some(obj) = entry.as_object() else {
        return Err(MajikSignatureError::validation(
            format!("allowlist[{index}] must be an object"),
            Some("allowlist"),
        ));
    };
    for field in ["signerId", "edPublicKey", "mlDsaPublicKey"] {
        let ok = obj.get(field).and_then(Value::as_str).map(|s| !s.is_empty()).unwrap_or(false);
        if !ok {
            return Err(MajikSignatureError::validation(
                format!("allowlist[{index}].{field} must be a non-empty string"),
                Some(field),
            ));
        }
    }
    Ok(())
}
