//! Port of `majik-signature.ts` — the `MajikSignature` class.
//!
//! Hybrid post-quantum signatures: every signature is produced by **both** Ed25519 and
//! ML-DSA-87 (FIPS 204) over the same canonical payload; both must verify.
//!
//! TS → Rust adaptations
//! - `async` / `Promise` / `Blob` / `Uint8Array` → synchronous functions over `&[u8]` / `Vec<u8>`.
//! - The `secureFill` clone-and-wipe dance disappears: secret material lives in
//!   [`zeroize::Zeroizing`] buffers (and the `ed25519-dalek` / `fips204` key types are
//!   `ZeroizeOnDrop`), so it is wiped on every exit path automatically.
//! - `Date` parameters become `Option<jiff::Timestamp>` (`None` = now).

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ed25519_dalek::{Signature as EdSignature, Signer as _, SigningKey, VerifyingKey};
use fips204::ml_dsa_87;
use fips204::traits::{SerDes as _, Signer as _, Verifier as _};
use jiff::Timestamp;
use majik_key::{KeyId, MajikKey};
use serde_json::Value;
use std::io::Read;
use zeroize::Zeroizing;

use crate::anchor::types::MajikChainAnchorMemo;
use crate::core::cbor::{decode_cbor, encode_cbor, signature_from_cbor, signature_to_cbor};
use crate::core::constants::*;
use crate::core::envelope::MajikSignatureEnvelope;
use crate::core::errors::{MajikSignatureError, MajikSignatureResult};
use crate::core::hash::{base64_to_bytes, bytes_to_base64, hash_content};
use crate::core::payload::{
    build_signature_attestation_bytes, build_signing_payload, build_tsa_canonical_bytes, PayloadFields,
};
use crate::core::streaming::{
    hash_reader, BatchStreamingOptions, StreamingBatchFileInput, StreamingBatchProgress,
    StreamingBatchVerifyInput, StreamingHashOptions, StreamingHashProgress,
};
use crate::core::time::{now_iso, parse_iso_millis, resolve_now, to_iso_string};
use crate::core::types::*;
use crate::core::validator::MajikSignatureValidator;

type R<T> = MajikSignatureResult<T>;

/// Anything that can be viewed as a [`MajikSignatureJSON`] (TS: `MajikSignature | MajikSignatureJSON`).
pub trait SignatureLike {
    fn to_signature_json(&self) -> MajikSignatureJSON;
}

impl SignatureLike for MajikSignatureJSON {
    fn to_signature_json(&self) -> MajikSignatureJSON {
        self.clone()
    }
}

impl SignatureLike for MajikSignature {
    fn to_signature_json(&self) -> MajikSignatureJSON {
        self.to_json()
    }
}

/// TS: `MajikKey | MajikSignerPublicKeys`.
#[derive(Clone, Copy)]
pub enum KeyOrPublicKeys<'a> {
    Key(&'a MajikKey),
    PublicKeys(&'a MajikSignerPublicKeys),
}

impl<'a> From<&'a MajikKey> for KeyOrPublicKeys<'a> {
    fn from(k: &'a MajikKey) -> Self {
        Self::Key(k)
    }
}
impl<'a> From<&'a MajikSignerPublicKeys> for KeyOrPublicKeys<'a> {
    fn from(k: &'a MajikSignerPublicKeys) -> Self {
        Self::PublicKeys(k)
    }
}

/// A hybrid Ed25519 + ML-DSA-87 content signature.
///
/// Immutable after construction except for the one-shot [`add_tsa`](Self::add_tsa).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MajikSignature {
    version: u8,
    signer_id: MajikKeyFingerprint,
    signer_ed_public_key: String,
    signer_ml_dsa_public_key: String,
    content_hash: String,
    content_type: Option<String>,
    timestamp: ISODateString,
    ed_signature: ED25519Signature,
    ml_dsa_signature: MLDSA87Signature,
    allowlist_hash: Option<String>,
    valid_until: Option<ISODateString>,
    version_chain_hash: Option<String>,
    session_context_hash: Option<String>,
    tsa: Option<MajikTimestamp>,
}

impl MajikSignature {
    fn new(data: MajikSignatureJSON) -> Self {
        Self {
            version: data.version,
            signer_id: data.signer_id,
            signer_ed_public_key: data.signer_ed_public_key,
            signer_ml_dsa_public_key: data.signer_ml_dsa_public_key,
            content_hash: data.content_hash,
            content_type: data.content_type,
            timestamp: data.timestamp,
            ed_signature: data.ed_signature,
            ml_dsa_signature: data.ml_dsa_signature,
            allowlist_hash: data.allowlist_hash,
            valid_until: data.valid_until,
            version_chain_hash: data.version_chain_hash,
            session_context_hash: data.session_context_hash,
            tsa: data.tsa,
        }
    }

    // ── Getters ──────────────────────────────────────────────────────────────

    pub fn version(&self) -> u8 {
        self.version
    }
    pub fn signer_id(&self) -> &str {
        &self.signer_id
    }
    pub fn signer_ed_public_key(&self) -> &str {
        &self.signer_ed_public_key
    }
    pub fn signer_ml_dsa_public_key(&self) -> &str {
        &self.signer_ml_dsa_public_key
    }
    pub fn content_hash(&self) -> &str {
        &self.content_hash
    }
    pub fn content_type(&self) -> Option<&str> {
        self.content_type.as_deref()
    }
    pub fn timestamp(&self) -> &str {
        &self.timestamp
    }
    pub fn ed_signature(&self) -> &str {
        &self.ed_signature
    }
    pub fn ml_dsa_signature(&self) -> &str {
        &self.ml_dsa_signature
    }
    /// SHA-256 of the canonical allowlist (base64). Present only on the issuer's signature.
    pub fn allowlist_hash(&self) -> Option<&str> {
        self.allowlist_hash.as_deref()
    }
    /// Expiry after which [`verify`](Self::verify) rejects this signature; `None` = never expires.
    pub fn valid_until(&self) -> Option<&str> {
        self.valid_until.as_deref()
    }
    pub fn version_chain_hash(&self) -> Option<&str> {
        self.version_chain_hash.as_deref()
    }
    /// Signed commitment to the SignRoom session, challenge, and policy.
    pub fn session_context_hash(&self) -> Option<&str> {
        self.session_context_hash.as_deref()
    }
    pub fn tsa(&self) -> Option<&MajikTimestamp> {
        self.tsa.as_ref()
    }
    pub fn has_tsa(&self) -> bool {
        self.tsa.is_some()
    }

    /// Structural expiry check against `valid_until` — does NOT verify the signature.
    pub fn is_expired(&self, now: Option<Timestamp>) -> bool {
        match self.valid_until.as_deref().and_then(parse_iso_millis) {
            Some(vu) => resolve_now(now).as_millisecond() > vu,
            None => false,
        }
    }

    // ── SIGN ─────────────────────────────────────────────────────────────────

    /// Sign content with an unlocked [`MajikKey`].
    ///
    /// Both Ed25519 and ML-DSA-87 sign the same canonical payload. `allowlist_hash`,
    /// `valid_until` and `version_chain_hash` (when given) are part of that payload, so a
    /// verifier cannot strip or alter them without invalidating the signature.
    pub fn sign(content: &[u8], key: &MajikKey, options: Option<&SignOptions>) -> R<MajikSignature> {
        MajikSignatureValidator::validate_content(content)?;
        Self::sign_digest(hash_content(content), key, options)
    }

    /// Sign bytes from a reader without materializing the complete input.
    /// The resulting contentHash is identical to sign() over the same bytes.
    pub fn sign_reader<Rd: Read>(
        reader: &mut Rd,
        key: &MajikKey,
        options: Option<&SignOptions>,
    ) -> R<MajikSignature> {
        let mut streaming = StreamingHashOptions::default();
        Self::sign_reader_with_options(reader, key, options, &mut streaming)
    }

    /// Configurable reader-based signing with progress, cancellation and input limits.
    pub fn sign_reader_with_options<Rd: Read + ?Sized>(
        reader: &mut Rd,
        key: &MajikKey,
        options: Option<&SignOptions>,
        streaming: &mut StreamingHashOptions<'_>,
    ) -> R<MajikSignature> {
        let result = hash_reader(reader, streaming)?;
        if result.bytes_processed == 0 {
            MajikSignatureValidator::validate_content(&[])?;
        }
        Self::sign_digest(result.digest, key, options)
    }

    fn sign_digest(
        content_hash_bytes: [u8; 32],
        key: &MajikKey,
        options: Option<&SignOptions>,
    ) -> R<MajikSignature> {
        let default_opts = SignOptions::default();
        let options = options.unwrap_or(&default_opts);

        MajikSignatureValidator::validate_content_type(options.content_type.as_deref())?;
        if let Some(timestamp) = options.timestamp.as_deref() {
            MajikSignatureValidator::validate_timestamp_for_signing(timestamp)?;
        }
        MajikSignatureValidator::validate_valid_until(options.valid_until.as_deref())?;
        if let Some(session_hash) = options.session_context_hash.as_deref() {
            MajikSignatureValidator::validate_session_context_hash(session_hash)?;
        }
        if let Some(hash) = options.allowlist_hash.as_deref() {
            MajikSignatureValidator::validate_sha256_digest(hash, "allowlistHash")?;
        }
        if let Some(hash) = options.version_chain_hash.as_deref() {
            MajikSignatureValidator::validate_sha256_digest(hash, "versionChainHash")?;
        }

        if key.is_locked() {
            return Err(MajikSignatureError::key("MajikKey is locked. Call unlock() before signing."));
        }
        if !key.has_keys(&[KeyId::Ed25519, KeyId::MlDsa87]) {
            return Err(MajikSignatureError::key(
                "MajikKey has no signing keys. Re-import via importFromMnemonicBackup() to enable signing.",
            ));
        }

        let ed_secret = key
            .get_private_key(KeyId::Ed25519)
            .map_err(|e| MajikSignatureError::key_with_cause("Failed to read Ed25519 secret key", e))?;
        let ml_dsa_secret = key
            .get_private_key(KeyId::MlDsa87)
            .map_err(|e| MajikSignatureError::key_with_cause("Failed to read ML-DSA-87 secret key", e))?;
        MajikSignatureValidator::validate_ed_secret_key(&ed_secret)?;
        MajikSignatureValidator::validate_ml_dsa_secret_key(&ml_dsa_secret)?;

        let ed_public_key = key
            .get_public_key(KeyId::Ed25519)
            .map_err(|e| MajikSignatureError::key_with_cause("Failed to read Ed25519 public key", e))?;
        let ml_dsa_public_key = key
            .get_public_key(KeyId::MlDsa87)
            .map_err(|e| MajikSignatureError::key_with_cause("Failed to read ML-DSA-87 public key", e))?;

        let content_hash = bytes_to_base64(&content_hash_bytes);
        let timestamp = options.timestamp.clone().unwrap_or_else(now_iso);
        let signer_id = key.fingerprint().to_string();

        let payload = build_signing_payload(&PayloadFields {
            signer_id: &signer_id,
            timestamp: &timestamp,
            content_hash: &content_hash,
            content_type: options.content_type.as_deref(),
            allowlist_hash: options.allowlist_hash.as_deref(),
            valid_until: options.valid_until.as_deref(),
            version_chain_hash: options.version_chain_hash.as_deref(),
            session_context_hash: options.session_context_hash.as_deref(),
        });

        let ed_sig_bytes = {
            let mut seed = Zeroizing::new([0u8; 32]);
            seed.copy_from_slice(&ed_secret[..32]);
            let signing_key = SigningKey::from_bytes(&seed);
            signing_key.sign(&payload).to_bytes()
        };

        let ml_dsa_sig_bytes = {
            let mut sk_bytes = Zeroizing::new([0u8; ML_DSA_87_SECRET_KEY_LEN]);
            sk_bytes.copy_from_slice(&ml_dsa_secret);
            let sk =
                ml_dsa_87::PrivateKey::try_from_bytes(*sk_bytes).map_err(|e| MajikSignatureError::Key {
                    message: format!("Invalid ML-DSA-87 secret key: {e}"),
                    cause: None,
                })?;
            sk.try_sign(&payload, &[]).map_err(|e| MajikSignatureError::Generic {
                message: format!("Failed to sign content: {e}"),
                cause: None,
            })?
        };

        Ok(MajikSignature::new(MajikSignatureJSON {
            version: MAJIK_SIGNATURE_VERSION,
            signer_id,
            signer_ed_public_key: bytes_to_base64(&ed_public_key),
            signer_ml_dsa_public_key: bytes_to_base64(&ml_dsa_public_key),
            content_hash,
            content_type: options.content_type.clone(),
            timestamp,
            ed_signature: bytes_to_base64(&ed_sig_bytes),
            ml_dsa_signature: bytes_to_base64(&ml_dsa_sig_bytes),
            allowlist_hash: options.allowlist_hash.clone(),
            valid_until: options.valid_until.clone(),
            tsa: None,
            version_chain_hash: options.version_chain_hash.clone(),
            session_context_hash: options.session_context_hash.clone(),
        }))
    }

    // ── VERIFY ───────────────────────────────────────────────────────────────

    /// Verify content against a signature and the signer's public keys.
    ///
    /// Both Ed25519 AND ML-DSA-87 must verify. Expiry (`valid_until`) is checked only after both
    /// signatures pass, so a forged-but-expired signature is reported as an invalid signature.
    /// `now` defaults to the current time.
    pub fn verify<S: SignatureLike + ?Sized>(
        content: &[u8],
        signature: &S,
        public_keys: &MajikSignerPublicKeys,
        now: Option<Timestamp>,
    ) -> R<VerificationResult> {
        MajikSignatureValidator::validate_content(content)?;
        Self::verify_digest_bytes(hash_content(content), signature, public_keys, now)
    }

    /// Verify reader content without materializing the complete input.
    pub fn verify_reader<S: SignatureLike + ?Sized, Rd: Read>(
        reader: &mut Rd,
        signature: &S,
        public_keys: &MajikSignerPublicKeys,
        now: Option<Timestamp>,
    ) -> R<VerificationResult> {
        let mut streaming = StreamingHashOptions::default();
        Self::verify_reader_with_options(reader, signature, public_keys, now, &mut streaming)
    }

    /// Configurable reader-based verification with progress, cancellation and input limits.
    pub fn verify_reader_with_options<S: SignatureLike + ?Sized, Rd: Read>(
        reader: &mut Rd,
        signature: &S,
        public_keys: &MajikSignerPublicKeys,
        now: Option<Timestamp>,
        streaming: &mut StreamingHashOptions<'_>,
    ) -> R<VerificationResult> {
        let result = hash_reader(reader, streaming)?;
        if result.bytes_processed == 0 {
            MajikSignatureValidator::validate_content(&[])?;
        }
        Self::verify_digest_bytes(result.digest, signature, public_keys, now)
    }

    fn verify_digest_bytes<S: SignatureLike + ?Sized>(
        digest: [u8; 32],
        signature: &S,
        public_keys: &MajikSignerPublicKeys,
        now: Option<Timestamp>,
    ) -> R<VerificationResult> {
        MajikSignatureValidator::validate_signer_public_keys(public_keys)?;
        let env = signature.to_signature_json();
        MajikSignatureValidator::validate_json(&env)?;

        let invalid = |reason: Option<String>| VerificationResult {
            valid: false,
            signer_id: Some(env.signer_id.clone()),
            content_hash: Some(env.content_hash.clone()),
            timestamp: env.timestamp.clone(),
            content_type: env.content_type.clone(),
            session_context_hash: env.session_context_hash.clone(),
            reason,
            ..Default::default()
        };

        if public_keys.signer_id != env.signer_id {
            return Ok(invalid(Some("Signer key fingerprint does not match signature signerId".into())));
        }
        if bytes_to_base64(&public_keys.ed_public_key) != env.signer_ed_public_key
            || bytes_to_base64(&public_keys.ml_dsa_public_key) != env.signer_ml_dsa_public_key
        {
            return Ok(invalid(Some("Supplied signer public keys do not match the signature record".into())));
        }

        let recomputed = bytes_to_base64(&digest);
        if recomputed != env.content_hash {
            return Ok(invalid(None));
        }

        let payload = payload_for(&env);
        if let Some(reason) = check_crypto(&env, public_keys, &payload) {
            return Ok(invalid(Some(reason)));
        }

        if let Some(vu) = env.valid_until.as_deref().and_then(parse_iso_millis) {
            let now = resolve_now(now);
            if now.as_millisecond() > vu {
                let mut r = invalid(Some(format!(
                    "Signature expired at {} (verified at {})",
                    env.valid_until.as_deref().unwrap_or_default(),
                    to_iso_string(now)
                )));
                r.expired = Some(true);
                return Ok(r);
            }
        }

        Ok(VerificationResult {
            valid: true,
            signer_id: Some(env.signer_id),
            content_hash: Some(env.content_hash),
            timestamp: env.timestamp,
            content_type: env.content_type,
            session_context_hash: env.session_context_hash,
            ..Default::default()
        })
    }

    /// Verify the cryptographic signatures of an envelope WITHOUT checking them against any
    /// content — used to validate a revision's commitment (`versionChainHash`) in isolation.
    pub fn verify_commitment<S: SignatureLike + ?Sized>(
        signature: &S,
        public_keys: &MajikSignerPublicKeys,
        now: Option<Timestamp>,
    ) -> R<RevisionCommitmentResult> {
        MajikSignatureValidator::validate_signer_public_keys(public_keys)?;
        let env = signature.to_signature_json();
        MajikSignatureValidator::validate_json(&env)?;

        let invalid = |reason: Option<String>| RevisionCommitmentResult {
            base: VerificationResult {
                valid: false,
                signer_id: Some(env.signer_id.clone()),
                content_hash: Some(env.content_hash.clone()),
                timestamp: env.timestamp.clone(),
                content_type: env.content_type.clone(),
                session_context_hash: env.session_context_hash.clone(),
                reason,
                ..Default::default()
            },
            commitment_only: true,
        };

        if public_keys.signer_id != env.signer_id {
            return Ok(invalid(Some("Signer key fingerprint does not match signature signerId".into())));
        }
        if bytes_to_base64(&public_keys.ed_public_key) != env.signer_ed_public_key
            || bytes_to_base64(&public_keys.ml_dsa_public_key) != env.signer_ml_dsa_public_key
        {
            return Ok(invalid(Some("Supplied signer public keys do not match the signature record".into())));
        }

        let payload = payload_for(&env);
        if let Some(reason) = check_crypto(&env, public_keys, &payload) {
            return Ok(invalid(Some(reason)));
        }

        if let Some(vu) = env.valid_until.as_deref().and_then(parse_iso_millis) {
            if resolve_now(now).as_millisecond() > vu {
                let mut r = invalid(Some(format!(
                    "Signature expired at {}",
                    env.valid_until.as_deref().unwrap_or_default()
                )));
                r.base.expired = Some(true);
                return Ok(r);
            }
        }

        Ok(RevisionCommitmentResult {
            base: VerificationResult {
                valid: true,
                signer_id: Some(env.signer_id),
                content_hash: Some(env.content_hash),
                timestamp: env.timestamp,
                content_type: env.content_type,
                session_context_hash: env.session_context_hash,
                ..Default::default()
            },
            commitment_only: true,
        })
    }

    /// Verify a hybrid signature against a trusted SHA-256 digest without plaintext bytes.
    ///
    /// Session-bound signatures require `expected_session_context_hash` to be supplied.
    /// Challenge issuance/consumption, signer authorization, and TSA trust remain
    /// responsibilities of the calling application.
    pub fn verify_digest<S: SignatureLike + ?Sized>(
        expected_content_hash: &str,
        signature: &S,
        public_keys: &MajikSignerPublicKeys,
        expected_session_context_hash: Option<&str>,
        now: Option<Timestamp>,
    ) -> R<RevisionCommitmentResult> {
        MajikSignatureValidator::validate_signer_public_keys(public_keys)?;
        let env = signature.to_signature_json();
        MajikSignatureValidator::validate_json(&env)?;

        let invalid = |reason: &str| RevisionCommitmentResult {
            base: VerificationResult {
                valid: false,
                signer_id: Some(env.signer_id.clone()),
                content_hash: Some(env.content_hash.clone()),
                timestamp: env.timestamp.clone(),
                content_type: env.content_type.clone(),
                session_context_hash: env.session_context_hash.clone(),
                reason: Some(reason.to_string()),
                ..Default::default()
            },
            commitment_only: true,
        };

        if expected_content_hash.len() != CONTENT_HASH_B64_LEN {
            return Ok(invalid("Expected content hash must be a base64 SHA-256 digest"));
        }
        let digest_bytes = match base64_to_bytes(expected_content_hash) {
            Ok(bytes) => bytes,
            Err(_) => return Ok(invalid("Expected content hash is not a valid base64 SHA-256 digest")),
        };
        if digest_bytes.len() != 32 || bytes_to_base64(&digest_bytes) != expected_content_hash {
            return Ok(invalid("Expected content hash is not a canonical SHA-256 digest"));
        }
        if env.content_hash != expected_content_hash {
            return Ok(invalid("Signature contentHash does not match the expected digest"));
        }

        match expected_session_context_hash {
            Some(expected) => {
                if MajikSignatureValidator::validate_session_context_hash(expected).is_err() {
                    return Ok(invalid("Expected session context hash is invalid"));
                }
                if env.session_context_hash.as_deref() != Some(expected) {
                    return Ok(invalid("Signature session context does not match the expected session"));
                }
            }
            None if env.session_context_hash.is_some() => {
                return Ok(invalid("Expected session context hash is required for session-bound signatures"));
            }
            None => {}
        }

        if public_keys.signer_id != env.signer_id {
            return Ok(invalid("Signer key fingerprint does not match signature signerId"));
        }

        Self::verify_commitment(signature, public_keys, now)
    }
    // ── SELF-VALIDATE ────────────────────────────────────────────────────────

    pub fn validate(&self) -> R<()> {
        MajikSignatureValidator::validate_json(&self.to_json())
    }

    pub fn is_valid(&self) -> bool {
        self.validate().is_ok()
    }

    // ── EXTRACT PUBLIC KEYS ──────────────────────────────────────────────────

    pub fn extract_public_keys(&self) -> R<MajikSignerPublicKeys> {
        let ed = base64_to_bytes(&self.signer_ed_public_key).map_err(|e| {
            MajikSignatureError::key_with_cause("Failed to extract public keys from envelope", e)
        })?;
        let ml = base64_to_bytes(&self.signer_ml_dsa_public_key).map_err(|e| {
            MajikSignatureError::key_with_cause("Failed to extract public keys from envelope", e)
        })?;
        MajikSignatureValidator::assert_bytes(&ed, "signerEdPublicKey", Some(ED25519_PUBLIC_KEY_LEN))?;
        MajikSignatureValidator::assert_bytes(&ml, "signerMlDsaPublicKey", Some(ML_DSA_87_PUBLIC_KEY_LEN))?;
        Ok(MajikSignerPublicKeys {
            signer_id: self.signer_id.clone(),
            ed_public_key: ed,
            ml_dsa_public_key: ml,
        })
    }

    // ── SERIALIZATION ────────────────────────────────────────────────────────

    pub fn to_json(&self) -> MajikSignatureJSON {
        MajikSignatureJSON {
            version: self.version,
            signer_id: self.signer_id.clone(),
            signer_ed_public_key: self.signer_ed_public_key.clone(),
            signer_ml_dsa_public_key: self.signer_ml_dsa_public_key.clone(),
            content_hash: self.content_hash.clone(),
            content_type: self.content_type.clone(),
            timestamp: self.timestamp.clone(),
            ed_signature: self.ed_signature.clone(),
            ml_dsa_signature: self.ml_dsa_signature.clone(),
            allowlist_hash: self.allowlist_hash.clone(),
            valid_until: self.valid_until.clone(),
            tsa: self.tsa.clone(),
            version_chain_hash: self.version_chain_hash.clone(),
            session_context_hash: self.session_context_hash.clone(),
        }
    }

    /// Compact JSON string of [`to_json`](Self::to_json) (TS `JSON.stringify(toJSON())`).
    pub fn to_json_string(&self) -> R<String> {
        serde_json::to_string(&self.to_json())
            .map_err(|e| MajikSignatureError::serialization_with_cause("Failed to serialize signature", e))
    }

    /// Encode as raw CBOR with native byte strings for cryptographic fields.
    pub fn to_cbor(&self) -> R<Vec<u8>> {
        signature_to_cbor(&self.to_json()).and_then(|value| encode_cbor(&value)).map_err(|e| {
            MajikSignatureError::serialization_with_cause("Failed to serialize signature as CBOR", e)
        })
    }

    /// Base64 of the UTF-8 JSON — the portable single-string form.
    pub fn serialize(&self) -> R<String> {
        Ok(B64.encode(self.to_json_string()?.as_bytes()))
    }

    // ── DESERIALIZATION ──────────────────────────────────────────────────────

    /// Validate and wrap a typed envelope.
    pub fn from_json(json: &MajikSignatureJSON) -> R<MajikSignature> {
        MajikSignatureValidator::validate_json(json)?;
        Ok(MajikSignature::new(json.clone()))
    }

    /// Parse and validate JSON text.
    pub fn from_json_str(json: &str) -> R<MajikSignature> {
        let value: Value = serde_json::from_str(json).map_err(|e| {
            MajikSignatureError::serialization_with_cause("Failed to parse MajikSignature from JSON", e)
        })?;
        Self::from_json_value(&value)
    }

    /// Validate untrusted JSON and wrap it.
    pub fn from_json_value(value: &Value) -> R<MajikSignature> {
        Ok(MajikSignature::new(MajikSignatureValidator::parse_json_value(value)?))
    }

    /// Decode raw CBOR into a structurally validated signature.
    pub fn from_cbor(input: &[u8]) -> R<MajikSignature> {
        let json = decode_cbor(input).and_then(|value| signature_from_cbor(&value)).map_err(|e| {
            MajikSignatureError::serialization_with_cause("Failed to deserialize signature from CBOR", e)
        })?;
        Self::from_json(&json)
    }

    pub fn deserialize(base64: &str) -> R<MajikSignature> {
        MajikSignatureValidator::assert_non_empty_string(base64, "base64")?;
        let bytes = B64.decode(base64.trim()).map_err(|e| {
            MajikSignatureError::serialization_with_cause(
                "Failed to deserialize MajikSignature from base64",
                e,
            )
        })?;
        let text = String::from_utf8(bytes).map_err(|e| {
            MajikSignatureError::serialization_with_cause(
                "Failed to deserialize MajikSignature from base64",
                e,
            )
        })?;
        Self::from_json_str(&text)
    }

    // ── STATIC KEY HELPERS ───────────────────────────────────────────────────

    pub fn public_keys_from_majik_key(key: &MajikKey) -> R<MajikSignerPublicKeys> {
        let (ed, ml) = signing_public_keys(
            key,
            "MajikKey has no signing public keys. Key may need re-import via importFromMnemonicBackup().",
        )?;
        MajikSignatureValidator::assert_bytes(&ed, "edPublicKey", Some(ED25519_PUBLIC_KEY_LEN))?;
        MajikSignatureValidator::assert_bytes(&ml, "mlDsaPublicKey", Some(ML_DSA_87_PUBLIC_KEY_LEN))?;
        Ok(MajikSignerPublicKeys {
            signer_id: key.fingerprint().to_string(),
            ed_public_key: ed,
            ml_dsa_public_key: ml,
        })
    }

    pub fn verify_with_key<S: SignatureLike + ?Sized>(
        content: &[u8],
        signature: &S,
        key: &MajikKey,
    ) -> R<VerificationResult> {
        Self::verify(content, signature, &Self::public_keys_from_majik_key(key)?, None)
    }

    /// Build an [`ExpectedSigner`] from a key (the key need not be unlocked).
    pub fn expected_signer_from_key(key: &MajikKey) -> R<ExpectedSigner> {
        let (ed, ml) =
            signing_public_keys(key, "MajikKey has no signing public keys — cannot build ExpectedSigner.")?;
        Ok(ExpectedSigner {
            signer_id: key.fingerprint().to_string(),
            ed_public_key: bytes_to_base64(&ed),
            ml_dsa_public_key: bytes_to_base64(&ml),
        })
    }

    // ── TRUSTED TIMESTAMPS ───────────────────────────────────────────────────

    /// Build a legacy content-scoped TSA request.
    pub fn build_tsa_request_payload(&self) -> MajikTsaRequest {
        self.build_tsa_request_payload_with_scope(None)
    }

    /// Build a TSA request scoped to the document content or the complete signer record.
    /// `None` and `Some(Content)` preserve the legacy content-hash request shape.
    pub fn build_tsa_request_payload_with_scope(&self, scope: Option<TsaDigestScope>) -> MajikTsaRequest {
        let (value, scope) = match scope {
            Some(TsaDigestScope::Signature) => {
                let attestation = build_signature_attestation_bytes(&self.to_json());
                (bytes_to_base64(&hash_content(&attestation)), Some(TsaDigestScope::Signature))
            }
            Some(TsaDigestScope::Content) | None => (self.content_hash.clone(), None),
        };
        MajikTsaRequest { digest: TsaDigest { algorithm: "SHA-256".into(), value, scope } }
    }

    /// Attach a trusted timestamp. One-shot: a TSA cannot be replaced once set.
    /// For compatibility, this uses the TSA public key embedded in the timestamp.
    pub fn add_tsa(&mut self, tsa: MajikTimestamp) -> R<()> {
        self.add_tsa_with_trusted_keys(tsa, None)
    }

    /// Attach a timestamp, optionally pinning it to an independently trusted TSA key.
    pub fn add_tsa_with_trusted_keys(
        &mut self,
        tsa: MajikTimestamp,
        trusted_tsa_public_keys: Option<&MajikSignerPublicKeys>,
    ) -> R<()> {
        if self.tsa.is_some() {
            return Err(MajikSignatureError::new("TSA is already set and cannot be replaced"));
        }
        MajikSignatureValidator::validate_majik_timestamp(&tsa)?;
        let expected_digest = match tsa.payload.digest.scope {
            Some(TsaDigestScope::Signature) => {
                let attestation = build_signature_attestation_bytes(&self.to_json());
                bytes_to_base64(&hash_content(&attestation))
            }
            Some(TsaDigestScope::Content) | None => self.content_hash.clone(),
        };
        if tsa.payload.digest.value != expected_digest {
            let message = if tsa.payload.digest.scope == Some(TsaDigestScope::Signature) {
                "TSA digest does not match the canonical signature record"
            } else {
                "TSA digest does not match signature contentHash"
            };
            return Err(MajikSignatureError::new(message));
        }
        if tsa.payload.tsa.signer_fingerprint != tsa.signature.signer_id {
            return Err(MajikSignatureError::verification(
                "TSA identity fingerprint does not match the embedded TSA signer",
            ));
        }

        let canonical = build_tsa_canonical_bytes(&tsa.payload);
        let tsa_sig = MajikSignature::from_json(&tsa.signature)?;
        let embedded_public_keys = tsa_sig.extract_public_keys()?;
        let verification_keys = if let Some(trusted) = trusted_tsa_public_keys {
            MajikSignatureValidator::validate_signer_public_keys(trusted)?;
            if tsa.payload.tsa.signer_fingerprint != trusted.signer_id
                || tsa.signature.signer_id != trusted.signer_id
            {
                return Err(MajikSignatureError::verification(
                    "TSA identity does not match the trusted TSA public-key fingerprint",
                ));
            }
            trusted
        } else {
            &embedded_public_keys
        };
        let result = MajikSignature::verify(&canonical, &tsa_sig, verification_keys, None)?;
        if !result.valid {
            return Err(MajikSignatureError::verification(format!(
                "TSA signature verification failed: {}",
                result.reason.as_deref().unwrap_or("unknown")
            )));
        }
        self.tsa = Some(tsa);
        Ok(())
    }

    /// Re-verify the embedded TSA token (e.g. after deserialization).
    /// Uses the embedded TSA public key unless a trusted key is explicitly supplied.
    pub fn verify_tsa(&self) -> R<VerificationResult> {
        self.verify_tsa_with_trusted_keys(None)
    }

    /// Re-verify the embedded TSA token, optionally pinning its identity to a trusted key.
    pub fn verify_tsa_with_trusted_keys(
        &self,
        trusted_tsa_public_keys: Option<&MajikSignerPublicKeys>,
    ) -> R<VerificationResult> {
        let tsa =
            self.tsa.as_ref().ok_or_else(|| MajikSignatureError::new("No TSA present on this signature"))?;
        let expected_digest = match tsa.payload.digest.scope {
            Some(TsaDigestScope::Signature) => {
                let attestation = build_signature_attestation_bytes(&self.to_json());
                bytes_to_base64(&hash_content(&attestation))
            }
            Some(TsaDigestScope::Content) | None => self.content_hash.clone(),
        };
        if tsa.payload.digest.value != expected_digest {
            let message = if tsa.payload.digest.scope == Some(TsaDigestScope::Signature) {
                "TSA digest does not match the canonical signature record"
            } else {
                "TSA digest does not match signature contentHash"
            };
            return Err(MajikSignatureError::new(message));
        }
        if tsa.payload.tsa.signer_fingerprint != tsa.signature.signer_id {
            return Err(MajikSignatureError::verification(
                "TSA identity fingerprint does not match the embedded TSA signer",
            ));
        }

        let canonical = build_tsa_canonical_bytes(&tsa.payload);
        let tsa_sig = MajikSignature::from_json(&tsa.signature)?;
        let embedded_public_keys = tsa_sig.extract_public_keys()?;
        let verification_keys = if let Some(trusted) = trusted_tsa_public_keys {
            MajikSignatureValidator::validate_signer_public_keys(trusted)?;
            if tsa.payload.tsa.signer_fingerprint != trusted.signer_id
                || tsa.signature.signer_id != trusted.signer_id
            {
                return Err(MajikSignatureError::verification(
                    "TSA identity does not match the trusted TSA public-key fingerprint",
                ));
            }
            trusted
        } else {
            &embedded_public_keys
        };
        MajikSignature::verify(&canonical, &tsa_sig, verification_keys, None)
    }

    /// Sign a TSA request and return a complete [`MajikTimestamp`] (server-side use).
    pub fn sign_tsa(
        request: &MajikTsaRequest,
        key: &MajikKey,
        tsa: MajikTsaIdentity,
        timestamp: Option<&str>,
    ) -> R<MajikTimestamp> {
        let mut nonce = [0u8; 32];
        getrandom::fill(&mut nonce).map_err(|e| {
            MajikSignatureError::new(format!("Failed to gather randomness for TSA nonce: {e}"))
        })?;
        let payload = MajikTsaPayload {
            digest: request.digest.clone(),
            nonce: bytes_to_base64(&nonce),
            timestamp: timestamp.map(str::to_string).unwrap_or_else(now_iso),
            tsa,
        };
        let canonical = build_tsa_canonical_bytes(&payload);
        let signature = MajikSignature::sign(&canonical, key, None)?;
        Ok(MajikTimestamp {
            version: MAJIK_TIMESTAMP_VERSION,
            id: uuid::Uuid::new_v4().to_string(),
            payload,
            signature: Box::new(signature.to_json()),
        })
    }

    // ── CHAIN ANCHOR ─────────────────────────────────────────────────────────

    pub fn build_chain_anchor_memo(seal_hash: &str) -> R<MajikChainAnchorMemo> {
        MajikSignatureValidator::validate_seal_hash(seal_hash)?;
        Ok(format!("{MAJIK_NOTARY_MEMO_DOMAIN}{seal_hash}"))
    }

    // ── COMPACT FORMAT ───────────────────────────────────────────────────────

    /// Strip the embedded public keys. The verifier must supply them out-of-band.
    pub fn to_compact(&self) -> MajikSignatureCompactJSON {
        MajikSignatureCompactJSON {
            v: self.version,
            signer_id: self.signer_id.clone(),
            content_hash: self.content_hash.clone(),
            content_type: self.content_type.clone(),
            timestamp: self.timestamp.clone(),
            ed_signature: self.ed_signature.clone(),
            ml_dsa_signature: self.ml_dsa_signature.clone(),
            allowlist_hash: self.allowlist_hash.clone(),
            valid_until: self.valid_until.clone(),
            version_chain_hash: self.version_chain_hash.clone(),
            session_context_hash: self.session_context_hash.clone(),
        }
    }

    /// Rehydrate a full signature from a compact payload + externally resolved public keys.
    pub fn from_compact(
        compact: &MajikSignatureCompactJSON,
        ed_public_key: &[u8],
        ml_dsa_public_key: &[u8],
    ) -> R<MajikSignature> {
        if ed_public_key.is_empty() || ml_dsa_public_key.is_empty() {
            return Err(MajikSignatureError::key(
                "fromCompact() requires the signer's public keys — resolve them by compact.signerId from your key registry / MUID service.",
            ));
        }
        Self::from_json(&MajikSignatureJSON {
            version: compact.v,
            signer_id: compact.signer_id.clone(),
            signer_ed_public_key: bytes_to_base64(ed_public_key),
            signer_ml_dsa_public_key: bytes_to_base64(ml_dsa_public_key),
            content_hash: compact.content_hash.clone(),
            content_type: compact.content_type.clone(),
            timestamp: compact.timestamp.clone(),
            ed_signature: compact.ed_signature.clone(),
            ml_dsa_signature: compact.ml_dsa_signature.clone(),
            allowlist_hash: compact.allowlist_hash.clone(),
            valid_until: compact.valid_until.clone(),
            tsa: None,
            version_chain_hash: compact.version_chain_hash.clone(),
            session_context_hash: compact.session_context_hash.clone(),
        })
    }

    /// Verify content against a compact envelope. `signer_id` is checked first so a mismatched
    /// key lookup fails fast with a clear reason.
    pub fn verify_compact(
        content: &[u8],
        compact: &MajikSignatureCompactJSON,
        public_keys: &MajikSignerPublicKeys,
    ) -> R<VerificationResult> {
        if compact.signer_id != public_keys.signer_id {
            return Ok(VerificationResult {
                valid: false,
                signer_id: Some(compact.signer_id.clone()),
                content_hash: Some(compact.content_hash.clone()),
                timestamp: compact.timestamp.clone(),
                content_type: compact.content_type.clone(),
                session_context_hash: compact.session_context_hash.clone(),
                reason: Some(format!(
                    "signerId mismatch: envelope is \"{}\", provided publicKeys are for \"{}\"",
                    compact.signer_id, public_keys.signer_id
                )),
                ..Default::default()
            });
        }
        let full = Self::from_compact(compact, &public_keys.ed_public_key, &public_keys.ml_dsa_public_key)?;
        Self::verify(content, &full, public_keys, None)
    }
}

// ── private helpers ──────────────────────────────────────────────────────────

fn payload_for(env: &MajikSignatureJSON) -> Vec<u8> {
    build_signing_payload(&PayloadFields {
        signer_id: &env.signer_id,
        timestamp: &env.timestamp,
        content_hash: &env.content_hash,
        content_type: env.content_type.as_deref(),
        allowlist_hash: env.allowlist_hash.as_deref(),
        valid_until: env.valid_until.as_deref(),
        version_chain_hash: env.version_chain_hash.as_deref(),
        session_context_hash: env.session_context_hash.as_deref(),
    })
}

/// Run both signature checks. `Some(reason)` = failure, `None` = both passed.
fn check_crypto(env: &MajikSignatureJSON, keys: &MajikSignerPublicKeys, payload: &[u8]) -> Option<String> {
    // Ed25519
    let ed_ok = (|| -> Result<bool, ()> {
        let pk: [u8; 32] = keys.ed_public_key.as_slice().try_into().map_err(|_| ())?;
        let vk = VerifyingKey::from_bytes(&pk).map_err(|_| ())?;
        let sig_bytes = base64_to_bytes(&env.ed_signature).map_err(|_| ())?;
        let sig = EdSignature::from_slice(&sig_bytes).map_err(|_| ())?;
        Ok(vk.verify_strict(payload, &sig).is_ok())
    })();
    match ed_ok {
        Err(()) => return Some("Failed to verify Ed25519 signature".into()),
        Ok(false) => return Some("Invalid Ed25519 signature".into()),
        Ok(true) => {}
    }

    // ML-DSA-87
    let ml_ok = (|| -> Result<bool, ()> {
        let pk_arr: [u8; ML_DSA_87_PUBLIC_KEY_LEN] =
            keys.ml_dsa_public_key.as_slice().try_into().map_err(|_| ())?;
        let pk = ml_dsa_87::PublicKey::try_from_bytes(pk_arr).map_err(|_| ())?;
        let sig_bytes = base64_to_bytes(&env.ml_dsa_signature).map_err(|_| ())?;
        let sig: [u8; ML_DSA_87_SIGNATURE_LEN] = sig_bytes.as_slice().try_into().map_err(|_| ())?;
        Ok(pk.verify(payload, &sig, &[]))
    })();
    match ml_ok {
        Err(()) => Some("Failed to verify ML-DSA-87 signature".into()),
        Ok(false) => Some("Invalid ML-DSA-87 signature".into()),
        Ok(true) => None,
    }
}

pub(crate) fn signing_public_keys(key: &MajikKey, missing_msg: &str) -> R<(Vec<u8>, Vec<u8>)> {
    if !key.has_keys(&[KeyId::Ed25519, KeyId::MlDsa87]) {
        return Err(MajikSignatureError::key(missing_msg));
    }
    let ed = key
        .get_public_key(KeyId::Ed25519)
        .map_err(|e| MajikSignatureError::key_with_cause("Failed to read Ed25519 public key", e))?;
    let ml = key
        .get_public_key(KeyId::MlDsa87)
        .map_err(|e| MajikSignatureError::key_with_cause("Failed to read ML-DSA-87 public key", e))?;
    Ok((ed, ml))
}

/// Base64 `(edPublicKey, mlDsaPublicKey)` of a key — shared with the envelope allowlist check.
pub(crate) fn signing_public_keys_b64(key: &MajikKey) -> R<(String, String)> {
    let (ed, ml) = signing_public_keys(key, "MajikKey has no signing public keys.")?;
    Ok((bytes_to_base64(&ed), bytes_to_base64(&ml)))
}

// ── FILE-AWARE METHODS (delegate to `MajikSignatureEmbed`) ───────────────────

use crate::anchor::types::MajikChainAnchor;
use crate::core::embed::majik_embed::{
    MajikSignatureEmbed, OrderOptions, SealResult, SignAndEmbedOptions, SignAndEmbedResult,
    SignDetachedOptions, SignDetachedResult, VerifyFileOptions, VerifyRevisionsOptions,
};
use crate::core::envelope::{CanAnchorResult, CanSignResult, EnvelopeInput};
use crate::core::mjksmap::MajikSignatureMap;
use crate::core::order::{normalize_expected_order, OrderEntry, SignatureOrderResult};

impl MajikSignature {
    /// Sign one detached document for a SignRoom participant.
    ///
    /// This additive API derives the session-context commitment internally and
    /// returns both the clean document bytes and the current binary MJKSIG sidecar.
    /// Challenge issuance/consumption and participant authorization remain server duties.
    pub fn sign_session_file(
        file: &[u8],
        key: &MajikKey,
        options: &SessionFileSignOptions,
    ) -> R<SessionFileSignResult> {
        let session_context_hash =
            crate::core::session_context::build_session_context_hash(&options.session_context)?;
        let session_envelope = match options.existing_envelope.clone() {
            Some(input) => crate::core::envelope::MajikSignatureEnvelope::from_input(input)?,
            None => crate::core::envelope::MajikSignatureEnvelope::empty(),
        };

        if options.file_version.is_some() && options.prior_file.is_some() {
            return Err(MajikSignatureError::new(
                "Pass fileVersion or priorFile to signSessionFile(), not both. fileVersion is the explicit SignRoom revision entry.",
            ));
        }

        let mut version_chain_hash = None;
        if let Some(file_version) = options.file_version.as_ref() {
            let expected_version = match session_envelope.last_file_version() {
                Some(last) => last.version.checked_add(1).ok_or_else(|| {
                    MajikSignatureError::validation(
                        "The existing FileVersion chain has reached the maximum revision number",
                        Some("version"),
                    )
                })?,
                None => 1,
            };
            let expected_previous_version_hash = session_envelope
                .last_file_version()
                .map(crate::core::envelope::MajikSignatureEnvelope::hash_file_version_entry);
            let timestamp_is_canonical = file_version
                .timestamp
                .parse::<Timestamp>()
                .ok()
                .map(to_iso_string)
                .is_some_and(|canonical| canonical == file_version.timestamp);
            let content_hash_is_canonical = base64_to_bytes(&file_version.content_hash)
                .is_ok_and(|bytes| bytes.len() == 32 && bytes_to_base64(&bytes) == file_version.content_hash);

            if file_version.version != expected_version
                || file_version.created_by.as_deref() != Some(key.fingerprint())
                || file_version.previous_version_hash != expected_previous_version_hash
                || !timestamp_is_canonical
                || !content_hash_is_canonical
            {
                return Err(MajikSignatureError::new(
                    "The supplied SignRoom FileVersion must be the next valid revision, linked to the existing envelope and created by the signing key.",
                ));
            }

            // Validate the supplied digest against the exact bytes that the detached
            // signing handler will cover, before performing any signing operation.
            let stripped = Self::strip_from(file, options.mime_type.as_deref())?;
            if bytes_to_base64(&hash_content(&stripped)) != file_version.content_hash {
                return Err(MajikSignatureError::new(
                    "The supplied SignRoom FileVersion contentHash does not match the document bytes being signed.",
                ));
            }

            let mut next_chain = session_envelope.file_versions().to_vec();
            next_chain.push(file_version.clone());
            version_chain_hash =
                Some(crate::core::envelope::MajikSignatureEnvelope::hash_file_version_chain(&next_chain));
        } else if !session_envelope.file_versions().is_empty() {
            // A participant who does not modify the document still commits to
            // the exact revision chain already stored in the detached sidecar.
            version_chain_hash =
                Some(crate::core::envelope::MajikSignatureEnvelope::hash_file_version_chain(
                    session_envelope.file_versions(),
                ));
        }

        let existing_envelope = Some(EnvelopeInput::Envelope(session_envelope.clone()));
        let detached = MajikSignatureEmbed::sign_detached_with_version_chain_hash(
            file,
            key,
            Some(&SignDetachedOptions {
                embed: EmbedOptions { mime_type: options.mime_type.clone(), ..Default::default() },
                content_type: options.content_type.clone(),
                timestamp: options
                    .file_version
                    .as_ref()
                    .map(|version| version.timestamp.clone())
                    .or_else(|| options.timestamp.clone()),
                valid_until: options.valid_until.clone(),
                expected_signers: options.expected_signers.clone(),
                existing_envelope,
                tsa: options.tsa.clone(),
                prior_file: options.prior_file.clone(),
                message: options.message.clone(),
                session_context_hash: Some(session_context_hash),
            }),
            version_chain_hash,
        )?;

        let envelope = match options.file_version.as_ref() {
            Some(file_version) => detached.envelope.with_file_version(file_version.clone())?,
            None => detached.envelope,
        };
        let mjksig = envelope.to_mjksig()?;
        Ok(SessionFileSignResult {
            blob: detached.blob,
            envelope,
            signature: detached.signature,
            handler: detached.handler,
            mime_type: detached.mime_type,
            mjksig,
        })
    }

    /// Verify a detached document and every participant against authoritative
    /// SignRoom contexts and trusted public keys.
    ///
    /// Contexts and public keys are keyed by signer fingerprint. Every signer
    /// must have a context; contexts must share one session and policy while
    /// using distinct one-time challenges. TSA trust is only established when
    /// a trusted TSA public key is supplied.
    pub fn verify_session_file(
        file: &[u8],
        envelope_input: impl Into<EnvelopeInput>,
        options: &SessionFileVerifyOptions,
    ) -> R<SessionFileVerificationResult> {
        use std::collections::{HashMap, HashSet};

        if options.require_trusted_tsa && options.trusted_tsa_public_keys.is_none() {
            return Err(MajikSignatureError::validation(
                "trustedTsaPublicKeys is required when requireTrustedTSA is enabled",
                Some("trustedTsaPublicKeys"),
            ));
        }

        let envelope = crate::core::envelope::MajikSignatureEnvelope::from_input(envelope_input.into())?;
        let signatures = envelope.signatures().to_vec();
        if signatures.is_empty() {
            return Ok(SessionFileVerificationResult {
                valid: false,
                results: Vec::new(),
                chain: None,
                tsa_results: Vec::new(),
                reason: Some("Session envelope contains no participant signatures".into()),
            });
        }

        let invalid_result = |signature: &MajikSignatureJSON, reason: String| VerificationResult {
            valid: false,
            signer_id: Some(signature.signer_id.clone()),
            content_hash: Some(signature.content_hash.clone()),
            timestamp: signature.timestamp.clone(),
            content_type: signature.content_type.clone(),
            session_context_hash: signature.session_context_hash.clone(),
            reason: Some(reason),
            ..Default::default()
        };

        let mut chain: Option<FileChainVerification> = None;
        let cryptographic_results: Vec<VerificationResult>;
        if !envelope.file_versions().is_empty() {
            let verified_chain = Self::verify_file_detached_chain(
                file,
                envelope.clone(),
                options.mime_type.as_deref(),
                options.now,
            )?;
            let mut by_signer: HashMap<String, VerificationResult> = HashMap::new();
            for result in &verified_chain.history {
                if let Some(signer_id) = &result.base.signer_id {
                    by_signer.insert(signer_id.clone(), result.base.clone());
                }
            }
            if let Some(signer_id) = &verified_chain.latest.signer_id {
                by_signer.insert(signer_id.clone(), verified_chain.latest.clone());
            }

            cryptographic_results = signatures
                .iter()
                .map(|signature| {
                    let Some(trusted_keys) = options.expected_signer_public_keys.get(&signature.signer_id)
                    else {
                        return invalid_result(
                            signature,
                            format!(
                                "No trusted public keys were supplied for signer {}",
                                signature.signer_id
                            ),
                        );
                    };

                    let commitment = match Self::verify_commitment(signature, trusted_keys, options.now) {
                        Ok(result) => result,
                        Err(error) => return invalid_result(signature, error.message().to_string()),
                    };
                    if !commitment.base.valid {
                        return commitment.base;
                    }

                    by_signer.get(&signature.signer_id).cloned().unwrap_or_else(|| {
                        invalid_result(
                            signature,
                            "No verified revision-chain result exists for this signer".into(),
                        )
                    })
                })
                .collect();
            chain = Some(verified_chain);
        } else {
            let has_unverifiable_revision_commitment =
                signatures.iter().any(|signature| signature.version_chain_hash.is_some());
            let stripped = Self::strip_from(file, options.mime_type.as_deref())?;
            cryptographic_results = signatures
                .iter()
                .map(|signature| {
                    if has_unverifiable_revision_commitment {
                        return invalid_result(
                            signature,
                            "Signature commits to a revision chain, but fileVersions is missing".into(),
                        );
                    }
                    let Some(trusted_keys) = options.expected_signer_public_keys.get(&signature.signer_id)
                    else {
                        return invalid_result(
                            signature,
                            format!(
                                "No trusted public keys were supplied for signer {}",
                                signature.signer_id
                            ),
                        );
                    };
                    match Self::verify(&stripped, signature, trusted_keys, options.now) {
                        Ok(result) => result,
                        Err(error) => invalid_result(signature, error.message().to_string()),
                    }
                })
                .collect();
        }

        let resolved_contexts: Vec<(String, crate::core::session_context::MajikSessionSigningContext)> =
            signatures
                .iter()
                .filter_map(|signature| {
                    options
                        .expected_session_contexts
                        .get(&signature.signer_id)
                        .cloned()
                        .map(|context| (signature.signer_id.clone(), context))
                })
                .collect();
        let session_ids: HashSet<String> =
            resolved_contexts.iter().map(|(_, context)| context.session_id.clone()).collect();
        let policy_hashes: HashSet<String> =
            resolved_contexts.iter().map(|(_, context)| context.policy_hash.clone()).collect();
        let challenge_ids: Vec<String> =
            resolved_contexts.iter().map(|(_, context)| context.challenge_id.clone()).collect();
        let unique_challenges = challenge_ids.iter().collect::<HashSet<_>>().len() == challenge_ids.len();

        let session_scope_reason = if resolved_contexts.len() != signatures.len() {
            None
        } else if session_ids.len() != 1 {
            Some("All participant signatures must belong to the same SignRoom session".to_string())
        } else if policy_hashes.len() != 1 {
            Some("All participant signatures must commit to the same immutable session policy".to_string())
        } else if !unique_challenges {
            Some("Each participant must use a distinct one-time challenge".to_string())
        } else {
            None
        };

        let results: Vec<VerificationResult> = signatures
            .iter()
            .zip(cryptographic_results)
            .map(|(signature, mut base)| {
                if envelope.has_allowlist() {
                    let is_issuer =
                        envelope.allowlist_signer_id() == Some(signature.signer_id.as_str());
                    let allowed = envelope.allowlist().unwrap_or(&[]).iter().any(|entry| {
                        entry.signer_id == signature.signer_id
                            && entry.ed_public_key == signature.signer_ed_public_key
                            && entry.ml_dsa_public_key == signature.signer_ml_dsa_public_key
                    });
                    if !is_issuer && !allowed {
                        base.valid = false;
                        base.session_context_hash = signature.session_context_hash.clone();
                        base.reason = Some("Signer is not authorized by the envelope allowlist".into());
                        return base;
                    }
                }

                if let Some(reason) = &session_scope_reason {
                    base.valid = false;
                    base.session_context_hash = signature.session_context_hash.clone();
                    base.reason = Some(reason.clone());
                    return base;
                }

                let Some(context) =
                    options.expected_session_contexts.get(&signature.signer_id)
                else {
                    base.valid = false;
                    base.session_context_hash = signature.session_context_hash.clone();
                    base.reason = Some(format!(
                        "No authoritative session context was supplied for signer {}",
                        signature.signer_id
                    ));
                    return base;
                };
                let expected_hash =
                    match crate::core::session_context::build_session_context_hash(context) {
                        Ok(hash) => hash,
                        Err(error) => {
                            base.valid = false;
                            base.session_context_hash = signature.session_context_hash.clone();
                            base.reason =
                                Some(format!("Invalid expected session context: {}", error.message()));
                            return base;
                        }
                    };
                if signature.session_context_hash.as_deref() != Some(expected_hash.as_str()) {
                    base.valid = false;
                    base.session_context_hash = signature.session_context_hash.clone();
                    base.reason = Some(
                        "Signature session context does not match the authoritative session, challenge, and policy"
                            .into(),
                    );
                    return base;
                }
                base.session_context_hash = signature.session_context_hash.clone();
                base
            })
            .collect();

        let tsa_results: Vec<SessionFileTsaVerificationResult> = signatures
            .iter()
            .map(|signature| {
                let instance = match Self::from_json(signature) {
                    Ok(instance) => instance,
                    Err(error) => {
                        return SessionFileTsaVerificationResult {
                            signer_id: signature.signer_id.clone(),
                            present: signature.tsa.is_some(),
                            valid: false,
                            trusted: false,
                            reason: Some(error.message().to_string()),
                        };
                    }
                };
                if !instance.has_tsa() {
                    return SessionFileTsaVerificationResult {
                        signer_id: signature.signer_id.clone(),
                        present: false,
                        valid: !options.require_tsa,
                        trusted: false,
                        reason: if options.require_tsa {
                            Some("A TSA attestation is required for this participant".into())
                        } else {
                            None
                        },
                    };
                }
                match instance.verify_tsa_with_trusted_keys(options.trusted_tsa_public_keys.as_ref()) {
                    Ok(verification) => SessionFileTsaVerificationResult {
                        signer_id: signature.signer_id.clone(),
                        present: true,
                        valid: verification.valid,
                        trusted: options.trusted_tsa_public_keys.is_some() && verification.valid,
                        reason: verification.reason,
                    },
                    Err(error) => SessionFileTsaVerificationResult {
                        signer_id: signature.signer_id.clone(),
                        present: true,
                        valid: false,
                        trusted: false,
                        reason: Some(error.message().to_string()),
                    },
                }
            })
            .collect();

        let allowlist_integrity = envelope.verify_allowlist_integrity();
        let version_chain_integrity = envelope.verify_version_chain_integrity();
        let seal_integrity = if envelope.is_sealed() {
            envelope.verify_seal()
        } else {
            SealVerificationResult { valid: true, ..Default::default() }
        };
        let chain_valid =
            chain.as_ref().map(|result| result.chain_valid).unwrap_or(version_chain_integrity.valid);
        let tsa_valid = tsa_results.iter().all(|result| result.valid);
        let trusted_tsa_valid = !options.require_trusted_tsa
            || tsa_results.iter().all(|result| result.present && result.valid && result.trusted);

        let valid = results.iter().all(|result| result.valid)
            && allowlist_integrity.valid
            && version_chain_integrity.valid
            && seal_integrity.valid
            && chain_valid
            && tsa_valid
            && trusted_tsa_valid;

        let reason = results
            .iter()
            .find(|result| !result.valid)
            .and_then(|result| result.reason.clone())
            .or(allowlist_integrity.reason)
            .or(version_chain_integrity.reason)
            .or(seal_integrity.reason)
            .or_else(|| {
                if chain.as_ref().is_some_and(|result| !result.chain_valid) {
                    Some("Detached revision chain verification failed".into())
                } else {
                    None
                }
            })
            .or_else(|| {
                tsa_results.iter().find(|result| !result.valid).and_then(|result| result.reason.clone())
            })
            .or_else(|| {
                if !trusted_tsa_valid {
                    Some("Every TSA attestation must verify against the trusted TSA public key".into())
                } else {
                    None
                }
            });

        Ok(SessionFileVerificationResult { valid, results, chain, tsa_results, reason })
    }

    /// Sign a file and embed the signature. First signer may pass
    /// `expected_signers` to restrict future signers; sealed files are always rejected.
    pub fn sign_file(
        file: &[u8],
        key: &MajikKey,
        options: Option<&SignAndEmbedOptions>,
    ) -> R<SignAndEmbedResult> {
        MajikSignatureEmbed::sign_and_embed(file, key, options)
    }

    /// Sign a file and return the envelope detached (nothing is embedded).
    pub fn sign_file_detached(
        file: &[u8],
        key: &MajikKey,
        options: Option<&SignDetachedOptions>,
    ) -> R<SignDetachedResult> {
        MajikSignatureEmbed::sign_detached(file, key, options)
    }

    pub fn sign_batch_detached(
        files: &[BatchFileInput],
        key: &MajikKey,
        options: Option<&BatchSignOptions>,
    ) -> R<BatchSignResult> {
        MajikSignatureEmbed::sign_batch_detached(files, key, options)
    }

    /// Sign multiple canonical byte streams as detached signatures without materializing
    /// their contents. Inputs are consumed sequentially using one bounded read buffer per file.
    ///
    /// This low-level API signs the exact bytes supplied by each reader. It does not parse or
    /// strip an existing embedded signature envelope from a stream.
    pub fn sign_batch_detached_stream(
        files: &mut [StreamingBatchFileInput<'_>],
        key: &MajikKey,
        options: Option<&BatchSignOptions>,
        mut streaming: BatchStreamingOptions<'_>,
    ) -> R<BatchSignResult> {
        let default_options = BatchSignOptions::default();
        let options = options.unwrap_or(&default_options);
        if files.is_empty() {
            return Err(MajikSignatureError::validation(
                "Batch must contain at least one file.",
                Some("files"),
            ));
        }

        let mut seen = std::collections::HashSet::new();
        for file in files.iter() {
            if file.path.trim().is_empty() {
                return Err(MajikSignatureError::validation(
                    "Every batch file must have a non-empty path.",
                    Some("path"),
                ));
            }
            if !seen.insert(file.path.as_str()) {
                return Err(MajikSignatureError::validation(
                    format!("Duplicate path in batch: \"{}\"", file.path),
                    Some("path"),
                ));
            }
        }

        let mode = options.mode.unwrap_or_default();
        let mut failures = Vec::new();
        let mut map = (mode == BatchSignMode::Map).then(MajikSignatureMap::empty);
        let mut signatures = Vec::new();
        let mut batch_progress = streaming.on_progress.take();
        let chunk_size = streaming.chunk_size;
        let max_bytes_per_file = streaming.max_bytes_per_file;
        let cancellation = streaming.cancellation;
        let total_files = files.len();

        for (file_index, file) in files.iter_mut().enumerate() {
            let path = file.path.clone();
            let mime_type = file.mime_type.clone().filter(|value| !value.is_empty());
            let total_bytes = file.total_bytes;

            let attempt = (|| -> R<(MajikSignatureEnvelope, MajikSignature, u64)> {
                let empty_envelope = MajikSignatureEnvelope::empty();
                let allowlist_hash =
                    empty_envelope.resolve_allowlist_hash_for(key, options.expected_signers.as_deref());
                let sign_options = SignOptions {
                    content_type: options.content_type.clone(),
                    timestamp: options.timestamp.clone(),
                    valid_until: options.valid_until.clone(),
                    allowlist_hash,
                    ..Default::default()
                };

                let mut bytes_processed = 0u64;
                let mut progress_callback = |progress: StreamingHashProgress| {
                    bytes_processed = progress.bytes_processed;
                    if let Some(callback) = batch_progress.as_deref_mut() {
                        callback(StreamingBatchProgress {
                            file_index,
                            total_files,
                            path: path.clone(),
                            bytes_processed: progress.bytes_processed,
                            total_bytes: progress.total_bytes,
                        });
                    }
                };
                let mut hash_options = StreamingHashOptions {
                    chunk_size,
                    threshold_bytes: crate::core::streaming::DEFAULT_HASH_STREAMING_THRESHOLD,
                    max_bytes: max_bytes_per_file,
                    total_bytes,
                    cancellation,
                    on_progress: Some(&mut progress_callback),
                };
                let signature = MajikSignature::sign_reader_with_options(
                    file.reader,
                    key,
                    Some(&sign_options),
                    &mut hash_options,
                )?;

                let base =
                    if let Some(expected) = options.expected_signers.as_deref().filter(|v| !v.is_empty()) {
                        empty_envelope.with_allowlist(expected, key.fingerprint())?
                    } else {
                        empty_envelope
                    };
                let envelope = base.with_signature(signature.to_json())?;
                Ok((envelope, signature, bytes_processed))
            })();

            match attempt {
                Ok((envelope, signature, bytes_processed)) => match mode {
                    BatchSignMode::Map => {
                        let entry = MjksMapEntry {
                            path: path.clone(),
                            content_hash: signature.content_hash().to_string(),
                            size: Some(bytes_processed),
                            mime_type,
                            envelope: envelope.to_json(),
                        };
                        let current = map.take().expect("map mode always initializes a manifest");
                        map = Some(current.with_entry(entry)?);
                    }
                    BatchSignMode::Separate => {
                        signatures
                            .push(SeparateSignature { path: path.clone(), blob: envelope.to_mjksig()? });
                    }
                },
                Err(error) => {
                    if !options.continue_on_error
                        || cancellation.is_some_and(|flag| {
                            flag.load(std::sync::atomic::Ordering::Acquire)
                        })
                    {
                        return Err(MajikSignatureError::Generic {
                            message: format!(
                                "Batch streaming signing failed on \"{path}\": {}",
                                error.message()
                            ),
                            cause: Some(Box::new(error)),
                        });
                    }
                    failures.push(BatchSignFailure { path, error: error.message().to_string() });
                }
            }
        }

        Ok(match map {
            Some(map) => {
                let map_blob = map.to_mjksmap();
                BatchSignResult::Map { map, map_blob, failures }
            }
            None => BatchSignResult::Separate { signatures, failures },
        })
    }

    /// Verify a file's embedded signatures (one result per signer).
    pub fn verify_file<'a>(
        file: &[u8],
        keys: impl Into<KeyOrPublicKeys<'a>>,
        options: Option<&VerifyFileOptions>,
    ) -> R<Vec<VerificationResult>> {
        match keys.into() {
            KeyOrPublicKeys::Key(k) => MajikSignatureEmbed::verify_with_key(file, k, options),
            KeyOrPublicKeys::PublicKeys(pk) => MajikSignatureEmbed::verify(file, pk, options),
        }
    }

    /// Verify a file against a detached envelope.
    pub fn verify_file_detached<'a>(
        file: &[u8],
        envelope: impl Into<EnvelopeInput>,
        keys: impl Into<KeyOrPublicKeys<'a>>,
        options: Option<&VerifyFileOptions>,
    ) -> R<Vec<VerificationResult>> {
        match keys.into() {
            KeyOrPublicKeys::Key(k) => {
                MajikSignatureEmbed::verify_detached_with_key(file, envelope.into(), k, options)
            }
            KeyOrPublicKeys::PublicKeys(pk) => {
                MajikSignatureEmbed::verify_detached(file, envelope.into(), pk, options)
            }
        }
    }

    /// Stream path-backed files against a .mjksmap without materializing their bytes.
    pub fn verify_files_from_mjksmap_stream(
        map: &MajikSignatureMap,
        files: &mut [StreamingBatchVerifyInput<'_>],
        public_keys: &MajikSignerPublicKeys,
        options: Option<&BatchVerifyOptions>,
        streaming: BatchStreamingOptions<'_>,
    ) -> R<Vec<FileVerifyResult>> {
        MajikSignatureEmbed::verify_files_from_mjksmap_stream(map, files, public_keys, options, streaming)
    }

    pub fn verify_files_from_mjksmap(
        map: &MajikSignatureMap,
        files: &[BatchVerifyInput],
        public_keys: &MajikSignerPublicKeys,
        options: Option<&BatchVerifyOptions>,
    ) -> R<Vec<FileVerifyResult>> {
        MajikSignatureEmbed::verify_files_from_mjksmap(map, files, public_keys, options)
    }

    pub fn verify_files_from_mjksmap_with_key(
        map: &MajikSignatureMap,
        files: &[BatchVerifyInput],
        key: &MajikKey,
        options: Option<&BatchVerifyOptions>,
    ) -> R<Vec<FileVerifyResult>> {
        MajikSignatureEmbed::verify_files_from_mjksmap_with_key(map, files, key, options)
    }

    pub fn summarize_batch_verification(results: &[FileVerifyResult]) -> BatchVerifySummary {
        MajikSignatureEmbed::summarize_batch_verification(results)
    }

    pub fn verify_file_order(
        file: &[u8],
        expected_order: &[OrderEntry<'_>],
        options: Option<&OrderOptions>,
    ) -> R<SignatureOrderResult> {
        MajikSignatureEmbed::verify_file_order(file, expected_order, options)
    }

    pub fn verify_file_detached_order(
        file: &[u8],
        envelope: impl Into<EnvelopeInput>,
        expected_order: &[OrderEntry<'_>],
        options: Option<&OrderOptions>,
    ) -> R<SignatureOrderResult> {
        MajikSignatureEmbed::verify_detached_order(file, envelope.into(), expected_order, options)
    }

    pub fn verify_file_chain(
        file: &[u8],
        mime_type: Option<&str>,
        now: Option<Timestamp>,
    ) -> R<FileChainVerification> {
        MajikSignatureEmbed::verify_file_chain(file, mime_type, now)
    }

    pub fn verify_file_detached_chain(
        file: &[u8],
        envelope: impl Into<EnvelopeInput>,
        mime_type: Option<&str>,
        now: Option<Timestamp>,
    ) -> R<FileChainVerification> {
        MajikSignatureEmbed::verify_detached_chain(file, envelope.into(), mime_type, now)
    }

    pub fn verify_file_revisions(
        final_file: &[u8],
        revisions: &[&[u8]],
        options: Option<&VerifyRevisionsOptions<'_>>,
    ) -> R<RevisionSetVerification> {
        MajikSignatureEmbed::verify_file_revisions(final_file, revisions, options)
    }

    pub fn verify_file_revisions_detached(
        final_file: &[u8],
        revisions: &[&[u8]],
        envelope: impl Into<EnvelopeInput>,
        options: Option<&VerifyRevisionsOptions<'_>>,
    ) -> R<RevisionSetVerification> {
        MajikSignatureEmbed::verify_detached_revisions(final_file, revisions, envelope.into(), options)
    }

    pub fn normalize_expected_order(expected_order: &[OrderEntry<'_>]) -> R<Vec<ExpectedSigner>> {
        normalize_expected_order(expected_order)
    }

    /// Embed this (already created) signature into a file. It must cover the original bytes.
    pub fn embed_in(&self, file: &[u8], mime_type: Option<&str>) -> R<Vec<u8>> {
        let opts = EmbedOptions { mime_type: mime_type.map(str::to_string), force_fallback: false };
        Ok(MajikSignatureEmbed::embed(file, &self.to_json(), Some(&opts))?.blob)
    }

    /// All embedded signatures of a file (empty when unsigned).
    pub fn extract_from(file: &[u8], mime_type: Option<&str>) -> R<Vec<MajikSignature>> {
        let opts = ExtractOptions { mime_type: mime_type.map(str::to_string) };
        match MajikSignatureEmbed::extract(file, Some(&opts))? {
            None => Ok(Vec::new()),
            Some(r) => r.envelope.signatures().iter().map(MajikSignature::from_json).collect(),
        }
    }

    /// The file with any embedded signatures removed (exactly what was originally signed).
    pub fn strip_from(file: &[u8], mime_type: Option<&str>) -> R<Vec<u8>> {
        MajikSignatureEmbed::strip(file, Some(&ExtractOptions { mime_type: mime_type.map(str::to_string) }))
    }

    /// Structural presence check — does not verify.
    pub fn is_signed(file: &[u8], mime_type: Option<&str>) -> R<bool> {
        MajikSignatureEmbed::has_signature(
            file,
            Some(&ExtractOptions { mime_type: mime_type.map(str::to_string) }),
        )
    }

    pub fn get_allowlist(file: &[u8], mime_type: Option<&str>) -> R<Option<Vec<ExpectedSigner>>> {
        MajikSignatureEmbed::get_allowlist(
            file,
            Some(&ExtractOptions { mime_type: mime_type.map(str::to_string) }),
        )
    }

    // ── seal ──

    /// Seal a multi-sig file against further signatures (issuer only when restricted).
    pub fn seal(
        file: &[u8],
        key: &MajikKey,
        mime_type: Option<&str>,
        timestamp: Option<&str>,
    ) -> R<SealResult> {
        MajikSignatureEmbed::seal(file, key, mime_type, timestamp)
    }

    pub fn verify_seal(file: &[u8], mime_type: Option<&str>) -> R<SealVerificationResult> {
        MajikSignatureEmbed::verify_seal(
            file,
            Some(&ExtractOptions { mime_type: mime_type.map(str::to_string) }),
        )
    }

    pub fn get_seal_info(file: &[u8], mime_type: Option<&str>) -> R<Option<SealInfo>> {
        MajikSignatureEmbed::get_seal_info(
            file,
            Some(&ExtractOptions { mime_type: mime_type.map(str::to_string) }),
        )
    }

    pub fn is_sealed(file: &[u8], mime_type: Option<&str>) -> R<bool> {
        MajikSignatureEmbed::is_sealed(
            file,
            Some(&ExtractOptions { mime_type: mime_type.map(str::to_string) }),
        )
    }

    // ── multi-sig queries ──

    pub fn is_multi_sig(file: &[u8], mime_type: Option<&str>) -> R<bool> {
        MajikSignatureEmbed::is_multi_sig(
            file,
            Some(&ExtractOptions { mime_type: mime_type.map(str::to_string) }),
        )
    }

    pub fn can_sign(file: &[u8], key: &MajikKey, mime_type: Option<&str>) -> R<CanSignResult> {
        MajikSignatureEmbed::can_sign(
            file,
            key,
            Some(&ExtractOptions { mime_type: mime_type.map(str::to_string) }),
        )
    }

    pub fn get_signatories(
        file: &[u8],
        mime_type: Option<&str>,
        filter: Option<SignatoriesFilter>,
    ) -> R<Option<SignatoriesResult>> {
        MajikSignatureEmbed::get_signatories(
            file,
            Some(&ExtractOptions { mime_type: mime_type.map(str::to_string) }),
            filter,
        )
    }

    pub fn get_signed_signatories(file: &[u8], mime_type: Option<&str>) -> R<Option<SignatoriesResult>> {
        Self::get_signatories(file, mime_type, Some(SignatoriesFilter::Signed))
    }

    pub fn get_pending_signatories(file: &[u8], mime_type: Option<&str>) -> R<Option<SignatoriesResult>> {
        Self::get_signatories(file, mime_type, Some(SignatoriesFilter::Pending))
    }

    pub fn get_all_signatories(file: &[u8], mime_type: Option<&str>) -> R<Option<SignatoriesResult>> {
        Self::get_signatories(file, mime_type, Some(SignatoriesFilter::All))
    }

    pub fn get_issuer(file: &[u8], mime_type: Option<&str>) -> R<Option<SignatoryInfo>> {
        MajikSignatureEmbed::get_issuer(
            file,
            Some(&ExtractOptions { mime_type: mime_type.map(str::to_string) }),
        )
    }

    pub fn get_envelope_info(file: &[u8], mime_type: Option<&str>) -> R<Option<EnvelopeInfo>> {
        MajikSignatureEmbed::get_envelope_info(
            file,
            Some(&ExtractOptions { mime_type: mime_type.map(str::to_string) }),
        )
    }

    // ── chain anchors ──

    pub fn can_anchor(file: &[u8], mime_type: Option<&str>) -> R<CanAnchorResult> {
        MajikSignatureEmbed::can_anchor(
            file,
            Some(&ExtractOptions { mime_type: mime_type.map(str::to_string) }),
        )
    }

    /// Embed an already-confirmed anchor into the file's envelope (no chain access).
    pub fn register_chain_anchor(
        file: &[u8],
        anchor: MajikChainAnchor,
        mime_type: Option<&str>,
    ) -> R<Vec<u8>> {
        Ok(MajikSignatureEmbed::register_chain_anchor(
            file,
            anchor,
            Some(&ExtractOptions { mime_type: mime_type.map(str::to_string) }),
        )?
        .blob)
    }

    pub fn get_chain_anchors(file: &[u8], mime_type: Option<&str>) -> R<Vec<MajikChainAnchor>> {
        MajikSignatureEmbed::get_chain_anchors(
            file,
            Some(&ExtractOptions { mime_type: mime_type.map(str::to_string) }),
        )
    }
}

// ── STAMP (compression-resistant image signing, experimental) ───────────────

use crate::core::stamp::core::types::{ImageSignOptions, ImageVerificationResult};
use crate::core::stamp::{ImageResult, InspectResult, MajikImageSignature, StampResult};

impl MajikSignature {
    /// ⚠️ Experimental. Sign an image with a DCT layer + appended pixel-row layer.
    pub fn stamp_image(
        image: &[u8],
        key: &MajikKey,
        options: Option<&ImageSignOptions>,
    ) -> ImageResult<StampResult> {
        MajikImageSignature::sign(image, key, options)
    }

    /// ⚠️ Experimental. Verify a stamped image (default Hamming threshold 8).
    pub fn verify_stamp(
        image: &[u8],
        hamming_threshold: Option<u32>,
    ) -> ImageResult<ImageVerificationResult> {
        MajikImageSignature::verify(image, hamming_threshold)
    }

    /// ⚠️ Experimental. Report which stamp layers are present.
    pub fn inspect_stamp(image: &[u8]) -> InspectResult {
        MajikImageSignature::inspect(image)
    }

    /// ⚠️ Experimental.
    pub fn is_stamped(image: &[u8]) -> bool {
        MajikImageSignature::is_signed(image)
    }
}

// Unused-import guard for items only referenced from the impl above.
#[allow(dead_code)]
type _MapAlias = MajikSignatureMap;
