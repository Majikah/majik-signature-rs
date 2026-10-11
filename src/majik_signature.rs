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
use ed25519_dalek::{Signature as EdSignature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use fips204::ml_dsa_87;
use fips204::traits::{SerDes as _, Signer as _, Verifier as _};
use jiff::Timestamp;
use majik_key::{KeyId, MajikKey};
use serde_json::Value;
use zeroize::Zeroizing;

use crate::anchor::types::MajikChainAnchorMemo;
use crate::core::constants::*;
use crate::core::errors::{MajikSignatureError, MajikSignatureResult};
use crate::core::hash::{base64_to_bytes, bytes_to_base64, hash_content};
use crate::core::payload::{build_signing_payload, build_tsa_canonical_bytes, PayloadFields};
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
        let default_opts = SignOptions::default();
        let options = options.unwrap_or(&default_opts);

        MajikSignatureValidator::validate_content(content)?;
        MajikSignatureValidator::validate_content_type(options.content_type.as_deref())?;
        MajikSignatureValidator::validate_valid_until(options.valid_until.as_deref())?;

        if key.is_locked() {
            return Err(MajikSignatureError::key("MajikKey is locked. Call unlock() before signing."));
        }
        if !key.has_keys(&[KeyId::Ed25519, KeyId::MlDsa87]) {
            return Err(MajikSignatureError::key(
                "MajikKey has no signing keys. Re-import via importFromMnemonicBackup() to enable signing.",
            ));
        }

        // Secret material is held in Zeroizing buffers and wiped on every exit path.
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

        let content_hash = bytes_to_base64(&hash_content(content));
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
        });

        // Ed25519 — the stored secret key is seed ‖ public (64 bytes); the seed is the first half.
        let ed_sig_bytes = {
            let mut seed = Zeroizing::new([0u8; 32]);
            seed.copy_from_slice(&ed_secret[..32]);
            let signing_key = SigningKey::from_bytes(&seed);
            signing_key.sign(&payload).to_bytes()
        };

        // ML-DSA-87 (FIPS 204, pure / empty context, hedged signing).
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
        MajikSignatureValidator::validate_signer_public_keys(public_keys)?;
        let env = signature.to_signature_json();
        MajikSignatureValidator::validate_json(&env)?;

        let invalid = |reason: Option<String>| VerificationResult {
            valid: false,
            signer_id: Some(env.signer_id.clone()),
            content_hash: Some(env.content_hash.clone()),
            timestamp: env.timestamp.clone(),
            content_type: env.content_type.clone(),
            reason,
            ..Default::default()
        };

        let recomputed = bytes_to_base64(&hash_content(content));
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
                reason,
                ..Default::default()
            },
            commitment_only: true,
        };

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
                ..Default::default()
            },
            commitment_only: true,
        })
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
        }
    }

    /// Compact JSON string of [`to_json`](Self::to_json) (TS `JSON.stringify(toJSON())`).
    pub fn to_json_string(&self) -> R<String> {
        serde_json::to_string(&self.to_json())
            .map_err(|e| MajikSignatureError::serialization_with_cause("Failed to serialize signature", e))
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

    pub fn build_tsa_request_payload(&self) -> MajikTsaRequest {
        MajikTsaRequest {
            digest: TsaDigest { algorithm: "SHA-256".into(), value: self.content_hash.clone() },
        }
    }

    /// Attach a trusted timestamp. One-shot: a TSA cannot be replaced once set.
    pub fn add_tsa(&mut self, tsa: MajikTimestamp) -> R<()> {
        if self.tsa.is_some() {
            return Err(MajikSignatureError::new("TSA is already set and cannot be replaced"));
        }
        MajikSignatureValidator::validate_majik_timestamp(&tsa)?;
        if tsa.payload.digest.value != self.content_hash {
            return Err(MajikSignatureError::new("TSA digest does not match signature contentHash"));
        }
        let canonical = build_tsa_canonical_bytes(&tsa.payload);
        let tsa_sig = MajikSignature::from_json(&tsa.signature)?;
        let public_keys = tsa_sig.extract_public_keys()?;
        let result = MajikSignature::verify(&canonical, &tsa_sig, &public_keys, None)?;
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
    pub fn verify_tsa(&self) -> R<VerificationResult> {
        let tsa =
            self.tsa.as_ref().ok_or_else(|| MajikSignatureError::new("No TSA present on this signature"))?;
        if tsa.payload.digest.value != self.content_hash {
            return Err(MajikSignatureError::new("TSA digest does not match signature contentHash"));
        }
        let canonical = build_tsa_canonical_bytes(&tsa.payload);
        let tsa_sig = MajikSignature::from_json(&tsa.signature)?;
        let public_keys = tsa_sig.extract_public_keys()?;
        MajikSignature::verify(&canonical, &tsa_sig, &public_keys, None)
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
        Ok(vk.verify(payload, &sig).is_ok())
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

    pub fn verify_file_revisions(
        final_file: &[u8],
        revisions: &[&[u8]],
        options: Option<&VerifyRevisionsOptions<'_>>,
    ) -> R<RevisionSetVerification> {
        MajikSignatureEmbed::verify_file_revisions(final_file, revisions, options)
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
