//! Port of `core/validator.ts` — `MajikSignatureValidator`.
//!
//! TS validators operate on `unknown` JSON. Here the `*_value` functions work on
//! `serde_json::Value` (so malformed input yields the same field-level messages as TS instead
//! of an opaque serde error), and the typed overloads simply re-serialize and delegate.

use serde_json::Value;

use crate::core::constants::*;
use crate::core::errors::{MajikSignatureError, MajikSignatureResult};
use crate::core::hash::{base64_to_bytes, bytes_to_base64};
use crate::core::time::is_valid_date;
use crate::core::types::{
    ExpectedSigner, MajikSignatureJSON, MajikSignerPublicKeys, MajikTimestamp, MajikTsaPayload,
    MultiSigEnvelope,
};

type R<T = ()> = MajikSignatureResult<T>;

fn verr(message: impl Into<String>, field: Option<&str>) -> MajikSignatureError {
    MajikSignatureError::validation(message, field)
}



fn required_object_string<'a>(
    object: &'a serde_json::Map<String, Value>,
    field: &str,
) -> R<&'a str> {
    object
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| verr(format!("{field} must be a non-empty string"), Some(field)))
}

fn utf16_len(value: &str) -> usize {
    value.encode_utf16().count()
}

fn validate_bounded_string(value: &str, max_len: usize, field: &str) -> R {
    if value.trim().is_empty()
        || utf16_len(value) > max_len
        || value.chars().any(|ch| (ch as u32) <= 0x1f || ch == '\u{7f}')
    {
        return Err(verr(
            format!("{field} must be a non-empty string of at most {max_len} characters without control characters"),
            Some(field),
        ));
    }
    Ok(())
}

fn validate_canonical_base64(value: &str, expected_bytes: usize, field: &str) -> R {
    let expected_chars = expected_bytes.div_ceil(3) * 4;
    if utf16_len(value) != expected_chars {
        return Err(verr(
            format!("{field} must be canonical base64 encoding of exactly {expected_bytes} bytes"),
            Some(field),
        ));
    }
    let decoded = base64_to_bytes(value).map_err(|_| {
        verr(
            format!("{field} must be canonical base64 encoding of exactly {expected_bytes} bytes"),
            Some(field),
        )
    })?;
    if decoded.len() != expected_bytes || bytes_to_base64(&decoded) != value {
        return Err(verr(
            format!("{field} must be canonical base64 encoding of exactly {expected_bytes} bytes"),
            Some(field),
        ));
    }
    Ok(())
}

fn validate_timestamp(value: &str, field: &str) -> R {
    validate_bounded_string(value, MAX_TIMESTAMP_CHARS, field)?;
    if !is_valid_date(value) {
        return Err(verr(format!("{field} must be a valid ISO 8601 date string"), Some(field)));
    }
    Ok(())
}

fn validate_anchor_value(anchor: &Value, index: usize) -> R {
    let label = format!("chainAnchors[{index}]");
    let obj = anchor.as_object().ok_or_else(|| verr(format!("{label} must be an object"), Some(&label)))?;
    if obj.get("version").and_then(Value::as_u64) != Some(1) {
        return Err(verr(format!("{label}.version must be 1"), Some("chainAnchors")));
    }
    validate_bounded_string(
        required_object_string(obj, "id")?,
        MAX_TSA_FIELD_CHARS,
        "id",
    )?;
    validate_bounded_string(
        required_object_string(obj, "memo")?,
        MAX_TSA_FIELD_CHARS,
        "memo",
    )?;
    validate_bounded_string(
        required_object_string(obj, "txSignature")?,
        MAX_TSA_FIELD_CHARS,
        "txSignature",
    )?;

    let payload = obj.get("payload").and_then(Value::as_object)
        .ok_or_else(|| verr(format!("{label}.payload must be an object"), Some("chainAnchors")))?;
    let chain = payload.get("chain").and_then(Value::as_str)
        .ok_or_else(|| verr(format!("{label}.payload.chain must be a string"), Some("chain")))?;
    validate_bounded_string(chain, 64, "chain")?;
    let network = payload.get("network").and_then(Value::as_str)
        .ok_or_else(|| verr(format!("{label}.payload.network must be a string"), Some("network")))?;
    validate_bounded_string(network, 64, "network")?;

    let digest = payload.get("digest").and_then(Value::as_object)
        .ok_or_else(|| verr(format!("{label}.payload.digest must be an object"), Some("digest")))?;
    if digest.get("algorithm").and_then(Value::as_str) != Some("SHA3-512") {
        return Err(verr(format!("{label}.payload.digest.algorithm must be SHA3-512"), Some("digest")));
    }
    let digest_value = digest.get("value").and_then(Value::as_str).unwrap_or_default();
    if digest_value.len() != SEAL_HASH_HEX_LEN || !digest_value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(verr(format!("{label}.payload.digest.value must be a {SEAL_HASH_HEX_LEN}-character hex digest"), Some("digest")));
    }

    let status = obj.get("status").and_then(Value::as_str).unwrap_or_default();
    if !matches!(status, "pending" | "confirmed" | "finalized" | "failed") {
        return Err(verr(format!("{label}.status is invalid"), Some("status")));
    }
    for field in ["slot", "blockTime"] {
        match obj.get(field) {
            Some(Value::Null) => {}
            Some(value) if value.as_f64().map(|n| n.is_finite() && n >= 0.0).unwrap_or(false) => {}
            _ => return Err(verr(format!("{label}.{field} must be a non-negative number or null"), Some(field))),
        }
    }
    match obj.get("confirmedAt") {
        Some(Value::Null) => {}
        Some(Value::String(value)) => validate_timestamp(value, "confirmedAt")?,
        _ => return Err(verr(format!("{label}.confirmedAt must be a timestamp or null"), Some("confirmedAt"))),
    }
    Ok(())
}

fn validate_file_version_value(entry: &Value, index: usize) -> R {
    let label = format!("fileVersions[{index}]");
    let obj = entry.as_object().ok_or_else(|| verr(format!("{label} must be an object"), Some(&label)))?;
    let version = obj.get("version").and_then(Value::as_u64).unwrap_or(0);
    if version == 0 || version > MAX_FILE_VERSIONS as u64 {
        return Err(verr(format!("{label}.version is invalid or exceeds the supported limit"), Some("version")));
    }
    let timestamp = obj.get("timestamp").and_then(Value::as_str)
        .ok_or_else(|| verr(format!("{label}.timestamp must be a string"), Some("timestamp")))?;
    validate_timestamp(timestamp, "timestamp")?;

    for field in ["contentHash", "previousVersionHash", "createdBy"] {
        if let Some(value) = obj.get(field) {
            if field != "contentHash" && value.is_null() {
                continue;
            }
            let text = value.as_str().ok_or_else(|| verr(format!("{label}.{field} must be a base64 string"), Some(field)))?;
            validate_canonical_base64(text, SHA256_DIGEST_LEN, field)?;
        }
    }
    if let Some(message) = obj.get("message") {
        if !message.is_null() {
            let text = message.as_str().ok_or_else(|| verr(format!("{label}.message must be a string"), Some("message")))?;
            if utf16_len(text) > MAX_FILE_VERSION_MESSAGE_CHARS {
                return Err(verr(format!("{label}.message exceeds the limit of {MAX_FILE_VERSION_MESSAGE_CHARS} characters"), Some("message")));
            }
        }
    }
    Ok(())
}

/// Namespace struct mirroring the TS static class.
pub struct MajikSignatureValidator;

impl MajikSignatureValidator {
    // ── Assertions ───────────────────────────────────────────────────────────

    pub fn assert(condition: bool, message: &str, field: Option<&str>) -> R {
        if !condition {
            return Err(verr(message, field));
        }
        Ok(())
    }

    pub fn assert_defined<'a, T>(value: Option<&'a T>, field: &str) -> R<&'a T> {
        value.ok_or_else(|| {
            verr(format!("{field} is required and must not be null or undefined"), Some(field))
        })
    }

    pub fn assert_non_empty_string(value: &str, field: &str) -> R {
        if value.trim().is_empty() {
            return Err(verr(format!("{field} must be a non-empty string"), Some(field)));
        }
        Ok(())
    }

    pub fn assert_bytes(value: &[u8], field: &str, expected_len: Option<usize>) -> R {
        if let Some(len) = expected_len {
            if value.len() != len {
                return Err(verr(
                    format!("{field} must be exactly {len} bytes (got {})", value.len()),
                    Some(field),
                ));
            }
        }
        Ok(())
    }

    // ── Content validators ───────────────────────────────────────────────────

    pub fn validate_content(content: &[u8]) -> R {
        Self::validate_content_field(content, "content")
    }

    pub fn validate_content_field(content: &[u8], field: &str) -> R {
        if content.is_empty() {
            return Err(verr(format!("{field} must not be empty"), Some(field)));
        }
        Ok(())
    }

    pub fn validate_timestamp_for_signing(value: &str) -> R {
        validate_timestamp(value, "timestamp")
    }

    pub fn validate_sha256_digest(value: &str, field: &str) -> R {
        validate_canonical_base64(value, SHA256_DIGEST_LEN, field)
    }

    pub fn validate_content_type(content_type: Option<&str>) -> R {
        match content_type {
            Some(ct) => validate_bounded_string(ct, MAX_CONTENT_TYPE_CHARS, "contentType"),
            None => Ok(()),
        }
    }

    // ── Key validators ───────────────────────────────────────────────────────

    pub fn validate_signer_public_keys(keys: &MajikSignerPublicKeys) -> R {
        validate_canonical_base64(&keys.signer_id, SHA256_DIGEST_LEN, "signerId")?;
        if keys.ed_public_key.len() != ED25519_PUBLIC_KEY_LEN {
            return Err(MajikSignatureError::key(format!(
                "edPublicKey must be a 32-byte Uint8Array (got {})",
                keys.ed_public_key.len()
            )));
        }
        if keys.ml_dsa_public_key.len() != ML_DSA_87_PUBLIC_KEY_LEN {
            return Err(MajikSignatureError::key(format!(
                "mlDsaPublicKey must be a 2592-byte Uint8Array (got {})",
                keys.ml_dsa_public_key.len()
            )));
        }
        Ok(())
    }

    pub fn validate_ed_secret_key(key: &[u8]) -> R {
        if key.len() != ED25519_SECRET_KEY_LEN {
            return Err(MajikSignatureError::key(format!(
                "Ed25519 secret key must be 64 bytes (got {})",
                key.len()
            )));
        }
        Ok(())
    }

    pub fn validate_ml_dsa_secret_key(key: &[u8]) -> R {
        if key.len() != ML_DSA_87_SECRET_KEY_LEN {
            return Err(MajikSignatureError::key(format!(
                "ML-DSA-87 secret key must be 4896 bytes (got {})",
                key.len()
            )));
        }
        Ok(())
    }

    // ── Per-signer envelope validator ────────────────────────────────────────

    /// Validate a typed signature envelope.
    pub fn validate_json(json: &MajikSignatureJSON) -> R {
        let value = serde_json::to_value(json).map_err(|e| {
            MajikSignatureError::serialization_with_cause("Failed to serialize signature JSON", e)
        })?;
        Self::validate_json_value(&value)
    }

    /// Validate untrusted JSON and, on success, deserialize it into a typed envelope.
    pub fn validate_json_value(json: &Value) -> R<()> {
        Self::validate_json_value_at(json, 0)
    }

    fn validate_json_value_at(json: &Value, depth: usize) -> R<()> {
        let j = json.as_object().ok_or_else(|| verr("Signature JSON must be an object", None))?;

        match j.get("version") {
            Some(v) if v.as_u64() == Some(MAJIK_SIGNATURE_VERSION as u64) => {}
            _ => return Err(verr("Unsupported signature version", Some("version"))),
        }

        validate_canonical_base64(required_object_string(j, "signerId")?, SHA256_DIGEST_LEN, "signerId")?;
        validate_canonical_base64(required_object_string(j, "signerEdPublicKey")?, ED25519_PUBLIC_KEY_LEN, "signerEdPublicKey")?;
        validate_canonical_base64(required_object_string(j, "signerMlDsaPublicKey")?, ML_DSA_87_PUBLIC_KEY_LEN, "signerMlDsaPublicKey")?;
        validate_canonical_base64(required_object_string(j, "contentHash")?, SHA256_DIGEST_LEN, "contentHash")?;
        validate_canonical_base64(required_object_string(j, "edSignature")?, ED25519_SIGNATURE_LEN, "edSignature")?;
        validate_canonical_base64(required_object_string(j, "mlDsaSignature")?, ML_DSA_87_SIGNATURE_LEN, "mlDsaSignature")?;
        validate_timestamp(required_object_string(j, "timestamp")?, "timestamp")?;

        if let Some(value) = j.get("contentType") {
            let value = value.as_str().ok_or_else(|| verr("contentType must be a string if present", Some("contentType")))?;
            Self::validate_content_type(Some(value))?;
        }
        if let Some(value) = j.get("allowlistHash") {
            let value = value.as_str().ok_or_else(|| verr("allowlistHash must be a canonical base64 SHA-256 digest", Some("allowlistHash")))?;
            validate_canonical_base64(value, SHA256_DIGEST_LEN, "allowlistHash")?;
        }
        if let Some(value) = j.get("versionChainHash") {
            let value = value.as_str().ok_or_else(|| verr("versionChainHash must be a canonical base64 SHA-256 digest", Some("versionChainHash")))?;
            validate_canonical_base64(value, SHA256_DIGEST_LEN, "versionChainHash")?;
        }
        if let Some(value) = j.get("sessionContextHash") {
            let value = value.as_str().ok_or_else(|| verr("sessionContextHash must be a canonical base64 SHA-256 digest", Some("sessionContextHash")))?;
            Self::validate_session_context_hash(value)?;
        }
        if let Some(value) = j.get("validUntil") {
            let value = value.as_str().ok_or_else(|| verr("validUntil must be a valid ISO 8601 timestamp string", Some("validUntil")))?;
            Self::validate_valid_until(Some(value))?;
        }
        if let Some(tsa) = j.get("tsa") {
            Self::validate_majik_timestamp_value_at(tsa, depth + 1)?;
        }
        Ok(())
    }

    /// Validate untrusted JSON and deserialize it.
    pub fn parse_json_value(json: &Value) -> R<MajikSignatureJSON> {
        Self::validate_json_value(json)?;
        serde_json::from_value(json.clone()).map_err(|e| {
            MajikSignatureError::serialization_with_cause("Failed to parse MajikSignature from JSON", e)
        })
    }

    // ── ExpectedSigner validator ─────────────────────────────────────────────

    pub fn validate_expected_signer_value(entry: &Value, index: Option<usize>) -> R {
        let label = index.map(|i| format!("allowlist[{i}]")).unwrap_or_else(|| "allowlist entry".to_string());
        let e = entry.as_object().ok_or_else(|| verr(format!("{label} must be an object"), Some(&label)))?;
        validate_canonical_base64(required_object_string(e, "signerId")?, SHA256_DIGEST_LEN, "signerId")?;
        validate_canonical_base64(required_object_string(e, "edPublicKey")?, ED25519_PUBLIC_KEY_LEN, "edPublicKey")?;
        validate_canonical_base64(required_object_string(e, "mlDsaPublicKey")?, ML_DSA_87_PUBLIC_KEY_LEN, "mlDsaPublicKey")?;
        Ok(())
    }

    pub fn validate_expected_signer(entry: &ExpectedSigner, index: Option<usize>) -> R {
        let v = serde_json::to_value(entry).map_err(|e| {
            MajikSignatureError::serialization_with_cause("Failed to serialize ExpectedSigner", e)
        })?;
        Self::validate_expected_signer_value(&v, index)
    }

    // ── Seal validator ───────────────────────────────────────────────────────

    /// All three seal fields must be present together — partial seals are invalid.
    /// Does NOT verify the seal hash cryptographically.
    pub fn validate_seal(env: &MultiSigEnvelope) -> R {
        Self::validate_seal_fields(
            env.seal_hash.as_deref(),
            env.seal_timestamp.as_deref(),
            env.sealed_by.as_deref(),
        )
    }

    fn validate_seal_fields(
        seal_hash: Option<&str>,
        seal_timestamp: Option<&str>,
        sealed_by: Option<&str>,
    ) -> R {
        let count = [seal_hash.is_some(), seal_timestamp.is_some(), sealed_by.is_some()]
            .iter()
            .filter(|b| **b)
            .count();
        if count > 0 && count < 3 {
            return Err(verr(
                "Seal is incomplete — sealHash, sealTimestamp, and sealedBy must all be present together",
                Some("seal"),
            ));
        }
        let Some(hash) = seal_hash else { return Ok(()) };
        if hash.len() != SEAL_HASH_HEX_LEN || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(verr(
                format!("sealHash must be exactly {SEAL_HASH_HEX_LEN} hex chars (SHA3-512)"),
                Some("sealHash"),
            ));
        }
        if validate_timestamp(seal_timestamp.unwrap_or_default(), "sealTimestamp").is_err() {
            return Err(verr("sealTimestamp must be a valid ISO 8601 date string", Some("sealTimestamp")));
        }
        if validate_bounded_string(sealed_by.unwrap_or_default(), MAX_SIGNER_ID_CHARS, "sealedBy").is_err() {
            return Err(verr("sealedBy must be a non-empty string", Some("sealedBy")));
        }
        Ok(())
    }

    pub fn validate_seal_hash(hash: &str) -> R {
        if hash.len() != SEAL_HASH_HEX_LEN || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(verr(
                format!("sealHash must be exactly {SEAL_HASH_HEX_LEN} hex chars (SHA3-512)"),
                Some("sealHash"),
            ));
        }
        Ok(())
    }

    /// Validate a canonical base64-encoded SHA-256 SignRoom context commitment.
    pub fn validate_session_context_hash(value: &str) -> R {
        if value.len() != CONTENT_HASH_B64_LEN {
            return Err(verr(
                "sessionContextHash must be a 44-character base64 SHA-256 digest",
                Some("sessionContextHash"),
            ));
        }
        let decoded = base64_to_bytes(value).map_err(|_| {
            verr("sessionContextHash must be a canonical base64 SHA-256 digest", Some("sessionContextHash"))
        })?;
        if decoded.len() != 32 || bytes_to_base64(&decoded) != value {
            return Err(verr(
                "sessionContextHash must be a canonical base64 SHA-256 digest",
                Some("sessionContextHash"),
            ));
        }
        Ok(())
    }

    pub fn validate_valid_until(value: Option<&str>) -> R {
        match value {
            Some(v) => validate_timestamp(v, "validUntil"),
            None => Ok(()),
        }
    }

    // ── MultiSigEnvelope validator ───────────────────────────────────────────

    /// Validate untrusted envelope JSON.
    pub fn validate_multi_sig_envelope_value(env: &Value) -> R {
        let e = env.as_object().ok_or_else(|| verr("MultiSigEnvelope must be an object", None))?;
        if e.get("version").and_then(Value::as_u64) != Some(MAJIK_ENVELOPE_VERSION as u64) {
            return Err(verr("Unsupported envelope version", Some("version")));
        }

        let sigs = e.get("signatures").and_then(Value::as_array)
            .ok_or_else(|| verr("MultiSigEnvelope.signatures must be an array", Some("signatures")))?;
        if sigs.len() > MAX_SIGNATURES_PER_ENVELOPE {
            return Err(verr(
                format!("MultiSigEnvelope.signatures exceeds the limit of {MAX_SIGNATURES_PER_ENVELOPE}"),
                Some("signatures"),
            ));
        }
        for (i, sig) in sigs.iter().enumerate() {
            Self::validate_json_value(sig).map_err(|err| {
                MajikSignatureError::validation_with_cause(
                    format!("signatures[{i}] is invalid: {}", err.message()),
                    Some(&format!("signatures[{i}]")),
                    err,
                )
            })?;
        }

        let has_allowlist = e.contains_key("allowlist");
        let has_issuer = e.contains_key("allowlistSignerId");
        if has_allowlist != has_issuer {
            return Err(verr("allowlist and allowlistSignerId must be set together", Some("allowlist")));
        }
        if let Some(al) = e.get("allowlist") {
            let arr = al.as_array().ok_or_else(|| {
                verr("MultiSigEnvelope.allowlist must be an array if present", Some("allowlist"))
            })?;
            if arr.is_empty() {
                return Err(verr(
                    "MultiSigEnvelope.allowlist must not be empty if present — omit the field for open signing",
                    Some("allowlist"),
                ));
            }
            if arr.len() > MAX_ALLOWLIST_ENTRIES {
                return Err(verr(
                    format!("MultiSigEnvelope.allowlist exceeds the limit of {MAX_ALLOWLIST_ENTRIES}"),
                    Some("allowlist"),
                ));
            }
            for (i, entry) in arr.iter().enumerate() {
                Self::validate_expected_signer_value(entry, Some(i))?;
            }
            let issuer = e.get("allowlistSignerId").and_then(Value::as_str)
                .ok_or_else(|| verr("MultiSigEnvelope.allowlistSignerId must be a non-empty string", Some("allowlistSignerId")))?;
            validate_canonical_base64(issuer, SHA256_DIGEST_LEN, "allowlistSignerId")?;
        }

        // Seal fields, validated structurally from raw JSON values.
        let count = ["sealHash", "sealTimestamp", "sealedBy"].iter().filter(|k| e.contains_key(**k)).count();
        if count > 0 && count < 3 {
            return Err(verr(
                "Seal is incomplete — sealHash, sealTimestamp, and sealedBy must all be present together",
                Some("seal"),
            ));
        }
        if count == 3 {
            let hash = e.get("sealHash").and_then(Value::as_str)
                .ok_or_else(|| verr("sealHash must be a hexadecimal SHA3-512 digest", Some("sealHash")))?;
            Self::validate_seal_hash(hash)?;
            let timestamp = e.get("sealTimestamp").and_then(Value::as_str)
                .ok_or_else(|| verr("sealTimestamp must be a valid ISO 8601 date string", Some("sealTimestamp")))?;
            validate_timestamp(timestamp, "sealTimestamp")?;
            let sealed_by = e.get("sealedBy").and_then(Value::as_str)
                .ok_or_else(|| verr("sealedBy must be a non-empty string", Some("sealedBy")))?;
            validate_bounded_string(sealed_by, MAX_SIGNER_ID_CHARS, "sealedBy")?;
        }

        if let Some(anchors) = e.get("chainAnchors") {
            let arr = anchors.as_array().ok_or_else(|| verr("chainAnchors must be an array when present", Some("chainAnchors")))?;
            if arr.len() > MAX_CHAIN_ANCHORS {
                return Err(verr(format!("chainAnchors exceeds the limit of {MAX_CHAIN_ANCHORS}"), Some("chainAnchors")));
            }
            for (i, anchor) in arr.iter().enumerate() {
                validate_anchor_value(anchor, i)?;
            }
        }
        if let Some(versions) = e.get("fileVersions") {
            let arr = versions.as_array().ok_or_else(|| verr("fileVersions must be an array when present", Some("fileVersions")))?;
            if arr.len() > MAX_FILE_VERSIONS {
                return Err(verr(format!("fileVersions exceeds the limit of {MAX_FILE_VERSIONS}"), Some("fileVersions")));
            }
            for (i, version) in arr.iter().enumerate() {
                validate_file_version_value(version, i)?;
            }
        }
        Ok(())
    }

    pub fn validate_multi_sig_envelope(env: &MultiSigEnvelope) -> R {
        let v = serde_json::to_value(env).map_err(|e| {
            MajikSignatureError::serialization_with_cause("Failed to serialize MultiSigEnvelope", e)
        })?;
        Self::validate_multi_sig_envelope_value(&v)
    }

    // ── TSA validators ───────────────────────────────────────────────────────

    pub fn validate_majik_tsa_payload_value(payload: &Value) -> R {
        let p = payload.as_object().ok_or_else(|| verr("TSA payload must be an object", None))?;
        let d = p.get("digest").and_then(Value::as_object)
            .ok_or_else(|| verr("TSA payload missing digest", None))?;
        if d.get("algorithm").and_then(Value::as_str) != Some("SHA-256") {
            return Err(verr("TSA payload digest algorithm must be SHA-256", None));
        }
        if let Some(scope) = d.get("scope") {
            if !matches!(scope.as_str(), Some("content") | Some("signature")) {
                return Err(verr("TSA payload digest scope must be content or signature", None));
            }
        }
        let digest = d.get("value").and_then(Value::as_str)
            .ok_or_else(|| verr("TSA payload digest value must be a canonical base64 SHA-256 digest", None))?;
        validate_canonical_base64(digest, SHA256_DIGEST_LEN, "digest.value")?;

        let nonce = p.get("nonce").and_then(Value::as_str)
            .ok_or_else(|| verr("TSA payload nonce must be a canonical base64 value", None))?;
        validate_canonical_base64(nonce, 32, "nonce")?;
        let timestamp = p.get("timestamp").and_then(Value::as_str)
            .ok_or_else(|| verr("TSA payload timestamp is invalid", None))?;
        validate_timestamp(timestamp, "timestamp")?;

        let identity = p.get("tsa").and_then(Value::as_object)
            .ok_or_else(|| verr("TSA payload missing tsa", None))?;
        let id = identity.get("id").and_then(Value::as_str)
            .ok_or_else(|| verr("TSA payload tsa.id missing", None))?;
        validate_bounded_string(id, MAX_TSA_FIELD_CHARS, "tsa.id")?;
        let fingerprint = identity.get("signerFingerprint").and_then(Value::as_str)
            .ok_or_else(|| verr("TSA payload tsa.signerFingerprint missing", None))?;
        validate_canonical_base64(fingerprint, SHA256_DIGEST_LEN, "tsa.signerFingerprint")?;
        Ok(())
    }

    pub fn validate_majik_tsa_payload(payload: &MajikTsaPayload) -> R {
        let v = serde_json::to_value(payload).map_err(|e| {
            MajikSignatureError::serialization_with_cause("Failed to serialize TSA payload", e)
        })?;
        Self::validate_majik_tsa_payload_value(&v)
    }

    pub fn validate_majik_timestamp_value(tsa: &Value) -> R {
        Self::validate_majik_timestamp_value_at(tsa, 0)
    }

    fn validate_majik_timestamp_value_at(tsa: &Value, depth: usize) -> R {
        if depth > MAX_TSA_SIGNATURE_NESTING {
            return Err(verr(
                format!("TSA signature nesting exceeds the maximum depth of {MAX_TSA_SIGNATURE_NESTING}"),
                Some("tsa"),
            ));
        }
        let t = tsa.as_object().ok_or_else(|| verr("MajikTimestamp must be an object", None))?;
        if t.get("version").and_then(Value::as_u64) != Some(1) {
            return Err(verr("MajikTimestamp version must be 1", None));
        }
        let id = t.get("id").and_then(Value::as_str)
            .ok_or_else(|| verr("MajikTimestamp missing id", None))?;
        validate_bounded_string(id, MAX_TSA_FIELD_CHARS, "timestamp.id")?;
        Self::validate_majik_tsa_payload_value(t.get("payload").unwrap_or(&Value::Null))?;
        Self::validate_json_value_at(t.get("signature").unwrap_or(&Value::Null), depth + 1)
    }

    pub fn validate_majik_timestamp(tsa: &MajikTimestamp) -> R {
        let v = serde_json::to_value(tsa).map_err(|e| {
            MajikSignatureError::serialization_with_cause("Failed to serialize MajikTimestamp", e)
        })?;
        Self::validate_majik_timestamp_value(&v)
    }
}

