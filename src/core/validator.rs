//! Port of `core/validator.ts` — `MajikSignatureValidator`.
//!
//! TS validators operate on `unknown` JSON. Here the `*_value` functions work on
//! `serde_json::Value` (so malformed input yields the same field-level messages as TS instead
//! of an opaque serde error), and the typed overloads simply re-serialize and delegate.

use serde_json::Value;

use crate::core::constants::*;
use crate::core::errors::{MajikSignatureError, MajikSignatureResult};
use crate::core::time::{is_valid_date, parse_iso_millis};
use crate::core::types::{
    ExpectedSigner, MajikSignatureJSON, MajikSignerPublicKeys, MajikTimestamp, MajikTsaPayload,
    MultiSigEnvelope,
};

type R<T = ()> = MajikSignatureResult<T>;

fn verr(message: impl Into<String>, field: Option<&str>) -> MajikSignatureError {
    MajikSignatureError::validation(message, field)
}

fn non_empty_str(v: Option<&Value>) -> Option<&str> {
    match v {
        Some(Value::String(s)) if !s.trim().is_empty() => Some(s.as_str()),
        _ => None,
    }
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

    pub fn validate_content_type(content_type: Option<&str>) -> R {
        match content_type {
            Some(ct) if ct.trim().is_empty() => {
                Err(verr("contentType must be a non-empty string if provided", Some("contentType")))
            }
            _ => Ok(()),
        }
    }

    // ── Key validators ───────────────────────────────────────────────────────

    pub fn validate_signer_public_keys(keys: &MajikSignerPublicKeys) -> R {
        Self::assert_non_empty_string(&keys.signer_id, "signerId")?;
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
        let j = json.as_object().ok_or_else(|| verr("Signature JSON must be an object", None))?;

        match j.get("version") {
            Some(v) if v.as_u64() == Some(MAJIK_SIGNATURE_VERSION as u64) => {}
            other => {
                return Err(verr(
                    format!(
                        "Unsupported signature version: {}",
                        other.map(js_display).unwrap_or_else(|| "undefined".into())
                    ),
                    Some("version"),
                ))
            }
        }

        for field in [
            "signerId",
            "signerEdPublicKey",
            "signerMlDsaPublicKey",
            "contentHash",
            "timestamp",
            "edSignature",
            "mlDsaSignature",
        ] {
            if non_empty_str(j.get(field)).is_none() {
                return Err(verr(format!("{field} must be a non-empty string"), Some(field)));
            }
        }

        let s = |k: &str| j.get(k).and_then(Value::as_str).unwrap_or_default();

        if s("signerEdPublicKey").chars().count() < MIN_ED_PUBLIC_KEY_B64_LEN {
            return Err(verr(
                "signerEdPublicKey is too short to be a valid Ed25519 public key",
                Some("signerEdPublicKey"),
            ));
        }
        if s("signerMlDsaPublicKey").chars().count() < MIN_DSA_PUBLIC_KEY_B64_LEN {
            return Err(verr(
                "signerMlDsaPublicKey is too short to be a valid ML-DSA-87 public key",
                Some("signerMlDsaPublicKey"),
            ));
        }
        if s("contentHash").chars().count() != CONTENT_HASH_B64_LEN {
            return Err(verr(
                format!("contentHash must be exactly {CONTENT_HASH_B64_LEN} base64 chars (SHA-256)"),
                Some("contentHash"),
            ));
        }
        if s("edSignature").chars().count() < MIN_SIGNATURE_B64_LEN {
            return Err(verr(
                "edSignature is too short to be a valid Ed25519 signature",
                Some("edSignature"),
            ));
        }
        if !is_valid_date(s("timestamp")) {
            return Err(verr("timestamp must be a valid ISO 8601 date string", Some("timestamp")));
        }

        // `undefined` and absent are the same in serde; an explicit JSON null is not "undefined" in
        // JS, so it is rejected exactly like TS (typeof null !== "string").
        if let Some(ct) = j.get("contentType") {
            if non_empty_str(Some(ct)).is_none() {
                return Err(verr("contentType must be a non-empty string if present", Some("contentType")));
            }
        }
        if let Some(ah) = j.get("allowlistHash") {
            let ok = ah.as_str().map(|x| x.chars().count() == ALLOWLIST_HASH_B64_LEN).unwrap_or(false);
            if !ok {
                return Err(verr(
                    format!(
                        "allowlistHash must be exactly {ALLOWLIST_HASH_B64_LEN} base64 chars (SHA-256) if present"
                    ),
                    Some("allowlistHash"),
                ));
            }
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
        let label = match index {
            Some(i) => format!("allowlist[{i}]"),
            None => "allowlist entry".to_string(),
        };
        let e = entry.as_object().ok_or_else(|| verr(format!("{label} must be an object"), Some(&label)))?;
        if non_empty_str(e.get("signerId")).is_none() {
            return Err(verr(
                format!("{label}.signerId must be a non-empty string"),
                Some(&format!("{label}.signerId")),
            ));
        }
        let short = |k: &str, min: usize| {
            e.get(k).and_then(Value::as_str).map(|s| s.chars().count() < min).unwrap_or(true)
        };
        if short("edPublicKey", MIN_ED_PUBLIC_KEY_B64_LEN) {
            return Err(verr(
                format!("{label}.edPublicKey is too short to be a valid Ed25519 public key"),
                Some(&format!("{label}.edPublicKey")),
            ));
        }
        if short("mlDsaPublicKey", MIN_DSA_PUBLIC_KEY_B64_LEN) {
            return Err(verr(
                format!("{label}.mlDsaPublicKey is too short to be a valid ML-DSA-87 public key"),
                Some(&format!("{label}.mlDsaPublicKey")),
            ));
        }
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
        if hash.chars().count() != SEAL_HASH_HEX_LEN {
            return Err(verr(
                format!("sealHash must be exactly {SEAL_HASH_HEX_LEN} hex chars (SHA3-512)"),
                Some("sealHash"),
            ));
        }
        if !is_valid_date(seal_timestamp.unwrap_or_default()) {
            return Err(verr("sealTimestamp must be a valid ISO 8601 date string", Some("sealTimestamp")));
        }
        if sealed_by.unwrap_or_default().trim().is_empty() {
            return Err(verr("sealedBy must be a non-empty string", Some("sealedBy")));
        }
        Ok(())
    }

    pub fn validate_seal_hash(hash: &str) -> R {
        if hash.chars().count() != SEAL_HASH_HEX_LEN {
            return Err(verr(
                format!("sealHash must be exactly {SEAL_HASH_HEX_LEN} hex chars (SHA3-512)"),
                Some("sealHash"),
            ));
        }
        Ok(())
    }

    pub fn validate_valid_until(value: Option<&str>) -> R {
        match value {
            Some(v) if parse_iso_millis(v).is_none() => {
                Err(verr("validUntil must be a valid ISO 8601 timestamp string", Some("validUntil")))
            }
            _ => Ok(()),
        }
    }

    // ── MultiSigEnvelope validator ───────────────────────────────────────────

    /// Validate untrusted envelope JSON.
    pub fn validate_multi_sig_envelope_value(env: &Value) -> R {
        let e = env.as_object().ok_or_else(|| verr("MultiSigEnvelope must be an object", None))?;

        match e.get("version") {
            Some(v) if v.as_u64() == Some(MAJIK_ENVELOPE_VERSION as u64) => {}
            other => {
                return Err(verr(
                    format!(
                        "Unsupported envelope version: {}",
                        other.map(js_display).unwrap_or_else(|| "undefined".into())
                    ),
                    Some("version"),
                ))
            }
        }

        let sigs = e
            .get("signatures")
            .and_then(Value::as_array)
            .ok_or_else(|| verr("MultiSigEnvelope.signatures must be an array", Some("signatures")))?;
        for (i, s) in sigs.iter().enumerate() {
            Self::validate_json_value(s).map_err(|err| {
                MajikSignatureError::validation_with_cause(
                    format!("signatures[{i}] is invalid: {}", err.message()),
                    Some(&format!("signatures[{i}]")),
                    err,
                )
            })?;
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
            for (i, entry) in arr.iter().enumerate() {
                Self::validate_expected_signer_value(entry, Some(i))?;
            }
            if non_empty_str(e.get("allowlistSignerId")).is_none() {
                return Err(verr(
                    "MultiSigEnvelope.allowlistSignerId must be a non-empty string when allowlist is present",
                    Some("allowlistSignerId"),
                ));
            }
        }

        // Seal fields, validated structurally from the raw values.
        let get_s = |k: &str| e.get(k).and_then(Value::as_str);
        // A present-but-non-string seal field is "defined" yet invalid, as in TS.
        let present = |k: &str| e.contains_key(k);
        let count = ["sealHash", "sealTimestamp", "sealedBy"].iter().filter(|k| present(k)).count();
        if count > 0 && count < 3 {
            return Err(verr(
                "Seal is incomplete — sealHash, sealTimestamp, and sealedBy must all be present together",
                Some("seal"),
            ));
        }
        if present("sealHash") {
            let hash_ok = get_s("sealHash").map(|h| h.chars().count() == SEAL_HASH_HEX_LEN).unwrap_or(false);
            if !hash_ok {
                return Err(verr(
                    format!("sealHash must be exactly {SEAL_HASH_HEX_LEN} hex chars (SHA3-512)"),
                    Some("sealHash"),
                ));
            }
            if !get_s("sealTimestamp").map(is_valid_date).unwrap_or(false) {
                return Err(verr(
                    "sealTimestamp must be a valid ISO 8601 date string",
                    Some("sealTimestamp"),
                ));
            }
            if get_s("sealedBy").map(|s| s.trim().is_empty()).unwrap_or(true) {
                return Err(verr("sealedBy must be a non-empty string", Some("sealedBy")));
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
        let d = p
            .get("digest")
            .and_then(Value::as_object)
            .ok_or_else(|| verr("TSA payload missing digest", None))?;
        if d.get("algorithm").and_then(Value::as_str) != Some("SHA-256") {
            return Err(verr("TSA payload digest algorithm must be SHA-256", None));
        }
        let vlen = d.get("value").and_then(Value::as_str).map(|s| s.chars().count());
        if vlen != Some(CONTENT_HASH_B64_LEN) {
            return Err(verr("TSA payload digest value must be a 44-char base64 string", None));
        }
        let nonempty = |v: Option<&Value>| v.and_then(Value::as_str).map(|s| !s.is_empty()).unwrap_or(false);
        if !nonempty(p.get("nonce")) {
            return Err(verr("TSA payload missing nonce", None));
        }
        if !nonempty(p.get("timestamp")) {
            return Err(verr("TSA payload missing timestamp", None));
        }
        let t =
            p.get("tsa").and_then(Value::as_object).ok_or_else(|| verr("TSA payload missing tsa", None))?;
        if !nonempty(t.get("id")) {
            return Err(verr("TSA payload tsa.id missing", None));
        }
        if !nonempty(t.get("signerFingerprint")) {
            return Err(verr("TSA payload tsa.signerFingerprint missing", None));
        }
        Ok(())
    }

    pub fn validate_majik_tsa_payload(payload: &MajikTsaPayload) -> R {
        let v = serde_json::to_value(payload).map_err(|e| {
            MajikSignatureError::serialization_with_cause("Failed to serialize TSA payload", e)
        })?;
        Self::validate_majik_tsa_payload_value(&v)
    }

    pub fn validate_majik_timestamp_value(tsa: &Value) -> R {
        let t = tsa.as_object().ok_or_else(|| verr("MajikTimestamp must be an object", None))?;
        if t.get("version").and_then(Value::as_u64) != Some(1) {
            return Err(verr("MajikTimestamp version must be 1", None));
        }
        if t.get("id").and_then(Value::as_str).map(|s| s.is_empty()).unwrap_or(true) {
            return Err(verr("MajikTimestamp missing id", None));
        }
        Self::validate_majik_tsa_payload_value(t.get("payload").unwrap_or(&Value::Null))?;
        Self::validate_json_value(t.get("signature").unwrap_or(&Value::Null))
    }

    pub fn validate_majik_timestamp(tsa: &MajikTimestamp) -> R {
        let v = serde_json::to_value(tsa).map_err(|e| {
            MajikSignatureError::serialization_with_cause("Failed to serialize MajikTimestamp", e)
        })?;
        Self::validate_majik_timestamp_value(&v)
    }
}

/// Render a JSON value the way a JS template literal would (`${value}`).
fn js_display(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => "null".into(),
        other => other.to_string(),
    }
}
