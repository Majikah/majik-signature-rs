//! Port of `core/cbor/cbor-wire.ts` — JSON-compatible types ⇄ CBOR-native wire values.
//!
//! Binary fields that are Base64 (or, for seal/anchor digests, hex) strings in the JSON model
//! become native CBOR byte strings here. Nothing in this module signs or verifies anything.
//!
//! Encoding emits plain CBOR byte strings, with map keys in the same order as the TS adapter.
//! Decoding accepts a bare byte string **or** one wrapped in CBOR tag 64 (`cbor-x` wraps
//! `Uint8Array` in tag 64), requires text map keys, and rejects duplicate keys.

use std::collections::HashSet;

use ciborium::value::Value;

use super::codec::CborError;
use crate::anchor::types::{
    MajikChainAnchor, MajikChainAnchorDigest, MajikChainAnchorPayload, MajikChainAnchorStatus,
};
use crate::core::constants::{ED25519_PUBLIC_KEY_LEN, ML_DSA_87_PUBLIC_KEY_LEN, ML_DSA_87_SIGNATURE_LEN};
use crate::core::hash::{base64_to_bytes, bytes_to_base64};
use crate::core::types::*;

type W<T> = Result<T, CborError>;

/// Prevent pathological recursion through nested TSA signature records.
const MAX_NESTING: usize = 8;
const SHA256_LEN: usize = 32;
const SHA3_512_LEN: usize = 64;
const ED25519_SIGNATURE_LEN: usize = 64;
/// Largest integer a JS `number` represents exactly (TS rejects anything beyond it).
const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;
/// CBOR tag for a `uint8` typed array (RFC 8746), as emitted by `cbor-x` for `Uint8Array`.
const TAG_UINT8_ARRAY: u64 = 64;

fn fail<T>(msg: impl Into<String>) -> W<T> {
    Err(CborError::new(msg))
}

fn assert_depth(depth: usize) -> W<()> {
    if depth > MAX_NESTING {
        return fail("CBOR signature nesting exceeds the maximum depth");
    }
    Ok(())
}

// ─── Decoding helpers ───────────────────────────────────────────────────────

struct Map<'a>(&'a [(Value, Value)]);

impl<'a> Map<'a> {
    fn get(&self, key: &str) -> Option<&'a Value> {
        self.0.iter().find(|(k, _)| matches!(k, Value::Text(t) if t == key)).map(|(_, v)| v)
    }
}

fn record<'a>(value: &'a Value, path: &str) -> W<Map<'a>> {
    let Value::Map(entries) = value else {
        return fail(format!("{path} must be a CBOR map/object"));
    };
    let mut seen = HashSet::new();
    for (k, _) in entries {
        let Value::Text(name) = k else {
            return fail(format!("{path} contains a non-text map key"));
        };
        if !seen.insert(name.as_str()) {
            return fail(format!("{path} contains the duplicate map key \"{name}\""));
        }
    }
    Ok(Map(entries))
}

fn array<'a>(value: Option<&'a Value>, path: &str) -> W<Option<&'a Vec<Value>>> {
    match value {
        None => Ok(None),
        Some(Value::Array(items)) => Ok(Some(items)),
        Some(_) => fail(format!("{path} must be an array")),
    }
}

fn required_string(value: Option<&Value>, path: &str) -> W<String> {
    match value {
        Some(Value::Text(s)) if !s.is_empty() => Ok(s.clone()),
        _ => fail(format!("{path} must be a non-empty string")),
    }
}

fn optional_string(value: Option<&Value>, path: &str) -> W<Option<String>> {
    value.map(|v| required_string(Some(v), path)).transpose()
}

fn nullable_string(value: Option<&Value>, path: &str) -> W<Option<String>> {
    match value {
        Some(Value::Null) => Ok(None),
        other => required_string(other, path).map(Some),
    }
}

fn assert_version_one(value: Option<&Value>, path: &str) -> W<()> {
    match value {
        Some(Value::Integer(i)) if i128::from(*i) == 1 => Ok(()),
        _ => fail(format!("{path} must be version 1")),
    }
}

fn assert_version_one_u8(version: u8, path: &str) -> W<()> {
    if version != 1 {
        return fail(format!("{path} must be version 1"));
    }
    Ok(())
}

fn check_len(bytes: Vec<u8>, expected: usize, path: &str) -> W<Vec<u8>> {
    if bytes.len() != expected {
        return fail(format!("{path} must be {expected} bytes; received {}", bytes.len()));
    }
    Ok(bytes)
}

fn bytes_from_cbor(value: Option<&Value>, path: &str, expected: usize) -> W<Vec<u8>> {
    match value {
        Some(Value::Bytes(b)) => check_len(b.clone(), expected, path),
        Some(Value::Tag(TAG_UINT8_ARRAY, inner)) => match inner.as_ref() {
            Value::Bytes(b) => check_len(b.clone(), expected, path),
            _ => fail(format!("{path} must be a CBOR byte string")),
        },
        _ => fail(format!("{path} must be a CBOR byte string")),
    }
}

fn b64_from_bytes(value: Option<&Value>, path: &str, expected: usize) -> W<String> {
    Ok(bytes_to_base64(&bytes_from_cbor(value, path, expected)?))
}

fn opt_b64_from_bytes(value: Option<&Value>, path: &str, expected: usize) -> W<Option<String>> {
    value.map(|v| b64_from_bytes(Some(v), path, expected)).transpose()
}

fn hex_from_bytes(value: Option<&Value>, path: &str, expected: usize) -> W<String> {
    Ok(hex::encode(bytes_from_cbor(value, path, expected)?))
}

fn number_to_u64(value: Option<&Value>, path: &str) -> W<u64> {
    let n = match value {
        Some(Value::Integer(i)) => u64::try_from(*i).ok(),
        Some(Value::Float(f)) if f.is_finite() && f.fract() == 0.0 && *f >= 0.0 => Some(*f as u64),
        _ => None,
    };
    match n {
        Some(n) if n <= MAX_SAFE_INTEGER => Ok(n),
        _ => fail(format!("{path} must be a finite, non-negative integer")),
    }
}

fn nullable_u64(value: Option<&Value>, path: &str) -> W<Option<u64>> {
    match value {
        Some(Value::Null) => Ok(None),
        other => number_to_u64(other, path).map(Some),
    }
}

// ─── Encoding helpers ───────────────────────────────────────────────────────

struct MapBuilder(Vec<(Value, Value)>);

impl MapBuilder {
    fn new() -> Self {
        Self(Vec::new())
    }
    fn put(mut self, key: &str, value: Value) -> Self {
        self.0.push((Value::Text(key.to_string()), value));
        self
    }
    fn put_opt(self, key: &str, value: Option<Value>) -> Self {
        match value {
            Some(v) => self.put(key, v),
            None => self,
        }
    }
    fn build(self) -> Value {
        Value::Map(self.0)
    }
}

fn text(s: &str) -> Value {
    Value::Text(s.to_string())
}

fn uint(n: u64) -> Value {
    Value::Integer(n.into())
}

fn opt_text(s: &Option<String>) -> Option<Value> {
    s.as_deref().map(text)
}

fn bytes_from_b64(value: &str, path: &str, expected: usize) -> W<Vec<u8>> {
    if value.is_empty() {
        return fail(format!("{path} must be a non-empty Base64 string"));
    }
    let bytes = base64_to_bytes(value).map_err(|_| CborError::new(format!("{path} must be valid Base64")))?;
    check_len(bytes, expected, path)
}

fn b64_value(value: &str, path: &str, expected: usize) -> W<Value> {
    Ok(Value::Bytes(bytes_from_b64(value, path, expected)?))
}

fn opt_b64_value(value: &Option<String>, path: &str, expected: usize) -> W<Option<Value>> {
    value.as_deref().map(|s| b64_value(s, path, expected)).transpose()
}

fn hex_value(value: &str, path: &str, expected: usize) -> W<Value> {
    if value.len() != expected * 2 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return fail(format!("{path} must be a {}-character hexadecimal string", expected * 2));
    }
    let bytes = hex::decode(value).map_err(|_| CborError::new(format!("{path} must be hexadecimal")))?;
    Ok(Value::Bytes(bytes))
}

// ─── Expected signers ───────────────────────────────────────────────────────

fn expected_signer_to_cbor(s: &ExpectedSigner) -> W<Value> {
    Ok(MapBuilder::new()
        .put("signerId", b64_value(&s.signer_id, "allowlist.signerId", SHA256_LEN)?)
        .put("edPublicKey", b64_value(&s.ed_public_key, "allowlist.edPublicKey", ED25519_PUBLIC_KEY_LEN)?)
        .put(
            "mlDsaPublicKey",
            b64_value(&s.ml_dsa_public_key, "allowlist.mlDsaPublicKey", ML_DSA_87_PUBLIC_KEY_LEN)?,
        )
        .build())
}

fn expected_signer_from_cbor(input: &Value) -> W<ExpectedSigner> {
    let obj = record(input, "allowlist entry")?;
    Ok(ExpectedSigner {
        signer_id: b64_from_bytes(obj.get("signerId"), "allowlist.signerId", SHA256_LEN)?,
        ed_public_key: b64_from_bytes(
            obj.get("edPublicKey"),
            "allowlist.edPublicKey",
            ED25519_PUBLIC_KEY_LEN,
        )?,
        ml_dsa_public_key: b64_from_bytes(
            obj.get("mlDsaPublicKey"),
            "allowlist.mlDsaPublicKey",
            ML_DSA_87_PUBLIC_KEY_LEN,
        )?,
    })
}

// ─── TSA records ────────────────────────────────────────────────────────────

fn timestamp_to_cbor(tsa: &MajikTimestamp, depth: usize) -> W<Value> {
    assert_depth(depth)?;
    assert_version_one_u8(tsa.version, "tsa.version")?;
    if tsa.payload.digest.algorithm != "SHA-256" {
        return fail("tsa.payload.digest.algorithm must be SHA-256");
    }
    let digest = MapBuilder::new()
        .put("algorithm", text("SHA-256"))
        .put("value", b64_value(&tsa.payload.digest.value, "tsa.payload.digest.value", SHA256_LEN)?)
        .build();
    let identity = MapBuilder::new()
        .put("id", text(&tsa.payload.tsa.id))
        .put(
            "signerFingerprint",
            b64_value(&tsa.payload.tsa.signer_fingerprint, "tsa.payload.tsa.signerFingerprint", SHA256_LEN)?,
        )
        .build();
    let payload = MapBuilder::new()
        .put("digest", digest)
        .put("nonce", b64_value(&tsa.payload.nonce, "tsa.payload.nonce", SHA256_LEN)?)
        .put("timestamp", text(&tsa.payload.timestamp))
        .put("tsa", identity)
        .build();
    Ok(MapBuilder::new()
        .put("version", uint(1))
        .put("id", text(&tsa.id))
        .put("payload", payload)
        .put("signature", signature_to_cbor_at(&tsa.signature, depth + 1)?)
        .build())
}

fn timestamp_from_cbor(input: &Value, depth: usize) -> W<MajikTimestamp> {
    assert_depth(depth)?;
    let obj = record(input, "tsa")?;
    assert_version_one(obj.get("version"), "tsa.version")?;

    let payload = record(obj.get("payload").unwrap_or(&Value::Null), "tsa.payload")?;
    let digest = record(payload.get("digest").unwrap_or(&Value::Null), "tsa.payload.digest")?;
    let identity = record(payload.get("tsa").unwrap_or(&Value::Null), "tsa.payload.tsa")?;

    if !matches!(digest.get("algorithm"), Some(Value::Text(a)) if a == "SHA-256") {
        return fail("tsa.payload.digest.algorithm must be SHA-256");
    }

    Ok(MajikTimestamp {
        version: 1,
        id: required_string(obj.get("id"), "tsa.id")?,
        payload: MajikTsaPayload {
            digest: TsaDigest {
                algorithm: "SHA-256".to_string(),
                value: b64_from_bytes(digest.get("value"), "tsa.payload.digest.value", SHA256_LEN)?,
            },
            nonce: b64_from_bytes(payload.get("nonce"), "tsa.payload.nonce", SHA256_LEN)?,
            timestamp: required_string(payload.get("timestamp"), "tsa.payload.timestamp")?,
            tsa: MajikTsaIdentity {
                id: required_string(identity.get("id"), "tsa.payload.tsa.id")?,
                signer_fingerprint: b64_from_bytes(
                    identity.get("signerFingerprint"),
                    "tsa.payload.tsa.signerFingerprint",
                    SHA256_LEN,
                )?,
            },
        },
        signature: Box::new(signature_from_cbor_at(obj.get("signature").unwrap_or(&Value::Null), depth + 1)?),
    })
}

// ─── Individual signature ───────────────────────────────────────────────────

/// `MajikSignatureJSON` → CBOR wire value.
pub fn signature_to_cbor(signature: &MajikSignatureJSON) -> W<Value> {
    signature_to_cbor_at(signature, 0)
}

fn signature_to_cbor_at(sig: &MajikSignatureJSON, depth: usize) -> W<Value> {
    assert_depth(depth)?;
    assert_version_one_u8(sig.version, "signature.version")?;

    let tsa = sig.tsa.as_ref().map(|t| timestamp_to_cbor(t, depth + 1)).transpose()?;

    Ok(MapBuilder::new()
        .put("version", uint(1))
        .put("signerId", b64_value(&sig.signer_id, "signerId", SHA256_LEN)?)
        .put(
            "signerEdPublicKey",
            b64_value(&sig.signer_ed_public_key, "signerEdPublicKey", ED25519_PUBLIC_KEY_LEN)?,
        )
        .put(
            "signerMlDsaPublicKey",
            b64_value(&sig.signer_ml_dsa_public_key, "signerMlDsaPublicKey", ML_DSA_87_PUBLIC_KEY_LEN)?,
        )
        .put("contentHash", b64_value(&sig.content_hash, "contentHash", SHA256_LEN)?)
        .put_opt("contentType", opt_text(&sig.content_type))
        .put("timestamp", text(&sig.timestamp))
        .put("edSignature", b64_value(&sig.ed_signature, "edSignature", ED25519_SIGNATURE_LEN)?)
        .put("mlDsaSignature", b64_value(&sig.ml_dsa_signature, "mlDsaSignature", ML_DSA_87_SIGNATURE_LEN)?)
        .put_opt("allowlistHash", opt_b64_value(&sig.allowlist_hash, "allowlistHash", SHA256_LEN)?)
        .put_opt("validUntil", opt_text(&sig.valid_until))
        .put_opt("versionChainHash", opt_b64_value(&sig.version_chain_hash, "versionChainHash", SHA256_LEN)?)
        .put_opt("tsa", tsa)
        .build())
}

/// CBOR wire value → `MajikSignatureJSON` (structure/length checked; crypto NOT verified).
pub fn signature_from_cbor(input: &Value) -> W<MajikSignatureJSON> {
    signature_from_cbor_at(input, 0)
}

fn signature_from_cbor_at(input: &Value, depth: usize) -> W<MajikSignatureJSON> {
    assert_depth(depth)?;
    let obj = record(input, "signature")?;
    assert_version_one(obj.get("version"), "signature.version")?;

    let content_type = optional_string(obj.get("contentType"), "contentType")?;
    let valid_until = optional_string(obj.get("validUntil"), "validUntil")?;
    let allowlist_hash = opt_b64_from_bytes(obj.get("allowlistHash"), "allowlistHash", SHA256_LEN)?;
    let version_chain_hash = opt_b64_from_bytes(obj.get("versionChainHash"), "versionChainHash", SHA256_LEN)?;
    let tsa = obj.get("tsa").map(|t| timestamp_from_cbor(t, depth + 1)).transpose()?;

    Ok(MajikSignatureJSON {
        version: 1,
        signer_id: b64_from_bytes(obj.get("signerId"), "signerId", SHA256_LEN)?,
        signer_ed_public_key: b64_from_bytes(
            obj.get("signerEdPublicKey"),
            "signerEdPublicKey",
            ED25519_PUBLIC_KEY_LEN,
        )?,
        signer_ml_dsa_public_key: b64_from_bytes(
            obj.get("signerMlDsaPublicKey"),
            "signerMlDsaPublicKey",
            ML_DSA_87_PUBLIC_KEY_LEN,
        )?,
        content_hash: b64_from_bytes(obj.get("contentHash"), "contentHash", SHA256_LEN)?,
        content_type,
        timestamp: required_string(obj.get("timestamp"), "timestamp")?,
        ed_signature: b64_from_bytes(obj.get("edSignature"), "edSignature", ED25519_SIGNATURE_LEN)?,
        ml_dsa_signature: b64_from_bytes(
            obj.get("mlDsaSignature"),
            "mlDsaSignature",
            ML_DSA_87_SIGNATURE_LEN,
        )?,
        allowlist_hash,
        valid_until,
        tsa,
        version_chain_hash,
    })
}

// ─── Chain anchors ──────────────────────────────────────────────────────────

fn status_str(s: MajikChainAnchorStatus) -> &'static str {
    match s {
        MajikChainAnchorStatus::Pending => "pending",
        MajikChainAnchorStatus::Confirmed => "confirmed",
        MajikChainAnchorStatus::Finalized => "finalized",
        MajikChainAnchorStatus::Failed => "failed",
    }
}

fn nullable_uint(n: Option<u64>) -> Value {
    n.map(uint).unwrap_or(Value::Null)
}

fn anchor_to_cbor(a: &MajikChainAnchor) -> W<Value> {
    if a.payload.digest.algorithm != "SHA3-512" {
        return fail("Unsupported chain-anchor digest algorithm");
    }
    let digest = MapBuilder::new()
        .put("algorithm", text("SHA3-512"))
        .put("value", hex_value(&a.payload.digest.value, "chainAnchor.payload.digest.value", SHA3_512_LEN)?)
        .build();
    let payload = MapBuilder::new()
        .put("chain", text(&a.payload.chain))
        .put("network", text(&a.payload.network))
        .put("digest", digest)
        .build();
    Ok(MapBuilder::new()
        .put("version", uint(1))
        .put("id", text(&a.id))
        .put("payload", payload)
        .put("memo", text(&a.memo))
        .put("txSignature", text(&a.tx_signature))
        .put("slot", nullable_uint(a.slot))
        .put("blockTime", nullable_uint(a.block_time))
        .put("confirmedAt", a.confirmed_at.as_deref().map(text).unwrap_or(Value::Null))
        .put("status", text(status_str(a.status)))
        .build())
}

fn anchor_from_cbor(input: &Value) -> W<MajikChainAnchor> {
    let obj = record(input, "chainAnchor")?;
    assert_version_one(obj.get("version"), "chainAnchor.version")?;

    let payload = record(obj.get("payload").unwrap_or(&Value::Null), "chainAnchor.payload")?;
    let digest = record(payload.get("digest").unwrap_or(&Value::Null), "chainAnchor.payload.digest")?;

    if !matches!(digest.get("algorithm"), Some(Value::Text(a)) if a == "SHA3-512") {
        return fail("chainAnchor.payload.digest.algorithm must be SHA3-512");
    }

    let status = match required_string(obj.get("status"), "chainAnchor.status")?.as_str() {
        "pending" => MajikChainAnchorStatus::Pending,
        "confirmed" => MajikChainAnchorStatus::Confirmed,
        "finalized" => MajikChainAnchorStatus::Finalized,
        "failed" => MajikChainAnchorStatus::Failed,
        _ => return fail("Invalid chainAnchor.status"),
    };

    Ok(MajikChainAnchor {
        version: 1,
        id: required_string(obj.get("id"), "chainAnchor.id")?,
        payload: MajikChainAnchorPayload {
            chain: required_string(payload.get("chain"), "chainAnchor.payload.chain")?,
            network: required_string(payload.get("network"), "chainAnchor.payload.network")?,
            digest: MajikChainAnchorDigest {
                algorithm: "SHA3-512".to_string(),
                value: hex_from_bytes(digest.get("value"), "chainAnchor.payload.digest.value", SHA3_512_LEN)?,
            },
        },
        memo: required_string(obj.get("memo"), "chainAnchor.memo")?,
        tx_signature: required_string(obj.get("txSignature"), "chainAnchor.txSignature")?,
        slot: nullable_u64(obj.get("slot"), "chainAnchor.slot")?,
        block_time: nullable_u64(obj.get("blockTime"), "chainAnchor.blockTime")?,
        confirmed_at: nullable_string(obj.get("confirmedAt"), "chainAnchor.confirmedAt")?,
        status,
    })
}

// ─── File versions ──────────────────────────────────────────────────────────

fn file_version_to_cbor(e: &FileVersion) -> W<Value> {
    Ok(MapBuilder::new()
        .put("version", uint(e.version as u64))
        .put("timestamp", text(&e.timestamp))
        .put("contentHash", b64_value(&e.content_hash, "fileVersion.contentHash", SHA256_LEN)?)
        .put_opt(
            "previousVersionHash",
            opt_b64_value(&e.previous_version_hash, "fileVersion.previousVersionHash", SHA256_LEN)?,
        )
        .put_opt("createdBy", opt_b64_value(&e.created_by, "fileVersion.createdBy", SHA256_LEN)?)
        .put_opt("message", opt_text(&e.message))
        .build())
}

fn file_version_from_cbor(input: &Value) -> W<FileVersion> {
    let obj = record(input, "fileVersion")?;
    let version = number_to_u64(obj.get("version"), "fileVersion.version")?;
    Ok(FileVersion {
        version: u32::try_from(version)
            .map_err(|_| CborError::new("fileVersion.version exceeds the supported range"))?,
        timestamp: required_string(obj.get("timestamp"), "fileVersion.timestamp")?,
        content_hash: b64_from_bytes(obj.get("contentHash"), "fileVersion.contentHash", SHA256_LEN)?,
        previous_version_hash: opt_b64_from_bytes(
            obj.get("previousVersionHash"),
            "fileVersion.previousVersionHash",
            SHA256_LEN,
        )?,
        created_by: opt_b64_from_bytes(obj.get("createdBy"), "fileVersion.createdBy", SHA256_LEN)?,
        message: optional_string(obj.get("message"), "fileVersion.message")?,
    })
}

// ─── Complete envelope ──────────────────────────────────────────────────────

/// `MultiSigEnvelope` (JSON model) → CBOR wire value.
pub fn envelope_to_cbor(env: &MultiSigEnvelope) -> W<Value> {
    assert_version_one_u8(env.version, "envelope.version")?;

    let signatures = env.signatures.iter().map(signature_to_cbor).collect::<W<Vec<_>>>()?;
    let allowlist = env
        .allowlist
        .as_ref()
        .map(|l| l.iter().map(expected_signer_to_cbor).collect::<W<Vec<_>>>().map(Value::Array))
        .transpose()?;
    let chain_anchors = env
        .chain_anchors
        .as_ref()
        .map(|l| l.iter().map(anchor_to_cbor).collect::<W<Vec<_>>>().map(Value::Array))
        .transpose()?;
    let file_versions = env
        .file_versions
        .as_ref()
        .map(|l| l.iter().map(file_version_to_cbor).collect::<W<Vec<_>>>().map(Value::Array))
        .transpose()?;
    let seal_hash = env.seal_hash.as_deref().map(|h| hex_value(h, "sealHash", SHA3_512_LEN)).transpose()?;

    Ok(MapBuilder::new()
        .put("version", uint(1))
        .put("signatures", Value::Array(signatures))
        .put_opt("allowlist", allowlist)
        .put_opt(
            "allowlistSignerId",
            opt_b64_value(&env.allowlist_signer_id, "allowlistSignerId", SHA256_LEN)?,
        )
        .put_opt("sealHash", seal_hash)
        .put_opt("sealTimestamp", opt_text(&env.seal_timestamp))
        .put_opt("sealedBy", opt_b64_value(&env.sealed_by, "sealedBy", SHA256_LEN)?)
        .put_opt("chainAnchors", chain_anchors)
        .put_opt("fileVersions", file_versions)
        .build())
}

/// CBOR wire value → `MultiSigEnvelope` (JSON model). Run the normal envelope validation after.
pub fn envelope_from_cbor(input: &Value) -> W<MultiSigEnvelope> {
    let obj = record(input, "envelope")?;
    assert_version_one(obj.get("version"), "envelope.version")?;

    let Some(signatures) = array(obj.get("signatures"), "envelope.signatures")? else {
        return fail("envelope.signatures must be an array");
    };
    let allowlist = array(obj.get("allowlist"), "envelope.allowlist")?;
    let chain_anchors = array(obj.get("chainAnchors"), "envelope.chainAnchors")?;
    let file_versions = array(obj.get("fileVersions"), "envelope.fileVersions")?;

    Ok(MultiSigEnvelope {
        version: 1,
        allowlist: allowlist.map(|l| l.iter().map(expected_signer_from_cbor).collect()).transpose()?,
        allowlist_signer_id: opt_b64_from_bytes(
            obj.get("allowlistSignerId"),
            "allowlistSignerId",
            SHA256_LEN,
        )?,
        signatures: signatures.iter().map(signature_from_cbor).collect::<W<Vec<_>>>()?,
        seal_hash: obj
            .get("sealHash")
            .map(|v| hex_from_bytes(Some(v), "sealHash", SHA3_512_LEN))
            .transpose()?,
        seal_timestamp: optional_string(obj.get("sealTimestamp"), "sealTimestamp")?,
        sealed_by: opt_b64_from_bytes(obj.get("sealedBy"), "sealedBy", SHA256_LEN)?,
        chain_anchors: chain_anchors.map(|l| l.iter().map(anchor_from_cbor).collect()).transpose()?,
        file_versions: file_versions.map(|l| l.iter().map(file_version_from_cbor).collect()).transpose()?,
    })
}
