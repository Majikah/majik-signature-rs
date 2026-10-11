//! Port of `core/payload.ts` — canonical signing payload construction.
//!
//! The byte layout is an on-wire compatibility contract with the TypeScript library:
//! `MAJIK_SIGNATURE_DOMAIN` ‖ compact JSON of `{v,id,ts,ct,hash[,alh][,vu][,vch]}`.
//! Field order is the struct declaration order and MUST NOT change.

use serde::Serialize;

use crate::core::constants::{MAJIK_SIGNATURE_DOMAIN, MAJIK_SIGNATURE_VERSION, MAJIK_TSA_DOMAIN};
use crate::core::types::MajikTsaPayload;

/// Fields that describe a signature being created or verified (TS `PayloadFields`).
#[derive(Debug, Clone, Default)]
pub struct PayloadFields<'a> {
    /// Signer fingerprint (serialized as `id`).
    pub signer_id: &'a str,
    /// ISO 8601 creation time (serialized as `ts`).
    pub timestamp: &'a str,
    /// Base64 SHA-256 of the content (serialized as `hash`).
    pub content_hash: &'a str,
    /// Advisory content type (serialized as `ct`; explicit `null` when absent).
    pub content_type: Option<&'a str>,
    /// Serialized as `alh` only when `Some`.
    pub allowlist_hash: Option<&'a str>,
    /// Serialized as `vu` only when `Some`.
    pub valid_until: Option<&'a str>,
    /// Serialized as `vch` only when `Some`.
    pub version_chain_hash: Option<&'a str>,
}

#[derive(Serialize)]
struct CanonicalMeta<'a> {
    v: u8,
    id: &'a str,
    ts: &'a str,
    ct: Option<&'a str>,
    hash: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    alh: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    vu: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    vch: Option<&'a str>,
}

/// Build the canonical byte payload signed by both Ed25519 and ML-DSA-87.
pub fn build_signing_payload(fields: &PayloadFields<'_>) -> Vec<u8> {
    let meta = CanonicalMeta {
        v: MAJIK_SIGNATURE_VERSION,
        id: fields.signer_id,
        ts: fields.timestamp,
        ct: fields.content_type,
        hash: fields.content_hash,
        alh: fields.allowlist_hash,
        vu: fields.valid_until,
        vch: fields.version_chain_hash,
    };
    // Serializing plain strings/ints to JSON cannot fail.
    let body = serde_json::to_vec(&meta).expect("canonical payload serialization is infallible");
    let mut out = Vec::with_capacity(MAJIK_SIGNATURE_DOMAIN.len() + body.len());
    out.extend_from_slice(MAJIK_SIGNATURE_DOMAIN.as_bytes());
    out.extend_from_slice(&body);
    out
}

/// Build the canonical byte payload signed by a Trusted Timestamp Authority:
/// `MAJIK_TSA_DOMAIN` ‖ JSON of `{digest, nonce, timestamp, tsa}`.
pub fn build_tsa_canonical_bytes(payload: &MajikTsaPayload) -> Vec<u8> {
    let body = serde_json::to_vec(payload).expect("TSA payload serialization is infallible");
    let mut out = Vec::with_capacity(MAJIK_TSA_DOMAIN.len() + body.len());
    out.extend_from_slice(MAJIK_TSA_DOMAIN.as_bytes());
    out.extend_from_slice(&body);
    out
}
