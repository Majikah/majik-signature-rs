//! Port of `core/stamp/core/payload.ts` — canonical bytes signed by the DCT-layer Ed25519 stub.

use serde::Serialize;

use crate::core::stamp::core::types::ImageSigningPayloadFields;

const DOMAIN_PREFIX: &str = "majik-image-v1:";

#[derive(Serialize)]
struct Canonical<'a> {
    id: &'a str,
    #[serde(rename = "pHash")]
    p_hash: &'a str,
    ts: &'a str,
    v: u8,
}

pub fn build_image_signing_payload(fields: &ImageSigningPayloadFields<'_>) -> Vec<u8> {
    let obj = Canonical { id: fields.signer_id, p_hash: fields.p_hash, ts: fields.timestamp, v: 1 };
    let mut out = DOMAIN_PREFIX.as_bytes().to_vec();
    out.extend_from_slice(&serde_json::to_vec(&obj).expect("serializing plain strings is infallible"));
    out
}
