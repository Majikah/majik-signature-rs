//! CBOR (MJKSIG v2) — port of the TS `cbor.test.ts` / `cbor-hardening.test.ts` essentials,
//! plus interop against bytes produced by the TypeScript `cbor-x` encoder
//! (`tests/fixtures/ts_cbor.json`).

mod common;

use ciborium::value::Value;
use common::new_key;
use majik_signature::*;

fn fixture() -> serde_json::Value {
    serde_json::from_str(include_str!("fixtures/ts_cbor.json")).unwrap()
}
fn unhex(v: &serde_json::Value) -> Vec<u8> {
    hex::decode(v["cborHex"].as_str().unwrap()).unwrap()
}
fn ts_keys(v: &serde_json::Value) -> MajikSignerPublicKeys {
    MajikSignerPublicKeys {
        signer_id: v["signerId"].as_str().unwrap().into(),
        ed_public_key: base64_to_bytes(v["edPublicKey"].as_str().unwrap()).unwrap(),
        ml_dsa_public_key: base64_to_bytes(v["mlDsaPublicKey"].as_str().unwrap()).unwrap(),
    }
}
fn container(version: u8, payload: &[u8], reserved: u8, declared: Option<u32>) -> Vec<u8> {
    let mut out = MJKSIG_MAGIC.to_vec();
    out.push(version);
    out.push(reserved);
    out.extend_from_slice(&declared.unwrap_or(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}
fn map_get<'a>(v: &'a Value, key: &str) -> &'a Value {
    let Value::Map(m) = v else { panic!("not a map") };
    m.iter().find(|(k, _)| matches!(k, Value::Text(t) if t == key)).map(|(_, v)| v).unwrap()
}
fn map_set(v: &mut Value, key: &str, new: Value) {
    let Value::Map(m) = v else { panic!("not a map") };
    for (k, val) in m.iter_mut() {
        if matches!(k, Value::Text(t) if t == key) {
            *val = new;
            return;
        }
    }
    panic!("missing key {key}");
}
fn msg(e: &MajikSignatureError) -> String {
    use std::error::Error;
    let mut s = e.to_string();
    let mut cur = e.source();
    while let Some(c) = cur {
        s.push_str(" | ");
        s.push_str(&c.to_string());
        cur = c.source();
    }
    s
}

// ── Interop with TypeScript (cbor-x) output ─────────────────────────────────

#[test]
fn decodes_typescript_cbor_signature_and_it_still_verifies() {
    let f = fixture();
    let bytes = unhex(&f["signature"]);
    let expected: MajikSignatureJSON = serde_json::from_value(f["signature"]["json"].clone()).unwrap();

    let sig = MajikSignature::from_cbor(&bytes).unwrap();
    assert_eq!(sig.to_json(), expected);

    let content = base64_to_bytes(f["content"].as_str().unwrap()).unwrap();
    let r = MajikSignature::verify(&content, &sig, &ts_keys(&f), None).unwrap();
    assert!(r.valid, "{:?}", r.reason);
}

#[test]
fn decodes_typescript_cbor_envelopes_at_wire_level() {
    let f = fixture();
    for name in ["envelopeBasic", "envelopeFull"] {
        let expected: MultiSigEnvelope = serde_json::from_value(f[name]["json"].clone()).unwrap();
        let value = decode_cbor(&unhex(&f[name])).unwrap();
        assert_eq!(envelope_from_cbor(&value).unwrap(), expected, "{name}");

        // Rust re-encodes to plain byte strings; it must decode back to the identical model.
        let rust_bytes = encode_cbor(&envelope_to_cbor(&expected).unwrap()).unwrap();
        let again = envelope_from_cbor(&decode_cbor(&rust_bytes).unwrap()).unwrap();
        assert_eq!(again, expected, "{name} rust round-trip");
    }
}

#[test]
fn typescript_cbor_envelope_loads_via_public_api_and_from_mjksig() {
    let f = fixture();
    let bytes = unhex(&f["envelopeBasic"]);
    let env = MajikSignatureEnvelope::from_cbor(&bytes).unwrap();
    assert_eq!(env.signatures().len(), 1);

    // Wrap the TS payload in a v2 container.
    let restored =
        MajikSignatureEnvelope::from_mjksig(&container(MJKSIG_CBOR_VERSION, &bytes, 0, None)).unwrap();
    assert_eq!(restored.to_json(), env.to_json());
}

// ── Round trips (Rust → Rust) ───────────────────────────────────────────────

#[test]
fn signature_and_envelope_cbor_round_trip_and_still_verify() {
    let key = new_key("cbor-roundtrip");
    let content = b"CBOR round trip";
    let sig = MajikSignature::sign(content, &key, None).unwrap();
    let keys = MajikSignature::public_keys_from_majik_key(&key).unwrap();

    let restored = MajikSignature::from_cbor(&sig.to_cbor().unwrap()).unwrap();
    assert_eq!(restored, sig);
    assert!(MajikSignature::verify(content, &restored, &keys, None).unwrap().valid);

    let env = MajikSignatureEnvelope::empty().with_signature(sig.to_json()).unwrap();
    let back = MajikSignatureEnvelope::from_cbor(&env.to_cbor().unwrap()).unwrap();
    assert_eq!(back.to_json(), env.to_json());

    // CBOR is smaller than the JSON form.
    assert!(env.to_cbor().unwrap().len() < env.to_json_string().len());
}

#[test]
fn uses_native_byte_strings_for_fixed_length_fields() {
    let key = new_key("cbor-bstr");
    let sig = MajikSignature::sign(b"x", &key, None).unwrap();
    let wire = signature_to_cbor(&sig.to_json()).unwrap();
    for (field, len) in [
        ("signerId", 32),
        ("signerEdPublicKey", 32),
        ("signerMlDsaPublicKey", 2592),
        ("contentHash", 32),
        ("edSignature", 64),
        ("mlDsaSignature", 4627),
    ] {
        match map_get(&wire, field) {
            Value::Bytes(b) => assert_eq!(b.len(), len, "{field}"),
            other => panic!("{field} is not a byte string: {other:?}"),
        }
    }
    assert_eq!(signature_from_cbor(&wire).unwrap(), sig.to_json());
}

#[test]
fn mjksig_v2_header_and_legacy_v1_still_load() {
    let key = new_key("cbor-container");
    let sig = MajikSignature::sign(b"container", &key, None).unwrap();
    let env = MajikSignatureEnvelope::empty().with_signature(sig.to_json()).unwrap();

    let bytes = env.to_mjksig_bytes().unwrap();
    assert_eq!(&bytes[..MJKSIG_MAGIC_LEN], &MJKSIG_MAGIC);
    assert_eq!(bytes[MJKSIG_MAGIC_LEN], MJKSIG_CBOR_VERSION);
    assert_eq!(bytes[MJKSIG_MAGIC_LEN + 1], 0);
    let declared = u32::from_be_bytes(bytes[8..12].try_into().unwrap()) as usize;
    assert_eq!(declared, bytes.len() - MJKSIG_HEADER_LEN);
    assert_eq!(MajikSignatureEnvelope::get_mjksig_version(&bytes), Some(MJKSIG_CBOR_VERSION));
    assert_eq!(MajikSignatureEnvelope::from_mjksig(&bytes).unwrap().to_json(), env.to_json());

    let legacy = container(MJKSIG_JSON_VERSION, env.to_json_string().as_bytes(), 0, None);
    assert_eq!(MajikSignatureEnvelope::from_mjksig(&legacy).unwrap().to_json(), env.to_json());
}

// ── Decoder hardening ───────────────────────────────────────────────────────

#[test]
fn decode_cbor_rejects_malformed_input() {
    assert!(decode_cbor(&[]).is_err());
    for bytes in [
        &[0xff][..],         // top-level break
        &[0x45, 0x01, 0x02], // truncated byte string
        &[0x82, 0x01],       // truncated array
        &[0xa1, 0x01],       // truncated map
        &[0x19, 0x01],       // truncated uint
        &[0x1c],             // reserved additional information
        &[0xa0, 0x00],       // valid item + trailing byte
    ] {
        assert!(decode_cbor(bytes).is_err(), "{bytes:02x?}");
    }
    assert!(decode_cbor(&[0xa0]).is_ok());
}

#[test]
fn envelope_from_cbor_rejects_wrong_shapes_and_trailing_data() {
    let f = fixture();
    let mut ok = unhex(&f["envelopeBasic"]);
    assert!(MajikSignatureEnvelope::from_cbor(&ok).is_ok());
    ok.push(0x00);
    assert!(MajikSignatureEnvelope::from_cbor(&ok).is_err());

    for v in [
        Value::Array(vec![1.into(), 2.into(), 3.into()]),
        Value::Text("not an envelope".into()),
        Value::Null,
        Value::Map(vec![]),
    ] {
        assert!(MajikSignatureEnvelope::from_cbor(&encode_cbor(&v).unwrap()).is_err());
        assert!(MajikSignature::from_cbor(&encode_cbor(&v).unwrap()).is_err());
    }
}

#[test]
fn signature_schema_validation() {
    let f = fixture();
    let sig: MajikSignatureJSON = serde_json::from_value(f["signature"]["json"].clone()).unwrap();
    let wire = signature_to_cbor(&sig).unwrap();

    let mut v = wire.clone();
    map_set(&mut v, "version", 99.into());
    assert!(signature_from_cbor(&v).unwrap_err().to_string().contains("version"));

    let mut v = wire.clone();
    map_set(&mut v, "contentHash", Value::Text("not-a-byte-string".into()));
    assert!(signature_from_cbor(&v).unwrap_err().to_string().contains("byte string"));

    for (field, len) in [
        ("signerId", 32),
        ("signerEdPublicKey", 32),
        ("signerMlDsaPublicKey", 2592),
        ("contentHash", 32),
        ("edSignature", 64),
        ("mlDsaSignature", 4627),
    ] {
        let mut v = wire.clone();
        map_set(&mut v, field, Value::Bytes(vec![0; len - 1]));
        assert!(signature_from_cbor(&v).is_err(), "{field}");
    }

    // cbor-x wraps Uint8Array in tag 64; that form must be accepted.
    let mut v = wire.clone();
    let Value::Bytes(h) = map_get(&wire, "contentHash").clone() else { unreachable!() };
    map_set(&mut v, "contentHash", Value::Tag(64, Box::new(Value::Bytes(h))));
    assert_eq!(signature_from_cbor(&v).unwrap(), sig);

    // Duplicate and non-text map keys are rejected (parser-differential hardening).
    let Value::Map(mut entries) = wire.clone() else { unreachable!() };
    entries.push((Value::Text("version".into()), 1.into()));
    assert!(signature_from_cbor(&Value::Map(entries)).unwrap_err().to_string().contains("duplicate"));
    let Value::Map(mut entries) = wire else { unreachable!() };
    entries.push((Value::Integer(7.into()), 1.into()));
    assert!(signature_from_cbor(&Value::Map(entries)).is_err());
}

#[test]
fn mjksig_container_hardening() {
    let f = fixture();
    let payload = unhex(&f["envelopeBasic"]);
    let valid = container(MJKSIG_CBOR_VERSION, &payload, 0, None);
    assert!(MajikSignatureEnvelope::from_mjksig(&valid).is_ok());

    let err = |bytes: Vec<u8>| MajikSignatureEnvelope::from_mjksig(&bytes).unwrap_err();

    for n in [0, 1, MJKSIG_MAGIC_LEN - 1, MJKSIG_HEADER_LEN - 1, MJKSIG_HEADER_LEN] {
        assert!(MajikSignatureEnvelope::from_mjksig(&valid[..n]).is_err(), "truncated {n}");
    }
    let mut bad = valid.clone();
    bad[0] ^= 0xff;
    assert!(msg(&err(bad)).contains("magic"));
    assert!(msg(&err(container(MJKSIG_CBOR_VERSION, &payload, 1, None))).contains("reserved"));
    assert!(msg(&err(container(0x7f, &payload, 0, None))).contains("version"));
    // Empty payload: the container is exactly the header, so it is "too short" (same as TS).
    assert!(msg(&err(container(MJKSIG_CBOR_VERSION, &[], 0, None))).contains("too short"));
    // Zero declared length with trailing data.
    assert!(
        msg(&err(container(MJKSIG_CBOR_VERSION, &payload, 0, Some(0)))).contains("invalid payload length")
    );
    assert!(msg(&err(container(MJKSIG_CBOR_VERSION, &payload, 0, Some(payload.len() as u32 + 1))))
        .contains("exceeds"));
    assert!(MajikSignatureEnvelope::from_mjksig(&container(
        MJKSIG_CBOR_VERSION,
        &payload,
        0,
        Some(u32::MAX)
    ))
    .is_err());
    assert!(msg(&err(container(MJKSIG_CBOR_VERSION, &payload, 0, Some(payload.len() as u32 - 1))))
        .contains("trailing"));
    let mut appended = valid.clone();
    appended.push(0);
    assert!(msg(&err(appended)).contains("trailing"));

    assert!(
        MajikSignatureEnvelope::from_mjksig(&container(MJKSIG_JSON_VERSION, &[0xff, 0xfe], 0, None)).is_err()
    );
    assert!(MajikSignatureEnvelope::from_mjksig(&container(MJKSIG_JSON_VERSION, b"{", 0, None)).is_err());
    assert!(MajikSignatureEnvelope::from_mjksig(&container(MJKSIG_CBOR_VERSION, &[0xff], 0, None)).is_err());
    let shape = encode_cbor(&Value::Array(vec![1.into(), 2.into(), 3.into()])).unwrap();
    assert!(MajikSignatureEnvelope::from_mjksig(&container(MJKSIG_CBOR_VERSION, &shape, 0, None)).is_err());
    let mut two_items = payload.clone();
    two_items.push(0x00);
    assert!(
        MajikSignatureEnvelope::from_mjksig(&container(MJKSIG_CBOR_VERSION, &two_items, 0, None)).is_err()
    );
}

// ── Embedded transport codec ────────────────────────────────────────────────

#[test]
fn embedded_codec_round_trip_legacy_json_and_rejections() {
    let key = new_key("cbor-embedded");
    let sig = MajikSignature::sign(b"embedded", &key, None).unwrap();
    let env = MajikSignatureEnvelope::empty().with_signature(sig.to_json()).unwrap();

    let text = serialize_embedded_envelope(&env).unwrap();
    assert!(text.starts_with(EMBEDDED_CBOR_PREFIX));
    assert_eq!(EMBEDDED_CBOR_PREFIX, format!("MJKSIG:CBOR:{MJKSIG_CBOR_VERSION}:"));
    assert_eq!(parse_embedded_envelope(&text).unwrap().to_json(), env.to_json());

    // Legacy JSON text (unprefixed) stays readable.
    assert_eq!(parse_embedded_envelope(&env.to_json_string()).unwrap().to_json(), env.to_json());

    let p = EMBEDDED_CBOR_PREFIX;
    assert!(parse_embedded_envelope(p).is_err()); // empty
    assert!(parse_embedded_envelope(&format!("{p}abc")).is_err()); // length % 4
    assert!(parse_embedded_envelope(&format!("{p}!!!!")).is_err()); // alphabet
    assert!(parse_embedded_envelope(&format!("{p}/w==")).is_err()); // valid base64, invalid CBOR
                                                                    // Non-canonical base64 (non-zero trailing bits): "AB==" decodes to 0x00 but re-encodes as "AA==".
    assert!(parse_embedded_envelope(&format!("{p}AB==")).is_err());
    // Prefixed JSON is never retried as JSON.
    let b64_json = bytes_to_base64(env.to_json_string().as_bytes());
    assert!(parse_embedded_envelope(&format!("{p}{b64_json}")).is_err());
}
