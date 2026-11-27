//! Adversarial MJKSMAP and bounded-memory manifest regressions.
mod common;

use ciborium::value::Value;
use common::new_key;
use majik_signature::*;

fn empty_envelope() -> MultiSigEnvelope {
    MultiSigEnvelope {
        version: 1,
        allowlist: None,
        allowlist_signer_id: None,
        signatures: vec![],
        seal_hash: None,
        seal_timestamp: None,
        sealed_by: None,
        chain_anchors: None,
        file_versions: None,
    }
}

fn entry(path: &str) -> MjksMapEntry {
    MjksMapEntry {
        path: path.into(),
        content_hash: bytes_to_base64(&[0x2a; 32]),
        size: Some(0),
        mime_type: Some("text/plain".into()),
        envelope: empty_envelope(),
    }
}

fn valid_map() -> MajikSignatureMap {
    MajikSignatureMap::empty().with_entry(entry("docs/report.txt")).unwrap()
}

fn map_json(entries: Vec<serde_json::Value>) -> serde_json::Value {
    serde_json::json!({
        "version": MJKSMAP_SCHEMA_VERSION,
        "createdAt": "2026-11-28T00:00:00.000Z",
        "entries": entries
    })
}

fn container(version: u8, payload: &[u8], reserved: u8, declared: Option<u32>, suffix: &[u8]) -> Vec<u8> {
    let mut bytes = MJKSMAP_MAGIC.to_vec();
    bytes.push(version);
    bytes.push(reserved);
    bytes.extend_from_slice(&declared.unwrap_or(payload.len() as u32).to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes.extend_from_slice(suffix);
    bytes
}

#[test]
fn round_trip_preserves_valid_manifest_and_normalized_paths() {
    let map = MajikSignatureMap::empty().with_entry(entry(r"C:\docs\report.txt")).unwrap();
    let bytes = map.to_mjksmap_bytes();
    let restored = MajikSignatureMap::from_mjksmap(&bytes).unwrap();
    assert_eq!(restored.size(), 1);
    assert!(restored.has_entry("docs/report.txt"));
    assert!(restored.has_entry(r"C:\docs\report.txt"));
}

#[test]
fn rejects_traversal_controls_and_oversized_paths() {
    for path in ["../secret.txt", "docs/../../secret.txt", "docs/\0/report.txt", "docs/\u{202e}/report.txt"] {
        assert!(MajikSignatureMap::empty().with_entry(entry(path)).is_err(), "{path:?}");
    }
    let long_path = "a".repeat(MAX_MJKSMAP_PATH_CHARS + 1);
    assert!(MajikSignatureMap::empty().with_entry(entry(&long_path)).is_err());
}

#[test]
fn rejects_duplicate_paths_after_normalization() {
    let hash = bytes_to_base64(&[0x2a; 32]);
    let env = serde_json::to_value(empty_envelope()).unwrap();
    let input = map_json(vec![
        serde_json::json!({"path": r"C:\docs\report.txt", "contentHash": hash.clone(), "size":0, "mimeType":"text/plain", "envelope":env.clone()}),
        serde_json::json!({"path": "docs/report.txt", "contentHash": hash, "size":0, "mimeType":"text/plain", "envelope":env}),
    ]);
    assert!(MajikSignatureMap::from_json_value(input)
        .unwrap_err()
        .to_string()
        .contains("Duplicate normalized path"));
}

#[test]
fn rejects_invalid_digest_size_mime_and_timestamp_fields() {
    let mut bad_hash = serde_json::to_value(entry("a.txt")).unwrap();
    bad_hash["contentHash"] = serde_json::Value::String("A".repeat(44));
    assert!(MajikSignatureMap::from_json_value(map_json(vec![bad_hash])).is_err());

    let mut bad_size = serde_json::to_value(entry("a.txt")).unwrap();
    bad_size["size"] = serde_json::Value::from(-1);
    assert!(MajikSignatureMap::from_json_value(map_json(vec![bad_size])).is_err());

    let mut unsafe_size = serde_json::to_value(entry("a.txt")).unwrap();
    unsafe_size["size"] = serde_json::Value::from(9_007_199_254_740_992u64);
    assert!(MajikSignatureMap::from_json_value(map_json(vec![unsafe_size])).is_err());

    let mut bad_mime = serde_json::to_value(entry("a.txt")).unwrap();
    bad_mime["mimeType"] = serde_json::Value::String("text/plain\r\nInjected: yes".into());
    assert!(MajikSignatureMap::from_json_value(map_json(vec![bad_mime])).is_err());

    let mut bad_timestamp = map_json(vec![]);
    bad_timestamp["createdAt"] = serde_json::Value::String("not-a-date".into());
    assert!(MajikSignatureMap::from_json_value(bad_timestamp).is_err());
}

#[test]
fn rejects_manifest_entry_count_before_building_indices() {
    let hash = bytes_to_base64(&[0x2a; 32]);
    let env = serde_json::to_value(empty_envelope()).unwrap();
    let entries = (0..=MAX_MJKSMAP_ENTRIES)
        .map(|index| {
            serde_json::json!({
                "path": format!("docs/{index}.txt"),
                "contentHash": hash.clone(),
                "envelope": env.clone()
            })
        })
        .collect();
    assert!(MajikSignatureMap::from_json_value(map_json(entries))
        .unwrap_err()
        .to_string()
        .contains("exceeds the limit"));
}

#[test]
fn writes_cbor_v2_and_reads_legacy_json_v1() {
    let map = valid_map();
    let bytes = map.to_mjksmap_bytes();
    assert_eq!(bytes[MJKSMAP_MAGIC_LEN], MJKSMAP_CBOR_VERSION);

    let legacy_json = serde_json::to_vec(&map.to_json()).unwrap();
    assert!(bytes.len() < MJKSMAP_HEADER_LEN + legacy_json.len());
    let legacy = container(MJKSMAP_JSON_VERSION, &legacy_json, 0, None, &[]);
    let restored = MajikSignatureMap::from_mjksmap(&legacy).unwrap();
    assert_eq!(restored.to_json(), map.to_json());
}

#[test]
fn encodes_manifest_and_nested_signature_binary_fields_as_cbor_byte_strings() {
    let key = new_key("mjksmap-cbor-native");
    let signature = MajikSignature::sign(b"compact MJKSMAP manifest", &key, None).unwrap();
    let signature_json = signature.to_json();

    let mut envelope = empty_envelope();
    envelope.signatures.push(signature_json.clone());
    let map = MajikSignatureMap::empty()
        .with_entry(MjksMapEntry {
            path: "docs/report.txt".into(),
            content_hash: signature_json.content_hash.clone(),
            size: Some(25),
            mime_type: Some("text/plain".into()),
            envelope,
        })
        .unwrap();

    let bytes = map.to_mjksmap_bytes();
    assert_eq!(bytes[MJKSMAP_MAGIC_LEN], MJKSMAP_CBOR_VERSION);
    let payload = &bytes[MJKSMAP_HEADER_LEN..];
    assert!(payload.len() < serde_json::to_vec(&map.to_json()).unwrap().len());

    let decoded = decode_cbor(payload).unwrap();
    let Value::Map(root) = decoded else { panic!("MJKSMAP root must be a CBOR map") };
    let root_get = |key: &str| {
        root.iter()
            .find(|(k, _)| matches!(k, Value::Text(name) if name == key))
            .map(|(_, value)| value)
            .unwrap()
    };
    let Value::Array(entries) = root_get("entries") else { panic!("entries must be an array") };
    let Value::Map(entry) = &entries[0] else { panic!("entry must be a map") };
    let entry_get = |key: &str| {
        entry
            .iter()
            .find(|(k, _)| matches!(k, Value::Text(name) if name == key))
            .map(|(_, value)| value)
            .unwrap()
    };
    assert!(matches!(entry_get("contentHash"), Value::Bytes(bytes) if bytes.len() == 32));

    let Value::Map(envelope) = entry_get("envelope") else { panic!("envelope must be a CBOR map") };
    let signatures = envelope
        .iter()
        .find(|(k, _)| matches!(k, Value::Text(name) if name == "signatures"))
        .map(|(_, value)| value)
        .unwrap();
    let Value::Array(signatures) = signatures else { panic!("signatures must be an array") };
    let Value::Map(signature) = &signatures[0] else { panic!("signature must be a map") };
    let signature_get = |key: &str| {
        signature
            .iter()
            .find(|(k, _)| matches!(k, Value::Text(name) if name == key))
            .map(|(_, value)| value)
            .unwrap()
    };

    for (field, length) in [
        ("signerId", 32),
        ("signerEdPublicKey", 32),
        ("signerMlDsaPublicKey", 2592),
        ("contentHash", 32),
        ("edSignature", 64),
        ("mlDsaSignature", 4627),
    ] {
        assert!(
            matches!(signature_get(field), Value::Bytes(bytes) if bytes.len() == length),
            "{field} must be a {length}-byte CBOR byte string"
        );
    }

    let restored = MajikSignatureMap::from_mjksmap(&bytes).unwrap();
    assert_eq!(restored.to_json(), map.to_json());
}

#[test]
fn accepts_cbor_x_tag_64_for_manifest_binary_fields() {
    let map = valid_map();
    let bytes = map.to_mjksmap_bytes();
    let mut decoded = decode_cbor(&bytes[MJKSMAP_HEADER_LEN..]).unwrap();
    let Value::Map(root) = &mut decoded else { panic!("root must be a map") };
    let entries = root
        .iter_mut()
        .find(|(key, _)| matches!(key, Value::Text(name) if name == "entries"))
        .map(|(_, value)| value)
        .unwrap();
    let Value::Array(entries) = entries else { panic!("entries must be an array") };
    let Value::Map(entry) = &mut entries[0] else { panic!("entry must be a map") };
    let content_hash = entry
        .iter_mut()
        .find(|(key, _)| matches!(key, Value::Text(name) if name == "contentHash"))
        .map(|(_, value)| value)
        .unwrap();
    let raw = std::mem::replace(content_hash, Value::Null);
    *content_hash = Value::Tag(64, Box::new(raw));

    let payload = encode_cbor(&decoded).unwrap();
    let tagged = container(MJKSMAP_CBOR_VERSION, &payload, 0, None, &[]);
    let restored = MajikSignatureMap::from_mjksmap(&tagged).unwrap();
    assert_eq!(restored.to_json(), map.to_json());
}

#[test]
fn rejects_cbor_with_multiple_top_level_items() {
    let valid = valid_map().to_mjksmap_bytes();
    assert_eq!(valid[MJKSMAP_MAGIC_LEN], MJKSMAP_CBOR_VERSION);
    let payload = &valid[MJKSMAP_HEADER_LEN..];
    let mut appended = payload.to_vec();
    appended.push(0xf6); // CBOR null as an extra top-level data item
    assert!(decode_cbor(&appended).unwrap_err().to_string().to_lowercase().contains("trailing"));
    let invalid = container(MJKSMAP_CBOR_VERSION, &appended, 0, None, &[]);
    assert!(MajikSignatureMap::from_mjksmap(&invalid).is_err());
}

#[test]
fn enforces_binary_header_length_utf8_and_payload_limits() {
    let valid = valid_map().to_mjksmap_bytes();
    assert!(MajikSignatureMap::from_mjksmap(&valid).is_ok());
    let payload = &valid[MJKSMAP_HEADER_LEN..];

    assert!(MajikSignatureMap::from_mjksmap(&container(MJKSMAP_CBOR_VERSION, payload, 1, None, &[]))
        .unwrap_err()
        .to_string()
        .contains("reserved byte"));
    assert!(MajikSignatureMap::from_mjksmap(&container(MJKSMAP_CBOR_VERSION, payload, 0, None, &[0]))
        .unwrap_err()
        .to_string()
        .contains("trailing bytes"));
    assert!(MajikSignatureMap::from_mjksmap(&container(
        MJKSMAP_CBOR_VERSION,
        payload,
        0,
        Some(payload.len() as u32 + 1),
        &[]
    ))
    .unwrap_err()
    .to_string()
    .contains("exceeds buffer"));
    assert!(MajikSignatureMap::from_mjksmap(&container(MJKSMAP_JSON_VERSION, &[0xff], 0, None, &[]))
        .unwrap_err()
        .to_string()
        .contains("UTF-8"));

    let oversized_json = " ".repeat(MAX_MJKSMAP_JSON_BYTES + 1);
    assert!(MajikSignatureMap::from_json_str(&oversized_json).is_err());
}
