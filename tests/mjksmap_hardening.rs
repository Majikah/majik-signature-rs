//! Adversarial MJKSMAP and bounded-memory manifest regressions.
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
        "version": MJKSMAP_VERSION,
        "createdAt": "2026-11-28T00:00:00.000Z",
        "entries": entries
    })
}

fn container(payload: &[u8], reserved: u8, declared: Option<u32>, suffix: &[u8]) -> Vec<u8> {
    let mut bytes = MJKSMAP_MAGIC.to_vec();
    bytes.push(MJKSMAP_VERSION);
    bytes.push(reserved);
    bytes.extend_from_slice(&declared.unwrap_or(payload.len() as u32).to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes.extend_from_slice(suffix);
    bytes
}

#[test]
fn round_trip_preserves_valid_manifest_and_normalized_paths() {
    let map = MajikSignatureMap::empty()
        .with_entry(entry(r"C:\docs\report.txt"))
        .unwrap();
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
        serde_json::json!({"path": r"C:\docs\report.txt", "contentHash": hash, "size":0, "mimeType":"text/plain", "envelope":env}),
        serde_json::json!({"path": "docs/report.txt", "contentHash": hash, "size":0, "mimeType":"text/plain", "envelope":env}),
    ]);
    assert!(MajikSignatureMap::from_json_value(input).unwrap_err().to_string().contains("Duplicate normalized path"));
}

#[test]
fn rejects_invalid_digest_size_mime_and_timestamp_fields() {
    let mut bad_hash = serde_json::to_value(entry("a.txt")).unwrap();
    bad_hash["contentHash"] = serde_json::Value::String("A".repeat(44));
    assert!(MajikSignatureMap::from_json_value(map_json(vec![bad_hash])).is_err());

    let mut bad_size = serde_json::to_value(entry("a.txt")).unwrap();
    bad_size["size"] = serde_json::Value::from(-1);
    assert!(MajikSignatureMap::from_json_value(map_json(vec![bad_size])).is_err());

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
        .map(|index| serde_json::json!({
            "path": format!("docs/{index}.txt"),
            "contentHash": hash,
            "envelope": env
        }))
        .collect();
    assert!(MajikSignatureMap::from_json_value(map_json(entries)).unwrap_err().to_string().contains("exceeds the limit"));
}

#[test]
fn enforces_binary_header_length_utf8_and_payload_limits() {
    let valid = valid_map().to_mjksmap_bytes();
    assert!(MajikSignatureMap::from_mjksmap(&valid).is_ok());
    let payload = &valid[MJKSMAP_HEADER_LEN..];

    assert!(MajikSignatureMap::from_mjksmap(&container(payload, 1, None, &[]))
        .unwrap_err().to_string().contains("reserved byte"));
    assert!(MajikSignatureMap::from_mjksmap(&container(payload, 0, None, &[0]))
        .unwrap_err().to_string().contains("trailing bytes"));
    assert!(MajikSignatureMap::from_mjksmap(&container(payload, 0, Some(payload.len() as u32 + 1), &[]))
        .unwrap_err().to_string().contains("exceeds buffer"));
    assert!(MajikSignatureMap::from_mjksmap(&container(&[0xff], 0, None, &[]))
        .unwrap_err().to_string().contains("UTF-8"));

    let oversized_json = " ".repeat(MAX_MJKSMAP_BYTES + 1);
    assert!(MajikSignatureMap::from_json_str(&oversized_json).is_err());
}
