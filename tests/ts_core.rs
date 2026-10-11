mod common;

use common::new_key;
use jiff::Timestamp;
use majik_signature::*;

const CONTENT: &[u8] = b"Hello, post-quantum world!";
const SIGNED_AT: &str = "2026-06-01T00:00:00.000Z";
const EXPIRY: &str = "2026-07-01T00:00:00.000Z";

fn timestamp(value: &str) -> Timestamp {
    value.parse().expect("valid test timestamp")
}

#[test]
fn signing_and_verification_match_typescript_core_cases() {
    let key = new_key("ts-core-signer");
    let signature = MajikSignature::sign(
        CONTENT,
        &key,
        Some(&SignOptions {
            content_type: Some("text/plain".into()),
            timestamp: Some(SIGNED_AT.into()),
            ..Default::default()
        }),
    )
    .unwrap();
    let public_keys = MajikSignature::public_keys_from_majik_key(&key).unwrap();

    assert_eq!(signature.version(), 1);
    assert_eq!(signature.signer_id(), key.fingerprint());
    assert_eq!(signature.content_type(), Some("text/plain"));
    assert!(!signature.content_hash().is_empty());
    assert!(!signature.ed_signature().is_empty());
    assert!(!signature.ml_dsa_signature().is_empty());

    let result = MajikSignature::verify(CONTENT, &signature, &public_keys, None).unwrap();
    assert!(result.valid, "{:?}", result.reason);
    assert_eq!(result.signer_id.as_deref(), Some(key.fingerprint()));

    let tampered = MajikSignature::verify(b"Tampered content!", &signature, &public_keys, None).unwrap();
    assert!(!tampered.valid);

    let via_key = MajikSignature::verify_with_key(CONTENT, &signature, &key).unwrap();
    assert!(via_key.valid, "{:?}", via_key.reason);
}

#[test]
fn cryptographic_tampering_of_each_signature_is_rejected() {
    let key = new_key("ts-core-crypto-tampering");
    let signature = MajikSignature::sign(CONTENT, &key, None).unwrap();
    let public_keys = MajikSignature::public_keys_from_majik_key(&key).unwrap();

    let mut tampered_ed = signature.to_json();
    let mut ed_bytes = base64_to_bytes(&tampered_ed.ed_signature).unwrap();
    ed_bytes[0] ^= 0x01;
    tampered_ed.ed_signature = bytes_to_base64(&ed_bytes);
    let ed_result = MajikSignature::verify(CONTENT, &tampered_ed, &public_keys, None).unwrap();
    assert!(!ed_result.valid);
    assert_eq!(ed_result.reason.as_deref(), Some("Invalid Ed25519 signature"));

    let mut tampered_ml = signature.to_json();
    let mut ml_bytes = base64_to_bytes(&tampered_ml.ml_dsa_signature).unwrap();
    ml_bytes[0] ^= 0x01;
    tampered_ml.ml_dsa_signature = bytes_to_base64(&ml_bytes);
    let ml_result = MajikSignature::verify(CONTENT, &tampered_ml, &public_keys, None).unwrap();
    assert!(!ml_result.valid);
    assert_eq!(ml_result.reason.as_deref(), Some("Invalid ML-DSA-87 signature"));
}

#[test]
fn signing_and_verification_reject_invalid_inputs() {
    let key = new_key("ts-core-invalid-inputs");
    assert!(MajikSignature::sign(b"", &key, None).is_err());
    assert!(MajikSignature::sign(
        CONTENT,
        &key,
        Some(&SignOptions { content_type: Some("  ".into()), ..Default::default() }),
    )
    .is_err());

    let signature = MajikSignature::sign(CONTENT, &key, None).unwrap();
    let mut public_keys = MajikSignature::public_keys_from_majik_key(&key).unwrap();
    public_keys.ed_public_key.pop();
    assert!(MajikSignature::verify(CONTENT, &signature, &public_keys, None).is_err());

    let mut invalid_json = signature.to_json();
    invalid_json.version = 2;
    assert!(MajikSignature::from_json(&invalid_json).is_err());
}

#[test]
fn serialization_json_validation_and_public_key_helpers_roundtrip() {
    let key = new_key("ts-core-serialization");
    let signature = MajikSignature::sign(CONTENT, &key, None).unwrap();

    assert!(signature.is_valid());
    let public_keys = MajikSignature::public_keys_from_majik_key(&key).unwrap();
    assert_eq!(signature.extract_public_keys().unwrap(), public_keys);

    let json = signature.to_json();
    assert_eq!(json.version, 1);
    assert_eq!(json.signer_id, key.fingerprint());
    assert_eq!(MajikSignature::from_json(&json).unwrap(), signature);

    let json_text = signature.to_json_string().unwrap();
    assert_eq!(MajikSignature::from_json_str(&json_text).unwrap(), signature);
    let value = serde_json::from_str(&json_text).unwrap();
    assert_eq!(MajikSignature::from_json_value(&value).unwrap(), signature);

    let serialized = signature.serialize().unwrap();
    assert_eq!(MajikSignature::deserialize(&serialized).unwrap(), signature);

    let expected = MajikSignature::expected_signer_from_key(&key).unwrap();
    assert_eq!(expected.signer_id, key.fingerprint());
    assert_eq!(expected.ed_public_key, bytes_to_base64(&public_keys.ed_public_key));
    assert_eq!(expected.ml_dsa_public_key, bytes_to_base64(&public_keys.ml_dsa_public_key));
}

#[test]
fn compact_signature_rehydrates_and_verifies() {
    let key = new_key("ts-core-compact");
    let signature = MajikSignature::sign(
        CONTENT,
        &key,
        Some(&SignOptions { valid_until: Some("2099-01-01T00:00:00.000Z".into()), ..Default::default() }),
    )
    .unwrap();
    let public_keys = MajikSignature::public_keys_from_majik_key(&key).unwrap();
    let compact = signature.to_compact();

    assert_eq!(compact.valid_until.as_deref(), Some("2099-01-01T00:00:00.000Z"));
    let restored =
        MajikSignature::from_compact(&compact, &public_keys.ed_public_key, &public_keys.ml_dsa_public_key)
            .unwrap();
    assert_eq!(restored.valid_until(), signature.valid_until());
    assert!(MajikSignature::verify_compact(CONTENT, &compact, &public_keys).unwrap().valid);

    let mut mismatched_keys = public_keys.clone();
    mismatched_keys.signer_id = "different-signer".into();
    let result = MajikSignature::verify_compact(CONTENT, &compact, &mismatched_keys).unwrap();
    assert!(!result.valid);
    assert!(result.reason.as_deref().unwrap().contains("signerId mismatch"));
}

#[test]
fn valid_until_enforces_expiry_after_crypto_and_at_the_boundary() {
    let key = new_key("ts-core-expiry");
    let signature = MajikSignature::sign(
        CONTENT,
        &key,
        Some(&SignOptions {
            timestamp: Some(SIGNED_AT.into()),
            valid_until: Some(EXPIRY.into()),
            ..Default::default()
        }),
    )
    .unwrap();
    let public_keys = MajikSignature::public_keys_from_majik_key(&key).unwrap();

    assert!(!signature.is_expired(Some(timestamp("2026-06-15T00:00:00.000Z"))));
    assert!(!signature.is_expired(Some(timestamp(EXPIRY))));
    assert!(signature.is_expired(Some(timestamp("2026-07-02T00:00:00.000Z"))));

    let before = MajikSignature::verify(CONTENT, &signature, &public_keys, Some(timestamp(EXPIRY))).unwrap();
    assert!(before.valid, "{:?}", before.reason);

    let after = MajikSignature::verify(
        CONTENT,
        &signature,
        &public_keys,
        Some(timestamp("2026-07-02T00:00:00.000Z")),
    )
    .unwrap();
    assert!(!after.valid);
    assert_eq!(after.expired, Some(true));

    let tampered = MajikSignature::verify(
        b"different content",
        &signature,
        &public_keys,
        Some(timestamp("2026-07-02T00:00:00.000Z")),
    )
    .unwrap();
    assert!(!tampered.valid);
    assert_eq!(tampered.expired, None);
}

#[test]
fn valid_until_roundtrips_and_compact_signatures_expire() {
    let key = new_key("ts-core-expiry-roundtrip");
    let signature = MajikSignature::sign(
        CONTENT,
        &key,
        Some(&SignOptions { valid_until: Some("2020-01-01T00:00:00.000Z".into()), ..Default::default() }),
    )
    .unwrap();
    let keys = MajikSignature::public_keys_from_majik_key(&key).unwrap();

    let restored = MajikSignature::deserialize(&signature.serialize().unwrap()).unwrap();
    assert_eq!(restored.valid_until(), Some("2020-01-01T00:00:00.000Z"));
    let result = MajikSignature::verify_compact(CONTENT, &restored.to_compact(), &keys).unwrap();
    assert!(!result.valid);
    assert_eq!(result.expired, Some(true));

    let never_expires = MajikSignature::sign(CONTENT, &key, None).unwrap();
    assert!(!never_expires.is_expired(Some(timestamp("2099-01-01T00:00:00.000Z"))));
}

#[test]
fn trusted_timestamp_sign_attach_verify_and_reject_replacement() {
    let signer = new_key("ts-core-signer-tsa");
    let tsa_key = new_key("ts-core-tsa");
    let mut signature = MajikSignature::sign(CONTENT, &signer, None).unwrap();
    let request = signature.build_tsa_request_payload();
    let tsa = MajikSignature::sign_tsa(
        &request,
        &tsa_key,
        MajikTsaIdentity {
            id: "tsa.majikah.solutions".into(),
            signer_fingerprint: tsa_key.fingerprint().into(),
        },
        Some(SIGNED_AT),
    )
    .unwrap();

    assert_eq!(tsa.version, 1);
    assert_eq!(tsa.payload.digest.value, signature.content_hash());
    assert_eq!(tsa.payload.tsa.signer_fingerprint, tsa_key.fingerprint());

    signature.add_tsa(tsa.clone()).unwrap();
    assert!(signature.has_tsa());
    assert!(signature.verify_tsa().unwrap().valid);
    assert!(signature.add_tsa(tsa).is_err());

    let restored = MajikSignature::from_json(&signature.to_json()).unwrap();
    assert!(restored.has_tsa());
    assert!(restored.verify_tsa().unwrap().valid);
}

#[test]
fn trusted_timestamp_rejects_wrong_content_digest() {
    let signer = new_key("ts-core-tsa-digest-signer");
    let tsa_key = new_key("ts-core-tsa-digest-authority");
    let mut signature = MajikSignature::sign(CONTENT, &signer, None).unwrap();
    let other = MajikSignature::sign(b"different content", &signer, None).unwrap();
    let request = other.build_tsa_request_payload();
    let tsa = MajikSignature::sign_tsa(
        &request,
        &tsa_key,
        MajikTsaIdentity {
            id: "tsa.majikah.solutions".into(),
            signer_fingerprint: tsa_key.fingerprint().into(),
        },
        Some(SIGNED_AT),
    )
    .unwrap();

    assert!(signature.add_tsa(tsa).is_err());
}

#[test]
fn signing_rejects_invalid_valid_until() {
    let key = new_key("ts-core-invalid-expiry");
    let result = MajikSignature::sign(
        CONTENT,
        &key,
        Some(&SignOptions { valid_until: Some("not-a-real-date".into()), ..Default::default() }),
    );
    assert!(result.is_err());
}
