mod common;

use common::new_key;
use majik_signature::*;

const CONTENT: &[u8] = b"SignRoom immutable source document for session-bound signing.";

fn digest_text(value: &str) -> String {
    bytes_to_base64(&hash_content(value.as_bytes()))
}

fn context(session_id: &str, challenge_id: &str) -> MajikSessionSigningContext {
    MajikSessionSigningContext {
        session_id: session_id.into(),
        challenge_id: challenge_id.into(),
        policy_hash: digest_text("immutable-session-policy"),
    }
}

#[test]
fn session_context_commitment_is_deterministic_and_validated() {
    let input = context("session-001", "challenge-001");
    let first = build_session_context_hash(&input).unwrap();
    assert_eq!(build_session_context_hash(&input).unwrap(), first);
    assert_eq!(first.len(), 44);

    let changed_challenge = MajikSessionSigningContext {
        challenge_id: "challenge-002".into(),
        ..input.clone()
    };
    assert_ne!(build_session_context_hash(&changed_challenge).unwrap(), first);

    let invalid_policy = MajikSessionSigningContext {
        policy_hash: "not-a-digest".into(),
        ..input.clone()
    };
    assert!(build_session_context_hash(&invalid_policy).is_err());

    let invalid_id = MajikSessionSigningContext {
        session_id: " session-001".into(),
        ..input
    };
    assert!(build_session_context_hash(&invalid_id).is_err());
}

#[test]
fn signs_and_verifies_session_context_and_digest_only() {
    let key = new_key("signroom-digest");
    let session_hash = build_session_context_hash(&context("session-verify", "challenge-verify")).unwrap();
    let signature = MajikSignature::sign(
        CONTENT,
        &key,
        Some(&SignOptions { session_context_hash: Some(session_hash.clone()), ..Default::default() }),
    ).unwrap();
    let keys = MajikSignature::public_keys_from_majik_key(&key).unwrap();

    let verified = MajikSignature::verify(CONTENT, &signature, &keys, None).unwrap();
    assert!(verified.valid, "{:?}", verified.reason);
    assert_eq!(verified.session_context_hash.as_deref(), Some(session_hash.as_str()));

    let digest = MajikSignature::verify_digest(
        signature.content_hash(), &signature, &keys, Some(&session_hash), None,
    ).unwrap();
    assert!(digest.base.valid, "{:?}", digest.base.reason);
    assert!(digest.commitment_only);

    let missing_context = MajikSignature::verify_digest(
        signature.content_hash(), &signature, &keys, None, None,
    ).unwrap();
    assert!(!missing_context.base.valid);
    assert!(missing_context.base.reason.unwrap().contains("session context hash is required"));

    let other_context = build_session_context_hash(&context("session-other", "challenge-other")).unwrap();
    let mismatch = MajikSignature::verify_digest(
        signature.content_hash(), &signature, &keys, Some(&other_context), None,
    ).unwrap();
    assert!(!mismatch.base.valid);

    let wrong_digest = MajikSignature::verify_digest(
        &digest_text("different document"), &signature, &keys, Some(&session_hash), None,
    ).unwrap();
    assert!(!wrong_digest.base.valid);
}

#[test]
fn rejects_public_keys_that_do_not_match_the_embedded_record() {
    let signer = new_key("signroom-key-owner");
    let other = new_key("signroom-key-other");
    let signature = MajikSignature::sign(CONTENT, &signer, None).unwrap();
    let other_keys = MajikSignature::public_keys_from_majik_key(&other).unwrap();

    let verified = MajikSignature::verify(CONTENT, &signature, &other_keys, None).unwrap();
    assert!(!verified.valid);
    assert!(verified.reason.unwrap().contains("fingerprint does not match"));
    let digest = MajikSignature::verify_digest(
        signature.content_hash(), &signature, &other_keys, None, None,
    ).unwrap();
    assert!(!digest.base.valid);
}

#[test]
fn session_context_round_trips_json_compact_and_cbor() {
    let key = new_key("signroom-serialization");
    let session_hash = build_session_context_hash(&context("session-serialization", "challenge-serialization")).unwrap();
    let signature = MajikSignature::sign(
        CONTENT,
        &key,
        Some(&SignOptions { session_context_hash: Some(session_hash.clone()), ..Default::default() }),
    ).unwrap();

    let json = signature.to_json();
    assert_eq!(MajikSignature::from_json(&json).unwrap().session_context_hash(), Some(session_hash.as_str()));

    let compact = signature.to_compact();
    assert_eq!(compact.session_context_hash.as_deref(), Some(session_hash.as_str()));
    let keys = signature.extract_public_keys().unwrap();
    let restored_compact = MajikSignature::from_compact(&compact, &keys.ed_public_key, &keys.ml_dsa_public_key).unwrap();
    assert_eq!(restored_compact.session_context_hash(), Some(session_hash.as_str()));
    assert!(MajikSignature::verify_digest(
        signature.content_hash(), &restored_compact, &keys, Some(&session_hash), None,
    ).unwrap().base.valid);

    let restored_cbor = MajikSignature::from_cbor(&signature.to_cbor().unwrap()).unwrap();
    assert_eq!(restored_cbor.session_context_hash(), Some(session_hash.as_str()));
    assert!(MajikSignature::verify(CONTENT, &restored_cbor, &keys, None).unwrap().valid);
}

#[test]
fn legacy_signatures_omit_session_fields_and_keep_content_tsa_scope() {
    let key = new_key("signroom-legacy");
    let signature = MajikSignature::sign(CONTENT, &key, None).unwrap();
    let json = serde_json::to_value(signature.to_json()).unwrap();
    assert!(json.get("sessionContextHash").is_none());
    assert!(signature.session_context_hash().is_none());
    assert!(MajikSignature::verify_digest(signature.content_hash(), &signature, &signature.extract_public_keys().unwrap(), None, None).unwrap().base.valid);

    let request = signature.build_tsa_request_payload();
    assert_eq!(request.digest.value, signature.content_hash());
    assert!(request.digest.scope.is_none());
}

#[test]
fn signature_scoped_tsa_is_pinned_and_cannot_be_reused() {
    let signer = new_key("signroom-tsa-signer");
    let other_signer = new_key("signroom-tsa-other-signer");
    let tsa_key = new_key("signroom-tsa-authority");
    let tsa_keys = MajikSignature::public_keys_from_majik_key(&tsa_key).unwrap();

    let session_hash = build_session_context_hash(&context("session-tsa", "challenge-tsa")).unwrap();
    let mut signature = MajikSignature::sign(
        CONTENT,
        &signer,
        Some(&SignOptions { session_context_hash: Some(session_hash), ..Default::default() }),
    ).unwrap();
    let request = signature.build_tsa_request_payload_with_scope(Some(TsaDigestScope::Signature));
    assert_eq!(request.digest.scope, Some(TsaDigestScope::Signature));
    assert_ne!(request.digest.value, signature.content_hash());

    let timestamp = MajikSignature::sign_tsa(
        &request,
        &tsa_key,
        MajikTsaIdentity {
            id: "tsa.majikah.solutions".into(),
            signer_fingerprint: tsa_keys.signer_id.clone(),
        },
        None,
    ).unwrap();
    signature.add_tsa_with_trusted_keys(timestamp.clone(), Some(&tsa_keys)).unwrap();
    assert!(signature.verify_tsa_with_trusted_keys(Some(&tsa_keys)).unwrap().valid);
    assert!(signature.verify_tsa().unwrap().valid);

    // The TSA field is excluded from the signature-scope commitment, so attachment is stable.
    let restored = MajikSignature::from_cbor(&signature.to_cbor().unwrap()).unwrap();
    assert_eq!(
        restored.tsa().unwrap().payload.digest.scope,
        Some(TsaDigestScope::Signature),
    );
    assert!(restored.verify_tsa_with_trusted_keys(Some(&tsa_keys)).unwrap().valid);

    let wrong_tsa_keys = MajikSignature::public_keys_from_majik_key(&other_signer).unwrap();
    assert!(signature.verify_tsa_with_trusted_keys(Some(&wrong_tsa_keys)).is_err());

    let mut different_record = MajikSignature::sign(CONTENT, &other_signer, None).unwrap();
    assert!(different_record.add_tsa(timestamp).is_err());
}

#[test]
fn rejects_invalid_session_hash_and_unsupported_tsa_scope() {
    assert!(MajikSignatureValidator::validate_session_context_hash("invalid").is_err());
    let invalid_tsa_payload = serde_json::json!({
        "digest": { "algorithm": "SHA-256", "value": digest_text("x"), "scope": "unknown" },
        "nonce": digest_text("nonce"),
        "timestamp": "2026-01-01T00:00:00.000Z",
        "tsa": { "id": "tsa.example", "signerFingerprint": digest_text("fingerprint") }
    });
    assert!(MajikSignatureValidator::validate_majik_tsa_payload_value(&invalid_tsa_payload).is_err());
    let key = new_key("signroom-validation");
    let result = MajikSignature::sign(
        CONTENT,
        &key,
        Some(&SignOptions { session_context_hash: Some("invalid".into()), ..Default::default() }),
    );
    assert!(result.is_err());
}
