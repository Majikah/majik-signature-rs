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
    assert_eq!(first, "6XSd2ZIRAOWQ+jWxEDkJAkcjeHSAJfzg4PKH8CQ3sD4=");
    assert_eq!(first.len(), 44);

    let changed_challenge =
        MajikSessionSigningContext { challenge_id: "challenge-002".into(), ..input.clone() };
    assert_ne!(build_session_context_hash(&changed_challenge).unwrap(), first);

    let invalid_policy = MajikSessionSigningContext { policy_hash: "not-a-digest".into(), ..input.clone() };
    assert!(build_session_context_hash(&invalid_policy).is_err());

    let invalid_id = MajikSessionSigningContext { session_id: " session-001".into(), ..input };
    assert!(build_session_context_hash(&invalid_id).is_err());
}

#[test]
fn session_context_is_appended_to_the_canonical_signing_payload() {
    let payload = build_signing_payload(&PayloadFields {
        signer_id: "id",
        timestamp: "2026-01-01T00:00:00.000Z",
        content_hash: "hash",
        content_type: None,
        allowlist_hash: Some("alh"),
        valid_until: Some("vu"),
        version_chain_hash: Some("vch"),
        session_context_hash: Some("sch"),
    });
    assert_eq!(
        String::from_utf8(payload).unwrap(),
        "majik-signature-v1:{\"v\":1,\"id\":\"id\",\"ts\":\"2026-01-01T00:00:00.000Z\",\"ct\":null,\"hash\":\"hash\",\"alh\":\"alh\",\"vu\":\"vu\",\"vch\":\"vch\",\"sch\":\"sch\"}",
    );
}

#[test]
fn signs_and_verifies_session_context_and_digest_only() {
    let key = new_key("signroom-digest");
    let session_hash = build_session_context_hash(&context("session-verify", "challenge-verify")).unwrap();
    let signature = MajikSignature::sign(
        CONTENT,
        &key,
        Some(&SignOptions { session_context_hash: Some(session_hash.clone()), ..Default::default() }),
    )
    .unwrap();
    let keys = MajikSignature::public_keys_from_majik_key(&key).unwrap();

    let verified = MajikSignature::verify(CONTENT, &signature, &keys, None).unwrap();
    assert!(verified.valid, "{:?}", verified.reason);
    assert_eq!(verified.session_context_hash.as_deref(), Some(session_hash.as_str()));

    let digest =
        MajikSignature::verify_digest(signature.content_hash(), &signature, &keys, Some(&session_hash), None)
            .unwrap();
    assert!(digest.base.valid, "{:?}", digest.base.reason);
    assert!(digest.commitment_only);

    let missing_context =
        MajikSignature::verify_digest(signature.content_hash(), &signature, &keys, None, None).unwrap();
    assert!(!missing_context.base.valid);
    assert!(missing_context.base.reason.unwrap().contains("session context hash is required"));

    let other_context = build_session_context_hash(&context("session-other", "challenge-other")).unwrap();
    let mismatch = MajikSignature::verify_digest(
        signature.content_hash(),
        &signature,
        &keys,
        Some(&other_context),
        None,
    )
    .unwrap();
    assert!(!mismatch.base.valid);

    let wrong_digest = MajikSignature::verify_digest(
        &digest_text("different document"),
        &signature,
        &keys,
        Some(&session_hash),
        None,
    )
    .unwrap();
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
    let digest =
        MajikSignature::verify_digest(signature.content_hash(), &signature, &other_keys, None, None).unwrap();
    assert!(!digest.base.valid);
}

#[test]
fn session_context_round_trips_json_compact_and_cbor() {
    let key = new_key("signroom-serialization");
    let session_hash =
        build_session_context_hash(&context("session-serialization", "challenge-serialization")).unwrap();
    let signature = MajikSignature::sign(
        CONTENT,
        &key,
        Some(&SignOptions { session_context_hash: Some(session_hash.clone()), ..Default::default() }),
    )
    .unwrap();

    let json = signature.to_json();
    assert_eq!(MajikSignature::from_json(&json).unwrap().session_context_hash(), Some(session_hash.as_str()));

    let compact = signature.to_compact();
    assert_eq!(compact.session_context_hash.as_deref(), Some(session_hash.as_str()));
    let keys = signature.extract_public_keys().unwrap();
    let restored_compact =
        MajikSignature::from_compact(&compact, &keys.ed_public_key, &keys.ml_dsa_public_key).unwrap();
    assert_eq!(restored_compact.session_context_hash(), Some(session_hash.as_str()));
    assert!(
        MajikSignature::verify_digest(
            signature.content_hash(),
            &restored_compact,
            &keys,
            Some(&session_hash),
            None,
        )
        .unwrap()
        .base
        .valid
    );

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
    assert!(
        MajikSignature::verify_digest(
            signature.content_hash(),
            &signature,
            &signature.extract_public_keys().unwrap(),
            None,
            None
        )
        .unwrap()
        .base
        .valid
    );

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
    )
    .unwrap();
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
    )
    .unwrap();
    signature.add_tsa_with_trusted_keys(timestamp.clone(), Some(&tsa_keys)).unwrap();
    assert!(signature.verify_tsa_with_trusted_keys(Some(&tsa_keys)).unwrap().valid);
    assert!(signature.verify_tsa().unwrap().valid);

    // The TSA field is excluded from the signature-scope commitment, so attachment is stable.
    let restored = MajikSignature::from_cbor(&signature.to_cbor().unwrap()).unwrap();
    assert_eq!(restored.tsa().unwrap().payload.digest.scope, Some(TsaDigestScope::Signature),);
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

#[test]
fn session_file_api_round_trips_a_detached_mjksig_sidecar() {
    let key = new_key("signroom-file-single");
    let session_context = context("session-file-single", "challenge-file-single");
    let mut sign_options = SessionFileSignOptions::new(session_context.clone());
    sign_options.mime_type = Some("text/plain".into());
    sign_options.content_type = Some("text/plain".into());

    let signed = MajikSignature::sign_session_file(CONTENT, &key, &sign_options).unwrap();
    assert!(MajikSignatureEnvelope::is_mjksig(&signed.mjksig));
    assert_eq!(signed.blob.as_slice(), CONTENT);
    let restored = MajikSignatureEnvelope::from_mjksig(&signed.mjksig).unwrap();
    assert_eq!(restored.signatures().len(), 1);

    let keys = MajikSignature::public_keys_from_majik_key(&key).unwrap();
    let mut verify_options = SessionFileVerifyOptions::default();
    verify_options.expected_session_contexts.insert(key.fingerprint().to_string(), session_context);
    verify_options.expected_signer_public_keys.insert(key.fingerprint().to_string(), keys);

    let verified =
        MajikSignature::verify_session_file(&signed.blob, signed.mjksig.as_slice(), &verify_options).unwrap();
    assert!(verified.valid, "{:?}", verified.reason);
    assert_eq!(verified.results.len(), 1);
    assert!(verified.results[0].valid);
    assert_eq!(verified.tsa_results.len(), 1);
    assert!(!verified.tsa_results[0].present);

    verify_options.require_tsa = true;
    let without_required_tsa =
        MajikSignature::verify_session_file(&signed.blob, signed.mjksig.as_slice(), &verify_options).unwrap();
    assert!(!without_required_tsa.valid);
    assert!(!without_required_tsa.tsa_results[0].valid);
}

#[test]
fn session_file_api_verifies_individual_challenges_and_visual_stamp_revisions() {
    let issuer = new_key("signroom-file-issuer");
    let participant = new_key("signroom-file-participant");
    let issuer_context = context("session-file-multi", "challenge-file-issuer");
    let participant_context = context("session-file-multi", "challenge-file-participant");

    let mut issuer_options = SessionFileSignOptions::new(issuer_context.clone());
    issuer_options.mime_type = Some("text/plain".into());
    issuer_options.content_type = Some("text/plain".into());
    issuer_options.expected_signers = Some(vec![
        MajikSignature::expected_signer_from_key(&issuer).unwrap(),
        MajikSignature::expected_signer_from_key(&participant).unwrap(),
    ]);
    let issuer_signed = MajikSignature::sign_session_file(CONTENT, &issuer, &issuer_options).unwrap();
    assert_eq!(issuer_signed.envelope.file_versions().len(), 1);

    // Simulate the next participant adding a visual stamp, changing the document bytes.
    let mut stamped_content = CONTENT.to_vec();
    stamped_content.extend_from_slice(b"\nvisual stamp");
    let mut participant_options = SessionFileSignOptions::new(participant_context.clone());
    participant_options.mime_type = Some("text/plain".into());
    participant_options.content_type = Some("text/plain".into());
    participant_options.existing_envelope = Some(EnvelopeInput::Envelope(issuer_signed.envelope.clone()));
    participant_options.prior_file = Some(issuer_signed.blob.clone());
    participant_options.message = Some("Participant added a visual stamp".into());
    let participant_signed =
        MajikSignature::sign_session_file(&stamped_content, &participant, &participant_options).unwrap();

    assert_eq!(participant_signed.envelope.file_versions().len(), 2);
    assert!(participant_signed.signature.version_chain_hash().is_some());

    let issuer_keys = MajikSignature::public_keys_from_majik_key(&issuer).unwrap();
    let participant_keys = MajikSignature::public_keys_from_majik_key(&participant).unwrap();
    let mut verify_options = SessionFileVerifyOptions::default();
    verify_options.expected_session_contexts.insert(issuer.fingerprint().to_string(), issuer_context.clone());
    verify_options
        .expected_session_contexts
        .insert(participant.fingerprint().to_string(), participant_context.clone());
    verify_options.expected_signer_public_keys.insert(issuer.fingerprint().to_string(), issuer_keys);
    verify_options
        .expected_signer_public_keys
        .insert(participant.fingerprint().to_string(), participant_keys);

    let verified = MajikSignature::verify_session_file(
        &participant_signed.blob,
        participant_signed.mjksig.as_slice(),
        &verify_options,
    )
    .unwrap();
    assert!(verified.valid, "{:?}", verified.reason);
    assert_eq!(verified.results.len(), 2);
    assert!(verified.results.iter().all(|result| result.valid));
    assert!(verified.chain.as_ref().is_some_and(|chain| chain.chain_valid));

    // Reusing the issuer's one-time challenge for the participant must fail closed.
    verify_options.expected_session_contexts.insert(
        participant.fingerprint().to_string(),
        MajikSessionSigningContext {
            challenge_id: issuer_context.challenge_id.clone(),
            ..participant_context.clone()
        },
    );
    let reused_challenge = MajikSignature::verify_session_file(
        &participant_signed.blob,
        participant_signed.mjksig.as_slice(),
        &verify_options,
    )
    .unwrap();
    assert!(!reused_challenge.valid);
    assert!(reused_challenge.reason.unwrap().contains("distinct one-time challenge"));

    // Missing authoritative context is reported against that participant.
    verify_options.expected_session_contexts.remove(&participant.fingerprint().to_string());
    let missing_context = MajikSignature::verify_session_file(
        &participant_signed.blob,
        participant_signed.mjksig.as_slice(),
        &verify_options,
    )
    .unwrap();
    assert!(!missing_context.valid);
    assert!(missing_context.results.iter().any(|result| {
        result.signer_id.as_deref() == Some(participant.fingerprint())
            && result.reason.as_deref().unwrap_or_default().contains("No authoritative session context")
    }));
}

#[test]
fn session_file_api_verifies_signature_scoped_tsa_with_a_pinned_identity() {
    let signer = new_key("signroom-file-tsa-signer");
    let tsa_key = new_key("signroom-file-tsa-authority");
    let session_context = context("session-file-tsa", "challenge-file-tsa");

    let mut sign_options = SessionFileSignOptions::new(session_context.clone());
    sign_options.mime_type = Some("text/plain".into());
    sign_options.content_type = Some("text/plain".into());
    let mut signed = MajikSignature::sign_session_file(CONTENT, &signer, &sign_options).unwrap();

    let tsa_keys = MajikSignature::public_keys_from_majik_key(&tsa_key).unwrap();
    let request = signed.signature.build_tsa_request_payload_with_scope(Some(TsaDigestScope::Signature));
    let timestamp = MajikSignature::sign_tsa(
        &request,
        &tsa_key,
        MajikTsaIdentity {
            id: "tsa.majikah.solutions".into(),
            signer_fingerprint: tsa_keys.signer_id.clone(),
        },
        None,
    )
    .unwrap();
    signed.signature.add_tsa_with_trusted_keys(timestamp, Some(&tsa_keys)).unwrap();

    let timestamped_envelope = signed.envelope.with_signature(signed.signature.to_json()).unwrap();
    let sidecar = timestamped_envelope.to_mjksig().unwrap();

    let signer_keys = MajikSignature::public_keys_from_majik_key(&signer).unwrap();
    let mut verify_options = SessionFileVerifyOptions::default();
    verify_options.expected_session_contexts.insert(signer.fingerprint().to_string(), session_context);
    verify_options.expected_signer_public_keys.insert(signer.fingerprint().to_string(), signer_keys);
    verify_options.trusted_tsa_public_keys = Some(tsa_keys);
    verify_options.require_tsa = true;
    verify_options.require_trusted_tsa = true;

    let verified =
        MajikSignature::verify_session_file(&signed.blob, sidecar.as_slice(), &verify_options).unwrap();
    assert!(verified.valid, "{:?}", verified.reason);
    assert_eq!(verified.tsa_results.len(), 1);
    assert!(verified.tsa_results[0].present);
    assert!(verified.tsa_results[0].valid);
    assert!(verified.tsa_results[0].trusted);
}
