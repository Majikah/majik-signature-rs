mod common;

use common::new_key;
use majik_signature::*;

fn sample_png() -> Vec<u8> {
    // Minimal valid PNG: signature + IHDR + IDAT + IEND (CRCs are not checked by the handler).
    let mut v = vec![0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
    for (kind, data) in [("IHDR", vec![0u8; 13]), ("IDAT", vec![1, 2, 3]), ("IEND", vec![])] {
        v.extend_from_slice(&(data.len() as u32).to_be_bytes());
        v.extend_from_slice(kind.as_bytes());
        v.extend_from_slice(&data);
        v.extend_from_slice(&[0, 0, 0, 0]);
    }
    v
}

fn samples() -> Vec<(&'static str, Vec<u8>, Option<&'static str>)> {
    let mut pdf = b"%PDF-1.4\n1 0 obj<<>>endobj\n%%EOF\n".to_vec();
    pdf.extend_from_slice(&[0u8; 8]);
    let mut jpeg = vec![0xff, 0xd8, 0xff, 0xe0, 0x00, 0x04, 0x00, 0x00];
    jpeg.extend_from_slice(&[0xff, 0xd9]);
    let mut wav = b"RIFF".to_vec();
    wav.extend_from_slice(&(4u32 + 8 + 4).to_le_bytes());
    wav.extend_from_slice(b"WAVE");
    wav.extend_from_slice(b"data");
    wav.extend_from_slice(&4u32.to_le_bytes());
    wav.extend_from_slice(&[1, 2, 3, 4]);
    let mut flac = b"fLaC".to_vec();
    flac.extend_from_slice(&[0x80, 0, 0, 34]);
    flac.extend_from_slice(&[0u8; 34]);
    flac.extend_from_slice(&[0xff, 0xf8, 1, 2, 3]);
    // ID3v2.3 tag holding one TIT2 frame (an *empty* tag is not restorable by strip — same as TS).
    let mut mp3 = b"ID3".to_vec();
    mp3.extend_from_slice(&[3, 0, 0, 0, 0, 0, 13]);
    mp3.extend_from_slice(b"TIT2");
    mp3.extend_from_slice(&3u32.to_be_bytes());
    mp3.extend_from_slice(&[0, 0, 0, b'h', b'i']);
    mp3.extend_from_slice(&[0xff, 0xfb, 0x90, 0x00, 1, 2, 3]);
    let mut mp4 = vec![0, 0, 0, 16];
    mp4.extend_from_slice(b"ftypisom\0\0\0\0");
    let moov_child = [&8u32.to_be_bytes()[..], b"free"].concat();
    mp4.extend_from_slice(&((8 + moov_child.len()) as u32).to_be_bytes());
    mp4.extend_from_slice(b"moov");
    mp4.extend_from_slice(&moov_child);
    vec![
        ("png", sample_png(), None),
        ("pdf", pdf, None),
        ("jpeg", jpeg, None),
        ("wav", wav, None),
        ("flac", flac, None),
        ("mp3", mp3, None),
        ("mp4", mp4, None),
        ("text", b"just some text\nline two\n".to_vec(), Some("text/plain")),
        ("unknown-binary", vec![0, 159, 146, 150, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10], None),
    ]
}

#[test]
fn sign_embed_verify_strip_roundtrip_every_format() {
    let key = new_key("fmt");
    let pk = MajikSignature::public_keys_from_majik_key(&key).unwrap();
    for (name, file, mime) in samples() {
        let opts = SignAndEmbedOptions {
            embed: EmbedOptions { mime_type: mime.map(String::from), force_fallback: false },
            ..Default::default()
        };
        let signed = MajikSignature::sign_file(&file, &key, Some(&opts)).unwrap();
        assert_ne!(signed.blob, file, "{name}: blob unchanged");
        assert!(MajikSignature::is_signed(&signed.blob, mime).unwrap(), "{name}: not detected as signed");

        let vopts = VerifyFileOptions { mime_type: mime.map(String::from), ..Default::default() };
        let res = MajikSignature::verify_file(&signed.blob, &pk, Some(&vopts)).unwrap();
        assert_eq!(res.len(), 1, "{name}");
        assert!(res[0].valid, "{name}: {:?}", res[0].reason);

        let stripped = MajikSignature::strip_from(&signed.blob, mime).unwrap();
        assert_eq!(stripped, file, "{name}: strip did not restore original");

        // Tamper: flip a byte inside the signed content region → must not verify.
        let mut bad = signed.blob.clone();
        bad[4] ^= 0x01;
        let r = MajikSignature::verify_file(&bad, &pk, Some(&vopts)).unwrap();
        assert!(!r[0].valid, "{name}: tampered file verified");
    }
}

#[test]
fn restricted_multisig_seal_and_order() {
    let alice = new_key("alice");
    let bob = new_key("bob");
    let mallory = new_key("mallory");
    let file = b"contract text".to_vec();
    let mime = Some("text/plain");
    let eo = EmbedOptions { mime_type: mime.map(String::from), force_fallback: false };

    let signers = vec![
        MajikSignature::expected_signer_from_key(&alice).unwrap(),
        MajikSignature::expected_signer_from_key(&bob).unwrap(),
    ];
    let a = MajikSignature::sign_file(
        &file,
        &alice,
        Some(&SignAndEmbedOptions {
            embed: eo.clone(),
            expected_signers: Some(signers),
            ..Default::default()
        }),
    )
    .unwrap();
    assert!(MajikSignature::is_multi_sig(&a.blob, mime).unwrap());
    let pending = MajikSignature::get_pending_signatories(&a.blob, mime).unwrap().unwrap();
    assert_eq!(pending.pending.len(), 1);

    // Mallory is not on the allowlist
    let denied = MajikSignature::sign_file(
        &a.blob,
        &mallory,
        Some(&SignAndEmbedOptions { embed: eo.clone(), ..Default::default() }),
    );
    assert!(matches!(denied, Err(MajikSignatureError::Allowlist { .. })));

    let b = MajikSignature::sign_file(
        &a.blob,
        &bob,
        Some(&SignAndEmbedOptions { embed: eo.clone(), ..Default::default() }),
    )
    .unwrap();
    let all = MajikSignature::get_all_signatories(&b.blob, mime).unwrap().unwrap();
    assert_eq!(all.signed.len(), 2);

    // Order alice → bob holds.
    let ord = MajikSignature::verify_file_order(
        &b.blob,
        &[OrderEntry::Key(&alice), OrderEntry::Key(&bob)],
        Some(&OrderOptions { mime_type: mime.map(String::from), strict: true }),
    )
    .unwrap();
    assert!(ord.all_valid && ord.all_expected_signed, "{:?}", ord.reason);

    // Only the issuer may seal.
    assert!(MajikSignature::seal(&b.blob, &bob, mime, None).is_err());
    let sealed = MajikSignature::seal(&b.blob, &alice, mime, None).unwrap();
    assert!(MajikSignature::verify_seal(&sealed.blob, mime).unwrap().valid);
    assert!(MajikSignature::is_sealed(&sealed.blob, mime).unwrap());
    assert!(MajikSignature::sign_file(
        &sealed.blob,
        &bob,
        Some(&SignAndEmbedOptions { embed: eo, ..Default::default() })
    )
    .is_err());
    assert!(MajikSignature::can_anchor(&sealed.blob, mime).unwrap().permitted);

    // Full verification of the sealed file passes for every signer.
    let pk_a = MajikSignature::public_keys_from_majik_key(&alice).unwrap();
    let r = MajikSignature::verify_file(
        &sealed.blob,
        &pk_a,
        Some(&VerifyFileOptions {
            mime_type: mime.map(String::from),
            expected_signer_id: Some(alice.fingerprint().into()),
            ..Default::default()
        }),
    )
    .unwrap();
    assert!(r[0].valid);
}

#[test]
fn detached_and_mjksmap_batch() {
    let key = new_key("batch");
    let pk = MajikSignature::public_keys_from_majik_key(&key).unwrap();
    let files = vec![
        BatchFileInput {
            path: "docs/a.txt".into(),
            blob: b"alpha".to_vec(),
            mime_type: Some("text/plain".into()),
        },
        BatchFileInput { path: "docs\\b.bin".into(), blob: vec![9, 8, 7, 6], mime_type: None },
    ];
    let BatchSignResult::Map { map_blob, failures, .. } =
        MajikSignature::sign_batch_detached(&files, &key, None).unwrap()
    else {
        panic!("expected map")
    };
    assert!(failures.is_empty());
    assert!(MajikSignatureMap::is_mjksmap(&map_blob));
    let loaded = MajikSignatureMap::from_mjksmap(&map_blob).unwrap();
    assert_eq!(loaded.size(), 2);

    let inputs = vec![
        BatchVerifyInput { path: "docs/a.txt".into(), blob: b"alpha".to_vec() },
        BatchVerifyInput { path: "docs/b.bin".into(), blob: vec![9, 8, 7, 6] },
        BatchVerifyInput { path: "other/c".into(), blob: b"nope".to_vec() },
        BatchVerifyInput { path: "docs/a.txt".into(), blob: b"ALPHA".to_vec() },
    ];
    let res = MajikSignature::verify_files_from_mjksmap(&loaded, &inputs, &pk, None).unwrap();
    assert_eq!(res[0].status, FileVerifyStatus::Verified);
    assert_eq!(res[1].status, FileVerifyStatus::Verified);
    assert_eq!(res[2].status, FileVerifyStatus::NotInMap);
    assert_eq!(res[3].status, FileVerifyStatus::Tampered);
    let sum = MajikSignature::summarize_batch_verification(&res);
    assert!(!sum.all_valid && sum.verified == 2 && sum.tampered == 1 && sum.not_in_map == 1);

    // Detached single file + .mjksig round trip
    let d = MajikSignature::sign_file_detached(b"detached body", &key, None).unwrap();
    let mjksig = d.envelope.to_mjksig();
    assert!(MajikSignatureEnvelope::is_mjksig(&mjksig));
    let r = MajikSignature::verify_file_detached(&d.blob, mjksig, &pk, None).unwrap();
    assert!(r[0].valid, "{:?}", r[0].reason);
}

#[test]
fn version_chain_across_resigns() {
    let alice = new_key("alice");
    let bob = new_key("bob");
    let v1 = b"version one".to_vec();
    let mime = Some("text/plain");
    let eo = EmbedOptions { mime_type: mime.map(String::from), force_fallback: false };
    let s1 = MajikSignature::sign_file(
        &v1,
        &alice,
        Some(&SignAndEmbedOptions { embed: eo.clone(), message: Some("first".into()), ..Default::default() }),
    )
    .unwrap();

    let v2 = b"version two (edited)".to_vec();
    let s2 = MajikSignature::sign_file(
        &v2,
        &bob,
        Some(&SignAndEmbedOptions {
            embed: eo,
            prior_signed_file: Some(s1.blob.clone()),
            ..Default::default()
        }),
    )
    .unwrap();
    assert_eq!(s2.envelope.file_versions().len(), 2);
    let chain = MajikSignature::verify_file_chain(&s2.blob, mime, None).unwrap();
    assert!(chain.chain_valid, "{:?}", chain);

    let revs = MajikSignature::verify_file_revisions(
        &s2.blob,
        &[s1.blob.as_slice()],
        Some(&VerifyRevisionsOptions { mime_type: mime.map(String::from), ..Default::default() }),
    )
    .unwrap();
    assert!(revs.all_valid && revs.is_complete_set, "{:?}", revs);
}

/// Emits Rust-produced files for the TypeScript verifier (interop/verify_rust_files.mjs).
#[test]
fn emit_rust_files_for_typescript() {
    use base64::Engine as _;
    let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
    let a = new_key("a");
    let b = new_key("b");
    let mime = Some("text/plain");
    let eo = EmbedOptions { mime_type: mime.map(String::from), force_fallback: false };
    let signers = vec![
        MajikSignature::expected_signer_from_key(&a).unwrap(),
        MajikSignature::expected_signer_from_key(&b).unwrap(),
    ];
    let s1 = MajikSignature::sign_file(
        b"rust text",
        &a,
        Some(&SignAndEmbedOptions {
            embed: eo.clone(),
            expected_signers: Some(signers),
            ..Default::default()
        }),
    )
    .unwrap();
    let s2 = MajikSignature::sign_file(
        &s1.blob,
        &b,
        Some(&SignAndEmbedOptions { embed: eo, ..Default::default() }),
    )
    .unwrap();
    let sealed = MajikSignature::seal(&s2.blob, &a, mime, None).unwrap();

    let docx_src = {
        let mut z = majik_signature::core::embed::zipio::ZipEntries::new();
        z.set("[Content_Types].xml".into(), b"<x/>".to_vec());
        z.set("word/document.xml".into(), b"<doc>hi</doc>".to_vec());
        majik_signature::core::embed::zipio::zip_stored(&z).unwrap()
    };
    let dm = "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
    let d = MajikSignature::sign_file(
        &docx_src,
        &a,
        Some(&SignAndEmbedOptions {
            embed: EmbedOptions { mime_type: Some(dm.into()), force_fallback: false },
            ..Default::default()
        }),
    )
    .unwrap();
    let pk = |k: &majik_key::MajikKey| {
        let p = MajikSignature::public_keys_from_majik_key(k).unwrap();
        serde_json::json!({"signerId": p.signer_id, "edPublicKey": b64(&p.ed_public_key), "mlDsaPublicKey": b64(&p.ml_dsa_public_key)})
    };
    let out = serde_json::json!({"text": b64(&sealed.blob), "docx": b64(&d.blob), "keys": {"a": pk(&a), "b": pk(&b)}});
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("target");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("rust_files.json"), out.to_string()).unwrap();
}
