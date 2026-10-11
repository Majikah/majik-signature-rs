//! Files produced by the TypeScript library (`@majikah/majik-signature` 0.10.0) must verify here.

use base64::Engine as _;
use majik_signature::*;

fn load() -> serde_json::Value {
    serde_json::from_str(include_str!("fixtures/ts_files.json")).unwrap()
}
fn bytes(v: &serde_json::Value, k: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD.decode(v[k].as_str().unwrap()).unwrap()
}
fn keys(v: &serde_json::Value, who: &str) -> MajikSignerPublicKeys {
    let k = &v["keys"][who];
    MajikSignerPublicKeys {
        signer_id: k["signerId"].as_str().unwrap().into(),
        ed_public_key: base64_to_bytes(k["edPublicKey"].as_str().unwrap()).unwrap(),
        ml_dsa_public_key: base64_to_bytes(k["mlDsaPublicKey"].as_str().unwrap()).unwrap(),
    }
}

#[test]
fn sealed_three_signer_text_file() {
    let v = load();
    let file = bytes(&v, "text");
    let mime = Some("text/plain");
    for who in ["a", "b", "c"] {
        let pk = keys(&v, who);
        let r = MajikSignature::verify_file(
            &file,
            &pk,
            Some(&VerifyFileOptions {
                mime_type: mime.map(String::from),
                expected_signer_id: Some(pk.signer_id.clone()),
                ..Default::default()
            }),
        )
        .unwrap();
        assert!(r[0].valid, "signer {who}: {:?}", r[0].reason);
    }
    // Seal hash is sorted with localeCompare in TS — must match byte-for-byte here.
    let seal = MajikSignature::verify_seal(&file, mime).unwrap();
    assert!(seal.valid, "{:?}", seal.reason);
    assert!(MajikSignature::is_multi_sig(&file, mime).unwrap());
    assert_eq!(MajikSignature::get_all_signatories(&file, mime).unwrap().unwrap().signed.len(), 3);
    // Allowlist hash too (verified as part of verify_file → verify_allowlist_integrity).
}

#[test]
fn docx_zip_roundtrips_byte_exact() {
    let v = load();
    let file = bytes(&v, "docx");
    let pk = keys(&v, "a");
    let mime = "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
    let r = MajikSignature::verify_file(
        &file,
        &pk,
        Some(&VerifyFileOptions { mime_type: Some(mime.into()), ..Default::default() }),
    )
    .unwrap();
    assert!(r[0].valid, "{:?}", r[0].reason);
}

#[test]
fn png_signed_by_typescript() {
    let v = load();
    let file = bytes(&v, "png");
    let r = MajikSignature::verify_file(&file, &keys(&v, "a"), None).unwrap();
    assert!(r[0].valid, "{:?}", r[0].reason);
}
