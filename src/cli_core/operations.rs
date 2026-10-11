//! Port of `cli-core/operations.ts` — the `sign`, `verify`, `seal`, `can-sign` and `inspect`
//! command implementations. Every function returns a [`CliResult`] (or an error for usage /
//! I/O failures), exactly like the TS `run*` functions.

use std::collections::HashSet;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use majik_key::MajikKey;
use serde::Serialize;
use serde_json::{json, Map, Value};

use crate::cli_core::io::*;
use crate::cli_core::key::{load_majik_key, load_signing_key, lock_key};
use crate::cli_core::types::*;
use crate::core::embed::majik_embed::{
    OrderOptions, SignAndEmbedOptions, SignDetachedOptions, VerifyFileOptions,
};
use crate::core::envelope::MajikSignatureEnvelope;
use crate::core::mjksmap::MajikSignatureMap;
use crate::core::order::OrderEntry;
use crate::core::types::*;
use crate::majik_signature::{KeyOrPublicKeys, MajikSignature};

fn result(command: &str, data: Value, ok: bool, message: &str) -> CliResult {
    let data = match data {
        Value::Object(m) => m,
        _ => Map::new(),
    };
    CliResult { ok, command: command.to_string(), message: message.to_string(), data }
}

fn to_value<T: Serialize>(v: &T) -> Value {
    serde_json::to_value(v).unwrap_or(Value::Null)
}

fn expected_signer_from_signature(sig: &MajikSignature) -> CliOutcome<ExpectedSigner> {
    let pk = sig.extract_public_keys()?;
    Ok(ExpectedSigner {
        signer_id: pk.signer_id,
        ed_public_key: crate::core::hash::bytes_to_base64(&pk.ed_public_key),
        ml_dsa_public_key: crate::core::hash::bytes_to_base64(&pk.ml_dsa_public_key),
    })
}

fn expected_signer_from_json(sig: &MajikSignatureJSON) -> CliOutcome<ExpectedSigner> {
    expected_signer_from_signature(&MajikSignature::from_json(sig)?)
}

fn dedupe_expected_signers(signers: Vec<ExpectedSigner>) -> Vec<ExpectedSigner> {
    let mut out: Vec<ExpectedSigner> = Vec::new();
    for s in signers {
        match out.iter().position(|x| x.signer_id == s.signer_id) {
            Some(i) => out[i] = s,
            None => out.push(s),
        }
    }
    out
}

fn build_expected_signers(signing_key: &MajikKey, additional: &[String]) -> CliOutcome<Vec<ExpectedSigner>> {
    let mut signers = vec![MajikSignature::expected_signer_from_key(signing_key)?];
    for path in additional {
        let key = load_majik_key(path)?;
        if !key.has_keys(&[majik_key::KeyId::Ed25519, majik_key::KeyId::MlDsa87]) {
            return Err(err(format!("Allowlist key \"{path}\" does not contain signing public keys.")));
        }
        signers.push(MajikSignature::expected_signer_from_key(&key)?);
    }
    Ok(dedupe_expected_signers(signers))
}

fn load_tsa_token(path: Option<&str>) -> CliOutcome<Option<MajikTimestamp>> {
    let Some(path) = path else { return Ok(None) };
    let p = resolve_cli_path(path);
    let token: MajikTimestamp =
        read_json_file(&p).map_err(|_| err(format!("TSA token \"{path}\" must contain a JSON object.")))?;
    Ok(Some(token))
}

fn assert_kind(kind: PathKind, expected: PathKind) -> CliOutcome<()> {
    if kind != expected {
        return Err(err(format!(
            "This operation requires a {}, but the supplied input is a {}.",
            expected.name(),
            kind.name()
        )));
    }
    Ok(())
}

fn assert_not_inside_input(input_dir: &Path, output_dir: &Path) -> CliOutcome<()> {
    let input = std::fs::canonicalize(input_dir).unwrap_or_else(|_| input_dir.to_path_buf());
    let output = if output_dir.exists() {
        std::fs::canonicalize(output_dir).unwrap_or_else(|_| output_dir.to_path_buf())
    } else {
        output_dir.to_path_buf()
    };
    if let Ok(rel) = output.strip_prefix(&input) {
        if !rel.as_os_str().is_empty() {
            return Err(err(format!(
                "Output directory \"{}\" cannot be inside input directory \"{}\".",
                output.display(),
                input.display()
            )));
        }
    }
    Ok(())
}

fn write_map_bundle(
    files: &[FolderFile],
    map_path: &Path,
    map_bytes: &[u8],
    output: &Path,
    overwrite: bool,
) -> CliOutcome<()> {
    if !overwrite && output.exists() {
        return Err(err(format!(
            "Output already exists: \"{}\". Use --overwrite to replace it.",
            output.display()
        )));
    }
    let mut cursor = std::io::Cursor::new(Vec::new());
    {
        let mut zip = zip::ZipWriter::new(&mut cursor);
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated)
            .compression_level(Some(6));
        for f in files {
            zip.start_file(f.relative_path.as_str(), opts).map_err(|e| err(e.to_string()))?;
            zip.write_all(&f.bytes)?;
        }
        let name = map_path.file_name().and_then(|n| n.to_str()).unwrap_or("signatures.mjksmap");
        zip.start_file(name, opts).map_err(|e| err(e.to_string()))?;
        zip.write_all(map_bytes)?;
        zip.finish().map_err(|e| err(e.to_string()))?;
    }
    write_bytes(output, &cursor.into_inner(), overwrite)
}

fn seal_info_value(env: &MajikSignatureEnvelope) -> Value {
    json!({ "sealHash": env.seal_hash(), "sealTimestamp": env.seal_timestamp(), "sealedBy": env.sealed_by() })
}

fn path_s(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

fn failures_value(f: &[(String, String)]) -> Value {
    Value::Array(f.iter().map(|(p, e)| json!({"path": p, "error": e})).collect())
}

// ── sign ─────────────────────────────────────────────────────────────────────

fn embed_opts(mime: &str) -> crate::core::types::EmbedOptions {
    crate::core::types::EmbedOptions { mime_type: Some(mime.to_string()), force_fallback: false }
}

fn sign_single_embedded(
    input: &Path,
    o: &SignCliOptions,
    key: &MajikKey,
    signers: Option<Vec<ExpectedSigner>>,
) -> CliOutcome<CliResult> {
    let source = read_bytes(input)?;
    let mime = mime_type_for_path(input);
    let signed = MajikSignature::sign_file(
        &source,
        key,
        Some(&SignAndEmbedOptions {
            embed: embed_opts(&mime),
            content_type: o.content_type.clone(),
            timestamp: o.timestamp.clone(),
            expected_signers: signers,
            valid_until: o.valid_until.clone(),
            ..Default::default()
        }),
    )?;
    let mut out = signed.blob;
    let mut seal_info = None;
    if o.seal {
        let s = MajikSignature::seal(&out, key, Some(&signed.mime_type), o.timestamp.as_deref())?;
        out = s.blob;
        seal_info = Some(s.seal_info);
    }
    let output_path = o.output.as_deref().map(resolve_cli_path).unwrap_or_else(|| input.to_path_buf());
    write_bytes(&output_path, &out, o.overwrite || output_path == input)?;
    let sigs = MajikSignature::extract_from(&out, Some(&signed.mime_type))?;
    Ok(result(
        "sign",
        json!({
            "mode": "embedded", "input": path_s(input), "output": path_s(&output_path),
            "signerId": key.fingerprint(), "algorithm": "Ed25519 + ML-DSA-87",
            "sha256": sigs.first().map(|s| s.content_hash().to_string()),
            "sealed": o.seal, "seal": seal_info.as_ref().map(to_value),
        }),
        true,
        "Embedded signature created successfully.",
    ))
}

fn sign_single_detached(
    input: &Path,
    o: &SignCliOptions,
    key: &MajikKey,
    signers: Option<Vec<ExpectedSigner>>,
    tsa: Option<MajikTimestamp>,
) -> CliOutcome<CliResult> {
    let source = read_bytes(input)?;
    let mime = mime_type_for_path(input);
    let signed = MajikSignature::sign_file_detached(
        &source,
        key,
        Some(&SignDetachedOptions {
            embed: embed_opts(&mime),
            content_type: o.content_type.clone(),
            timestamp: o.timestamp.clone(),
            valid_until: o.valid_until.clone(),
            expected_signers: signers,
            tsa: tsa.clone(),
            ..Default::default()
        }),
    )?;
    let mut envelope = signed.envelope;
    if o.seal {
        envelope = envelope.with_seal(key.fingerprint(), o.timestamp.as_deref())?;
    }
    let output_path =
        o.output.as_deref().map(resolve_cli_path).unwrap_or_else(|| output_path_for_detached_file(input));
    write_bytes(&output_path, &envelope.to_mjksig(), o.overwrite)?;
    Ok(result(
        "sign",
        json!({
            "mode": "detached", "input": path_s(input), "output": path_s(&output_path),
            "signerId": key.fingerprint(), "algorithm": "Ed25519 + ML-DSA-87",
            "sha256": envelope.signatures().first().map(|s| s.content_hash.clone()),
            "sealed": envelope.is_sealed(), "seal": envelope.is_sealed().then(|| seal_info_value(&envelope)),
            "tsa": tsa.is_some(),
        }),
        true,
        "Detached signature created successfully.",
    ))
}

fn sign_folder_embedded(
    input_dir: &Path,
    o: &SignCliOptions,
    key: &MajikKey,
    signers: Option<Vec<ExpectedSigner>>,
) -> CliOutcome<CliResult> {
    let files = read_folder_files(input_dir)?;
    if files.is_empty() {
        return Ok(result(
            "sign",
            json!({"mode": "embedded", "input": path_s(input_dir), "output": o.output.clone().unwrap_or_else(|| path_s(input_dir)), "signerId": key.fingerprint(), "files": 0}),
            true,
            "No signable files were found in the folder.",
        ));
    }
    let output_dir = o.output.as_deref().map(resolve_cli_path).unwrap_or_else(|| input_dir.to_path_buf());
    if output_dir != input_dir {
        assert_not_inside_input(input_dir, &output_dir)?;
    }
    let mut failures: Vec<(String, String)> = Vec::new();
    for (i, file) in files.iter().enumerate() {
        eprintln!("[{}/{}] Signing {}", i + 1, files.len(), file.relative_path);
        let attempt = (|| -> CliOutcome<()> {
            let signed = MajikSignature::sign_file(
                &file.bytes,
                key,
                Some(&SignAndEmbedOptions {
                    embed: embed_opts(&file.mime_type),
                    content_type: o.content_type.clone(),
                    timestamp: o.timestamp.clone(),
                    expected_signers: signers.clone(),
                    valid_until: o.valid_until.clone(),
                    ..Default::default()
                }),
            )?;
            let mut out = signed.blob;
            if o.seal {
                out = MajikSignature::seal(&out, key, Some(&file.mime_type), o.timestamp.as_deref())?.blob;
            }
            let out_path = file.relative_path.split('/').fold(output_dir.clone(), |p, s| p.join(s));
            write_bytes(&out_path, &out, o.overwrite || output_dir == input_dir)
        })();
        if let Err(e) = attempt {
            eprintln!("    ✘ {e}");
            failures.push((file.relative_path.clone(), e.to_string()));
            if !o.continue_on_error {
                return Err(err(format!("Signing stopped at \"{}\": {e}", file.relative_path)));
            }
        }
    }
    let (count, bytes) = summarize_files(&files);
    Ok(result(
        "sign",
        json!({"mode": "embedded", "input": path_s(input_dir), "output": path_s(&output_dir), "signerId": key.fingerprint(),
               "algorithm": "Ed25519 + ML-DSA-87", "files": count, "bytes": bytes, "failures": failures_value(&failures), "sealed": o.seal}),
        failures.is_empty(),
        if failures.is_empty() {
            "Folder signing completed successfully."
        } else {
            "Folder signing completed with failures."
        },
    ))
}

fn sign_folder_detached(
    input_dir: &Path,
    o: &SignCliOptions,
    key: &MajikKey,
    signers: Option<Vec<ExpectedSigner>>,
    tsa: Option<MajikTimestamp>,
) -> CliOutcome<CliResult> {
    let files = read_folder_files(input_dir)?;
    let output_dir = o.output.as_deref().map(resolve_cli_path).unwrap_or_else(|| input_dir.to_path_buf());
    if output_dir != input_dir {
        assert_not_inside_input(input_dir, &output_dir)?;
    }
    let mut failures: Vec<(String, String)> = Vec::new();
    for (i, file) in files.iter().enumerate() {
        eprintln!("[{}/{}] Signing {}", i + 1, files.len(), file.relative_path);
        let attempt = (|| -> CliOutcome<()> {
            let signed = MajikSignature::sign_file_detached(
                &file.bytes,
                key,
                Some(&SignDetachedOptions {
                    embed: embed_opts(&file.mime_type),
                    content_type: o.content_type.clone(),
                    timestamp: o.timestamp.clone(),
                    valid_until: o.valid_until.clone(),
                    expected_signers: signers.clone(),
                    tsa: tsa.clone(),
                    ..Default::default()
                }),
            )?;
            let mut envelope = signed.envelope;
            if o.seal {
                envelope = envelope.with_seal(key.fingerprint(), o.timestamp.as_deref())?;
            }
            let out_path = output_dir.join(format!("{}.mjksig", file.relative_path));
            write_bytes(&out_path, &envelope.to_mjksig(), o.overwrite)
        })();
        if let Err(e) = attempt {
            eprintln!("    ✘ {e}");
            failures.push((file.relative_path.clone(), e.to_string()));
            if !o.continue_on_error {
                return Err(err(format!("Signing stopped at \"{}\": {e}", file.relative_path)));
            }
        }
    }
    Ok(result(
        "sign",
        json!({"mode": "detached", "input": path_s(input_dir), "output": path_s(&output_dir), "signerId": key.fingerprint(),
               "algorithm": "Ed25519 + ML-DSA-87", "files": files.len(), "failures": failures_value(&failures), "sealed": o.seal, "tsa": tsa.is_some()}),
        failures.is_empty(),
        if failures.is_empty() {
            "Detached folder signing completed successfully."
        } else {
            "Detached folder signing completed with failures."
        },
    ))
}

fn sign_folder_map(
    input_dir: &Path,
    o: &SignCliOptions,
    key: &MajikKey,
    signers: Option<Vec<ExpectedSigner>>,
) -> CliOutcome<CliResult> {
    if o.tsa_token_path.is_some() {
        return Err(err("--tsa-token is not supported with --map yet. The current batch signing SDK does not accept a per-signature TSA token."));
    }
    let files = read_folder_files(input_dir)?;
    let inputs: Vec<BatchFileInput> = files
        .iter()
        .map(|f| BatchFileInput {
            path: f.relative_path.clone(),
            blob: f.bytes.clone(),
            mime_type: Some(f.mime_type.clone()),
        })
        .collect();
    let batch = MajikSignature::sign_batch_detached(
        &inputs,
        key,
        Some(&BatchSignOptions {
            content_type: o.content_type.clone(),
            timestamp: o.timestamp.clone(),
            expected_signers: signers,
            valid_until: o.valid_until.clone(),
            mode: Some(BatchSignMode::Map),
            continue_on_error: o.continue_on_error,
        }),
    )?;
    let BatchSignResult::Map { mut map, failures, .. } = batch else {
        return Err(err("Unexpected SDK batch result: expected map mode."));
    };
    if o.seal {
        for entry in map.entries().to_vec() {
            let sealed = MajikSignatureEnvelope::from_json(&entry.envelope)?
                .with_seal(key.fingerprint(), o.timestamp.as_deref())?;
            map = map.with_entry(MjksMapEntry { envelope: sealed.to_json(), ..entry })?;
        }
    }
    let map_bytes = map.to_mjksmap();
    let map_path =
        o.output.as_deref().map(resolve_cli_path).unwrap_or_else(|| output_path_for_map(input_dir));
    write_bytes(&map_path, &map_bytes, o.overwrite)?;
    let mut bundle_path = None;
    if o.bundle {
        let bp = output_path_for_map_bundle(input_dir, &map_path);
        write_map_bundle(&files, &map_path, &map_bytes, &bp, o.overwrite)?;
        bundle_path = Some(bp);
    }
    let f: Vec<(String, String)> = failures.into_iter().map(|x| (x.path, x.error)).collect();
    Ok(result(
        "sign",
        json!({"mode": "map", "input": path_s(input_dir), "map": path_s(&map_path), "bundle": bundle_path.as_deref().map(path_s),
               "signerId": key.fingerprint(), "algorithm": "Ed25519 + ML-DSA-87", "files": files.len(), "entries": map.size(),
               "failures": failures_value(&f), "sealed": o.seal}),
        f.is_empty(),
        if f.is_empty() { "MJKSMAP created successfully." } else { "MJKSMAP created with batch failures." },
    ))
}

fn cosign_folder_map(
    input_dir: &Path,
    o: &SignCliOptions,
    key: &MajikKey,
    tsa: Option<MajikTimestamp>,
) -> CliOutcome<CliResult> {
    let Some(cosign) = &o.cosign_map_path else {
        return Err(err("An existing map path is required for cosign mode."));
    };
    let files = read_folder_files(input_dir)?;
    let map_path = resolve_cli_path(cosign);
    let mut map = MajikSignatureMap::from_mjksmap(&read_bytes(&map_path)?)?;
    let mut failures: Vec<(String, String)> = Vec::new();
    let mut updated = 0usize;
    for (i, file) in files.iter().enumerate() {
        eprintln!("[{}/{}] Cosigning {}", i + 1, files.len(), file.relative_path);
        let attempt = (|| -> CliOutcome<()> {
            let lookup = map.find_entry(&file.relative_path, &file.bytes);
            let entry = match (lookup.found, lookup.entry) {
                (true, Some(e)) => e,
                _ => return Err(err("File is not present in the supplied .mjksmap.")),
            };
            if lookup.hash_matches == Some(false) {
                return Err(err("File content does not match the hash recorded in the .mjksmap."));
            }
            let mime = entry.mime_type.clone().unwrap_or_else(|| file.mime_type.clone());
            let signed = MajikSignature::sign_file_detached(
                &file.bytes,
                key,
                Some(&SignDetachedOptions {
                    embed: embed_opts(&mime),
                    content_type: Some(mime.clone()),
                    timestamp: o.timestamp.clone(),
                    valid_until: o.valid_until.clone(),
                    existing_envelope: Some(entry.envelope.clone().into()),
                    tsa: tsa.clone(),
                    ..Default::default()
                }),
            )?;
            let mut envelope = signed.envelope;
            if o.seal {
                envelope = envelope.with_seal(key.fingerprint(), o.timestamp.as_deref())?;
            }
            map = map.with_entry(MjksMapEntry { envelope: envelope.to_json(), ..entry })?;
            updated += 1;
            Ok(())
        })();
        if let Err(e) = attempt {
            eprintln!("    ✘ {e}");
            failures.push((file.relative_path.clone(), e.to_string()));
            if !o.continue_on_error {
                return Err(err(format!("Cosigning stopped at \"{}\": {e}", file.relative_path)));
            }
        }
    }
    let out_map_path = o.output.as_deref().map(resolve_cli_path).unwrap_or_else(|| map_path.clone());
    let out_bytes = map.to_mjksmap();
    write_bytes(&out_map_path, &out_bytes, o.overwrite || out_map_path == map_path)?;
    let mut bundle_path = None;
    if o.bundle {
        let bp = output_path_for_map_bundle(input_dir, &out_map_path);
        write_map_bundle(&files, &out_map_path, &out_bytes, &bp, o.overwrite)?;
        bundle_path = Some(bp);
    }
    Ok(result(
        "sign",
        json!({"mode": "cosign-map", "input": path_s(input_dir), "map": path_s(&out_map_path), "bundle": bundle_path.as_deref().map(path_s),
               "signerId": key.fingerprint(), "algorithm": "Ed25519 + ML-DSA-87", "files": files.len(), "updatedEntries": updated,
               "failures": failures_value(&failures), "sealed": o.seal, "tsa": tsa.is_some()}),
        failures.is_empty(),
        if failures.is_empty() {
            "MJKSMAP cosigning completed successfully."
        } else {
            "MJKSMAP cosigning completed with failures."
        },
    ))
}

pub fn run_sign(o: &SignCliOptions) -> CliOutcome<CliResult> {
    let input = resolve_cli_path(&o.input);
    let kind = get_path_kind(&input)?;
    if matches!(o.mode, SignMode::Map | SignMode::CosignMap) {
        assert_kind(kind, PathKind::Directory)?;
    }
    let mut key = load_signing_key(&o.key_path)?;
    let outcome = (|| -> CliOutcome<CliResult> {
        let signers = if !o.allow_key_paths.is_empty() && o.mode != SignMode::CosignMap {
            Some(build_expected_signers(&key, &o.allow_key_paths)?)
        } else {
            None
        };
        let tsa = load_tsa_token(o.tsa_token_path.as_deref())?;
        if tsa.is_some() && !matches!(o.mode, SignMode::Detached | SignMode::CosignMap) {
            return Err(err("--tsa-token requires --detached or --cosign-map."));
        }
        let bundle_err = || err("--bundle only applies to --map or --cosign-map.");
        match (kind, o.mode) {
            (PathKind::File, SignMode::Embedded) => {
                if o.bundle {
                    return Err(bundle_err());
                }
                sign_single_embedded(&input, o, &key, signers)
            }
            (PathKind::File, SignMode::Detached) => {
                if o.bundle {
                    return Err(bundle_err());
                }
                sign_single_detached(&input, o, &key, signers, tsa)
            }
            (PathKind::Directory, SignMode::Embedded) => {
                if let Some(out) = &o.output {
                    assert_not_inside_input(&input, &resolve_cli_path(out))?;
                }
                if o.bundle {
                    return Err(bundle_err());
                }
                sign_folder_embedded(&input, o, &key, signers)
            }
            (PathKind::Directory, SignMode::Detached) => {
                if let Some(out) = &o.output {
                    assert_not_inside_input(&input, &resolve_cli_path(out))?;
                }
                if o.bundle {
                    return Err(bundle_err());
                }
                sign_folder_detached(&input, o, &key, signers, tsa)
            }
            (_, SignMode::Map) => sign_folder_map(&input, o, &key, signers),
            (_, SignMode::CosignMap) => cosign_folder_map(&input, o, &key, tsa),
        }
    })();
    lock_key(&mut key);
    outcome
}

// ── verify ───────────────────────────────────────────────────────────────────

fn order_valid(order: &Option<Value>) -> bool {
    match order {
        None => true,
        Some(v) => v.get("valid").and_then(Value::as_bool).unwrap_or(false),
    }
}

fn first_failure(results: &[VerificationResult]) -> Option<String> {
    results.iter().find(|r| !r.valid).and_then(|r| r.reason.clone())
}

fn verify_embedded(input: &Path, o: &VerifyCliOptions, trusted: Option<&MajikKey>) -> CliOutcome<CliResult> {
    let bytes = read_bytes(input)?;
    let mime = mime_type_for_path(input);
    let sigs = MajikSignature::extract_from(&bytes, Some(&mime))?;
    if sigs.is_empty() {
        return Ok(result(
            "verify",
            json!({"input": path_s(input), "verdict": "unsigned", "signatures": [], "reason": "No embedded Majik Signature envelope was found."}),
            false,
            "File is unsigned.",
        ));
    }
    let vopts = VerifyFileOptions { mime_type: Some(mime.clone()), ..Default::default() };
    let mut results: Vec<VerificationResult> = Vec::new();
    match trusted {
        Some(k) => results = MajikSignature::verify_file(&bytes, KeyOrPublicKeys::Key(k), Some(&vopts))?,
        None => {
            for s in &sigs {
                let pk = s.extract_public_keys()?;
                let cur = MajikSignature::verify_file(
                    &bytes,
                    KeyOrPublicKeys::PublicKeys(&pk),
                    Some(&VerifyFileOptions {
                        expected_signer_id: Some(s.signer_id().to_string()),
                        ..vopts.clone()
                    }),
                )?;
                results.extend(cur);
            }
        }
    }
    let all_valid = !results.is_empty() && results.iter().all(|r| r.valid);

    let mut order_result: Option<Value> = None;
    if !o.order.is_empty() {
        let mut expected: Vec<ExpectedSigner> = Vec::new();
        for id in &o.order {
            match sigs.iter().find(|s| s.signer_id() == id) {
                Some(s) => expected.push(expected_signer_from_signature(s)?),
                None => {
                    return Ok(result(
                        "verify",
                        json!({"input": path_s(input), "verdict": "invalid-order", "signatures": to_value(&results),
                               "reason": format!("Signer \"{id}\" does not exist in the envelope.")}),
                        false,
                        "Signing order is invalid.",
                    ));
                }
            }
        }
        let entries: Vec<OrderEntry<'_>> = expected.iter().map(OrderEntry::Signer).collect();
        let r = MajikSignature::verify_file_order(
            &bytes,
            &entries,
            Some(&OrderOptions { mime_type: Some(mime), strict: o.strict }),
        )?;
        order_result = Some(to_value(&r));
    }
    let valid = all_valid && order_valid(&order_result);
    Ok(result(
        "verify",
        json!({"input": path_s(input), "verdict": if valid { "valid" } else { "invalid" }, "signatures": to_value(&results),
               "order": order_result, "reason": if valid { None } else { first_failure(&results) }}),
        valid,
        if valid { "Signature verification passed." } else { "Signature verification failed." },
    ))
}

fn pk_of(sig: &MajikSignatureJSON) -> CliOutcome<MajikSignerPublicKeys> {
    Ok(MajikSignerPublicKeys {
        signer_id: sig.signer_id.clone(),
        ed_public_key: crate::core::hash::base64_to_bytes(&sig.signer_ed_public_key)?,
        ml_dsa_public_key: crate::core::hash::base64_to_bytes(&sig.signer_ml_dsa_public_key)?,
    })
}

fn verify_detached_with(
    bytes: &[u8],
    envelope: &MajikSignatureEnvelope,
    mime: &str,
    trusted: Option<&MajikKey>,
) -> CliOutcome<Vec<VerificationResult>> {
    let vopts = VerifyFileOptions { mime_type: Some(mime.to_string()), ..Default::default() };
    let mut results = Vec::new();
    match trusted {
        Some(k) => {
            results = MajikSignature::verify_file_detached(
                bytes,
                envelope.clone(),
                KeyOrPublicKeys::Key(k),
                Some(&vopts),
            )?
        }
        None => {
            for s in envelope.signatures() {
                let pk = pk_of(s)?;
                results.extend(MajikSignature::verify_file_detached(
                    bytes,
                    envelope.clone(),
                    KeyOrPublicKeys::PublicKeys(&pk),
                    Some(&VerifyFileOptions {
                        expected_signer_id: Some(s.signer_id.clone()),
                        ..vopts.clone()
                    }),
                )?);
            }
        }
    }
    Ok(results)
}

fn detached_order(
    bytes: &[u8],
    envelope: &MajikSignatureEnvelope,
    order: &[String],
    mime: &str,
    strict: bool,
) -> CliOutcome<Result<Value, String>> {
    let mut expected: Vec<ExpectedSigner> = Vec::new();
    for id in order {
        match envelope.signatures().iter().find(|s| &s.signer_id == id) {
            Some(s) => expected.push(expected_signer_from_json(s)?),
            None => return Ok(Err(id.clone())),
        }
    }
    let entries: Vec<OrderEntry<'_>> = expected.iter().map(OrderEntry::Signer).collect();
    let r = MajikSignature::verify_file_detached_order(
        bytes,
        envelope.clone(),
        &entries,
        Some(&OrderOptions { mime_type: Some(mime.to_string()), strict }),
    )?;
    Ok(Ok(to_value(&r)))
}

fn verify_detached_file(
    input: &Path,
    detached: &Path,
    o: &VerifyCliOptions,
    trusted: Option<&MajikKey>,
) -> CliOutcome<CliResult> {
    let bytes = read_bytes(input)?;
    let envelope = MajikSignatureEnvelope::from_mjksig(&read_bytes(detached)?)?;
    if envelope.signatures().is_empty() {
        return Ok(result(
            "verify",
            json!({"input": path_s(input), "detached": path_s(detached), "verdict": "unsigned", "signatures": []}),
            false,
            "Detached envelope contains no signatures.",
        ));
    }
    let mime = mime_type_for_path(input);
    let results = verify_detached_with(&bytes, &envelope, &mime, trusted)?;
    let all_valid = !results.is_empty() && results.iter().all(|r| r.valid);
    let mut order_result: Option<Value> = None;
    if !o.order.is_empty() {
        match detached_order(&bytes, &envelope, &o.order, &mime, o.strict)? {
            Ok(v) => order_result = Some(v),
            Err(id) => {
                return Ok(result(
                    "verify",
                    json!({"input": path_s(input), "detached": path_s(detached), "verdict": "invalid-order", "signatures": to_value(&results),
                           "reason": format!("Signer \"{id}\" does not exist in the detached envelope.")}),
                    false,
                    "Signing order is invalid.",
                ));
            }
        }
    }
    let valid = all_valid && order_valid(&order_result);
    Ok(result(
        "verify",
        json!({"input": path_s(input), "detached": path_s(detached), "verdict": if valid { "valid" } else { "invalid" },
               "signatures": to_value(&results), "order": order_result, "sealed": envelope.is_sealed(),
               "seal": envelope.is_sealed().then(|| seal_info_value(&envelope)),
               "reason": if valid { None } else { first_failure(&results) }}),
        valid,
        if valid {
            "Detached signature verification passed."
        } else {
            "Detached signature verification failed."
        },
    ))
}

fn verify_map_folder(
    input_dir: &Path,
    map_path: &Path,
    o: &VerifyCliOptions,
    trusted: Option<&MajikKey>,
) -> CliOutcome<CliResult> {
    let files = read_folder_files(input_dir)?;
    let map = MajikSignatureMap::from_mjksmap(&read_bytes(map_path)?)?;
    let mut file_results: Vec<Value> = Vec::new();
    let mut accounted: HashSet<String> = HashSet::new();

    for file in &files {
        let direct = map.find_entry(&file.relative_path, &file.bytes);
        let mut entry = if direct.found { direct.entry.clone() } else { None };
        let mut relocated_from: Option<String> = None;
        if entry.is_none() {
            let matches = map.find_entries_by_hash(&file.bytes);
            if matches.len() == 1 {
                relocated_from = Some(matches[0].path.clone());
                entry = Some(matches[0].clone());
            }
        }
        let Some(entry) = entry else {
            file_results.push(json!({"path": file.relative_path, "status": "not_in_map", "reason": "The file is not represented by the supplied .mjksmap."}));
            continue;
        };
        accounted.insert(entry.path.clone());
        if direct.found && direct.hash_matches == Some(false) {
            file_results.push(json!({"path": file.relative_path, "status": "tampered", "reason": "The file content does not match the content hash recorded in the map."}));
            continue;
        }
        let envelope = MajikSignatureEnvelope::from_json(&entry.envelope)?;
        let mime = entry.mime_type.clone().unwrap_or_else(|| file.mime_type.clone());
        let results = verify_detached_with(&file.bytes, &envelope, &mime, trusted)?;
        let crypto_valid = !results.is_empty() && results.iter().all(|r| r.valid);

        let mut order_result: Option<Value> = None;
        if !o.order.is_empty() {
            order_result = Some(match detached_order(&file.bytes, &envelope, &o.order, &mime, o.strict)? {
                Ok(v) => v,
                Err(id) => {
                    json!({"valid": false, "reason": format!("Signer \"{id}\" does not exist in the envelope.")})
                }
            });
        }
        let ok = crypto_valid && order_valid(&order_result);
        file_results.push(json!({
            "path": file.relative_path, "status": if ok { "verified" } else { "invalid" }, "relocatedFrom": relocated_from,
            "signatures": to_value(&results), "order": order_result,
            "reason": if ok { None } else { Some(first_failure(&results).unwrap_or_else(|| "Signature or signing-order verification failed.".into())) },
        }));
    }

    let missing: Vec<String> =
        map.entries().iter().map(|e| e.path.clone()).filter(|p| !accounted.contains(p)).collect();
    for p in &missing {
        file_results.push(json!({"path": p, "status": "not_in_map", "reason": "The map contains this path, but the file was not supplied for verification."}));
    }
    let invalid =
        file_results.iter().filter(|v| v.get("status").and_then(Value::as_str) != Some("verified")).count();
    let all_valid = file_results.is_empty() || invalid == 0;
    Ok(result(
        "verify",
        json!({"input": path_s(input_dir), "map": path_s(map_path), "verdict": if all_valid { "valid" } else { "invalid" }, "files": file_results, "missing": missing}),
        all_valid,
        if all_valid { "MJKSMAP verification passed." } else { "MJKSMAP verification failed." },
    ))
}

pub fn run_verify(o: &VerifyCliOptions) -> CliOutcome<CliResult> {
    let input = resolve_cli_path(&o.input);
    let kind = get_path_kind(&input)?;
    let mut trusted = match &o.key_path {
        Some(p) => Some(load_majik_key(p)?),
        None => None,
    };
    let outcome = (|| -> CliOutcome<CliResult> {
        if let Some(map_path) = &o.map_path {
            assert_kind(kind, PathKind::Directory)?;
            if o.detached_path.is_some() {
                return Err(err("--map and --detached cannot be combined."));
            }
            return verify_map_folder(&input, &resolve_cli_path(map_path), o, trusted.as_ref());
        }
        if let Some(d) = &o.detached_path {
            assert_kind(kind, PathKind::File)?;
            return verify_detached_file(&input, &resolve_cli_path(d), o, trusted.as_ref());
        }
        if kind != PathKind::File {
            return Err(err(
                "Embedded verification currently requires a single file. Use --map for folder verification.",
            ));
        }
        verify_embedded(&input, o, trusted.as_ref())
    })();
    if let Some(k) = trusted.as_mut() {
        lock_key(k);
    }
    outcome
}

// ── seal / can-sign / inspect ────────────────────────────────────────────────

fn is_detached_ext(p: &Path) -> bool {
    p.extension().and_then(|e| e.to_str()).map(|e| e.eq_ignore_ascii_case("mjksig")).unwrap_or(false)
}

pub fn run_seal(o: &SealCliOptions) -> CliOutcome<CliResult> {
    let input = resolve_cli_path(&o.input);
    assert_kind(get_path_kind(&input)?, PathKind::File)?;
    let mut key = load_signing_key(&o.key_path)?;
    let outcome = (|| -> CliOutcome<CliResult> {
        let out_path = o.output.as_deref().map(resolve_cli_path).unwrap_or_else(|| input.clone());
        if is_detached_ext(&input) {
            let envelope = MajikSignatureEnvelope::from_mjksig(&read_bytes(&input)?)?
                .with_seal(key.fingerprint(), o.timestamp.as_deref())?;
            write_bytes(&out_path, &envelope.to_mjksig(), o.overwrite || out_path == input)?;
            return Ok(result(
                "seal",
                json!({"input": path_s(&input), "output": path_s(&out_path), "sealedBy": envelope.sealed_by(),
                       "sealTimestamp": envelope.seal_timestamp(), "sealHash": envelope.seal_hash()}),
                true,
                "Detached envelope sealed successfully.",
            ));
        }
        let source = read_bytes(&input)?;
        let sealed =
            MajikSignature::seal(&source, &key, Some(&mime_type_for_path(&input)), o.timestamp.as_deref())?;
        write_bytes(&out_path, &sealed.blob, o.overwrite || out_path == input)?;
        Ok(result(
            "seal",
            json!({"input": path_s(&input), "output": path_s(&out_path), "sealedBy": sealed.seal_info.sealed_by,
                   "sealTimestamp": sealed.seal_info.seal_timestamp, "sealHash": sealed.seal_info.seal_hash}),
            true,
            "Embedded signature envelope sealed successfully.",
        ))
    })();
    lock_key(&mut key);
    outcome
}

pub fn run_can_sign(o: &CanSignCliOptions) -> CliOutcome<CliResult> {
    let input = resolve_cli_path(&o.input);
    assert_kind(get_path_kind(&input)?, PathKind::File)?;
    let mut key = load_signing_key(&o.key_path)?;
    let outcome = (|| -> CliOutcome<CliResult> {
        let bytes = read_bytes(&input)?;
        let p = MajikSignature::can_sign(&bytes, &key, Some(&mime_type_for_path(&input)))?;
        Ok(result(
            "can-sign",
            json!({"input": path_s(&input), "permitted": p.permitted, "reason": p.reason}),
            p.permitted,
            if p.permitted {
                "The file can be signed by this key."
            } else {
                "The file cannot be signed by this key."
            },
        ))
    })();
    lock_key(&mut key);
    outcome
}

pub fn run_inspect(o: &InspectCliOptions) -> CliOutcome<CliResult> {
    let input = resolve_cli_path(&o.input);
    assert_kind(get_path_kind(&input)?, PathKind::File)?;
    let bytes = read_bytes(&input)?;
    if is_detached_ext(&input) {
        let envelope = MajikSignatureEnvelope::from_mjksig(&bytes)?;
        return Ok(result(
            "inspect",
            json!({"input": path_s(&input), "signed": !envelope.signatures().is_empty(), "envelope": to_value(&envelope.to_json())}),
            true,
            "Detached signature envelope inspected successfully.",
        ));
    }
    let info = MajikSignature::get_envelope_info(&bytes, Some(&mime_type_for_path(&input)))?;
    Ok(result(
        "inspect",
        json!({"input": path_s(&input), "signed": info.is_some(), "envelope": info.as_ref().map(to_value)}),
        true,
        if info.is_some() {
            "Embedded signature envelope inspected successfully."
        } else {
            "The file does not contain a Majik Signature envelope."
        },
    ))
}

#[allow(dead_code)]
fn _unused(_: PathBuf) {}
