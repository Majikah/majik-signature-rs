//! Port of `core/embed/majik-embed.ts` — `MajikSignatureEmbed`: the file-aware layer that
//! signs, embeds, extracts and verifies signatures inside real files.
//!
//! The TS implementation threads a `MajikSignatureStaticAdapter` through every call purely to
//! dodge a circular import between `majik-signature.ts` and this file. Rust modules may refer
//! to each other freely, so `MajikSignature` is used directly and the adapter types are gone.
//! `async`/`Blob` become synchronous functions over `&[u8]` / `Vec<u8>`; the declared MIME
//! type that a `Blob` carries is passed as `EmbedOptions::mime_type`.

use std::sync::OnceLock;

use jiff::Timestamp;
use majik_key::MajikKey;

use crate::anchor::types::MajikChainAnchor;
use crate::core::embed::canonical::{
    assert_canonical, no_signature_reason, prepare_detached_bytes, CanonicalResult, DetachedPrepareOptions,
};
use crate::core::embed::embedded_envelope_codec::{parse_embedded_envelope, serialize_embedded_envelope};
use crate::core::embed::fallback::FallbackHandler;
use crate::core::embed::handlers::*;
use crate::core::embed::registry::FormatHandlerRegistry;
use crate::core::embed::utils::detect_mime_type;
use crate::core::envelope::{EnvelopeInput, MajikSignatureEnvelope};
use crate::core::errors::{MajikSignatureError, MajikSignatureResult};
use crate::core::hash::{base64_to_bytes, bytes_to_base64, hash_content};
use crate::core::mjksmap::MajikSignatureMap;
use crate::core::order::{
    verify_signature_order, OrderEntry, SignatureOrderResult, VerifySignatureOrderOptions,
};
use crate::core::time::now_iso;
use crate::core::types::*;
use crate::majik_signature::MajikSignature;

type R<T> = MajikSignatureResult<T>;

// ── Default registry ─────────────────────────────────────────────────────────

fn default_registry() -> &'static FormatHandlerRegistry {
    static REGISTRY: OnceLock<FormatHandlerRegistry> = OnceLock::new();
    REGISTRY.get_or_init(|| {
        let mut r = FormatHandlerRegistry::new();
        r.register(Box::new(PdfHandler))
            .register(Box::new(PngHandler))
            .register(Box::new(JpegHandler))
            .register(Box::new(WavHandler))
            .register(Box::new(Mp3Handler))
            .register(Box::new(Mp4Handler))
            .register(Box::new(FlacHandler))
            .register(Box::new(MkvHandler))
            .register(Box::new(OfficeHandler))
            .register(Box::new(TextHandler))
            .register(Box::new(MsixHandler));
        r
    })
}

static FALLBACK: FallbackHandler = FallbackHandler;

// ── Option / result types ────────────────────────────────────────────────────

/// Options for [`MajikSignatureEmbed::sign_and_embed`].
#[derive(Debug, Clone, Default)]
pub struct SignAndEmbedOptions {
    pub embed: EmbedOptions,
    pub content_type: Option<String>,
    pub timestamp: Option<ISODateString>,
    pub expected_signers: Option<Vec<ExpectedSigner>>,
    pub valid_until: Option<ISODateString>,
    /// Free-form note stored on the new `FileVersion` entry.
    pub message: Option<String>,
    /// A previously signed copy to build on (its envelope is fully verified first).
    pub prior_signed_file: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct SignAndEmbedResult {
    pub blob: Vec<u8>,
    pub handler: String,
    pub mime_type: String,
    pub signature: MajikSignature,
    pub envelope: MajikSignatureEnvelope,
}

#[derive(Debug, Clone, Default)]
pub struct SignDetachedOptions {
    pub embed: EmbedOptions,
    pub content_type: Option<String>,
    pub timestamp: Option<ISODateString>,
    pub valid_until: Option<ISODateString>,
    pub expected_signers: Option<Vec<ExpectedSigner>>,
    pub existing_envelope: Option<EnvelopeInput>,
    pub tsa: Option<MajikTimestamp>,
}

#[derive(Debug, Clone)]
pub struct SignDetachedResult {
    /// The file with any embedded envelope stripped (the exact bytes that were signed).
    pub blob: Vec<u8>,
    pub envelope: MajikSignatureEnvelope,
    pub signature: MajikSignature,
    pub handler: String,
    pub mime_type: String,
}

/// Options shared by the verify entry points.
#[derive(Debug, Clone, Default)]
pub struct VerifyFileOptions {
    pub mime_type: Option<String>,
    pub expected_signer_id: Option<String>,
    pub now: Option<Timestamp>,
    /// Detached verification only: demand that the file is already in canonical (stripped) form.
    pub require_canonical: bool,
}

#[derive(Debug, Clone, Default)]
pub struct OrderOptions {
    pub mime_type: Option<String>,
    pub strict: bool,
}

#[derive(Debug, Clone)]
pub struct SealResult {
    pub blob: Vec<u8>,
    pub seal_info: SealInfo,
    pub handler: String,
    pub mime_type: String,
}

/// Resolve a signer's public keys by id (used by [`MajikSignatureEmbed::verify_file_revisions`]).
pub type ResolvePublicKeys<'a> = dyn Fn(&str) -> R<MajikSignerPublicKeys> + 'a;

#[derive(Default)]
pub struct VerifyRevisionsOptions<'a> {
    pub mime_type: Option<String>,
    pub now: Option<Timestamp>,
    pub resolve_public_keys: Option<&'a ResolvePublicKeys<'a>>,
}

struct Prepared<'a> {
    bytes: &'a [u8],
    mime_type: String,
    handler: &'static dyn FormatHandler,
}

/// Namespace for the file-aware operations (TS static class).
pub struct MajikSignatureEmbed;

impl MajikSignatureEmbed {
    // ── EMBED ────────────────────────────────────────────────────────────────

    /// Embed an already-created signature into a file (adds to / replaces within its envelope).
    /// The signature must cover the original (stripped) file bytes.
    pub fn embed(
        file: &[u8],
        signature: &MajikSignatureJSON,
        options: Option<&EmbedOptions>,
    ) -> R<EmbedResult> {
        let p = Self::prepare(file, options);
        let envelope = Self::read_envelope(p.handler, p.bytes)?;
        let updated = envelope.with_signature(signature.clone())?;
        let stripped = p.handler.strip(p.bytes)?;
        let result = p.handler.embed(&stripped, &serialize_embedded_envelope(&updated)?)?;
        Ok(EmbedResult { blob: result, handler: p.handler.name().to_string(), mime_type: p.mime_type })
    }

    /// Sign a file and embed the signature (multi-sig, allowlist, version chain aware).
    pub fn sign_and_embed(
        file: &[u8],
        key: &MajikKey,
        options: Option<&SignAndEmbedOptions>,
    ) -> R<SignAndEmbedResult> {
        let default_opts = SignAndEmbedOptions::default();
        let options = options.unwrap_or(&default_opts);
        let p = Self::prepare(file, Some(&options.embed));

        let envelope = match &options.prior_signed_file {
            Some(prior) => Self::read_and_verify_prior_envelope(prior)?,
            None => Self::read_envelope(p.handler, p.bytes)?,
        };
        envelope.assert_can_sign(key)?;

        let original = p.handler.strip(p.bytes)?;
        let allowlist_hash = envelope.resolve_allowlist_hash_for(key, options.expected_signers.as_deref());

        let last = envelope.last_file_version();
        let new_entry = FileVersion {
            version: last.map(|l| l.version + 1).unwrap_or(1),
            timestamp: options.timestamp.clone().unwrap_or_else(now_iso),
            content_hash: bytes_to_base64(&hash_content(&original)),
            previous_version_hash: last.map(MajikSignatureEnvelope::hash_file_version_entry),
            created_by: Some(key.fingerprint().to_string()),
            message: options.message.clone().filter(|m| !m.is_empty()),
        };
        let mut chain = envelope.file_versions().to_vec();
        chain.push(new_entry.clone());
        let version_chain_hash = MajikSignatureEnvelope::hash_file_version_chain(&chain);

        let signature = MajikSignature::sign(
            &original,
            key,
            Some(&SignOptions {
                content_type: options.content_type.clone(),
                timestamp: Some(new_entry.timestamp.clone()),
                valid_until: options.valid_until.clone(),
                version_chain_hash: Some(version_chain_hash),
                allowlist_hash,
                ..Default::default()
            }),
        )?;

        let establishing = envelope.is_first_signer()
            && options.expected_signers.as_ref().map(|e| !e.is_empty()).unwrap_or(false);
        let with_allowlist = if establishing {
            envelope.with_allowlist(options.expected_signers.as_deref().unwrap_or(&[]), key.fingerprint())?
        } else {
            envelope
        };
        let next = with_allowlist.with_file_version(new_entry)?.with_signature(signature.to_json())?;
        let result = p.handler.embed(&original, &serialize_embedded_envelope(&next)?)?;
        Ok(SignAndEmbedResult {
            blob: result,
            handler: p.handler.name().to_string(),
            mime_type: p.mime_type,
            signature,
            envelope: next,
        })
    }

    fn read_and_verify_prior_envelope(prior: &[u8]) -> R<MajikSignatureEnvelope> {
        let p = Self::prepare(prior, None);
        let raw =
            p.handler.extract(p.bytes)?.filter(|r| !r.is_empty()).ok_or_else(|| {
                MajikSignatureError::new("priorSignedFile has no embedded signature envelope.")
            })?;
        let mut envelope = parse_embedded_envelope(&raw)?;

        let allowlist_integrity = envelope.verify_allowlist_integrity();
        if !allowlist_integrity.valid {
            return Err(MajikSignatureError::new(format!(
                "priorSignedFile allowlist integrity failed: {}",
                allowlist_integrity.reason.unwrap_or_default()
            )));
        }
        let chain_integrity = envelope.verify_version_chain_integrity();
        if !chain_integrity.valid {
            return Err(MajikSignatureError::new(format!(
                "priorSignedFile version chain integrity failed: {}",
                chain_integrity.reason.unwrap_or_default()
            )));
        }
        let prior_stripped = match assert_canonical(p.handler, p.bytes, &raw) {
            CanonicalResult::Ok { original } => original,
            CanonicalResult::Err { reason } => {
                return Err(MajikSignatureError::new(format!(
                    "priorSignedFile is not in canonical signed form: {reason}"
                )))
            }
        };
        let checked = Self::verify_envelope_self_contained(&envelope, &prior_stripped, None)?;
        if !checked.ok {
            let failed = std::iter::once(&checked.latest)
                .chain(checked.history.iter().map(|h| &h.base))
                .find(|r| !r.valid);
            return Err(MajikSignatureError::new(format!(
                "Refusing to build on priorSignedFile — signature by \"{}\" is invalid: {}",
                failed.and_then(|f| f.signer_id.as_deref()).unwrap_or("undefined"),
                failed.and_then(|f| f.reason.as_deref()).unwrap_or("undefined")
            )));
        }
        // Back-fill a version-1 entry for files signed before the revision chain existed.
        if envelope.file_versions().is_empty() && !envelope.signatures().is_empty() {
            let first = &envelope.signatures()[0];
            let entry = FileVersion {
                version: 1,
                timestamp: first.timestamp.clone(),
                content_hash: bytes_to_base64(&hash_content(&prior_stripped)),
                previous_version_hash: None,
                created_by: Some(first.signer_id.clone()),
                message: None,
            };
            envelope = envelope.with_file_version(entry)?;
        }
        Ok(envelope)
    }

    /// Verify a whole envelope against one set of stripped bytes: the signature that matches the
    /// current bytes in full, plus commitment-only checks for every earlier revision.
    fn verify_envelope_self_contained(
        envelope: &MajikSignatureEnvelope,
        current_stripped: &[u8],
        now: Option<Timestamp>,
    ) -> R<SelfContained> {
        let chain = envelope.file_versions();
        let current_hash = bytes_to_base64(&hash_content(current_stripped));
        let full_chain_hash = MajikSignatureEnvelope::hash_file_version_chain(chain);
        let sigs = envelope.signatures();

        let latest_idx = sigs
            .iter()
            .position(|s| {
                s.content_hash == current_hash
                    && s.version_chain_hash.as_deref() == Some(full_chain_hash.as_str())
            })
            .or_else(|| sigs.iter().position(|s| s.content_hash == current_hash));

        let check_chain_hash = |sig: &MajikSignatureJSON| -> (bool, Option<String>) {
            if sig.version_chain_hash.is_none() && chain.is_empty() {
                return (true, None); // pre-feature file
            }
            let idx = chain.iter().enumerate().position(|(i, v)| {
                v.content_hash == sig.content_hash
                    && match sig.version_chain_hash.as_deref().filter(|h| !h.is_empty()) {
                        Some(h) => MajikSignatureEnvelope::hash_file_version_chain(&chain[..=i]) == h,
                        None => true,
                    }
            });
            let Some(idx) = idx else {
                return (false, Some("No fileVersions entry matches this signature's state.".into()));
            };
            let expected = MajikSignatureEnvelope::hash_file_version_chain(&chain[..=idx]);
            match sig.version_chain_hash.as_deref() {
                None => (true, None),
                Some(h) if h == expected => (true, None),
                Some(_) => (
                    false,
                    Some("versionChainHash does not match the recomputed chain prefix — chain may be tampered.".into()),
                ),
            }
        };
        let public_keys_of = |sig: &MajikSignatureJSON| -> R<MajikSignerPublicKeys> {
            Ok(MajikSignerPublicKeys {
                signer_id: sig.signer_id.clone(),
                ed_public_key: base64_to_bytes(&sig.signer_ed_public_key)?,
                ml_dsa_public_key: base64_to_bytes(&sig.signer_ml_dsa_public_key)?,
            })
        };

        let latest = match latest_idx {
            None => VerificationResult {
                valid: false,
                reason: Some("No signature's contentHash matches the current bytes.".into()),
                timestamp: now_iso(),
                ..Default::default()
            },
            Some(i) => {
                let sig = &sigs[i];
                let (ok, reason) = check_chain_hash(sig);
                if ok {
                    MajikSignature::verify(current_stripped, sig, &public_keys_of(sig)?, now)?
                } else {
                    VerificationResult {
                        valid: false,
                        signer_id: Some(sig.signer_id.clone()),
                        content_hash: Some(sig.content_hash.clone()),
                        timestamp: sig.timestamp.clone(),
                        reason,
                        ..Default::default()
                    }
                }
            }
        };

        let mut history = Vec::new();
        for (i, sig) in sigs.iter().enumerate() {
            if Some(i) == latest_idx {
                continue;
            }
            let (ok, reason) = check_chain_hash(sig);
            let result = if ok {
                MajikSignature::verify_commitment(sig, &public_keys_of(sig)?, now)?
            } else {
                RevisionCommitmentResult {
                    base: VerificationResult {
                        valid: false,
                        signer_id: Some(sig.signer_id.clone()),
                        content_hash: Some(sig.content_hash.clone()),
                        timestamp: sig.timestamp.clone(),
                        reason,
                        ..Default::default()
                    },
                    commitment_only: true,
                }
            };
            history.push(result);
        }
        let ok = latest.valid && history.iter().all(|h| h.base.valid);
        Ok(SelfContained { latest, history, ok })
    }

    // ── DETACHED SIGNING ─────────────────────────────────────────────────────

    /// Sign a file and return the envelope detached (the file is NOT modified; the returned
    /// `blob` is the file with any embedded envelope stripped).
    pub fn sign_detached(
        file: &[u8],
        key: &MajikKey,
        options: Option<&SignDetachedOptions>,
    ) -> R<SignDetachedResult> {
        let default_opts = SignDetachedOptions::default();
        let options = options.unwrap_or(&default_opts);
        let p = Self::prepare(file, Some(&options.embed));

        let envelope = match &options.existing_envelope {
            Some(e) => MajikSignatureEnvelope::from_input(e.clone())?,
            None => Self::read_envelope(p.handler, p.bytes)?,
        };
        envelope.assert_can_sign(key)?;

        let original = p.handler.strip(p.bytes)?;
        let allowlist_hash = envelope.resolve_allowlist_hash_for(key, options.expected_signers.as_deref());

        let mut signature = MajikSignature::sign(
            &original,
            key,
            Some(&SignOptions {
                content_type: options.content_type.clone(),
                timestamp: options.timestamp.clone(),
                valid_until: options.valid_until.clone(),
                allowlist_hash,
                ..Default::default()
            }),
        )?;
        if let Some(tsa) = &options.tsa {
            signature.add_tsa(tsa.clone())?;
        }

        let establishing = envelope.is_first_signer()
            && options.expected_signers.as_ref().map(|e| !e.is_empty()).unwrap_or(false);
        let with_allowlist = if establishing {
            envelope.with_allowlist(options.expected_signers.as_deref().unwrap_or(&[]), key.fingerprint())?
        } else {
            envelope
        };
        let next = with_allowlist.with_signature(signature.to_json())?;
        Ok(SignDetachedResult {
            blob: original,
            handler: p.handler.name().to_string(),
            mime_type: p.mime_type,
            envelope: next,
            signature,
        })
    }

    /// Sign a batch of files as detached envelopes, packaged as one `.mjksmap` (default) or as
    /// separate `.mjksig` blobs.
    pub fn sign_batch_detached(
        files: &[BatchFileInput],
        key: &MajikKey,
        options: Option<&BatchSignOptions>,
    ) -> R<BatchSignResult> {
        let default_opts = BatchSignOptions::default();
        let options = options.unwrap_or(&default_opts);
        Self::assert_valid_batch(files)?;

        let mode = options.mode.unwrap_or_default();
        let mut failures: Vec<BatchSignFailure> = Vec::new();
        let mut map = (mode == BatchSignMode::Map).then(MajikSignatureMap::empty);
        let mut signatures: Vec<SeparateSignature> = Vec::new();

        for file in files {
            let attempt = (|| -> R<()> {
                let (envelope, content_hash) = Self::sign_one_detached(file, key, options)?;
                match (&mut map, mode) {
                    (Some(m), BatchSignMode::Map) => {
                        *m = m.with_entry(MjksMapEntry {
                            path: file.path.clone(),
                            content_hash,
                            size: Some(file.blob.len() as u64),
                            mime_type: file.mime_type.clone().filter(|t| !t.is_empty()),
                            envelope: envelope.to_json(),
                        })?;
                    }
                    _ => signatures
                        .push(SeparateSignature { path: file.path.clone(), blob: envelope.to_mjksig()? }),
                }
                Ok(())
            })();
            if let Err(err) = attempt {
                if !options.continue_on_error {
                    return Err(MajikSignatureError::Generic {
                        message: format!("Batch signing failed on \"{}\": {}", file.path, err.message()),
                        cause: Some(Box::new(err)),
                    });
                }
                failures.push(BatchSignFailure { path: file.path.clone(), error: err.message().to_string() });
            }
        }

        Ok(match map {
            Some(m) => BatchSignResult::Map { map_blob: m.to_mjksmap(), map: m, failures },
            None => BatchSignResult::Separate { signatures, failures },
        })
    }

    fn sign_one_detached(
        file: &BatchFileInput,
        key: &MajikKey,
        options: &BatchSignOptions,
    ) -> R<(MajikSignatureEnvelope, String)> {
        let result = Self::sign_detached(
            &file.blob,
            key,
            Some(&SignDetachedOptions {
                embed: EmbedOptions {
                    mime_type: file.mime_type.clone().filter(|t| !t.is_empty()),
                    force_fallback: false,
                },
                content_type: options.content_type.clone(),
                timestamp: options.timestamp.clone(),
                expected_signers: options.expected_signers.clone(),
                valid_until: options.valid_until.clone(),
                ..Default::default()
            }),
        )?;
        let sig = result.envelope.find_signature(key.fingerprint()).ok_or_else(|| {
            MajikSignatureError::new(format!(
                "Internal error: no signature found for this signer after signing \"{}\"",
                file.path
            ))
        })?;
        let content_hash = sig.content_hash.clone();
        Ok((result.envelope, content_hash))
    }

    fn assert_valid_batch(files: &[BatchFileInput]) -> R<()> {
        if files.is_empty() {
            return Err(MajikSignatureError::validation(
                "Batch must contain at least one file.",
                Some("files"),
            ));
        }
        let mut seen = std::collections::HashSet::new();
        for file in files {
            if file.path.trim().is_empty() {
                return Err(MajikSignatureError::validation(
                    "Every batch file must have a non-empty path.",
                    Some("path"),
                ));
            }
            if !seen.insert(file.path.as_str()) {
                return Err(MajikSignatureError::validation(
                    format!("Duplicate path in batch: \"{}\"", file.path),
                    Some("path"),
                ));
            }
        }
        Ok(())
    }

    // ── EXTRACT / VERIFY ─────────────────────────────────────────────────────

    pub fn extract(file: &[u8], options: Option<&ExtractOptions>) -> R<Option<ExtractResult>> {
        let p = Self::prepare_mime(file, options.and_then(|o| o.mime_type.as_deref()));
        let Some(raw) = p.handler.extract(p.bytes)?.filter(|r| !r.is_empty()) else { return Ok(None) };
        let envelope = parse_embedded_envelope(&raw)?;
        Ok(Some(ExtractResult { envelope, handler: p.handler.name().to_string() }))
    }

    /// Verify a file's embedded signatures; one result per signer.
    pub fn verify(
        file: &[u8],
        public_keys: &MajikSignerPublicKeys,
        options: Option<&VerifyFileOptions>,
    ) -> R<Vec<VerificationResult>> {
        let default_opts = VerifyFileOptions::default();
        let options = options.unwrap_or(&default_opts);
        let p = Self::prepare_mime(file, options.mime_type.as_deref());

        let Some(raw) = p.handler.extract(p.bytes)?.filter(|r| !r.is_empty()) else {
            return Ok(vec![Self::no_signature_result(Some(no_signature_reason(p.handler, p.bytes)))]);
        };
        let envelope = match parse_embedded_envelope(&raw) {
            Ok(e) => e,
            Err(_) => return Ok(vec![Self::failure("Embedded signature payload is malformed")]),
        };
        let original = match assert_canonical(p.handler, p.bytes, &raw) {
            CanonicalResult::Ok { original } => original,
            CanonicalResult::Err { reason } => return Ok(vec![Self::failure(reason)]),
        };
        let integrity = envelope.verify_allowlist_integrity();
        if !integrity.valid {
            return Ok(vec![Self::failure(integrity.reason.unwrap_or_default())]);
        }
        Self::verify_signatures(
            &envelope,
            &original,
            public_keys,
            p.handler.name(),
            options.expected_signer_id.as_deref(),
            options.now,
        )
    }

    pub fn verify_with_key(
        file: &[u8],
        key: &MajikKey,
        options: Option<&VerifyFileOptions>,
    ) -> R<Vec<VerificationResult>> {
        let keys = MajikSignature::public_keys_from_majik_key(key)?;
        Self::verify(file, &keys, options)
    }

    /// Verify a file against a detached envelope.
    pub fn verify_detached(
        file: &[u8],
        envelope: EnvelopeInput,
        public_keys: &MajikSignerPublicKeys,
        options: Option<&VerifyFileOptions>,
    ) -> R<Vec<VerificationResult>> {
        let default_opts = VerifyFileOptions::default();
        let options = options.unwrap_or(&default_opts);
        let p = Self::prepare_mime(file, options.mime_type.as_deref());
        let envelope = MajikSignatureEnvelope::from_input(envelope)?;

        let prepared = prepare_detached_bytes(
            p.handler,
            p.bytes,
            &DetachedPrepareOptions {
                require_canonical: options.require_canonical,
                validate_envelope: &|raw| parse_embedded_envelope(raw).map(|_| ()),
            },
        )?;
        let original = match prepared {
            CanonicalResult::Ok { original } => original,
            CanonicalResult::Err { reason } => return Ok(vec![Self::failure(reason)]),
        };
        let integrity = envelope.verify_allowlist_integrity();
        if !integrity.valid {
            return Ok(vec![Self::failure(integrity.reason.unwrap_or_default())]);
        }
        Self::verify_signatures(
            &envelope,
            &original,
            public_keys,
            p.handler.name(),
            options.expected_signer_id.as_deref(),
            options.now,
        )
    }

    pub fn verify_detached_with_key(
        file: &[u8],
        envelope: EnvelopeInput,
        key: &MajikKey,
        options: Option<&VerifyFileOptions>,
    ) -> R<Vec<VerificationResult>> {
        let keys = MajikSignature::public_keys_from_majik_key(key)?;
        Self::verify_detached(file, envelope, &keys, options)
    }

    /// Verify extracted files against a `.mjksmap`. Reports a per-file status instead of
    /// failing — missing, tampered or invalid files are normal outcomes to display.
    pub fn verify_files_from_mjksmap(
        map: &MajikSignatureMap,
        files: &[BatchVerifyInput],
        public_keys: &MajikSignerPublicKeys,
        options: Option<&BatchVerifyOptions>,
    ) -> R<Vec<FileVerifyResult>> {
        let default_opts = BatchVerifyOptions::default();
        let options = options.unwrap_or(&default_opts);
        let mut results = Vec::new();

        for file in files {
            let resolved = map.resolve_entry(&file.path, &file.blob);
            if resolved.status == MjksMapResolveStatus::NotFound {
                if options.require_all_present {
                    return Err(MajikSignatureError::new(format!(
                        "File \"{}\" was not found in the signature map.",
                        file.path
                    )));
                }
                results.push(FileVerifyResult {
                    path: file.path.clone(),
                    status: FileVerifyStatus::NotInMap,
                    results: None,
                    reason: Some(format!(
                        "No signature entry found for \"{}\" (checked by path and by content).",
                        file.path
                    )),
                    relocated_from: None,
                });
                continue;
            }
            if resolved.status == MjksMapResolveStatus::PathTampered {
                results.push(FileVerifyResult {
                    path: file.path.clone(),
                    status: FileVerifyStatus::Tampered,
                    results: None,
                    reason: Some(
                        "File content no longer matches what was signed — it may have been modified after signing."
                            .into(),
                    ),
                    relocated_from: None,
                });
                continue;
            }

            let entry = resolved.entry.as_ref().expect("resolved entry present for matched status");
            let envelope = MajikSignatureEnvelope::from_json(&entry.envelope)?;
            let integrity = envelope.verify_allowlist_integrity();
            let relocated_from = if resolved.status == MjksMapResolveStatus::Relocated {
                resolved.original_path.clone()
            } else {
                None
            };

            if !integrity.valid {
                results.push(FileVerifyResult {
                    path: file.path.clone(),
                    status: FileVerifyStatus::Invalid,
                    results: None,
                    reason: integrity.reason,
                    relocated_from,
                });
                continue;
            }
            let verify_results = Self::verify_signatures(
                &envelope,
                &file.blob,
                public_keys,
                "mjksmap",
                options.expected_signer_id.as_deref(),
                options.now,
            )?;
            let all_valid = verify_results.iter().all(|r| r.valid);
            let reason = match (&relocated_from, all_valid) {
                (Some(from), true) => {
                    Some(format!("Verified by content match — originally signed as \"{from}\"."))
                }
                _ => None,
            };
            results.push(FileVerifyResult {
                path: file.path.clone(),
                status: if all_valid { FileVerifyStatus::Verified } else { FileVerifyStatus::Invalid },
                results: Some(verify_results),
                reason,
                relocated_from,
            });
        }
        Ok(results)
    }

    pub fn verify_files_from_mjksmap_with_key(
        map: &MajikSignatureMap,
        files: &[BatchVerifyInput],
        key: &MajikKey,
        options: Option<&BatchVerifyOptions>,
    ) -> R<Vec<FileVerifyResult>> {
        let keys = MajikSignature::public_keys_from_majik_key(key)?;
        Self::verify_files_from_mjksmap(map, files, &keys, options)
    }

    pub fn summarize_batch_verification(results: &[FileVerifyResult]) -> BatchVerifySummary {
        let mut s = BatchVerifySummary { total: results.len(), ..Default::default() };
        for r in results {
            match r.status {
                FileVerifyStatus::Verified => s.verified += 1,
                FileVerifyStatus::Invalid => s.invalid += 1,
                FileVerifyStatus::Tampered => s.tampered += 1,
                FileVerifyStatus::NotInMap => s.not_in_map += 1,
            }
        }
        s.all_valid = s.verified == s.total && s.total > 0;
        s
    }

    // ── ORDER / CHAIN / REVISIONS ────────────────────────────────────────────

    pub fn verify_file_order(
        file: &[u8],
        expected_order: &[OrderEntry<'_>],
        options: Option<&OrderOptions>,
    ) -> R<SignatureOrderResult> {
        let default_opts = OrderOptions::default();
        let options = options.unwrap_or(&default_opts);
        let p = Self::prepare_mime(file, options.mime_type.as_deref());
        let raw = p.handler.extract(p.bytes)?.filter(|r| !r.is_empty());

        let (envelope, original) = match &raw {
            Some(raw) => {
                let envelope = parse_embedded_envelope(raw)?;
                let integrity = envelope.verify_allowlist_integrity();
                if !integrity.valid {
                    return Err(MajikSignatureError::new(
                        integrity.reason.unwrap_or_else(|| "Allowlist integrity check failed".into()),
                    ));
                }
                match assert_canonical(p.handler, p.bytes, raw) {
                    CanonicalResult::Ok { original } => (envelope, original),
                    CanonicalResult::Err { reason } => return Err(MajikSignatureError::new(reason)),
                }
            }
            None => (MajikSignatureEnvelope::empty(), p.bytes.to_vec()),
        };
        verify_signature_order(
            &envelope,
            &original,
            expected_order,
            &|content, sig, pk| MajikSignature::verify(content, sig, pk, None),
            Some(VerifySignatureOrderOptions { strict: options.strict }),
        )
    }

    pub fn verify_detached_order(
        file: &[u8],
        envelope: EnvelopeInput,
        expected_order: &[OrderEntry<'_>],
        options: Option<&OrderOptions>,
    ) -> R<SignatureOrderResult> {
        let default_opts = OrderOptions::default();
        let options = options.unwrap_or(&default_opts);
        let p = Self::prepare_mime(file, options.mime_type.as_deref());
        let envelope = MajikSignatureEnvelope::from_input(envelope)?;
        let integrity = envelope.verify_allowlist_integrity();
        if !integrity.valid {
            return Err(MajikSignatureError::new(
                integrity.reason.unwrap_or_else(|| "Allowlist integrity check failed".into()),
            ));
        }
        let prepared = prepare_detached_bytes(
            p.handler,
            p.bytes,
            &DetachedPrepareOptions {
                require_canonical: false,
                validate_envelope: &|raw| parse_embedded_envelope(raw).map(|_| ()),
            },
        )?;
        let original = match prepared {
            CanonicalResult::Ok { original } => original,
            CanonicalResult::Err { reason } => return Err(MajikSignatureError::new(reason)),
        };
        verify_signature_order(
            &envelope,
            &original,
            expected_order,
            &|content, sig, pk| MajikSignature::verify(content, sig, pk, None),
            Some(VerifySignatureOrderOptions { strict: options.strict }),
        )
    }

    /// Verify the latest signature fully and every earlier revision by commitment.
    pub fn verify_file_chain(
        file: &[u8],
        mime_type: Option<&str>,
        now: Option<Timestamp>,
    ) -> R<FileChainVerification> {
        let p = Self::prepare_mime(file, mime_type);
        let raw =
            p.handler.extract(p.bytes)?.filter(|r| !r.is_empty()).ok_or_else(|| {
                MajikSignatureError::new("Cannot verify chain — no embedded envelope found.")
            })?;
        let envelope = parse_embedded_envelope(&raw)?;
        let original = match assert_canonical(p.handler, p.bytes, &raw) {
            CanonicalResult::Ok { original } => original,
            CanonicalResult::Err { reason } => return Err(MajikSignatureError::new(reason)),
        };
        let allowlist_integrity = envelope.verify_allowlist_integrity();
        let chain_integrity = envelope.verify_version_chain_integrity();
        let checked = Self::verify_envelope_self_contained(&envelope, &original, now)?;
        Ok(FileChainVerification {
            chain_valid: allowlist_integrity.valid && chain_integrity.valid && checked.ok,
            latest: checked.latest,
            history: checked.history,
        })
    }

    /// Verify a set of saved revisions against the final file's `fileVersions` chain.
    pub fn verify_file_revisions(
        final_file: &[u8],
        revisions: &[&[u8]],
        options: Option<&VerifyRevisionsOptions<'_>>,
    ) -> R<RevisionSetVerification> {
        let default_opts = VerifyRevisionsOptions::default();
        let options = options.unwrap_or(&default_opts);
        let p = Self::prepare_mime(final_file, options.mime_type.as_deref());
        let raw = p.handler.extract(p.bytes)?.filter(|r| !r.is_empty()).ok_or_else(|| {
            MajikSignatureError::new("Cannot verify revisions — no embedded envelope found.")
        })?;
        let envelope = parse_embedded_envelope(&raw)?;
        let chain = envelope.file_versions();
        if chain.is_empty() {
            return Err(MajikSignatureError::new("This file has no fileVersions chain to verify against."));
        }

        struct Normalized {
            stripped: Vec<u8>,
            content_hash: String,
        }
        let mut normalized: Vec<Normalized> = Vec::new();
        for input in revisions.iter().copied().chain(std::iter::once(final_file)) {
            let rp = Self::prepare(input, None);
            let r_raw = rp.handler.extract(rp.bytes)?;
            let stripped = match r_raw {
                Some(r) => match assert_canonical(rp.handler, rp.bytes, &r) {
                    CanonicalResult::Ok { original } => original,
                    CanonicalResult::Err { .. } => continue,
                },
                None => rp.handler.strip(rp.bytes)?,
            };
            normalized.push(Normalized { content_hash: bytes_to_base64(&hash_content(&stripped)), stripped });
        }

        let mut results: Vec<RevisionCheckResult> = Vec::new();
        for (i, entry) in chain.iter().enumerate() {
            let Some(m) = normalized.iter().find(|r| r.content_hash == entry.content_hash) else {
                results.push(RevisionCheckResult {
                    version: entry.version,
                    status: RevisionCheckStatus::Unmatched,
                    signer_id: None,
                    reason: Some(format!("No supplied file matches fileVersions[{i}].")),
                });
                continue;
            };
            let expected_prev = if i == 0 {
                None
            } else {
                Some(MajikSignatureEnvelope::hash_file_version_entry(&chain[i - 1]))
            };
            if entry.previous_version_hash != expected_prev {
                results.push(RevisionCheckResult {
                    version: entry.version,
                    status: RevisionCheckStatus::ChainBroken,
                    signer_id: None,
                    reason: Some(format!("fileVersions[{i}] does not chain onto the prior entry.")),
                });
                continue;
            }
            let expected_chain_hash = MajikSignatureEnvelope::hash_file_version_chain(&chain[..=i]);
            let sig = envelope.signatures().iter().find(|s| {
                s.content_hash == entry.content_hash
                    && match entry.created_by.as_deref().filter(|c| !c.is_empty()) {
                        Some(by) => s.signer_id == by,
                        None => true,
                    }
                    && match s.version_chain_hash.as_deref().filter(|h| !h.is_empty()) {
                        Some(h) => h == expected_chain_hash,
                        None => true,
                    }
            });
            let Some(sig) = sig else {
                results.push(RevisionCheckResult {
                    version: entry.version,
                    status: RevisionCheckStatus::Unmatched,
                    signer_id: None,
                    reason: Some(format!("No signature matches fileVersions[{i}].")),
                });
                continue;
            };
            if let Some(h) = sig.version_chain_hash.as_deref().filter(|h| !h.is_empty()) {
                if h != expected_chain_hash {
                    results.push(RevisionCheckResult {
                        version: entry.version,
                        status: RevisionCheckStatus::ChainBroken,
                        signer_id: Some(sig.signer_id.clone()),
                        reason: Some("versionChainHash does not match this revision's chain state.".into()),
                    });
                    continue;
                }
            }
            let public_keys = match options.resolve_public_keys {
                Some(resolve) => resolve(&sig.signer_id)?,
                None => MajikSignerPublicKeys {
                    signer_id: sig.signer_id.clone(),
                    ed_public_key: base64_to_bytes(&sig.signer_ed_public_key)?,
                    ml_dsa_public_key: base64_to_bytes(&sig.signer_ml_dsa_public_key)?,
                },
            };
            let vr = MajikSignature::verify(&m.stripped, sig, &public_keys, options.now)?;
            results.push(RevisionCheckResult {
                version: entry.version,
                status: if vr.valid {
                    RevisionCheckStatus::Verified
                } else {
                    RevisionCheckStatus::SignatureInvalid
                },
                signer_id: Some(sig.signer_id.clone()),
                reason: vr.reason,
            });
        }
        Ok(RevisionSetVerification {
            all_valid: results.len() == chain.len()
                && results.iter().all(|r| r.status == RevisionCheckStatus::Verified),
            is_complete_set: results.iter().all(|r| r.status != RevisionCheckStatus::Unmatched),
            results,
        })
    }

    // ── SEAL ─────────────────────────────────────────────────────────────────

    /// Seal an embedded envelope (issuer only when an allowlist exists).
    pub fn seal(
        file: &[u8],
        key: &MajikKey,
        mime_type: Option<&str>,
        timestamp: Option<&str>,
    ) -> R<SealResult> {
        let p = Self::prepare_mime(file, mime_type);
        let raw =
            p.handler.extract(p.bytes)?.filter(|r| !r.is_empty()).ok_or_else(|| {
                MajikSignatureError::new("Cannot seal an unsigned file — no envelope found.")
            })?;
        let envelope = parse_embedded_envelope(&raw)?;
        let sealed = envelope.with_seal(key.fingerprint(), timestamp)?;
        let original = p.handler.strip(p.bytes)?;
        let result = p.handler.embed(&original, &serialize_embedded_envelope(&sealed)?)?;
        Ok(SealResult {
            blob: result,
            seal_info: sealed.get_seal_info().expect("freshly sealed envelope has seal info"),
            handler: p.handler.name().to_string(),
            mime_type: p.mime_type,
        })
    }

    pub fn verify_seal(file: &[u8], options: Option<&ExtractOptions>) -> R<SealVerificationResult> {
        Ok(match Self::extract(file, options)? {
            None => SealVerificationResult {
                valid: false,
                reason: Some("No embedded envelope found".into()),
                ..Default::default()
            },
            Some(r) => r.envelope.verify_seal(),
        })
    }

    pub fn get_seal_info(file: &[u8], options: Option<&ExtractOptions>) -> R<Option<SealInfo>> {
        Ok(Self::extract(file, options)?.and_then(|r| r.envelope.get_seal_info()))
    }

    pub fn is_sealed(file: &[u8], options: Option<&ExtractOptions>) -> R<bool> {
        Ok(Self::extract(file, options)?.map(|r| r.envelope.is_sealed()).unwrap_or(false))
    }

    pub fn is_multi_sig(file: &[u8], options: Option<&ExtractOptions>) -> R<bool> {
        Ok(Self::extract(file, options)?.map(|r| r.envelope.is_multi_sig()).unwrap_or(false))
    }

    pub fn can_sign(
        file: &[u8],
        key: &MajikKey,
        options: Option<&ExtractOptions>,
    ) -> R<crate::core::envelope::CanSignResult> {
        Ok(match Self::extract(file, options)? {
            None => crate::core::envelope::CanSignResult { permitted: true, reason: None },
            Some(r) => r.envelope.can_sign(key),
        })
    }

    pub fn get_signatories(
        file: &[u8],
        options: Option<&ExtractOptions>,
        filter: Option<SignatoriesFilter>,
    ) -> R<Option<SignatoriesResult>> {
        Ok(Self::extract(file, options)?.and_then(|r| r.envelope.get_signatories(filter)))
    }

    pub fn get_issuer(file: &[u8], options: Option<&ExtractOptions>) -> R<Option<SignatoryInfo>> {
        Ok(Self::extract(file, options)?.and_then(|r| r.envelope.resolve_issuer()))
    }

    pub fn get_envelope_info(file: &[u8], options: Option<&ExtractOptions>) -> R<Option<EnvelopeInfo>> {
        Ok(Self::extract(file, options)?.map(|r| r.envelope.get_envelope_info()))
    }

    /// The file with any embedded envelope removed (exactly what was originally signed).
    pub fn strip(file: &[u8], options: Option<&ExtractOptions>) -> R<Vec<u8>> {
        let p = Self::prepare_mime(file, options.and_then(|o| o.mime_type.as_deref()));
        p.handler.strip(p.bytes)
    }

    pub fn has_signature(file: &[u8], options: Option<&ExtractOptions>) -> R<bool> {
        Ok(Self::extract(file, options)?.is_some())
    }

    pub fn get_allowlist(file: &[u8], options: Option<&ExtractOptions>) -> R<Option<Vec<ExpectedSigner>>> {
        Ok(Self::extract(file, options)?.and_then(|r| r.envelope.allowlist().map(|a| a.to_vec())))
    }

    /// The default handler registry.
    pub fn registry() -> &'static FormatHandlerRegistry {
        default_registry()
    }

    pub fn list_handlers() -> Vec<String> {
        default_registry().list_handlers()
    }

    // ── CHAIN ANCHORS ────────────────────────────────────────────────────────

    pub fn can_anchor(
        file: &[u8],
        options: Option<&ExtractOptions>,
    ) -> R<crate::core::envelope::CanAnchorResult> {
        Ok(match Self::extract(file, options)? {
            None => crate::core::envelope::CanAnchorResult {
                permitted: false,
                reason: Some("Cannot anchor an unsigned file — no envelope found.".into()),
            },
            Some(r) => r.envelope.can_anchor(),
        })
    }

    pub fn register_chain_anchor(
        file: &[u8],
        anchor: MajikChainAnchor,
        options: Option<&ExtractOptions>,
    ) -> R<EmbedResult> {
        let p = Self::prepare_mime(file, options.and_then(|o| o.mime_type.as_deref()));
        let raw = p.handler.extract(p.bytes)?.filter(|r| !r.is_empty()).ok_or_else(|| {
            MajikSignatureError::new(
                "Cannot register a chain anchor on an unsigned file — no envelope found.",
            )
        })?;
        let envelope = parse_embedded_envelope(&raw)?;
        let next = envelope.with_chain_anchor(anchor)?;
        let original = p.handler.strip(p.bytes)?;
        let result = p.handler.embed(&original, &serialize_embedded_envelope(&next)?)?;
        Ok(EmbedResult { blob: result, handler: p.handler.name().to_string(), mime_type: p.mime_type })
    }

    pub fn get_chain_anchors(file: &[u8], options: Option<&ExtractOptions>) -> R<Vec<MajikChainAnchor>> {
        Ok(Self::extract(file, options)?.map(|r| r.envelope.chain_anchors().to_vec()).unwrap_or_default())
    }

    // ── private helpers ──────────────────────────────────────────────────────

    fn prepare<'a>(file: &'a [u8], options: Option<&EmbedOptions>) -> Prepared<'a> {
        let mime = options.and_then(|o| o.mime_type.as_deref());
        let mime_type = mime.map(str::to_string).unwrap_or_else(|| detect_mime_type(file, None));
        let handler: &'static dyn FormatHandler = if options.map(|o| o.force_fallback).unwrap_or(false) {
            &FALLBACK
        } else {
            default_registry().resolve(file, Some(&mime_type))
        };
        Prepared { bytes: file, mime_type, handler }
    }

    fn prepare_mime<'a>(file: &'a [u8], mime_type: Option<&str>) -> Prepared<'a> {
        Self::prepare(
            file,
            Some(&EmbedOptions { mime_type: mime_type.map(str::to_string), force_fallback: false }),
        )
    }

    fn read_envelope(handler: &dyn FormatHandler, bytes: &[u8]) -> R<MajikSignatureEnvelope> {
        match handler.extract(bytes)?.filter(|r| !r.is_empty()) {
            Some(raw) => parse_embedded_envelope(&raw),
            None => Ok(MajikSignatureEnvelope::empty()),
        }
    }

    fn no_signature_result(reason: Option<String>) -> VerificationResult {
        VerificationResult {
            valid: false,
            reason: Some(reason.unwrap_or_else(|| "No embedded signature found".into())),
            timestamp: now_iso(),
            ..Default::default()
        }
    }

    fn failure(reason: impl Into<String>) -> VerificationResult {
        VerificationResult {
            valid: false,
            reason: Some(reason.into()),
            timestamp: now_iso(),
            ..Default::default()
        }
    }

    fn verify_signatures(
        envelope: &MajikSignatureEnvelope,
        original: &[u8],
        public_keys: &MajikSignerPublicKeys,
        handler_name: &str,
        expected_signer_id: Option<&str>,
        now: Option<Timestamp>,
    ) -> R<Vec<VerificationResult>> {
        let expected = expected_signer_id.filter(|s| !s.is_empty());
        let sigs: Vec<&MajikSignatureJSON> = match expected {
            Some(id) => envelope.signatures().iter().filter(|s| s.signer_id == id).collect(),
            None => envelope.signatures().iter().collect(),
        };
        if sigs.is_empty() {
            return Ok(vec![Self::failure(match expected {
                Some(id) => format!("No signature found for signerId \"{id}\""),
                None => "Envelope contains no signatures".to_string(),
            })]);
        }
        sigs.into_iter()
            .map(|sig| {
                let mut r = MajikSignature::verify(original, sig, public_keys, now)?;
                r.handler = Some(handler_name.to_string());
                Ok(r)
            })
            .collect()
    }
}

struct SelfContained {
    latest: VerificationResult,
    history: Vec<RevisionCommitmentResult>,
    ok: bool,
}
