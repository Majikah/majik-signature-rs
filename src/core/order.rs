//! Port of `core/order.ts` — signing-order verification for multi-signer files.

use std::collections::{HashMap, HashSet};

use majik_key::MajikKey;
use serde::Serialize;

use crate::core::envelope::MajikSignatureEnvelope;
use crate::core::errors::{MajikSignatureError, MajikSignatureResult};
use crate::core::hash::base64_to_bytes;
use crate::core::time::parse_iso_millis;
use crate::core::types::*;
use crate::majik_signature::signing_public_keys_b64;

type R<T> = MajikSignatureResult<T>;

/// Where a signer's effective timestamp came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TimestampSource {
    /// Server-attested by a Trusted Timestamp Authority.
    Tsa,
    /// The signer's own (unattested) clock.
    #[serde(rename = "self")]
    SelfReported,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignerOrderStatus {
    pub signer_id: String,
    pub expected_position: usize,
    pub has_signed: bool,
    pub valid: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub effective_timestamp: Option<String>,
    pub timestamp_source: Option<TimestampSource>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrderViolation {
    pub earlier: String,
    pub later: String,
    pub earlier_timestamp: String,
    pub later_timestamp: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SoftTieWarning {
    pub a: String,
    pub b: String,
    pub timestamp: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignatureOrderResult {
    pub valid: bool,
    pub all_expected_signed: bool,
    pub all_valid: bool,
    pub order_respected: bool,
    pub strict: bool,
    pub unexpected_signers: Vec<String>,
    pub pending_signers: Vec<String>,
    pub invalid_signers: Vec<String>,
    pub violations: Vec<OrderViolation>,
    pub uses_unattested_timestamp: bool,
    pub soft_tie_warnings: Vec<SoftTieWarning>,
    pub signers: Vec<SignerOrderStatus>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct VerifySignatureOrderOptions {
    pub strict: bool,
}

/// TS `MajikKey | ExpectedSigner`.
#[derive(Clone, Copy)]
pub enum OrderEntry<'a> {
    Key(&'a MajikKey),
    Signer(&'a ExpectedSigner),
}

impl<'a> From<&'a MajikKey> for OrderEntry<'a> {
    fn from(k: &'a MajikKey) -> Self {
        Self::Key(k)
    }
}
impl<'a> From<&'a ExpectedSigner> for OrderEntry<'a> {
    fn from(s: &'a ExpectedSigner) -> Self {
        Self::Signer(s)
    }
}

/// The per-signature verifier injected by the caller (keeps this module free of a hard
/// dependency on `MajikSignature`).
pub type OrderVerifyFn<'a> =
    dyn Fn(&[u8], &MajikSignatureJSON, &MajikSignerPublicKeys) -> R<VerificationResult> + 'a;

fn to_expected_signer(input: &OrderEntry<'_>) -> R<ExpectedSigner> {
    match input {
        OrderEntry::Signer(s) => Ok((*s).clone()),
        OrderEntry::Key(key) => {
            let (ed, ml) = signing_public_keys_b64(key).map_err(|_| {
                MajikSignatureError::key(
                    "MajikKey has no signing public keys — cannot build expected order entry.",
                )
            })?;
            Ok(ExpectedSigner {
                signer_id: key.fingerprint().to_string(),
                ed_public_key: ed,
                ml_dsa_public_key: ml,
            })
        }
    }
}

/// Normalise a mixed list of keys / expected signers into plain [`ExpectedSigner`]s.
pub fn normalize_expected_order(input: &[OrderEntry<'_>]) -> R<Vec<ExpectedSigner>> {
    input.iter().map(to_expected_signer).collect()
}

/// A TSA-attested timestamp is preferred; otherwise the signer's own clock is used.
pub fn resolve_effective_timestamp(sig: &MajikSignatureJSON) -> (String, TimestampSource) {
    if let Some(tsa) = &sig.tsa {
        if !tsa.payload.timestamp.is_empty() {
            return (tsa.payload.timestamp.clone(), TimestampSource::Tsa);
        }
    }
    (sig.timestamp.clone(), TimestampSource::SelfReported)
}

/// Verify that signatures in `envelope` were produced in `expected_order`.
pub fn verify_signature_order(
    envelope: &MajikSignatureEnvelope,
    original_bytes: &[u8],
    expected_order: &[OrderEntry<'_>],
    verify_fn: &OrderVerifyFn<'_>,
    options: Option<VerifySignatureOrderOptions>,
) -> R<SignatureOrderResult> {
    let strict = options.map(|o| o.strict).unwrap_or(false);
    let normalized = normalize_expected_order(expected_order)?;

    if normalized.is_empty() {
        return Err(MajikSignatureError::validation(
            "expectedOrder must contain at least one signer.",
            Some("expectedOrder"),
        ));
    }
    let mut seen_ids: HashSet<&str> = HashSet::new();
    for e in &normalized {
        if !seen_ids.insert(e.signer_id.as_str()) {
            return Err(MajikSignatureError::validation(
                format!("Duplicate signerId in expectedOrder: \"{}\"", e.signer_id),
                Some("expectedOrder"),
            ));
        }
    }

    // Later duplicates win, as with `new Map(entries)` in TS.
    let sigs_by_id: HashMap<&str, &MajikSignatureJSON> =
        envelope.signatures().iter().map(|s| (s.signer_id.as_str(), s)).collect();

    let mut signers: Vec<SignerOrderStatus> = Vec::new();
    let mut pending: Vec<String> = Vec::new();
    let mut invalid: Vec<String> = Vec::new();
    let mut uses_unattested = false;

    struct Considered {
        signer_id: String,
        timestamp: String,
        time_ms: Option<i64>,
    }
    let mut considered: Vec<Considered> = Vec::new();

    for (i, expected) in normalized.iter().enumerate() {
        let Some(sig) = sigs_by_id.get(expected.signer_id.as_str()) else {
            pending.push(expected.signer_id.clone());
            signers.push(SignerOrderStatus {
                signer_id: expected.signer_id.clone(),
                expected_position: i,
                has_signed: false,
                valid: None,
                reason: None,
                effective_timestamp: None,
                timestamp_source: None,
            });
            continue;
        };

        let public_keys = MajikSignerPublicKeys {
            signer_id: expected.signer_id.clone(),
            ed_public_key: base64_to_bytes(&expected.ed_public_key)?,
            ml_dsa_public_key: base64_to_bytes(&expected.ml_dsa_public_key)?,
        };
        let result = verify_fn(original_bytes, sig, &public_keys)?;
        let (timestamp, source) = resolve_effective_timestamp(sig);

        if !result.valid {
            invalid.push(expected.signer_id.clone());
            signers.push(SignerOrderStatus {
                signer_id: expected.signer_id.clone(),
                expected_position: i,
                has_signed: true,
                valid: Some(false),
                reason: result.reason,
                effective_timestamp: Some(timestamp),
                timestamp_source: Some(source),
            });
            continue;
        }

        if source == TimestampSource::SelfReported {
            uses_unattested = true;
        }
        signers.push(SignerOrderStatus {
            signer_id: expected.signer_id.clone(),
            expected_position: i,
            has_signed: true,
            valid: Some(true),
            reason: None,
            effective_timestamp: Some(timestamp.clone()),
            timestamp_source: Some(source),
        });
        considered.push(Considered {
            signer_id: expected.signer_id.clone(),
            time_ms: parse_iso_millis(&timestamp),
            timestamp,
        });
    }

    let mut violations: Vec<OrderViolation> = Vec::new();
    let mut soft_ties: Vec<SoftTieWarning> = Vec::new();
    for i in 0..considered.len() {
        for j in (i + 1)..considered.len() {
            let (a, b) = (&considered[i], &considered[j]);
            // An unparseable timestamp (NaN in JS) is neither a violation nor a tie.
            if let (Some(ta), Some(tb)) = (a.time_ms, b.time_ms) {
                if ta > tb {
                    violations.push(OrderViolation {
                        earlier: a.signer_id.clone(),
                        later: b.signer_id.clone(),
                        earlier_timestamp: a.timestamp.clone(),
                        later_timestamp: b.timestamp.clone(),
                    });
                } else if ta == tb {
                    soft_ties.push(SoftTieWarning {
                        a: a.signer_id.clone(),
                        b: b.signer_id.clone(),
                        timestamp: a.timestamp.clone(),
                    });
                }
            }
        }
    }

    let mut unexpected: Vec<String> = Vec::new();
    if strict {
        for sig in envelope.signatures() {
            if !seen_ids.contains(sig.signer_id.as_str()) {
                unexpected.push(sig.signer_id.clone());
            }
        }
    }

    let all_expected_signed = pending.is_empty();
    let all_valid = invalid.is_empty();
    let order_respected = violations.is_empty();
    let strict_satisfied = !strict || unexpected.is_empty();
    let valid = all_expected_signed && all_valid && order_respected && strict_satisfied;

    let reason = if !all_expected_signed {
        Some(format!("Missing signature(s) from: {}", pending.join(", ")))
    } else if !all_valid {
        Some(format!("Invalid signature(s) from: {}", invalid.join(", ")))
    } else if !strict_satisfied {
        Some(format!("Unexpected signer(s) present (strict mode): {}", unexpected.join(", ")))
    } else if !order_respected {
        Some(format!(
            "Signing order violated: {}",
            violations
                .iter()
                .map(|v| format!("\"{}\" expected before \"{}\" but signed after", v.earlier, v.later))
                .collect::<Vec<_>>()
                .join("; ")
        ))
    } else if !soft_ties.is_empty() {
        Some(format!(
            "All signatures valid and in order, but {} pair(s) share an identical timestamp — order cannot be distinguished for: {}",
            soft_ties.len(),
            soft_ties.iter().map(|w| format!("\"{}\"/\"{}\"", w.a, w.b)).collect::<Vec<_>>().join(", ")
        ))
    } else {
        None
    };

    Ok(SignatureOrderResult {
        valid,
        all_expected_signed,
        all_valid,
        order_respected,
        strict,
        unexpected_signers: unexpected,
        pending_signers: pending,
        invalid_signers: invalid,
        violations,
        uses_unattested_timestamp: uses_unattested,
        soft_tie_warnings: soft_ties,
        signers,
        reason,
    })
}
