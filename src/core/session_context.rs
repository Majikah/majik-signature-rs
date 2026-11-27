//! Canonical SignRoom session-context commitment helpers.

use serde::Serialize;

use crate::core::constants::MAJIK_SESSION_CONTEXT_DOMAIN;
use crate::core::errors::{MajikSignatureError, MajikSignatureResult};
use crate::core::hash::{base64_to_bytes, bytes_to_base64, hash_content};
use crate::core::text::trim_ecmascript_whitespace;

/// Authoritative values used to bind a SignRoom signature to a signing attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
/// Authoritative session, one-time challenge, and immutable policy values committed by a SignRoom signature.
pub struct MajikSessionSigningContext {
    pub session_id: String,
    pub challenge_id: String,
    /// Canonical base64 SHA-256 digest of the immutable policy snapshot.
    pub policy_hash: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CanonicalSessionContext<'a> {
    v: u8,
    session_id: &'a str,
    challenge_id: &'a str,
    policy_hash: &'a str,
}

fn validate_identifier(value: &str, field: &str) -> MajikSignatureResult<()> {
    if value.is_empty()
        || value.encode_utf16().count() > 256
        || trim_ecmascript_whitespace(value) != value
    {
        return Err(MajikSignatureError::validation(
            format!(
                "{field} must be a non-empty string of at most 256 characters without surrounding whitespace"
            ),
            Some(field),
        ));
    }
    Ok(())
}

fn validate_policy_hash(value: &str) -> MajikSignatureResult<()> {
    if value.len() != 44 {
        return Err(MajikSignatureError::validation(
            "policyHash must be a base64-encoded SHA-256 digest",
            Some("policyHash"),
        ));
    }
    let decoded = base64_to_bytes(value).map_err(|_| {
        MajikSignatureError::validation(
            "policyHash must be a canonical base64-encoded SHA-256 digest",
            Some("policyHash"),
        )
    })?;
    if decoded.len() != 32 || bytes_to_base64(&decoded) != value {
        return Err(MajikSignatureError::validation(
            "policyHash must be a canonical base64-encoded SHA-256 digest",
            Some("policyHash"),
        ));
    }
    Ok(())
}

/// Build the base64 SHA-256 commitment signed by each SignRoom participant.
///
/// Property order and the domain separator are protocol constants shared with TypeScript.
pub fn build_session_context_hash(context: &MajikSessionSigningContext) -> MajikSignatureResult<String> {
    validate_identifier(&context.session_id, "sessionId")?;
    validate_identifier(&context.challenge_id, "challengeId")?;
    validate_policy_hash(&context.policy_hash)?;

    let canonical = CanonicalSessionContext {
        v: 1,
        session_id: &context.session_id,
        challenge_id: &context.challenge_id,
        policy_hash: &context.policy_hash,
    };
    let body = serde_json::to_vec(&canonical).expect("session context serialization is infallible");
    let mut bytes = Vec::with_capacity(MAJIK_SESSION_CONTEXT_DOMAIN.len() + body.len());
    bytes.extend_from_slice(MAJIK_SESSION_CONTEXT_DOMAIN.as_bytes());
    bytes.extend_from_slice(&body);
    Ok(bytes_to_base64(&hash_content(&bytes)))
}

#[cfg(test)]
mod identifier_whitespace_tests {
    use super::validate_identifier;

    #[test]
    fn matches_ecmascript_trim_for_bom_and_next_line() {
        assert!(
            validate_identifier("\u{0085}session\u{0085}", "sessionId").is_ok()
        );
        assert!(validate_identifier("\u{feff}session", "sessionId").is_err());
        assert!(validate_identifier("session\u{feff}", "challengeId").is_err());
    }
}
