//! Port of `core/embed/embedded-envelope-codec.ts` — centralized codec for envelopes embedded
//! in files.
//!
//! New writes use a version-tagged, Base64-transported CBOR envelope; existing embedded JSON
//! envelopes remain readable. This transport wrapper is separate from the MJKSIG binary
//! container header and from `MAJIK_ENVELOPE_VERSION`.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;

use crate::core::envelope::MajikSignatureEnvelope;
use crate::core::errors::{MajikSignatureError, MajikSignatureResult};

/// Identifies a CBOR-encoded embedded envelope: `MJKSIG:CBOR:<MJKSIG_CBOR_VERSION>:`.
/// Embedded JSON envelopes do not start with this prefix.
pub const EMBEDDED_CBOR_PREFIX: &str = "MJKSIG:CBOR:2:";

/// Serialize an envelope for embedding in a format handler's text payload.
///
/// Base64 is only the transport layer required by the string-based `FormatHandler` API.
pub fn serialize_embedded_envelope(envelope: &MajikSignatureEnvelope) -> MajikSignatureResult<String> {
    let cbor = envelope.to_cbor()?;
    if cbor.is_empty() {
        return Err(MajikSignatureError::serialization("Cannot embed an empty CBOR envelope payload"));
    }
    Ok(format!("{EMBEDDED_CBOR_PREFIX}{}", B64.encode(cbor)))
}

/// Deserialize an embedded payload.
///
/// Prefixed payloads are decoded as CBOR; unprefixed payloads use the legacy JSON parser.
/// An invalid prefixed CBOR payload is rejected — it is never silently retried as JSON.
pub fn parse_embedded_envelope(payload: &str) -> MajikSignatureResult<MajikSignatureEnvelope> {
    // Backward compatibility: old files contain JSON envelope text.
    let Some(encoded) = payload.strip_prefix(EMBEDDED_CBOR_PREFIX) else {
        return MajikSignatureEnvelope::from_json_str(payload);
    };

    if encoded.is_empty() || encoded.len() % 4 != 0 {
        return Err(MajikSignatureError::serialization(
            "Malformed embedded CBOR envelope: invalid Base64 payload",
        ));
    }
    let cbor = B64.decode(encoded).map_err(|e| {
        MajikSignatureError::serialization_with_cause(
            "Malformed embedded CBOR envelope: failed to decode Base64",
            e,
        )
    })?;
    // Require canonical Base64 instead of accepting alternative encodings.
    if B64.encode(&cbor) != encoded {
        return Err(MajikSignatureError::serialization(
            "Malformed embedded CBOR envelope: non-canonical Base64 encoding",
        ));
    }
    MajikSignatureEnvelope::from_cbor(&cbor)
}
