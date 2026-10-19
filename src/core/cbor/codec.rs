//! Port of `core/cbor/cbor.ts` — standard CBOR bytes ⇄ [`Value`].
//!
//! Ordinary CBOR maps / byte strings only (no record extensions). Application-level
//! validation belongs to [`super::wire`].

use ciborium::value::Value;

/// Structural/schema error raised while encoding or decoding CBOR (TS `TypeError`).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct CborError(pub String);

impl CborError {
    pub(crate) fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}

/// Encode a value as CBOR bytes.
pub fn encode_cbor(value: &Value) -> Result<Vec<u8>, CborError> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(value, &mut out)
        .map_err(|e| CborError::new(format!("CBOR encoding failed: {e}")))?;
    Ok(out)
}

/// Decode exactly one CBOR data item.
///
/// Rejects empty input, a top-level break code, truncated/malformed items and any
/// trailing bytes after the first item.
pub fn decode_cbor(input: &[u8]) -> Result<Value, CborError> {
    if input.is_empty() {
        return Err(CborError::new("CBOR input must not be empty"));
    }
    // 0xff (break) cannot be a standalone top-level item.
    if input[0] == 0xff {
        return Err(CborError::new("Malformed CBOR: break code cannot appear at the top level"));
    }
    let mut rest: &[u8] = input;
    let value: Value =
        ciborium::de::from_reader(&mut rest).map_err(|e| CborError::new(format!("Malformed CBOR: {e}")))?;
    if !rest.is_empty() {
        return Err(CborError::new("Malformed CBOR: unexpected trailing data after the top-level item"));
    }
    Ok(value)
}
