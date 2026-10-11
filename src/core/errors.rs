//! Port of `core/errors.ts` — the MajikSignature error hierarchy.
//!
//! The TS class hierarchy (`MajikSignatureError` and five subclasses) is modelled as a single
//! enum; each TS subclass is one variant. `cause` is kept as an optional boxed source.

use std::error::Error as StdError;
use std::fmt;

pub type BoxedCause = Box<dyn StdError + Send + Sync + 'static>;

#[derive(Debug)]
pub enum MajikSignatureError {
    /// Base `MajikSignatureError`.
    Generic { message: String, cause: Option<BoxedCause> },
    /// `MajikSignatureValidationError` — carries the offending `field`.
    Validation { message: String, field: Option<String>, cause: Option<BoxedCause> },
    /// `MajikSignatureVerificationError`.
    Verification { message: String, cause: Option<BoxedCause> },
    /// `MajikSignatureKeyError`.
    Key { message: String, cause: Option<BoxedCause> },
    /// `MajikSignatureSerializationError`.
    Serialization { message: String, cause: Option<BoxedCause> },
    /// `MajikSignatureAllowlistError` — raised before any cryptographic operation.
    Allowlist { message: String, signer_id: String, cause: Option<BoxedCause> },
}

pub type MajikSignatureResult<T> = Result<T, MajikSignatureError>;

fn boxed<E: StdError + Send + Sync + 'static>(e: E) -> BoxedCause {
    Box::new(e)
}

impl MajikSignatureError {
    pub fn new(message: impl Into<String>) -> Self {
        Self::Generic { message: message.into(), cause: None }
    }
    pub fn with_cause<E: StdError + Send + Sync + 'static>(message: impl Into<String>, cause: E) -> Self {
        Self::Generic { message: message.into(), cause: Some(boxed(cause)) }
    }
    pub fn validation(message: impl Into<String>, field: Option<&str>) -> Self {
        Self::Validation { message: message.into(), field: field.map(str::to_string), cause: None }
    }
    pub fn validation_with_cause(
        message: impl Into<String>,
        field: Option<&str>,
        cause: MajikSignatureError,
    ) -> Self {
        Self::Validation {
            message: message.into(),
            field: field.map(str::to_string),
            cause: Some(Box::new(cause)),
        }
    }
    pub fn verification(message: impl Into<String>) -> Self {
        Self::Verification { message: message.into(), cause: None }
    }
    pub fn key(message: impl Into<String>) -> Self {
        Self::Key { message: message.into(), cause: None }
    }
    pub fn key_with_cause<E: StdError + Send + Sync + 'static>(message: impl Into<String>, cause: E) -> Self {
        Self::Key { message: message.into(), cause: Some(boxed(cause)) }
    }
    pub fn serialization(message: impl Into<String>) -> Self {
        Self::Serialization { message: message.into(), cause: None }
    }
    pub fn serialization_with_cause<E: StdError + Send + Sync + 'static>(
        message: impl Into<String>,
        cause: E,
    ) -> Self {
        Self::Serialization { message: message.into(), cause: Some(boxed(cause)) }
    }
    pub fn allowlist(message: impl Into<String>, signer_id: impl Into<String>) -> Self {
        Self::Allowlist { message: message.into(), signer_id: signer_id.into(), cause: None }
    }

    /// TS `error.name`.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Generic { .. } => "MajikSignatureError",
            Self::Validation { .. } => "MajikSignatureValidationError",
            Self::Verification { .. } => "MajikSignatureVerificationError",
            Self::Key { .. } => "MajikSignatureKeyError",
            Self::Serialization { .. } => "MajikSignatureSerializationError",
            Self::Allowlist { .. } => "MajikSignatureAllowlistError",
        }
    }

    pub fn message(&self) -> &str {
        match self {
            Self::Generic { message, .. }
            | Self::Validation { message, .. }
            | Self::Verification { message, .. }
            | Self::Key { message, .. }
            | Self::Serialization { message, .. }
            | Self::Allowlist { message, .. } => message,
        }
    }

    /// The offending field of a validation error, if any.
    pub fn field(&self) -> Option<&str> {
        match self {
            Self::Validation { field, .. } => field.as_deref(),
            _ => None,
        }
    }

    /// The rejected signer of an allowlist error, if any.
    pub fn signer_id(&self) -> Option<&str> {
        match self {
            Self::Allowlist { signer_id, .. } => Some(signer_id),
            _ => None,
        }
    }
}

impl fmt::Display for MajikSignatureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
    }
}

impl StdError for MajikSignatureError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        let cause = match self {
            Self::Generic { cause, .. }
            | Self::Validation { cause, .. }
            | Self::Verification { cause, .. }
            | Self::Key { cause, .. }
            | Self::Serialization { cause, .. }
            | Self::Allowlist { cause, .. } => cause,
        };
        cause.as_deref().map(|c| c as &(dyn StdError + 'static))
    }
}
