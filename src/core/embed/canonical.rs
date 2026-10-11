//! Port of `core/embed/canonical.ts` — canonical-form checks for embedded signatures.
//!
//! A signed file is *canonical* when `embed(strip(bytes), envelope) == bytes`, i.e. it contains
//! nothing outside the signed content and the signature envelope.

use crate::core::embed::utils::buffer_equal;
use crate::core::errors::MajikSignatureResult;
use crate::core::types::FormatHandler;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonicalResult {
    Ok { original: Vec<u8> },
    Err { reason: String },
}

pub fn assert_canonical(handler: &dyn FormatHandler, bytes: &[u8], raw: &str) -> CanonicalResult {
    let attempt = (|| -> MajikSignatureResult<(Vec<u8>, Vec<u8>)> {
        let original = handler.strip(bytes)?;
        let rebuilt = handler.embed(&original, raw)?;
        Ok((original, rebuilt))
    })();
    let (original, rebuilt) = match attempt {
        Ok(v) => v,
        Err(err) => {
            return CanonicalResult::Err {
                reason: format!(
                    "File is not in canonical signed form ({}): {}",
                    handler.name(),
                    err.message()
                ),
            }
        }
    };
    if !buffer_equal(&rebuilt, bytes) {
        return CanonicalResult::Err {
            reason: format!(
                "File is not in canonical signed form ({}): it contains bytes outside the signed content and signature envelope ({} bytes on disk, {} expected). It may have been modified after signing.",
                handler.name(),
                bytes.len(),
                rebuilt.len()
            ),
        };
    }
    CanonicalResult::Ok { original }
}

pub struct DetachedPrepareOptions<'a> {
    pub require_canonical: bool,
    /// Throws if `raw` is not a valid envelope.
    pub validate_envelope: &'a dyn Fn(&str) -> MajikSignatureResult<()>,
}

pub fn prepare_detached_bytes(
    handler: &dyn FormatHandler,
    bytes: &[u8],
    options: &DetachedPrepareOptions<'_>,
) -> MajikSignatureResult<CanonicalResult> {
    let raw = handler.extract(bytes)?;
    if let Some(raw) = raw {
        if (options.validate_envelope)(&raw).is_err() {
            return Ok(CanonicalResult::Err {
                reason: "The file ends with a signature-shaped block that is not a valid envelope; refusing to ignore it. The file may have been modified.".into(),
            });
        }
        return Ok(assert_canonical(handler, bytes, &raw));
    }

    let stripped = handler.strip(bytes)?;
    if options.require_canonical && !buffer_equal(&stripped, bytes) {
        return Ok(CanonicalResult::Err {
            reason: format!(
                "File is not in canonical form for {} ({} bytes on disk, {} canonical). Verify the exact blob returned by signFileDetached().",
                handler.name(),
                bytes.len(),
                stripped.len()
            ),
        });
    }
    Ok(CanonicalResult::Ok { original: stripped })
}

pub fn no_signature_reason(handler: &dyn FormatHandler, bytes: &[u8]) -> String {
    handler.diagnose(bytes).unwrap_or_else(|| "No embedded signature found".to_string())
}
