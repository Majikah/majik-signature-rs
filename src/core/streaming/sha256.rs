//! Incremental SHA-256 helpers. Chunk boundaries are not part of the digest.

use std::io::{Cursor, Read};
use std::sync::atomic::Ordering;

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::core::errors::{MajikSignatureError, MajikSignatureResult};

use super::config::validate_chunk_size;
use super::strategy::{detect_hash_strategy, HashStrategy};
use super::types::{StreamingHashOptions, StreamingHashProgress, StreamingHashResult};

type R<T> = MajikSignatureResult<T>;

fn cancelled(options: &StreamingHashOptions<'_>) -> bool {
    options.cancellation.map(|flag| flag.load(Ordering::Acquire)).unwrap_or(false)
}

/// Hash any reader incrementally using one SHA-256 state.
///
/// The reader is consumed from its current position to EOF. No per-chunk
/// prefix, delimiter, or intermediate digest is added to the message.
pub fn hash_reader<Rd: Read>(
    reader: &mut Rd,
    options: &mut StreamingHashOptions<'_>,
) -> R<StreamingHashResult> {
    if !validate_chunk_size(options.chunk_size) {
        return Err(MajikSignatureError::validation(
            format!(
                "chunk_size must be between {} and {} bytes",
                super::config::MIN_HASH_CHUNK_SIZE,
                super::config::MAX_HASH_CHUNK_SIZE
            ),
            Some("chunk_size"),
        ));
    }
    if let (Some(max), Some(total)) = (options.max_bytes, options.total_bytes) {
        if total > max {
            return Err(MajikSignatureError::validation(
                format!("Input exceeds the configured maximum of {max} bytes"),
                Some("max_bytes"),
            ));
        }
    }

    let mut hasher = Sha256::new();
    // Reserve the full buffer before touching the input stream. This makes allocation
    // failure a recoverable error instead of relying on infallible Vec allocation.
    let mut allocation = Vec::new();
    allocation.try_reserve_exact(options.chunk_size).map_err(|error| {
        MajikSignatureError::with_cause(
            format!(
                "Unable to allocate the {}-byte streaming hash buffer",
                options.chunk_size
            ),
            error,
        )
    })?;
    allocation.resize(options.chunk_size, 0);
    let mut buffer = Zeroizing::new(allocation);
    let mut bytes_processed = 0u64;

    loop {
        if cancelled(options) {
            return Err(MajikSignatureError::validation(
                "Streaming hash was cancelled",
                Some("cancellation"),
            ));
        }

        let count = match reader.read(&mut buffer[..]) {
            Ok(0) => break,
            Ok(count) => count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => {
                return Err(MajikSignatureError::with_cause("Failed to read content stream", error));
            }
        };

        let count_u64 = u64::try_from(count).map_err(|_| {
            MajikSignatureError::validation("Read size exceeds the supported range", Some("source"))
        })?;
        let next = bytes_processed
            .checked_add(count_u64)
            .ok_or_else(|| MajikSignatureError::validation("Input byte count overflowed", Some("source")))?;

        if let Some(max_bytes) = options.max_bytes {
            if next > max_bytes {
                return Err(MajikSignatureError::validation(
                    format!("Input exceeds the configured maximum of {max_bytes} bytes"),
                    Some("max_bytes"),
                ));
            }
        }

        hasher.update(&buffer[..count]);
        bytes_processed = next;

        if let Some(callback) = options.on_progress.as_deref_mut() {
            callback(StreamingHashProgress { bytes_processed, total_bytes: options.total_bytes });
        }
    }

    if let Some(expected) = options.total_bytes {
        if bytes_processed != expected {
            return Err(MajikSignatureError::validation(
                format!("Stream length mismatch: expected {expected} bytes, read {bytes_processed}"),
                Some("total_bytes"),
            ));
        }
    }

    Ok(StreamingHashResult {
        digest: hasher.finalize().into(),
        bytes_processed,
        strategy: HashStrategy::Streaming,
        total_bytes: options.total_bytes,
    })
}

/// Hash a byte slice using the same automatic threshold policy as the TS engine.
pub fn hash_bytes_auto(bytes: &[u8], options: &mut StreamingHashOptions<'_>) -> R<StreamingHashResult> {
    if !validate_chunk_size(options.chunk_size) {
        return Err(MajikSignatureError::validation(
            format!(
                "chunk_size must be between {} and {} bytes",
                super::config::MIN_HASH_CHUNK_SIZE,
                super::config::MAX_HASH_CHUNK_SIZE
            ),
            Some("chunk_size"),
        ));
    }

    let size = u64::try_from(bytes.len()).map_err(|_| {
        MajikSignatureError::validation("Input size exceeds the supported range", Some("source"))
    })?;
    if let Some(max_bytes) = options.max_bytes {
        if size > max_bytes {
            return Err(MajikSignatureError::validation(
                format!("Input exceeds the configured maximum of {max_bytes} bytes"),
                Some("max_bytes"),
            ));
        }
    }

    let strategy = detect_hash_strategy(Some(size), options.threshold_bytes);
    if strategy == HashStrategy::Buffered {
        if cancelled(options) {
            return Err(MajikSignatureError::validation(
                "Streaming hash was cancelled",
                Some("cancellation"),
            ));
        }
        if let Some(callback) = options.on_progress.as_deref_mut() {
            if size > 0 {
                callback(StreamingHashProgress { bytes_processed: size, total_bytes: Some(size) });
            }
        }
        return Ok(StreamingHashResult {
            digest: Sha256::digest(bytes).into(),
            bytes_processed: size,
            strategy,
            total_bytes: Some(size),
        });
    }

    options.total_bytes = Some(size);
    let mut reader = Cursor::new(bytes);
    hash_reader(&mut reader, options)
}
