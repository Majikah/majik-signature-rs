//! Public streaming-hash configuration and result types.

use std::sync::atomic::AtomicBool;

use super::strategy::HashStrategy;

/// Progress after a complete read chunk has been added to the digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamingHashProgress {
    pub bytes_processed: u64,
    pub total_bytes: Option<u64>,
}

/// Options borrowed for one hashing operation.
pub struct StreamingHashOptions<'a> {
    /// Read/update granularity. Defaults to 1 MiB.
    pub chunk_size: usize,
    /// Inputs no larger than this can use the one-shot path when their size is known.
    pub threshold_bytes: u64,
    /// Optional maximum accepted input size. No default file-size ceiling is imposed.
    pub max_bytes: Option<u64>,
    /// Optional expected total size, used for progress and truncation detection.
    pub total_bytes: Option<u64>,
    /// Set to true to cancel between read operations.
    pub cancellation: Option<&'a AtomicBool>,
    /// Optional progress callback.
    pub on_progress: Option<&'a mut dyn FnMut(StreamingHashProgress)>,
}

impl Default for StreamingHashOptions<'_> {
    fn default() -> Self {
        Self {
            chunk_size: super::config::DEFAULT_HASH_CHUNK_SIZE,
            threshold_bytes: super::config::DEFAULT_HASH_STREAMING_THRESHOLD,
            max_bytes: None,
            total_bytes: None,
            cancellation: None,
            on_progress: None,
        }
    }
}

/// Result of hashing one complete logical byte sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamingHashResult {
    /// Raw SHA-256 digest. Identical to the existing one-shot hash for the same bytes.
    pub digest: [u8; 32],
    pub bytes_processed: u64,
    pub strategy: HashStrategy,
    pub total_bytes: Option<u64>,
}
