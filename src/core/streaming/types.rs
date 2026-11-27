//! Public streaming-hash configuration and result types.

use std::sync::atomic::AtomicBool;

use super::strategy::HashStrategy;

/// Progress after a complete read chunk has been added to the digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Progress snapshot emitted after a chunk has been incorporated into the SHA-256 state.
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

impl<'a> Default for StreamingHashOptions<'a> {
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

/// One input in a streaming detached batch-signing operation.
pub struct StreamingBatchFileInput<'a> {
    pub path: String,
    pub reader: &'a mut dyn std::io::Read,
    pub total_bytes: Option<u64>,
    pub mime_type: Option<String>,
}

/// One file supplied to streaming MJKSMAP verification.
pub struct StreamingBatchVerifyInput<'a> {
    pub path: String,
    pub reader: &'a mut dyn std::io::Read,
    pub total_bytes: Option<u64>,
}

/// Progress associated with one file in a streaming batch.
#[derive(Debug, Clone, PartialEq, Eq)]
/// Progress information for one file inside a sequential streaming batch operation.
pub struct StreamingBatchProgress {
    pub file_index: usize,
    pub total_files: usize,
    pub path: String,
    pub bytes_processed: u64,
    pub total_bytes: Option<u64>,
}

/// Resource and progress settings shared by a streaming batch-signing operation.
pub struct BatchStreamingOptions<'a> {
    pub chunk_size: usize,
    pub max_bytes_per_file: Option<u64>,
    pub cancellation: Option<&'a AtomicBool>,
    pub on_progress: Option<&'a mut dyn FnMut(StreamingBatchProgress)>,
}

impl Default for BatchStreamingOptions<'_> {
    fn default() -> Self {
        Self {
            chunk_size: super::config::DEFAULT_HASH_CHUNK_SIZE,
            max_bytes_per_file: None,
            cancellation: None,
            on_progress: None,
        }
    }
}

/// Result of hashing one complete logical byte sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
/// Final digest, byte count, and selected strategy returned by a streaming hash operation.
pub struct StreamingHashResult {
    /// Raw SHA-256 digest. Identical to the existing one-shot hash for the same bytes.
    pub digest: [u8; 32],
    pub bytes_processed: u64,
    pub strategy: HashStrategy,
    pub total_bytes: Option<u64>,
}
