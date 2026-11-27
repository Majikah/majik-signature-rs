//! Default policy for SHA-256 stream processing.

/// Default read/update granularity for incremental SHA-256 (1 MiB).
pub const DEFAULT_HASH_CHUNK_SIZE: usize = 1024 * 1024;
/// Smallest permitted streaming hash chunk size (64 KiB).
pub const MIN_HASH_CHUNK_SIZE: usize = 64 * 1024;
/// Hard cap per hashing worker to prevent caller-selected excessive buffering.
pub const MAX_HASH_CHUNK_SIZE: usize = 64 * 1024 * 1024;
/// Known-size sources at or below this threshold may use the buffered strategy (8 MiB).
pub const DEFAULT_HASH_STREAMING_THRESHOLD: u64 = 8 * 1024 * 1024;

/// Return whether a requested chunk size is within the supported 64 KiB–64 MiB range.
pub fn validate_chunk_size(chunk_size: usize) -> bool {
    (MIN_HASH_CHUNK_SIZE..=MAX_HASH_CHUNK_SIZE).contains(&chunk_size)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_supported_chunk_boundaries() {
        assert!(validate_chunk_size(MIN_HASH_CHUNK_SIZE));
        assert!(validate_chunk_size(MAX_HASH_CHUNK_SIZE));
        assert!(!validate_chunk_size(MIN_HASH_CHUNK_SIZE - 1));
        assert!(!validate_chunk_size(MAX_HASH_CHUNK_SIZE + 1));
        assert!(!validate_chunk_size(0));
    }
}
