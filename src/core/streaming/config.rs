//! Default policy for SHA-256 stream processing.

pub const DEFAULT_HASH_CHUNK_SIZE: usize = 1024 * 1024;
pub const MIN_HASH_CHUNK_SIZE: usize = 64 * 1024;
/// Hard cap per hashing worker to prevent caller-selected excessive buffering.
pub const MAX_HASH_CHUNK_SIZE: usize = 64 * 1024 * 1024;
pub const DEFAULT_HASH_STREAMING_THRESHOLD: u64 = 8 * 1024 * 1024;

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
