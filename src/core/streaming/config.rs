//! Default policy for SHA-256 stream processing.

pub const DEFAULT_HASH_CHUNK_SIZE: usize = 1024 * 1024;
pub const MIN_HASH_CHUNK_SIZE: usize = 64 * 1024;
pub const MAX_HASH_CHUNK_SIZE: usize = 8 * 1024 * 1024;
pub const DEFAULT_HASH_STREAMING_THRESHOLD: u64 = 8 * 1024 * 1024;

pub fn validate_chunk_size(chunk_size: usize) -> bool {
    (MIN_HASH_CHUNK_SIZE..=MAX_HASH_CHUNK_SIZE).contains(&chunk_size)
}
