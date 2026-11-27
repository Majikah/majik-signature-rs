//! Strategy selection for inputs whose size is known.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Processing strategy selected for a source whose size may or may not be known.
pub enum HashStrategy {
    Buffered,
    Streaming,
}

/// Select the buffered path for known inputs at or below the threshold; unknown/large inputs stream.
pub fn detect_hash_strategy(source_size: Option<u64>, threshold_bytes: u64) -> HashStrategy {
    match source_size {
        Some(size) if size <= threshold_bytes => HashStrategy::Buffered,
        _ => HashStrategy::Streaming,
    }
}
