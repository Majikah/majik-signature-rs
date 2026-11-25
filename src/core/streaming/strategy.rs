//! Strategy selection for inputs whose size is known.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashStrategy {
    Buffered,
    Streaming,
}

pub fn detect_hash_strategy(
    source_size: Option<u64>,
    threshold_bytes: u64,
) -> HashStrategy {
    match source_size {
        Some(size) if size <= threshold_bytes => HashStrategy::Buffered,
        _ => HashStrategy::Streaming,
    }
}
