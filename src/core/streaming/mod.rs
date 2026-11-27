//! Bounded-memory processing for large content inputs.
/// Supported streaming chunk defaults, bounds, and strategy configuration.
pub mod config;
/// Incremental, bounded-chunk SHA-256 hashing over reader inputs.
pub mod sha256;
/// Buffered-versus-streaming strategy selection for known and unknown source sizes.
pub mod strategy;
/// Public streaming source, option, progress, and result types.
pub mod types;

pub use config::*;
pub use sha256::{hash_bytes_auto, hash_reader};
pub use strategy::HashStrategy;
pub use types::{
    BatchStreamingOptions, StreamingBatchFileInput, StreamingBatchProgress, StreamingBatchVerifyInput,
    StreamingHashOptions, StreamingHashProgress, StreamingHashResult,
};
