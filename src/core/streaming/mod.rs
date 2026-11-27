//! Bounded-memory processing for large content inputs.
pub mod config;
pub mod sha256;
pub mod strategy;
pub mod types;

pub use config::*;
pub use sha256::{hash_bytes_auto, hash_reader};
pub use strategy::HashStrategy;
pub use types::{BatchStreamingOptions, StreamingBatchFileInput, StreamingBatchProgress, StreamingHashOptions, StreamingHashProgress, StreamingHashResult};
