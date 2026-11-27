//! Port of `cli-core/` — everything the `mjksig` binary needs (feature `cli`).

/// Filesystem access, path normalization, and output-path helpers for CLI commands.
pub mod io;
/// Key loading and cleanup helpers used by signing commands.
pub mod key;
/// Reusable command workflows for signing, verification, sealing, and inspection.
pub mod operations;
/// Human-readable and machine-readable CLI output renderers.
pub mod output;
/// Parsed CLI option and result data structures.
pub mod types;

pub use operations::{run_can_sign, run_inspect, run_seal, run_sign, run_verify};
pub use output::{print_failure, print_json_result, print_result};
pub use types::*;
