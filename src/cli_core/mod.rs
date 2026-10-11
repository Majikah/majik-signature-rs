//! Port of `cli-core/` — everything the `mjksig` binary needs (feature `cli`).

pub mod io;
pub mod key;
pub mod operations;
pub mod output;
pub mod types;

pub use operations::{run_can_sign, run_inspect, run_seal, run_sign, run_verify};
pub use output::{print_failure, print_json_result, print_result};
pub use types::*;
