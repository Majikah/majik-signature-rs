//! Port of `cli-core/types.ts`.

use serde::Serialize;
use serde_json::{Map, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Select embedded versus detached output for CLI signing commands.
pub enum SignMode {
    Embedded,
    Detached,
    Map,
    CosignMap,
}

#[derive(Debug, Clone)]
/// Parsed options controlling the CLI sign workflow.
pub struct SignCliOptions {
    pub input: String,
    pub key_path: String,
    pub mode: SignMode,
    pub output: Option<String>,
    pub content_type: Option<String>,
    pub timestamp: Option<String>,
    pub valid_until: Option<String>,
    pub allow_key_paths: Vec<String>,
    pub continue_on_error: bool,
    pub bundle: bool,
    pub seal: bool,
    pub tsa_token_path: Option<String>,
    pub overwrite: bool,
    pub json: bool,
    pub cosign_map_path: Option<String>,
}

#[derive(Debug, Clone)]
/// Parsed options controlling the CLI verify workflow.
pub struct VerifyCliOptions {
    pub input: String,
    pub key_path: Option<String>,
    pub detached_path: Option<String>,
    pub map_path: Option<String>,
    pub order: Vec<String>,
    pub strict: bool,
    pub json: bool,
}

#[derive(Debug, Clone)]
/// Parsed options controlling the CLI seal workflow.
pub struct SealCliOptions {
    pub input: String,
    pub key_path: String,
    pub output: Option<String>,
    pub timestamp: Option<String>,
    pub overwrite: bool,
    pub json: bool,
}

#[derive(Debug, Clone)]
/// Parsed options for the non-mutating signing-policy preflight command.
pub struct CanSignCliOptions {
    pub input: String,
    pub key_path: String,
    pub json: bool,
}

#[derive(Debug, Clone)]
/// Parsed options for non-verifying envelope inspection.
pub struct InspectCliOptions {
    pub input: String,
    pub json: bool,
}

/// Uniform command result: `{ ok, command, message, ...data }`.
#[derive(Debug, Clone, Serialize)]
/// Structured outcome returned by a CLI operation before output rendering.
pub struct CliResult {
    pub ok: bool,
    pub command: String,
    pub message: String,
    #[serde(flatten)]
    pub data: Map<String, Value>,
}

#[derive(Debug, Clone)]
/// File discovered during recursive folder selection for a CLI batch.
pub struct FolderFile {
    pub absolute_path: std::path::PathBuf,
    pub relative_path: String,
    pub bytes: Vec<u8>,
    pub size: u64,
    pub mime_type: String,
}
