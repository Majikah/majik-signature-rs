//! Port of `cli.ts` — the `mjksig` command-line tool (`cargo install majik-signature --features cli`).

use clap::{Args, Parser, Subcommand};
use majik_signature::cli_core::*;

#[derive(Parser)]
#[command(
    name = "mjksig",
    version,
    about = "Majik Signature CLI — hybrid Ed25519 + ML-DSA-87 file signing, verification, sealing, and MJKSMAP workflows."
)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Sign a file or folder. Embedded signing is the default.
    Sign(SignArgs),
    /// Verify an embedded signature, detached .mjksig, or .mjksmap.
    Verify(VerifyArgs),
    /// Seal an embedded signature envelope or detached .mjksig.
    Seal(SealArgs),
    /// Check whether a Majik Key is permitted to sign a file.
    #[command(name = "can-sign")]
    CanSign(CanSignArgs),
    /// Inspect an embedded envelope or a detached .mjksig.
    Inspect(InspectArgs),
}

#[derive(Args)]
struct SignArgs {
    input: String,
    /// Majik Key JSON backup used for signing.
    #[arg(short, long)]
    key: String,
    /// Output file or output directory.
    #[arg(short, long)]
    output: Option<String>,
    #[arg(long)]
    detached: bool,
    #[arg(long, alias = "mjksmap", alias = "as-map")]
    map: bool,
    #[arg(long, alias = "cosign-map")]
    cosign: Option<String>,
    #[arg(long)]
    bundle: bool,
    #[arg(long)]
    seal: bool,
    #[arg(long)]
    content_type: Option<String>,
    #[arg(long)]
    timestamp: Option<String>,
    #[arg(long)]
    valid_until: Option<String>,
    /// Additional Majik Key JSON used for the signing allowlist (repeatable).
    #[arg(long = "allow-key")]
    allow_key: Vec<String>,
    #[arg(long)]
    tsa_token: Option<String>,
    #[arg(long)]
    continue_on_error: bool,
    #[arg(long)]
    overwrite: bool,
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct VerifyArgs {
    input: String,
    #[arg(short, long)]
    key: Option<String>,
    #[arg(long)]
    detached: Option<String>,
    #[arg(long)]
    map: Option<String>,
    /// Comma-separated signer fingerprints.
    #[arg(long, value_delimiter = ',')]
    order: Vec<String>,
    #[arg(long)]
    strict: bool,
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct SealArgs {
    input: String,
    #[arg(short, long)]
    key: String,
    #[arg(short, long)]
    output: Option<String>,
    #[arg(long)]
    timestamp: Option<String>,
    #[arg(long)]
    overwrite: bool,
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct CanSignArgs {
    input: String,
    #[arg(short, long)]
    key: String,
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct InspectArgs {
    input: String,
    #[arg(long)]
    json: bool,
}

fn usage_fail(message: &str) -> ! {
    eprintln!("✘ {message}");
    std::process::exit(2);
}

fn normalize_sign(a: SignArgs) -> SignCliOptions {
    let cosign = a.cosign.clone();
    if a.map && a.detached {
        usage_fail("--map and --detached cannot be combined.");
    }
    if a.map && cosign.is_some() {
        usage_fail("--map and --cosign cannot be combined.");
    }
    if a.detached && cosign.is_some() {
        usage_fail("--detached and --cosign cannot be combined.");
    }
    if a.bundle && !a.map && cosign.is_none() {
        usage_fail("--bundle requires --map or --cosign.");
    }
    if a.tsa_token.is_some() && !a.detached && cosign.is_none() {
        usage_fail("--tsa-token requires --detached or --cosign.");
    }
    if !a.allow_key.is_empty() && cosign.is_some() {
        usage_fail("--allow-key cannot be used with --cosign.");
    }
    let mode = if cosign.is_some() {
        SignMode::CosignMap
    } else if a.map {
        SignMode::Map
    } else if a.detached {
        SignMode::Detached
    } else {
        SignMode::Embedded
    };
    SignCliOptions {
        input: a.input,
        key_path: a.key,
        mode,
        output: a.output,
        content_type: a.content_type,
        timestamp: a.timestamp,
        valid_until: a.valid_until,
        allow_key_paths: a.allow_key,
        continue_on_error: a.continue_on_error,
        bundle: a.bundle,
        seal: a.seal,
        tsa_token_path: a.tsa_token,
        overwrite: a.overwrite,
        json: a.json,
        cosign_map_path: cosign,
    }
}

fn finish(outcome: Result<CliResult, Box<dyn std::error::Error + Send + Sync>>, json: bool) -> i32 {
    match outcome {
        Ok(r) => {
            if json {
                print_json_result(&r);
            } else {
                print_result(&r);
            }
            if r.ok {
                0
            } else {
                1
            }
        }
        Err(e) => {
            print_failure(e.as_ref());
            1
        }
    }
}

fn main() {
    let cli = Cli::parse();
    let code = match cli.command {
        Cmd::Sign(a) => {
            let o = normalize_sign(a);
            let json = o.json;
            finish(run_sign(&o), json)
        }
        Cmd::Verify(a) => {
            let o = VerifyCliOptions {
                input: a.input,
                key_path: a.key,
                detached_path: a.detached,
                map_path: a.map,
                order: a.order,
                strict: a.strict,
                json: a.json,
            };
            let json = o.json;
            finish(run_verify(&o), json)
        }
        Cmd::Seal(a) => {
            let o = SealCliOptions {
                input: a.input,
                key_path: a.key,
                output: a.output,
                timestamp: a.timestamp,
                overwrite: a.overwrite,
                json: a.json,
            };
            let json = o.json;
            finish(run_seal(&o), json)
        }
        Cmd::CanSign(a) => {
            let o = CanSignCliOptions { input: a.input, key_path: a.key, json: a.json };
            let json = o.json;
            finish(run_can_sign(&o), json)
        }
        Cmd::Inspect(a) => {
            let o = InspectCliOptions { input: a.input, json: a.json };
            let json = o.json;
            finish(run_inspect(&o), json)
        }
    };
    std::process::exit(code);
}
