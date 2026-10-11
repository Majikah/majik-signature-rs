//! Port of `cli-core/output.ts` — human and JSON result printing.

use serde_json::Value;

use crate::cli_core::types::CliResult;

fn stringify(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Number(_) | Value::Bool(_) | Value::Null => value.to_string(),
        other => serde_json::to_string_pretty(other).unwrap_or_default(),
    }
}

fn print_field(result: &CliResult, label: &str, key: &str) {
    match result.data.get(key) {
        None | Some(Value::Null) => {}
        Some(v) => println!("{:<18} {}", label, stringify(v)),
    }
}

pub fn print_result(result: &CliResult) {
    if !result.ok {
        eprintln!("✘ {}", result.message);
        return;
    }
    println!("→ {}", result.message);
    let fields: &[(&str, &str)] = match result.command.as_str() {
        "sign" => &[
            ("Mode", "mode"),
            ("Input", "input"),
            ("Output", "output"),
            ("Signer", "signerId"),
            ("Algorithm", "algorithm"),
            ("SHA-256", "sha256"),
            ("SHA3-512", "sha3_512"),
            ("Files", "files"),
            ("Failures", "failures"),
            ("Map", "map"),
            ("Bundle", "bundle"),
            ("Sealed", "sealed"),
        ],
        "verify" => &[
            ("Input", "input"),
            ("Verdict", "verdict"),
            ("Signatures", "signatures"),
            ("Reason", "reason"),
            ("Relocated From", "relocatedFrom"),
            ("Map", "map"),
            ("Files", "files"),
            ("Missing", "missing"),
        ],
        "seal" => &[
            ("Input", "input"),
            ("Output", "output"),
            ("Sealed By", "sealedBy"),
            ("Seal Timestamp", "sealTimestamp"),
            ("Seal Hash", "sealHash"),
        ],
        "can-sign" => &[("Input", "input"), ("Permitted", "permitted"), ("Reason", "reason")],
        "inspect" => &[("Input", "input"), ("Signed", "signed"), ("Envelope", "envelope")],
        _ => {
            for (k, v) in &result.data {
                if !v.is_null() {
                    println!("{:<18} {}", k, stringify(v));
                }
            }
            return;
        }
    };
    for (label, key) in fields {
        print_field(result, label, key);
    }
}

pub fn print_json_result(result: &CliResult) {
    println!("{}", serde_json::to_string_pretty(result).unwrap_or_default());
}

pub fn print_failure(error: &dyn std::error::Error) {
    eprintln!("✘ {error}");
}
