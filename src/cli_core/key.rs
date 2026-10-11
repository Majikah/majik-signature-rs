//! Port of `cli-core/key.ts` — loading and unlocking a Majik Key JSON backup.

use std::io::IsTerminal;

use majik_key::MajikKey;

use crate::cli_core::io::{err, read_bytes, resolve_cli_path, CliOutcome};

pub type LoadedMajikKey = MajikKey;

/// `MAJIK_KEY_PASSPHRASE`, else an echo-less TTY prompt.
pub fn prompt_for_passphrase(message: &str) -> CliOutcome<String> {
    if let Ok(p) = std::env::var("MAJIK_KEY_PASSPHRASE") {
        return Ok(p);
    }
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return Err(err(
            "A passphrase is required, but stdin is not an interactive terminal. Set MAJIK_KEY_PASSPHRASE for non-interactive use.",
        ));
    }
    rpassword::prompt_password(message).map_err(|e| err(format!("Operation cancelled: {e}")))
}

fn assert_supported_key_path(path: &str) -> CliOutcome<()> {
    let lower = path.to_lowercase();
    if lower.ends_with(".json") {
        return Ok(());
    }
    if lower.ends_with(".png") {
        return Err(err("PNG Majik Key backups are not supported by this CLI. Use a .json backup."));
    }
    Err(err(format!("Unsupported Majik Key file \"{path}\". Expected a .json backup.")))
}

pub fn load_majik_key(key_path: &str) -> CliOutcome<LoadedMajikKey> {
    let resolved = resolve_cli_path(key_path);
    assert_supported_key_path(&resolved.to_string_lossy())?;
    let bytes = read_bytes(&resolved)?;
    let text = String::from_utf8_lossy(&bytes);
    MajikKey::from_json_str(&text)
        .map_err(|e| err(format!("Failed to load Majik Key \"{}\": {e}", resolved.display())))
}

pub fn load_signing_key(key_path: &str) -> CliOutcome<LoadedMajikKey> {
    let mut key = load_majik_key(key_path)?;
    if !key.has_keys(&[majik_key::KeyId::Ed25519, majik_key::KeyId::MlDsa87]) {
        return Err(err("The supplied Majik Key does not contain Ed25519 + ML-DSA-87 signing keys."));
    }
    if !key.is_unlocked() {
        let passphrase = prompt_for_passphrase("Majik Key passphrase: ")?;
        key.unlock(&passphrase).map_err(|e| err(format!("Failed to unlock Majik Key: {e}")))?;
    }
    if !key.is_unlocked() {
        return Err(err("Majik Key remained locked after unlock."));
    }
    Ok(key)
}

pub fn lock_key(key: &mut LoadedMajikKey) {
    if key.is_unlocked() {
        key.lock();
    }
}
