//! Shared test helpers.
#![allow(dead_code)]

use majik_key::{MajikKey, MajikKeyCreateOptions, MnemonicLanguage};

pub const PASSPHRASE: &str = "correct horse battery staple 42!";

/// A fresh, unlocked key with the core four derived (X25519, Ed25519, ML-KEM, ML-DSA).
pub fn new_key(label: &str) -> MajikKey {
    let mnemonic = MajikKey::generate_mnemonic(128, MnemonicLanguage::default()).expect("mnemonic");
    MajikKey::create(&mnemonic, PASSPHRASE, Some(label), &MajikKeyCreateOptions::default())
        .expect("create key")
}
