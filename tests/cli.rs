#![cfg(feature = "cli")]
mod common;

use std::path::Path;
use std::process::Command;

fn mjksig(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_mjksig"))
        .args(args)
        .env("MAJIK_KEY_PASSPHRASE", common::PASSPHRASE)
        .output()
        .expect("run mjksig");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn write_key(dir: &Path, name: &str) -> String {
    let key = common::new_key(name);
    let p = dir.join(format!("{name}.json"));
    std::fs::write(&p, key.to_json_string(true).unwrap()).unwrap();
    p.to_string_lossy().into_owned()
}

#[test]
fn embedded_sign_inspect_verify_seal() {
    let dir = tempdir("cli_embedded");
    let key = write_key(&dir, "alice");
    let file = dir.join("note.txt");
    std::fs::write(&file, "hello cli").unwrap();
    let f = file.to_str().unwrap();

    let (c, out, err) = mjksig(&["sign", f, "-k", &key, "--json"]);
    assert_eq!(c, 0, "sign failed: {out} {err}");
    assert!(out.contains("\"mode\": \"embedded\""));

    let (c, out, _) = mjksig(&["inspect", f, "--json"]);
    assert_eq!(c, 0);
    assert!(out.contains("\"signed\": true"));

    let (c, out, err) = mjksig(&["verify", f, "--json"]);
    assert_eq!(c, 0, "verify failed: {out} {err}");
    assert!(out.contains("\"verdict\": \"valid\""));

    let (c, out, err) = mjksig(&["seal", f, "-k", &key, "--json"]);
    assert_eq!(c, 0, "seal failed: {out} {err}");
    let (c, out, _) = mjksig(&["can-sign", f, "-k", &key, "--json"]);
    assert_eq!(c, 1, "sealed file must not be signable: {out}");

    // tamper
    let mut b = std::fs::read(&file).unwrap();
    b[0] ^= 1;
    std::fs::write(&file, b).unwrap();
    let (c, out, _) = mjksig(&["verify", f, "--json"]);
    assert_eq!(c, 1);
    assert!(out.contains("\"verdict\": \"invalid\"") || out.contains("unsigned"), "{out}");
}

#[test]
fn map_sign_and_verify_folder() {
    let dir = tempdir("cli_map");
    let key = write_key(&dir, "bob");
    let docs = dir.join("docs");
    std::fs::create_dir_all(docs.join("sub")).unwrap();
    std::fs::write(docs.join("a.txt"), "alpha").unwrap();
    std::fs::write(docs.join("sub/b.bin"), [1u8, 2, 3, 4]).unwrap();
    let d = docs.to_str().unwrap();

    let (c, out, err) = mjksig(&["sign", d, "-k", &key, "--map", "--json"]);
    assert_eq!(c, 0, "{out} {err}");
    let map = docs.join("signatures.mjksmap");
    assert!(map.exists());

    let (c, out, err) = mjksig(&["verify", d, "--map", map.to_str().unwrap(), "--json"]);
    assert_eq!(c, 0, "{out} {err}");
    assert!(out.contains("\"verdict\": \"valid\""));

    std::fs::write(docs.join("a.txt"), "ALPHA").unwrap();
    let (c, out, _) = mjksig(&["verify", d, "--map", map.to_str().unwrap(), "--json"]);
    assert_eq!(c, 1);
    assert!(out.contains("tampered"));
}

#[test]
fn usage_errors_exit_2() {
    let (c, _, err) = mjksig(&["sign", "x", "-k", "k.json", "--map", "--detached"]);
    assert_eq!(c, 2);
    assert!(err.contains("cannot be combined"));
}

fn tempdir(name: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("mjksig-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}
