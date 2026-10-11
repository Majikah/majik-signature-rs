# Majik Signature (Rust)



[![Developed by Zelijah](https://img.shields.io/badge/Developed%20by-Zelijah-red?logo=github&logoColor=white&style=for-the-badge)](https://thezelijah.world) ![GitHub Sponsors](https://img.shields.io/github/sponsors/jedlsf?style=for-the-badge&label=Sponsors&link=https%3A%2F%2Fgithub.com%2Fsponsors%2Fjedlsf)
[![Crates.io](https://img.shields.io/crates/v/majik-signature.svg?logo=rust&color=D34516)](https://crates.io/crates/majik-signature) [![Documentation](https://docs.rs/majik-signature/badge.svg)](https://docs.rs/majik-signature) ![crates downloads](https://img.shields.io/crates/d/majik-signature?logo=rust&color=D34516) [![License](https://img.shields.io/badge/License-Apache_2.0-D34516.svg)](https://opensource.org/licenses/Apache-2.0) ![Rust](https://img.shields.io/badge/Rust-Ready-D34516) 

[![Static Badge](https://img.shields.io/badge/IANA-vnd.majikah.mjksig-green?style=for-the-badge)](https://www.iana.org/assignments/media-types/application/vnd.majikah.mjksig) [![Static Badge](https://img.shields.io/badge/IANA-vnd.majikah.mjksmap-green?style=for-the-badge)](https://www.iana.org/assignments/media-types/application/vnd.majikah.mjksmap)


**Majik Signature** is a pure-Rust port of the TypeScript `@majikah/majik-signature` library: **hybrid post-quantum signing** for files and data in the Majikah ecosystem. Every signature is produced by **both** Ed25519 and **ML-DSA-87 (FIPS 204)** over the same canonical payload, and **both** must verify.

Keys come from [`majik-key`](https://crates.io/crates/majik-key) (one BIP-39 mnemonic → Ed25519 + ML-DSA-87 + more).

The crate mirrors the TypeScript source tree one-to-one (`index.ts` → `lib.rs`/`mod.rs`, `types.ts` → serde structs), uses `zeroize` where TS used `secureFill`, and produces/accepts the same wire formats — verified against the published TypeScript package in **both directions** (see [Interoperability](#interoperability)).

## Quick start

```rust
use majik_key::{MajikKey, MajikKeyCreateOptions, MnemonicLanguage};
use majik_signature::*;

let mnemonic = MajikKey::generate_mnemonic(128, MnemonicLanguage::default())?;
let key = MajikKey::create(&mnemonic, "passphrase", Some("alice"), &MajikKeyCreateOptions::default())?;

// Sign / verify raw bytes
let sig = MajikSignature::sign(b"hello", &key, None)?;
let pk = MajikSignature::public_keys_from_majik_key(&key)?;
assert!(MajikSignature::verify(b"hello", &sig, &pk, None)?.valid);

// Sign a *file* (PDF, PNG, JPEG, WAV, MP3, FLAC, MP4, MKV, Office/ODF, text, anything else)
let file = std::fs::read("report.pdf")?;
let signed = MajikSignature::sign_file(&file, &key, None)?;
std::fs::write("report.signed.pdf", &signed.blob)?;
let results = MajikSignature::verify_file(&signed.blob, &pk, None)?;
assert!(results[0].valid);
```

### Multi-signer, allowlist, seal

```rust
let signers = vec![
    MajikSignature::expected_signer_from_key(&alice)?,
    MajikSignature::expected_signer_from_key(&bob)?,
];
let a = MajikSignature::sign_file(&file, &alice,
    Some(&SignAndEmbedOptions { expected_signers: Some(signers), ..Default::default() }))?;
let b = MajikSignature::sign_file(&a.blob, &bob, None)?;           // only allowlisted keys may sign
let sealed = MajikSignature::seal(&b.blob, &alice, None, None)?;  // issuer locks the file
assert!(MajikSignature::verify_seal(&sealed.blob, None)?.valid);
```

Also: detached `.mjksig` envelopes, `.mjksmap` folder manifests (`sign_batch_detached`, `verify_files_from_mjksmap`), signing-order checks, revision chains (`verify_file_chain`, `verify_file_revisions`), Trusted Timestamps (`sign_tsa`, `add_tsa`), chain-anchor registration, compact signatures, and the experimental image **stamp** (`stamp_image`, `verify_stamp`).

## CLI

```bash
cargo install majik-signature --features cli    # installs `mjksig`
export MAJIK_KEY_PASSPHRASE=...                  # or be prompted (no echo)
mjksig sign report.pdf -k key.json
mjksig verify report.pdf
mjksig sign ./docs -k key.json --map --bundle
mjksig verify ./docs --map ./docs/signatures.mjksmap
```

Same commands and flags as the TypeScript CLI — see [CLI_README.md](CLI_README.md).

## Layout (mirrors the TS tree)

```
src/
├── lib.rs                      ← index.ts
├── majik_signature.rs          ← majik-signature.ts
├── anchor/{mod.rs,types.rs}
├── core/
│   ├── constants.rs errors.rs hash.rs payload.rs types.rs validator.rs
│   ├── envelope.rs mjksmap.rs order.rs
│   ├── time.rs collate.rs      ← Rust-only helpers (JS Date / localeCompare semantics)
│   ├── embed/
│   │   ├── majik_embed.rs canonical.rs constants.rs fallback.rs registry.rs utils.rs
│   │   ├── zipio.rs            ← Rust-only: fflate-compatible stored-ZIP writer
│   │   └── handlers/{png,jpeg,pdf,wav,mp3,mp4,flac,mkv,office,msix,text}.rs
│   └── stamp/{image_signature.rs, core/{dct_stego,phash,pixel_row,reed_solomon,stub,payload,types,image_utils}.rs}
├── cli_core/{io,key,operations,output,types}.rs      (feature `cli`)
└── bin/mjksig.rs               ← cli.ts
```

## Rust API notes

- **Synchronous.** `async`/`Promise`/`Blob`/`Uint8Array` become plain functions over `&[u8]` / `Vec<u8>`. A `Blob`'s declared type is passed as `mime_type` in the options structs.
- **Types are structs** with `#[serde(rename_all = "camelCase")]`, so JSON is byte-compatible with TS (`skip_serializing_if` mirrors `undefined`).
- **Zeroization.** Secret keys are read into `Zeroizing` buffers; `ed25519-dalek`/`fips204` key types are `ZeroizeOnDrop`. The TS clone-and-wipe `try/finally` is replaced by RAII.
- **Errors.** One `MajikSignatureError` enum (variants = the TS subclasses: `Validation { field }`, `Verification`, `Key`, `Serialization`, `Allowlist { signer_id }`).
- **No adapter.** TS threads a `MajikSignatureStaticAdapter` to avoid a circular import; Rust modules reference each other directly.

## Interoperability

Checked against `@majikah/majik-signature@0.10.0` (see `tests/ts_interop.rs`, `tests/fixtures/`):

| Direction               | Verified                                                                                                                                                                           |
| ----------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| TS-signed → Rust verify | bytes signature (Ed25519 + ML-DSA-87, `validUntil`, `contentType`); 3-signer restricted **sealed** text file (allowlist hash + seal hash); PNG; DOCX (byte-exact canonical re-zip) |
| Rust-signed → TS verify | bytes signature; 2-signer sealed text file (allowlist + seal); DOCX                                                                                                                |

Details that had to be matched exactly: the canonical signing payload (field order, explicit `"ct":null`), SHA3-512 seal domain/body, **`localeCompare` ordering** of signer ids (V8/ICU, *not* byte order — `core/collate.rs`, tested on 400+ strings), and the stored-ZIP layout fflate emits (`core/embed/zipio.rs`).

## Deliberate differences from the TypeScript implementation

Please read these before relying on cross-implementation behaviour.

1. **Image stamp is not wire-compatible with TS.** The TS stamp cannot work as written, so it was fixed rather than ported literally (the stamp is marked experimental in TS as well):
   - **Reed-Solomon decoder** — the TS error-correction path miscorrects (it fails to repair even *one* flipped byte; verified against the published code). The encoder and zero-error path are identical; the correction path is a standard BM + Chien + Forney decoder (corrects up to 37 byte errors).
   - **DCT embedding** — TS's adaptive block-skipping with parity-of-`round(c)` desynchronises on a lossless round trip. Replaced by standard QIM: 1 bit/block in one fixed coefficient, step 24, no skipping. Survives JPEG Q95/85/75 in the tests.
   - **DCT signer id** — the stub stores 32 bytes but a fingerprint is 44 chars, so TS signs the full id and stores a truncated one (the DCT signature can never verify). Here the DCT layer signs what it stores; the full id is in layer 2.
   - **Layer-2 signature** — TS signs a canvas-encoded PNG and verifies a re-encoded copy that carries no envelope (can't succeed). Here layer 2 signs the raw RGBA buffer, independent of any image encoder.
   - WebP output is lossless only (the `image` crate has no lossy WebP encoder).
2. **ZIP timestamp is UTC.** fflate writes the DOS time in *local* time, so TS Office/ODF output differs by machine timezone; Rust always uses 1995-10-26 00:00:00 UTC (identical to TS on a UTC machine).
3. **MJKSMAP paths** are indexed by their *normalised* form (TS indexes the raw string but looks up the normalised one, which misses un-normalised stored paths).
4. **`btoa` semantics** are kept in the text handler (signature JSON must be Latin-1) and MP3 frames with a ≥ 2³¹ size stop parsing instead of looping.
5. **Canvas / `sharp` / browser branches** (`hasBrowserCanvas`, `decodeImageNode`, …) don't exist — the `image` crate does all decode/encode.

## Known limitations

- Office/ODF canonical-form checks compare re-zipped bytes: they match TS only for archives *produced by this handler or by TS fflate stored-mode* (any file that went through another zip tool is re-zipped on `strip`, as in TS).
- An allowlist hash is computed from the struct field order; envelopes whose JSON keys arrive in a different order hash differently than TS would for that raw JSON.
- Dependencies are pinned to the same major versions as `majik-key 1.0.0`; Rust ≥ 1.85 recommended.

## Testing

```bash
cargo test                       # unit + integration + TS interop vectors
cargo test --features cli        # also the CLI end-to-end tests
```

`[profile.test]` builds at `opt-level = 3` (ML-DSA/Argon2id are very slow unoptimised).


---

## Contributing

If you want to contribute or help extend support to more platforms or file formats, reach out via email. All contributions are welcome!

---

## License

[Apache-2.0](LICENSE) — free for personal and commercial use.

---

## Author

Developed by **Josef Elijah Fabian (Zelijah)** | [Majikah Solutions OPC](https://majikah.solutions/about)

**Developer**: [Josef Elijah Fabian](https://github.com/jedlsf)
**GitHub**: [https://github.com/Majikah](https://github.com/Majikah)
**Project Repository**: [https://github.com/Majikah/majik-signature-rs](https://github.com/Majikah/majik-signature-rs)

---

## Contact

- **Business Email**: [business@majikah.solutions](mailto:business@majikah.solutions)
- **Official Website**: [https://www.thezelijah.world](https://www.thezelijah.world)
- **Majikah Ecosystem**: [https://majikah.solutions](https://majikah.solutions)