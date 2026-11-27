# Security Policy

This policy describes the security properties and limitations of the `majik-signature` Rust crate 1.6.0 as implemented in this repository. It covers integrity/signature verification, envelope and manifest parsing, and the boundaries between this library and the application that uses it.

## Supported versions

The `Cargo.toml` source manifest declares version **1.6.0** and requires Rust **1.88 or newer**. Only the latest published crate release is intended to receive security fixes; older releases should be upgraded. A repository source version does not, by itself, establish whether that version has been published to the package registry.

There is no long-term support branch or contractual patch window. Security maintenance and response are best-effort.

## Reporting a vulnerability

Please do not disclose exploitable security issues in public GitHub issues.

Report privately through [GitHub Private Vulnerability Reporting](https://github.com/Majikah/majik-signature-rs/security) or by email to [business@majikah.solutions](mailto:business@majikah.solutions) with `SECURITY` in the subject.

Include the affected release/commit, runtime or platform, impact, reproduction steps or a minimal proof of concept, and whether the issue concerns signature verification, parsing, file embedding, streaming, a dependency, or an application integration.

Response and remediation are best-effort. We aim to acknowledge reports within five business days and provide an initial assessment within ten business days where practical; these are targets, not an SLA.

## Security model

### What the library provides

Majik Signature provides content integrity and cryptographic signer proof. It does not encrypt content, establish the real-world identity of a signer by itself, provide key revocation, or replace application authorization.

Every per-signer signature uses **Ed25519 and ML-DSA-87 (FIPS 204)** over the same canonical signing payload. Verification requires both signature checks to succeed. The signed content is represented by its SHA-256 digest; the full content is hashed before the fixed-size signing payload is constructed.

The canonical payload uses the `majik-signature-v1:` domain separator. Separate domain prefixes are used for seal (`majik-seal-v1:`), TSA (`majikah-tsa-v-1:`), signature-scoped TSA attestation (`majik-signature-attestation-v1:`), and SignRoom session-context (`majik-signature-session-context-v1:`) commitments. These prefixes and canonical field ordering are protocol data; changing them would break compatibility.

### Signer identity and key trust

A successful cryptographic result proves that the signature verifies under the public keys supplied for that verification. Applications must obtain or pin those keys through an independently trusted channel and compare the verified `signerId` with the identity they expect. Public keys embedded in an envelope are self-asserted data until authenticated externally.

Do not treat `getSignatories()`, `getIssuer()`, `isSigned()`, envelope parsing, or an extracted public key as proof that a person or organization has signed. Use the verification result and application-level identity policy.

### Expiry and timestamps

`validUntil`, when present, is included in the signed canonical payload and is enforced by verification against the caller's verification time (the current time by default). The application controls the clock supplied to verification; clock correctness and any policy requiring a maximum signature age remain application responsibilities.

The ordinary signature `timestamp` is self-reported by the signer. It is covered by the signature, but it is not independently attested. A TSA token can provide an attested timestamp, but the application must trust the TSA public-key identity. Verifying a token only against a public key embedded inside that same token proves internal cryptographic consistency, not that the token came from an authoritative TSA.

TSA request transport, server authentication, trusted-key distribution, nonce/challenge issuance and consumption, replay prevention, and participant authorization are outside this library. Signature-scoped TSA tokens bind to a particular signer record; do not reuse one signer's token for another record.

### Allowlists, seals, and revision chains

- **Allowlists:** The allowlist hash is committed by the issuer's signature. The library's signing methods enforce the allowlist when used normally. The envelope's presence or displayed signatory list is not a substitute for verifying the issuer and each signer record.
- **Seals:** A seal is a SHA3-512 hash commitment over envelope state, not an additional digital signature. `verifySeal()` checks the seal commitment; verify the underlying per-signer Ed25519 and ML-DSA-87 signatures separately.
- **Revision chains:** Structural previous-version hashes detect inconsistencies in the chain. A signer's `versionChainHash` cryptographically commits to the chain prefix at their signing turn. Commitment-only checks verify the signed commitment but cannot prove that historical bytes actually matched an earlier content hash. Full historical verification requires the actual archived revision bytes.

### MJKSMAP batch manifests

MJKSMAP maps normalized paths to content hashes and detached signature envelopes. The envelope signatures authenticate the signed content digest and signed per-signer metadata; they do **not** sign the manifest's path strings or the manifest as a whole. MJKSMAP path mapping, entry ordering, and other manifest metadata must therefore be protected by the application's trusted storage or transport if they have security significance.

File resolution checks the recorded path and digest and can report relocation or tampering. This is not a filesystem sandbox. Applications extracting archives or writing untrusted paths must independently enforce root containment, symlink policy, case/alias rules, and platform-specific filename restrictions.

New `.mjksmap` containers use version 2 CBOR with raw binary byte strings; readers also accept legacy version 1 JSON. The container version selects the decoder but does not authenticate the manifest.

## Input bounds and streaming

The implementation rejects oversized or malformed envelope/CBOR inputs and applies structural limits to signatures, allowlist entries, TSA nesting, revision metadata, and MJKSMAP entries/paths. MJKSMAP v2 binary payloads are limited to 16 MiB; its JSON compatibility model has a separate 24 MiB input budget for Base64 expansion. The manifest is limited to 10,000 entries, signature arrays and allowlists to 1,024 items, revision arrays to 10,000 entries, and nested TSA signature records to depth 8.

Streaming SHA-256 uses a 1 MiB default chunk size, accepts configured chunk sizes from 64 KiB through 64 MiB, and uses an 8 MiB default threshold to select buffered versus streaming work when source size is known. There is no default maximum content-file size: applications processing untrusted or resource-sensitive inputs should set the supported maximum-byte option and use cancellation/progress callbacks as appropriate. Supplying an expected total length enables truncation/overrun detection.

These metadata and streaming bounds reduce accidental or adversarial resource use; they do not eliminate denial-of-service risks from all application workloads. Applications should still enforce request, concurrency, storage, and CPU budgets.

## Known limitations and non-goals

- **No confidentiality:** signing does not encrypt the document or envelope.
- **No revocation:** signatures remain cryptographically verifiable after a key is compromised unless the application maintains and checks a revocation/authorization policy.
- **No automatic identity trust:** an embedded signer or TSA public key is not inherently trusted.
- **No trusted wall clock:** expiry uses the verification time supplied by the caller or the local clock.
- **Advisory content type:** `contentType` is signed metadata, not a policy boundary or safe file-type detector.
- **Signature removal:** embedded signature metadata can be stripped; stripping produces unsigned content and does not create a valid signature over altered bytes.
- **Manifest paths are not signed:** protect MJKSMAP manifests and path mapping through trusted storage/transport and enforce filesystem containment separately.
- **Experimental image stamping:** image-stamp helpers are a separate experimental feature and should not be treated as equivalent to the core detached/embedded file-signature workflow.
- **No automatic external audit:** passing repository CI does not amount to an independent cryptographic review or continuous dependency-advisory monitoring.

## Dependencies and supply chain

Cryptographic primitives are delegated to upstream Rust dependencies: `ed25519-dalek` (Ed25519), `fips204` (ML-DSA-87), `sha2` / `sha3` (hash operations), and `majik-key` (key management). The crate also uses `ciborium` for CBOR, `serde`/`serde_json` for data models, `zeroize` for secret-buffer cleanup, `zip` for Office/ODF embedding, `image` for image operations, and `clap`/`rpassword` for the optional CLI feature. This project does not implement the Ed25519, ML-DSA-87, SHA-256, or SHA3-512 algorithms itself. Dependency vulnerabilities may require upgrading the affected crate and then releasing a compatible update.

Review dependency updates, use lockfiles where applicable, and run the package manager's advisory tooling in your own release pipeline. Repository CI tests and builds the source but should not be interpreted as an independent software-composition or cryptographic audit.

## Secure usage checklist

- Verify the file/content and inspect every per-signer verification result.
- Authenticate signer public keys independently and enforce the expected signer identity in the application.
- Verify the allowlist issuer before relying on its policy.
- Verify seal commitments **and** the underlying signer signatures.
- Supply trusted TSA public keys when TSA provenance matters.
- Require the expected SignRoom session context for session-bound digest-only verification.
- Set maximum input/concurrency limits for untrusted streams and cancel work when the operation is no longer needed.
- Protect MJKSMAP manifests and enforce filesystem containment independently.
- Keep `@majikah/majik-key` secret material protected and lock/zeroize keys through the key-management API after use.

## Cryptographic parameters

| Property | Value |
|---|---|
| Classical signature | Ed25519 |
| Post-quantum signature | ML-DSA-87 (FIPS 204) |
| Content digest | SHA-256 |
| Allowlist digest | SHA-256 |
| Seal digest | SHA3-512 |
| Signature schema version | 1 |
| Envelope schema version | 1 |
| MJKSIG container writer | v2 CBOR (v1 JSON remains readable) |
| MJKSMAP container writer | v2 CBOR (v1 JSON remains readable) |

## Disclosure

We follow coordinated disclosure where practical. After a fix is available, maintainers may publish release notes and credit the reporter if requested. We do not currently operate a paid bug-bounty program.

## Contact

- Security: [GitHub Private Vulnerability Reporting](https://github.com/Majikah/majik-signature/security) or [business@majikah.solutions](mailto:business@majikah.solutions) (`SECURITY` subject)
- Maintainer: [Majikah](https://github.com/Majikah)