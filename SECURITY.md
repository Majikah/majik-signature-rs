# Security Policy

This document describes the security model of `majik-signature`, what it does and does not guarantee, and how to report a vulnerability. It is written to match the actual implementation — if something here looks inconsistent with the code, please [report it](#reporting-a-vulnerability).

---

## Table of Contents

- [Security Policy](#security-policy)
  - [Table of Contents](#table-of-contents)
  - [Supported Versions](#supported-versions)
  - [Reporting a Vulnerability](#reporting-a-vulnerability)
  - [Security Model](#security-model)
    - [What this library actually does](#what-this-library-actually-does)
    - [Hybrid signing](#hybrid-signing)
    - [Domain separation](#domain-separation)
    - [What's covered by the signature](#whats-covered-by-the-signature)
    - [Multi-party integrity](#multi-party-integrity)
  - [Scope](#scope)
    - [In scope](#in-scope)
    - [Out of scope](#out-of-scope)
  - [Known Limitations \& Non-Goals](#known-limitations--non-goals)
  - [Dependency \& Supply Chain](#dependency--supply-chain)
  - [Secure Usage Guidelines](#secure-usage-guidelines)
  - [Cryptographic Details](#cryptographic-details)
  - [Disclosure Policy](#disclosure-policy)
  - [Contact](#contact)

---

## Supported Versions

This library is currently pre-1.0 (`0.0.x`). There is no long-term support branch — **only the latest published version on npm receives security fixes.**

| Version          | Supported             |
| ---------------- | --------------------- |
| Latest (`0.0.x`) | ✅ Yes                 |
| Older `0.0.x`    | ❌ No — please upgrade |

Once the library reaches `1.0.0`, this table will be updated with a defined support window. Until then, treat every release as the only supported release, and pin your dependency deliberately rather than assuming older minor versions remain patched.

---

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Report privately via:

1. **GitHub Private Vulnerability Reporting**  — [github.com/Majikah/majik-signature-rs/security](https://github.com/Majikah/majik-signature-rs/security)
2. **Email** — [business@majikah.solutions](mailto:business@majikah.solutions), with `SECURITY` in the subject line

Please include:
- A description of the issue and its potential impact
- Steps to reproduce, or a minimal proof-of-concept
- The affected version(s), and whether the issue is in this package or a dependency
- Whether the issue is in the core cryptographic path (`sign`/`verify`) or the file-embedding layer

**This is a small, independently maintained project — response times are best-effort, not a contractual SLA.** In good faith, we aim to:

| Stage                                   | Target                               |
| --------------------------------------- | ------------------------------------ |
| Initial acknowledgment                  | Within 5 business days               |
| Preliminary assessment                  | Within 10 business days              |
| Fix or mitigation, for confirmed issues | Best-effort, prioritized by severity |

We will keep you informed as the report is triaged and credit reporters (if desired) once a fix ships, in line with the [Disclosure Policy](#disclosure-policy) below.

---

## Security Model

### What this library actually does

Majik Signature provides **integrity and authenticity**, not confidentiality. It answers the question *"was this exact content produced by this key, unmodified, at this time?"* — it does not encrypt content, hide it, or control who can read it.

### Hybrid signing

Every signature is produced by **two independent algorithms over the same canonical payload**, and verification requires **both** to pass:

- **Ed25519** — classical, 128-bit security, via `@stablelib/ed25519`
- **ML-DSA-87 (FIPS-204)** — post-quantum, NIST Category 5, via `@noble/post-quantum`

This hybrid construction means a break in either algorithm alone — a classical cryptanalytic advance against Ed25519, or a future quantum attack against ML-DSA-87 — is not sufficient on its own to forge a valid signature.

### Domain separation

Three independent domain-separation prefixes prevent a signature (or hash) produced for one purpose from being replayed as another:

| Purpose                   | Prefix                |
| ------------------------- | --------------------- |
| Content signing payload   | `majik-signature-v1:` |
| Seal hash payload         | `majik-seal-v1:`      |
| Trusted timestamp payload | `majikah-tsa-v-1:`    |

### What's covered by the signature

The signed payload binds: envelope version, signer fingerprint, ISO 8601 timestamp, advisory content type, SHA-256 content hash, and — only when establishing an allowlist — the allowlist's own hash. Content itself is never embedded in the envelope; only its hash is signed, so signature cost is independent of content size.

### Multi-party integrity

- **Allowlists** are cryptographically committed: the issuer's `allowlistHash` is inside their own signed payload, so modifying the allowlist after the fact invalidates the issuer's signature.
- **Sealing** computes a SHA3-512 hash over all current signatories plus a seal timestamp. This is a **hash commitment, not a signature** — `verifySeal()` checks hash equality, and does not itself perform any Ed25519/ML-DSA-87 verification. Always call `verifyFile()` separately to validate the underlying signer signatures.

---

## Scope

### In scope

- The core signing/verification path (`sign`, `verify`, `verifyWithKey`) in `majik-signature.ts`
- The canonical payload construction (`payload.ts`) and any weakening of domain separation or hash binding
- The file embedding/extraction/strip round-trip (`majik-embed.ts` and all format handlers)
- Multi-signature, allowlist, and seal logic (`multi-sig.ts`)
- Serialization/deserialization (`toJSON`/`fromJSON`/`serialize`/`deserialize`)
- Any vulnerability that allows a signature to verify as `valid: true` against content or a signer it should not

### Out of scope

- **`MajikKey`** — key generation, storage, and mnemonic handling live in the separate `@majikah/majik-key` peer dependency. Report key-management issues there.
- **Image stamping module** (`stampImage`/`verifyStamp`/`inspectStamp`/`isStamped`) — explicitly marked `@experimental` in source and not API-stable. Issues are welcome but are not treated as security-critical in the same sense as the core signing path.
- **Applications built on this library** — misuse (e.g., trusting an unverified `signerId`, skipping `key.lock()`, treating `contentType` as enforced) is an application-level concern; see [Secure Usage Guidelines](#secure-usage-guidelines).
- **Denial-of-service via large inputs** — the library hashes and signs whatever it's given; enforcing size limits on untrusted input is the caller's responsibility.

---

## Known Limitations & Non-Goals

Documented honestly, so you can design around them:

- **No confidentiality.** Signing does not encrypt or hide content. A signed file's contents (and the signature envelope itself) are fully readable by anyone with the file. If you need confidentiality, encrypt separately before or after signing.
- **No revocation.** There is no mechanism to revoke a previously issued signature. If a signer's key is later compromised, signatures made before compromise remain cryptographically valid forever — key compromise response is an application/key-management concern, not something `verify()` can detect.
- **No freshness/expiry enforcement.** The signed payload includes a timestamp, but `verify()` does not check it against a validity window or current time. An old-but-legitimately-signed file will always verify as valid. If your use case needs "signed within the last N days," enforce that check on `result.timestamp` yourself.
- **`contentType` is advisory only.** It is included in the signed payload (so it can't be silently swapped after signing), but it is never used to restrict what verify() will accept. Don't rely on it as an access-control mechanism.
- **Signatures can be stripped, not forged.** Anyone can remove an embedded signature from a file (`strip()` is a public, deterministic operation) — that just produces an unsigned file. This is expected and analogous to removing a physical signature page: it does not let an attacker produce a *valid* signature over modified content, or make a stripped file appear signed.
- **Array-of-signatures does not imply array-of-valid-signatures.** `extractFrom()` and the raw envelope can technically contain malformed or invalid signature entries (e.g., a hand-edited file with a garbage `edSignature`). Always check `valid` on each `VerificationResult` returned by `verifyFile()` — never assume presence in the envelope implies cryptographic validity.
- **Allowlist enforcement is a library-level, not container-level, guarantee.** `signAndEmbed()` rejects non-listed signers before doing any cryptographic work when you go through the library's own APIs. Nothing stops a party with direct file access from hand-crafting an envelope with an unauthorized signer's ID and a bogus signature — it will simply fail verification, so this is not a forgery risk, but downstream code that inspects `getSignatories()` without also calling `verifyFile()` could be misled about who has "signed."
- **No built-in transport security.** Trusted Timestamp requests/responses and any network calls your application layers on top of this library are your responsibility to secure (TLS, server authentication, etc.) — the library only handles the cryptographic payload.
- **Pre-1.0 API stability.** Until `1.0.0`, minor versions may include breaking changes, including to security-relevant defaults. Read release notes before upgrading.
- **ML-DSA-87 is a relatively young standard** (FIPS-204 finalized in 2024). The hybrid design exists specifically so that a weakness discovered in ML-DSA-87 alone does not compromise signatures already issued — Ed25519 coverage remains intact — but this is not a substitute for tracking NIST post-quantum guidance as the field matures.

---

## Dependency & Supply Chain

Majik Signature has a deliberately small dependency surface and **no native bindings**:

| Dependency                  | Role                                                    |
| --------------------------- | ------------------------------------------------------- |
| `@noble/post-quantum`       | ML-DSA-87 (FIPS-204) implementation                     |
| `@stablelib/ed25519`        | Ed25519 implementation                                  |
| `@stablelib/sha256`         | SHA-256 hashing                                         |
| `fflate`                    | ZIP handling for Office/ODF format embedding            |
| `@majikah/majik-key` (peer) | Key generation, unlocking, and secret material handling |

Cryptographic primitives are delegated entirely to the underlying libraries above — this project does not implement its own Ed25519, ML-DSA-87, or SHA-256/SHA3-512 primitives. Vulnerabilities in the cryptographic math itself should generally be reported upstream to those projects as well as to us, since we would need to update the dependency to ship a fix.

We recommend running `npm audit` (or your package manager's equivalent) against your own lockfile regularly, since transitive dependency advisories can appear between our releases.

---

## Secure Usage Guidelines

The full list lives in the [README's Security Considerations](README.md#security-considerations). The security-critical subset:

- ✅ Always check `result.valid` **and** cross-check `result.signerId` against a fingerprint you actually trust — a cryptographically valid signature from an *unexpected* signer is not the same as a trusted one.
- ✅ Call `key.lock()` immediately after signing to purge secret key material from memory.
- ✅ Treat every entry in `verifyFile()`'s result array independently — a file with multiple signatures can have some valid and some invalid entries.
- ✅ If you rely on sealing, call both `verifySeal()` (structural) **and** `verifyFile()` (cryptographic) — they check different things.
- ❌ Never treat `contentType`, file extension, or MIME type as a trust boundary.
- ❌ Never assume a signature's presence means it verified — always call `verify()`/`verifyFile()`; don't infer trust from `isSigned()` or `extractFrom()` alone.

---

## Cryptographic Details

| Property                         | Value                                 |
| -------------------------------- | ------------------------------------- |
| Classical signature algorithm    | Ed25519                               |
| Post-quantum signature algorithm | ML-DSA-87 (NIST FIPS-204, Category 5) |
| Content hash                     | SHA-256                               |
| Allowlist hash                   | SHA-256                               |
| Seal hash                        | SHA3-512                              |
| Signature envelope version       | `1` (`MAJIK_SIGNATURE_VERSION`)       |
| Envelope wrapper version         | `1` (`MAJIK_ENVELOPE_VERSION`)        |
| Timestamp payload version        | `1` (`MAJIK_TIMESTAMP_VERSION`)       |

Version fields are embedded in every envelope specifically to support future cryptographic migration (e.g., a future `MAJIK_SIGNATURE_VERSION = 2` using different or additional algorithms) without breaking verification of signatures issued under the current scheme.

---

## Disclosure Policy

We follow a **coordinated disclosure** approach:

1. You report privately, per [Reporting a Vulnerability](#reporting-a-vulnerability).
2. We confirm, assess severity, and work on a fix without public disclosure.
3. Once a fix is published to npm, we credit the reporter (if they wish to be credited) and publish details of the issue.
4. If a report goes unacknowledged for an extended period despite good-faith reporting attempts, we consider public disclosure by the reporter reasonable — we'd rather you responsibly disclose than sit on a real issue indefinitely because we were slow.

We do not currently operate a paid bug bounty program.

---

## Contact

- **Security reports**: [github.com/Majikah/majik-signature-rs/security](https://github.com/Majikah/majik-signature-rs/security) or [business@majikah.solutions](mailto:business@majikah.solutions) (subject: `SECURITY`)
- **General/non-security issues**: [GitHub Issues](https://github.com/Majikah/majik-signature-rs/issues)
- **Maintainer**: [Josef Elijah Fabian](https://github.com/jedlsf)