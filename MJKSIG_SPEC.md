# MJKSIG — Majik Signature Envelope Format

[![Static Badge](https://img.shields.io/badge/IANA-vnd.majikah.mjksig-green)](https://www.iana.org/assignments/media-types/application/vnd.majikah.mjksig)

**File Extension:** `.mjksig`
**Proposed Media Type:** `application/vnd.majikah.mjksig`
**Category:** Secure digital signature envelope
**Specification Version:** 1.0
**Format Version Byte:** `0x01`
**Status:** Draft / Implementation-aligned

---

## 1. Overview

**MJKSIG (Majik Signature Envelope)** is a self-contained, detached digital signature binary format. It is designed to carry cryptographic proofs of file integrity, authorship, and signing policies (multi-sig and allowlists) independently of the file it signs. 

The format employs a **hybrid cryptographic construction**, requiring signatures from both a classical elliptic curve algorithm (**Ed25519**) and a post-quantum algorithm (**ML-DSA-87**). The binary structure acts as a lightweight wrapper around a deterministically structured UTF-8 JSON payload known as the `MultiSigEnvelope`.

---

## 2. Cryptographic Model

MJKSIG relies on a hybrid signature model ensuring resilience against both classical and quantum computing attacks.

### 2.1 Hybrid Signatures
Every valid signatory entry within an MJKSIG envelope contains two distinct signatures:
*   **Ed25519 Signature:** 64 bytes, stored as base64.
*   **ML-DSA-87 Signature:** 4595 bytes, stored as base64.

Both algorithms sign the exact same **canonical payload** bytes. Verification requires **both** signatures to pass; if either fails, the entire signature is deemed invalid.

### 2.2 Canonical Payload
The canonical signing payload is constructed deterministically to ensure byte-for-byte identical inputs during both signing and verification.

**Format:**
`"majik-signature-v1:" + JSON.stringify({ v, id, ts, ct, hash[, alh][, vu][, vch] })`

Where:
*   `v`: Envelope version (integer, `1`).
*   `id`: Signer fingerprint (string).
*   `ts`: ISO 8601 timestamp (string).
*   `ct`: Content type or `null`.
*   `hash`: SHA-256 hash of the original detached file's content, base64 encoded.
*   `alh`: SHA-256 hash of the canonical allowlist JSON, base64 encoded. This key is completely omitted (not set to `null`) if an allowlist is not established, preserving backward compatibility.
*   `vu`:  Optional ISO 8601 expiry. When present, verify() treats the signature as invalid once the current time is past this value. Absent = never expires (matches all pre-existing signatures — fully backward compatible). Covered by the canonical signing payload when present, so it cannot be stripped or extended post-hoc without breaking both signatures.
*   `vch`: Optional SHA-256 hash of the `fileVersions` revision chain, base64 encoded, as it stood when this signer signed (including their own new entry). Present only on files using file versioning (see §2.4). Omitted entirely, never `null`, on any signature that predates or doesn't use this feature — preserves the same backward-compatibility guarantee as `alh`/`vu`.

### 2.3 Allowlist and Sealing
*   **Allowlist:** The first signer may optionally restrict future signers by embedding an `ExpectedSigner` array. The establisher commits to this allowlist cryptographically via the `allowlistHash` in their canonical payload.
*   **Seal:** The issuer (allowlist establisher) can permanently lock the envelope against further signatures. Sealing computes a SHA3-512 hash over the current signatories and a seal timestamp. The seal hash domain prefix is `majik-seal-v1:`. 
  
### 2.4 File Versioning & Revision Chains

MJKSIG supports an append-only revision chain (`fileVersions`) for workflows where a signer visually mutates the document itself (e.g. a drawn signature stamp) before signing — which changes the file's byte content on every hand-off, not just its metadata.

Each entry in `fileVersions` is a `FileVersion`:

```typescript
interface FileVersion {
  /** Sequential, 1-indexed */
  version: number;
  timestamp: string; // ISO 8601
  /** SHA-256 of this revision's stripped bytes, base64 */
  contentHash: string;
  /** SHA-256 of the entire prior FileVersion entry — absent only on version 1 */
  previousVersionHash?: string;
  createdBy?: string; // signer fingerprint
  message?: string;
}
```

Two independent integrity mechanisms apply:

1. **Structural chaining** — each entry's `previousVersionHash` is the hash of the complete prior `FileVersion` object (not just its `contentHash`), so tampering with any field of an earlier entry — including `timestamp` or `message` — breaks the chain at that point. Checked via a walk of the array; requires no cryptographic key.
2. **Cryptographic binding** — each signer's `versionChainHash` (§2.2) commits to `SHA256(JSON.stringify(fileVersions[0..their own new entry]))`. This is what prevents a wholesale, internally-consistent forged chain: without it, an attacker with file-edit access could rewrite `fileVersions` end-to-end in a way that still passes the structural check in (1), since that check alone never touches a signature. `versionChainHash` anchors the chain's *state at that signer's turn* to a value only they could have produced.

Verifiers should treat a file as chain-valid only when **both** checks pass for every signature — structural chaining alone is a self-consistency check, not a security property.

**Self-contained vs. archive-assisted verification.** Because a raw content hash alone can't be recomputed for an *earlier* revision without the earlier bytes, two levels of verification exist:

- **Commitment verification** (self-contained, no earlier bytes needed): recompute the canonical payload from the stored `MajikSignatureJSON` fields, verify Ed25519 + ML-DSA-87 against it, and confirm `versionChainHash` matches the recomputed prefix of `fileVersions`. This proves the signer's commitment is genuine and the chain hasn't been rewritten, but does not independently prove the `contentHash` at that revision ever corresponded to real bytes.
- **Full revision verification** (archive-assisted): given the actual byte content of each historical revision, confirm each one's hash matches its `fileVersions` entry and that the full signature verifies against those bytes directly. This is the only way to fully close the gap left by commitment verification, and requires the verifier to have retained each intermediate revision.

`fileVersions` is intentionally metadata-only — it never stores revision content directly, to avoid the container growing linearly with each signer for large files. Storage of the actual per-revision bytes, if needed for full revision verification, is left to the application layer.

---

## 3. Binary Layout

All multi-byte integer fields are **big-endian**.

The file begins with a strictly sized **12-byte header** regardless of the version, enabling parsers to easily locate the JSON payload.

```text
Offset  Length  Field
──────  ──────  ──────────────────────────────────────────────────
0       6       Magic bytes: ASCII "MJKSIG" (0x4D 0x4A 0x4B 0x53 0x49 0x47)
6       1       Format version: 0x01
7       1       Reserved byte
8       4       Payload JSON byte length (big-endian uint32)
12      N       Payload JSON (UTF-8, MultiSigEnvelope format)
```

### 3.1 Field Definitions

| Field          | Offset | Length  | Encoding          | Description                                                                   |
| -------------- | ------ | ------- | ----------------- | ----------------------------------------------------------------------------- |
| Magic          | 0      | 6 bytes | Raw bytes         | ASCII "MJKSIG" — `0x4d, 0x4a, 0x4b, 0x53, 0x49, 0x47`.                        |
| Version        | 6      | 1 byte  | Unsigned integer  | Format version. Current: `0x01`.                                              |
| Reserved       | 7      | 1 byte  | Raw byte          | Reserved for future flags. Currently ignored/set to `0x00`.                   |
| Payload length | 8      | 4 bytes | Big-endian uint32 | Byte length of the following UTF-8 payload JSON section (`N`).                |
| Payload JSON   | 12     | N bytes | UTF-8 JSON        | The `MultiSigEnvelope` structure carrying the envelope state and public keys. |

---

## 4. Payload JSON Schema

The payload section located at byte offset `12` parses into the `MultiSigEnvelope` schema.

### 4.1 MultiSigEnvelope (Root Object)

```typescript
interface MultiSigEnvelope {
  /** Envelope wrapper version — must equal 1 */
  version: 1;

  /** Restricts signing to these keys only. Absent = open signing. */
  allowlist?: ExpectedSigner[];

  /** Fingerprint of the signer who established the allowlist. */
  allowlistSignerId?: string;

  /** All per-signer envelopes. One entry per signer. */
  signatures: MajikSignatureJSON[];

  /** SHA3-512 hash of the canonical seal payload, hex-encoded (128 chars). */
  sealHash?: string;

  /** ISO 8601 timestamp of when the seal was applied. */
  sealTimestamp?: string;

  /** Fingerprint of the issuer who applied the seal. */
  sealedBy?: string;
  
  /** Multi-chain-ready anchor receipts. */
  chainAnchors?: MajikChainAnchor[];

   /** Append-only revision chain. Absent on files predating this feature. */
  fileVersions?: FileVersion[];
}
```

### 4.2 MajikSignatureJSON (Per-Signer Entry)

Every entry in the `signatures` array adheres to the following interface:

```typescript
interface MajikSignatureJSON {
  /** Envelope version — must equal MAJIK_SIGNATURE_VERSION */
  version: 1;

  /** MajikKey fingerprint (SHA-256 of X25519 public key, base64) */
  signerId: MajikKeyFingerprint;

  /** Ed25519 public key, base64 (32 bytes) */
  signerEdPublicKey: string;

  /** ML-DSA-87 public key, base64 (2592 bytes) */
  signerMlDsaPublicKey: string;

  /** SHA-256 hash of the original content, base64 (32 bytes → 44 chars) */
  contentHash: string;

  /** Advisory content type — e.g. "audio/wav", "application/pdf" */
  contentType?: string;

  /** ISO 8601 timestamp of when the signature was created */
  timestamp: ISODateString;

  /** Ed25519 signature over the canonical payload, base64 (64 bytes) */
  edSignature: ED25519Signature;

  /** ML-DSA-87 signature over the canonical payload, base64 (4595 bytes) */
  mlDsaSignature: MLDSA87Signature;

  /** SHA-256 hash of the canonical allowlist JSON, base64 (44 chars). */
  allowlistHash?: string;

   /**
   * Optional ISO 8601 expiry. When present, verify() treats the signature
   * as invalid once the current time is past this value. Absent = never
   * expires (matches all pre-existing signatures — fully backward compatible).
   * Covered by the canonical signing payload when present, so it cannot be
   * stripped or extended post-hoc without breaking both signatures.
   */
   validUntil?: ISODateString;

    /**
   * SHA-256 of the fileVersions chain as it stood when this signer signed
   * (i.e. including their own new entry). Covered by the canonical payload,
   * same treatment as allowlistHash/validUntil — absent, never null.
   */
  versionChainHash?: string;
  
  /** Trusted Timestamp Authority metadata and signature */
  tsa?: MajikTimestamp;
}
```

### 4.3 ExpectedSigner

Used within the `allowlist` array to mandate exact key matches.

```typescript
interface ExpectedSigner {
  signerId: string;
  edPublicKey: string;
  mlDsaPublicKey: string;
}
```
*Note: All three fields must match during the signing-eligibility gate to prevent spoofing by a different key pair sharing the same fingerprint.*

---

## 5. File Identification

| Property             | Value                            |
| -------------------- | -------------------------------- |
| Magic bytes          | `4D 4A 4B 53 49 47`              |
| ASCII representation | `MJKSIG`                         |
| Offset               | `0x00`                           |
| Minimum valid header | 12 bytes                         |
| File Extension       | `.mjksig`                        |
| MIME Type            | `application/vnd.majikah.mjksig` |

---

## 6. Parsing & Verification Pipeline

1.  **Header Verification:** Read the first 6 bytes and verify the `MJKSIG` magic sequence.
2.  **Version Check:** Read byte offset `6` to ensure the version is `0x01`. 
3.  **Read Payload Length:** Extract the 4-byte big-endian `uint32` starting at offset `8`. 
4.  **Parse Payload:** Read the specified number of bytes starting at offset `12` as a UTF-8 string, then parse it into a `MultiSigEnvelope` JSON object.
5.  **Target Verification:** For a target signature in the `signatures` array:
    *   Compute the SHA-256 hash of the detached original file and ensure it base64-matches `contentHash`.
    *   Reconstruct the deterministic canonical byte payload.
    *   Verify the classical `edSignature` against `signerEdPublicKey`.
    *   Verify the post-quantum `mlDsaSignature` against `signerMlDsaPublicKey`.
6.  **Version Chain Verification (if `fileVersions` is present):** Walk the chain confirming each entry's `previousVersionHash` matches the hash of the prior entry (§2.4.1), then for each signature carrying a `versionChainHash`, recompute the hash of the chain prefix up to and including its corresponding entry and confirm it matches.

If all checks pass, the detached signature securely correlates to the file.

---

## Author

Developed by **Josef Elijah Fabian (Zelijah)** | [Majikah Solutions OPC](https://majikah.solutions/about)


**Developer**: [Josef Elijah Fabian](https://github.com/jedlsf)
**GitHub**: [https://github.com/Majikah](https://github.com/Majikah)
**Project Repository**: [https://github.com/Majikah/majik-signature](https://github.com/Majikah/majik-signature)

---

## Contact

- **Business Email**: [business@majikah.solutions](mailto:business@majikah.solutions)
- **Official Website**: [https://www.thezelijah.world](https://www.thezelijah.world)
- **Majikah Ecosystem**: [https://majikah.solutions](https://majikah.solutions)