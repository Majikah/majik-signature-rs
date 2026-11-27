# Majik Signature Map (`MJKSMAP`) Specification

[![Static Badge](https://img.shields.io/badge/IANA-vnd.majikah.mjksmap-green)](https://www.iana.org/assignments/media-types/application/vnd.majikah.mjksmap)


**Status:** Container version 2 (CBOR); version 1 JSON remains readable
**Manifest schema version:** `1` (`0x01`)
**Format:** Self-identifying binary container carrying a CBOR-native manifest
**Purpose:** Batch/folder/archive mapping of file paths to detached `MajikSignatureEnvelope` objects

---

## 1. Scope

`MJKSMAP` is the batch-oriented manifest format used by `MajikSignatureMap`.

A map stores one entry per signed file. Each entry contains:

- a normalized relative path;
- the SHA-256 hash of the file content represented by that entry; and
- a full `MajikSignatureEnvelope` containing one or more signer records and its associated envelope metadata.

`MJKSMAP` is a **structural container and lookup manifest**. It does not create, alter, or verify the cryptographic signatures inside its entries. Signature verification is performed by the normal `MajikSignature` APIs using the envelope stored for the matched entry.

The map may calculate SHA-256 hashes while resolving files by content. This hashing is used for integrity checking and lookup; the map does not perform asymmetric signing or signature verification itself.

---

## 2. Security Model

An `MJKSMAP` entry's embedded envelope cryptographically binds the signed file content through its `contentHash` and the signatures contained in that envelope.

However, the `MJKSMAP` container itself does **not** cryptographically authenticate its own manifest structure.

In particular, the map format alone does not cryptographically bind:

- the entry path to the signed content;
- the set of entries as a complete batch;
- the order of entries;
- the presence or absence of a particular entry; or
- the map file itself to a trusted issuer.

Changing an entry's `path`, removing an entry, or adding an unrelated entry does not by itself invalidate the cryptographic signatures stored inside the unchanged entry envelopes.

Applications that require authenticated manifest membership, path provenance, or proof that a batch is complete should authenticate the manifest itself separately (for example by signing an appropriate canonical manifest representation).

---

## 3. Design Properties

### 3.1 Path-keyed

Entries are logically keyed by normalized path rather than by content hash.

This allows multiple files with identical content to coexist in one map.

For example, both of the following are valid distinct entries:

```text
copies/a.txt
copies/b.txt
```

when both files have the same `contentHash`.

### 3.2 Content-hash indexed

Each entry also stores a SHA-256 content hash. The implementation maintains an in-memory secondary hash index so a file can be searched by content when its expected path is no longer present.

### 3.3 Immutable API model

`MajikSignatureMap` is intended to be immutable. Builder methods such as `withEntry()` and `withoutEntry()` return a new map instance rather than modifying the receiver.

### 3.4 Detached-envelope based

Every map entry stores a complete `MajikSignatureEnvelope`, making the map self-contained with respect to the per-file detached signature data.

---

## 4. Binary Container Format

An `.mjksmap` file contains a fixed 13-byte header followed by exactly one length-prefixed payload. The header version selects the payload encoding.

### 4.1 Layout

| Offset | Length | Description |
|---|---:|---|
| `0` | `MJKSMAP_MAGIC_LEN` | ASCII magic bytes `MJKSMAP` |
| `MJKSMAP_MAGIC_LEN` | `1` | Container version |
| `MJKSMAP_MAGIC_LEN + 1` | `1` | Reserved byte; must be `0x00` |
| `MJKSMAP_MAGIC_LEN + 2` | `4` | Payload length as unsigned big-endian 32-bit integer |
| `MJKSMAP_HEADER_LEN` | `payloadLen` | Version-selected payload bytes |

The header constants are unchanged across versions:

- Magic: ASCII `MJKSMAP`
- Magic length: `7` bytes
- Header length: `13` bytes
- Maximum payload length: `16 MiB`

### 4.2 Container versions

| Container version | Encoding | Read | Write |
|---|---|---|---|
| `0x01` | UTF-8 JSON manifest (legacy) | Yes | No |
| `0x02` | CBOR-native manifest (current) | Yes | **Yes — default** |

New `.mjksmap` files always use container version `0x02`. Version `0x01` exists only for backward compatibility with previously generated JSON containers.

The manifest schema version inside either payload remains `1`. The container version is an encoding selector, not a change to the map's logical schema or cryptographic semantics.

### 4.3 Payload length and validation

The header records the exact number of payload bytes. Readers reject empty or oversized payloads, a declared length that exceeds the available buffer, and any trailing bytes after the declared payload.

Readers also require the reserved byte to be zero and require the payload to contain exactly one complete CBOR data item for version `0x02`. Version `0x01` is decoded as strict UTF-8 JSON.

### 4.4 Malformed binary input

Binary parsing fails with a serialization error when, among other cases:

- the input is too short to contain a complete header and non-empty payload;
- the magic bytes do not match `MJKSMAP`;
- the container version is unsupported;
- the reserved byte is nonzero;
- the payload length is invalid, oversized, truncated, or followed by trailing bytes;
- a v1 payload is not valid UTF-8 or JSON; or
- a v2 payload is malformed CBOR, contains more than one top-level data item, or does not match the MJKSMAP CBOR schema.

A v2 parsing failure is never retried as JSON.

## 5. Manifest Schema and CBOR Payload

The public object model remains `MjksMapJSON` with schema version `1`. The JSON API is retained for application interoperability and legacy v1 parsing. It is **not** the representation written inside new `.mjksmap` files.

### 5.1 Logical manifest model

The root object has the following logical shape:

```json
{
  "version": 1,
  "createdAt": "2026-01-01T00:00:00.000Z",
  "entries": []
}
```

- `version` is the manifest schema version and must equal `1`.
- `createdAt` is a non-empty ISO 8601 timestamp.
- `entries` is an array of per-file entries; an empty array is valid.

`toJSON()` continues to return this JSON-compatible representation. In that public representation, binary values are represented by their existing Base64 or hexadecimal strings.

### 5.2 CBOR-native representation (container v2)

The v2 payload is one standard CBOR map with the same logical root and entry fields. It is converted through the shared CBOR wire adapters used by `MJKSIG`; it is **not** a generic CBOR encoding of the JSON object.

Binary data is represented as CBOR byte strings (`byte string` major type), rather than Base64/hex text. This includes:

- each entry's SHA-256 `contentHash` (32 raw bytes);
- envelope signer IDs and public keys;
- per-signer content hashes and Ed25519 / ML-DSA signatures;
- allowlist hashes and signer IDs;
- seal hashes and sealer IDs;
- TSA digest values, nonces, and TSA signer fingerprints;
- revision-chain and session-context hashes; and
- chain-anchor digest values.

Text fields such as paths, timestamps, MIME types, identifiers, and transaction signatures remain CBOR text strings. File sizes remain CBOR unsigned integers. Optional fields remain omitted when absent.

The envelope uses the exact same CBOR-native field mapping as the standalone `MJKSIG` / `MajikSignatureEnvelope` adapter. A consumer must decode the binary fields to the existing JSON model before using the ordinary envelope APIs.

### 5.3 Why the binary mapping matters

Base64 expands binary data to approximately four-thirds of its original byte length. A CBOR byte string stores the underlying bytes directly, avoiding that textual expansion for hashes, public keys, signatures, and other binary envelope fields. CBOR does not compress the manifest; the size reduction comes from using binary fields instead of Base64 or hex encodings.

### 5.4 Backward compatibility

A reader selects the parser strictly from the container header:

- version `0x01`: parse the UTF-8 JSON payload and validate manifest schema `1`;
- version `0x02`: decode one CBOR data item, convert binary fields to the JSON model, and validate manifest schema `1`.

The JSON model and its schema remain unchanged, allowing existing `toJSON()` / `fromJSON()` integrations to continue working.

## 6. Entry Structure

Each map entry has the following shape:

```json
{
  "path": "docs/report.pdf",
  "contentHash": "base64-sha256-digest",
  "envelope": {
    "version": 1,
    "signatures": []
  }
}
```

### 6.1 `path`

Type: `string`

Required: non-empty after trimming.

The implementation normalizes the path before storing it on the `MajikSignatureMap` instance.

Normalization is described in Section 7.

### 6.2 `contentHash`

Type: `string`

Required: non-empty after trimming.

The intended value is the Base64 representation of the SHA-256 digest of the file bytes represented by the entry.

In the public JSON model this is a canonical Base64-encoded 32-byte SHA-256 digest. In the v2 CBOR payload the same digest is a raw 32-byte byte string.

### 6.3 `envelope`

Type: object

Required: yes.

The value must be accepted by:

```ts
MajikSignatureEnvelope.fromJSON(entry.envelope)
```

so validation of the envelope structure is delegated to the existing envelope implementation rather than duplicated by `MajikSignatureMap`.

The envelope therefore retains the normal `Majik Signature` capabilities supported by the current envelope model, including multi-signature records and any supported allowlist, seal, timestamp, revision, or chain-anchor metadata.

---

## 7. Path Normalization

The implementation applies the following normalization to paths before storing and looking them up as map keys:

1. Replace backslashes (`\\`) with forward slashes (`/`).
2. Trim leading and trailing whitespace from the complete path string.
3. Remove a Windows drive-letter prefix such as `C:` or `D:`.
4. Remove leading `/` characters.

Examples:

| Input | Normalized path |
|---|---|
| `docs\\report.pdf` | `docs/report.pdf` |
| `C:\\Users\\Alice\\report.pdf` | `Users/Alice/report.pdf` |
| `/docs/report.pdf` | `docs/report.pdf` |
| `  docs/report.pdf  ` | `docs/report.pdf` |

### 7.1 Path rules not currently enforced

The current implementation does **not** additionally resolve or reject:

- `.` path segments;
- `..` path segments;
- repeated internal `/` separators;
- control characters;
- NUL characters; or
- Unicode normalization differences.

Applications that use untrusted archive paths should apply their own archive/path-safety policy before creating a map.

### 7.2 Case sensitivity

The map's JavaScript `Map` indices compare normalized path strings exactly. No case-folding is performed by the current implementation.

Therefore, path keys are case-sensitive at the map layer:

```text
Foo.txt
foo.txt
```

are distinct strings.

---

## 8. Duplicate Paths

`fromJSON()` validation checks for duplicate path strings in the supplied `entries` array.

The duplicate check currently uses the path string as supplied to validation, before the constructor performs its storage normalization.

Therefore, applications producing untrusted JSON should normalize paths consistently before constructing manifests to avoid equivalent paths expressed in different pre-normalized forms.

`withEntry()` replaces an existing stored entry having the same normalized path rather than creating a second stored entry.

---

## 9. File Resolution

`MajikSignatureMap` provides several levels of lookup.

### 9.1 Direct path lookup

```ts
map.getEntry(path)
```

returns the entry associated with the normalized path, without reading file contents or recomputing the hash.

### 9.2 Path + content integrity check

```ts
await map.findEntry(path, file)
```

performs the following:

1. Normalize the supplied path.
2. Look up the corresponding entry.
3. Read the file bytes.
4. Compute SHA-256.
5. Encode the digest as Base64.
6. Compare it with `entry.contentHash`.

The result distinguishes:

- no entry at the supplied path; and
- an existing entry whose content hash matches or does not match.

The method does not itself perform signature verification.

### 9.3 Content-hash lookup

```ts
await map.findEntriesByHash(file)
```

hashes the supplied file and returns **all** entries having the same stored `contentHash`.

This intentionally returns an array because duplicate-content entries are valid.

### 9.4 Relocation-tolerant resolution

```ts
await map.resolveEntry(path, file)
```

uses the following order:

1. Try the normalized path.
2. If an entry exists there, recompute the file hash.
3. If the hash matches, return `path_match`.
4. If the hash does not match, return `path_tampered`.
5. If there is no direct-path entry, hash the file and search by content hash.
6. If at least one content-hash match exists, return `relocated`.
7. Otherwise return `not_found`.

The current result type is effectively:

```ts
type MjksMapResolveResult =
  | { status: "path_match"; entry: MjksMapEntry }
  | { status: "path_tampered"; entry: MjksMapEntry }
  | { status: "relocated"; entry: MjksMapEntry; originalPath: string }
  | { status: "not_found" };
```

### 9.5 Duplicate-content relocation ambiguity

When a content-hash fallback finds multiple entries, the current implementation returns the **first** matching entry and exposes its `path` as `originalPath`.

This means content-only relocation is not inherently one-to-one when duplicate files share the same hash.

Applications requiring unambiguous whole-batch reconstruction should use the full set returned by `findEntriesByHash()` and perform their own batch-level matching policy.

---

## 10. Cryptographic Verification

`MajikSignatureMap` itself does not verify `Ed25519`, `ML-DSA-87`, TSA records, seals, or chain anchors.

After an entry has been resolved, callers should use the corresponding envelope with the normal `MajikSignature` verification APIs.

For example, the batch verification API uses the map to locate the correct entry, then delegates the cryptographic check to the signature layer.

Conceptually:

```text
MJKSMAP
  │
  ├── path ──────────────► locate file entry
  │
  ├── contentHash ───────► verify content identity
  │
  └── envelope ──────────► MajikSignature verification
```

The map therefore acts as a manifest/index rather than as another cryptographic protocol.

---

## 11. Envelope Equivalence with `MJKSIG`

The `envelope` field uses the same JSON envelope model as the standalone detached signature container (`MJKSIG`).

That means a map entry can be treated as a detached multi-signature envelope and converted with the same envelope APIs used elsewhere in the library.

For example:

```ts
const envelope = map.getEnvelope("docs/report.pdf");
```

returns a `MajikSignatureEnvelope` instance, or `null` when the path has no map entry.

The map does not alter the envelope's internal cryptographic semantics.

---

## 12. Immutable Builder API

### `MajikSignatureMap.empty()`

Creates a new logical map using manifest schema version 1 (new binary output is still container v2) with:

- `version: 1`;
- `createdAt: new Date().toISOString()`; and
- an empty `entries` array.

### `withEntry(entry)`

Returns a new map containing the supplied entry.

The entry path is normalized before storage. If an existing stored entry has the same normalized path, that entry is replaced.

The receiver is not modified.

### `withoutEntry(path)`

Returns a new map with entries matching the normalized path removed.

The receiver is not modified.

---

## 13. Serialization APIs

### JSON

```ts
map.toJSON()
MajikSignatureMap.fromJSON(json)
```

`fromJSON()` accepts either:

- a `MjksMapJSON` object; or
- a JSON string.

The parser performs structural validation before constructing the map.

### Base64

Unlike `MajikSignature` and `MajikSignatureEnvelope`, `MajikSignatureMap` does not currently define a dedicated `serialize()` / `deserialize()` Base64 API. Its portable serialized representations are its JSON form and the `.mjksmap` binary container.

### Binary

```ts
map.toMJKSMAPBytes()
map.toMJKSMAP()
MajikSignatureMap.fromMJKSMAP(input)
```

`toMJKSMAPBytes()` returns a `Uint8Array`.

`toMJKSMAP()` returns a `Blob` using the configured `MJKSMAP_MEDIA_TYPE`.

`fromMJKSMAP()` accepts either a `Blob` or a `Uint8Array` and returns a `Promise<MajikSignatureMap>`.

---

## 14. Type-agnostic Input Conversion

The universal constructor helper:

```ts
MajikSignatureMap.from(input)
```

accepts any of:

- an existing `MajikSignatureMap` instance;
- a `MjksMapJSON` object;
- a JSON/binary `Uint8Array`; or
- a `Blob`.

Instances are returned unchanged. Binary inputs are parsed as `.mjksmap` containers. Object inputs are parsed as JSON map structures.

---

## 15. Structural Validation

```ts
map.validate()
```

re-runs shape validation and throws a `MajikSignatureValidationError` for structural failures.

```ts
map.isValid()
```

returns `false` instead of throwing for validation failures.

Current structural checks include:

### Root

- object, not `null`;
- not an array;
- `version === 1`;
- non-empty `createdAt` string;
- `entries` is an array.

### Entry

- entry is an object;
- `path` is a non-empty string;
- `contentHash` is a non-empty string;
- `envelope` is an object;
- envelope passes `MajikSignatureEnvelope.fromJSON()` validation.

### Duplicate path check

Duplicate path strings in the supplied JSON array are rejected.

Unknown JSON properties are not currently rejected by `MajikSignatureMap` itself.

---

## 16. Format Identification

```ts
await MajikSignatureMap.isMJKSMAP(input)
```

is a **cheap magic-byte check**.

It checks only whether the leading bytes match the `MJKSMAP_MAGIC` sequence.

It does **not**:

- parse or validate the version-selected JSON/CBOR payload;
- validate the payload length;
- validate the schema version; or
- validate the contents of the map.

Consequently, `isMJKSMAP()` should be treated as a format sniff, not as proof that the input is a valid map.

---

## 17. Media Type and Extension

The format uses the following media type and extension:

| Property | Value |
|---|---|
| Extension | `.mjksmap` |
| Media type | `application/vnd.majikah.mjksmap` |
| Magic bytes | `MJKSMAP` |

The media type is emitted by `toMJKSMAP()` through the returned `Blob`.

---

## 18. Relationship to ZIP / Folder Batches

`MJKSMAP` is designed to accompany a group of files, including files extracted from a ZIP/archive or collected from a folder.

A typical layout is:

```text
project.zip
├── docs/
│   ├── report.pdf
│   └── appendix.pdf
├── assets/
│   └── cover.png
└── signatures.mjksmap
```

The paths stored in the manifest are intended to identify files relative to the batch/archive root.

The current map format does not itself encode directory metadata, archive metadata, filesystem permissions, symlink information, or filesystem timestamps.

The manifest also does not automatically include or exclude the `.mjksmap` file itself; deciding which files belong to a batch is the responsibility of the caller creating the map.

---

## 19. Recommended Batch Verification Flow

A typical batch verification process is:

```text
1. Load MJKSMAP
2. Parse and validate the manifest
3. For each supplied file:
   a. normalize its path
   b. try direct path lookup
   c. recompute SHA-256 if a path entry exists
   d. if the path is missing, search by content hash
   e. obtain the corresponding envelope
   f. verify the envelope using MajikSignature
4. Record the per-file verification result
5. Summarize the batch
```

The higher-level library API:

```ts
MajikSignature.verifyFilesFromMjksMap(...)
```

implements this workflow and returns a `FileVerifyResult[]` instead of requiring the caller to manually iterate over every entry.

---

## 20. Batch Verification Result Semantics

The current public batch verification result uses these statuses:

```ts
"verified"
"invalid"
"tampered"
"not_in_map"
```

Their intended meanings are:

### `verified`

A supplied file was matched to a map entry and the corresponding signature verification succeeded.

### `invalid`

A map entry was located, but cryptographic verification of its signature/envelope did not succeed.

### `tampered`

A direct path match was found, but the supplied file's hash does not match the stored `contentHash`.

### `not_in_map`

The supplied file could not be associated with an entry in the map.

The batch result may also include:

```ts
relocatedFrom?: string
```

when a file was found through content-hash fallback rather than its original path.

---

## 21. Current API Surface

The current `MajikSignatureMap` class exposes:

### Properties

```ts
version
createdAt
entries
size
```

### Lookup

```ts
getEntry(path)
hasEntry(path)
findEntry(path, file)
findEntriesByHash(file)
resolveEntry(path, file)
getEnvelope(path)
getAllEnvelopes()
```

### Immutable builders

```ts
withEntry(entry)
withoutEntry(path)
```

### Serialization

```ts
toJSON()
toMJKSMAPBytes()
toMJKSMAP()
```

### Parsing / creation

```ts
MajikSignatureMap.empty()
MajikSignatureMap.fromJSON(json)
MajikSignatureMap.fromMJKSMAP(input)
MajikSignatureMap.from(input)
```

### Validation / identification

```ts
validate()
isValid()
MajikSignatureMap.isMJKSMAP(input)
```

---

## 22. Size and Performance Considerations

Each entry embeds a complete `MajikSignatureEnvelope`, so map size grows with the number of files and signers rather than with file content size. Container v2 stores cryptographic binary fields as CBOR byte strings, avoiding Base64/hex expansion in the on-disk payload.

The map stores hashes rather than file bytes. A large video and a small text file therefore contribute approximately the same hash-field size, although their envelopes may differ depending on the number of signers and optional metadata.

Lookup by path is intended to be inexpensive because the implementation maintains an in-memory path index.

Lookup by content requires reading and hashing the candidate file.

For large batches, callers should avoid repeatedly hashing the same file bytes when they can reuse an already-computed SHA-256 digest. The binary payload is limited to 16 MiB; JSON API inputs allow up to 24 MiB to account for Base64 representation overhead, while legacy v1 binary JSON payloads remain subject to the 16 MiB container limit.

---

## 23. Compatibility and Versioning

The current binary writer uses container version `2` (CBOR). Readers accept container versions `1` (legacy JSON) and `2` (CBOR). Both payload encodings carry manifest schema version `1`.

Consumers must reject unsupported container versions rather than guessing how to interpret them.

Future versions may change the JSON structure or binary encoding while retaining the self-identifying header mechanism.

A future implementation should use a new supported version rather than silently changing version-1 semantics.

---

## 24. Reference Constants

The format is defined in the library by constants including:

```ts
MJKSMAP_MAGIC
MJKSMAP_MAGIC_LEN
MJKSMAP_HEADER_LEN
MJKSMAP_MEDIA_TYPE
MJKSMAP_SUPPORTED_VERSIONS
MJKSMAP_JSON_VERSION
MJKSMAP_CBOR_VERSION
MJKSMAP_SCHEMA_VERSION
MJKSMAP_VERSION
```

The current documented values are:

```text
MJKSMAP_MAGIC        = ASCII "MJKSMAP"
MJKSMAP_MAGIC_LEN    = 7
MJKSMAP_JSON_VERSION   = 0x01  (legacy JSON reader)
MJKSMAP_CBOR_VERSION   = 0x02  (current writer)
MJKSMAP_VERSION        = 0x02  (current container version)
MJKSMAP_SCHEMA_VERSION = 0x01
MJKSMAP_HEADER_LEN   = 13
```

`MJKSMAP_MEDIA_TYPE` is:

```text
application/vnd.majikah.mjksmap
```

---

## 25. Reference Example

### JSON form

```json
{
  "version": 1,
  "createdAt": "2026-09-23T03:00:00.000Z",
  "entries": [
    {
      "path": "docs/report.pdf",
      "contentHash": "<base64-sha256>",
      "envelope": {
        "version": 1,
        "signatures": [
          {
            "version": 1,
            "signerId": "<signer-id>",
            "signerEdPublicKey": "<base64-ed25519-public-key>",
            "signerMlDsaPublicKey": "<base64-ml-dsa-public-key>",
            "contentHash": "<base64-sha256>",
            "contentType": "application/pdf",
            "timestamp": "2026-09-23T03:00:00.000Z",
            "edSignature": "<base64-ed25519-signature>",
            "mlDsaSignature": "<base64-ml-dsa-87-signature>"
          }
        ]
      }
    }
  ]
}
```

The exact structure of the `envelope` is governed by the `MajikSignatureEnvelope` specification and implementation; `MJKSMAP` does not redefine those cryptographic fields.

---

## 26. Non-Goals

`MJKSMAP` does not by itself provide:

- cryptographic signing of the manifest;
- proof that a path is owned by a particular signer;
- proof that a manifest contains every file in an archive;
- proof that no extra files exist outside the manifest;
- archive extraction or filesystem traversal;
- filesystem metadata preservation;
- symlink policy;
- public-key trust or identity resolution; or
- cryptographic verification of embedded envelopes.

Those responsibilities belong to the surrounding application and the existing `MajikSignature` / `MajikSignatureEnvelope` layers.

---

## 27. Summary

`MJKSMAP` is a compact, versioned batch manifest that maps normalized file paths to SHA-256 content identifiers and detached `MajikSignatureEnvelope` objects.

Its main responsibilities are:

1. represent a collection of signed files;
2. provide efficient path-based lookup;
3. retain content hashes for integrity checking and relocation lookup;
4. carry full detached multi-signature envelopes alongside their entries; and
5. convert binary envelope fields to CBOR byte strings and serialize the manifest into a self-identifying MJKSMAP v2 `.mjksmap` container.

Its cryptographic responsibility ends at carrying the existing signature envelopes. The actual authenticity decision remains with the `MajikSignature` verification layer and, where applicable, the application's trust policy for signer identities.
