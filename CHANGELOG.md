# Changelog

## 1.6.0 - 2026-11-28
- Align the core release version with the TypeScript package.
- Match TypeScript and Rust streaming chunk-size limits at 64 KiB–64 MiB, retaining a 1 MiB default and 8 MiB automatic threshold.
- Enforce declared total stream lengths, rejecting both truncated and overlong readers before accepting a digest.
- Add regression coverage for expected-length validation and cross-path hash equivalence.
- Add `MajikSignature::sign_batch_detached_stream()` with sequential reader consumption, bounded chunking, per-file progress, cancellation, and per-file failure collection.
- Preserve existing `.mjksmap` / `.mjksig` batch result formats for streaming inputs.
- Add `MajikSignature::verify_files_from_mjksmap_stream()` with single-pass digest verification, path-first tamper detection, and content-hash relocation.
- Cover both MJKSMAP and separate MJKSIG output modes in streaming batch signing tests.
- Bound MJKSMAP payloads to 16 MiB, entries to 10,000, and normalized paths to 4,096 UTF-16 code units; reject traversal, spoofing controls, duplicate normalized paths, malformed UTF-8, trailing bytes, invalid header fields, and file sizes above JavaScript's safe-integer range.
- Apply the 16 MiB envelope ceiling to typed objects and immutable builders; reject oversized Base64 before decoding and validate builder-supplied signatures, allowlists, seals, anchors, and revision metadata.
- Add virtual 32 MiB multi-chunk stress tests and an opt-in 10 GiB reader stress test, plus read-failure and invalid chunk configuration regressions.

## 1.5.1 - 2026-11-27
- Raise the configurable reader-hashing chunk ceiling to 128 MiB.
- Allocate streaming hash buffers fallibly before reading input, returning a normal error on reservation failure.
- Add minimum/maximum chunk-boundary validation tests.

## Unreleased
- Upgrade `jiff` to 1.0.3 and `majik-key` to 1.2.0; migrate civil date/time conversions to `to_zoned_datetime`, preserve UTC parsing semantics, and raise the MSRV to Rust 1.88.
- Add explicit SignRoom FileVersion commitments and bind no-revision session signatures to the existing revision-chain hash without appending a new version.
- Validate explicit revision order, previous-entry linkage, creator fingerprint, canonical timestamp, and document content digest before signing.
- Add session-aware detached-file signing and strict per-participant SignRoom verification APIs, including MJKSIG sidecar output, revision-chain checks, allowlist/seal integrity, and optional pinned TSA verification.
- Add Rust tests for single-signer and multi-signer SignRoom detached workflows, including visual-stamp revision chains and challenge isolation.
- Add SignRoom session-context commitments, digest-only hybrid verification, and signature-scoped TSA attestations with optional trusted TSA fingerprint pinning.
- Extend JSON, compact signature, and CBOR wire representations while preserving legacy signatures and content-scoped TSA payloads.


## 1.0.0
- Initial pure-Rust port of `@majikah/majik-signature` 0.10.0 (core, envelope, MJKSMAP, signing order, embed handlers, revision chains, TSA, chain anchors, stamp, `mjksig` CLI).
- Verified wire-compatible with the TypeScript package in both directions (signatures, multi-sig, allowlist, seal, DOCX, PNG).
- Image stamp reworked (see README → *Deliberate differences*).
