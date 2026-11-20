# Changelog

## Unreleased
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
