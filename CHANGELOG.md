# Changelog

## Unreleased
- Add SignRoom session-context commitments, digest-only hybrid verification, and signature-scoped TSA attestations with optional trusted TSA fingerprint pinning.
- Extend JSON, compact signature, and CBOR wire representations while preserving legacy signatures and content-scoped TSA payloads.


## 1.0.0
- Initial pure-Rust port of `@majikah/majik-signature` 0.10.0 (core, envelope, MJKSMAP, signing order, embed handlers, revision chains, TSA, chain anchors, stamp, `mjksig` CLI).
- Verified wire-compatible with the TypeScript package in both directions (signatures, multi-sig, allowlist, seal, DOCX, PNG).
- Image stamp reworked (see README → *Deliberate differences*).
