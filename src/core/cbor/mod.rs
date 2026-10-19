//! Port of `core/cbor/` — standard CBOR encoding/decoding and the JSON ⇄ CBOR wire adapter.
//!
//! * [`codec`] ↔ `cbor.ts`      — `encode_cbor` / `decode_cbor` (single top-level item only).
//! * [`wire`]  ↔ `cbor-wire.ts` — converts the JSON-compatible types into CBOR-native maps
//!   where binary fields (Base64/hex in JSON) become real CBOR byte strings.
//!
//! The TS `types.ts` wire interfaces have no separate Rust file: the wire schema is expressed
//! directly by [`wire`] over [`ciborium::value::Value`], so decoding stays as strict as TS.
//!
//! This is a serialization format only; the signed canonical payload is unchanged.

pub mod codec;
pub mod wire;

pub use codec::{decode_cbor, encode_cbor, CborError};
pub use wire::{envelope_from_cbor, envelope_to_cbor, signature_from_cbor, signature_to_cbor};
