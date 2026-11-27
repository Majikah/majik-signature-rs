//! Port of `core/embed/`.

pub mod canonical;
/// Shared identifiers and names used by embedded file-format handlers.
pub mod constants;
/// Codec for version-marked embedded envelope payloads and legacy representations.
pub mod embedded_envelope_codec;
/// Generic trailing-block fallback handler for formats without a native metadata container.
pub mod fallback;
/// Built-in format-specific embedding and extraction handlers.
pub mod handlers;
/// High-level orchestration over format handlers for sign, verify, embed, extract, and seal operations.
pub mod majik_embed;
/// Registry used to select a format handler from MIME type and file bytes.
pub mod registry;
/// Binary and text helpers shared by embedded-format handlers.
pub mod utils;
/// Bounded ZIP read/write helpers used for Office and archive-based formats.
pub mod zipio;
