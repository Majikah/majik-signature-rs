//! Port of `core/embed/constants.ts` — embed-format constants.

/// 8-byte magic closing the universal trailer: `"MAJIKSIG"`.
pub const TRAILER_MAGIC: [u8; 8] = [0x4d, 0x41, 0x4a, 0x49, 0x4b, 0x53, 0x49, 0x47];
/// `[payloadLen(8, LE u64)][magic(8)]`.
pub const TRAILER_SUFFIX_LENGTH: usize = 16;

/// Key / keyword under which the envelope is stored in text-like containers.
pub const SIGNATURE_KEY: &str = "majik-signature";
pub const MAJIK_NAMESPACE: &str = "https://signature.majikah.solutions";

pub const PNG_CHUNK_TYPE: &str = "iTXt";
pub const PNG_KEYWORD: &str = "majik-signature";
pub const RIFF_CHUNK_FOURCC: &str = "majk";
pub const ID3_TXXX_DESCRIPTION: &str = "MAJIK-SIGNATURE";
pub const OFFICE_ZIP_ENTRY: &str = "majik-signature.json";
pub const MP4_BOX_TYPE: &str = "majk";
/// Custom metadata key for MKV/WebM.
pub const MKV_TAG_NAME: &str = "MAJIK_SIGNATURE";

/// Fixed ZIP entry timestamp (1995-10-26T00:00:00Z) so re-zipping identical content always
/// yields identical bytes. DOS time supports 1980–2099; any constant in range works.
pub const CANONICAL_MTIME: (u16, u8, u8, u8, u8, u8) = (1995, 10, 26, 0, 0, 0);
