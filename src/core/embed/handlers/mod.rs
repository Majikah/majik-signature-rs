//! Port of `core/embed/handlers/index.ts` — the per-format embed handlers.

/// FLAC metadata handler for embedded Majik Signature envelopes.
pub mod flac;
/// JPEG APP-segment metadata handler.
pub mod jpeg;
/// Matroska container metadata handler.
pub mod mkv;
/// MP3 ID3 metadata handler.
pub mod mp3;
/// MP4/ISO-BMFF metadata handler.
pub mod mp4;
/// MSIX package metadata handler.
pub mod msix;
/// Office/ODF ZIP-package metadata handler.
pub mod office;
/// PDF document metadata handler.
pub mod pdf;
/// PNG ancillary-chunk metadata handler.
pub mod png;
/// Supported text-format metadata handler.
pub mod text;
/// WAV RIFF metadata handler.
pub mod wav;

pub use flac::FlacHandler;
pub use jpeg::JpegHandler;
pub use mkv::MkvHandler;
pub use mp3::Mp3Handler;
pub use mp4::Mp4Handler;
pub use msix::MsixHandler;
pub use office::OfficeHandler;
pub use pdf::PdfHandler;
pub use png::PngHandler;
pub use text::TextHandler;
pub use wav::WavHandler;
