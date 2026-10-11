//! Port of `core/embed/handlers/index.ts` — the per-format embed handlers.

pub mod flac;
pub mod jpeg;
pub mod mkv;
pub mod mp3;
pub mod mp4;
pub mod msix;
pub mod office;
pub mod pdf;
pub mod png;
pub mod text;
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
