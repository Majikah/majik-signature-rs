//! Port of `cli-core/io.ts` — filesystem helpers.

use std::fs;
use std::path::{Path, PathBuf};

use crate::cli_core::types::FolderFile;

/// Type-erased error returned by CLI filesystem and operation helpers.
pub type CliError = Box<dyn std::error::Error + Send + Sync>;
/// Standard result type for reusable CLI operations.
pub type CliOutcome<T> = Result<T, CliError>;

/// Convert a human-readable CLI failure message into the boxed error type.
pub fn err(msg: impl Into<String>) -> CliError {
    msg.into().into()
}

/// Infer a MIME type from a path extension, using a generic fallback for unknown types.
pub fn mime_type_for_path(path: &Path) -> String {
    let ext = path.extension().and_then(|e| e.to_str()).map(|e| format!(".{}", e.to_lowercase()));
    let m = match ext.as_deref() {
        Some(".txt") => "text/plain",
        Some(".md") => "text/markdown",
        Some(".csv") => "text/csv",
        Some(".json") => "application/json",
        Some(".xml") => "application/xml",
        Some(".html") | Some(".htm") => "text/html",
        Some(".pdf") => "application/pdf",
        Some(".png") => "image/png",
        Some(".jpg") | Some(".jpeg") => "image/jpeg",
        Some(".webp") => "image/webp",
        Some(".gif") => "image/gif",
        Some(".mp3") => "audio/mpeg",
        Some(".wav") => "audio/wav",
        Some(".flac") => "audio/flac",
        Some(".mp4") => "video/mp4",
        Some(".mkv") => "video/x-matroska",
        Some(".docx") => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        Some(".xlsx") => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        Some(".pptx") => "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        Some(".zip") => "application/zip",
        Some(".exe") => "application/vnd.microsoft.portable-executable",
        Some(".msi") => "application/x-msi",
        Some(".msix") => "application/msix",
        Some(".deb") => "application/vnd.debian.binary-package",
        Some(".mjksig") => "application/vnd.majikah.mjksig",
        Some(".mjksmap") => "application/vnd.majikah.mjksmap",
        _ => "application/octet-stream",
    };
    m.to_string()
}

/// Check whether a path has a known Majik Signature artifact extension.
pub fn is_majik_artifact(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|e| e.to_str()).map(|e| e.to_lowercase()).as_deref(),
        Some("mjksig") | Some("mjksmap")
    )
}

/// Convert a target path into a root-relative forward-slash path for manifest entries.
pub fn relative_posix(root: &Path, target: &Path) -> String {
    let rel = target.strip_prefix(root).unwrap_or(target);
    rel.to_string_lossy().replace('\\', "/").trim_start_matches('/').trim().to_string()
}

/// Resolve a CLI-provided path against the current working directory.
pub fn resolve_cli_path(path: &str) -> PathBuf {
    let p = Path::new(path);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir().unwrap_or_default().join(p)
    }
}

/// Read an entire file into memory; use reader-based APIs for large files.
pub fn read_bytes(path: &Path) -> CliOutcome<Vec<u8>> {
    fs::read(path).map_err(|e| err(format!("{}: {e}", path.display())))
}

/// Read a UTF-8 JSON file and deserialize it into the requested type.
pub fn read_json_file<T: serde::de::DeserializeOwned>(path: &Path) -> CliOutcome<T> {
    let text = fs::read_to_string(path).map_err(|e| err(format!("{}: {e}", path.display())))?;
    serde_json::from_str(&text).map_err(|e| err(format!("Invalid JSON in \"{}\": {e}", path.display())))
}

/// Write bytes to a destination while enforcing the explicit overwrite policy.
pub fn write_bytes(path: &Path, bytes: &[u8], overwrite: bool) -> CliOutcome<()> {
    if !overwrite && path.exists() {
        return Err(err(format!(
            "Output already exists: \"{}\". Use --overwrite to replace it.",
            path.display()
        )));
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, bytes)?;
    Ok(())
}

fn walk(root: &Path, current: &Path, out: &mut Vec<FolderFile>) -> CliOutcome<()> {
    let mut entries: Vec<_> = fs::read_dir(current)?.collect::<Result<_, _>>()?;
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let path = entry.path();
        let ft = entry.file_type()?;
        if ft.is_symlink() {
            continue;
        }
        if ft.is_dir() {
            walk(root, &path, out)?;
            continue;
        }
        if !ft.is_file() || is_majik_artifact(&path) {
            continue;
        }
        let bytes = fs::read(&path)?;
        out.push(FolderFile {
            relative_path: relative_posix(root, &path),
            size: bytes.len() as u64,
            mime_type: mime_type_for_path(&path),
            bytes,
            absolute_path: path,
        });
    }
    Ok(())
}

/// Every regular file under `root` (symlinks and `.mjksig`/`.mjksmap` skipped), sorted.
pub fn read_folder_files(root_path: &Path) -> CliOutcome<Vec<FolderFile>> {
    let root = fs::canonicalize(root_path)?;
    if !root.is_dir() {
        return Err(err(format!("Expected a directory: \"{}\"", root.display())));
    }
    let mut out = Vec::new();
    walk(&root, &root, &mut out)?;
    out.sort_by_key(|file| file.relative_path.to_lowercase());
    Ok(out)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Filesystem path classification used by CLI input validation.
pub enum PathKind {
    File,
    Directory,
}

impl PathKind {
    /// Return the stable human-readable name for this path kind.
    pub fn name(&self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Directory => "directory",
        }
    }
}

/// Inspect a path and return its supported file/directory kind or a filesystem error.
pub fn get_path_kind(path: &Path) -> CliOutcome<PathKind> {
    let md = fs::metadata(path).map_err(|_| err(format!("Path does not exist: \"{}\"", path.display())))?;
    if md.is_dir() {
        Ok(PathKind::Directory)
    } else if md.is_file() {
        Ok(PathKind::File)
    } else {
        Err(err(format!("Unsupported filesystem object: \"{}\"", path.display())))
    }
}

/// Derive the default detached-signature output path for an input file.
pub fn output_path_for_detached_file(input: &Path) -> PathBuf {
    let mut s = input.as_os_str().to_os_string();
    s.push(".mjksig");
    PathBuf::from(s)
}

/// Derive the default MJKSMAP output path for a directory batch.
pub fn output_path_for_map(input_dir: &Path) -> PathBuf {
    input_dir.join("signatures.mjksmap")
}

/// Derive the default map output path when a bundle/archive path is also supplied.
pub fn output_path_for_map_bundle(input_dir: &Path, map_path: &Path) -> PathBuf {
    let dir_name = input_dir.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let map_name = map_path.file_stem().and_then(|n| n.to_str()).unwrap_or("map");
    let base = if dir_name.is_empty() { map_name } else { dir_name };
    map_path.parent().unwrap_or(Path::new(".")).join(format!("{base}.mjksbundle.zip"))
}

/// Return the crate version embedded at compile time.
pub fn package_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Return the file count and aggregate byte length for a discovered batch.
pub fn summarize_files(files: &[FolderFile]) -> (usize, u64) {
    (files.len(), files.iter().map(|f| f.size).sum())
}
