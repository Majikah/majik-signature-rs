//! Rust-only helper: deterministic ZIP I/O for the Office handler.
//!
//! TS builds Office/ODF containers with `fflate.zipSync(files, { level: 0 })` and a pinned
//! `mtime`. The Office canonical-form check compares `embed(strip(bytes))` with the file
//! byte-for-byte, so the Rust port must emit the *same bytes* as fflate. The `zip` crate adds
//! its own extra fields / header layout, so *writing* is done here by hand (stored entries
//! only, exactly fflate's layout); the `zip` crate is used only for *reading*.
//!
//! Layout notes (all copied from fflate 0.8):
//! - local header: version-needed 20, flags 0 (bit 11 / `0x0800` set only for non-ASCII
//!   names), method 0, DOS time/date, CRC-32, sizes, name length, extra length 0;
//! - central header: version-made-by `20, 0`, otherwise the same, then comment length 0,
//!   disk 0, internal attrs 0, external attrs 0, local-header offset;
//! - end record: entry counts, central directory size/offset, comment length 0;
//! - entries keep their given order. A duplicate name replaces the data in place.
//!
//! The DOS timestamp is written in **UTC** (fflate uses the local zone, which makes its own
//! output machine-dependent unless the machine runs in UTC).

use std::io::{Cursor, Read};

use crate::core::embed::constants::CANONICAL_MTIME;
use crate::core::embed::utils::crc32;
use crate::core::errors::{MajikSignatureError, MajikSignatureResult};

/// Upper bound for the total uncompressed size of an archive we are willing to process.
pub const MAX_UNZIPPED_BYTES: u64 = 512 * 1024 * 1024;

/// An ordered `name → bytes` map (a JS object with string keys, in insertion order).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ZipEntries {
    entries: Vec<(String, Vec<u8>)>,
}

impl ZipEntries {
    pub fn new() -> Self {
        Self::default()
    }
    /// `files[name] = data` — replaces in place if the name exists, else appends.
    pub fn set(&mut self, name: String, data: Vec<u8>) {
        match self.entries.iter_mut().find(|(n, _)| *n == name) {
            Some(slot) => slot.1 = data,
            None => self.entries.push((name, data)),
        }
    }
    /// `delete files[name]`.
    pub fn remove(&mut self, name: &str) {
        self.entries.retain(|(n, _)| n != name);
    }
    pub fn get(&self, name: &str) -> Option<&[u8]> {
        self.entries.iter().find(|(n, _)| n == name).map(|(_, d)| d.as_slice())
    }
    pub fn contains(&self, name: &str) -> bool {
        self.get(name).is_some()
    }
    pub fn iter(&self) -> impl Iterator<Item = &(String, Vec<u8>)> {
        self.entries.iter()
    }
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

fn zip_err(e: impl std::fmt::Display) -> MajikSignatureError {
    MajikSignatureError::new(format!("Invalid ZIP archive: {e}"))
}

/// Decode an entry name the way fflate does: UTF-8 when valid, else Latin-1.
fn decode_name(raw: &[u8]) -> String {
    match std::str::from_utf8(raw) {
        Ok(s) => s.to_string(),
        Err(_) => raw.iter().map(|&b| b as char).collect(),
    }
}

/// Entry names, in central-directory order, without decompressing anything.
pub fn list_names(bytes: &[u8]) -> MajikSignatureResult<Vec<String>> {
    let archive = zip::ZipArchive::new(Cursor::new(bytes)).map_err(zip_err)?;
    let mut out = Vec::with_capacity(archive.len());
    let mut archive = archive;
    for i in 0..archive.len() {
        let f = archive.by_index_raw(i).map_err(zip_err)?;
        out.push(decode_name(f.name_raw()));
    }
    Ok(out)
}

/// Read selected entries (`want(name, uncompressed_size)`), in archive order.
pub fn unzip_filtered(
    bytes: &[u8],
    mut want: impl FnMut(&str, u64) -> bool,
) -> MajikSignatureResult<ZipEntries> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).map_err(zip_err)?;
    let mut out = ZipEntries::new();
    for i in 0..archive.len() {
        let (name, size) = {
            let f = archive.by_index_raw(i).map_err(zip_err)?;
            (decode_name(f.name_raw()), f.size())
        };
        if !want(&name, size) {
            continue;
        }
        let mut f = archive.by_index(i).map_err(zip_err)?;
        let mut data = Vec::with_capacity(size.min(1 << 24) as usize);
        f.read_to_end(&mut data).map_err(zip_err)?;
        out.set(name, data);
    }
    Ok(out)
}

/// Read every entry, refusing archives whose declared total exceeds [`MAX_UNZIPPED_BYTES`].
pub fn unzip_bounded(bytes: &[u8]) -> MajikSignatureResult<ZipEntries> {
    let mut total: u64 = 0;
    // The size check must happen before any entry is inflated.
    {
        let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).map_err(zip_err)?;
        for i in 0..archive.len() {
            total += archive.by_index_raw(i).map_err(zip_err)?.size();
            if total > MAX_UNZIPPED_BYTES {
                return Err(MajikSignatureError::new("Archive too large to process"));
            }
        }
    }
    unzip_filtered(bytes, |_, _| true)
}

fn dos_time_date() -> (u16, u16) {
    let (year, month, day, hour, minute, second) = CANONICAL_MTIME;
    let time = ((hour as u16) << 11) | ((minute as u16) << 5) | ((second as u16) >> 1);
    let date = ((year - 1980) << 9) | ((month as u16) << 5) | day as u16;
    (time, date)
}

fn u16le(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_le_bytes());
}
fn u32le(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}

/// `fflate.zipSync(toZippable(files), { level: 0 })` with the canonical mtime.
pub fn zip_stored(files: &ZipEntries) -> MajikSignatureResult<Vec<u8>> {
    let (dos_time, dos_date) = dos_time_date();
    let mut local = Vec::new();
    let mut central = Vec::new();

    for (name, data) in files.iter() {
        let name_bytes = name.as_bytes();
        if name_bytes.len() > 65535 {
            return Err(MajikSignatureError::new("ZIP entry name too long"));
        }
        // fflate: `u = utf8Len != utf16Len`
        let utf16_len = name.encode_utf16().count();
        let flags_hi: u8 = if name_bytes.len() != utf16_len { 8 } else { 0 };
        let crc = crc32(data);
        let offset = local.len() as u32;
        let len = data.len() as u32;

        // local file header
        u32le(&mut local, 0x0403_4b50);
        u16le(&mut local, 20); // version needed
        local.push(0); // flags (low byte)
        local.push(flags_hi); // flags (high byte)
        u16le(&mut local, 0); // method: stored
        u16le(&mut local, dos_time);
        u16le(&mut local, dos_date);
        u32le(&mut local, crc);
        u32le(&mut local, len); // compressed size
        u32le(&mut local, len); // uncompressed size
        u16le(&mut local, name_bytes.len() as u16);
        u16le(&mut local, 0); // extra length
        local.extend_from_slice(name_bytes);
        local.extend_from_slice(data);

        // central directory header
        u32le(&mut central, 0x0201_4b50);
        central.push(20); // version made by
        central.push(0); // host OS (fflate leaves `os` undefined → 0)
        u16le(&mut central, 20); // version needed
        central.push(0);
        central.push(flags_hi);
        u16le(&mut central, 0);
        u16le(&mut central, dos_time);
        u16le(&mut central, dos_date);
        u32le(&mut central, crc);
        u32le(&mut central, len);
        u32le(&mut central, len);
        u16le(&mut central, name_bytes.len() as u16);
        u16le(&mut central, 0); // extra length
        u16le(&mut central, 0); // comment length
        u16le(&mut central, 0); // disk number start
        u16le(&mut central, 0); // internal attrs
        u32le(&mut central, 0); // external attrs
        u32le(&mut central, offset);
        central.extend_from_slice(name_bytes);
    }

    let mut out = local;
    let cd_offset = out.len() as u32;
    let cd_size = central.len() as u32;
    out.extend_from_slice(&central);
    // end of central directory
    u32le(&mut out, 0x0605_4b50);
    u16le(&mut out, 0); // disk
    u16le(&mut out, 0); // disk with CD
    u16le(&mut out, files.len() as u16);
    u16le(&mut out, files.len() as u16);
    u32le(&mut out, cd_size);
    u32le(&mut out, cd_offset);
    u16le(&mut out, 0); // comment length
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_stored() {
        let mut e = ZipEntries::new();
        e.set("a.txt".into(), b"hello".to_vec());
        e.set("dir/".into(), Vec::new());
        e.set("dir/b.bin".into(), vec![1, 2, 3]);
        let z = zip_stored(&e).unwrap();
        let back = unzip_bounded(&z).unwrap();
        assert_eq!(back, e);
        // Deterministic.
        assert_eq!(z, zip_stored(&back).unwrap());
    }
}
