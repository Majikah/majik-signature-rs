//! Port of `core/stamp/core/stub.ts` — fixed 150-byte binary stub (the DCT-layer payload).
//!
//! Layout: `MSIG`(4) · version u16 BE(2) · pHash(8) · Ed25519 pubkey(32) · timestamp ms
//! u64 BE(8) · signerId UTF-8, NUL-padded/truncated(32) · Ed25519 signature(64).

use crate::core::stamp::core::types::ImageSignatureStub;
use crate::core::time::{parse_iso_millis, to_iso_string};

const MAGIC: [u8; 4] = [0x4d, 0x53, 0x49, 0x47]; // "MSIG"
const VERSION: u16 = 1;
pub const STUB_SIZE: usize = 150;

fn hex_to_bytes(hex: &str, expected_len: usize) -> Result<Vec<u8>, String> {
    let clean = hex.strip_prefix("0x").unwrap_or(hex);
    if clean.len() != expected_len * 2 {
        return Err(format!("hexToBytes: expected {} hex chars, got {}", expected_len * 2, clean.len()));
    }
    (0..expected_len)
        .map(|i| u8::from_str_radix(&clean[i * 2..i * 2 + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

pub fn serialize_stub(stub: &ImageSignatureStub) -> Result<Vec<u8>, String> {
    let mut buf = vec![0u8; STUB_SIZE];
    let mut o = 0;
    buf[o..o + 4].copy_from_slice(&MAGIC);
    o += 4;
    buf[o..o + 2].copy_from_slice(&VERSION.to_be_bytes());
    o += 2;
    buf[o..o + 8].copy_from_slice(&hex_to_bytes(&stub.p_hash, 8)?);
    o += 8;
    buf[o..o + 32].copy_from_slice(&hex_to_bytes(&stub.signer_ed_public_key, 32)?);
    o += 32;
    let ts = parse_iso_millis(&stub.timestamp).unwrap_or(0).max(0) as u64;
    buf[o..o + 8].copy_from_slice(&ts.to_be_bytes());
    o += 8;
    let id = stub.signer_id.as_bytes();
    let n = id.len().min(32);
    buf[o..o + n].copy_from_slice(&id[..n]);
    o += 32;
    buf[o..o + 64].copy_from_slice(&hex_to_bytes(&stub.ed_signature, 64)?);
    o += 64;
    if o != STUB_SIZE {
        return Err(format!("Stub serialization bug: wrote {o}, expected {STUB_SIZE}"));
    }
    Ok(buf)
}

pub fn deserialize_stub(buf: &[u8]) -> Option<ImageSignatureStub> {
    if buf.len() < STUB_SIZE || buf[..4] != MAGIC {
        return None;
    }
    let mut o = 4;
    if u16::from_be_bytes([buf[o], buf[o + 1]]) != VERSION {
        return None;
    }
    o += 2;
    let p_hash = hex::encode(&buf[o..o + 8]);
    o += 8;
    let signer_ed_public_key = hex::encode(&buf[o..o + 32]);
    o += 32;
    let mut ts = [0u8; 8];
    ts.copy_from_slice(&buf[o..o + 8]);
    let ms = u64::from_be_bytes(ts);
    // `new Date(ms).toISOString()` throws RangeError outside ±8.64e15 ms.
    let timestamp = jiff::Timestamp::from_millisecond(i64::try_from(ms).ok()?).ok().map(to_iso_string)?;
    o += 8;
    let raw = &buf[o..o + 32];
    let end = raw.iter().position(|&b| b == 0).unwrap_or(32);
    let signer_id = String::from_utf8_lossy(&raw[..end]).into_owned();
    o += 32;
    let ed_signature = hex::encode(&buf[o..o + 64]);
    Some(ImageSignatureStub { p_hash, signer_ed_public_key, ed_signature, signer_id, timestamp })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let stub = ImageSignatureStub {
            p_hash: "0123456789abcdef".into(),
            signer_ed_public_key: "11".repeat(32),
            ed_signature: "22".repeat(64),
            signer_id: "x".repeat(44),
            timestamp: "2026-01-02T03:04:05.678Z".into(),
        };
        let bytes = serialize_stub(&stub).unwrap();
        assert_eq!(bytes.len(), STUB_SIZE);
        let back = deserialize_stub(&bytes).unwrap();
        assert_eq!(back.timestamp, stub.timestamp);
        assert_eq!(back.signer_id, "x".repeat(32)); // truncated to 32 bytes, as in TS
        assert_eq!(back.p_hash, stub.p_hash);
    }
}
