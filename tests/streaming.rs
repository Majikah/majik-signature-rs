mod common;

use common::new_key;
use majik_signature::*;
use std::io::{self, Read};
use std::sync::atomic::AtomicBool;

struct FragmentedReader<'a> {
    bytes: &'a [u8],
    offset: usize,
    fragment_sizes: &'a [usize],
    next_fragment: usize,
}

impl<'a> FragmentedReader<'a> {
    fn new(bytes: &'a [u8], fragment_sizes: &'a [usize]) -> Self {
        Self { bytes, offset: 0, fragment_sizes, next_fragment: 0 }
    }
}

impl Read for FragmentedReader<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if self.offset >= self.bytes.len() {
            return Ok(0);
        }
        let requested = self.fragment_sizes[self.next_fragment % self.fragment_sizes.len()];
        self.next_fragment += 1;
        let count = requested.min(output.len()).min(self.bytes.len() - self.offset);
        output[..count].copy_from_slice(&self.bytes[self.offset..self.offset + count]);
        self.offset += count;
        Ok(count)
    }
}

#[test]
fn streaming_hash_matches_one_shot_for_large_and_fragmented_inputs() {
    let mut bytes = vec![0u8; 25 * 1024 * 1024 + 37];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = ((index * 31 + 7) & 0xff) as u8;
    }

    let expected = hash_content(&bytes);
    let mut reader = FragmentedReader::new(&bytes, &[1, 63, 64, 65, 4093, 8191]);
    let mut options = StreamingHashOptions::default();
    let actual = hash_reader(&mut reader, &mut options).unwrap();

    assert_eq!(actual.digest, expected);
    assert_eq!(actual.bytes_processed, bytes.len() as u64);
    assert_eq!(actual.strategy, HashStrategy::Streaming);
}

#[test]
fn automatic_hash_strategy_preserves_the_existing_digest() {
    let bytes = vec![0x5a; 25 * 1024 * 1024];
    let expected = hash_content(&bytes);
    let mut options = StreamingHashOptions::default();
    let actual = hash_bytes_auto(&bytes, &mut options).unwrap();

    assert_eq!(actual.digest, expected);
    assert_eq!(actual.strategy, HashStrategy::Streaming);
}

#[test]
fn reader_signing_and_verification_match_buffered_signatures() {
    let key = new_key("streaming-alice");
    let content = b"content hashed incrementally from a reader";
    let mut reader = FragmentedReader::new(content, &[1, 2, 7, 3, 11]);

    let signature = MajikSignature::sign_reader(&mut reader, &key, None).unwrap();
    let public_keys = MajikSignature::public_keys_from_majik_key(&key).unwrap();

    let mut verify_reader = FragmentedReader::new(content, &[3, 1, 5, 2]);
    let result = MajikSignature::verify_reader(
        &mut verify_reader,
        &signature,
        &public_keys,
        None,
    )
    .unwrap();
    assert!(result.valid, "{:?}", result.reason);

    let buffered = MajikSignature::sign(content, &key, None).unwrap();
    assert_eq!(signature.content_hash(), buffered.content_hash());
}

#[test]
fn streaming_hash_enforces_limits_and_cancellation() {
    let bytes = vec![0x11; 1024];
    let mut reader = io::Cursor::new(&bytes);
    let mut limited = StreamingHashOptions {
        max_bytes: Some(100),
        ..StreamingHashOptions::default()
    };
    assert!(hash_reader(&mut reader, &mut limited).is_err());

    let cancelled = AtomicBool::new(true);
    let mut reader = io::Cursor::new(&bytes);
    let mut options = StreamingHashOptions {
        cancellation: Some(&cancelled),
        ..StreamingHashOptions::default()
    };
    assert!(hash_reader(&mut reader, &mut options).is_err());
}

#[test]
fn streaming_hash_reports_progress() {
    let bytes = vec![0x22; 1024 * 1024 + 19];
    let mut reader = io::Cursor::new(&bytes);
    let mut last_progress = 0u64;
    let mut callback = |progress: StreamingHashProgress| {
        last_progress = progress.bytes_processed;
    };
    let mut options = StreamingHashOptions {
        chunk_size: 64 * 1024,
        total_bytes: Some(bytes.len() as u64),
        on_progress: Some(&mut callback),
        ..StreamingHashOptions::default()
    };
    let result = hash_reader(&mut reader, &mut options).unwrap();
    assert_eq!(last_progress, bytes.len() as u64);
    assert_eq!(result.bytes_processed, bytes.len() as u64);
}
