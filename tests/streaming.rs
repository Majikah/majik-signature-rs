mod common;

use common::new_key;
use majik_signature::*;
use sha2::{Digest, Sha256};
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
    let result = MajikSignature::verify_reader(&mut verify_reader, &signature, &public_keys, None).unwrap();
    assert!(result.valid, "{:?}", result.reason);

    let buffered = MajikSignature::sign(content, &key, None).unwrap();
    assert_eq!(signature.content_hash(), buffered.content_hash());
}

#[test]
fn streaming_hash_enforces_limits_and_cancellation() {
    let bytes = vec![0x11; 1024];
    let mut reader = io::Cursor::new(&bytes);
    let mut limited = StreamingHashOptions { max_bytes: Some(100), ..StreamingHashOptions::default() };
    assert!(hash_reader(&mut reader, &mut limited).is_err());

    let cancelled = AtomicBool::new(true);
    let mut reader = io::Cursor::new(&bytes);
    let mut options =
        StreamingHashOptions { cancellation: Some(&cancelled), ..StreamingHashOptions::default() };
    assert!(hash_reader(&mut reader, &mut options).is_err());
}

#[test]
fn streaming_hash_enforces_expected_total_length() {
    let bytes = vec![0x33; 4097];

    let mut exact_reader = io::Cursor::new(&bytes);
    let mut exact_options =
        StreamingHashOptions { total_bytes: Some(bytes.len() as u64), ..StreamingHashOptions::default() };
    let exact = hash_reader(&mut exact_reader, &mut exact_options).unwrap();
    assert_eq!(exact.bytes_processed, bytes.len() as u64);
    assert_eq!(exact.total_bytes, Some(bytes.len() as u64));

    let mut overlong_reader = io::Cursor::new(&bytes);
    let mut overlong_options =
        StreamingHashOptions { total_bytes: Some(bytes.len() as u64 - 1), ..StreamingHashOptions::default() };
    assert!(hash_reader(&mut overlong_reader, &mut overlong_options).is_err());

    let mut truncated_reader = io::Cursor::new(&bytes[..1000]);
    let mut truncated_options =
        StreamingHashOptions { total_bytes: Some(bytes.len() as u64), ..StreamingHashOptions::default() };
    assert!(hash_reader(&mut truncated_reader, &mut truncated_options).is_err());
}

#[test]
fn automatic_hash_rejects_declared_length_mismatch() {
    let bytes = vec![0x44; 32];
    let mut options = StreamingHashOptions {
        total_bytes: Some((bytes.len() + 1) as u64),
        ..StreamingHashOptions::default()
    };
    assert!(hash_bytes_auto(&bytes, &mut options).is_err());
}

#[test]
fn streaming_hash_reports_progress() {
    let bytes = vec![0x22; 1024 * 1024 + 19];
    let mut reader = io::Cursor::new(&bytes);
    let mut last_progress = 0u64;
    let processed = {
        let mut callback = |progress: StreamingHashProgress| {
            last_progress = progress.bytes_processed;
        };
        let mut options = StreamingHashOptions {
            chunk_size: 64 * 1024,
            total_bytes: Some(bytes.len() as u64),
            on_progress: Some(&mut callback),
            ..StreamingHashOptions::default()
        };
        hash_reader(&mut reader, &mut options).unwrap().bytes_processed
    };

    // The scoped options and callback release their mutable borrows naturally.
    assert_eq!(last_progress, bytes.len() as u64);
    assert_eq!(processed, bytes.len() as u64);
}

#[test]
fn detached_batch_reader_signing_matches_buffered_signatures() {
    let key = new_key("streaming-batch-alice");
    let first = b"first streaming batch file".to_vec();
    let second = b"second streaming batch file".to_vec();
    let mut first_reader = io::Cursor::new(first.clone());
    let mut second_reader = io::Cursor::new(second.clone());
    let mut files = vec![
        StreamingBatchFileInput {
            path: "docs/first.txt".into(),
            reader: &mut first_reader,
            total_bytes: Some(first.len() as u64),
            mime_type: Some("text/plain".into()),
        },
        StreamingBatchFileInput {
            path: "docs/second.txt".into(),
            reader: &mut second_reader,
            total_bytes: Some(second.len() as u64),
            mime_type: Some("text/plain".into()),
        },
    ];

    let result =
        MajikSignature::sign_batch_detached_stream(&mut files, &key, None, BatchStreamingOptions::default())
            .unwrap();

    let BatchSignResult::Map { map, map_blob, failures } = result else {
        panic!("expected MJKSMAP result");
    };
    assert!(failures.is_empty());
    assert_eq!(map.size(), 2);
    assert!(!map_blob.is_empty());

    let first_entry = map.get_entry("docs/first.txt").unwrap();
    assert_eq!(first_entry.content_hash, bytes_to_base64(&hash_content(&first)));
    assert_eq!(first_entry.size, Some(first.len() as u64));
    let public_keys = MajikSignature::public_keys_from_majik_key(&key).unwrap();
    let first_signature = &first_entry.envelope.signatures[0];
    let verified = MajikSignature::verify(&first, first_signature, &public_keys, None).unwrap();
    assert!(verified.valid, "{:?}", verified.reason);

    let mut exact_reader = io::Cursor::new(first.clone());
    let mut relocated_reader = io::Cursor::new(second.clone());
    let mut verify_inputs = vec![
        StreamingBatchVerifyInput {
            path: "docs/first.txt".into(),
            reader: &mut exact_reader,
            total_bytes: Some(first.len() as u64),
        },
        StreamingBatchVerifyInput {
            path: "moved/second.txt".into(),
            reader: &mut relocated_reader,
            total_bytes: Some(second.len() as u64),
        },
    ];
    let verify_results = MajikSignature::verify_files_from_mjksmap_stream(
        &map,
        &mut verify_inputs,
        &public_keys,
        None,
        BatchStreamingOptions::default(),
    )
    .unwrap();
    assert_eq!(verify_results[0].status, FileVerifyStatus::Verified);
    assert_eq!(verify_results[1].status, FileVerifyStatus::Verified);
    assert_eq!(verify_results[1].relocated_from.as_deref(), Some("docs/second.txt"));

    let modified = b"modified batch content".to_vec();
    let mut modified_reader = io::Cursor::new(modified.clone());
    let mut tampered_input = vec![StreamingBatchVerifyInput {
        path: "docs/first.txt".into(),
        reader: &mut modified_reader,
        total_bytes: Some(modified.len() as u64),
    }];
    let tampered = MajikSignature::verify_files_from_mjksmap_stream(
        &map,
        &mut tampered_input,
        &public_keys,
        None,
        BatchStreamingOptions::default(),
    )
    .unwrap();
    assert_eq!(tampered[0].status, FileVerifyStatus::Tampered);
}

#[test]
fn detached_batch_reader_signing_can_continue_after_a_file_failure() {
    let key = new_key("streaming-batch-continue");
    let valid = b"valid file".to_vec();
    let invalid = b"declared length is too long".to_vec();
    let mut valid_reader = io::Cursor::new(valid.clone());
    let mut invalid_reader = io::Cursor::new(invalid.clone());
    let mut files = vec![
        StreamingBatchFileInput {
            path: "valid.txt".into(),
            reader: &mut valid_reader,
            total_bytes: Some(valid.len() as u64),
            mime_type: None,
        },
        StreamingBatchFileInput {
            path: "invalid.txt".into(),
            reader: &mut invalid_reader,
            total_bytes: Some((invalid.len() + 1) as u64),
            mime_type: None,
        },
    ];
    let options = BatchSignOptions { continue_on_error: true, ..BatchSignOptions::default() };

    let result = MajikSignature::sign_batch_detached_stream(
        &mut files,
        &key,
        Some(&options),
        BatchStreamingOptions::default(),
    )
    .unwrap();

    let BatchSignResult::Map { map, failures, .. } = result else {
        panic!("expected MJKSMAP result");
    };
    assert_eq!(map.size(), 1);
    assert_eq!(failures.len(), 1);
    assert_eq!(failures[0].path, "invalid.txt");
}

#[test]
fn detached_batch_reader_signing_stops_on_cancellation_even_when_continue_is_enabled() {
    let key = new_key("streaming-batch-cancel");
    let bytes = b"cancelled batch input".to_vec();
    let mut reader = io::Cursor::new(bytes.clone());
    let mut files = vec![StreamingBatchFileInput {
        path: "cancelled.txt".into(),
        reader: &mut reader,
        total_bytes: Some(bytes.len() as u64),
        mime_type: None,
    }];
    let options = BatchSignOptions { continue_on_error: true, ..BatchSignOptions::default() };
    let cancellation = AtomicBool::new(true);
    let streaming =
        BatchStreamingOptions { cancellation: Some(&cancellation), ..BatchStreamingOptions::default() };

    let result = MajikSignature::sign_batch_detached_stream(&mut files, &key, Some(&options), streaming);
    assert!(result.is_err());
}

#[test]
fn detached_batch_reader_signing_emits_separate_mjksig_outputs() {
    let key = new_key("streaming-batch-separate");
    let first = b"separate streamed result one".to_vec();
    let second = b"separate streamed result two".to_vec();
    let mut first_reader = io::Cursor::new(first.clone());
    let mut second_reader = io::Cursor::new(second.clone());
    let mut files = vec![
        StreamingBatchFileInput {
            path: "one.txt".into(),
            reader: &mut first_reader,
            total_bytes: Some(first.len() as u64),
            mime_type: None,
        },
        StreamingBatchFileInput {
            path: "two.txt".into(),
            reader: &mut second_reader,
            total_bytes: Some(second.len() as u64),
            mime_type: None,
        },
    ];
    let options = BatchSignOptions { mode: Some(BatchSignMode::Separate), ..BatchSignOptions::default() };
    let result = MajikSignature::sign_batch_detached_stream(
        &mut files,
        &key,
        Some(&options),
        BatchStreamingOptions::default(),
    )
    .unwrap();

    let BatchSignResult::Separate { signatures, failures } = result else {
        panic!("expected separate signature results");
    };
    assert!(failures.is_empty());
    assert_eq!(signatures.len(), 2);
    assert_eq!(signatures[0].path, "one.txt");
    assert_eq!(signatures[1].path, "two.txt");
    assert!(signatures.iter().all(|item| !item.blob.is_empty()));
}

#[test]
fn ed25519_scalar_malleability_is_rejected() {
    let key = new_key("malleability-alice");
    let content = b"malleability regression fixture";
    let signature = MajikSignature::sign(content, &key, None).unwrap();
    let public_keys = MajikSignature::public_keys_from_majik_key(&key).unwrap();
    let mut altered = signature.to_json();

    let mut sig = base64_to_bytes(&altered.ed_signature).unwrap();
    const L: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ];
    let mut carry = 0u16;
    for index in 0..32 {
        let sum = sig[32 + index] as u16 + L[index] as u16 + carry;
        sig[32 + index] = sum as u8;
        carry = sum >> 8;
    }
    assert_eq!(carry, 0);
    altered.ed_signature = bytes_to_base64(&sig);

    let result = MajikSignature::verify(content, &altered, &public_keys, None).unwrap();
    assert!(!result.valid);
}

struct RepeatingReader {
    remaining: u64,
    pattern: Vec<u8>,
    offset: usize,
}

impl RepeatingReader {
    fn new(total_bytes: u64, pattern: Vec<u8>) -> Self {
        Self { remaining: total_bytes, pattern, offset: 0 }
    }
}

impl Read for RepeatingReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() || self.remaining == 0 {
            return Ok(0);
        }
        let count = output.len().min(self.remaining.min(usize::MAX as u64) as usize);
        for (index, byte) in output[..count].iter_mut().enumerate() {
            *byte = self.pattern[(self.offset + index) % self.pattern.len()];
        }
        self.offset = (self.offset + count) % self.pattern.len();
        self.remaining -= count as u64;
        Ok(count)
    }
}

fn expected_repeating_digest(total_bytes: u64, pattern: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    let mut remaining = total_bytes;
    let mut offset = 0usize;
    while remaining > 0 {
        let count = remaining.min((pattern.len() - offset) as u64) as usize;
        hasher.update(&pattern[offset..offset + count]);
        remaining -= count as u64;
        offset = (offset + count) % pattern.len();
    }
    hasher.finalize().into()
}

#[test]
fn hashes_virtual_large_files_with_multiple_chunk_sizes_without_full_file_allocation() {
    let total_bytes = 32 * 1024 * 1024 + 37;
    let pattern: Vec<u8> = (0..(1024 * 1024 + 113))
        .map(|index| ((index * 31 + (index >> 8) * 17 + 0x5a) & 0xff) as u8)
        .collect();
    let expected = expected_repeating_digest(total_bytes, &pattern);

    for chunk_size in [MIN_HASH_CHUNK_SIZE, 256 * 1024, 1024 * 1024, 4 * 1024 * 1024, 16 * 1024 * 1024] {
        let mut reader = RepeatingReader::new(total_bytes, pattern.clone());
        let mut options = StreamingHashOptions {
            chunk_size,
            max_bytes: Some(total_bytes),
            total_bytes: Some(total_bytes),
            ..StreamingHashOptions::default()
        };
        let result = hash_reader(&mut reader, &mut options).unwrap();
        assert_eq!(result.bytes_processed, total_bytes, "chunk_size={chunk_size}");
        assert_eq!(result.digest, expected, "chunk_size={chunk_size}");
    }
}

struct FailingReader {
    emitted: bool,
}

impl Read for FailingReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if !self.emitted {
            self.emitted = true;
            let count = output.len().min(64 * 1024);
            output[..count].fill(0x5a);
            return Ok(count);
        }
        Err(io::Error::other("synthetic source failure"))
    }
}

#[test]
fn returns_read_errors_and_invalid_configuration_without_panicking() {
    let mut reader = FailingReader { emitted: false };
    let mut options = StreamingHashOptions::default();
    assert!(hash_reader(&mut reader, &mut options).is_err());

    let bytes = b"invalid chunk size";
    let mut reader = io::Cursor::new(bytes);
    let mut options = StreamingHashOptions { chunk_size: 0, ..StreamingHashOptions::default() };
    assert!(hash_reader(&mut reader, &mut options).is_err());
}

#[test]
#[ignore = "Opt-in real multi-gigabyte CPU stress; set MAJIK_STRESS_BYTES and run with --ignored"]
fn streams_a_virtual_ten_gib_file_with_bounded_memory() {
    let total_bytes = std::env::var("MAJIK_STRESS_BYTES")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(10 * 1024 * 1024 * 1024);
    assert!(total_bytes > 0);

    let pattern = vec![0x5a; 1024 * 1024];
    let expected = expected_repeating_digest(total_bytes, &pattern);
    let mut reader = RepeatingReader::new(total_bytes, pattern);
    let mut options = StreamingHashOptions {
        chunk_size: 8 * 1024 * 1024,
        total_bytes: Some(total_bytes),
        max_bytes: Some(total_bytes),
        ..StreamingHashOptions::default()
    };
    let result = hash_reader(&mut reader, &mut options).unwrap();
    assert_eq!(result.bytes_processed, total_bytes);
    assert_eq!(result.digest, expected);
}
