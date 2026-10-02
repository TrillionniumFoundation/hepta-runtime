// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Regression tests for pty.
use super::*;

#[test]
fn ring_tracks_dropped_prefix() {
	let mut ring = RingBuffer::new();
	ring.append(&vec![b'x'; MAX_BUFFER_BYTES + 7]);
	assert_eq!(ring.base_offset, 7);
	let (_, _, truncated, _) = ring.read(0, 32);
	assert!(truncated);
}

#[test]
fn ring_offsets_count_bytes_not_unicode_characters() {
	let mut ring = RingBuffer::new();
	ring.append("中文α".as_bytes());
	let mut recovered = Vec::new();
	let mut offset = 0;
	while offset < ring.data.len() as u64 {
		let (begin, next, truncated, _) = ring.read(offset, 1);
		assert!(!truncated);
		assert_eq!(next, offset + 1);
		recovered.extend_from_slice(&ring.data[begin as usize..next as usize]);
		offset = next;
	}
	assert_eq!(String::from_utf8(recovered).unwrap(), "中文α");
}
