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
	let (_, _, truncated, _) = ring.read(0, 32, true, true);
	assert!(truncated);
}

#[test]
fn ring_offsets_count_bytes_not_unicode_characters() {
	let mut ring = RingBuffer::new();
	ring.append("中文α".as_bytes());
	let mut recovered = Vec::new();
	let mut offset = 0;
	while offset < ring.data.len() as u64 {
		let (begin, next, truncated, _) = ring.read(offset, 1, true, true);
		assert!(!truncated);
		assert_eq!(next, offset + 1);
		recovered.extend_from_slice(&ring.data[begin as usize..next as usize]);
		offset = next;
	}
	assert_eq!(String::from_utf8(recovered).unwrap(), "中文α");
}

#[test]
fn returned_text_survives_tiny_unicode_pages() {
	let original = "中文α🦀ascii";
	for limit in 1..=9 {
		let mut ring = RingBuffer::new();
		ring.append(original.as_bytes());
		let mut result = String::new();
		let mut offset = 0;
		while offset < original.len() as u64 {
			let (_, next, _, text) = ring.read(offset, limit, true, false);
			assert!(next > offset);
			result.push_str(&text);
			offset = next;
		}
		assert_eq!(result, original, "page size {limit}");
	}
}

#[test]
fn live_partial_unicode_waits_and_raw_bytes_never_wait() {
	let mut ring = RingBuffer::new();
	let bytes = "中".as_bytes();
	ring.append(&bytes[..1]);
	assert_eq!(ring.read(0, 8, false, false), (0, 0, false, String::new()));
	assert_eq!(ring.read(0, 1, false, true).1, 1);
	ring.append(&bytes[1..2]);
	assert_eq!(ring.read(0, 8, false, false).1, 0);
	ring.append(&bytes[2..]);
	assert_eq!(ring.read(0, 1, false, false), (0, 3, false, "中".into()));
}

#[test]
fn invalid_and_final_partial_bytes_are_never_lost() {
	let bytes = [b"\xff".as_slice(), "中\0🦀".as_bytes(), b"\xe4\xb8"].concat();
	for limit in 1..=9 {
		let mut ring = RingBuffer::new();
		ring.append(&bytes);
		let mut recovered = Vec::new();
		let mut offset = 0;
		while offset < bytes.len() as u64 {
			let (begin, next, _, _) = ring.read(offset, limit, true, false);
			assert!(next > offset);
			assert!(next - begin <= (limit + 3) as u64);
			recovered.extend_from_slice(&ring.data[begin as usize..next as usize]);
			offset = next;
		}
		assert_eq!(recovered, bytes);
	}
}

#[test]
fn maximum_page_preserves_unicode_and_size_bound() {
	let text = "a".repeat(MAX_READ_BYTES - 1) + "中文";
	let mut ring = RingBuffer::new();
	ring.append(text.as_bytes());
	let (_, next, _, first) = ring.read(0, MAX_READ_BYTES, true, false);
	assert_eq!(next as usize, MAX_READ_BYTES - 1);
	let (_, _, _, second) = ring.read(next, MAX_READ_BYTES, true, false);
	assert_eq!(first + &second, text);
}

fn payload_for(data: &[u8], state: PtyState, detail: Option<String>, raw_bytes: bool) -> Value {
	let id = next_id();
	let mut output = RingBuffer::new();
	output.append(data);
	registry().lock().unwrap().insert(
		id.clone(),
		PtySession {
			stop: CancellationToken::new(),
			id: id.clone(),
			host: "output-test".into(),
			pid: 0,
			created_unix_ms: now_ms(),
			stdin: Arc::new(AsyncMutex::new(None)),
			output: Arc::new(Mutex::new(output)),
			status: Arc::new(Mutex::new(PtyStatus {
				state,
				exit_code: Some(0),
				detail,
			})),
		},
	);
	let result = read_pty(PtyReadParams {
		host: "output-test".into(),
		session_id: id.clone(),
		offset: Some(0),
		limit: Some(1),
		raw_bytes,
	});
	registry().lock().unwrap().remove(&id);
	serde_json::from_str(&result.unwrap()).unwrap()
}

#[test]
fn public_text_and_raw_fields_agree() {
	let result = payload_for("中".as_bytes(), PtyState::Exited, None, false);
	assert_eq!(result["text"], "中");
	assert_eq!(result["bytes_hex"], "e4b8ad");
	assert_eq!(result["next_offset"], 3);
	assert_eq!(result["text_is_lossy"], false);
	assert_eq!(result["output_complete"], true);
	let result = payload_for(&[0xff], PtyState::Exited, None, false);
	assert_eq!(result["bytes_hex"], "ff");
	assert_eq!(result["text_is_lossy"], true);
}

#[test]
fn public_pending_field_and_explicit_raw_mode() {
	let result = payload_for(&[0xe4], PtyState::Running, None, false);
	assert_eq!(result["utf8_pending"], true);
	assert_eq!(result["next_offset"], 0);
	assert_eq!(result["bytes_hex"], "");
	let raw = payload_for(&[0xe4], PtyState::Running, None, true);
	assert_eq!(raw["utf8_pending"], false);
	assert_eq!(raw["next_offset"], 1);
	assert_eq!(raw["bytes_hex"], "e4");
}

struct BrokenReader;
impl AsyncRead for BrokenReader {
	fn poll_read(
		self: std::pin::Pin<&mut Self>,
		_: &mut std::task::Context<'_>,
		_: &mut tokio::io::ReadBuf<'_>,
	) -> std::task::Poll<std::io::Result<()>> {
		std::task::Poll::Ready(Err(std::io::Error::other("injected read failure")))
	}
}

#[tokio::test]
async fn capture_read_error_reaches_public_incomplete_status() {
	let output = Arc::new(Mutex::new(RingBuffer::new()));
	let task = tokio::spawn(copy_reader(BrokenReader, output));
	let detail = drain_readers(vec![task], std::time::Duration::from_secs(1)).await;
	assert!(detail.as_ref().unwrap().contains("injected read failure"));
	let result = payload_for(b"partial", PtyState::Exited, detail, false);
	assert_eq!(result["output_complete"], false);
	assert_eq!(result["status"]["exit_code"], 0);
}

#[tokio::test]
async fn clean_capture_and_timed_out_capture_are_distinct() {
	let output = Arc::new(Mutex::new(RingBuffer::new()));
	let task = tokio::spawn(copy_reader(&b"all output"[..], output.clone()));
	assert!(drain_readers(vec![task], std::time::Duration::from_secs(1))
		.await
		.is_none());
	assert_eq!(output.lock().unwrap().data, b"all output");
	let task = tokio::spawn(std::future::pending::<std::io::Result<()>>());
	let detail = drain_readers(vec![task], std::time::Duration::from_millis(1)).await;
	assert!(detail.unwrap().contains("deadline exceeded"));
}
