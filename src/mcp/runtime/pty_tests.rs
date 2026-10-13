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

#[derive(Clone, Copy)]
enum WriteFault {
	PartialError,
	FlushError,
	PartialTimeout,
	None,
}
struct FaultWriter {
	accepted: Vec<u8>,
	fault: WriteFault,
	polls: usize,
}
impl AsyncWrite for FaultWriter {
	fn poll_write(
		mut self: std::pin::Pin<&mut Self>,
		_: &mut std::task::Context<'_>,
		data: &[u8],
	) -> std::task::Poll<std::io::Result<usize>> {
		self.polls += 1;
		if !self.accepted.is_empty() {
			match self.fault {
				WriteFault::PartialError => {
					return std::task::Poll::Ready(Err(std::io::Error::other(
						"SECRET partial write failure",
					)))
				}
				WriteFault::PartialTimeout => return std::task::Poll::Pending,
				_ => {}
			}
		}
		let n = if matches!(
			self.fault,
			WriteFault::PartialError | WriteFault::PartialTimeout
		) {
			data.len().min(3)
		} else {
			data.len()
		};
		self.accepted.extend_from_slice(&data[..n]);
		std::task::Poll::Ready(Ok(n))
	}
	fn poll_flush(
		self: std::pin::Pin<&mut Self>,
		_: &mut std::task::Context<'_>,
	) -> std::task::Poll<std::io::Result<()>> {
		std::task::Poll::Ready(if matches!(self.fault, WriteFault::FlushError) {
			Err(std::io::Error::other("SECRET flush failure"))
		} else {
			Ok(())
		})
	}
	fn poll_shutdown(
		self: std::pin::Pin<&mut Self>,
		_: &mut std::task::Context<'_>,
	) -> std::task::Poll<std::io::Result<()>> {
		std::task::Poll::Ready(Ok(()))
	}
}
fn fault_writer(fault: WriteFault) -> FaultWriter {
	FaultWriter {
		accepted: Vec::new(),
		fault,
		polls: 0,
	}
}

#[tokio::test]
async fn failed_pty_intent_refuses_before_any_input_dispatch() {
	let mut writer = fault_writer(WriteFault::None);
	let result = dispatch_input(
		&mut writer,
		"target-host",
		"pty-existing",
		b"business command\n",
		Err(anyhow!("SECRET intent unavailable")),
		std::time::Duration::from_secs(1),
	)
	.await;
	assert!(result
		.unwrap_err()
		.to_string()
		.contains("no terminal operation dispatched"));
	assert_eq!(writer.polls, 0);
	assert!(writer.accepted.is_empty());
}

#[tokio::test]
async fn partial_input_flush_failure_and_timeout_retain_unknown_identity_without_retry() {
	for fault in [
		WriteFault::PartialError,
		WriteFault::FlushError,
		WriteFault::PartialTimeout,
	] {
		let mut writer = fault_writer(fault);
		let result = dispatch_input(
			&mut writer,
			"target-host",
			"pty-existing",
			b"business command\n",
			Ok(()),
			std::time::Duration::from_millis(5),
		)
		.await
		.unwrap();
		assert!(
			!writer.accepted.is_empty(),
			"fault must occur after real accepted bytes"
		);
		assert_eq!(result["outcome"], "unknown");
		assert_eq!(result["automatic_retry"], false);
		assert_eq!(result["host"], "target-host");
		assert_eq!(result["session_id"], "pty-existing");
		assert!(
			result.get("bytes_written").is_none(),
			"a partial write must not assert the full count"
		);
		assert!(!result.to_string().contains("SECRET"));
	}
}

#[tokio::test]
async fn completed_input_survives_post_effect_audit_failure() {
	let mut writer = fault_writer(WriteFault::None);
	let result = dispatch_input(
		&mut writer,
		"target-host",
		"pty-existing",
		b"business command\n",
		Ok(()),
		std::time::Duration::from_secs(1),
	)
	.await
	.unwrap();
	assert_eq!(writer.accepted, b"business command\n");
	let result = retain_pty_after_audit(result, Err(anyhow!("SECRET audit sync failure")));
	assert_eq!(result["bytes_written"], writer.accepted.len());
	assert_eq!(result["host"], "target-host");
	assert_eq!(result["session_id"], "pty-existing");
	assert_eq!(result["audit_recorded"], false);
	assert_eq!(result["automatic_retry"], false);
	assert!(!result.to_string().contains("SECRET"));
}

#[test]
fn start_and_close_result_survive_completion_audit_failure() {
	for value in [
		json!({"session_id":"pty-existing","host":"target-host","pid":123,"pid_scope":"controller_ssh"}),
		json!({"session_id":"pty-existing","host":"target-host","result":"close_requested","termination_confirmed":false}),
	] {
		let result = retain_pty_after_audit(value.clone(), Err(anyhow!("SECRET audit path")));
		for (key, field) in value.as_object().unwrap() {
			assert_eq!(result[key], *field);
		}
		assert_eq!(result["audit_recorded"], false);
		assert_eq!(result["automatic_retry"], false);
		assert!(!result.to_string().contains("SECRET"));
	}
}
