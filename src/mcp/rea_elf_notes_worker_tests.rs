// Copyright 2026 Muvon Un Limited
// SPDX-License-Identifier: Apache-2.0

//! Transport/lifetime tests; real upstream operation qualification is separate.

#![cfg(unix)]

use super::*;
use serde_json::json;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

fn fixture_header(bytes: usize) -> Header {
	Header {
		input: Input {
			path: "/admitted/worker-fixture.elf".to_owned(),
			max_file_bytes: MAX_BYTES,
			max_entries: 32,
		},
		sha256: "00".repeat(32),
		bytes: bytes as u64,
	}
}

fn bare_elf() -> Vec<u8> {
	let mut bytes = vec![0_u8; 64];
	bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
	bytes[16..18].copy_from_slice(&3_u16.to_le_bytes());
	bytes[18..20].copy_from_slice(&62_u16.to_le_bytes());
	bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
	bytes[52..54].copy_from_slice(&64_u16.to_le_bytes());
	bytes
}

fn large_gold_image(text_bytes: usize) -> Vec<u8> {
	let mut bytes = bare_elf();
	let table_bytes = (16 + text_bytes + 1 + 3) & !3;
	bytes.resize(120 + table_bytes, 0);
	bytes[32..40].copy_from_slice(&64_u64.to_le_bytes());
	bytes[54..56].copy_from_slice(&56_u16.to_le_bytes());
	bytes[56..58].copy_from_slice(&1_u16.to_le_bytes());
	bytes[64..68].copy_from_slice(&4_u32.to_le_bytes());
	bytes[72..80].copy_from_slice(&120_u64.to_le_bytes());
	bytes[96..104].copy_from_slice(&(table_bytes as u64).to_le_bytes());
	bytes[112..120].copy_from_slice(&4_u64.to_le_bytes());
	bytes[120..124].copy_from_slice(&4_u32.to_le_bytes());
	bytes[124..128].copy_from_slice(&((text_bytes + 1) as u32).to_le_bytes());
	bytes[128..132].copy_from_slice(&4_u32.to_le_bytes());
	bytes[132..136].copy_from_slice(b"GNU\0");
	// Interior NULs survive the GNU gold text projection; the final nonzero byte
	// keeps them from being removed as trailing padding.
	bytes[136 + text_bytes] = b'x';
	bytes
}

#[test]
fn typed_reply_preserves_complete_report_and_each_failure_representation() {
	let bytes = bare_elf();
	let header = fixture_header(bytes.len());
	let report = parser::parse_elf_notes(
		&bytes,
		parser::ElfNotesArtifact {
			path: header.input.path.clone(),
			sha256: header.sha256.clone(),
			bytes: header.bytes,
		},
		MAX_BYTES,
		32,
	)
	.unwrap();
	assert_eq!(
		serde_json::to_value(parse(&header, &bytes)).unwrap(),
		json!({"report":report})
	);
	for failure in [
		parser::ElfNotesFailure::Format {
			message: "invalid format".to_owned(),
		},
		parser::ElfNotesFailure::Unsupported {
			message: "unsupported".to_owned(),
		},
		parser::ElfNotesFailure::EntryBudget { max_entries: 32 },
		parser::ElfNotesFailure::TextBudget { limit_bytes: 64 },
		parser::ElfNotesFailure::SectionNamesBudget {
			minimum_required_bytes: u128::from(u64::MAX) + 2,
			max_file_bytes: MAX_BYTES,
		},
	] {
		let message = failure.to_string();
		let mut legacy = serde_json::to_value(&failure).unwrap();
		legacy["message"] = json!(message);
		let message = if matches!(
			failure,
			parser::ElfNotesFailure::Format { .. } | parser::ElfNotesFailure::Unsupported { .. }
		) {
			None
		} else {
			Some(message)
		};
		let reply = Reply::Failure {
			failure: FailureReply { failure, message },
		};
		let encoded = serde_json::to_string(&reply).unwrap();
		assert_eq!(encoded.matches("\"message\":").count(), 1);
		assert_eq!(
			serde_json::from_str::<Value>(&encoded).unwrap(),
			json!({"failure":legacy})
		);
	}
}

#[test]
fn output_bound_counts_newline_and_never_writes_beyond_limit() {
	let value = json!({"text":"\0\\\""});
	let exact = serde_json::to_vec(&value).unwrap().len() + 1;
	let mut bytes = Vec::new();
	write_json(&mut bytes, &value, exact).unwrap();
	assert_eq!(bytes.len(), exact);
	assert_eq!(serde_json::from_slice::<Value>(&bytes).unwrap(), value);
	for limit in [0, 1, exact - 1] {
		let mut bytes = Vec::new();
		assert!(write_json(&mut bytes, &value, limit).is_err());
		assert!(bytes.len() <= limit);
	}
}

#[test]
fn reply_reader_rejects_truncation_extra_values_and_whitespace_over_budget() {
	for text in [b"{}".as_slice(), b"{} \n", b"null\n"] {
		let reader = BoundedReader {
			inner: io::Cursor::new(text),
			remaining: text.len(),
		};
		assert!(serde_json::from_reader::<_, Value>(reader).is_ok());
	}
	for (text, limit) in [(b"{".as_slice(), 1), (b"{}{}", 4), (b"{} \n", 3)] {
		let reader = BoundedReader {
			inner: io::Cursor::new(text),
			remaining: limit,
		};
		assert!(serde_json::from_reader::<_, Value>(reader).is_err());
	}
}

#[test]
fn output_flush_errors_are_not_successful_delivery() {
	struct FailFlush;
	impl Write for FailFlush {
		fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
			Ok(bytes.len())
		}
		fn flush(&mut self) -> io::Result<()> {
			Err(io::Error::other("fixture flush failure"))
		}
	}
	assert!(write_json(FailFlush, &json!({}), 100)
		.unwrap_err()
		.to_string()
		.contains("fixture flush failure"));
}

#[test]
fn valid_report_larger_than_old_64_mib_cap_streams_without_encoded_document_buffer() {
	const TEXT_BYTES: usize = 11 * 1024 * 1024;
	let image = large_gold_image(TEXT_BYTES);
	let reply = parse(&fixture_header(image.len()), &image);
	assert!(matches!(reply, Reply::Report { .. }));
	drop(image);
	// Eleven MiB of interior NUL characters require >66 MiB when JSON escaped.
	// The pipe transports that expansion directly; neither endpoint stores it.
	let (writer, reader) = UnixStream::pair().unwrap();
	writer
		.set_write_timeout(Some(Duration::from_secs(30)))
		.unwrap();
	let delivered = Arc::new(AtomicUsize::new(0));
	let writer = CountingWriter {
		inner: writer,
		delivered: delivered.clone(),
	};
	let writing = std::thread::spawn(move || write_json(writer, &reply, MAX_WORKER_REPLY));
	let file = std::fs::File::from(OwnedFd::from(reader));
	let parsed = read_reply(file, MAX_WORKER_REPLY, CancellationToken::new());
	let written = writing.join().unwrap();
	written.unwrap();
	let parsed = parsed.unwrap();
	let text = parsed["report"]["entries"][0]["gnu"]["gold_version"]
		.as_str()
		.unwrap();
	assert_eq!(text.len(), TEXT_BYTES + 1);
	assert!(text.as_bytes()[..TEXT_BYTES].iter().all(|&byte| byte == 0));
	assert_eq!(text.as_bytes()[TEXT_BYTES], b'x');
	assert_eq!(parsed["report"]["coverage"]["status"], "complete");
	assert!(delivered.load(Ordering::SeqCst) > 64 * 1024 * 1024);
}

struct CountingWriter<W> {
	inner: W,
	delivered: Arc<AtomicUsize>,
}
impl<W: Write> Write for CountingWriter<W> {
	fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
		let written = self.inner.write(bytes)?;
		self.delivered.fetch_add(written, Ordering::SeqCst);
		Ok(written)
	}
	fn flush(&mut self) -> io::Result<()> {
		self.inner.flush()
	}
}

#[tokio::test]
async fn blocking_reader_can_be_cancelled_without_writer_eof() {
	let (_writer, reader) = UnixStream::pair().unwrap();
	let cancellation = CancellationToken::new();
	let token = cancellation.clone();
	let (started, ready) = tokio::sync::oneshot::channel();
	let worker = tokio::task::spawn_blocking(move || {
		let _ = started.send(());
		read_reply(std::fs::File::from(OwnedFd::from(reader)), 1024, token)
	});
	ready.await.unwrap();
	cancellation.cancel();
	let error = tokio::time::timeout(Duration::from_secs(2), worker)
		.await
		.unwrap()
		.unwrap()
		.unwrap_err();
	assert!(format!("{error:#}").contains("cancelled"));
}

fn child_fixture(script: &str) -> tokio::process::Child {
	tokio::process::Command::new("/bin/sh")
		.arg("-c")
		.arg(script)
		.stdin(Stdio::piped())
		.stdout(Stdio::piped())
		.stderr(Stdio::piped())
		.kill_on_drop(true)
		.spawn()
		.unwrap()
}

fn assert_reaped(pid: u32) {
	let mut status = 0;
	let result = unsafe { libc::waitpid(pid as libc::pid_t, &mut status, libc::WNOHANG) };
	assert_eq!(result, -1, "owner did not finish reaping child {pid}");
	assert_eq!(
		io::Error::last_os_error().raw_os_error(),
		Some(libc::ECHILD)
	);
}

#[tokio::test]
async fn child_success_and_malformed_output_both_finish_owned_readers() {
	for (script, expected) in [
		(
			"/bin/cat >/dev/null; printf '{\"report\":{\"ok\":true}}'",
			true,
		),
		(
			"/bin/cat >/dev/null; printf 'fixture stderr' >&2; printf 'broken'; exit 7",
			false,
		),
	] {
		let child = child_fixture(script);
		let pid = child.id().unwrap();
		let result = supervise_child(
			child,
			b"{}".to_vec(),
			Arc::new(vec![]),
			CancellationToken::new(),
			1024,
			Duration::from_secs(5),
		)
		.await;
		assert_reaped(pid);
		if expected {
			assert_eq!(result.unwrap(), json!({"report":{"ok":true}}));
		} else {
			let failure = result.unwrap_err();
			assert_eq!(failure.0["code"], "unreadable_output");
			assert_eq!(failure.0["details"]["worker_stderr"], "fixture stderr");
		}
	}
}

#[tokio::test]
async fn child_timeout_and_cancellation_reap_before_returning() {
	for cancel in [false, true] {
		let child = child_fixture("exec /bin/sleep 30");
		let pid = child.id().unwrap();
		let cancellation = CancellationToken::new();
		if cancel {
			cancellation.cancel();
		}
		let result = supervise_child(
			child,
			b"{}".to_vec(),
			Arc::new(vec![]),
			cancellation,
			1024,
			Duration::from_millis(20),
		)
		.await;
		assert_eq!(
			result.unwrap_err().0["code"],
			if cancel {
				"cancelled"
			} else {
				"provider_timeout"
			}
		);
		assert_reaped(pid);
	}
}

struct DropWitness(Arc<AtomicBool>);
impl Drop for DropWitness {
	fn drop(&mut self) {
		self.0.store(true, Ordering::SeqCst);
	}
}

#[tokio::test]
async fn aborting_request_keeps_lease_and_admission_until_owned_cleanup_finishes() {
	let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
	let lease = Arc::new(semaphore.clone().acquire_owned().await.unwrap());
	let dropped = Arc::new(AtomicBool::new(false));
	let admission = Arc::new(DropWitness(dropped.clone()));
	let child = child_fixture("exec /bin/sleep 30");
	let pid = child.id().unwrap();
	let (started, ready) = tokio::sync::oneshot::channel();
	let outer = tokio::spawn(async move {
		await_owned(
			(lease, admission),
			&CancellationToken::new(),
			move |token| async move {
				let _ = started.send(());
				supervise_child(
					child,
					b"{}".to_vec(),
					Arc::new(vec![]),
					token,
					1024,
					Duration::from_secs(30),
				)
				.await
			},
		)
		.await
	});
	ready.await.unwrap();
	outer.abort();
	assert!(outer.await.unwrap_err().is_cancelled());
	let returned = tokio::time::timeout(Duration::from_secs(2), semaphore.clone().acquire_owned())
		.await
		.unwrap()
		.unwrap();
	assert!(dropped.load(Ordering::SeqCst));
	assert_reaped(pid);
	drop(returned);
	// A subsequent owner can use the same capacity after the cancelled owner ends.
	let lease = semaphore.clone().try_acquire_owned().unwrap();
	let child = child_fixture("/bin/cat >/dev/null; printf '{\"report\":{}}'");
	let result = await_owned(lease, &CancellationToken::new(), move |token| async move {
		supervise_child(
			child,
			b"{}".to_vec(),
			Arc::new(vec![]),
			token,
			1024,
			Duration::from_secs(5),
		)
		.await
	})
	.await;
	assert_eq!(result.unwrap(), json!({"report":{}}));
}

#[tokio::test]
async fn outer_abort_does_not_drop_guards_during_a_paused_cleanup() {
	let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
	let lease = semaphore.clone().acquire_owned().await.unwrap();
	let dropped = Arc::new(AtomicBool::new(false));
	let admission = DropWitness(dropped.clone());
	let (started, ready) = tokio::sync::oneshot::channel();
	let (cleaning, cleanup_started) = tokio::sync::oneshot::channel();
	let (release, finish) = tokio::sync::oneshot::channel();
	let outer = tokio::spawn(async move {
		await_owned(
			(lease, admission),
			&CancellationToken::new(),
			move |token| async move {
				let _ = started.send(());
				token.cancelled().await;
				let _ = cleaning.send(());
				let _ = finish.await;
				Err(Failure::cancelled(OP))
			},
		)
		.await
	});
	ready.await.unwrap();
	outer.abort();
	assert!(outer.await.unwrap_err().is_cancelled());
	cleanup_started.await.unwrap();
	assert_eq!(semaphore.available_permits(), 0);
	assert!(!dropped.load(Ordering::SeqCst));
	release.send(()).unwrap();
	let _returned = tokio::time::timeout(Duration::from_secs(2), semaphore.acquire_owned())
		.await
		.unwrap()
		.unwrap();
	assert!(dropped.load(Ordering::SeqCst));
}
