// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Opt-in, bounded-vocabulary audit diagnostics. No request or path is formatted.
use anyhow::Result;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const SLOW: Duration = Duration::from_millis(100);
const MAX_EVENTS: usize = 256;

fn enabled() -> bool {
	static ENABLED: OnceLock<bool> = OnceLock::new();
	*ENABLED.get_or_init(|| {
		std::env::var_os("HEPTA_REQUEST_AUDIT_TRACE").is_some_and(|value| value == "1")
	})
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Cause {
	code: &'static str,
	errno: Option<i32>,
}

fn cause(error: &anyhow::Error) -> Cause {
	for source in error.chain() {
		if let Some(error) = source.downcast_ref::<std::io::Error>() {
			let code = match error.kind() {
				std::io::ErrorKind::NotFound => "io_not_found",
				std::io::ErrorKind::PermissionDenied => "io_permission_denied",
				std::io::ErrorKind::AlreadyExists => "io_already_exists",
				std::io::ErrorKind::Interrupted => "io_interrupted",
				std::io::ErrorKind::WouldBlock => "io_would_block",
				std::io::ErrorKind::WriteZero => "io_write_zero",
				std::io::ErrorKind::UnexpectedEof => "io_unexpected_eof",
				_ => "io_other",
			};
			return Cause {
				code,
				errno: error.raw_os_error(),
			};
		}
	}
	if error
		.chain()
		.any(|source| source.downcast_ref::<serde_json::Error>().is_some())
	{
		return Cause {
			code: "record_json",
			errno: None,
		};
	}
	// Compare against a closed vocabulary; never emit the original error text.
	// Typed message access also avoids invoking an arbitrary Error::fmt in a
	// critical section. Unknown error implementations stay unclassified.
	let message: Option<&str> = error
		.downcast_ref::<&'static str>()
		.copied()
		.or_else(|| error.downcast_ref::<String>().map(String::as_str));
	let code = match message.unwrap_or("") {
		"audit queue closed or full; no automatic replay" => "queue_closed_or_full",
		"audit queue unavailable" => "queue_lock",
		"audit coordinator closed; never replay" => "coordinator_closed",
		"audit acknowledgement unavailable; never replay" => "reply_disconnected",
		"audit cohort durability unavailable; never replay" => "cohort_refused",
		"audit file barrier worker unavailable; never replay" => "sync_worker_unavailable",
		"audit file barrier pool unavailable" => "sync_pool_unavailable",
		"audit file barrier cohort exceeded" => "sync_cohort_bound",
		"request audit state lock unavailable" => "store_lock",
		"request audit active registry unavailable" => "active_registry",
		"request read pin state unavailable" => "read_pin_registry",
		"request hot cache unavailable" => "hot_cache_lock",
		"request hot cache binding changed" => "hot_binding_changed",
		"request hot namespace changed during validation" => "hot_namespace_unstable",
		"private request audit directory refused" => "private_directory",
		"private request audit inode refused" => "private_inode",
		"request audit receipt binding changed" => "receipt_binding_changed",
		"request archive identity changed" => "archive_identity_changed",
		"request archive terminal outcome changed" => "archive_outcome_changed",
		"audit cohort directory identity changed" => "cohort_directory_changed",
		"audit cohort root binding changed" => "cohort_root_changed",
		"audit cohort archive binding changed" => "cohort_archive_changed",
		"request identity entropy unavailable" => "identity_entropy",
		"invalid bounded audit admission" | "invalid audit cohort admission" => "invalid_admission",
		"request unavailable to this scope" => "read_scope",
		_ => "internal_other",
	};
	Cause { code, errno: None }
}

#[derive(Clone, Copy)]
struct Event {
	stage: &'static str,
	unix_ms: u64,
	elapsed_us: u64,
	cohort: usize,
	slot: Option<usize>,
	failed: bool,
	cause: Cause,
	dropped: u64,
}

struct Buffer {
	send: mpsc::SyncSender<Event>,
	receive: Mutex<mpsc::Receiver<Event>>,
	dropped: AtomicU64,
}

fn buffer() -> &'static Buffer {
	static BUFFER: OnceLock<Buffer> = OnceLock::new();
	BUFFER.get_or_init(|| {
		let (send, receive) = mpsc::sync_channel(MAX_EVENTS);
		Buffer {
			send,
			receive: Mutex::new(receive),
			dropped: AtomicU64::new(0),
		}
	})
}

fn unix_ms() -> u64 {
	SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.unwrap_or_default()
		.as_millis()
		.min(u64::MAX as u128) as u64
}

fn emit(event: Event) {
	// An optional subscriber must not change the operation's return value.
	let _ = std::panic::catch_unwind(|| {
		// main.rs intentionally emits only the message field. Keep every safe
		// diagnostic value in that field so the real stderr subscriber sees it.
		tracing::warn!(target: "hepta_request_audit_trace",
			"opt-in request audit diagnostic stage={} unix_ms={} elapsed_us={} cohort={} slot={:?} failed={} cause={} errno={:?} dropped_events={}",
			event.stage,
			event.unix_ms,
			event.elapsed_us,
			event.cohort,
			event.slot,
			event.failed,
			event.cause.code,
			event.cause.errno,
			event.dropped);
	});
}

/// Only API boundaries outside STORE_LOCK/coordinator locks may flush. Workers
/// and inner stages only try_send; a full diagnostic buffer never blocks an ACK.
pub(in crate::mcp::runtime) fn flush() {
	if !enabled() {
		return;
	}
	let buffer = buffer();
	let events: Vec<_> = {
		let Ok(receive) = buffer.receive.try_lock() else {
			return;
		};
		receive.try_iter().take(MAX_EVENTS).collect()
	};
	// Release even the diagnostic receiver lock before touching a log writer.
	for event in events {
		emit(event);
	}
	let dropped = buffer.dropped.swap(0, Ordering::Relaxed);
	if dropped != 0 {
		emit(Event {
			stage: "trace_events_dropped",
			unix_ms: unix_ms(),
			elapsed_us: 0,
			cohort: 0,
			slot: None,
			failed: false,
			cause: Cause {
				code: "none",
				errno: None,
			},
			dropped,
		});
	}
}

pub(in crate::mcp::runtime) struct Span {
	stage: &'static str,
	cohort: usize,
	slot: Option<usize>,
	started: Option<Instant>,
}

impl Span {
	pub(in crate::mcp::runtime) fn new(
		stage: &'static str,
		cohort: usize,
		slot: Option<usize>,
	) -> Self {
		let started = if enabled() {
			let _ = buffer();
			Some(Instant::now())
		} else {
			None
		};
		Self {
			stage,
			cohort,
			slot,
			started,
		}
	}

	pub(in crate::mcp::runtime) fn finish<T>(self, result: Result<T>) -> Result<T> {
		self.record(result.as_ref().err());
		result
	}

	pub(in crate::mcp::runtime) fn record(&self, error: Option<&anyhow::Error>) {
		let Some(started) = self.started else {
			return;
		};
		let elapsed = started.elapsed();
		if error.is_none() && elapsed < SLOW {
			return;
		}
		let cause = error.map(cause).unwrap_or(Cause {
			code: "none",
			errno: None,
		});
		let event = Event {
			stage: self.stage,
			unix_ms: unix_ms(),
			elapsed_us: elapsed.as_micros().min(u64::MAX as u128) as u64,
			cohort: self.cohort,
			slot: self.slot,
			failed: error.is_some(),
			cause,
			dropped: 0,
		};
		let buffer = buffer();
		if buffer.send.try_send(event).is_err() {
			buffer.dropped.fetch_add(1, Ordering::Relaxed);
		}
	}
}

pub(in crate::mcp::runtime) fn measure<T>(
	stage: &'static str,
	cohort: usize,
	slot: Option<usize>,
	operation: impl FnOnce() -> Result<T>,
) -> Result<T> {
	let span = Span::new(stage, cohort, slot);
	span.finish(operation())
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::sync::Arc;

	// Match main.rs::MessageVisitor, including its deliberate rejection of all
	// structured fields except message. Capture the emitted line instead of
	// writing stderr so this exercises the real tracing event representation.
	struct MessageVisitor<'a>(&'a mut String);

	impl tracing::field::Visit for MessageVisitor<'_> {
		fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
			if field.name() == "message" {
				let _ = std::fmt::write(self.0, format_args!("{:?}", value));
			}
		}

		fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
			if field.name() == "message" {
				self.0.push_str(value);
			}
		}
	}

	struct MessageOnlySubscriber {
		lines: Arc<Mutex<Vec<String>>>,
	}

	impl tracing::Subscriber for MessageOnlySubscriber {
		fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
			metadata.level() <= &tracing::Level::WARN
		}

		fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
			tracing::span::Id::from_u64(1)
		}

		fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

		fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

		fn event(&self, event: &tracing::Event<'_>) {
			let mut line = format!("[{}] ", event.metadata().level());
			event.record(&mut MessageVisitor(&mut line));
			self.lines.lock().unwrap().push(line);
		}

		fn enter(&self, _span: &tracing::span::Id) {}
		fn exit(&self, _span: &tracing::span::Id) {}
	}

	#[test]
	fn actual_message_only_subscriber_receives_all_diagnostics_without_sensitive_context() {
		let lines = Arc::new(Mutex::new(Vec::new()));
		let subscriber = MessageOnlySubscriber {
			lines: Arc::clone(&lines),
		};
		let error = anyhow::Error::new(std::io::Error::from_raw_os_error(5))
			.context("sensitive-owner-token-path-and-payload-fixture");
		tracing::subscriber::with_default(subscriber, || {
			// This control must lose its structured value, exactly like main.rs.
			tracing::warn!(target: "hepta_request_audit_trace",
				stage = "invisible-structured-control", "control message");
			emit(Event {
				stage: "file_sync_worker",
				unix_ms: 1792580060123,
				elapsed_us: 2245123,
				cohort: 8,
				slot: Some(3),
				failed: true,
				cause: cause(&error),
				dropped: 0,
			});
			emit(Event {
				stage: "store_lock_wait",
				unix_ms: 1792580060223,
				elapsed_us: 123456,
				cohort: 0,
				slot: None,
				failed: false,
				cause: Cause {
					code: "none",
					errno: None,
				},
				dropped: 0,
			});
			emit(Event {
				stage: "trace_events_dropped",
				unix_ms: 1792580060323,
				elapsed_us: 0,
				cohort: 0,
				slot: None,
				failed: false,
				cause: Cause {
					code: "none",
					errno: None,
				},
				dropped: 7,
			});
		});
		let lines = lines.lock().unwrap();
		assert_eq!(lines.len(), 4);
		assert_eq!(lines[0], "[WARN] control message");
		for expected in [
			"stage=file_sync_worker",
			"unix_ms=1792580060123",
			"elapsed_us=2245123",
			"cohort=8",
			"slot=Some(3)",
			"failed=true",
			"cause=io_",
			"errno=Some(5)",
			"dropped_events=0",
		] {
			assert!(
				lines[1].contains(expected),
				"missing {expected}: {}",
				lines[1]
			);
		}
		for expected in [
			"stage=store_lock_wait",
			"unix_ms=1792580060223",
			"elapsed_us=123456",
			"cohort=0",
			"slot=None",
			"failed=false",
			"cause=none",
			"errno=None",
		] {
			assert!(
				lines[2].contains(expected),
				"missing {expected}: {}",
				lines[2]
			);
		}
		assert!(lines[3].contains("stage=trace_events_dropped"));
		assert!(lines[3].contains("dropped_events=7"));
		assert!(lines
			.iter()
			.all(|line| !line.contains("sensitive")
				&& !line.contains("invisible-structured-control")));
	}

	#[test]
	fn diagnostic_cause_retains_io_errno_through_context_without_emitting_context() {
		let error = anyhow::Error::new(std::io::Error::from_raw_os_error(5))
			.context("sensitive-owner-token-path-and-payload-fixture");
		let detail = cause(&error);
		assert_eq!(detail.errno, Some(5));
		assert!(detail.code.starts_with("io_"));
		assert!(!format!("{detail:?}").contains("sensitive"));
	}

	#[test]
	fn unrecognized_internal_text_is_never_in_the_diagnostic_vocabulary() {
		let error = anyhow::anyhow!("sensitive-owner-token-path-and-payload-fixture");
		assert_eq!(
			cause(&error),
			Cause {
				code: "internal_other",
				errno: None
			}
		);
	}
}
