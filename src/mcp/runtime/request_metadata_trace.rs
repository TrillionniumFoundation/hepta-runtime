// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Opt-in metadata timing with local call/cohort IDs and bounded, nonblocking capture.
//! No owner, request ID, cursor, path, original record or error text is retained.
use std::cell::Cell;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Mutex, OnceLock};
use std::time::Instant;

const MAX_EVENTS: usize = 4096;

#[derive(Clone, Copy)]
struct Context {
	id: u64,
	tool: &'static str,
	entered: Instant,
	deadline: Instant,
	limit: u16,
	cursor: bool,
}

thread_local! {
	static CURRENT: Cell<Option<Context>> = const { Cell::new(None) };
}

#[derive(serde::Serialize)]
struct Event {
	sequence: u64,
	call: u64,
	tool: &'static str,
	phase: &'static str,
	kind: &'static str,
	at_us: u64,
	call_us: u64,
	remaining_us: i64,
	cohort: u64,
	value: u64,
	limit: u16,
	cursor: bool,
}

struct Buffer {
	send: mpsc::SyncSender<Event>,
	receive: Mutex<mpsc::Receiver<Event>>,
	dropped: AtomicU64,
}

fn enabled() -> bool {
	static ENABLED: OnceLock<bool> = OnceLock::new();
	*ENABLED
		.get_or_init(|| std::env::var_os("HEPTA_METADATA_TRACE").is_some_and(|value| value == "1"))
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

fn micros(value: std::time::Duration) -> u64 {
	value.as_micros().min(u64::MAX as u128) as u64
}

fn remaining(deadline: Instant, now: Instant) -> i64 {
	if deadline >= now {
		micros(deadline.duration_since(now)).min(i64::MAX as u64) as i64
	} else {
		-(micros(now.duration_since(deadline)).min(i64::MAX as u64) as i64)
	}
}

fn record(context: Context, phase: &'static str, kind: &'static str, cohort: u64, value: u64) {
	static ORIGIN: OnceLock<Instant> = OnceLock::new();
	static SEQUENCE: AtomicU64 = AtomicU64::new(1);
	let origin = *ORIGIN.get_or_init(Instant::now);
	let now = Instant::now();
	let event = Event {
		sequence: SEQUENCE.fetch_add(1, Ordering::Relaxed),
		call: context.id,
		tool: context.tool,
		phase,
		kind,
		at_us: micros(now.saturating_duration_since(origin)),
		call_us: micros(now.saturating_duration_since(context.entered)),
		remaining_us: remaining(context.deadline, now),
		cohort,
		value,
		limit: context.limit,
		cursor: context.cursor,
	};
	let buffer = buffer();
	if buffer.send.try_send(event).is_err() {
		buffer.dropped.fetch_add(1, Ordering::Relaxed);
	}
}

/// Only call after the original query/lock scopes have returned. Capture inside
/// those scopes is try_send only; an unavailable logger never changes results.
pub(super) fn flush() {
	if !enabled() {
		return;
	}
	let buffer = buffer();
	let events: Vec<_> = {
		let Ok(receiver) = buffer.receive.try_lock() else {
			return;
		};
		receiver.try_iter().take(MAX_EVENTS).collect()
	};
	let dropped = buffer.dropped.swap(0, Ordering::Relaxed);
	let _ = std::panic::catch_unwind(|| {
		for event in events {
			if let Ok(line) = serde_json::to_string(&event) {
				tracing::warn!(target: "hepta_metadata_trace", "hepta_metadata_trace {}", line);
			}
		}
		if dropped != 0 {
			tracing::warn!(target: "hepta_metadata_trace", "hepta_metadata_trace {{\"dropped_events\":{}}}", dropped);
		}
	});
}

#[derive(Clone, Copy)]
pub(super) struct QueryTrace(Option<Context>);

impl QueryTrace {
	pub(super) fn new(tool: &'static str, deadline: Instant, limit: u16, cursor: bool) -> Self {
		static IDS: AtomicU64 = AtomicU64::new(1);
		let trace = Self(enabled().then(|| Context {
			id: IDS.fetch_add(1, Ordering::Relaxed),
			tool,
			entered: Instant::now(),
			deadline,
			limit,
			cursor,
		}));
		trace.mark("api_enter", 0);
		trace
	}

	pub(super) fn mark(self, phase: &'static str, value: u64) {
		if let Some(context) = self.0 {
			record(context, phase, "event", 0, value);
		}
	}

	pub(super) fn mark_cohort(self, phase: &'static str, cohort: u64, value: u64) {
		if let Some(context) = self.0 {
			record(context, phase, "event", cohort, value);
		}
	}

	pub(super) fn enter(self) -> ThreadContext {
		ThreadContext(CURRENT.with(|current| current.replace(self.0)))
	}

	pub(super) fn boundary(self, phase: &'static str) -> Boundary {
		Boundary(self, phase)
	}
}

pub(super) struct Boundary(QueryTrace, &'static str);
impl Drop for Boundary {
	fn drop(&mut self) {
		self.0.mark(self.1, 0);
		flush();
	}
}

pub(super) struct ThreadContext(Option<Context>);
impl Drop for ThreadContext {
	fn drop(&mut self) {
		mark("blocking_scope_end", 0, 0);
		CURRENT.with(|current| current.set(self.0));
		flush();
	}
}

pub(super) fn next_cohort() -> u64 {
	static IDS: AtomicU64 = AtomicU64::new(1);
	if enabled() {
		IDS.fetch_add(1, Ordering::Relaxed)
	} else {
		0
	}
}

pub(super) fn mark(phase: &'static str, cohort: u64, value: u64) {
	CURRENT.with(|current| {
		if let Some(context) = current.get() {
			record(context, phase, "event", cohort, value);
		}
	});
}

pub(super) struct Stage {
	context: Option<Context>,
	phase: &'static str,
	started: Option<Instant>,
}
impl Stage {
	pub(super) fn new(phase: &'static str) -> Self {
		let context = CURRENT.with(Cell::get);
		if let Some(context) = context {
			record(context, phase, "begin", 0, 0);
		}
		Self {
			context,
			phase,
			started: context.map(|_| Instant::now()),
		}
	}
}
impl Drop for Stage {
	fn drop(&mut self) {
		if let (Some(context), Some(started)) = (self.context, self.started) {
			record(context, self.phase, "end", 0, micros(started.elapsed()));
		}
	}
}

#[cfg(test)]
#[path = "request_metadata_trace_tests.rs"]
mod tests;
