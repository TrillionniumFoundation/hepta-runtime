// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Observe the unchanged Tokio create future, actual task cancellation and drain.
//!
//! Only the outer future and its waker are instrumented. A tracer may hold an
//! observer write while this actual Tokio task is polling or before a completed
//! blocking operation forwards its wake. No await is inserted into the target.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
compile_error!("this private syscall qualification profile is Linux x86-64");

use std::ffi::OsString;
use std::future::Future;
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::thread::JoinHandleExt;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Wake, Waker};

#[rustfmt::skip]
mod mcp {
	pub mod fs {
		pub mod remote { include!("original_remote.rs"); }
		pub use remote::PathSource;
		pub mod text_editing { include!("original_text_editing.rs"); }
		pub mod delta { include!("original_delta.rs"); include!("cache_observer.rs"); }
		pub mod file_ops { include!("original_file_ops.rs"); }
	}
	pub mod request_ctx { include!("original_request_ctx.rs"); }
}


// The locked minimal reference has no additional crate dependencies. These are
// the libc ABI declarations for the stated platform, used only by the observer.
#[repr(C)]
struct SignalSet([u64; 16]);

unsafe extern "C" {
	fn sigemptyset(set: *mut SignalSet) -> i32;
	fn sigaddset(set: *mut SignalSet, signal: i32) -> i32;
	fn pthread_sigmask(how: i32, set: *const SignalSet, old: *mut SignalSet) -> i32;
	fn sigwait(set: *const SignalSet, signal: *mut i32) -> i32;
	fn pthread_kill(thread: usize, signal: i32) -> i32;
	fn syscall(number: i64, ...) -> i64;
}

const SIGUSR1: i32 = 10;
const SIGUSR2: i32 = 12;
static SERIAL: AtomicU64 = AtomicU64::new(0);

fn marker(event: u64, poll: u64, wake: u64, first: u64, second: u64) {
	let serial = SERIAL.fetch_add(1, Ordering::SeqCst).wrapping_add(1);
	let tid = unsafe { syscall(186) } as u64;
	let words = [
		128, event, serial, poll, wake, tid, first, second, 0, 0, 0, 0, 0, 0, 0,
	];
	let mut bytes = [0u8; 128];
	bytes[..8].copy_from_slice(b"HLCARP01");
	for (index, word) in words.iter().enumerate() {
		bytes[8 + index * 8..16 + index * 8].copy_from_slice(&word.to_le_bytes());
	}
	// One PIPE_BUF-sized raw write avoids an observer mutex being held across
	// another thread's real destructor. An observer failure is infrastructure.
	if unsafe { syscall(1, 2i32, bytes.as_ptr(), bytes.len()) } != 128 {
		std::process::exit(125);
	}
}

struct State {
	polls: AtomicU64,
	wakes: AtomicU64,
	done: AtomicBool,
	real_waker: Mutex<Option<Waker>>,
}

struct WakeObserver {
	state: Arc<State>,
	real: Waker,
	poll: u64,
}

impl Wake for WakeObserver {
	fn wake(self: Arc<Self>) {
		self.wake_by_ref();
	}

	fn wake_by_ref(self: &Arc<Self>) {
		let count = self
			.state
			.wakes
			.fetch_add(1, Ordering::SeqCst)
			.wrapping_add(1);
		marker(4, self.poll, count, 0, 0);
		self.real.wake_by_ref();
		marker(5, self.poll, count, 0, 0);
	}
}

struct Observed<F: Future> {
	inner: Option<Pin<Box<F>>>,
	state: Arc<State>,
}

impl<F: Future> Future for Observed<F> {
	type Output = F::Output;

	fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
		let this = self.get_mut();
		let count = this
			.state
			.polls
			.fetch_add(1, Ordering::SeqCst)
			.wrapping_add(1);
		*this.state.real_waker.lock().expect("observer waker lock") = Some(cx.waker().clone());
		marker(1, count, 0, 0, 0);
		let waker = Waker::from(Arc::new(WakeObserver {
			state: this.state.clone(),
			real: cx.waker().clone(),
			poll: count,
		}));
		let mut observed = Context::from_waker(&waker);
		let result = this
			.inner
			.as_mut()
			.expect("live original future")
			.as_mut()
			.poll(&mut observed);
		marker(if result.is_pending() { 2 } else { 3 }, count, 0, 0, 0);
		result
	}
}

impl<F: Future> Drop for Observed<F> {
	fn drop(&mut self) {
		let count = self.state.polls.load(Ordering::SeqCst);
		marker(6, count, 0, 0, 0);
		drop(self.inner.take());
		marker(7, count, 0, 0, 0);
	}
}

fn signals() -> io::Result<SignalSet> {
	let mut set = SignalSet([0; 16]);
	let result = unsafe {
		let empty = sigemptyset(&mut set);
		let first = sigaddset(&mut set, SIGUSR1);
		let second = sigaddset(&mut set, SIGUSR2);
		if empty != 0 || first != 0 || second != 0 {
			return Err(io::Error::last_os_error());
		}
		pthread_sigmask(0, &set, std::ptr::null_mut())
	};
	if result != 0 {
		return Err(io::Error::from_raw_os_error(result));
	}
	Ok(set)
}

fn word(raw: &[u8], offset: usize) -> u64 {
	u64::from_le_bytes(
		raw[offset..offset + 8]
			.try_into()
			.expect("checked frame extent"),
	)
}

fn framed(raw: &[u8]) -> io::Result<()> {
	let mut stream = io::stdout().lock();
	stream.write_all(&(raw.len() as u64).to_le_bytes())?;
	stream.write_all(raw)?;
	stream.flush()
}

fn invalid(message: &'static str) -> io::Error {
	io::Error::new(io::ErrorKind::InvalidInput, message)
}


fn complete_cache_observation(cache: &mcp::fs::delta::ViewCache, phase: u64) -> io::Result<()> {
	let raw = mcp::fs::delta::fixture_snapshot(cache, phase);
	io::stderr().lock().write_all(&raw)
}

fn empty_cache_response() -> Vec<u8> {
	let mut result = b"HVCAR001".to_vec();
	result.extend_from_slice(&[0; 24]);
	result
}

fn main() -> io::Result<()> {
	std::panic::set_hook(Box::new(|_| {}));
	let mut input = Vec::new();
	io::stdin().lock().read_to_end(&mut input)?;
	let mut frames = Vec::new();
	let mut cursor = 0;
	while cursor < input.len() {
		if input.len() - cursor < 8 {
			return Err(invalid("private fixture transport header is incomplete"));
		}
		let extent = usize::try_from(word(&input, cursor)).map_err(|_| invalid("fixture extent overflow"))?;
		cursor += 8;
		if extent > input.len() - cursor || extent < 8 {
			return Err(invalid("private fixture transport extent differs"));
		}
		frames.push(&input[cursor..cursor + extent]);
		cursor += extent;
	}
	let create_indices: Vec<_> = frames.iter().enumerate()
		.filter(|(_, frame)| &frame[..8] == b"HLCSPQ01").map(|(index, _)| index).collect();
	if create_indices.len() != 1 {
		return Err(invalid("exactly one Create frame is required"));
	}
	let create_index = create_indices[0];
	let wire = frames[create_index];
	if wire.len() < 64 || word(wire, 8) != 1 || !matches!(word(wire, 16), 1 | 2)
		|| word(wire, 40) == 0 || word(wire, 48) != 0 || word(wire, 56) != 0
	{
		return Err(invalid("private Create fixture header differs"));
	}
	let selector = word(wire, 16);
	let path_len = usize::try_from(word(wire, 24)).map_err(|_| invalid("path extent overflows"))?;
	let content_len = usize::try_from(word(wire, 32)).map_err(|_| invalid("content extent overflows"))?;
	if path_len > wire.len() - 64 || content_len != wire.len() - 64 - path_len {
		return Err(invalid("private Create fixture path/content extents differ"));
	}
	let path = PathBuf::from(OsString::from_vec(wire[64..64 + path_len].to_vec()));
	let content = std::str::from_utf8(&wire[64 + path_len..])
		.map_err(|_| invalid("content is not an admitted UTF-8 String"))?.to_owned();
	let source = mcp::fs::PathSource::Local(path);
	let set = signals()?;
	let cache = Arc::new(mcp::fs::delta::ViewCache::default());
	if create_index == 0 || frames[0] != [b"HVCACH01".as_slice(), &[0u8; 40]].concat() {
		return Err(invalid("fresh cache initialization must precede Create"));
	}
	framed(&empty_cache_response())?;
	for frame in &frames[1..create_index] {
		framed(&mcp::fs::delta::fixture_apply(&cache, frame)?)?;
	}
	complete_cache_observation(&cache, 0)?;
	let runtime = tokio::runtime::Builder::new_current_thread()
		.max_blocking_threads(1)
		.on_thread_start(|| marker(16, 0, 0, 0, 0))
		.on_thread_stop(|| marker(17, 0, 0, 0, 0))
		.build()?;
	let state = Arc::new(State {
		polls: AtomicU64::new(0), wakes: AtomicU64::new(0), done: AtomicBool::new(false),
		real_waker: Mutex::new(None),
	});
	let context_cache = cache.clone();
	let original = async move {
		if selector == 1 {
			mcp::request_ctx::with_request_context(context_cache,
				mcp::fs::file_ops::create_file_spec(&source, &content)).await
		} else {
			mcp::fs::file_ops::create_file_spec(&source, &content).await
		}
	};
	let task = runtime.spawn(Observed { inner: Some(Box::pin(original)), state: state.clone() });
	let abort = task.abort_handle();
	let observer = state.clone();
	let control = std::thread::spawn(move || {
		marker(14, 0, 0, 0, 0);
		loop {
			let mut signal = 0;
			let error = unsafe { sigwait(&set, &mut signal) };
			if error != 0 { std::process::exit(124); }
			if observer.done.load(Ordering::SeqCst) { break; }
			if signal == SIGUSR1 {
				marker(8, observer.polls.load(Ordering::SeqCst), 0, 0, 0);
				abort.abort();
				marker(9, observer.polls.load(Ordering::SeqCst), 0, 0, 0);
			} else if signal == SIGUSR2 {
				let waker = observer.real_waker.lock().expect("observer waker lock").clone();
				marker(10, observer.polls.load(Ordering::SeqCst), 0, 0, 0);
				if let Some(waker) = waker { waker.wake(); }
			}
		}
	});
	marker(15, 0, 0, 0, 0);
	let actual = runtime.block_on(task);
	match actual {
		Err(error) if error.is_cancelled() => {
			marker(11, state.polls.load(Ordering::SeqCst), 0, 0, 0);
			let mut stream = io::stdout().lock();
			stream.write_all(&0xfffffff7u64.to_le_bytes())?;
			stream.flush()?;
		}
		Err(error) => return Err(io::Error::other(format!("original task panicked: {error}"))),
		Ok(result) => {
			let (kind, message) = match result {
				Ok(message) => (0u64, message),
				Err(error) => (1u64, error.to_string()),
			};
			marker(12, state.polls.load(Ordering::SeqCst), 0, kind, message.len() as u64);
			let mut response = b"HLCSPR01".to_vec();
			for value in [1, kind, message.len() as u64] {
				response.extend_from_slice(&value.to_le_bytes());
			}
			response.extend_from_slice(message.as_bytes());
			framed(&response)?;
		}
	}
	drop(runtime);
	marker(13, state.polls.load(Ordering::SeqCst), state.wakes.load(Ordering::SeqCst), 0, 0);
	state.done.store(true, Ordering::SeqCst);
	let error = unsafe { pthread_kill(control.as_pthread_t() as usize, SIGUSR2) };
	if error != 0 { return Err(io::Error::from_raw_os_error(error)); }
	control.join().map_err(|_| io::Error::other("observer control thread panicked"))?;
	complete_cache_observation(&cache, 1)?;
	for frame in &frames[create_index + 1..] {
		if frame.len() < 48 || &frame[..8] != b"HVCACH01" || word(frame, 8) != 1 {
			return Err(invalid("post-Create cache inspection must be read-only"));
		}
		framed(&mcp::fs::delta::fixture_apply(&cache, frame)?)?;
	}
	Ok(())
}
