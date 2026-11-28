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
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Wake, Waker};
use tokio::io::AsyncWriteExt;

include!("original_function.rs");

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

fn main() -> io::Result<()> {
	let mut input = Vec::new();
	io::stdin().lock().read_to_end(&mut input)?;
	if input.len() < 72 || word(&input, 0) != (input.len() - 8) as u64 {
		return Err(invalid("private fixture transport extent differs"));
	}
	let wire = &input[8..];
	if &wire[..8] != b"HLCARQ01"
		|| word(wire, 8) != 1
		|| word(wire, 32) != 1
		|| wire[40..64].iter().any(|byte| *byte != 0)
	{
		return Err(invalid("private fixture header differs"));
	}
	let path_len = usize::try_from(word(wire, 16)).map_err(|_| invalid("path extent overflows"))?;
	let content_len =
		usize::try_from(word(wire, 24)).map_err(|_| invalid("content extent overflows"))?;
	if path_len > wire.len() - 64 || content_len != wire.len() - 64 - path_len {
		return Err(invalid("private fixture path/content extents differ"));
	}
	let path_bytes = wire[64..64 + path_len].to_vec();
	let has_nul = path_bytes.contains(&0);
	let path = PathBuf::from(OsString::from_vec(path_bytes));
	let content = wire[64 + path_len..].to_vec();
	let set = signals()?;
	let runtime = tokio::runtime::Builder::new_current_thread()
		.max_blocking_threads(1)
		.on_thread_start(|| marker(16, 0, 0, 0, 0))
		.on_thread_stop(|| marker(17, 0, 0, 0, 0))
		.build()?;
	let state = Arc::new(State {
		polls: AtomicU64::new(0),
		wakes: AtomicU64::new(0),
		done: AtomicBool::new(false),
		real_waker: Mutex::new(None),
	});
	let original = async move { create_local_file(&path, &content).await };
	let task = runtime.spawn(Observed {
		inner: Some(Box::pin(original)),
		state: state.clone(),
	});
	let abort = task.abort_handle();
	let observer = state.clone();
	let control = std::thread::spawn(move || {
		marker(14, 0, 0, 0, 0);
		loop {
			let mut signal = 0;
			let error = unsafe { sigwait(&set, &mut signal) };
			if error != 0 {
				std::process::exit(124);
			}
			if observer.done.load(Ordering::SeqCst) {
				break;
			}
			if signal == SIGUSR1 {
				marker(8, observer.polls.load(Ordering::SeqCst), 0, 0, 0);
				abort.abort();
				marker(9, observer.polls.load(Ordering::SeqCst), 0, 0, 0);
			} else if signal == SIGUSR2 {
				let waker = observer
					.real_waker
					.lock()
					.expect("observer waker lock")
					.clone();
				marker(10, observer.polls.load(Ordering::SeqCst), 0, 0, 0);
				if let Some(waker) = waker {
					waker.wake();
				}
			}
		}
	});
	marker(15, 0, 0, 0, 0);
	let actual = runtime.block_on(task);
	match actual {
		Err(error) if error.is_cancelled() => {
			marker(11, state.polls.load(Ordering::SeqCst), 0, 0, 0);
			let mut response = b"HLCCAN01".to_vec();
			response.extend_from_slice(&16u64.to_le_bytes());
			framed(&response)?;
		}
		Err(error) => return Err(io::Error::other(format!("original task panicked: {error}"))),
		Ok(result) => {
			let (kind, error, written) = match result {
				Ok(()) => (0u64, 0u64, content_len as u64),
				Err(error) => match error.raw_os_error() {
					Some(number) if number > 0 => (1, number as u64, 0),
					None if error.kind() == io::ErrorKind::InvalidInput && has_nul => (2, 0, 0),
					None if error.kind() == io::ErrorKind::WriteZero => (3, 0, 0),
					_ => return Err(error),
				},
			};
			marker(12, state.polls.load(Ordering::SeqCst), 0, kind, error);
			let mut response = b"HLCRER01".to_vec();
			for value in [48, kind, error, written, 0] {
				response.extend_from_slice(&value.to_le_bytes());
			}
			framed(&response)?;
		}
	}
	// Cancellation publication may precede an in-flight blocking operation. The
	// actual Runtime drop waits for that operation; no completion is invented.
	drop(runtime);
	marker(
		13,
		state.polls.load(Ordering::SeqCst),
		state.wakes.load(Ordering::SeqCst),
		0,
		0,
	);
	state.done.store(true, Ordering::SeqCst);
	let signal_error = unsafe { pthread_kill(control.as_pthread_t() as usize, SIGUSR2) };
	if signal_error != 0 {
		return Err(io::Error::from_raw_os_error(signal_error));
	}
	control
		.join()
		.map_err(|_| io::Error::other("observer control thread panicked"))?;
	Ok(())
}
