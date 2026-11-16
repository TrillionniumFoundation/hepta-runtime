// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Execute the HIA-emitted synchronization boundary on actual Linux threads.

use std::cell::UnsafeCell;
use std::ffi::{c_int, c_long, c_void};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::marker::PhantomData;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError, TryLockError};
use std::time::{Duration, Instant};

unsafe extern "C" {
	fn mmap(
		address: *mut c_void,
		length: usize,
		protection: c_int,
		flags: c_int,
		fd: c_int,
		offset: i64,
	) -> *mut c_void;
	fn mprotect(address: *mut c_void, length: usize, protection: c_int) -> c_int;
	fn munmap(address: *mut c_void, length: usize) -> c_int;
	fn syscall(number: c_long, ...) -> c_long;
	fn signal(number: c_int, handler: usize) -> usize;
	fn siginterrupt(number: c_int, interrupt: c_int) -> c_int;
}

type Entry = unsafe extern "C" fn(*const u8, usize, *mut u8, usize, *mut u8, usize) -> u32;

struct Image {
	address: *mut c_void,
	length: usize,
	entry: Entry,
}

// The mapping is made read/execute before publication and remains immutable.
unsafe impl Send for Image {}
unsafe impl Sync for Image {}

impl Image {
	fn load() -> Self {
		let bytes = std::fs::read(std::env::var("HIA_AUDIT_SYNC_IMAGE").unwrap()).unwrap();
		assert!(!bytes.is_empty());
		let length = (bytes.len() + 4095) & !4095;
		unsafe {
			let address = mmap(std::ptr::null_mut(), length, 3, 0x22, -1, 0);
			assert_ne!(address as isize, -1);
			std::ptr::copy_nonoverlapping(bytes.as_ptr(), address.cast::<u8>(), bytes.len());
			assert_eq!(mprotect(address, length, 5), 0);
			Self {
				address,
				length,
				entry: std::mem::transmute::<*mut c_void, Entry>(address),
			}
		}
	}
}

impl Drop for Image {
	fn drop(&mut self) {
		assert_eq!(unsafe { munmap(self.address, self.length) }, 0);
	}
}

static IMAGE: OnceLock<Arc<Image>> = OnceLock::new();
static JOURNAL: OnceLock<Mutex<File>> = OnceLock::new();
static CALLS: AtomicU64 = AtomicU64::new(0);
static GENERATIONS: AtomicU64 = AtomicU64::new(1);
static SIGNALS: AtomicU64 = AtomicU64::new(0);

fn observation(state: &State, kind: &str, fields: &str) {
	writeln!(JOURNAL.get().unwrap().lock().unwrap(),
		"{{\"record\":\"observation\",\"case\":\"{}\",\"generation\":{},\"kind\":\"{kind}\",{fields}}}",
		state.case_name, state.generation)
	.unwrap();
}

fn hex(bytes: &[u8]) -> String {
	let mut output = String::with_capacity(bytes.len() * 2);
	for byte in bytes {
		use std::fmt::Write;
		write!(&mut output, "{byte:02x}").unwrap();
	}
	output
}

fn record(
	frame: &[u64; 16],
	returned: u32,
	before: &[u8],
	after: &[u8],
	state: &State,
	shape: [usize; 3],
	alias: &str,
) {
	let index = CALLS.fetch_add(1, Ordering::Relaxed);
	let input: Vec<u8> = frame.iter().flat_map(|word| word.to_le_bytes()).collect();
	let journal = JOURNAL.get_or_init(|| {
		Mutex::new(
			OpenOptions::new()
				.write(true)
				.create_new(true)
				.open(std::env::var("HIA_AUDIT_SYNC_JOURNAL").unwrap())
				.unwrap(),
		)
	});
	let tid = unsafe { syscall(186) };
	writeln!(journal.lock().unwrap(),
		"{{\"record\":\"call\",\"case\":\"{}\",\"index\":{index},\"pid\":{},\"tid\":{tid},\"generation\":{},\"returned\":{returned},\"input_length\":{},\"output_length\":{},\"state_length\":{},\"alias\":\"{alias}\",\"input_hex\":\"{}\",\"output_before_hex\":\"{}\",\"output_after_hex\":\"{}\"}}",
		state.case_name, std::process::id(), state.generation, shape[0], shape[1], shape[2],
		hex(&input), hex(before), hex(after)).unwrap();
}

struct State {
	words: UnsafeCell<[u64; 10]>,
	generation: u64,
	image: Arc<Image>,
	case_name: String,
}

// Only the machine-code atomic protocol accesses a live shared synchronization
// state. Rust snapshots below are restricted to explicitly quiescent tests.
unsafe impl Send for State {}
unsafe impl Sync for State {}

#[derive(Debug)]
struct Reply {
	returned: u32,
	words: [u64; 16],
	bytes: [u8; 160],
}

impl State {
	fn new() -> Arc<Self> {
		let case_name = std::thread::current().name().unwrap().to_owned();
		assert!(case_name
			.bytes()
			.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'));
		let state = Arc::new(Self {
			words: UnsafeCell::new([
				0,
				0,
				0,
				0,
				0,
				0,
				0,
				0,
				0xa5a5a5a5a5a5a5a5,
				0xa5a5a5a5a5a5a5a5,
			]),
			generation: GENERATIONS.fetch_add(1, Ordering::Relaxed),
			image: IMAGE.get_or_init(|| Arc::new(Image::load())).clone(),
			case_name,
		});
		let reply = state.invoke(state.frame(0, 0), 128, 128, 64);
		assert_eq!(reply.returned, 128);
		assert_eq!(reply.words[0], u64::from_le_bytes(*b"HASYNR01"));
		assert_eq!(reply.words[10], state.generation);
		state
	}

	fn frame(&self, operation: u64, kind: u64) -> [u64; 16] {
		let mut frame = [0; 16];
		frame[0] = u64::from_le_bytes(*b"HASCMD01");
		frame[1] = operation;
		frame[2] = kind;
		frame[3] = self.generation;
		frame
	}

	fn invoke(
		&self,
		mut frame: [u64; 16],
		input_len: usize,
		output_len: usize,
		state_len: usize,
	) -> Reply {
		let original_frame = frame;
		let before = [0xa5; 160];
		let mut bytes = before;
		let returned = unsafe {
			(self.image.entry)(
				frame.as_mut_ptr().cast(),
				input_len,
				bytes.as_mut_ptr(),
				output_len,
				self.words.get().cast(),
				state_len,
			)
		};
		assert_eq!(frame, original_frame);
		record(
			&frame,
			returned,
			&before,
			&bytes,
			self,
			[input_len, output_len, state_len],
			"disjoint",
		);
		assert_eq!(&bytes[128..], &before[128..]);
		if returned != 128 {
			assert_eq!(bytes, before);
		}
		let words = std::array::from_fn(|index| {
			u64::from_le_bytes(bytes[index * 8..index * 8 + 8].try_into().unwrap())
		});
		Reply {
			returned,
			words,
			bytes,
		}
	}

	fn command(&self, frame: [u64; 16]) -> Reply {
		let reply = self.invoke(frame, 128, 128, 64);
		assert_eq!(reply.returned, 128, "{reply:?}");
		assert_eq!(reply.words[0], u64::from_le_bytes(*b"HASYNR01"));
		assert_eq!(reply.words[1], frame[1]);
		assert_eq!(reply.words[3], unsafe { syscall(186) } as u64);
		assert_eq!(reply.words[10], self.generation);
		assert_eq!(reply.words[15], 0);
		reply
	}

	fn lock(self: &Arc<Self>, kind: u64) -> Result<Guard, PoisonError<Guard>> {
		let mut frame = self.frame(1, kind);
		frame[5] = u64::from(std::thread::panicking());
		let result = self.command(frame);
		let guard = Guard {
			state: self.clone(),
			kind,
			active: true,
			not_send: PhantomData,
		};
		match result.words[2] {
			0 => Ok(guard),
			1 => Err(PoisonError::new(guard)),
			other => panic!("unexpected lock result {other}"),
		}
	}

	fn try_lock(self: &Arc<Self>, kind: u64) -> Result<Guard, TryLockError<Guard>> {
		let mut frame = self.frame(2, kind);
		frame[5] = u64::from(std::thread::panicking());
		let result = self.command(frame);
		if result.words[2] == 2 {
			return Err(TryLockError::WouldBlock);
		}
		let guard = Guard {
			state: self.clone(),
			kind,
			active: true,
			not_send: PhantomData,
		};
		match result.words[2] {
			0 => Ok(guard),
			1 => Err(TryLockError::Poisoned(PoisonError::new(guard))),
			other => panic!("unexpected try-lock result {other}"),
		}
	}

	fn status(&self) -> Reply {
		self.command(self.frame(7, 0))
	}

	fn notify(&self) {
		let result = self.command(self.frame(5, 0));
		assert_eq!(result.words[2], 0);
		assert_eq!(result.words[4], 0);
	}

	fn snapshot_quiescent(&self) -> [u64; 10] {
		let value = unsafe { *self.words.get() };
		let raw: Vec<u8> = value.iter().flat_map(|word| word.to_le_bytes()).collect();
		writeln!(JOURNAL.get().unwrap().lock().unwrap(),
			"{{\"record\":\"quiescent-state\",\"case\":\"{}\",\"generation\":{},\"calls_seen\":{},\"state_hex\":\"{}\"}}",
			self.case_name, self.generation, CALLS.load(Ordering::Relaxed), hex(&raw)).unwrap();
		value
	}
}

struct Guard {
	state: Arc<State>,
	kind: u64,
	active: bool,
	not_send: PhantomData<MutexGuard<'static, ()>>,
}

impl std::fmt::Debug for Guard {
	fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		formatter
			.debug_struct("Guard")
			.field("kind", &self.kind)
			.field("active", &self.active)
			.finish()
	}
}

impl Guard {
	fn wait(
		mut self,
		duration: Option<Duration>,
		sequence: u64,
	) -> (Result<Self, PoisonError<Self>>, u64) {
		assert_eq!(self.kind, 0);
		let mut frame = self.state.frame(4, 0);
		frame[4] = sequence;
		if let Some(duration) = duration {
			frame[6] = 1;
			frame[7] = duration.as_secs();
			frame[8] = u64::from(duration.subsec_nanos());
		}
		let result = self.state.command(frame);
		let errno = result.words[4];
		assert!([0, 4, 11, 110].contains(&errno));
		assert_eq!(result.words[11], result.words[3]);
		assert_eq!(result.words[13], 1);
		self.active = true;
		match result.words[2] {
			0 => (Ok(self), errno),
			1 => (Err(PoisonError::new(self)), errno),
			other => panic!("unexpected condition wait result {other}"),
		}
	}
}

impl Drop for Guard {
	fn drop(&mut self) {
		if self.active {
			let mut frame = self.state.frame(3, self.kind);
			frame[5] = u64::from(std::thread::panicking());
			let reply = self.state.command(frame);
			assert_eq!(reply.words[2], 0);
			self.active = false;
		}
	}
}

#[test]
fn canonical_frames_and_capacities_refuse_without_writes() {
	let state = State::new();
	let before = state.snapshot_quiescent();
	let good = state.frame(7, 0);
	let mut controls = Vec::new();
	for (index, value) in [
		(0, 0),
		(1, 8),
		(2, 1),
		(2, 2),
		(3, 0),
		(3, state.generation + 1),
		(4, 1),
		(5, 1),
		(6, 1),
		(7, 1),
		(8, 1),
		(9, 1),
		(10, 1),
		(11, 1),
		(12, 1),
		(13, 1),
		(14, 1),
		(15, 1),
	] {
		let mut frame = good;
		frame[index] = value;
		controls.push((frame, 128, 128, 64));
	}
	controls.extend([
		(good, 127, 128, 64),
		(good, 129, 128, 64),
		(good, 128, 127, 64),
		(good, 128, 128, 63),
	]);
	for (frame, input, output, workspace) in controls {
		let reply = state.invoke(frame, input, output, workspace);
		assert!([0xffffffff, 0xfffffffe, 0xfffffff9].contains(&reply.returned));
		assert_eq!(reply.bytes, [0xa5; 160]);
		assert_eq!(state.snapshot_quiescent(), before);
	}
	let repeated_init = state.invoke(state.frame(0, 0), 128, 128, 64);
	assert_eq!(repeated_init.returned, 0xfffffff9);
	assert_eq!(state.snapshot_quiescent(), before);
	assert_eq!(state.status().words[2], 0);
}

#[test]
fn independent_mutexes_and_real_try_lock_results() {
	let state = State::new();
	let queue = state.lock(0).unwrap();
	let inner = state.lock(1).unwrap();
	assert!(matches!(state.try_lock(0), Err(TryLockError::WouldBlock)));
	assert!(matches!(state.try_lock(1), Err(TryLockError::WouldBlock)));
	let status = state.status();
	assert_eq!((status.words[13], status.words[14]), (1, 1));
	assert_eq!(status.words[11], status.words[3]);
	assert_eq!(status.words[12], status.words[3]);
	drop(inner);
	drop(queue);
	drop(state.try_lock(0).unwrap());
	drop(state.try_lock(1).unwrap());
	let final_state = state.snapshot_quiescent();
	assert_eq!(&final_state[1..6], &[0, 0, 0, 0, 0]);
	assert_eq!(&final_state[8..], &[0xa5a5a5a5a5a5a5a5; 2]);
}

struct Counter(UnsafeCell<u64>);
// Every access below is protected by the native queue mutex.
unsafe impl Sync for Counter {}

#[test]
fn sixteen_threads_preserve_actual_mutual_exclusion() {
	let state = State::new();
	let counter = Arc::new(Counter(UnsafeCell::new(0)));
	let barrier = Arc::new(std::sync::Barrier::new(17));
	let mut threads = Vec::new();
	for _ in 0..16 {
		let (state, counter, barrier) = (state.clone(), counter.clone(), barrier.clone());
		threads.push(std::thread::spawn(move || {
			barrier.wait();
			let tid = unsafe { syscall(186) };
			for _ in 0..256 {
				let guard = state.lock(0).unwrap();
				unsafe {
					*counter.0.get() += 1;
				}
				drop(guard);
			}
			tid
		}));
	}
	barrier.wait();
	let tids: std::collections::BTreeSet<_> = threads
		.into_iter()
		.map(|thread| thread.join().unwrap())
		.collect();
	assert_eq!(tids.len(), 16);
	assert_eq!(unsafe { *counter.0.get() }, 4096);
	observation(
		&state,
		"mutual-exclusion",
		&format!(
			"\"worker_tids\":{:?},\"counter\":{}",
			tids.into_iter().collect::<Vec<_>>(),
			unsafe { *counter.0.get() }
		),
	);
	assert_eq!(state.status().words[13], 0);
}

#[test]
fn poison_is_published_by_actual_owner_unwinding() {
	for kind in [0, 1] {
		let state = State::new();
		let owner = state.clone();
		assert!(std::thread::spawn(move || {
			let _guard = owner.lock(kind).unwrap();
			panic!("source-owned native poison observation");
		})
		.join()
		.is_err());
		let original = Arc::new(Mutex::new(()));
		let original_owner = original.clone();
		assert!(std::thread::spawn(move || {
			let _guard = original_owner.lock().unwrap();
			panic!("source-owned original poison observation");
		})
		.join()
		.is_err());
		assert!(original.is_poisoned());
		assert_eq!(state.status().words[6 + kind as usize], 1);
		observation(
			&state,
			"poison",
			&format!("\"mutex_kind\":{kind},\"original_poisoned\":true,\"native_poisoned\":true"),
		);
		let poisoned = state.lock(kind).unwrap_err().into_inner();
		assert_eq!(state.status().words[13 + kind as usize], 1);
		drop(poisoned);
		match state.try_lock(kind) {
			Err(TryLockError::Poisoned(error)) => drop(error.into_inner()),
			other => panic!("poisoned try-lock did not retain custody: {other:?}"),
		}
		assert_eq!(state.status().words[13 + kind as usize], 0);
	}
}

struct DuringUnwind {
	state: Arc<State>,
	original: Arc<Mutex<()>>,
	kind: u64,
}

impl Drop for DuringUnwind {
	fn drop(&mut self) {
		assert!(std::thread::panicking());
		let native = self.state.lock(self.kind).unwrap();
		let original = self.original.lock().unwrap();
		drop(original);
		drop(native);
	}
}

#[test]
fn lock_entered_during_existing_unwind_does_not_invent_poison() {
	for kind in [0, 1] {
		let state = State::new();
		let original = Arc::new(Mutex::new(()));
		let actor = DuringUnwind {
			state: state.clone(),
			original: original.clone(),
			kind,
		};
		assert!(std::thread::spawn(move || {
			let _actor = actor;
			panic!("begin unwind before queue acquisition");
		})
		.join()
		.is_err());
		assert!(!original.is_poisoned());
		assert_eq!(state.status().words[6 + kind as usize], 0);
		observation(
			&state,
			"existing-unwind",
			&format!("\"mutex_kind\":{kind},\"original_poisoned\":false,\"native_poisoned\":false"),
		);
		drop(state.lock(kind).unwrap());
	}
}

#[test]
fn timeout_and_changed_sequence_reacquire_the_same_mutex() {
	let state = State::new();
	let guard = state.lock(0).unwrap();
	let sequence = state.status().words[5];
	let (guard, errno) = guard.wait(Some(Duration::ZERO), sequence);
	assert_eq!(errno, 110);
	let guard = guard.unwrap();
	let original = Mutex::new(());
	let changed = std::sync::Condvar::new();
	let (original_guard, timed) = changed
		.wait_timeout(original.lock().unwrap(), Duration::ZERO)
		.unwrap();
	assert!(timed.timed_out());
	drop(original_guard);
	state.notify();
	let (guard, errno) = guard.wait(Some(Duration::from_secs(5)), sequence);
	assert_eq!(errno, 11);
	drop(guard.unwrap());
	assert_eq!(state.status().words[13], 0);
}

#[test]
fn real_notification_cannot_be_lost_between_unlock_and_wait() {
	let state = State::new();
	let guard = state.lock(0).unwrap();
	let sequence = state.status().words[5];
	let (ready, receive) = std::sync::mpsc::channel();
	let peer = state.clone();
	let worker = std::thread::spawn(move || {
		ready.send(()).unwrap();
		let guard = peer.lock(0).unwrap();
		peer.notify();
		drop(guard);
		unsafe { syscall(186) }
	});
	receive.recv_timeout(Duration::from_secs(5)).unwrap();
	let start = Instant::now();
	let (guard, errno) = guard.wait(Some(Duration::from_secs(5)), sequence);
	let guard = guard.unwrap();
	assert!([0, 11].contains(&errno));
	assert!(start.elapsed() < Duration::from_secs(5));
	assert_eq!(state.status().words[5], sequence + 1);
	drop(guard);
	assert_ne!(worker.join().unwrap(), unsafe { syscall(186) });
}

#[test]
fn notify_all_releases_all_sixty_five_actual_waiters() {
	let state = State::new();
	let (ready, receive) = std::sync::mpsc::channel();
	let mut workers = Vec::new();
	for _ in 0..65 {
		let (peer, ready) = (state.clone(), ready.clone());
		workers.push(std::thread::spawn(move || {
			let guard = peer.lock(0).unwrap();
			let sequence = peer.status().words[5];
			ready.send(()).unwrap();
			let (guard, errno) = guard.wait(Some(Duration::from_secs(5)), sequence);
			assert!([0, 11].contains(&errno));
			drop(guard.unwrap());
			unsafe { syscall(186) }
		}));
	}
	drop(ready);
	let deadline = Instant::now() + Duration::from_secs(5);
	for _ in 0..65 {
		receive
			.recv_timeout(deadline.saturating_duration_since(Instant::now()))
			.unwrap();
	}
	let guard = state.lock(0).unwrap();
	state.notify();
	drop(guard);
	let tids: std::collections::BTreeSet<_> = workers
		.into_iter()
		.map(|worker| worker.join().unwrap())
		.collect();
	assert_eq!(tids.len(), 65);
	observation(
		&state,
		"notify-all",
		&format!("\"worker_tids\":{:?}", tids.into_iter().collect::<Vec<_>>()),
	);
	let status = state.status();
	assert_eq!(status.words[13], 0);
	assert_eq!(status.words[5], 1);
}

#[test]
fn condition_reacquisition_preserves_poison_and_guard_custody() {
	let state = State::new();
	let guard = state.lock(0).unwrap();
	let sequence = state.status().words[5];
	let (ready, receive) = std::sync::mpsc::channel();
	let peer = state.clone();
	let worker = std::thread::spawn(move || {
		ready.send(()).unwrap();
		let _guard = peer.lock(0).unwrap();
		peer.notify();
		panic!("publish poison after notification while still owning the mutex");
	});
	receive.recv_timeout(Duration::from_secs(5)).unwrap();
	let (guard, errno) = guard.wait(Some(Duration::from_secs(5)), sequence);
	assert!([0, 11].contains(&errno));
	let guard = guard.unwrap_err().into_inner();
	assert_eq!(state.status().words[6], 1);
	assert_eq!(state.status().words[13], 1);
	drop(guard);
	assert!(worker.join().is_err());
}

#[test]
fn only_the_actual_kernel_owner_can_unlock() {
	let state = State::new();
	for kind in [0, 1] {
		let guard = state.lock(kind).unwrap();
		let before = state.snapshot_quiescent();
		let peer = state.clone();
		let reply = std::thread::spawn(move || peer.invoke(peer.frame(3, kind), 128, 128, 64))
			.join()
			.unwrap();
		assert_eq!(reply.returned, 0xfffffff9);
		assert_eq!(reply.bytes, [0xa5; 160]);
		assert_eq!(state.snapshot_quiescent(), before);
		drop(guard);
	}
	let before = state.snapshot_quiescent();
	assert_eq!(
		state.invoke(state.frame(5, 0), 128, 128, 64).returned,
		0xfffffff9
	);
	assert_eq!(
		state.invoke(state.frame(4, 0), 128, 128, 64).returned,
		0xfffffff9
	);
	assert_eq!(state.snapshot_quiescent(), before);
}

fn kernel_clock() -> u128 {
	let mut value = [0i64; 2];
	assert_eq!(unsafe { syscall(228, 1, value.as_mut_ptr()) }, 0);
	assert!(value[0] >= 0 && (0..1_000_000_000).contains(&value[1]));
	(value[0] as u128) * 1_000_000_000 + value[1] as u128
}

#[test]
fn native_clock_is_the_actual_unsigned_monotonic_epoch() {
	let state = State::new();
	let mut previous = 0;
	for _ in 0..128 {
		let before = kernel_clock();
		let reply = state.command(state.frame(6, 0));
		let after = kernel_clock();
		assert_eq!(reply.words[2], 0);
		assert_eq!(reply.words[4], 0);
		let value = (u128::from(reply.words[9]) << 64) | u128::from(reply.words[8]);
		assert!(before <= value && value <= after && previous <= value);
		observation(
			&state,
			"clock",
			&format!("\"before\":{before},\"value\":{value},\"after\":{after}"),
		);
		previous = value;
	}
}

#[test]
fn invalid_wait_frames_keep_existing_queue_custody() {
	let state = State::new();
	let guard = state.lock(0).unwrap();
	let before = state.snapshot_quiescent();
	let mut base = state.frame(4, 0);
	base[6] = 1;
	base[8] = 1;
	for (index, value) in [
		(2, 1),
		(4, 1u64 << 32),
		(5, 1),
		(6, 2),
		(7, 1u64 << 63),
		(8, 1_000_000_000),
		(9, 1),
		(15, 1),
	] {
		let mut frame = base;
		frame[index] = value;
		assert_eq!(state.invoke(frame, 128, 128, 64).returned, 0xffffffff);
		assert_eq!(state.snapshot_quiescent(), before);
	}
	base[6] = 0;
	assert_eq!(state.invoke(base, 128, 128, 64).returned, 0xffffffff);
	assert_eq!(state.snapshot_quiescent(), before);
	drop(guard);
}

#[test]
fn overlapping_borrowed_regions_are_refused_before_any_write() {
	let state = State::new();
	let frame = state.frame(7, 0);
	let input: Vec<u8> = frame.iter().flat_map(|word| word.to_le_bytes()).collect();
	let state_before = state.snapshot_quiescent();
	let mut shared = [0xa5; 160];
	shared[..128].copy_from_slice(&input);
	let before = shared;
	let pointer = shared.as_mut_ptr();
	let returned =
		unsafe { (state.image.entry)(pointer, 128, pointer, 128, state.words.get().cast(), 64) };
	record(
		&frame,
		returned,
		&before,
		&shared,
		&state,
		[128, 128, 64],
		"input-output",
	);
	assert_eq!(returned, 0xffffffff);
	assert_eq!(shared, before);
	assert_eq!(state.snapshot_quiescent(), state_before);
	let mut overlap = [0xa5a5a5a5a5a5a5a5u64; 20];
	let mut output = [0xa5; 160];
	let before = output;
	let pointer = overlap.as_mut_ptr().cast::<u8>();
	let returned =
		unsafe { (state.image.entry)(frame.as_ptr().cast(), 128, pointer, 128, pointer, 64) };
	assert_eq!(returned, 0xffffffff);
	assert_eq!(overlap, [0xa5a5a5a5a5a5a5a5u64; 20]);
	let after = unsafe { std::slice::from_raw_parts(pointer, 160) };
	record(
		&frame,
		returned,
		&before,
		after,
		&state,
		[128, 128, 64],
		"output-state",
	);
	overlap[..16].copy_from_slice(&frame);
	let original_overlap = overlap;
	let returned =
		unsafe { (state.image.entry)(pointer, 128, output.as_mut_ptr(), 128, pointer, 64) };
	record(
		&frame,
		returned,
		&before,
		&output,
		&state,
		[128, 128, 64],
		"input-state",
	);
	assert_eq!(returned, 0xffffffff);
	assert_eq!(overlap, original_overlap);
	assert_eq!(output, before);
}

#[test]
fn corrupted_control_words_are_refused_quiescently() {
	for (word, value) in [
		(0, 0),
		(1, 2),
		(1, 2u64 << 32),
		(2, 2),
		(2, 2u64 << 32),
		(3, 1u64 << 32),
		(7, 2),
		(7, 2u64 << 32),
	] {
		let state = State::new();
		unsafe {
			(*state.words.get())[word] = value;
		}
		let before = state.snapshot_quiescent();
		assert_eq!(
			state.invoke(state.frame(7, 0), 128, 128, 64).returned,
			0xfffffff9
		);
		assert_eq!(state.snapshot_quiescent(), before);
	}
}

extern "C" fn observe_signal(_: c_int) {
	SIGNALS.fetch_add(1, Ordering::Relaxed);
}

struct RestoreSignal(usize);

impl Drop for RestoreSignal {
	fn drop(&mut self) {
		assert_ne!(unsafe { signal(10, self.0) }, usize::MAX);
	}
}

#[test]
fn interrupted_kernel_wait_reacquires_custody_without_inventing_timeout() {
	SIGNALS.store(0, Ordering::Relaxed);
	let old = unsafe { signal(10, observe_signal as *const () as usize) };
	assert_ne!(old, usize::MAX);
	let _restore = RestoreSignal(old);
	assert_eq!(unsafe { siginterrupt(10, 1) }, 0);
	let state = State::new();
	let (ready, receive) = std::sync::mpsc::channel();
	let peer = state.clone();
	let worker = std::thread::spawn(move || {
		let guard = peer.lock(0).unwrap();
		let sequence = peer.status().words[5];
		let tid = unsafe { syscall(186) };
		ready.send(tid).unwrap();
		let (guard, errno) = guard.wait(Some(Duration::from_secs(5)), sequence);
		assert_eq!(errno, 4);
		drop(guard.unwrap());
	});
	let tid = receive.recv_timeout(Duration::from_secs(5)).unwrap();
	// Acquiring the queue proves the waiter has released it. Its observed
	// futex wait channel then distinguishes the actual sleeping kernel phase.
	let guard = state.lock(0).unwrap();
	let path = format!("/proc/self/task/{tid}/wchan");
	let deadline = Instant::now() + Duration::from_secs(5);
	loop {
		if std::fs::read_to_string(&path).unwrap().contains("futex") {
			break;
		}
		assert!(
			Instant::now() < deadline,
			"owned waiter never entered the kernel wait"
		);
		std::thread::yield_now();
	}
	assert_eq!(unsafe { syscall(234, std::process::id(), tid, 10) }, 0);
	drop(guard);
	worker.join().unwrap();
	assert_eq!(SIGNALS.load(Ordering::Relaxed), 1);
	observation(
		&state,
		"interrupted-wait",
		&format!("\"worker_tid\":{tid},\"signals\":1,\"signal\":10,\"errno\":4"),
	);
}
