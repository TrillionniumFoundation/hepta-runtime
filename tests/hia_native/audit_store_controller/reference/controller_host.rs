// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Test-only actual-thread adapter observing the HIA/native callable composition.

use std::cell::{Cell, RefCell, UnsafeCell};
use std::collections::VecDeque;
use std::ffi::{c_int, c_long, c_void};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::marker::PhantomData;
use std::ops::Deref;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::Instant;

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
}

type Entry = unsafe extern "C" fn(*const u8, usize, *mut u8, usize, *mut u8, usize) -> u32;

struct Image {
	address: *mut c_void,
	length: usize,
	entry: Entry,
}

// The code is made read/execute before publication and is never modified.
unsafe impl Send for Image {}
unsafe impl Sync for Image {}

impl Image {
	fn load(variable: &str) -> Self {
		let raw = std::fs::read(std::env::var(variable).unwrap()).unwrap();
		assert!(!raw.is_empty());
		let length = (raw.len() + 4095) & !4095;
		unsafe {
			let address = mmap(std::ptr::null_mut(), length, 3, 0x22, -1, 0);
			assert_ne!(address as isize, -1);
			std::ptr::copy_nonoverlapping(raw.as_ptr(), address.cast::<u8>(), raw.len());
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

struct Images {
	callable: Image,
	sync: Image,
}

static IMAGES: OnceLock<Arc<Images>> = OnceLock::new();
static JOURNAL: OnceLock<Mutex<File>> = OnceLock::new();
static INDICES: AtomicU64 = AtomicU64::new(0);
static CONTEXTS: AtomicU64 = AtomicU64::new(1);
static ACTORS: AtomicU64 = AtomicU64::new(1);

fn tid() -> u64 {
	let value = unsafe { syscall(186) };
	assert!(value > 0);
	value as u64
}

fn hex(raw: &[u8]) -> String {
	let mut text = String::with_capacity(raw.len() * 2);
	for byte in raw {
		use std::fmt::Write;
		write!(&mut text, "{byte:02x}").unwrap();
	}
	text
}

fn word(raw: &[u8], index: usize) -> u64 {
	u64::from_le_bytes(raw[index * 8..index * 8 + 8].try_into().unwrap())
}

fn byte_words<const N: usize>(value: &[u64; N]) -> Vec<u8> {
	value.iter().flat_map(|word| word.to_le_bytes()).collect()
}

fn record(case: &str, generation: u64, kind: &str, fields: &str) {
	assert!(case
		.bytes()
		.all(|value| value.is_ascii_alphanumeric() || value == b'_' || value == b':'));
	let index = INDICES.fetch_add(1, Ordering::Relaxed);
	let journal = JOURNAL.get_or_init(|| {
		Mutex::new(
			OpenOptions::new()
				.write(true)
				.create_new(true)
				.open(std::env::var("HIA_AUDIT_CONTROLLER_JOURNAL").unwrap())
				.unwrap(),
		)
	});
	writeln!(journal.lock().unwrap(),
		"{{\"record\":\"{kind}\",\"case\":\"{case}\",\"generation\":{generation},\"index\":{index},\"pid\":{},\"tid\":{},{fields}}}",
		std::process::id(), tid()).unwrap();
}

struct Observation {
	kind: u64,
	input: Vec<u8>,
	output: Vec<u8>,
	queue: Vec<u8>,
	capacity: usize,
	owned: bool,
	initial: bool,
	old_capacity: usize,
	required: usize,
	serial: u64,
}

thread_local! {
	static CURRENT_ACTOR: Cell<u64> = const { Cell::new(0) };
	static PENDING: RefCell<Option<Observation>> = const { RefCell::new(None) };
}

fn observed_bytes(pointer: u64, length: usize) -> Vec<u8> {
	assert!(pointer != 0 || length == 0);
	if length == 0 {
		Vec::new()
	} else {
		unsafe { std::slice::from_raw_parts(pointer as *const u8, length) }.to_vec()
	}
}

// This callback copies observations only. The native callable has already
// chosen every operation and owns every buffer passed here.
extern "C" fn observe(pointer: *const u64, user: *const Core) {
	let event = unsafe { std::slice::from_raw_parts(pointer, 16) };
	let core = unsafe { &*user };
	let actor = CURRENT_ACTOR.with(Cell::get);
	assert!(actor > 0);
	assert!((1..=3).contains(&event[0]) && event[1] <= 1);
	let capacity: usize = event[7].try_into().unwrap();
	if event[1] == 0 {
		let input = observed_bytes(event[3], event[4].try_into().unwrap());
		let output = match event[0] {
			1 => observed_bytes(event[5], 528),
			2 => observed_bytes(event[5], 144),
			_ => Vec::new(),
		};
		let queue = if event[0] == 2 {
			Vec::new()
		} else {
			observed_bytes(event[6], capacity + 16)
		};
		let observation = Observation {
			kind: event[0],
			input,
			output,
			queue,
			capacity,
			owned: event[8] != 0,
			initial: event[9] != 0,
			old_capacity: event[10].try_into().unwrap(),
			required: event[11].try_into().unwrap(),
			serial: event[12],
		};
		PENDING.with(|pending| assert!(pending.replace(Some(observation)).is_none()));
		return;
	}
	let before = PENDING.with(|pending| pending.take().unwrap());
	assert_eq!(before.kind, event[0]);
	assert_eq!(
		before.input,
		observed_bytes(event[3], event[4].try_into().unwrap())
	);
	match event[0] {
		1 => {
			let after = observed_bytes(event[5], 528);
			let queue = observed_bytes(event[6], capacity + 16);
			assert_eq!(event[2], 512);
			assert_eq!(&after[512..], &[0xa5; 16]);
			assert_eq!(&queue[capacity..], &[0xa5; 16]);
			assert_eq!(before.capacity, capacity);
			let owned = before.owned;
			let initial = before.initial;
			record(&core.case, core.generation, "controller", &format!(
				"\"actor\":{actor},\"returned\":512,\"queue_owned\":{owned},\"initial\":{initial},\"queue_capacity\":{capacity},\"input_hex\":\"{}\",\"output_before_hex\":\"{}\",\"output_after_hex\":\"{}\",\"queue_before_hex\":\"{}\",\"queue_after_hex\":\"{}\"",
				hex(&before.input), hex(&before.output), hex(&after), hex(&before.queue), hex(&queue)));
		}
		2 => {
			let after = observed_bytes(event[5], 144);
			assert_eq!(event[2], 128);
			assert_eq!(&after[128..], &[0xa5; 16]);
			let owner = if word(&before.input, 1) == 0 {
				0
			} else {
				actor
			};
			let serial = before.serial;
			record(&core.case, core.generation, "boundary", &format!(
				"\"actor\":{owner},\"serial\":{serial},\"returned\":128,\"input_hex\":\"{}\",\"output_before_hex\":\"{}\",\"output_after_hex\":\"{}\"",
				hex(&before.input), hex(&before.output), hex(&after)));
		}
		3 => {
			let after = observed_bytes(event[6], capacity + 16);
			let old_capacity = before.old_capacity;
			let required = before.required;
			assert_eq!(capacity, required);
			assert!(required > old_capacity);
			assert_eq!(&after[..old_capacity], &before.queue[..old_capacity]);
			assert_eq!(
				&after[old_capacity..required],
				vec![0; required - old_capacity]
			);
			assert_eq!(&after[required..], &[0xa5; 16]);
			let serial = word(&observed_bytes(event[5], 512), 3);
			record(&core.case, core.generation, "growth", &format!(
				"\"actor\":{actor},\"serial\":{serial},\"old_capacity\":{old_capacity},\"required\":{required},\"before_hex\":\"{}\",\"after_hex\":\"{}\"",
				hex(&before.queue), hex(&after)));
		}
		_ => unreachable!(),
	}
}

struct Core {
	images: Arc<Images>,
	kernel: UnsafeCell<[u64; 10]>,
	context: UnsafeCell<[u64; 18]>,
	generation: u64,
	case: String,
}

// The kernel state uses the qualified native atomic protocol. Queue accesses
// below occur only before publication, under actual native queue custody, or
// after the final owner disappears. No Rust mutex implements admission policy.
unsafe impl Send for Core {}
unsafe impl Sync for Core {}

struct Actor {
	bytes: [u8; 528],
	id: u64,
	not_send: PhantomData<MutexGuard<'static, ()>>,
}

impl Actor {
	fn new() -> Self {
		let mut bytes = [0; 528];
		bytes[512..].fill(0xa5);
		Self {
			bytes,
			id: ACTORS.fetch_add(1, Ordering::Relaxed),
			not_send: PhantomData,
		}
	}

	fn word(&self, index: usize) -> u64 {
		word(&self.bytes, index)
	}
}

impl Core {
	fn new() -> Arc<Self> {
		let core = Arc::new(Self {
			images: IMAGES
				.get_or_init(|| {
					Arc::new(Images {
						callable: Image::load("HIA_AUDIT_CALLABLE_IMAGE"),
						sync: Image::load("HIA_AUDIT_SYNC_IMAGE"),
					})
				})
				.clone(),
			kernel: UnsafeCell::new([
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
			context: UnsafeCell::new([0; 18]),
			generation: CONTEXTS.fetch_add(1, Ordering::Relaxed),
			case: std::thread::current().name().unwrap().to_owned(),
		});
		unsafe {
			let context = &mut *core.context.get();
			context[2] = core.kernel.get() as u64;
			context[3] = 64;
			context[7] = observe as *const () as u64;
			context[8] = Arc::as_ptr(&core) as u64;
			context[16..].fill(0xa5a5a5a5a5a5a5a5);
		}
		let mut actor = Actor::new();
		assert_eq!(core.pump(&mut actor, 0, None), 0);
		assert_eq!(actor.word(1), 0);
		assert_eq!(actor.word(2), 0);
		core
	}

	fn kernel_frame(&self, operation: u64, kind: u64) -> [u64; 16] {
		let mut frame = [0; 16];
		frame[0] = u64::from_le_bytes(*b"HASCMD01");
		frame[1] = operation;
		frame[2] = kind;
		frame[3] = self.generation;
		if (1..=3).contains(&operation) {
			frame[5] = u64::from(std::thread::panicking());
		}
		frame
	}

	fn boundary(&self, mut frame: [u64; 16], actor: u64, serial: u64) -> [u64; 16] {
		let before_input = frame;
		let before = [0xa5; 144];
		let mut output = before;
		let returned = unsafe {
			(self.images.sync.entry)(
				frame.as_mut_ptr().cast(),
				128,
				output.as_mut_ptr(),
				128,
				self.kernel.get().cast(),
				64,
			)
		};
		assert_eq!(frame, before_input);
		record(&self.case, self.generation, "boundary", &format!(
			"\"actor\":{actor},\"serial\":{serial},\"returned\":{returned},\"input_hex\":\"{}\",\"output_before_hex\":\"{}\",\"output_after_hex\":\"{}\"",
			hex(&byte_words(&frame)), hex(&before), hex(&output)));
		assert_eq!(returned, 128);
		assert_eq!(&output[128..], &[0xa5; 16]);
		let response = std::array::from_fn(|index| word(&output, index));
		assert_eq!(response[0], u64::from_le_bytes(*b"HASYNR01"));
		assert_eq!(response[1], frame[1]);
		assert_eq!(response[3], tid());
		assert_eq!(response[10], self.generation);
		assert!(response[2] <= 2);
		response
	}

	fn frame(&self, command: u64, deadline: Option<Instant>) -> [u64; 32] {
		let mut frame = [0; 32];
		frame[0] = u64::from_le_bytes(*b"HAUCTL01");
		frame[1] = command;
		frame[4] = self.generation;
		if let Some(deadline) = deadline {
			let (debug, value) = exact_deadline(deadline);
			record(
				&self.case,
				self.generation,
				"deadline",
				&format!("\"debug\":{debug:?},\"value\":{value}"),
			);
			frame[5] = 1;
			frame[6] = value as u64;
			frame[7] = (value >> 64) as u64;
		}
		frame[8] = u64::from(std::thread::panicking());
		if command == 0 {
			frame[8] = 0;
		}
		frame
	}

	fn pump(&self, actor: &mut Actor, command: u64, deadline: Option<Instant>) -> u64 {
		let frame = self.frame(command, deadline);
		let before = frame;
		CURRENT_ACTOR.with(|current| {
			assert_eq!(current.replace(actor.id), 0);
		});
		let returned = unsafe {
			(self.images.callable.entry)(
				frame.as_ptr().cast(),
				256,
				actor.bytes.as_mut_ptr(),
				512,
				self.context.get().cast(),
				128,
			)
		};
		CURRENT_ACTOR.with(|current| assert_eq!(current.replace(0), actor.id));
		PENDING.with(|pending| assert!(pending.borrow().is_none()));
		assert_eq!(returned, 512);
		assert_eq!(frame, before);
		assert_eq!(&actor.bytes[512..], &[0xa5; 16]);
		assert_eq!(actor.word(1), 0);
		actor.word(2)
	}

	unsafe fn queue_owned(&self) -> &[u8] {
		let pointer = unsafe { (*self.context.get())[4] } as *const u8;
		let capacity = unsafe { (*self.context.get())[5] } as usize;
		unsafe { std::slice::from_raw_parts(pointer, capacity + 16) }
	}
}

impl Drop for Core {
	fn drop(&mut self) {
		let status = self.boundary(self.kernel_frame(7, 0), 0, 0);
		assert_eq!((status[13], status[14]), (0, 0));
		let kernel = unsafe { *self.kernel.get() };
		assert_eq!(&kernel[8..], &[0xa5a5a5a5a5a5a5a5; 2]);
		let queue = unsafe { self.queue_owned() };
		assert_eq!(word(queue, 2), 0);
		assert_eq!(word(queue, 3), 0);
		assert_eq!(word(queue, 5), 0);
		assert_eq!(word(queue, 6), 128);
		assert_eq!(&queue[queue.len() - 16..], &[0xa5; 16]);
		record(
			&self.case,
			self.generation,
			"quiescent",
			&format!(
				"\"kernel_hex\":\"{}\",\"queue_hex\":\"{}\"",
				hex(&byte_words(&kernel)),
				hex(queue)
			),
		);
		let frame = self.frame(6, None);
		let mut actor = [0u8; 528];
		actor[512..].fill(0xa5);
		let returned = unsafe {
			(self.images.callable.entry)(
				frame.as_ptr().cast(),
				256,
				actor.as_mut_ptr(),
				512,
				self.context.get().cast(),
				128,
			)
		};
		assert_eq!(returned, 0);
		let context = unsafe { *self.context.get() };
		assert_eq!(
			(context[0], context[1], context[4], context[5], context[6]),
			(0, 0, 0, 0, 0)
		);
		assert_eq!(&context[16..], &[0xa5a5a5a5a5a5a5a5; 2]);
		assert_eq!(&actor[512..], &[0xa5; 16]);
	}
}

#[derive(Debug)]
pub struct QueueSnapshot {
	pub next_ticket: u64,
	pub active: bool,
	pub readers: usize,
	pub reader_poisoned: bool,
	pub waiting: VecDeque<(u64, u64)>,
}

pub struct Probe {
	core: Arc<Core>,
	kind: u64,
}

pub struct ProbeGuard<'a> {
	probe: &'a Probe,
	snapshot: QueueSnapshot,
	not_send: PhantomData<MutexGuard<'static, ()>>,
}

impl std::fmt::Debug for ProbeGuard<'_> {
	fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		self.snapshot.fmt(formatter)
	}
}

impl Probe {
	pub fn lock(&self) -> Result<ProbeGuard<'_>, PoisonError<ProbeGuard<'_>>> {
		let response = self
			.core
			.boundary(self.core.kernel_frame(1, self.kind), 0, 0);
		assert!(response[2] <= 1);
		let snapshot = if self.kind == 0 {
			assert_eq!(response[11], tid());
			let queue = unsafe { self.core.queue_owned() };
			let count: usize = word(queue, 5).try_into().unwrap();
			let waiting = (0..count)
				.map(|index| (word(queue, 16 + index * 2), word(queue, 17 + index * 2)))
				.collect();
			let snapshot = QueueSnapshot {
				next_ticket: word(queue, 1),
				active: word(queue, 2) != 0,
				readers: word(queue, 3).try_into().unwrap(),
				reader_poisoned: word(queue, 4) != 0,
				waiting,
			};
			record(
				&self.core.case,
				self.core.generation,
				"queue-probe",
				&format!("\"queue_hex\":\"{}\"", hex(queue)),
			);
			snapshot
		} else {
			QueueSnapshot {
				next_ticket: 0,
				active: false,
				readers: 0,
				reader_poisoned: false,
				waiting: VecDeque::new(),
			}
		};
		let guard = ProbeGuard {
			probe: self,
			snapshot,
			not_send: PhantomData,
		};
		if response[2] == 0 {
			Ok(guard)
		} else {
			Err(PoisonError::new(guard))
		}
	}

	pub fn is_poisoned(&self) -> bool {
		self.core.boundary(self.core.kernel_frame(7, 0), 0, 0)[6 + self.kind as usize] != 0
	}
}

impl Deref for ProbeGuard<'_> {
	type Target = QueueSnapshot;
	fn deref(&self) -> &Self::Target {
		&self.snapshot
	}
}

impl Drop for ProbeGuard<'_> {
	fn drop(&mut self) {
		let response =
			self.probe
				.core
				.boundary(self.probe.core.kernel_frame(3, self.probe.kind), 0, 0);
		assert_eq!(response[2], 0);
	}
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreLockFailure {
	Deadline,
	Unavailable,
}

pub struct AuditStoreLock {
	core: Arc<Core>,
	pub queue: Probe,
	pub inner: Probe,
}

impl Default for AuditStoreLock {
	fn default() -> Self {
		let core = Core::new();
		Self {
			queue: Probe {
				core: core.clone(),
				kind: 0,
			},
			inner: Probe {
				core: core.clone(),
				kind: 1,
			},
			core,
		}
	}
}

pub struct AuditStoreGuard<'a> {
	core: &'a Core,
	actor: Actor,
}

pub struct AuditSharedGuard<'a> {
	core: &'a Core,
	actor: Actor,
}

fn failure(result: u64) -> StoreLockFailure {
	match result {
		5 => StoreLockFailure::Deadline,
		6 => StoreLockFailure::Unavailable,
		other => panic!("unexpected HIA result {other}"),
	}
}

impl AuditStoreLock {
	pub fn acquire(
		&self,
		deadline: Option<Instant>,
	) -> Result<AuditStoreGuard<'_>, StoreLockFailure> {
		let mut actor = Actor::new();
		match self.core.pump(&mut actor, 1, deadline) {
			3 => Ok(AuditStoreGuard {
				core: &self.core,
				actor,
			}),
			result => Err(failure(result)),
		}
	}

	pub fn acquire_shared(
		&self,
		deadline: Instant,
	) -> Result<AuditSharedGuard<'_>, StoreLockFailure> {
		let mut actor = Actor::new();
		match self.core.pump(&mut actor, 2, Some(deadline)) {
			3 => Ok(AuditSharedGuard {
				core: &self.core,
				actor,
			}),
			result => Err(failure(result)),
		}
	}
}

impl AuditSharedGuard<'_> {
	pub fn finish(mut self) -> Result<(), StoreLockFailure> {
		match self.core.pump(&mut self.actor, 4, None) {
			0 => Ok(()),
			result => Err(failure(result)),
		}
	}
}

impl Drop for AuditSharedGuard<'_> {
	fn drop(&mut self) {
		if self.actor.word(13) != 0 {
			assert_eq!(self.core.pump(&mut self.actor, 5, None), 0);
		}
	}
}

impl Drop for AuditStoreGuard<'_> {
	fn drop(&mut self) {
		if self.actor.word(13) != 0 {
			assert_eq!(self.core.pump(&mut self.actor, 5, None), 0);
		}
	}
}

fn exact_deadline(deadline: Instant) -> (String, u128) {
	// This is a pinned Linux/Rust test adapter, not a production Instant ABI.
	// Retain the actual diagnostic representation and validate the conversion
	// against independent CLOCK_MONOTONIC syscalls in the frozen test domain.
	let debug = format!("{deadline:?}");
	let body = debug
		.strip_prefix("Instant { tv_sec: ")
		.unwrap()
		.strip_suffix(" }")
		.unwrap();
	let (seconds, nanos) = body.split_once(", tv_nsec: ").unwrap();
	let seconds: i64 = seconds.parse().unwrap();
	let nanos: u32 = nanos.parse().unwrap();
	assert!(nanos < 1_000_000_000);
	let value = if seconds < 0 {
		0
	} else {
		(seconds as u128) * 1_000_000_000 + u128::from(nanos)
	};
	(debug, value)
}

fn kernel_clock() -> u128 {
	let mut value = [0i64; 2];
	assert_eq!(unsafe { syscall(228, 1, value.as_mut_ptr()) }, 0);
	assert!(value[0] >= 0 && (0..1_000_000_000).contains(&value[1]));
	(value[0] as u128) * 1_000_000_000 + value[1] as u128
}

pub fn clock_mapping_domain() {
	let case = std::thread::current().name().unwrap().to_owned();
	for _ in 0..128 {
		let before = kernel_clock();
		let actual = Instant::now();
		let after = kernel_clock();
		let (debug, value) = exact_deadline(actual);
		assert!(before <= value && value <= after);
		record(
			&case,
			0,
			"clock-mapping",
			&format!("\"debug\":{debug:?},\"value\":{value},\"before\":{before},\"after\":{after}"),
		);
	}
}

pub fn test_observation(kind: &str, fields: &str) {
	let case = std::thread::current().name().unwrap().to_owned();
	record(&case, 0, kind, fields);
}
