// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Test-only mechanical pump for frozen HIA decisions and native kernel effects.

use std::cell::UnsafeCell;
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
	controller: Image,
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

struct Core {
	images: Arc<Images>,
	kernel: UnsafeCell<[u64; 10]>,
	queue: UnsafeCell<Vec<u8>>,
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
		let mut queue = vec![0; 144];
		queue[128..].fill(0xa5);
		let core = Arc::new(Self {
			images: IMAGES
				.get_or_init(|| {
					Arc::new(Images {
						controller: Image::load("HIA_AUDIT_CONTROLLER_IMAGE"),
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
			queue: UnsafeCell::new(queue),
			generation: CONTEXTS.fetch_add(1, Ordering::Relaxed),
			case: std::thread::current().name().unwrap().to_owned(),
		});
		core.boundary(core.kernel_frame(0, 0), 0, 0);
		let mut actor = Actor::new();
		let frame = core.frame(0, None);
		core.step(frame, &mut actor, true, true);
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

	fn step(&self, mut frame: [u64; 32], actor: &mut Actor, queue_owned: bool, initial: bool) {
		let before_input = frame;
		let before_output = actor.bytes;
		let mut dummy = [0xa5; 16];
		let (pointer, capacity, before_queue) = if queue_owned {
			let queue = unsafe { &mut *self.queue.get() };
			(queue.as_mut_ptr(), queue.len() - 16, queue.clone())
		} else {
			(dummy.as_mut_ptr(), 0, dummy.to_vec())
		};
		let returned = unsafe {
			(self.images.controller.entry)(
				frame.as_mut_ptr().cast(),
				256,
				actor.bytes.as_mut_ptr(),
				512,
				pointer,
				capacity,
			)
		};
		assert_eq!(frame, before_input);
		let after_queue = if queue_owned {
			unsafe { (&*self.queue.get()).clone() }
		} else {
			dummy.to_vec()
		};
		record(&self.case, self.generation, "controller", &format!(
			"\"actor\":{},\"returned\":{returned},\"queue_owned\":{queue_owned},\"initial\":{initial},\"queue_capacity\":{capacity},\"input_hex\":\"{}\",\"output_before_hex\":\"{}\",\"output_after_hex\":\"{}\",\"queue_before_hex\":\"{}\",\"queue_after_hex\":\"{}\"",
			actor.id, hex(&byte_words(&frame)), hex(&before_output), hex(&actor.bytes),
			hex(&before_queue), hex(&after_queue)));
		assert_eq!(returned, 512);
		assert_eq!(&actor.bytes[512..], &[0xa5; 16]);
		assert_eq!(&after_queue[capacity..], &[0xa5; 16]);
		assert_eq!(actor.word(0), u64::from_le_bytes(*b"HAUCOR01"));
		assert!(actor.word(1) <= 2);
		if !queue_owned {
			assert_eq!(dummy, [0xa5; 16]);
		}
	}

	fn pump(&self, actor: &mut Actor, command: u64, deadline: Option<Instant>) -> u64 {
		self.step(self.frame(command, deadline), actor, false, false);
		let mut queue_owned = false;
		loop {
			match actor.word(1) {
				0 => return actor.word(2),
				1 => {
					let serial = actor.word(3);
					let effect = std::array::from_fn(|index| word(&actor.bytes[256..384], index));
					let response = self.boundary(effect, actor.id, serial);
					queue_owned = response[11] == tid() && response[13] == 1;
					let mut frame = [0; 32];
					frame[0] = u64::from_le_bytes(*b"HAUCTL01");
					frame[1] = 3;
					frame[2] = serial;
					frame[3] = 128;
					frame[16..].copy_from_slice(&response);
					self.step(frame, actor, queue_owned, false);
				}
				2 => {
					assert!(queue_owned);
					assert_eq!(actor.word(11), 1);
					let serial = actor.word(3);
					let required: usize = actor.word(24).try_into().unwrap();
					let queue = unsafe { &mut *self.queue.get() };
					let before = queue.clone();
					let old_capacity = queue.len() - 16;
					assert!(required > old_capacity);
					queue.resize(required.checked_add(16).unwrap(), 0);
					queue[old_capacity..required].fill(0);
					queue[required..].fill(0xa5);
					assert_eq!(&queue[..old_capacity], &before[..old_capacity]);
					record(&self.case, self.generation, "growth", &format!(
						"\"actor\":{},\"serial\":{serial},\"old_capacity\":{old_capacity},\"required\":{required},\"before_hex\":\"{}\",\"after_hex\":\"{}\"",
						actor.id, hex(&before), hex(queue)));
					let mut frame = [0; 32];
					frame[0] = u64::from_le_bytes(*b"HAUCTL01");
					frame[1] = 3;
					frame[2] = serial;
					self.step(frame, actor, true, false);
				}
				other => panic!("unknown HIA continuation status {other}"),
			}
		}
	}
}

impl Drop for Core {
	fn drop(&mut self) {
		let status = self.boundary(self.kernel_frame(7, 0), 0, 0);
		assert_eq!((status[13], status[14]), (0, 0));
		let kernel = unsafe { *self.kernel.get() };
		assert_eq!(&kernel[8..], &[0xa5a5a5a5a5a5a5a5; 2]);
		let queue = unsafe { &*self.queue.get() };
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
			let queue = unsafe { &*self.core.queue.get() };
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
