// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
// Test adapter only: every registry decision runs in the emitted HIA owner.
use std::cell::{Cell, RefCell, UnsafeCell};
use std::ffi::c_void;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::marker::PhantomData;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::Instant;

type Result<T> = std::result::Result<T, String>;
type Entry = unsafe extern "C" fn(*const u8, usize, *mut u8, usize, *mut u8, usize) -> u32;
extern "C" {
	fn mmap(address: *mut c_void, length: usize, protection: i32, flags: i32, fd: i32, offset: i64) -> *mut c_void;
	fn mprotect(address: *mut c_void, length: usize, protection: i32) -> i32;
	fn munmap(address: *mut c_void, length: usize) -> i32;
	fn syscall(number: i64, ...) -> i64;
}

struct Image {
	address: *mut c_void,
	length: usize,
	entry: Entry,
}
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
			Self { address, length, entry: std::mem::transmute::<*mut c_void, Entry>(address) }
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
	refs: Image,
	sync: Image,
}
static IMAGES: OnceLock<Images> = OnceLock::new();
static CORE: OnceLock<Box<Core>> = OnceLock::new();
static JOURNAL: OnceLock<Mutex<File>> = OnceLock::new();
static INDICES: AtomicU64 = AtomicU64::new(0);
static ACTORS: AtomicU64 = AtomicU64::new(1);
static CALLS: AtomicU64 = AtomicU64::new(1);

fn images() -> &'static Images {
	IMAGES.get_or_init(|| Images {
		callable: Image::load("HIA_LIFETIME_CALLABLE"),
		refs: Image::load("HIA_LIFETIME_REFS"),
		sync: Image::load("HIA_LIFETIME_SYNC"),
	})
}
fn tid() -> u64 {
	let value = unsafe { syscall(186) };
	assert!(value > 0);
	value as u64
}
fn hex(raw: &[u8]) -> String {
	const DIGITS: &[u8; 16] = b"0123456789abcdef";
	let mut text = String::with_capacity(raw.len() * 2);
	for byte in raw {
		text.push(DIGITS[(byte >> 4) as usize] as char);
		text.push(DIGITS[(byte & 15) as usize] as char);
	}
	text
}
fn word(raw: &[u8], index: usize) -> u64 {
	u64::from_le_bytes(raw[index * 8..index * 8 + 8].try_into().unwrap())
}
fn bytes<const N: usize>(words: &[u64; N]) -> Vec<u8> {
	words.iter().flat_map(|word| word.to_le_bytes()).collect()
}
fn copied(pointer: u64, length: usize) -> Vec<u8> {
	if length == 0 {
		Vec::new()
	} else {
		assert_ne!(pointer, 0);
		unsafe { std::slice::from_raw_parts(pointer as *const u8, length) }.to_vec()
	}
}
fn record(kind: &str, fields: &str) {
	let journal = JOURNAL.get_or_init(|| {
		Mutex::new(OpenOptions::new().write(true).create_new(true)
			.open(std::env::var("HIA_LIFETIME_JOURNAL").unwrap()).unwrap())
	});
	let mut file = journal.lock().unwrap();
	let index = INDICES.fetch_add(1, Ordering::Relaxed);
	writeln!(file, "{{\"record\":\"{kind}\",\"index\":{index},\"pid\":{},\"tid\":{},{fields}}}",
		std::process::id(), tid()).unwrap();
}

struct Observation {
	event: [u64; 16],
	input: Vec<u8>,
	output: Vec<u8>,
	map: Vec<u8>,
	started: Instant,
}
thread_local! {
	static CURRENT_ACTOR: Cell<u64> = const { Cell::new(0) };
	static CURRENT_CALL: Cell<u64> = const { Cell::new(0) };
	static PENDING: RefCell<Option<Observation>> = const { RefCell::new(None) };
}

// Optional observation is restricted to copying buffers already chosen by
// the native pump. It performs no registry, ownership, or effect decisions.
extern "C" fn observe(pointer: *const u64, user: *const Core) {
	let event: [u64; 16] = unsafe { std::slice::from_raw_parts(pointer, 16) }.try_into().unwrap();
	let core = unsafe { &*user };
	assert_eq!(event[13], core.context.get() as u64);
	assert!((1..=4).contains(&event[0]) && event[1] <= 1);
	let actor = CURRENT_ACTOR.with(Cell::get);
	let call = CURRENT_CALL.with(Cell::get);
	assert!(actor > 0 && call > 0);
	let capacity: usize = event[7].try_into().unwrap();
	let input = copied(event[3], event[4].try_into().unwrap());
	let output = copied(event[5], match event[0] { 1 | 4 => 528, 2 => 144, 3 => 80, _ => unreachable!() });
	let map = if event[0] == 1 || event[0] == 4 {
		copied(event[6], capacity + 16)
	} else {
		Vec::new()
	};
	if event[1] == 0 {
		let before = Observation { event, input, output, map, started: Instant::now() };
		PENDING.with(|pending| assert!(pending.replace(Some(before)).is_none()));
		return;
	}
	let before = PENDING.with(|pending| pending.take().unwrap());
	assert_eq!(before.event[0], event[0]);
	assert_eq!(before.input, input);
	assert_eq!(&output[output.len() - 16..], &[0xa5; 16]);
	if event[0] == 1 || event[0] == 4 {
		if event[8] == 1 {
			assert_eq!(&map[capacity..], &[0xa5; 16]);
		} else {
			assert_eq!(capacity, 0);
			assert_eq!(map, vec![0; 16]);
		}
	}
	let elapsed = before.started.elapsed().as_nanos();
	record("effect", &format!(
		"\"actor\":{actor},\"call\":{call},\"elapsed_ns\":{elapsed},\"event_before_hex\":\"{}\",\"event_after_hex\":\"{}\",\"input_hex\":\"{}\",\"output_before_hex\":\"{}\",\"output_after_hex\":\"{}\",\"map_before_hex\":\"{}\",\"map_after_hex\":\"{}\"",
		hex(&bytes(&before.event)), hex(&bytes(&event)), hex(&input), hex(&before.output), hex(&output), hex(&before.map), hex(&map)));
}

struct Core {
	kernel: UnsafeCell<[u64; 10]>,
	context: UnsafeCell<[u64; 18]>,
}
// All mutable maps are accessed under their actual native mutex, or while
// unpublished/quiescent. The test adapter never implements map policy.
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
		Self { bytes, id: ACTORS.fetch_add(1, Ordering::Relaxed), not_send: PhantomData }
	}
}

impl Core {
	fn new() -> Box<Self> {
		let core = Box::new(Self { kernel: UnsafeCell::new([0; 10]), context: UnsafeCell::new([0; 18]) });
		unsafe {
			(*core.kernel.get())[8..].fill(0xa5a5a5a5a5a5a5a5);
			let context = &mut *core.context.get();
			context[2] = core.kernel.get() as u64;
			context[3] = 64;
			context[10] = observe as *const () as u64;
			context[11] = &*core as *const Core as u64;
			context[16..].fill(0xa5a5a5a5a5a5a5a5);
		}
		assert_eq!(core.pump(&mut Actor::new(), 0, "", 0), 0);
		core.quiescent("initialized");
		core
	}
	fn pump(&self, actor: &mut Actor, operation: u64, key: &str, pointer: u64) -> u64 {
		let mut words = [0; 8];
		words[0] = u64::from_le_bytes(*b"HARGQ001");
		words[1] = operation;
		words[2] = 1;
		words[3] = pointer;
		words[4] = key.len() as u64;
		words[5] = u64::from(std::thread::panicking());
		if operation == 0 { words[5] = 0; }
		let mut input = bytes(&words);
		input.extend_from_slice(key.as_bytes());
		input.extend_from_slice(&[0; 128]);
		let length = input.len();
		input.extend_from_slice(&[0xa5; 16]);
		let before = input.clone();
		let call = CALLS.fetch_add(1, Ordering::Relaxed);
		let id = actor.id;
		record("public-start", &format!("\"actor\":{id},\"call\":{call},\"input_hex\":\"{}\",\"actor_hex\":\"{}\"", hex(&input), hex(&actor.bytes)));
		CURRENT_ACTOR.with(|current| assert_eq!(current.replace(id), 0));
		CURRENT_CALL.with(|current| assert_eq!(current.replace(call), 0));
		let started = Instant::now();
		let returned = unsafe { (images().callable.entry)(input.as_ptr(), length, actor.bytes.as_mut_ptr(), 512, self.context.get().cast(), 128) };
		let elapsed = started.elapsed().as_nanos();
		CURRENT_CALL.with(|current| assert_eq!(current.replace(0), call));
		CURRENT_ACTOR.with(|current| assert_eq!(current.replace(0), id));
		PENDING.with(|pending| assert!(pending.borrow().is_none()));
		record("public-end", &format!("\"actor\":{id},\"call\":{call},\"returned\":{returned},\"elapsed_ns\":{elapsed},\"input_hex\":\"{}\",\"actor_hex\":\"{}\"", hex(&input), hex(&actor.bytes)));
		assert_eq!(returned, 512);
		assert_eq!(input, before);
		assert_eq!(&actor.bytes[512..], &[0xa5; 16]);
		assert_eq!(word(&actor.bytes, 1), 0);
		word(&actor.bytes, 2)
	}
	fn boundary(&self, operation: u64, kind: u64) -> [u64; 16] {
		let mut frame = [0; 16];
		frame[0] = u64::from_le_bytes(*b"HASCMD01");
		frame[1] = operation;
		frame[2] = kind;
		frame[3] = 1;
		frame[5] = u64::from(std::thread::panicking());
		let before = frame;
		let mut output = [0xa5; 144];
		let returned = unsafe { (images().sync.entry)(frame.as_ptr().cast(), 128, output.as_mut_ptr(), 128, self.kernel.get().cast(), 64) };
		record("boundary-external", &format!("\"returned\":{returned},\"input_hex\":\"{}\",\"output_before_hex\":\"{}\",\"output_after_hex\":\"{}\"", hex(&bytes(&frame)), hex(&[0xa5; 144]), hex(&output)));
		assert_eq!(frame, before);
		assert_eq!(returned, 128);
		assert_eq!(&output[128..], &[0xa5; 16]);
		let result = std::array::from_fn(|index| word(&output, index));
		assert_eq!(result[0], u64::from_le_bytes(*b"HASYNR01"));
		assert_eq!(result[1], operation);
		assert_eq!(result[3], tid());
		assert!(result[2] <= 1);
		result
	}
	unsafe fn map_owned(&self, kind: usize) -> Vec<u8> {
		let context = &*self.context.get();
		copied(context[4 + kind * 3], context[5 + kind * 3] as usize + 16)
	}
	fn quiescent(&self, phase: &str) {
		let context = unsafe { *self.context.get() };
		let kernel = unsafe { *self.kernel.get() };
		assert_eq!(&context[16..], &[0xa5a5a5a5a5a5a5a5; 2]);
		assert_eq!(&kernel[8..], &[0xa5a5a5a5a5a5a5a5; 2]);
		let active = if context[4] == 0 { Vec::new() } else { unsafe { self.map_owned(0) } };
		let pins = if context[7] == 0 { Vec::new() } else { unsafe { self.map_owned(1) } };
		record("quiescent", &format!("\"phase\":{phase:?},\"context_hex\":\"{}\",\"kernel_hex\":\"{}\",\"active_hex\":\"{}\",\"pins_hex\":\"{}\"", hex(&bytes(&context)), hex(&bytes(&kernel)), hex(&active), hex(&pins)));
	}
}

fn core() -> &'static Core { CORE.get_or_init(Core::new) }

fn reference(operation: u64, kind: u64, pointer: u64) -> [u64; 8] {
	let frame = [u64::from_le_bytes(*b"HARREF01"), operation, kind, pointer, 0, 0, 0, 0];
	let before = frame;
	let mut output = [0xa5; 80];
	let returned = unsafe { (images().refs.entry)(frame.as_ptr().cast(), 64, output.as_mut_ptr(), 64, std::ptr::null_mut(), 0) };
	record("reference-external", &format!("\"returned\":{returned},\"input_hex\":\"{}\",\"output_before_hex\":\"{}\",\"output_after_hex\":\"{}\"", hex(&bytes(&frame)), hex(&[0xa5; 80]), hex(&output)));
	assert_eq!(frame, before);
	assert_eq!(returned, 64);
	assert_eq!(&output[64..], &[0xa5; 16]);
	let result = std::array::from_fn(|index| word(&output, index));
	assert_eq!(result[0], u64::from_le_bytes(*b"HARRES01"));
	assert_eq!(result[1], operation);
	assert_eq!(result[6], kind);
	if operation >= 2 { assert_eq!(result[3], pointer); }
	result
}

struct Strong { pointer: u64, kind: u64 }
impl Strong {
	fn new(kind: u64) -> Self {
		let result = reference(kind - 1, kind, 0);
		assert_eq!(result[2], 1);
		Self { pointer: result[3], kind }
	}
}
impl Clone for Strong {
	fn clone(&self) -> Self {
		assert_eq!(reference(2, self.kind, self.pointer)[2], 1);
		Self { pointer: self.pointer, kind: self.kind }
	}
}
impl Drop for Strong {
	fn drop(&mut self) {
		assert!(matches!(reference(3, self.kind, self.pointer)[2], 0 | 2));
	}
}

#[derive(Clone)]
struct Marker(Strong);
impl Marker {
	fn new() -> Self { Self(Strong::new(1)) }
	fn finish(&self) { assert_eq!(reference(9, 1, self.0.pointer)[7], 0); }
	fn value(&self) -> bool { reference(8, 1, self.0.pointer)[7] != 0 }
	fn downgrade(&self) -> WeakMarker {
		assert_eq!(reference(4, 1, self.0.pointer)[2], 1);
		WeakMarker(self.0.pointer)
	}
}

#[derive(Clone)]
struct Pin(Strong);
impl Pin { fn new() -> Self { Self(Strong::new(2)) } }

struct WeakMarker(u64);
impl WeakMarker {
	fn upgrade(&self) -> Option<Marker> {
		match reference(7, 1, self.0)[2] {
			0 => None,
			1 => Some(Marker(Strong { pointer: self.0, kind: 1 })),
			other => panic!("invalid upgrade result {other}"),
		}
	}
	fn strong_count(&self) -> usize { reference(6, 1, self.0)[4].try_into().unwrap() }
}
impl Clone for WeakMarker {
	fn clone(&self) -> Self {
		assert_eq!(reference(4, 1, self.0)[2], 1);
		Self(self.0)
	}
}
impl Drop for WeakMarker {
	fn drop(&mut self) { assert!(matches!(reference(5, 1, self.0)[2], 0 | 2)); }
}

fn result(value: u64) -> Result<u64> {
	match value {
		0..=2 => Ok(value),
		100 => Err("request audit active registry unavailable".to_owned()),
		101 => Err("request read pin state unavailable".to_owned()),
		other => panic!("invalid registry result {other}"),
	}
}
fn setup() { let _ = core(); }
fn publish_active(key: &str, marker: &Marker) -> Result<()> {
	result(core().pump(&mut Actor::new(), 1, key, marker.0.pointer)).map(|value| assert_eq!(value, 0))
}
fn publish_pin(key: &str, pin: &Pin) -> Result<()> {
	result(core().pump(&mut Actor::new(), 2, key, pin.0.pointer)).map(|value| assert_eq!(value, 0))
}
fn is_dispatch_active(key: &str) -> Result<bool> {
	result(core().pump(&mut Actor::new(), 3, key, 0)).map(|value| {
		assert!(value <= 1);
		value != 0
	})
}
fn is_active(key: &str) -> Result<bool> {
	result(core().pump(&mut Actor::new(), 4, key, 0)).map(|value| {
		assert!(value <= 1);
		value != 0
	})
}

struct ActiveGuard { actor: Actor }
fn held() -> Result<ActiveGuard> {
	let mut actor = Actor::new();
	let value = result(core().pump(&mut actor, 6, "", 0))?;
	assert_eq!(value, 2);
	Ok(ActiveGuard { actor })
}
impl ActiveGuard {
	fn insert(&mut self, key: &str, marker: &Marker) {
		assert_eq!(core().pump(&mut self.actor, 7, key, marker.0.pointer), 2);
	}
}
impl Drop for ActiveGuard {
	fn drop(&mut self) { assert_eq!(core().pump(&mut self.actor, 8, "", 0), 0); }
}

struct PinGuard { not_send: PhantomData<MutexGuard<'static, ()>> }
fn pin_guard() -> PinGuard {
	assert_eq!(core().boundary(1, 1)[2], 0);
	PinGuard { not_send: PhantomData }
}
impl Drop for PinGuard {
	fn drop(&mut self) { assert_eq!(core().boundary(3, 1)[2], 0); }
}

fn sizes() -> (usize, usize, usize) {
	let core = core();
	core.boundary(1, 0);
	core.boundary(1, 1);
	let active = unsafe { core.map_owned(0) };
	let pins = unsafe { core.map_owned(1) };
	let mut keys = std::collections::BTreeSet::new();
	let mut position = 64;
	while position < word(&pins, 5) as usize {
		let length = word(&pins[position..], 0) as usize;
		keys.insert(pins[position + 16..position + 16 + length].to_vec());
		position += (length + 23) & !7;
	}
	assert_eq!(position, word(&pins, 5) as usize);
	let answer = (word(&active, 4) as usize, keys.len(), word(&pins, 4) as usize);
	record("map-probe", &format!("\"active_hex\":\"{}\",\"pins_hex\":\"{}\"", hex(&active), hex(&pins)));
	assert_eq!(core.boundary(3, 1)[2], 0);
	assert_eq!(core.boundary(3, 0)[2], 0);
	answer
}

fn finalize() {
	let core = core();
	core.quiescent("before-disposal");
	assert_eq!(core.pump(&mut Actor::new(), 5, "", 0), 0);
	let context = unsafe { *core.context.get() };
	assert!([0, 1, 4, 5, 6, 7, 8, 9].iter().all(|index| context[*index] == 0));
	assert_eq!(context[2], core.kernel.get() as u64);
	assert_eq!(context[3], 64);
	core.quiescent("disposed");
}

include!("cases.rs");
