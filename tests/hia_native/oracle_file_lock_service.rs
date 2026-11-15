// Copyright 2026 Muvon Un Limited
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Actual original map/Arc/Tokio operations under an explicit poll schedule.

use std::collections::HashMap;
use std::future::Future;
use std::io::{Read, Write};
use std::os::unix::ffi::OsStringExt;
use std::pin::Pin;
use std::sync::{Arc, Mutex, Weak, mpsc};
use std::task::{Context, Poll, Wake, Waker};
use std::thread;
use tokio::sync::{Mutex as AsyncMutex, MutexGuard};

#[allow(dead_code)]
mod original {
	use anyhow::Result;
	use std::collections::HashMap;
	use std::path::{Path, PathBuf};
	use std::sync::{Arc, Mutex, OnceLock};
	use tokio::sync::Mutex as AsyncMutex;
	include!(concat!(env!("OUT_DIR"), "/path_source_original.rs"));
	include!(concat!(env!("OUT_DIR"), "/path_key_original.rs"));
	include!(concat!(env!("OUT_DIR"), "/file_lock_original.rs"));
	pub fn map_len() -> usize {
		get_file_locks().lock().unwrap().len()
	}
	pub fn fixture_clear() {
		let mut locks = get_file_locks().lock().unwrap();
		assert!(locks.values().all(|value| Arc::strong_count(value) == 1));
		locks.clear();
	}
}

struct Notified {
	lease: u64,
	events: Arc<Mutex<Vec<u64>>>,
}
impl Wake for Notified {
	fn wake(self: Arc<Self>) {
		self.wake_by_ref();
	}
	fn wake_by_ref(self: &Arc<Self>) {
		self.events.lock().unwrap().push(self.lease);
	}
}

enum Command {
	Poll,
	Cancel,
	Unlock,
	Clone,
	Drop,
}
enum Answer {
	Polled(bool),
	Done,
	Cloned(Arc<AsyncMutex<()>>),
}

struct Worker {
	commands: mpsc::SyncSender<Command>,
	answers: mpsc::Receiver<Answer>,
	thread: thread::JoinHandle<()>,
}
impl Worker {
	fn start(lease: u64, value: Arc<AsyncMutex<()>>, events: Arc<Mutex<Vec<u64>>>) -> Self {
		let (commands, incoming) = mpsc::sync_channel(0);
		let (outgoing, answers) = mpsc::sync_channel(0);
		let thread = thread::Builder::new()
			.name(format!("lock-{lease}"))
			.stack_size(128 << 10)
			.spawn(move || {
				let waker = Waker::from(Arc::new(Notified { lease, events }));
				let mut context = Context::from_waker(&waker);
				let mut future: Option<Pin<Box<dyn Future<Output = MutexGuard<'_, ()>>>>> = None;
				let mut guard: Option<MutexGuard<'_, ()>> = None;
				while let Ok(command) = incoming.recv() {
					match command {
						Command::Poll => {
							assert!(guard.is_none());
							if future.is_none() {
								future = Some(Box::pin(value.lock()));
							}
							match future.as_mut().unwrap().as_mut().poll(&mut context) {
								Poll::Ready(acquired) => {
									guard = Some(acquired);
									future = None;
									outgoing.send(Answer::Polled(true)).unwrap();
								}
								Poll::Pending => outgoing.send(Answer::Polled(false)).unwrap(),
							}
						}
						Command::Cancel => {
							assert!(guard.is_none());
							if future.take().is_none() {
								drop(value.lock());
							}
							outgoing.send(Answer::Done).unwrap();
						}
						Command::Unlock => {
							assert!(guard.is_some());
							drop(guard.take());
							outgoing.send(Answer::Done).unwrap();
						}
						Command::Clone => outgoing.send(Answer::Cloned(value.clone())).unwrap(),
						Command::Drop => break,
					}
				}
				drop(future);
				drop(guard);
				drop(value);
			})
			.unwrap();
		Self {
			commands,
			answers,
			thread,
		}
	}
	fn ask(&self, command: Command) -> Answer {
		self.commands.send(command).unwrap();
		self.answers.recv().unwrap()
	}
	fn close(self) {
		self.commands.send(Command::Drop).unwrap();
		self.thread.join().unwrap();
	}
}

enum Storage {
	Idle(Arc<AsyncMutex<()>>),
	Active(Worker),
}
struct Lease {
	node: u64,
	storage: Option<Storage>,
}

struct State {
	leases: HashMap<u64, Lease>,
	nodes: Vec<Weak<AsyncMutex<()>>>,
	identities: HashMap<usize, u64>,
	next_lease: u64,
	events: Arc<Mutex<Vec<u64>>>,
}
impl State {
	fn new() -> Self {
		original::fixture_clear();
		Self {
			leases: HashMap::new(),
			nodes: Vec::new(),
			identities: HashMap::new(),
			next_lease: 1,
			events: Arc::new(Mutex::new(Vec::new())),
		}
	}
	fn insert(&mut self, value: Arc<AsyncMutex<()>>) -> u64 {
		let pointer = Arc::as_ptr(&value) as usize;
		let node = if let Some(node) = self.identities.get(&pointer) {
			*node
		} else {
			let node = self.nodes.len() as u64 + 1;
			self.nodes.push(Arc::downgrade(&value));
			self.identities.insert(pointer, node);
			node
		};
		let lease = self.next_lease;
		self.next_lease += 1;
		assert!(
			self.leases
				.insert(
					lease,
					Lease {
						node,
						storage: Some(Storage::Idle(value))
					}
				)
				.is_none()
		);
		lease
	}
	fn apply(
		&mut self,
		op: u64,
		mut lease_id: u64,
		source: Option<original::PathSource>,
	) -> [u64; 7] {
		assert!(self.events.lock().unwrap().is_empty());
		if op == 0 {
			return [0; 7];
		}
		if op == 7 {
			return [
				7,
				0,
				0,
				0,
				original::map_len() as u64,
				self.leases.len() as u64,
				0,
			];
		}
		if op == 9 {
			assert!(self.leases.is_empty());
			original::fixture_clear();
			return [9, 0, 0, 0, 0, 0, 0];
		}
		let mut status = 0;
		if op == 1 {
			let source = source.unwrap();
			let value = {
				let mut future = Box::pin(original::acquire_file_lock(&source));
				match future
					.as_mut()
					.poll(&mut Context::from_waker(Waker::noop()))
				{
					Poll::Ready(value) => value.unwrap(),
					Poll::Pending => panic!("synchronous original map admission yielded"),
				}
			};
			lease_id = self.insert(value);
		} else if op == 2 {
			let value = match self.leases[&lease_id].storage.as_ref().unwrap() {
				Storage::Idle(value) => value.clone(),
				Storage::Active(worker) => match worker.ask(Command::Clone) {
					Answer::Cloned(value) => value,
					_ => panic!("clone reply differs"),
				},
			};
			lease_id = self.insert(value);
		}
		let node = self.leases[&lease_id].node;
		if op == 3 {
			let lease = self.leases.get_mut(&lease_id).unwrap();
			if matches!(lease.storage, Some(Storage::Idle(_))) {
				let Some(Storage::Idle(value)) = lease.storage.take() else {
					unreachable!()
				};
				lease.storage = Some(Storage::Active(Worker::start(
					lease_id,
					value,
					self.events.clone(),
				)));
			}
			let Some(Storage::Active(worker)) = lease.storage.as_ref() else {
				unreachable!()
			};
			let Answer::Polled(ready) = worker.ask(Command::Poll) else {
				panic!("poll reply differs")
			};
			status = u64::from(!ready);
		} else if op == 4 || op == 5 {
			match self.leases[&lease_id].storage.as_ref().unwrap() {
				Storage::Idle(value) => {
					assert_eq!(op, 4);
					drop(value.lock());
				}
				Storage::Active(worker) => {
					let answer = worker.ask(if op == 4 {
						Command::Cancel
					} else {
						Command::Unlock
					});
					assert!(matches!(answer, Answer::Done));
				}
			}
		} else if op == 6 {
			let lease = self.leases.remove(&lease_id).unwrap();
			match lease.storage.unwrap() {
				Storage::Idle(value) => drop(value),
				Storage::Active(worker) => worker.close(),
			}
		} else {
			assert!(op == 1 || op == 2);
		}
		let mut events = self.events.lock().unwrap();
		assert!(
			events.len() <= 1,
			"unexpected original wake batch: {events:?}"
		);
		let woken = events.pop().unwrap_or(0);
		[
			op,
			status,
			lease_id,
			node,
			original::map_len() as u64,
			self.nodes[(node - 1) as usize].strong_count() as u64,
			woken,
		]
	}
}

fn word(raw: &[u8], offset: usize) -> u64 {
	u64::from_le_bytes(raw[offset..offset + 8].try_into().unwrap())
}

fn source_from(frame: &[u8]) -> original::PathSource {
	let kind = word(frame, 24);
	let path_len = usize::try_from(word(frame, 32)).unwrap();
	let host_len = usize::try_from(word(frame, 40)).unwrap();
	let port = word(frame, 48);
	assert_eq!(frame.len(), 64 + path_len + host_len);
	let path = frame[64..64 + path_len].to_vec();
	if kind == 1 {
		assert_eq!((host_len, port), (0, 0));
		original::PathSource::Local(std::ffi::OsString::from_vec(path).into())
	} else {
		assert_eq!(kind, 2);
		original::PathSource::Remote {
			user: String::new(),
			host: String::from_utf8(frame[64 + path_len..].to_vec()).unwrap(),
			port: u16::try_from(port).unwrap(),
			path: String::from_utf8(path).unwrap(),
			user_explicit: false,
			port_explicit: false,
		}
	}
}

fn acquire(source: original::PathSource) -> Arc<AsyncMutex<()>> {
	let mut future = Box::pin(original::acquire_file_lock(&source));
	match future
		.as_mut()
		.poll(&mut Context::from_waker(Waker::noop()))
	{
		Poll::Ready(value) => value.unwrap(),
		Poll::Pending => panic!("original synchronous admission yielded"),
	}
}

fn main() {
	if std::env::args().nth(1).as_deref() == Some("--concurrent") {
		concurrent();
		return;
	}
	let kernel_stream = std::env::args().nth(1).as_deref() == Some("--kernel-stream");
	assert_eq!(std::env::args().count(), if kernel_stream { 2 } else { 1 });
	let mut input = std::io::BufReader::new(std::io::stdin().lock());
	let mut output = std::io::BufWriter::new(std::io::stdout().lock());
	let mut state = State::new();
	let mut counts = [0_u64; 8];
	let mut rows = 0;
	loop {
		let mut header = [0_u8; 16];
		if input.read(&mut header[..1]).unwrap() == 0 {
			break;
		}
		input.read_exact(&mut header[1..]).unwrap();
		let length = usize::try_from(word(&header, 0)).unwrap();
		let tag = word(&header, 8);
		assert!((64..=(128 << 20)).contains(&length));
		let mut frame = vec![0; length];
		input.read_exact(&mut frame).unwrap();
		assert_eq!(&frame[..8], b"HRLKSRV1");
		let op = word(&frame, 8);
		let ident = word(&frame, 16);
		assert!((1..=7).contains(&op));
		assert_eq!(word(&frame, 56), 0);
		let source = if op == 1 {
			assert_eq!(ident, 0);
			Some(source_from(&frame))
		} else {
			assert_eq!(length, 64);
			assert_eq!(&frame[24..64], &[0; 40]);
			None
		};
		let values = state.apply(op, ident, source);
		output.write_all(&tag.to_le_bytes()).unwrap();
		output.write_all(&64_u32.to_le_bytes()).unwrap();
		output.write_all(b"HRFLKR01").unwrap();
		for value in values {
			output.write_all(&value.to_le_bytes()).unwrap();
		}
		if kernel_stream {
			output.flush().unwrap();
		}
		counts[op as usize] += 1;
		rows += 1;
	}
	assert!(state.leases.is_empty());
	output.flush().unwrap();
	eprintln!(
		"{{\"status\":\"PASS\",\"rows\":{rows},\"original_owner_operations\":{rows},\"operation_counts\":{:?},\"borrowed_guards\":true,\"extra_strong_observer_refs\":0}}",
		counts
	);
}

fn concurrent() {
	use std::sync::Barrier;
	use std::sync::atomic::{AtomicUsize, Ordering};
	original::fixture_clear();
	let mut calls = [0_u64; 8];
	let aliases = [
		"file".to_owned(),
		"./file".to_owned(),
		"alias".to_owned(),
		std::env::current_dir()
			.unwrap()
			.join("file")
			.to_str()
			.unwrap()
			.to_owned(),
	];
	for _ in 0..128 {
		let ready = Arc::new(Barrier::new(4));
		let threads: Vec<_> = aliases
			.iter()
			.map(|path| {
				let ready = ready.clone();
				let source = original::PathSource::Local(path.into());
				thread::spawn(move || {
					ready.wait();
					acquire(source)
				})
			})
			.collect();
		let values: Vec<_> = threads
			.into_iter()
			.map(|thread| thread.join().unwrap())
			.collect();
		assert!(values.iter().all(|value| Arc::ptr_eq(&values[0], value)));
		assert!(values.iter().all(|value| Arc::strong_count(value) == 5));
		calls[1] += 4;
		let barrier = Arc::new(Barrier::new(4));
		let held = Arc::new(AtomicUsize::new(0));
		let active = Arc::new(AtomicUsize::new(0));
		let threads: Vec<_> = values
			.into_iter()
			.map(|value| {
				let barrier = barrier.clone();
				let held = held.clone();
				let active = active.clone();
				thread::spawn(move || {
					let mut future = Some(Box::pin(value.lock()));
					barrier.wait();
					let guard = match future
						.as_mut()
						.unwrap()
						.as_mut()
						.poll(&mut Context::from_waker(Waker::noop()))
					{
						Poll::Ready(guard) => {
							held.fetch_add(1, Ordering::SeqCst);
							assert_eq!(active.fetch_add(1, Ordering::SeqCst), 0);
							Some(guard)
						}
						Poll::Pending => None,
					};
					barrier.wait();
					assert_eq!(held.load(Ordering::SeqCst), 1);
					drop(future.take());
					barrier.wait();
					if guard.is_some() {
						assert_eq!(active.fetch_sub(1, Ordering::SeqCst), 1);
					}
					drop(guard);
				})
			})
			.collect();
		for thread in threads {
			thread.join().unwrap();
		}
		assert_eq!(held.load(Ordering::SeqCst), 1);
		assert_eq!(active.load(Ordering::SeqCst), 0);
		calls[3] += 4;
		calls[4] += 3;
		calls[5] += 1;
		calls[6] += 4;
	}
	let mut values = Vec::new();
	for group in 0..520 {
		let barrier = Arc::new(Barrier::new(4));
		let threads: Vec<_> = (0..4)
			.map(|index| {
				let barrier = barrier.clone();
				thread::spawn(move || {
					barrier.wait();
					acquire(original::PathSource::Local(
						format!("growth-{group}-{index}").into(),
					))
				})
			})
			.collect();
		values.extend(threads.into_iter().map(|thread| thread.join().unwrap()));
		calls[1] += 4;
	}
	assert_eq!(values.len(), 2080);
	assert!(original::map_len() >= 2080);
	assert!(values.iter().all(|value| Arc::strong_count(value) == 2));
	calls[7] += 1;
	while !values.is_empty() {
		let barrier = Arc::new(Barrier::new(4));
		let mut threads = Vec::new();
		for _ in 0..4 {
			let value = values.pop().unwrap();
			let barrier = barrier.clone();
			threads.push(thread::spawn(move || {
				barrier.wait();
				drop(value);
			}));
		}
		for thread in threads {
			thread.join().unwrap();
		}
		calls[6] += 4;
	}
	assert!(original::map_len() >= 2080);
	calls[7] += 1;
	original::fixture_clear();
	assert_eq!(calls.iter().sum::<u64>(), 6210);
	println!(
		"{{\"status\":\"PASS\",\"original_owner_operations\":6210,\"mutual_exclusion_rounds\":128,\"retained_growth_leases\":2080,\"operation_counts\":{:?},\"actual_std_threads\":5184}}",
		calls
	);
}
