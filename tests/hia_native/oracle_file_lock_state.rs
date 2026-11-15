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
	fn apply(&mut self, op: u64, mut lease_id: u64, key: Vec<u8>) -> [u64; 7] {
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
			let source =
				original::PathSource::Local(std::ffi::OsString::from_vec(key.clone()).into());
			assert_eq!(original::lock_key_for_source(&source).as_bytes(), key);
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

fn main() {
	let mut input = std::io::BufReader::new(std::io::stdin().lock());
	let mut output = std::io::BufWriter::new(std::io::stdout().lock());
	let mut current = 0;
	let mut state: Option<State> = None;
	let mut counts = [0_u64; 10];
	let mut rows = 0;
	loop {
		let mut header = [0_u8; 16];
		let got = input.read(&mut header[..1]).unwrap();
		if got == 0 {
			break;
		}
		input.read_exact(&mut header[1..]).unwrap();
		let session = word(&header, 0);
		let length = usize::try_from(word(&header, 8)).unwrap();
		assert!((64..=(128 << 20)).contains(&length));
		let mut frame = vec![0; length];
		input.read_exact(&mut frame).unwrap();
		assert_eq!(&frame[..8], b"HRFLOCK1");
		let op = word(&frame, 8);
		let ident = word(&frame, 16);
		assert_eq!(word(&frame, 24) as usize, length - 64);
		assert_eq!(&frame[32..64], &[0; 32]);
		assert!(op <= 9 && op != 8);
		if op == 0 {
			assert!(session > current);
			assert!(state.as_ref().is_none_or(|value| value.leases.is_empty()));
			state = Some(State::new());
			current = session;
		}
		assert_eq!(session, current);
		let values = state
			.as_mut()
			.unwrap()
			.apply(op, ident, frame[64..].to_vec());
		output.write_all(b"HRFLKR01").unwrap();
		for value in values {
			output.write_all(&value.to_le_bytes()).unwrap();
		}
		counts[op as usize] += 1;
		rows += 1;
	}
	assert!(state.as_ref().is_none_or(|value| value.leases.is_empty()));
	output.flush().unwrap();
	eprintln!(
		"{{\"status\":\"PASS\",\"rows\":{rows},\"lifecycle_rows\":{},\"original_owner_rows\":{},\"operation_counts\":{:?},\"borrowed_guards\":true,\"extra_strong_observer_refs\":0}}",
		counts[0] + counts[9],
		rows - counts[0] - counts[9],
		counts
	);
}
