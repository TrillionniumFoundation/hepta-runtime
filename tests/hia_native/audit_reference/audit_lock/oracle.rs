// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Real threads and framing around unchanged AuditStoreLock and guard methods.
use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};
include!("original_lock.rs");

fn number(bytes: &[u8], at: usize) -> u64 {
	u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}
fn word(bytes: &mut [u8], at: usize, value: u64) {
	bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}
fn failure(error: StoreLockFailure) -> u64 {
	match error {
		StoreLockFailure::Deadline => 6,
		StoreLockFailure::Unavailable => 7,
	}
}
fn deadline(command: &[u8]) -> Option<Instant> {
	match number(command, 32) {
		0 => {
			assert_eq!(number(command, 40), 0);
			None
		}
		1 => {
			let nanos = number(command, 40);
			assert!(nanos <= 3_600_000_000_000);
			Some(Instant::now() + Duration::from_nanos(nanos))
		}
		2 => Some(Instant::now()),
		_ => panic!("qualification deadline mode"),
	}
}
fn worker(
	actor: usize,
	lock: Arc<AuditStoreLock>,
	input: mpsc::Receiver<[u8; 64]>,
	output: Arc<Mutex<io::BufWriter<io::Stdout>>>,
) -> io::Result<()> {
	let mut exclusive: Option<AuditStoreGuard<'_>> = None;
	let mut shared: Option<AuditSharedGuard<'_>> = None;
	let mut raw: Option<std::sync::MutexGuard<'_, ()>> = None;
	let mut queue: Option<std::sync::MutexGuard<'_, AuditStoreQueue>> = None;
	while let Ok(command) = input.recv() {
		assert_eq!(&command[..8], b"HRALC001");
		assert_eq!(number(&command, 16), actor as u64);
		assert_eq!(number(&command, 48), 0);
		assert_eq!(number(&command, 56), 0);
		let operation = number(&command, 24);
		let mut reply = [0; 80];
		reply[..8].copy_from_slice(b"HRALO001");
		word(&mut reply, 8, number(&command, 8));
		word(&mut reply, 16, actor as u64);
		word(&mut reply, 24, operation);
		let status = match operation {
			1 => {
				assert!(exclusive.is_none() && shared.is_none());
				match lock.acquire(deadline(&command)) {
					Ok(guard) => {
						exclusive = Some(guard);
						5
					}
					Err(error) => failure(error),
				}
			}
			2 => {
				assert!(exclusive.is_none() && shared.is_none());
				match lock.acquire_shared(deadline(&command).unwrap()) {
					Ok(guard) => {
						shared = Some(guard);
						5
					}
					Err(error) => failure(error),
				}
			}
			3 => match shared.take().unwrap().finish() {
				Ok(()) => 0,
				Err(error) => failure(error),
			},
			4 => {
				assert!(exclusive.is_some() || shared.is_some());
				drop(exclusive.take());
				drop(shared.take());
				0
			}
			5 => {
				assert!(exclusive.is_some() || shared.is_some());
				let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
					let _exclusive = exclusive.take();
					let _shared = shared.take();
					panic!("owned guard unwind");
				}));
				assert!(result.is_err());
				0
			}
			6 => {
				let current = lock.queue.lock().unwrap_or_else(|error| error.into_inner());
				let poison = u64::from(lock.queue.is_poisoned())
					| (u64::from(lock.inner.is_poisoned()) << 1)
					| (u64::from(current.reader_poisoned) << 2)
					| (u64::from(current.active) << 3);
				word(&mut reply, 40, current.next_ticket);
				word(&mut reply, 48, poison);
				word(&mut reply, 56, current.readers as u64);
				word(&mut reply, 64, current.waiting.len() as u64);
				0
			}
			7 => {
				assert!(queue.is_none());
				let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
					let _held = lock.queue.lock().unwrap_or_else(|error| error.into_inner());
					panic!("owned queue mutex unwind");
				}));
				assert!(result.is_err());
				0
			}
			8 => {
				assert!(raw.is_none() && exclusive.is_none());
				let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
					let _held = lock.inner.lock().unwrap_or_else(|error| error.into_inner());
					panic!("owned inner mutex unwind");
				}));
				assert!(result.is_err());
				0
			}
			9 => {
				lock.changed.notify_all();
				0
			}
			10 => {
				assert!(raw.is_none() && exclusive.is_none());
				raw = Some(lock.inner.lock().unwrap_or_else(|error| error.into_inner()));
				0
			}
			11 => {
				drop(raw.take().unwrap());
				0
			}
			12 => {
				assert!(raw.is_some());
				let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
					let _held = raw.take().unwrap();
					panic!("owned retained inner mutex unwind");
				}));
				assert!(result.is_err());
				0
			}
			14 => {
				assert!(queue.is_none());
				queue = Some(lock.queue.lock().unwrap_or_else(|error| error.into_inner()));
				0
			}
			15 => {
				drop(queue.take().unwrap());
				0
			}
			16 => {
				let mut queue = lock.queue.lock().unwrap();
				assert!(!queue.active && queue.readers == 0 && queue.waiting.is_empty());
				queue.next_ticket = number(&command, 32);
				0
			}
			17 => {
				lock.queue.lock().unwrap().readers = number(&command, 32) as usize;
				0
			}
			_ => panic!("qualification command"),
		};
		word(&mut reply, 32, status);
		let mut output = output.lock().unwrap();
		output.write_all(&reply)?;
		output.flush()?;
	}
	// Every worker is told to stop before the parent joins any one of them.
	// Release a direct queue fixture before invoking a guard's own Drop path.
	drop(queue);
	drop(exclusive);
	drop(shared);
	drop(raw);
	Ok(())
}
fn main() -> io::Result<()> {
	assert_eq!(std::env::args_os().count(), 1);
	std::panic::set_hook(Box::new(|_| {}));
	let lock = Arc::new(AuditStoreLock::default());
	let output = Arc::new(Mutex::new(io::BufWriter::new(io::stdout())));
	let mut senders = Vec::new();
	let mut workers = Vec::new();
	for actor in 0..4 {
		let (sender, receiver) = mpsc::channel();
		senders.push(sender);
		let lock = lock.clone();
		let output = output.clone();
		workers.push(std::thread::spawn(move || {
			worker(actor, lock, receiver, output)
		}));
	}
	let mut input = io::stdin().lock();
	loop {
		let mut command = [0; 64];
		if input.read(&mut command[..1])? == 0 {
			break;
		}
		input.read_exact(&mut command[1..])?;
		let actor = number(&command, 16) as usize;
		assert!(actor < 4);
		senders[actor].send(command).unwrap();
	}
	drop(senders);
	for thread in workers {
		thread.join().unwrap()?;
	}
	let queue = lock.queue.lock().unwrap_or_else(|error| error.into_inner());
	assert!(!queue.active && queue.readers == 0 && queue.waiting.is_empty());
	output.lock().unwrap().flush()?;
	Ok(())
}
