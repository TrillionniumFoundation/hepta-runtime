// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Original registry functions with real Arc, Weak, atomic and poison lifetimes.
use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex, OnceLock, Weak};
include!("original_active.rs");

#[derive(Clone)]
enum Marker {
	Active(Arc<AtomicBool>, u64),
	Pin(Arc<()>, u64),
}
impl Marker {
	fn generation(&self) -> u64 {
		match self {
			Self::Active(_, value) | Self::Pin(_, value) => *value,
		}
	}
}
struct Owner {
	next: u64,
	handles: HashMap<u64, Marker>,
}
fn number(raw: &[u8], at: usize) -> u64 {
	u64::from_le_bytes(raw[at..at + 8].try_into().unwrap())
}
fn word(raw: &mut [u8], at: usize, value: u64) {
	raw[at..at + 8].copy_from_slice(&value.to_le_bytes());
}
fn diagnostic(error: anyhow::Error) -> u64 {
	match error.to_string().as_str() {
		"request audit active registry unavailable" => 38,
		"request read pin state unavailable" => 39,
		"invalid private lease" => 40,
		"private lease counter exhausted" => 41,
		value => panic!("unexpected original error {value}"),
	}
}
fn execute(owner: &mut Owner, wire: &[u8]) -> [u8; 64] {
	assert!((64..=320).contains(&wire.len()));
	assert_eq!(&wire[..8], b"HRAAQ001");
	let op = number(wire, 8);
	let token = number(wire, 16);
	let count = number(wire, 24) as usize;
	let flag = number(wire, 32);
	assert!(op <= 12 && flag <= 1 && count <= 256 && count == wire.len() - 64);
	assert_eq!(&wire[40..64], &[0; 24]);
	let id = std::str::from_utf8(&wire[64..]).unwrap();
	let with_id = matches!(op, 1 | 2 | 6 | 7);
	let with_token = matches!(op, 3 | 4 | 5 | 11);
	assert!(with_id || count == 0);
	assert!(if with_token { token != 0 } else { token == 0 });
	assert!(matches!(op, 1 | 5) || flag == 0);
	let outcome = (|| -> Result<(u64, u64)> {
		match op {
			0 | 8 => Ok((0, 0)),
			1 | 2 => {
				if owner.next == u64::MAX {
					return Err(anyhow!("private lease counter exhausted"));
				}
				let next = owner.next;
				let marker = if op == 1 {
					let active = Arc::new(AtomicBool::new(flag != 0));
					active_registry()?.insert(id.to_owned(), Arc::downgrade(&active));
					Marker::Active(active, next)
				} else {
					let pin = Arc::new(());
					read_pins()?
						.entry(id.to_owned())
						.or_default()
						.push(Arc::downgrade(&pin));
					Marker::Pin(pin, next)
				};
				assert!(owner.handles.insert(next, marker).is_none());
				owner.next += 1;
				Ok((next, next))
			}
			3 => {
				let marker = owner
					.handles
					.get(&token)
					.ok_or_else(|| anyhow!("invalid private lease"))?;
				if owner.next == u64::MAX {
					return Err(anyhow!("private lease counter exhausted"));
				}
				let cloned = marker.clone();
				let generation = cloned.generation();
				let next = owner.next;
				assert!(owner.handles.insert(next, cloned).is_none());
				owner.next += 1;
				Ok((next, generation))
			}
			4 => {
				let marker = owner
					.handles
					.remove(&token)
					.ok_or_else(|| anyhow!("invalid private lease"))?;
				let generation = marker.generation();
				drop(marker);
				Ok((0, generation))
			}
			5 | 11 => {
				match owner
					.handles
					.get(&token)
					.ok_or_else(|| anyhow!("invalid private lease"))?
				{
					Marker::Active(marker, generation) => {
						if op == 5 {
							marker.store(flag != 0, Ordering::Release);
							Ok((0, *generation))
						} else {
							Ok((u64::from(marker.load(Ordering::Acquire)), *generation))
						}
					}
					Marker::Pin(_, _) => Err(anyhow!("invalid private lease")),
				}
			}
			6 => is_dispatch_active(id).map(|active| (u64::from(active), 0)),
			7 => is_active(id).map(|active| (u64::from(active), 0)),
			9 => {
				let failure = std::panic::catch_unwind(|| {
					let _held = active_registry().unwrap();
					panic!("controlled original active registry poison");
				});
				assert!(failure.is_err() && ACTIVE.get().unwrap().is_poisoned());
				Ok((0, 0))
			}
			10 => {
				let failure = std::panic::catch_unwind(|| {
					let _held = read_pins().unwrap();
					panic!("controlled original read pin registry poison");
				});
				assert!(failure.is_err() && READ_PINS.get().unwrap().is_poisoned());
				Ok((0, 0))
			}
			12 => {
				owner.handles.clear();
				Ok((0, 0))
			}
			_ => unreachable!(),
		}
	})();
	let mut out = [0; 64];
	out[..8].copy_from_slice(b"HRAAR001");
	match outcome {
		Ok((value, generation)) => {
			word(&mut out, 16, value);
			word(&mut out, 24, generation);
		}
		Err(error) => word(&mut out, 8, diagnostic(error)),
	}
	let active = ACTIVE
		.get_or_init(|| Mutex::new(HashMap::new()))
		.lock()
		.unwrap_or_else(|e| e.into_inner());
	word(&mut out, 32, active.len() as u64);
	drop(active);
	let pins = READ_PINS
		.get_or_init(|| Mutex::new(HashMap::new()))
		.lock()
		.unwrap_or_else(|e| e.into_inner());
	word(&mut out, 40, pins.len() as u64);
	word(
		&mut out,
		48,
		pins.values().map(|values| values.len() as u64).sum(),
	);
	word(&mut out, 56, owner.handles.len() as u64);
	out
}

fn main() {
	std::panic::set_hook(Box::new(|_| {}));
	let owner = Arc::new(Mutex::new(Owner {
		next: 1,
		handles: HashMap::new(),
	}));
	let stdout = Arc::new(Mutex::new(std::io::stdout()));
	let mut senders = Vec::new();
	let mut workers = Vec::new();
	for actor in 0..4_u64 {
		let (sender, receiver) = mpsc::sync_channel::<[u8; 384]>(0);
		senders.push(sender);
		let owner = Arc::clone(&owner);
		let stdout = Arc::clone(&stdout);
		workers.push(std::thread::spawn(move || {
			while let Ok(frame) = receiver.recv() {
				assert_eq!(number(&frame, 16), actor);
				let count = number(&frame, 24) as usize;
				assert!((64..=320).contains(&count));
				assert!(frame[64 + count..].iter().all(|value| *value == 0));
				let result = execute(&mut owner.lock().unwrap(), &frame[64..64 + count]);
				let mut out = [0; 96];
				out[..8].copy_from_slice(b"HRAAO001");
				out[8..24].copy_from_slice(&frame[8..24]);
				word(&mut out, 24, 64);
				out[32..].copy_from_slice(&result);
				let mut output = stdout.lock().unwrap();
				output.write_all(&out).unwrap();
				output.flush().unwrap();
			}
		}));
	}
	let mut input = std::io::stdin().lock();
	loop {
		let mut frame = [0; 384];
		let first = loop {
			match input.read(&mut frame[..1]) {
				Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
				value => break value.unwrap(),
			}
		};
		if first == 0 {
			break;
		}
		input.read_exact(&mut frame[1..]).unwrap();
		assert_eq!(&frame[..8], b"HRAAC001");
		assert_eq!(&frame[32..64], &[0; 32]);
		let actor = number(&frame, 16) as usize;
		assert!(actor < 4);
		senders[actor].send(frame).unwrap();
	}
	drop(senders);
	for worker in workers {
		worker.join().unwrap();
	}
	let mut remaining = owner.lock().unwrap();
	remaining.handles.clear();
	assert!(remaining.handles.is_empty());
}
