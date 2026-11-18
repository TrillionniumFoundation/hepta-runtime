// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Original registry functions with real Arc, Weak, atomic and poison lifetimes.
use super::{active_registry, is_active, is_dispatch_active, read_pins, ACTIVE, READ_PINS};
use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex, OnceLock, Weak};

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
	bound_ids: HashMap<u64, String>,
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
		"private marker identity changed" => 42,
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
	assert!(op <= 16 && flag <= 1 && count <= 256 && count == wire.len() - 64);
	assert_eq!(&wire[40..64], &[0; 24]);
	let id = std::str::from_utf8(&wire[64..]).unwrap();
	let with_id = matches!(op, 1 | 2 | 6 | 7 | 14 | 16);
	let with_token = matches!(op, 3 | 4 | 5 | 11 | 14 | 16);
	assert!(with_id || count == 0);
	assert!(if with_token { token != 0 } else { token == 0 });
	assert!(matches!(op, 1 | 5 | 13) || flag == 0);
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
				if op == 1 || op == 2 {
					owner.bound_ids.insert(next, id.to_owned());
				}
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
			13 => {
				if owner.next == u64::MAX {
					return Err(anyhow!("private lease counter exhausted"));
				}
				let next = owner.next;
				let marker = Marker::Active(Arc::new(AtomicBool::new(flag != 0)), next);
				assert!(owner.handles.insert(next, marker).is_none());
				owner.next += 1;
				Ok((next, next))
			}
			14 => {
				let mut registry = active_registry()?;
				let (marker, generation) = match owner
					.handles
					.get(&token)
					.ok_or_else(|| anyhow!("invalid private lease"))?
				{
					Marker::Active(marker, generation) => (marker, *generation),
					Marker::Pin(_, _) => return Err(anyhow!("invalid private lease")),
				};
				if owner
					.bound_ids
					.get(&generation)
					.is_some_and(|previous| previous != id)
				{
					return Err(anyhow!("private marker identity changed"));
				}
				registry.insert(id.to_owned(), Arc::downgrade(marker));
				owner.bound_ids.insert(generation, id.to_owned());
				Ok((0, generation))
			}
			15 => {
				if owner.next == u64::MAX {
					return Err(anyhow!("private lease counter exhausted"));
				}
				let next = owner.next;
				let marker = Marker::Pin(Arc::new(()), next);
				assert!(owner.handles.insert(next, marker).is_none());
				owner.next += 1;
				Ok((next, next))
			}
			16 => {
				let mut registry = read_pins()?;
				let (marker, generation) = match owner
					.handles
					.get(&token)
					.ok_or_else(|| anyhow!("invalid private lease"))?
				{
					Marker::Pin(marker, generation) => (marker, *generation),
					Marker::Active(_, _) => return Err(anyhow!("invalid private lease")),
				};
				if let Some(previous) = owner.bound_ids.get(&generation) {
					if previous != id {
						return Err(anyhow!("private marker identity changed"));
					}
					return Ok((0, generation));
				}
				registry
					.entry(id.to_owned())
					.or_default()
					.push(Arc::downgrade(marker));
				owner.bound_ids.insert(generation, id.to_owned());
				Ok((0, generation))
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

pub(super) struct Bridge {
	owner: Owner,
	calls: [u64; 17],
}

impl Bridge {
	pub(super) fn new() -> Self {
		let mut value = Self {
			owner: Owner {
				next: 1,
				handles: HashMap::new(),
				bound_ids: HashMap::new(),
			},
			calls: [0; 17],
		};
		let mut raw = [0; 64];
		raw[..8].copy_from_slice(b"HRAAQ001");
		let reply = execute(&mut value.owner, &raw);
		assert_eq!(&reply[..8], b"HRAAR001");
		assert_eq!(number(&reply, 8), 0);
		value
	}
	pub(super) fn calls(&self) -> &[u64; 17] {
		&self.calls
	}
	pub(super) fn finish(&mut self) {
		let mut raw = [0; 64];
		raw[..8].copy_from_slice(b"HRAAQ001");
		word(&mut raw, 8, 12);
		let reply = execute(&mut self.owner, &raw);
		assert_eq!(number(&reply, 8), 0);
		assert!(self.owner.handles.is_empty());
	}
	pub(super) fn invoke(&mut self, raw: &[u8]) -> (u32, Vec<u8>) {
		let invalid = || (u32::MAX, Vec::new());
		if !(64..=320).contains(&raw.len()) || &raw[..8] != b"HRAAQ001" {
			return invalid();
		}
		let op = number(raw, 8);
		let token = number(raw, 16);
		let count = number(raw, 24);
		let flag = number(raw, 32);
		if op > 16
			|| flag > 1
			|| count > 256
			|| count != (raw.len() - 64) as u64
			|| raw[40..64].iter().any(|v| *v != 0)
			|| std::str::from_utf8(&raw[64..]).is_err()
			|| (!matches!(op, 1 | 2 | 6 | 7 | 14 | 16) && count != 0)
			|| (matches!(op, 3 | 4 | 5 | 11 | 14 | 16) != (token != 0))
			|| (!matches!(op, 1 | 5 | 13) && flag != 0)
		{
			return invalid();
		}
		self.calls[op as usize] += 1;
		let reply = if op == 9 || op == 10 {
			let hook = std::panic::take_hook();
			std::panic::set_hook(Box::new(|_| {}));
			let reply = execute(&mut self.owner, raw);
			std::panic::set_hook(hook);
			reply
		} else {
			execute(&mut self.owner, raw)
		};
		(64, reply.to_vec())
	}
}

pub(super) fn retention_is_active(id: &str) -> Result<bool> {
	is_active(id)
}
