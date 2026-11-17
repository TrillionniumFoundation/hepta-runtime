// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, Weak};

type Result<T> = std::result::Result<T, String>;
macro_rules! anyhow {
	($message:literal) => {
		$message.to_owned()
	};
}

static ACTIVE: OnceLock<Mutex<HashMap<String, Weak<AtomicBool>>>> = OnceLock::new();
static READ_PINS: OnceLock<Mutex<HashMap<String, Vec<Weak<()>>>>> = OnceLock::new();
include!("registry.rs.txt");

#[derive(Clone)]
struct Marker(Arc<AtomicBool>);
impl Marker {
	fn new() -> Self {
		Self(Arc::new(AtomicBool::new(true)))
	}
	fn finish(&self) {
		self.0.store(false, Ordering::Release);
	}
	fn value(&self) -> bool {
		self.0.load(Ordering::Acquire)
	}
	fn downgrade(&self) -> WeakMarker {
		WeakMarker(Arc::downgrade(&self.0))
	}
}

#[derive(Clone)]
struct Pin(Arc<()>);
impl Pin {
	fn new() -> Self {
		Self(Arc::new(()))
	}
}

#[derive(Clone)]
struct WeakMarker(Weak<AtomicBool>);
impl WeakMarker {
	fn upgrade(&self) -> Option<Marker> {
		self.0.upgrade().map(Marker)
	}
	fn strong_count(&self) -> usize {
		self.0.strong_count()
	}
}

struct ActiveGuard(MutexGuard<'static, HashMap<String, Weak<AtomicBool>>>);
impl ActiveGuard {
	fn insert(&mut self, key: &str, marker: &Marker) {
		self.0.insert(key.to_owned(), Arc::downgrade(&marker.0));
	}
}

fn setup() {
	drop(active_registry().unwrap());
	drop(read_pins().unwrap());
}

fn held() -> Result<ActiveGuard> {
	active_registry().map(ActiveGuard)
}

fn publish_active(key: &str, marker: &Marker) -> Result<()> {
	active_registry()?.insert(key.to_owned(), Arc::downgrade(&marker.0));
	Ok(())
}

fn publish_pin(key: &str, pin: &Pin) -> Result<()> {
	read_pins()?
		.entry(key.to_owned())
		.or_default()
		.push(Arc::downgrade(&pin.0));
	Ok(())
}

fn pin_guard() -> MutexGuard<'static, HashMap<String, Vec<Weak<()>>>> {
	read_pins().unwrap()
}

fn sizes() -> (usize, usize, usize) {
	let active = ACTIVE
		.get()
		.unwrap()
		.lock()
		.unwrap_or_else(|error| error.into_inner());
	let pins = READ_PINS
		.get()
		.unwrap()
		.lock()
		.unwrap_or_else(|error| error.into_inner());
	(active.len(), pins.len(), pins.values().map(Vec::len).sum())
}

fn finalize() {
	ACTIVE
		.get()
		.unwrap()
		.lock()
		.unwrap_or_else(|error| error.into_inner())
		.clear();
	READ_PINS
		.get()
		.unwrap()
		.lock()
		.unwrap_or_else(|error| error.into_inner())
		.clear();
}

include!("cases.rs");
