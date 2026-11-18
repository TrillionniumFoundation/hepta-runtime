// Copyright 2026 Muvon Un Limited
// SPDX-License-Identifier: Apache-2.0
static ACTIVE: OnceLock<Mutex<HashMap<String, Weak<AtomicBool>>>> = OnceLock::new();
static READ_PINS: OnceLock<Mutex<HashMap<String, Vec<Weak<()>>>>> = OnceLock::new();
fn active_registry() -> Result<std::sync::MutexGuard<'static, HashMap<String, Weak<AtomicBool>>>> {
	ACTIVE
		.get_or_init(|| Mutex::new(HashMap::new()))
		.lock()
		.map_err(|_| anyhow!("request audit active registry unavailable"))
}
fn read_pins() -> Result<std::sync::MutexGuard<'static, HashMap<String, Vec<Weak<()>>>>> {
	READ_PINS
		.get_or_init(|| Mutex::new(HashMap::new()))
		.lock()
		.map_err(|_| anyhow!("request read pin state unavailable"))
}
fn is_dispatch_active(id: &str) -> Result<bool> {
	let mut registry = active_registry()?;
	registry.retain(|_, marker| marker.strong_count() > 0);
	Ok(registry
		.get(id)
		.and_then(Weak::upgrade)
		.is_some_and(|marker| marker.load(Ordering::Acquire)))
}
fn is_active(id: &str) -> Result<bool> {
	let active = is_dispatch_active(id)?;
	let mut pins = read_pins()?;
	pins.retain(|_, markers| {
		markers.retain(|marker| marker.strong_count() > 0);
		!markers.is_empty()
	});
	Ok(active || pins.contains_key(id))
}
