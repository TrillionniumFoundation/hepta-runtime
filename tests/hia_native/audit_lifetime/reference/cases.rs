// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
// These exact scenarios run once per fresh original/native process.
fn check<T: std::fmt::Debug + PartialEq>(label: &str, observed: T, expected: T) {
	assert_eq!(observed, expected, "{label}");
	println!("{{\"label\":{label:?},\"value\":{:?}}}", format!("{observed:?}"));
}

fn active_lifecycle() {
	let marker = Marker::new();
	check("missing", is_active("request"), Ok(false));
	check("publish", publish_active("request", &marker), Ok(()));
	check("active", is_dispatch_active("request"), Ok(true));
	check("active_any", is_active("request"), Ok(true));
	marker.finish();
	check("finished", is_dispatch_active("request"), Ok(false));
	check("live_false_kept", sizes(), (1, 0, 0));
	drop(marker);
	check("dropped", is_active("request"), Ok(false));
	check("expired_pruned", sizes(), (0, 0, 0));
}

fn pin_multiset() {
	let first = Pin::new();
	let second = Pin::new();
	let clone = first.clone();
	publish_pin("read", &first).unwrap();
	publish_pin("read", &second).unwrap();
	publish_pin("read", &first).unwrap();
	check("three_weak_one_key", sizes(), (0, 1, 3));
	check("not_dispatch", is_dispatch_active("read"), Ok(false));
	check("read_pinned", is_active("read"), Ok(true));
	drop(first);
	drop(second);
	check("clone_holds_two_entries", is_active("read"), Ok(true));
	check("expired_second_pruned", sizes(), (0, 1, 2));
	drop(clone);
	check("last_pin_gone", is_active("read"), Ok(false));
	check("empty_pin_key_removed", sizes(), (0, 0, 0));
}

fn replace_marker() {
	let old = Marker::new();
	let new = Marker::new();
	publish_active("same", &old).unwrap();
	publish_active("same", &new).unwrap();
	old.finish();
	drop(old);
	check("replacement_alive", is_active("same"), Ok(true));
	check("replacement_single_entry", sizes(), (1, 0, 0));
	new.finish();
	check("replacement_false", is_dispatch_active("same"), Ok(false));
	drop(new);
	let newest = Marker::new();
	publish_active("same", &newest).unwrap();
	check("replace_expired", is_dispatch_active("same"), Ok(true));
	drop(newest);
	check("replacement_released", is_active("same"), Ok(false));
}

fn pruning_all_ids() {
	let mut markers = Vec::new();
	let mut pins = Vec::new();
	for index in 0..32 {
		let marker = Marker::new();
		let pin = Pin::new();
		let key = format!("retained-{index}");
		publish_active(&key, &marker).unwrap();
		publish_pin(&key, &pin).unwrap();
		if index % 2 == 0 {
			marker.finish();
			markers.push(marker);
			pins.push(pin);
		}
	}
	check("before_global_prune", sizes(), (32, 32, 32));
	check("absent_query", is_active("not-present"), Ok(false));
	check("global_prune_retains_live_false", sizes(), (16, 16, 16));
	drop(markers);
	drop(pins);
	check("second_absent_query", is_active("not-present"), Ok(false));
	check("global_prune_empty", sizes(), (0, 0, 0));
}

fn keys_and_growth() {
	let keys = ["".to_owned(), "a\0b".to_owned(), "读取-🧪".to_owned(), "k".repeat(8193)];
	let marker = Marker::new();
	let pin = Pin::new();
	for key in &keys {
		publish_active(key, &marker).unwrap();
		publish_pin(key, &pin).unwrap();
	}
	for (index, key) in keys.iter().enumerate() {
		check(&format!("exact_key_{index}"), is_dispatch_active(key), Ok(true));
	}
	check("prefix_not_equal", is_active("a"), Ok(false));
	check("long_prefix_not_equal", is_active(&"k".repeat(8192)), Ok(false));
	check("distinct_keys", sizes(), (4, 4, 4));
	marker.finish();
	for key in &keys {
		assert!(!is_dispatch_active(key).unwrap());
		assert!(is_active(key).unwrap());
	}
	drop(marker);
	drop(pin);
	check("all_keys_retired", is_active(""), Ok(false));
	check("growth_cleanup", sizes(), (0, 0, 0));
}

fn cohort_atomic_publication() {
	let first = Marker::new();
	let second = Marker::new();
	let mut guard = held().unwrap();
	guard.insert("cohort-first", &first);
	let (started_tx, started_rx) = std::sync::mpsc::channel();
	let (finished_tx, finished_rx) = std::sync::mpsc::channel();
	let worker = std::thread::spawn(move || {
		started_tx.send(()).unwrap();
		let first = is_dispatch_active("cohort-first").unwrap();
		let second = is_dispatch_active("cohort-second").unwrap();
		finished_tx.send((first, second)).unwrap();
	});
	started_rx.recv().unwrap();
	check("cohort_blocks_reader", finished_rx.recv_timeout(std::time::Duration::from_millis(40)).is_err(), true);
	guard.insert("cohort-second", &second);
	drop(guard);
	check("whole_cohort_visible", finished_rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap(), (true, true));
	worker.join().unwrap();
	drop(first);
	drop(second);
	check("cohort_cleanup", is_active("cohort-first"), Ok(false));
}

fn cohort_panic_poison() {
	let marker = Marker::new();
	let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
		let mut guard = held().unwrap();
		guard.insert("poisoned", &marker);
		panic!("intentional active guard unwind");
	}));
	check("caught_active_unwind", result.is_err(), true);
	check("active_poison_error", is_dispatch_active("poisoned"), Err("request audit active registry unavailable".to_owned()));
	check("held_poison_error", held().err(), Some("request audit active registry unavailable".to_owned()));
	drop(marker);
}

fn already_unwinding_guard() {
	struct DuringUnwind;
	impl Drop for DuringUnwind {
		fn drop(&mut self) {
			assert!(std::thread::panicking());
			let guard = held().unwrap();
			drop(guard);
		}
	}
	let result = std::panic::catch_unwind(|| {
		let _during = DuringUnwind;
		panic!("intentional pre-existing unwind");
	});
	check("caught_existing_unwind", result.is_err(), true);
	check("no_new_poison", is_dispatch_active("missing"), Ok(false));
}

fn poison_pin_lock() {
	let result = std::panic::catch_unwind(|| {
		let _guard = pin_guard();
		panic!("intentional pin guard unwind");
	});
	assert!(result.is_err());
}

fn pin_poison_active_true() {
	let marker = Marker::new();
	publish_active("live", &marker).unwrap();
	poison_pin_lock();
	check("dispatch_ignores_pin_lock", is_dispatch_active("live"), Ok(true));
	check("any_checks_poison_even_if_active", is_active("live"), Err("request read pin state unavailable".to_owned()));
	drop(marker);
}

fn active_poison_first() {
	poison_pin_lock();
	assert!(std::panic::catch_unwind(|| {
		let _guard = held().unwrap();
		panic!("intentional second poison");
	}).is_err());
	check("active_error_precedes_pin", is_active("missing"), Err("request audit active registry unavailable".to_owned()));
}

fn strong_clone_contenders() {
	let marker = Marker::new();
	let weak = marker.downgrade();
	let barrier = std::sync::Arc::new(std::sync::Barrier::new(17));
	let mut workers = Vec::new();
	for _ in 0..16 {
		let owner = marker.clone();
		let barrier = barrier.clone();
		workers.push(std::thread::spawn(move || {
			barrier.wait();
			for _ in 0..64 {
				let clone = owner.clone();
				assert!(clone.value());
				drop(clone);
			}
		}));
	}
	barrier.wait();
	for worker in workers {
		worker.join().unwrap();
	}
	check("last_strong_after_contention", weak.strong_count(), 1);
	marker.finish();
	check("release_visible_to_upgrade", weak.upgrade().unwrap().value(), false);
	drop(marker);
	check("zero_strong_after_drop", weak.strong_count(), 0);
	check("no_resurrection", weak.upgrade().is_none(), true);
	drop(weak);
}

fn weak_upgrade_race() {
	for index in 0..64 {
		let marker = Marker::new();
		let weak = marker.downgrade();
		let concurrent_weak = weak.clone();
		let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
		let other = barrier.clone();
		let worker = std::thread::spawn(move || {
			other.wait();
			let upgraded = concurrent_weak.upgrade();
			if let Some(value) = &upgraded {
				assert!(value.value());
			}
			upgraded.is_some()
		});
		barrier.wait();
		drop(marker);
		let upgraded = worker.join().unwrap();
		println!("{{\"race\":{index},\"upgraded\":{upgraded}}}");
		assert_eq!(weak.strong_count(), 0);
		assert!(weak.upgrade().is_none());
		drop(weak);
	}
	check("race_trials_without_resurrection", 64, 64);
}

fn map_disposal_outliving_strong() {
	let marker = Marker::new();
	let weak = marker.downgrade();
	let pin = Pin::new();
	publish_active("outlive", &marker).unwrap();
	publish_pin("outlive", &pin).unwrap();
	finalize();
	check("strong_survives_map_disposal", marker.value(), true);
	check("external_weak_survives_map_disposal", weak.strong_count(), 1);
	marker.finish();
	check("external_upgrade_after_map_disposal", weak.upgrade().unwrap().value(), false);
	drop(marker);
	drop(pin);
	check("external_weak_expires", weak.upgrade().is_none(), true);
	drop(weak);
}

fn capacity_beyond_512() {
	let mut owners = Vec::new();
	for index in 0..513 {
		let marker = Marker::new();
		let pin = Pin::new();
		let key = format!("item-{index:04}");
		publish_active(&key, &marker).unwrap();
		publish_pin(&key, &pin).unwrap();
		owners.push((marker, pin));
	}
	check("no_512_entry_quota", sizes(), (513, 513, 513));
	check("entry_513_visible", is_active("item-0512"), Ok(true));
	check("entry_513_dispatch", is_dispatch_active("item-0512"), Ok(true));
	drop(owners);
	check("all_513_reclaimed", is_active("missing"), Ok(false));
	check("both_maps_empty", sizes(), (0, 0, 0));
}

fn pin_active_combination() {
	let marker = Marker::new();
	let pin = Pin::new();
	publish_active("combined", &marker).unwrap();
	publish_pin("combined", &pin).unwrap();
	marker.finish();
	check("finished_but_pinned", is_active("combined"), Ok(true));
	check("finished_not_dispatch", is_dispatch_active("combined"), Ok(false));
	drop(marker);
	check("dropped_marker_still_pinned", is_active("combined"), Ok(true));
	drop(pin);
	check("both_lifetimes_ended", is_active("combined"), Ok(false));
}

fn concurrent_shared_key() {
	let ready = std::sync::Arc::new(std::sync::Barrier::new(17));
	let release = std::sync::Arc::new(std::sync::Barrier::new(17));
	let owners: Vec<_> = (0..16).map(|_| (Marker::new(), Pin::new())).collect();
	let mut workers = Vec::new();
	for (marker, pin) in owners {
		let ready = ready.clone();
		let release = release.clone();
		workers.push(std::thread::spawn(move || {
			publish_active("shared", &marker).unwrap();
			publish_pin("shared", &pin).unwrap();
			ready.wait();
			release.wait();
			marker.finish();
		}));
	}
	ready.wait();
	check("all_concurrent_pins_visible", sizes(), (1, 1, 16));
	check("concurrent_last_marker_visible", is_dispatch_active("shared"), Ok(true));
	check("concurrent_any_visible", is_active("shared"), Ok(true));
	release.wait();
	for worker in workers {
		worker.join().unwrap();
	}
	check("concurrent_lifetimes_finished", is_active("shared"), Ok(false));
	check("concurrent_maps_pruned", sizes(), (0, 0, 0));
}

fn main() {
	let name = std::env::args().nth(1).expect("one frozen scenario name");
	setup();
	match name.as_str() {
		"active_lifecycle" => active_lifecycle(),
		"pin_multiset" => pin_multiset(),
		"replace_marker" => replace_marker(),
		"pruning_all_ids" => pruning_all_ids(),
		"keys_and_growth" => keys_and_growth(),
		"cohort_atomic_publication" => cohort_atomic_publication(),
		"cohort_panic_poison" => cohort_panic_poison(),
		"already_unwinding_guard" => already_unwinding_guard(),
		"pin_poison_active_true" => pin_poison_active_true(),
		"active_poison_first" => active_poison_first(),
		"strong_clone_contenders" => strong_clone_contenders(),
		"weak_upgrade_race" => weak_upgrade_race(),
		"map_disposal_outliving_strong" => map_disposal_outliving_strong(),
		"capacity_beyond_512" => capacity_beyond_512(),
		"pin_active_combination" => pin_active_combination(),
		"concurrent_shared_key" => concurrent_shared_key(),
		_ => panic!("unknown frozen scenario"),
	}
	if name != "map_disposal_outliving_strong" {
		finalize();
	}
	println!("{{\"case\":{name:?},\"status\":\"PASS\"}}");
}
