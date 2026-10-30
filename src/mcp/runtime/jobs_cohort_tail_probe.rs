// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Opt-in lookup-only diagnosis; these timings are not release MCP performance.
use super::*;
use std::rc::Rc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

const ORIGINALS: usize = 6;
const HISTORY: usize = 6_000;
const WAVES: usize = 8;

#[derive(Default)]
struct Timing {
	registered: Option<Instant>,
	scan_started: Option<Instant>,
	scan_finished: Option<Instant>,
	cohort_wait_started: Option<Instant>,
}

struct ActiveWorker {
	active: Arc<AtomicUsize>,
}

impl ActiveWorker {
	fn enter(active: Arc<AtomicUsize>, peak: &AtomicUsize) -> Self {
		let count = active.fetch_add(1, Ordering::SeqCst) + 1;
		peak.fetch_max(count, Ordering::SeqCst);
		Self { active }
	}
}

impl Drop for ActiveWorker {
	fn drop(&mut self) {
		self.active.fetch_sub(1, Ordering::SeqCst);
	}
}

fn milliseconds(duration: Duration) -> f64 {
	duration.as_secs_f64() * 1_000.0
}

fn thread_cpu_seconds() -> f64 {
	let mut value = libc::timespec {
		tv_sec: 0,
		tv_nsec: 0,
	};
	// A thread CPU clock excludes time sleeping behind admission or a scan gate.
	assert_eq!(
		unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut value) },
		0
	);
	value.tv_sec as f64 + value.tv_nsec as f64 / 1_000_000_000.0
}

fn install_timing(timing: &Rc<RefCell<Timing>>) {
	let state = timing.clone();
	AFTER_REGISTRATION.with(|slot| {
		*slot.borrow_mut() = Some(Box::new(move || {
			state.borrow_mut().registered = Some(Instant::now());
		}));
	});
	let state = timing.clone();
	ON_SCAN.with(|slot| {
		*slot.borrow_mut() = Some(Box::new(move || {
			state.borrow_mut().scan_started = Some(Instant::now());
		}));
	});
	let state = timing.clone();
	AFTER_SCAN.with(|slot| {
		*slot.borrow_mut() = Some(Box::new(move || {
			state.borrow_mut().scan_finished = Some(Instant::now());
		}));
	});
	let state = timing.clone();
	ON_COHORT_WAIT.with(|slot| {
		*slot.borrow_mut() = Some(Box::new(move || {
			state.borrow_mut().cohort_wait_started = Some(Instant::now());
		}));
	});
}

async fn lookup_batch(
	root: &Path,
	cache: &Arc<Mutex<ReuseHitCache>>,
	slots: &Arc<Semaphore>,
	indices: std::ops::Range<usize>,
) -> (Vec<Value>, usize) {
	let active = Arc::new(AtomicUsize::new(0));
	let peak = Arc::new(AtomicUsize::new(0));
	let (sender, receiver) = std::sync::mpsc::channel();
	let mut tasks = Vec::new();
	for index in indices {
		let root = root.to_path_buf();
		let cache = cache.clone();
		let slots = slots.clone();
		let sender = sender.clone();
		let active = active.clone();
		let peak = peak.clone();
		let submitted = Instant::now();
		// Natural submission: no barrier or sleep inside admission, scan or publication.
		tasks.push(tokio::spawn(async move {
			let original = format!("original-{index:02}");
			let result = run_registry_lookup(slots, move || {
				let entered = Instant::now();
				let _active = ActiveWorker::enter(active, &peak);
				let _hooks = Hooks::new();
				let timing = Rc::new(RefCell::new(Timing::default()));
				install_timing(&timing);
				let cpu_start = thread_cpu_seconds();
				let found = find_idempotent_in(
					&root,
					&format!("host-{index:02}"),
					&format!("original-key-{index:02}"),
					cache.as_ref(),
				);
				let cpu_seconds = thread_cpu_seconds() - cpu_start;
				let finished = Instant::now();
				let timing = timing.borrow();
				let first_scan_ms = timing.scan_started.zip(timing.scan_finished)
					.map(|(start, end)| milliseconds(end.duration_since(start)));
				let wait_to_end_ms = timing.cohort_wait_started
					.map(|start| milliseconds(finished.duration_since(start)));
				sender.send(json!({
					"index": index,
					"okay": matches!(&found, Ok(Some(value)) if value.id == format!("original-{index:02}")),
					"error": found.as_ref().err().map(ToString::to_string),
					"full_scan_passes": SCANS.with(Cell::get),
					"submit_to_worker_ms": milliseconds(entered.duration_since(submitted)),
					"worker_ms": milliseconds(finished.duration_since(entered)),
					"submit_to_lookup_end_ms": milliseconds(finished.duration_since(submitted)),
					"worker_cpu_ms": cpu_seconds * 1_000.0,
					"post_registration_hook_ms": timing.registered.map(|value| milliseconds(value.duration_since(entered))),
					"first_scan_ms": first_scan_ms,
					"waited_for_cohort": timing.cohort_wait_started.is_some(),
					"cohort_wait_to_lookup_end_ms": wait_to_end_ms,
				})).expect("probe receiver remains live");
				found
			}).await.expect("read-only lookup worker failed");
			assert_eq!(result.expect("original binding disappeared").id, original);
		}));
	}
	drop(sender);
	for task in tasks {
		task.await.expect("lookup task failed");
	}
	let mut rows: Vec<Value> = receiver.into_iter().collect();
	rows.sort_by_key(|value| value["index"].as_u64().unwrap());
	assert_eq!(active.load(Ordering::SeqCst), 0);
	let peak = peak.load(Ordering::SeqCst);
	assert!(peak <= MAX_REGISTRY_LOOKUPS);
	(rows, peak)
}

fn write_fixture(root: &Path) {
	for index in 0..ORIGINALS {
		write(
			root,
			&record(
				&format!("original-{index:02}"),
				&format!("host-{index:02}"),
				&format!("original-key-{index:02}"),
				"launched",
			),
		);
	}
	for index in 0..HISTORY {
		let identity = format!("benchmark-unqueried-history-{index:05}");
		let value = record(
			&identity,
			"unqueried-host",
			&format!("unqueried-key-{index:05}"),
			"launched",
		);
		// Synthetic lookup fixture only: no remote command, durable effect or fsync claim.
		let mut file = OpenOptions::new()
			.write(true)
			.create_new(true)
			.open(root.join(format!("{identity}.json")))
			.unwrap();
		file.write_all(&serde_json::to_vec(&value).unwrap())
			.unwrap();
	}
}

#[test]
#[ignore = "manual lookup-only cold-tail diagnosis; not a release MCP benchmark"]
fn six_callers_four_slots_cold_tail_probe() {
	assert_eq!(
		MAX_REGISTRY_LOOKUPS, 4,
		"probe requires the actual four-slot limit"
	);
	let root = tempfile::tempdir().unwrap();
	write_fixture(root.path());
	assert!(registry_has_content_watch(
		&registry_epoch(root.path()).unwrap()
	));
	let cache = Arc::new(Mutex::new(ReuseHitCache::default()));
	let slots = Arc::new(Semaphore::new(MAX_REGISTRY_LOOKUPS));
	let runtime = tokio::runtime::Builder::new_multi_thread()
		.worker_threads(2)
		.enable_all()
		.build()
		.unwrap();
	let results = runtime.block_on(async {
		// Prime original strict ownership and the bounded prediction list outside measurement.
		for index in 0..ORIGINALS {
			let (rows, _) = lookup_batch(root.path(), &cache, &slots, index..index + 1).await;
			assert_eq!(rows.len(), 1);
		}
		assert_eq!(cache.lock().unwrap().known.len(), ORIGINALS);
		assert!(cache
			.lock()
			.unwrap()
			.known
			.values()
			.all(|binding| binding.strict));
		// Start the existing blocking threads before timing. This barrier is setup only.
		let ready = Arc::new(std::sync::Barrier::new(MAX_REGISTRY_LOOKUPS + 1));
		let workers: Vec<_> = (0..MAX_REGISTRY_LOOKUPS)
			.map(|_| {
				let ready = ready.clone();
				tokio::task::spawn_blocking(move || {
					ready.wait();
				})
			})
			.collect();
		ready.wait();
		for worker in workers {
			worker.await.unwrap();
		}
		let mut results = Vec::new();
		for pattern in ["natural-six", "first-four-complete-then-last-two"] {
			for wave in 0..WAVES {
				std::fs::write(
					root.path().join(format!("{pattern}-{wave:02}.marker")),
					b"invalidate\n",
				)
				.unwrap();
				for category in ["cold", "warm"] {
					let started = Instant::now();
					let (rows, peak) = if pattern == "natural-six" {
						lookup_batch(root.path(), &cache, &slots, 0..ORIGINALS).await
					} else {
						let (mut first, first_peak) =
							lookup_batch(root.path(), &cache, &slots, 0..4).await;
						let (last, last_peak) =
							lookup_batch(root.path(), &cache, &slots, 4..ORIGINALS).await;
						first.extend(last);
						(first, first_peak.max(last_peak))
					};
					let elapsed_ms = milliseconds(started.elapsed());
					assert_eq!(rows.len(), ORIGINALS);
					assert!(rows.iter().all(|row| row["okay"] == true));
					let scans: u64 = rows
						.iter()
						.map(|row| row["full_scan_passes"].as_u64().unwrap())
						.sum();
					if category == "warm" {
						assert_eq!(scans, 0, "warm reads must keep their verified hits");
					}
					let state = cache.lock().unwrap().cold.clone();
					let state = state.state.lock().unwrap();
					assert!(
						state.demands.is_empty()
							&& state.hints.is_empty()
							&& state.active.is_none()
					);
					drop(state);
					results.push(json!({"pattern":pattern,"wave":wave,"category":category,
						"calls":rows,"full_scan_passes":scans,"peak_lookup_workers":peak,"wave_ms":elapsed_ms}));
				}
			}
		}
		results
	});
	println!(
		"HEPTA_COHORT_TAIL_PROBE {}",
		json!({
			"schema":"hepta-test-only-cohort-tail-probe/v1", "passed":true,
			"scope":"synthetic lookup-only diagnostic; no start audit, SSH, RPC envelope or remote effects",
			"originals":ORIGINALS, "synthetic_records":HISTORY, "lookup_slots":MAX_REGISTRY_LOOKUPS,
			"tokio_workers":2, "waves_per_pattern":WAVES,
			"submit_to_worker_scope":"async scheduling plus semaphore admission plus blocking-pool dispatch, not isolated semaphore wait",
			"cohort_wait_scope":"cohort-wait entry until lookup end; includes final validation and is an upper bound on gate wait",
			"first_scan_scope":"first full record scan only; total scan count includes any further passes",
			"staged_scope":"first four tasks fully complete before the final two are submitted; per-call timers start at each submission",
			"results":results,
		})
	);
}
