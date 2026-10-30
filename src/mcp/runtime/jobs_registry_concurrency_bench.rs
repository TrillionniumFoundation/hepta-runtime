// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Isolated R3-compatible cold lookup benchmark; never launches a remote effect.
use super::*;
use std::os::unix::fs::PermissionsExt;
use std::sync::Barrier;
use std::time::Instant;

fn usage() -> (f64, f64, libc::c_long) {
	let mut value: libc::rusage = unsafe { std::mem::zeroed() };
	assert_eq!(unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut value) }, 0);
	let seconds = |time: libc::timeval| time.tv_sec as f64 + time.tv_usec as f64 / 1_000_000.0;
	(
		seconds(value.ru_utime),
		seconds(value.ru_stime),
		value.ru_maxrss,
	)
}

fn percentile(samples: &[f64], percentile: f64) -> f64 {
	let mut values = samples.to_vec();
	values.sort_by(f64::total_cmp);
	values[((values.len() as f64 * percentile).ceil() as usize).saturating_sub(1)]
}

#[test]
#[ignore = "isolated cold positive/absent concurrency benchmark; not remote launch TPS"]
fn cold_positive_and_absent_concurrency_benchmark() {
	let root = tempfile::tempdir().unwrap();
	let template: JobRecord = serde_json::from_value(json!({
		"id":"fixture", "host":"main", "ssh_target":"never-connect.invalid",
		"unit":"fixture-unit", "remote_job_dir":"/never-launch/jobs/fixture",
		"executable":"/usr/bin/true", "args":[], "cwd":null, "env_keys":[],
		"created_unix_ms":1, "idempotency_key":"fixture-key", "request_fingerprint":1,
		"request_digest":"a".repeat(64), "launch_state":"launched"
	}))
	.unwrap();
	for index in 0..6000 {
		let mut record = template.clone();
		record.id = format!("fixture-job-{index:05}");
		record.idempotency_key = Some(format!("fixture-key-{index:05}"));
		record.created_unix_ms = index;
		let path = root.path().join(format!("{}.json", record.id));
		std::fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
		std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
	}
	let runtime = Arc::new(
		tokio::runtime::Builder::new_multi_thread()
			.worker_threads(2)
			.max_blocking_threads(MAX_REGISTRY_LOOKUPS)
			.enable_all()
			.build()
			.unwrap(),
	);
	let mut rows = Vec::new();
	for repetition in 0..4 {
		// Reverse category and concurrency order in alternating repeats. Every
		// wave still gets its own empty cache; no marker write enters the timing.
		let kinds = if repetition % 2 == 0 {
			["fresh_positive", "absent", "known_invalidated"]
		} else {
			["known_invalidated", "absent", "fresh_positive"]
		};
		let widths = if repetition % 2 == 0 {
			[1, 4, 8]
		} else {
			[8, 4, 1]
		};
		for kind in kinds {
			let positive = kind != "absent";
			for concurrency in widths {
				let cache = Arc::new(Mutex::new(ReuseHitCache::default()));
				if kind == "known_invalidated" {
					for index in 0..concurrency {
						let key = format!("fixture-key-{:05}", 5992 + index);
						assert!(find_idempotent_in(root.path(), "main", &key, &cache)
							.unwrap()
							.is_some());
					}
					// Unique non-JSON publication invalidates the original positive
					// hits without adding another receipt or erasing known ownership.
					std::fs::write(
						root.path()
							.join(format!("marker-{repetition}-{concurrency}")),
						b"invalidate",
					)
					.unwrap();
				}
				let primed_strict_bindings = cache
					.lock()
					.unwrap()
					.known
					.values()
					.filter(|binding| binding.strict)
					.count();
				let slots = Arc::new(Semaphore::new(MAX_REGISTRY_LOOKUPS));
				let barrier = Arc::new(Barrier::new(concurrency + 1));
				let mut workers = Vec::new();
				for index in 0..concurrency {
					let path = root.path().to_owned();
					let cache = cache.clone();
					let slots = slots.clone();
					let runtime = runtime.clone();
					let barrier = barrier.clone();
					workers.push(std::thread::spawn(move || {
						let key = if positive {
							format!("fixture-key-{:05}", 5992 + index)
						} else {
							format!("absent-key-{index}")
						};
						barrier.wait();
						let started = Instant::now();
						let found = runtime
							.block_on(run_registry_lookup(slots, move || {
								find_idempotent_in(&path, "main", &key, &cache)
							}))
							.unwrap();
						let elapsed = started.elapsed().as_secs_f64() * 1000.0;
						if positive {
							assert_eq!(
								found.unwrap().id,
								format!("fixture-job-{:05}", 5992 + index)
							);
						} else {
							assert!(found.is_none());
						}
						elapsed
					}));
				}
				let before = usage();
				let started = Instant::now();
				barrier.wait();
				let latencies: Vec<_> = workers
					.into_iter()
					.map(|worker| worker.join().unwrap())
					.collect();
				let wall = started.elapsed().as_secs_f64();
				let after = usage();
				assert_eq!(slots.available_permits(), MAX_REGISTRY_LOOKUPS);
				let row = json!({
					"repetition":repetition, "kind":kind, "primed_strict_bindings":primed_strict_bindings,
					"concurrency":concurrency, "successes":latencies.len(), "failures":0,
					"wall_seconds":wall, "user_cpu_seconds":after.0-before.0,
					"system_cpu_seconds":after.1-before.1,
					"cpu_seconds_per_call":((after.0-before.0)+(after.1-before.1))/concurrency as f64,
					"calls_per_second":concurrency as f64/wall,
					"p50_ms":percentile(&latencies,0.50), "p95_ms":percentile(&latencies,0.95),
					"latencies_ms":latencies, "process_lifetime_maxrss":after.2,
				});
				println!("REGISTRY_CONCURRENCY_WAVE {row}");
				std::io::stdout().flush().unwrap();
				rows.push(row);
			}
		}
	}
	println!(
		"REGISTRY_CONCURRENCY_BENCH {}",
		json!({
			"schema":"hepta-registry-cold-concurrency-v1", "records":6000,
			"actual_worker_limit":MAX_REGISTRY_LOOKUPS, "repetitions":4,
			"cache":"fresh ReuseHitCache per wave; known_invalidated primes original keys then adds non-JSON marker before timing; OS cache may stay warm",
			"timing":"main barrier wait through all original worker joins; fixture and thread creation excluded",
			"cpu":"getrusage RUSAGE_SELF delta for each complete wave",
			"maxrss":"process lifetime maximum; KiB on Linux, bytes on macOS; not per-wave peak",
			"tail":"nearest rank; p95 equals maximum for each C1/C4/C8 wave",
			"remote_effects":0, "rows":rows
		})
	);
}
