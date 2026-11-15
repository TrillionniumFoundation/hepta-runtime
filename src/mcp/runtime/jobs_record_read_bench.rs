// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Compare actual guarded receipt reads and lookups on identically built binaries.
use super::*;
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

fn fixture(size: usize) -> (tempfile::TempDir, JobRecord, RegistryEpoch) {
	let root = tempfile::tempdir().unwrap();
	let mut original: JobRecord = serde_json::from_value(json!({
		"execution_mode":"operator", "id":"read-benchmark-original", "host":"main",
		"ssh_target":"never-connect.invalid", "unit":"fixture-unit",
		"remote_job_dir":"/never-launch/read-benchmark-original", "executable":"/usr/bin/true",
		"args":[""], "cwd":null, "env_keys":[], "created_unix_ms":1,
		"idempotency_key":"read-benchmark-key", "request_fingerprint":1,
		"request_digest":"a".repeat(64), "launch_state":"launched"
	}))
	.unwrap();
	let overhead = serde_json::to_vec(&original).unwrap().len();
	assert!(size >= overhead && size as u64 <= MAX_CACHED_RECORD_BYTES);
	original.args[0] = "x".repeat(size - overhead);
	let path = root.path().join(format!("{}.json", original.id));
	save_record_at(&path, &original).unwrap();
	let bytes = serde_json::to_vec(&original).unwrap();
	assert_eq!(bytes.len(), size);
	std::fs::write(path, bytes).unwrap();
	let mut epoch = registry_epoch(root.path()).unwrap();
	// A fixed epoch isolates receipt work from unrelated watch/host activity.
	// The same harness is usable with the parent binary without deriving Eq.
	epoch.content = Some(super::super::namespace_version::Version::Watch(41, 43));
	(root, original, epoch)
}

fn lookup(mode: &str, root: &Path, original: &JobRecord, epoch: RegistryEpoch) -> JobRecord {
	match mode {
		"strict_read" => read_verified_cached_record(root, &original.id).unwrap(),
		"strict_rescan" => scan_idempotent_binding_once(
			root,
			&original.host,
			original.idempotency_key.as_deref().unwrap(),
			&epoch,
			Some(&original.id),
			&|_| Ok(epoch),
			RegistryScanObserver {
				cohort: &mut [],
				after_scan: || {},
			},
		)
		.unwrap()
		.0
		.unwrap(),
		"fresh_lookup" => find_idempotent_in_with_probe(
			root,
			&original.host,
			original.idempotency_key.as_deref().unwrap(),
			&Mutex::new(ReuseHitCache::default()),
			|_| Ok(epoch),
			|| {},
		)
		.unwrap()
		.unwrap(),
		_ => panic!("unknown benchmark mode"),
	}
}

#[test]
#[ignore = "isolated guarded large-receipt CPU benchmark; no remote effects; allocations unmeasured"]
fn guarded_receipt_reads_and_complete_comparisons_benchmark() {
	const CALLS: usize = 64;
	let mut rows = Vec::new();
	for repetition in 0..4 {
		let sizes = if repetition % 2 == 0 {
			[1024, 64 * 1024, 768 * 1024]
		} else {
			[768 * 1024, 64 * 1024, 1024]
		};
		let modes = if repetition % 2 == 0 {
			["strict_read", "strict_rescan", "fresh_lookup"]
		} else {
			["fresh_lookup", "strict_rescan", "strict_read"]
		};
		for size in sizes {
			let (root, original, epoch) = fixture(size);
			for mode in modes {
				for _ in 0..4 {
					let found = lookup(mode, root.path(), &original, epoch);
					assert_eq!(found.id, original.id);
					assert_eq!(found.args, original.args);
				}
				let before = usage();
				let started = Instant::now();
				for _ in 0..CALLS {
					let found = lookup(mode, root.path(), &original, epoch);
					assert_eq!(found.id, original.id);
					assert_eq!(found.args[0].len(), original.args[0].len());
					std::hint::black_box(found);
				}
				let wall = started.elapsed().as_secs_f64();
				let after = usage();
				let row = json!({
					"repetition":repetition, "mode":mode, "receipt_bytes":size,
					"successes":CALLS, "failures":0, "wall_seconds":wall,
					"user_cpu_seconds":after.0-before.0, "system_cpu_seconds":after.1-before.1,
					"cpu_seconds_per_call":((after.0-before.0)+(after.1-before.1))/CALLS as f64,
					"calls_per_second":CALLS as f64/wall, "process_lifetime_maxrss_kib":after.2
				});
				println!("GUARDED_RECEIPT_WAVE {row}");
				std::io::stdout().flush().unwrap();
				rows.push(row);
			}
		}
	}
	println!(
		"GUARDED_RECEIPT_BENCH {}",
		json!({
			"schema":"hepta-guarded-receipt-cpu-v1", "repetitions":4, "calls_per_wave":CALLS,
			"remote_effects":0, "allocations_measured":false, "rows":rows,
			"measurement":"actual guarded file reads/full lookup; fixed epoch; one receipt per registry; fixture and warmups excluded; fresh cache per fresh_lookup",
			"comparison":"run identical harness on control/candidate binaries in interleaved order; not a remote launch or general concurrency benchmark",
			"cpu":"getrusage RUSAGE_SELF delta; run this test alone",
			"rss":"Linux process-lifetime maximum, not allocation count or per-wave peak"
		})
	);
}
