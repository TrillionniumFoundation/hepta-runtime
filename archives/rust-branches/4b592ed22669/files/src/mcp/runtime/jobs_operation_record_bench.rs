// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Isolated A/B receipt decode and retained-route footprint on one immutable input.
use super::*;
use operation_record::read_operation_record_at;
use std::time::Instant;

fn usage() -> (f64, libc::c_long) {
	let mut value: libc::rusage = unsafe { std::mem::zeroed() };
	assert_eq!(unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut value) }, 0);
	let seconds = |v: libc::timeval| v.tv_sec as f64 + v.tv_usec as f64 / 1_000_000.0;
	(
		seconds(value.ru_utime) + seconds(value.ru_stime),
		value.ru_maxrss,
	)
}

fn resident_kib() -> u64 {
	std::fs::read_to_string("/proc/self/status")
		.unwrap()
		.lines()
		.find_map(|line| line.strip_prefix("VmRSS:"))
		.unwrap()
		.split_whitespace()
		.next()
		.unwrap()
		.parse()
		.unwrap()
}

fn route(record: OperationRecordRef<'_>) -> Value {
	json!({
		"id":record.id,"host":record.host,"ssh_target":record.ssh_target,"unit":record.unit,
		"remote_job_dir":record.remote_job_dir,"request_digest":record.request_digest,
		"execution_mode":record.execution_mode,"system_jobctl":record.system_jobctl
	})
}

#[test]
#[ignore = "isolated local receipt projection A/B; parent supplies immutable fixture; no remote effects"]
fn guarded_operation_receipt_projection_benchmark() {
	let fixture = PathBuf::from(std::env::var("HEPTA_OPERATION_BENCH_FIXTURE").unwrap());
	let id = fixture.file_stem().unwrap().to_str().unwrap();
	let mode = std::env::var("HEPTA_OPERATION_BENCH_MODE").unwrap();
	let pins: usize = std::env::var("HEPTA_OPERATION_BENCH_PINS")
		.unwrap()
		.parse()
		.unwrap();
	let rounds: usize = std::env::var("HEPTA_OPERATION_BENCH_ROUNDS")
		.unwrap()
		.parse()
		.unwrap();
	assert!((1..=64).contains(&pins) && (1..=16).contains(&rounds));
	assert!(matches!(mode.as_str(), "owned" | "projected"));
	let expected = {
		let original = read_record_at(&fixture, id).unwrap();
		route((&original).into())
	};
	let before_hash = Sha256::digest(std::fs::read(&fixture).unwrap());
	let resident_before = resident_kib();
	let before = usage();
	let start = Instant::now();
	let mut resident_pinned_max = resident_before;
	for _ in 0..rounds {
		if mode == "owned" {
			let mut pinned = Vec::with_capacity(pins);
			for _ in 0..pins {
				let record = read_record_at(&fixture, id).unwrap();
				assert_eq!(route((&record).into()), expected);
				pinned.push(record);
			}
			resident_pinned_max = resident_pinned_max.max(resident_kib());
			std::hint::black_box(&pinned);
		} else {
			let mut pinned = Vec::with_capacity(pins);
			for _ in 0..pins {
				let record = read_operation_record_at(&fixture, id).unwrap();
				assert_eq!(route((&record).into()), expected);
				pinned.push(record);
			}
			resident_pinned_max = resident_pinned_max.max(resident_kib());
			std::hint::black_box(&pinned);
		}
	}
	let wall = start.elapsed().as_secs_f64();
	let after = usage();
	assert_eq!(
		Sha256::digest(std::fs::read(&fixture).unwrap()),
		before_hash
	);
	println!(
		"OPERATION_PROJECTION_BENCH {}",
		json!({
			"schema":"hepta-operation-projection-bench/v1","mode":mode,"pins":pins,"rounds":rounds,
			"successes":pins*rounds,"failures":0,"wall_seconds":wall,
			"cpu_seconds":after.0-before.0,"cpu_seconds_per_call":(after.0-before.0)/(pins*rounds) as f64,
			"calls_per_second":(pins*rounds) as f64/wall,
			"resident_before_kib":resident_before,"resident_pinned_max_kib":resident_pinned_max,
			"process_lifetime_maxrss_kib":after.1,"remote_effects":0,
			"fixture_sha256":before_hash.iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
			"measurement":"guarded file read/full schema validation/projected routing equality; held cohort; local warm fixture; not SSH throughput",
			"rss":"Linux current RSS during retained cohort plus process lifetime getrusage peak; fixture baseline owned warmup affects peak"
		})
	);
}
