// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Isolated guarded inventory reads; identical harness for two pinned libtest builds.
use super::*;
use std::os::unix::fs::PermissionsExt;
use std::sync::Barrier;
use std::time::Instant;

const RECORDS: usize = 128;

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

fn option(name: &str, fallback: usize) -> usize {
	std::env::var(name)
		.map(|value| value.parse().expect("invalid inventory benchmark integer"))
		.unwrap_or(fallback)
}

fn file_digest(path: &Path) -> String {
	let mut file = File::open(path).unwrap();
	let mut digest = Sha256::new();
	let mut buffer = [0; 64 * 1024];
	loop {
		let count = file.read(&mut buffer).unwrap();
		if count == 0 {
			break;
		}
		digest.update(&buffer[..count]);
	}
	digest
		.finalize()
		.iter()
		.map(|byte| format!("{byte:02x}"))
		.collect()
}

fn public_row(index: usize) -> Value {
	json!({
		"id":format!("inventory-bench-{index:04}"),
		"host":if index.is_multiple_of(2) { "main" } else { "other" },
		"created_unix_ms":index + 1, "execution_mode":"operator", "launch_state":"launched"
	})
}

fn fixture(payload: usize) -> (Option<tempfile::TempDir>, PathBuf) {
	if let Ok(path) = std::env::var("HEPTA_INVENTORY_BENCH_FIXTURE") {
		let path = PathBuf::from(path);
		assert_eq!(path.canonicalize().unwrap(), path);
		return (None, path);
	}
	let root = tempfile::tempdir().unwrap();
	let path = root.path().canonicalize().unwrap();
	let jobs = path.join("jobs");
	std::fs::create_dir(&jobs).unwrap();
	std::fs::set_permissions(&jobs, std::fs::Permissions::from_mode(0o700)).unwrap();
	let mut manifest = BTreeMap::new();
	for index in 0..RECORDS {
		let row = public_row(index);
		let record = json!({
			"execution_mode":"operator", "system_jobctl":false,
			"id":row["id"], "host":row["host"], "created_unix_ms":row["created_unix_ms"],
			"ssh_target":"never-connect.invalid", "unit":"inventory-bench-unit",
			"remote_job_dir":"/never-launch/inventory-bench", "executable":"/usr/bin/true",
			"args":["x".repeat(payload), "escaped\n中文\\\""], "cwd":null, "env_keys":["EXAMPLE"],
			"idempotency_key":format!("inventory-key-{index:04}"), "request_fingerprint":1,
			"request_digest":"a".repeat(64), "launch_state":"launched", "launch_error":null
		});
		let name = format!("inventory-bench-{index:04}.json");
		let raw = serde_json::to_vec(&record).unwrap();
		let item = jobs.join(&name);
		std::fs::write(&item, &raw).unwrap();
		std::fs::set_permissions(&item, std::fs::Permissions::from_mode(0o600)).unwrap();
		manifest.insert(name, json!({"sha256":file_digest(&item),"bytes":raw.len()}));
	}
	std::fs::write(
		path.join("fixture.json"),
		serde_json::to_vec(&json!({"schema":"hepta-inventory-bench-fixture/v1",
			"records":RECORDS,"payload_bytes":payload,"files":manifest}))
		.unwrap(),
	)
	.unwrap();
	(Some(root), path)
}

fn verify_fixture(root: &Path, payload: usize) -> (String, u64) {
	let path = root.join("fixture.json");
	let hash = file_digest(&path);
	if let Ok(expected) = std::env::var("HEPTA_INVENTORY_BENCH_FIXTURE_SHA256") {
		assert_eq!(hash, expected);
	}
	let manifest: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
	assert_eq!(manifest["schema"], "hepta-inventory-bench-fixture/v1");
	assert_eq!(manifest["records"], RECORDS);
	assert_eq!(manifest["payload_bytes"], payload);
	let files = manifest["files"].as_object().unwrap();
	assert_eq!(files.len(), RECORDS);
	assert_eq!(
		std::fs::read_dir(root.join("jobs")).unwrap().count(),
		RECORDS
	);
	let mut total = 0;
	for index in 0..RECORDS {
		let name = format!("inventory-bench-{index:04}.json");
		let file = root.join("jobs").join(&name);
		let bytes = std::fs::metadata(&file).unwrap().len();
		assert_eq!(files[&name]["bytes"].as_u64(), Some(bytes));
		assert_eq!(files[&name]["sha256"], file_digest(&file));
		total += bytes;
	}
	assert!(total < InventoryLimits::default().bytes);
	(hash, total)
}

fn read_inventory(root: &Path, mode: &str) -> Result<String> {
	match mode {
		"list" => job_inventory_rows_response(&list_job_rows_in(&root.join("jobs"), None)?),
		"page" => page_job_rows(
			&inventory_page_rows_at(root, None, InventoryLimits::default())?,
			&ProcessListPageParams {
				host: None,
				cursor: None,
				limit: Some(RECORDS as u16),
			},
			root.to_str().unwrap(),
		),
		_ => panic!("inventory benchmark mode must be list or page"),
	}
}

fn verify_result(text: &str, expected: &Value, mode: &str) {
	let value: Value = serde_json::from_str(text).unwrap();
	assert_eq!(&value["jobs"], expected);
	assert_eq!(value["total"], RECORDS);
	assert_eq!(value["inventory_complete"], true);
	assert_eq!(value["status_authoritative"], false);
	if mode == "page" {
		assert_eq!(value["has_more"], false);
		assert!(value["next_cursor"].is_null());
		assert_eq!(value["snapshot_sha256"].as_str().unwrap().len(), 64);
	}
}

#[test]
#[ignore = "isolated 128-receipt inventory benchmark; select one payload/mode/concurrency per process"]
fn guarded_inventory_reads_benchmark() {
	let payload = option("HEPTA_INVENTORY_BENCH_PAYLOAD_BYTES", 1024);
	let concurrency = option("HEPTA_INVENTORY_BENCH_CONCURRENCY", 1);
	let calls = option("HEPTA_INVENTORY_BENCH_CALLS_PER_WORKER", 4);
	let mode = std::env::var("HEPTA_INVENTORY_BENCH_MODE").unwrap_or_else(|_| "list".into());
	assert!([1024, 64 * 1024, 768 * 1024].contains(&payload));
	assert!([1, 4, 8].contains(&concurrency));
	assert!((1..=32).contains(&calls));
	assert!(["list", "page"].contains(&mode.as_str()));
	let (_owned_fixture, root) = fixture(payload);
	let original = verify_fixture(&root, payload);
	let expected = Arc::new(Value::Array((0..RECORDS).map(public_row).collect()));
	let warmup = read_inventory(&root, &mode).unwrap();
	verify_result(&warmup, &expected, &mode);
	let response_sha256: String = Sha256::digest(warmup.as_bytes())
		.iter()
		.map(|byte| format!("{byte:02x}"))
		.collect();
	drop(warmup);
	let runtime = Arc::new(
		tokio::runtime::Builder::new_multi_thread()
			.worker_threads(2)
			.max_blocking_threads(MAX_INVENTORY_READ_WORKERS)
			.enable_all()
			.build()
			.unwrap(),
	);
	let slots = Arc::new(Semaphore::new(MAX_INVENTORY_READ_WORKERS));
	let barrier = Arc::new(Barrier::new(concurrency + 1));
	let mut workers = Vec::new();
	for worker in 0..concurrency {
		let (root, mode, expected, runtime, slots, barrier) = (
			root.clone(),
			mode.clone(),
			expected.clone(),
			runtime.clone(),
			slots.clone(),
			barrier.clone(),
		);
		workers.push(std::thread::spawn(move || {
			barrier.wait();
			let mut latencies = Vec::new();
			for call in 0..calls {
				let (path, selected) = (root.clone(), mode.clone());
				let started = Instant::now();
				let result = runtime
					.block_on(run_inventory_read(slots.clone(), move || {
						read_inventory(&path, &selected)
					}))
					.unwrap();
				let elapsed = started.elapsed().as_secs_f64() * 1000.0;
				verify_result(&result, &expected, &mode);
				latencies.push(json!({"worker":worker,"call":call,"latency_ms":elapsed}));
			}
			latencies
		}));
	}
	let before = usage();
	let started = Instant::now();
	barrier.wait();
	let samples: Vec<_> = workers
		.into_iter()
		.flat_map(|worker| worker.join().unwrap())
		.collect();
	let wall = started.elapsed().as_secs_f64();
	let after = usage();
	assert_eq!(samples.len(), concurrency * calls);
	assert_eq!(slots.available_permits(), MAX_INVENTORY_READ_WORKERS);
	assert_eq!(verify_fixture(&root, payload), original);
	let result = json!({
		"schema":"hepta-inventory-read-bench/v1", "records":RECORDS,
		"mode":mode,"payload_bytes":payload,"concurrency":concurrency,
		"calls_per_worker":calls,"successes":samples.len(),"failures":0,
		"physical_read_workers":MAX_INVENTORY_READ_WORKERS,"tokio_workers":2,
		"fixture_sha256":original.0,"fixture_bytes":original.1,"fixture_unchanged":true,
		"public_identity_checked_each_call":true,"response_sha256":response_sha256,
		"wall_seconds":wall,"user_cpu_seconds":after.0-before.0,"system_cpu_seconds":after.1-before.1,
		"process_lifetime_maxrss_kib":after.2,"latencies":samples,"remote_effects":0,
		"timing":"barrier through original joins; includes response identity checks; fixture/warmup excluded",
		"latency":"read-worker admission through guarded scan/projection/wire return; excludes response checking",
		"cpu":"RUSAGE_SELF measurement delta; isolated libtest process",
		"rss":"Linux process-lifetime maximum, including fixture verification/warmup; not measurement-only",
		"cache":"full fixture hash verification and one inventory warmup precede measurement; not cold disk",
		"scope":"local 128-receipt inventory paths and four-worker bound; not SSH or full MCP throughput"
	});
	println!("INVENTORY_READ_BENCH {result}");
	std::io::stdout().flush().unwrap();
}
