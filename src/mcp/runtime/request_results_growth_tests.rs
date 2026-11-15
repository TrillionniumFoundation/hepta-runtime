// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Original-result storage growth with private filesystem fixtures only.
//! Low-level stored fixtures do not claim to have passed the provider DTO policy.
use super::*;
use rmcp::model::ContentBlock;
use std::fs::{self, OpenOptions};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

const LEGACY_OWNER_CAPACITY: usize = 128;
const LEGACY_GLOBAL_CAPACITY: usize = 512;

fn request(number: u64, owner_number: u64, tool_name: &str) -> RequestIdentity {
	RequestIdentity {
		request_id: format!("{number:064x}"),
		owner: format!("{owner_number:064x}"),
		tool_name: tool_name.into(),
		accepted_unix_ms: 10_000 + number as u128,
	}
}

fn binding() -> String {
	"b".repeat(64)
}

fn private_root() -> tempfile::TempDir {
	let root = tempfile::tempdir().unwrap();
	fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
	root
}

fn private_write(path: &Path, raw: &[u8]) {
	let mut file = OpenOptions::new()
		.write(true)
		.create_new(true)
		.mode(0o600)
		.open(path)
		.unwrap();
	file.write_all(raw).unwrap();
	file.sync_all().unwrap();
}

fn audit(root: &Path, identity: &RequestIdentity) {
	let path = root.join("request-audit");
	if !path.exists() {
		fs::create_dir(&path).unwrap();
		fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
	}
	private_write(
		&path.join(format!("{}.json", identity.request_id)),
		&serde_json::to_vec(&json!({
			"request_id": identity.request_id, "owner": identity.owner,
			"tool_name": identity.tool_name, "state": "unknown",
			"accepted_unix_ms": identity.accepted_unix_ms, "elapsed_ms": null
		}))
		.unwrap(),
	);
}

fn original_result(identity: &RequestIdentity) -> CallToolResult {
	let text = json!({"fixture_original": identity.request_id,
		"tool": identity.tool_name, "text": "中文 🦊\noriginal bytes"});
	let mut result = Ok(CallToolResult::success(vec![ContentBlock::text(
		serde_json::to_string_pretty(&text).unwrap(),
	)])
	.into());
	attach_identity(&mut result, &identity.request_id);
	match result.unwrap() {
		CallToolResponse::Complete(result) => result,
		_ => panic!("fixture must have a complete envelope"),
	}
}

fn original_record(identity: &RequestIdentity) -> (Record, Vec<u8>) {
	let bytes = serde_json::to_vec(&original_result(identity)).unwrap();
	let record = Record {
		request_id: identity.request_id.clone(),
		owner: identity.owner.clone(),
		tool_name: identity.tool_name.clone(),
		accepted_unix_ms: identity.accepted_unix_ms,
		policy_binding: binding(),
		state: ResultState::Stored,
		payload_base64: Some(base64(&bytes)),
		payload_bytes: Some(bytes.len()),
		payload_sha256: Some(digest(&bytes)),
	};
	(record, bytes)
}

fn store_original(mut intent: ResultIntent) -> Vec<u8> {
	let identity = RequestIdentity {
		request_id: intent.record.request_id.clone(),
		owner: intent.record.owner.clone(),
		tool_name: intent.record.tool_name.clone(),
		accepted_unix_ms: intent.record.accepted_unix_ms,
	};
	let (record, bytes) = original_record(&identity);
	intent.record = record;
	// Match the production STORE_LOCK rule even when other fixture threads admit.
	let _guard = record_lock(&intent.record.request_id).unwrap();
	save(&intent.directory, &intent.record, true).unwrap();
	bytes
}

fn admit_required(root: &Path, identity: &RequestIdentity) -> ResultIntent {
	admit_synchronous_at(root, identity.clone(), binding())
		.unwrap_or_else(|error| panic!("valid growth admission refused: {error:#}"))
		.unwrap_or_else(|| {
			panic!("completed history must not disable new original-result retention")
		})
}

fn retained(root: &Path, identity: &RequestIdentity) -> Record {
	lookup_at(root, identity, &binding())
		.unwrap()
		.unwrap_or_else(|| panic!("original identity was not retained"))
}

fn assert_original(root: &Path, identity: &RequestIdentity, expected: &[u8]) {
	let record = retained(root, identity);
	assert!(record.state == ResultState::Stored);
	let raw = unbase64(record.payload_base64.as_deref().unwrap()).unwrap();
	assert_eq!(raw, expected);
	assert_eq!(record.payload_bytes, Some(expected.len()));
	assert_eq!(record.payload_sha256, Some(digest(expected)));
}

fn record_path(root: &Path, identity: &RequestIdentity) -> PathBuf {
	let name = format!("{}.json", identity.request_id);
	let flat = root.join(STORE_NAME).join(&name);
	if flat.exists() {
		flat
	} else {
		root.join(ARCHIVE_STORE_NAME)
			.join(ARCHIVE_NAME)
			.join(&identity.request_id[..2])
			.join(name)
	}
}

fn pin(path: &Path) -> (u64, u64, u32, u32, u64, Vec<u8>) {
	let metadata = path.symlink_metadata().unwrap();
	assert!(metadata.is_file());
	(
		metadata.dev(),
		metadata.ino(),
		metadata.mode(),
		metadata.uid(),
		metadata.nlink(),
		fs::read(path).unwrap(),
	)
}

fn seed_legacy(root: &Path, count: usize) -> Vec<(RequestIdentity, Vec<u8>)> {
	let directory = open_store(root).unwrap();
	let _guard = store_lock().unwrap();
	(1..=count as u64)
		.map(|number| {
			let tool = if number % 2 == 0 {
				"host_list"
			} else {
				"host_health"
			};
			let identity = request(number, 1, tool);
			audit(root, &identity);
			let (record, bytes) = original_record(&identity);
			save(&directory, &record, false).unwrap();
			(identity, bytes)
		})
		.collect()
}

#[test]
fn completed_owner_history_can_grow_beyond_the_old_128_lifetime_slots() {
	let root = private_root();
	let mut originals = Vec::new();
	for number in 1..=(LEGACY_OWNER_CAPACITY + 19) as u64 {
		let tool = if number % 2 == 0 {
			"host_list"
		} else {
			"host_health"
		};
		let identity = request(number, 1, tool);
		audit(root.path(), &identity);
		let bytes = store_original(admit_required(root.path(), &identity));
		originals.push((identity, bytes));
	}
	for (identity, bytes) in originals {
		assert_original(root.path(), &identity, &bytes);
	}
}

#[test]
fn completed_global_history_can_grow_beyond_512_without_losing_any_result() {
	let root = private_root();
	let mut originals = Vec::new();
	for number in 1..=(LEGACY_GLOBAL_CAPACITY + 19) as u64 {
		let identity = request(number, 1 + number % 4, "host_health");
		audit(root.path(), &identity);
		let bytes = store_original(admit_required(root.path(), &identity));
		originals.push((identity, bytes));
	}
	for (identity, bytes) in originals {
		assert_original(root.path(), &identity, &bytes);
	}
}

#[test]
fn full_legacy_store_grows_in_new_storage_without_rewriting_old_file_identities() {
	let root = private_root();
	let originals = seed_legacy(root.path(), LEGACY_GLOBAL_CAPACITY);
	let pins: Vec<_> = originals
		.iter()
		.map(|(identity, _)| {
			let path = record_path(root.path(), identity);
			let before = pin(&path);
			(path, before)
		})
		.collect();
	for number in 10_000..10_019 {
		let identity = request(number, 1, "host_list");
		audit(root.path(), &identity);
		let bytes = store_original(admit_required(root.path(), &identity));
		assert_original(root.path(), &identity, &bytes);
	}
	for (path, expected) in pins {
		assert_eq!(pin(&path), expected);
	}
	for (identity, bytes) in originals {
		assert_original(root.path(), &identity, &bytes);
	}
}

#[test]
fn reopened_result_handles_preserve_old_and_new_policy_and_identity_bindings() {
	let root = private_root();
	let originals = seed_legacy(root.path(), LEGACY_GLOBAL_CAPACITY);
	let identity = request(10_000, 1, "host_health");
	audit(root.path(), &identity);
	let bytes = store_original(admit_required(root.path(), &identity));
	// No ResultIntent or open result-directory handles survive these lookups.
	for (identity, bytes) in [(&originals[0].0, &originals[0].1), (&identity, &bytes)] {
		assert_original(root.path(), identity, bytes);
		for changed in 0..4 {
			let mut wrong = identity.clone();
			let mut policy = binding();
			match changed {
				0 => wrong.owner = format!("{:064x}", 999),
				1 => wrong.tool_name = "effective_config".into(),
				2 => wrong.accepted_unix_ms += 1,
				_ => policy = "c".repeat(64),
			}
			assert!(lookup_at(root.path(), &wrong, &policy).is_err());
		}
		assert!(admit_synchronous_at(root.path(), identity.clone(), binding()).is_err());
	}
}

#[test]
fn dropped_unknown_identity_survives_growth_without_payload_or_readmission() {
	let root = private_root();
	seed_legacy(root.path(), LEGACY_GLOBAL_CAPACITY - 1);
	let unknown = request(10_000, 1, "host_health");
	audit(root.path(), &unknown);
	drop(admit_required(root.path(), &unknown));
	let path = record_path(root.path(), &unknown);
	let original_pin = pin(&path);
	for number in 20_000..20_019 {
		let identity = request(number, 1, "host_list");
		audit(root.path(), &identity);
		let bytes = store_original(admit_required(root.path(), &identity));
		assert_original(root.path(), &identity, &bytes);
	}
	let record = retained(root.path(), &unknown);
	assert!(record.state == ResultState::Unknown);
	assert!(record.payload_base64.is_none());
	assert!(record.payload_bytes.is_none());
	assert!(record.payload_sha256.is_none());
	assert_eq!(pin(&path), original_pin);
	assert!(admit_synchronous_at(root.path(), unknown, binding()).is_err());
}

#[test]
fn terminal_completions_do_not_create_a_history_count_gate() {
	let root = private_root();
	seed_legacy(root.path(), LEGACY_GLOBAL_CAPACITY);
	for number in 10_000..10_000 + (LEGACY_OWNER_CAPACITY + 19) as u64 {
		let identity = request(number, 1, "host_health");
		audit(root.path(), &identity);
		let intent = admit_required(root.path(), &identity);
		assert_eq!(complete_sync(intent, None).unwrap(), "not_completed");
		assert!(retained(root.path(), &identity).state == ResultState::NotCompleted);
	}
}

#[test]
fn historical_corruption_refuses_its_identity_without_scanning_unrelated_new_admissions() {
	for unsafe_permissions in [false, true] {
		let root = private_root();
		let originals = seed_legacy(root.path(), LEGACY_GLOBAL_CAPACITY);
		let initialized = request(10_000, 1, "host_health");
		audit(root.path(), &initialized);
		drop(admit_required(root.path(), &initialized));
		let path = record_path(root.path(), &originals[0].0);
		if unsafe_permissions {
			fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
		} else {
			fs::write(&path, b"{corrupt-original").unwrap();
		}
		assert!(lookup_at(root.path(), &originals[0].0, &binding()).is_err());
		assert!(admit_synchronous_at(root.path(), originals[0].0.clone(), binding()).is_err());
		// New independent IDs validate their own destination and namespace,
		// rather than reparsing every unrelated original payload on each call.
		let identity = request(20_000, 1, "host_list");
		audit(root.path(), &identity);
		drop(admit_required(root.path(), &identity));
	}
}

#[test]
fn corrupt_archive_anchor_refuses_admission_and_lookup_without_using_a_cached_success() {
	let root = private_root();
	let unknown = request(10_000, 1, "host_health");
	audit(root.path(), &unknown);
	drop(admit_required(root.path(), &unknown));
	let path = root.path().join(ARCHIVE_ANCHOR);
	fs::write(&path, b"{invalid-binding").unwrap();
	let identity = request(20_000, 1, "host_list");
	audit(root.path(), &identity);
	assert!(admit_synchronous_at(root.path(), identity, binding()).is_err());
	assert!(lookup_at(root.path(), &unknown, &binding()).is_err());
}

#[test]
fn replacing_the_admitted_archive_shard_refuses_completion_without_replaying() {
	let root = private_root();
	seed_legacy(root.path(), LEGACY_GLOBAL_CAPACITY);
	let identity = request(10_000, 1, "host_health");
	audit(root.path(), &identity);
	let intent = admit_required(root.path(), &identity);
	let path = record_path(root.path(), &identity);
	let shard = path.parent().unwrap();
	let moved = shard.with_file_name("fixture-original-shard");
	let original_pin = pin(&path);
	fs::rename(shard, &moved).unwrap();
	fs::create_dir(shard).unwrap();
	fs::set_permissions(shard, fs::Permissions::from_mode(0o700)).unwrap();
	assert!(complete_sync(intent, None).is_err());
	assert_eq!(pin(&moved.join(path.file_name().unwrap())), original_pin);
	assert!(!path.exists());
	assert!(lookup_at(root.path(), &identity, &binding()).is_err());
}

#[test]
fn concurrent_32_and_64_new_admissions_keep_independent_original_results() {
	for concurrency in [32, 64] {
		let root = private_root();
		let originals = seed_legacy(root.path(), LEGACY_GLOBAL_CAPACITY);
		let old_path = record_path(root.path(), &originals[0].0);
		let old_pin = pin(&old_path);
		let identities: Vec<_> = (10_000..10_000 + concurrency)
			.map(|number| request(number, 1, "host_health"))
			.collect();
		for identity in &identities {
			audit(root.path(), identity);
		}
		let barrier = std::sync::Arc::new(std::sync::Barrier::new(concurrency as usize));
		let workers: Vec<_> = identities
			.into_iter()
			.map(|identity| {
				let path = root.path().to_path_buf();
				let barrier = barrier.clone();
				std::thread::spawn(move || {
					barrier.wait();
					let bytes = store_original(admit_required(&path, &identity));
					(identity, bytes)
				})
			})
			.collect();
		for worker in workers {
			let (identity, bytes) = worker.join().unwrap();
			assert_original(root.path(), &identity, &bytes);
		}
		assert_eq!(pin(&old_path), old_pin);
	}
}

#[test]
fn targeted_interrupted_archive_link_is_recovered_without_rewriting_original_bytes() {
	let root = private_root();
	seed_legacy(root.path(), LEGACY_GLOBAL_CAPACITY);
	let identity = request(10_000, 1, "host_health");
	audit(root.path(), &identity);
	let bytes = store_original(admit_required(root.path(), &identity));
	let path = record_path(root.path(), &identity);
	let original_pin = pin(&path);
	let staging = path.parent().unwrap().join(format!(
		".{}-{}.tmp",
		identity.request_id, identity.request_id
	));
	fs::hard_link(&path, &staging).unwrap();
	assert_eq!(path.metadata().unwrap().nlink(), 2);
	assert_original(root.path(), &identity, &bytes);
	assert!(!staging.exists());
	assert_eq!(pin(&path), original_pin);
}

#[test]
fn targeted_unpublished_archive_staging_does_not_invent_a_receipt() {
	let root = private_root();
	seed_legacy(root.path(), LEGACY_GLOBAL_CAPACITY);
	let identity = request(10_000, 1, "host_health");
	audit(root.path(), &identity);
	let bytes = store_original(admit_required(root.path(), &identity));
	let path = record_path(root.path(), &identity);
	let original_pin = pin(&path);
	let absent = request(20_000, 1, "host_health");
	let staging = path
		.parent()
		.unwrap()
		.join(format!(".{}-{}.tmp", absent.request_id, absent.request_id));
	private_write(&staging, b"partial unpublished result fixture");
	assert_eq!(staging.metadata().unwrap().nlink(), 1);
	assert!(lookup_at(root.path(), &absent, &binding())
		.unwrap()
		.is_none());
	assert!(!staging.exists());
	assert!(!record_path(root.path(), &absent).exists());
	assert_original(root.path(), &identity, &bytes);
	assert_eq!(pin(&path), original_pin);
}

#[test]
fn removing_archive_and_anchor_does_not_reinitialize_marked_legacy_history() {
	let root = private_root();
	seed_legacy(root.path(), LEGACY_GLOBAL_CAPACITY);
	let identity = request(10_000, 1, "host_health");
	audit(root.path(), &identity);
	drop(admit_required(root.path(), &identity));
	let path = record_path(root.path(), &identity);
	let original_pin = pin(&path);
	let relative = path
		.strip_prefix(root.path().join(ARCHIVE_STORE_NAME))
		.unwrap()
		.to_path_buf();
	assert!(root.path().join(STORE_NAME).join(ARCHIVE_MARKER).is_file());
	let moved = root.path().join("fixture-moved-v2");
	fs::rename(root.path().join(ARCHIVE_STORE_NAME), &moved).unwrap();
	fs::rename(
		root.path().join(ARCHIVE_ANCHOR),
		root.path().join("fixture-moved-anchor"),
	)
	.unwrap();
	let next = request(20_000, 1, "host_list");
	audit(root.path(), &next);
	assert!(admit_synchronous_at(root.path(), next, binding()).is_err());
	assert!(lookup_at(root.path(), &identity, &binding()).is_err());
	assert!(!root.path().join(ARCHIVE_STORE_NAME).exists());
	assert!(!root.path().join(ARCHIVE_ANCHOR).exists());
	assert_eq!(pin(&moved.join(relative)), original_pin);
}

#[test]
fn more_than_1024_unknown_receipts_do_not_block_new_identity_or_replay_old_identity() {
	let root = private_root();
	let mut originals = Vec::new();
	for number in 1..=1041 {
		let identity = request(number, 1, "host_health");
		audit(root.path(), &identity);
		drop(admit_required(root.path(), &identity));
		let path = record_path(root.path(), &identity);
		originals.push((identity, path.clone(), pin(&path)));
	}
	for (identity, path, before) in originals {
		let record = retained(root.path(), &identity);
		assert!(record.state == ResultState::Unknown && record.payload_base64.is_none());
		assert_eq!(pin(&path), before);
		assert!(admit_synchronous_at(root.path(), identity, binding()).is_err());
	}
	let next = request(20_000, 1, "host_list");
	audit(root.path(), &next);
	let bytes = store_original(admit_required(root.path(), &next));
	assert_original(root.path(), &next, &bytes);
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "explicit isolated storage throughput measurement; run separately from functional suites"]
fn durable_result_storage_parallel_throughput_benchmark() {
	use std::sync::{
		atomic::{AtomicUsize, Ordering},
		Arc, Barrier,
	};
	use std::time::Instant;
	fn usage() -> (f64, i64) {
		let mut value: libc::rusage = unsafe { std::mem::zeroed() };
		assert_eq!(unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut value) }, 0);
		let cpu = value.ru_utime.tv_sec as f64
			+ value.ru_utime.tv_usec as f64 / 1e6
			+ value.ru_stime.tv_sec as f64
			+ value.ru_stime.tv_usec as f64 / 1e6;
		(cpu, value.ru_maxrss)
	}
	fn distributed(number: u64) -> RequestIdentity {
		let mut identity = request(number, 1, "host_health");
		identity.request_id = format!("{:02x}{number:062x}", number % 256);
		identity
	}
	fn percentile(values: &[f64], fraction: f64) -> f64 {
		let mut ordered = values.to_vec();
		ordered.sort_by(f64::total_cmp);
		ordered[((ordered.len() as f64 * fraction).ceil() as usize).saturating_sub(1)]
	}
	for concurrency in [32_usize, 64] {
		let root = private_root();
		for number in 1..=1024 {
			let identity = distributed(number);
			audit(root.path(), &identity);
			drop(admit_required(root.path(), &identity));
		}
		let per_worker = 16;
		let identities: Vec<_> = (10_000..10_000 + (concurrency * per_worker) as u64)
			.map(distributed)
			.collect();
		for identity in &identities {
			audit(root.path(), identity);
		}
		let start = Arc::new(Barrier::new(concurrency + 1));
		let active = Arc::new(AtomicUsize::new(0));
		let peak = Arc::new(AtomicUsize::new(0));
		let workers: Vec<_> = identities
			.chunks(per_worker)
			.map(|batch| {
				let batch = batch.to_vec();
				let path = root.path().to_path_buf();
				let (start, active, peak) = (start.clone(), active.clone(), peak.clone());
				std::thread::spawn(move || {
					start.wait();
					batch
						.into_iter()
						.enumerate()
						.map(|(index, identity)| {
							let inflight = active.fetch_add(1, Ordering::SeqCst) + 1;
							peak.fetch_max(inflight, Ordering::SeqCst);
							let began = Instant::now();
							let intent = admit_required(&path, &identity);
							let stored = index % 4 != 0;
							if stored {
								let bytes = store_original(intent);
								assert_original(&path, &identity, &bytes);
							} else {
								drop(intent);
								assert!(retained(&path, &identity).state == ResultState::Unknown);
							}
							let milliseconds = began.elapsed().as_secs_f64() * 1000.;
							active.fetch_sub(1, Ordering::SeqCst);
							(milliseconds, stored)
						})
						.collect::<Vec<_>>()
				})
			})
			.collect();
		let cpu_before = usage().0;
		let began = Instant::now();
		start.wait();
		let observations: Vec<_> = workers
			.into_iter()
			.flat_map(|w| w.join().unwrap())
			.collect();
		let wall = began.elapsed().as_secs_f64();
		let (cpu_after, peak_rss_kib) = usage();
		let all: Vec<_> = observations.iter().map(|(latency, _)| *latency).collect();
		let stored: Vec<_> = observations
			.iter()
			.filter_map(|(latency, stored)| stored.then_some(*latency))
			.collect();
		println!(
			"HEPTA_RESULT_STORAGE_BENCH {}",
			json!({"scope":"low-level durable storage only; no provider DTO/HTTP/SSH",
				"concurrency":concurrency,"actual_peak_inflight":peak.load(Ordering::SeqCst),
				"unknown_receipts_present_before_load":1024,"attempted":all.len(),"accepted":all.len(),
				"stored_originals":stored.len(),"new_unknowns":all.len()-stored.len(),
				"wall_seconds":wall,"durable_operations_per_second":all.len() as f64/wall,
				"stored_originals_per_second":stored.len() as f64/wall,
				"all_latency_ms_p50":percentile(&all,0.5),"all_latency_ms_p95":percentile(&all,0.95),
				"stored_latency_ms_p50":percentile(&stored,0.5),"stored_latency_ms_p95":percentile(&stored,0.95),
				"cpu_seconds":cpu_after-cpu_before,"peak_rss_kib":peak_rss_kib,
				"fast_refusals_counted_as_success":false})
		);
	}
}
