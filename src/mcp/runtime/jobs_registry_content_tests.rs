// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! In-place receipt mutations invalidate reuse without weakening original ownership.
use super::*;
use std::cell::RefCell;
use std::os::unix::fs::{MetadataExt, PermissionsExt};

thread_local! {
	static AFTER_CACHED_STAT: RefCell<Option<Box<dyn FnOnce()>>> = const { RefCell::new(None) };
}

pub(super) fn after_cached_stat() {
	let hook = AFTER_CACHED_STAT.with(|slot| slot.borrow_mut().take());
	if let Some(hook) = hook {
		hook();
	}
}

struct CachedStatHook;

impl CachedStatHook {
	fn set(hook: impl FnOnce() + 'static) -> Self {
		AFTER_CACHED_STAT.with(|slot| {
			assert!(slot.borrow_mut().replace(Box::new(hook)).is_none());
		});
		Self
	}
}

impl Drop for CachedStatHook {
	fn drop(&mut self) {
		AFTER_CACHED_STAT.with(|slot| {
			slot.borrow_mut().take();
		});
	}
}

fn record(id: &str, key: &str) -> JobRecord {
	JobRecord {
		execution_mode: ExecutionMode::Operator,
		system_jobctl: false,
		id: id.to_owned(),
		host: "main".to_owned(),
		ssh_target: "never-connect.invalid".to_owned(),
		unit: format!("hepta-runtime-job-{id}"),
		remote_job_dir: format!("/never-launch/jobs/{id}"),
		executable: "/usr/bin/true".to_owned(),
		args: Vec::new(),
		cwd: None,
		env_keys: Vec::new(),
		created_unix_ms: 1,
		idempotency_key: Some(key.to_owned()),
		request_fingerprint: 1,
		request_digest: Some("a".repeat(64)),
		launch_state: "launched".to_owned(),
		launch_error: None,
	}
}

fn fixture() -> (
	tempfile::TempDir,
	Mutex<ReuseHitCache>,
	JobRecord,
	JobRecord,
) {
	let root = tempfile::tempdir().unwrap();
	let first = record("first-original", "first-key");
	let second = record("second-original", "other-key");
	for original in [&first, &second] {
		save_record_at(&root.path().join(format!("{}.json", original.id)), original).unwrap();
	}
	let cache = Mutex::new(ReuseHitCache::default());
	let found = find_idempotent_in(root.path(), "main", "first-key", &cache)
		.unwrap()
		.unwrap();
	assert_eq!(found.id, first.id);
	assert_eq!(
		cache.lock().unwrap().hits.len(),
		usize::from(registry_has_content_watch(
			&registry_epoch(root.path()).unwrap()
		))
	);
	(root, cache, first, second)
}

fn rewrite(path: &Path, bytes: &[u8]) {
	let before = std::fs::metadata(path).unwrap();
	let mut file = OpenOptions::new()
		.write(true)
		.truncate(true)
		.open(path)
		.unwrap();
	file.write_all(bytes).unwrap();
	file.sync_all().unwrap();
	assert_eq!(before.ino(), file.metadata().unwrap().ino());
}

fn directory_stamp(root: &Path) -> (u64, i64, i64, i64, i64) {
	let metadata = std::fs::metadata(root).unwrap();
	(
		metadata.ino(),
		metadata.mtime(),
		metadata.mtime_nsec(),
		metadata.ctime(),
		metadata.ctime_nsec(),
	)
}

#[test]
fn hot_reuse_rejects_another_original_rebound_in_place() {
	let (root, cache, first, mut second) = fixture();
	let original = std::fs::read(root.path().join(format!("{}.json", first.id))).unwrap();
	let directory = directory_stamp(root.path());
	second.idempotency_key = first.idempotency_key.clone();
	rewrite(
		&root.path().join(format!("{}.json", second.id)),
		&serde_json::to_vec(&second).unwrap(),
	);
	assert_eq!(directory, directory_stamp(root.path()));
	for _ in 0..2 {
		let error = find_idempotent_in(root.path(), "main", "first-key", &cache)
			.unwrap_err()
			.to_string();
		assert!(error.contains("duplicate original"), "{error}");
	}
	assert_eq!(
		std::fs::read(root.path().join(format!("{}.json", first.id))).unwrap(),
		original
	);
}

#[test]
fn hot_reuse_rejects_another_original_corrupted_in_place() {
	let (root, cache, _, second) = fixture();
	let directory = directory_stamp(root.path());
	rewrite(&root.path().join(format!("{}.json", second.id)), b"{torn");
	assert_eq!(directory, directory_stamp(root.path()));
	for _ in 0..2 {
		let error = find_idempotent_in(root.path(), "main", "first-key", &cache)
			.unwrap_err()
			.to_string();
		assert!(error.contains("corrupt job record"), "{error}");
	}
}

#[test]
fn post_enumeration_in_place_binding_change_cannot_authorize_a_new_job() {
	let (root, _, _, mut second) = fixture();
	let path = root.path().join(format!("{}.json", second.id));
	let directory = directory_stamp(root.path());
	let mut attempts = 0;
	let found = scan_idempotent_binding_in_with_retries(root.path(), "main", "new-key", |round| {
		attempts += 1;
		if round == 0 {
			second.idempotency_key = Some("new-key".to_owned());
			rewrite(&path, &serde_json::to_vec(&second).unwrap());
		}
	})
	.unwrap()
	.unwrap();
	assert_eq!(directory, directory_stamp(root.path()));
	assert_eq!(attempts, 2);
	assert_eq!(found.id, second.id);
	assert_eq!(found.idempotency_key.as_deref(), Some("new-key"));
}

#[test]
fn content_invalidation_cannot_downgrade_a_strict_original_to_legacy_permissions() {
	let (root, cache, first, _) = fixture();
	retain_strict_history(root.path(), &cache, &first);
	let path = root.path().join(format!("{}.json", first.id));
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
	for _ in 0..2 {
		let error = find_idempotent_in(root.path(), "main", "first-key", &cache)
			.unwrap_err()
			.to_string();
		assert!(error.contains("permissions unsafe"), "{error}");
	}
	assert_eq!(std::fs::metadata(path).unwrap().mode() & 0o777, 0o644);
	assert!(cache.lock().unwrap().known[&("main".into(), "first-key".into())].strict);
}

#[test]
fn unavailable_content_watch_revalidates_every_receipt_without_timestamp_authority() {
	let (root, _, _, mut second) = fixture();
	let fingerprint =
		|| scan_registry_records(root.path(), "main", "not-present", true).map(|scan| scan.1);
	let before = fingerprint().unwrap();
	assert_eq!(before, fingerprint().unwrap());
	let path = root.path().join(format!("{}.json", second.id));
	let modified = std::fs::metadata(&path).unwrap().modified().unwrap();
	let directory = directory_stamp(root.path());
	second.idempotency_key = Some("first-key".to_owned());
	rewrite(&path, &serde_json::to_vec(&second).unwrap());
	File::options()
		.write(true)
		.open(&path)
		.unwrap()
		.set_times(std::fs::FileTimes::new().set_modified(modified))
		.unwrap();
	assert_eq!(directory, directory_stamp(root.path()));
	assert_ne!(before, fingerprint().unwrap());
	rewrite(&path, b"not-json");
	assert!(fingerprint().is_err());
}

fn no_content_watch(root: &Path) -> Result<RegistryEpoch> {
	let mut epoch = registry_epoch(root)?;
	epoch.content = None;
	Ok(epoch)
}

fn retain_strict_history(root: &Path, cache: &Mutex<ReuseHitCache>, original: &JobRecord) {
	// Represent a previously verified cache binding even on a platform that
	// cannot currently provide a content watch. No test depends on watch limits.
	read_verified_cached_record(root, &original.id).unwrap();
	cache
		.lock()
		.unwrap()
		.known
		.get_mut(&(
			original.host.clone(),
			original.idempotency_key.clone().unwrap(),
		))
		.unwrap()
		.strict = true;
}

#[test]
fn strict_original_widened_after_initial_check_is_refused_after_rescan() {
	for fallback in [false, true] {
		let (root, cache, first, _) = fixture();
		retain_strict_history(root.path(), &cache, &first);
		let path = root.path().join(format!("{}.json", first.id));
		let directory = directory_stamp(root.path());
		let mut injected = false;
		let probe = |dir: &Path| {
			if fallback {
				no_content_watch(dir)
			} else {
				registry_epoch(dir)
			}
		};
		let error =
			find_idempotent_in_with_probe(root.path(), "main", "first-key", &cache, probe, || {
				injected = true;
				std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
			})
			.unwrap_err()
			.to_string();
		assert!(injected);
		assert!(error.contains("permissions unsafe"), "{error}");
		assert_eq!(directory, directory_stamp(root.path()));
		assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o644);
		assert!(cache.lock().unwrap().known[&("main".into(), "first-key".into())].strict);
	}
}

#[test]
fn fallback_scan_detects_in_place_binding_change_before_authorizing_absence() {
	let (root, _, _, mut second) = fixture();
	let path = root.path().join(format!("{}.json", second.id));
	let original_modified = std::fs::metadata(&path).unwrap().modified().unwrap();
	let directory = directory_stamp(root.path());
	let mut attempts = 0;
	let found = scan_idempotent_binding_with_probe(
		root.path(),
		"main",
		"new-key",
		None,
		&no_content_watch,
		|attempt| {
			attempts += 1;
			if attempt == 0 {
				second.idempotency_key = Some("new-key".to_owned());
				rewrite(&path, &serde_json::to_vec(&second).unwrap());
				File::options()
					.write(true)
					.open(&path)
					.unwrap()
					.set_times(std::fs::FileTimes::new().set_modified(original_modified))
					.unwrap();
			}
		},
	)
	.unwrap()
	.unwrap();
	assert_eq!(found.id, second.id);
	assert_eq!(attempts, 2);
	assert_eq!(directory, directory_stamp(root.path()));
}

#[test]
fn fallback_second_scan_refuses_a_new_duplicate_or_corrupt_original() {
	for corrupt in [false, true] {
		let (root, _, first, mut second) = fixture();
		let path = root.path().join(format!("{}.json", second.id));
		let mut attempts = 0;
		let error = scan_idempotent_binding_with_probe(
			root.path(),
			"main",
			"first-key",
			None,
			&no_content_watch,
			|_| {
				attempts += 1;
				if corrupt {
					rewrite(&path, b"{torn");
				} else {
					second.idempotency_key = first.idempotency_key.clone();
					rewrite(&path, &serde_json::to_vec(&second).unwrap());
				}
			},
		)
		.unwrap_err()
		.to_string();
		assert_eq!(attempts, 1, "invalid historical receipts are never retried");
		let expected = if corrupt {
			"corrupt job record"
		} else {
			"duplicate original"
		};
		assert!(error.contains(expected), "{error}");
	}
}

#[test]
fn fallback_keeps_known_ownership_without_retaining_positive_hits() {
	let (root, _, first, mut second) = fixture();
	let cache = Mutex::new(ReuseHitCache::default());
	for _ in 0..2 {
		let found = find_idempotent_in_with_probe(
			root.path(),
			"main",
			"first-key",
			&cache,
			no_content_watch,
			|| {},
		)
		.unwrap()
		.unwrap();
		assert_eq!(found.id, first.id);
		assert!(cache.lock().unwrap().hits.is_empty());
		assert_eq!(cache.lock().unwrap().known.len(), 1);
	}
	second.idempotency_key = first.idempotency_key.clone();
	rewrite(
		&root.path().join(format!("{}.json", second.id)),
		&serde_json::to_vec(&second).unwrap(),
	);
	let error = find_idempotent_in_with_probe(
		root.path(),
		"main",
		"first-key",
		&cache,
		no_content_watch,
		|| {},
	)
	.unwrap_err()
	.to_string();
	assert!(error.contains("duplicate original"), "{error}");
}

#[test]
fn fallback_churn_exhausts_the_original_three_attempt_budget() {
	let (root, _, _, mut second) = fixture();
	let path = root.path().join(format!("{}.json", second.id));
	let mut attempts = 0;
	let error = scan_idempotent_binding_with_probe(
		root.path(),
		"main",
		"absent-key",
		None,
		&no_content_watch,
		|_| {
			attempts += 1;
			second.created_unix_ms += 1;
			rewrite(&path, &serde_json::to_vec(&second).unwrap());
		},
	)
	.unwrap_err();
	assert_eq!(attempts, MAX_IDEMPOTENCY_SCAN_ATTEMPTS);
	assert!(error.downcast_ref::<RegistryScanChanged>().is_some());
}

#[test]
fn compatible_legacy_receipts_are_never_falsely_promoted_to_strict_hits() {
	for large in [false, true] {
		let root = tempfile::tempdir().unwrap();
		let mut original = record("legacy-original", "legacy-key");
		if large {
			original
				.args
				.push("x".repeat(MAX_CACHED_RECORD_BYTES as usize + 1));
		}
		let path = root.path().join("legacy-original.json");
		save_record_at(&path, &original).unwrap();
		if large {
			let size = std::fs::metadata(&path).unwrap().len();
			assert!(size > MAX_CACHED_RECORD_BYTES && size <= MAX_JOB_RECORD_BYTES);
		} else {
			std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
		}
		read_record_at(&path, &original.id).unwrap();
		assert!(read_verified_cached_record(root.path(), &original.id).is_err());
		let cache = Mutex::new(ReuseHitCache::default());
		for _ in 0..2 {
			let found = find_idempotent_in(root.path(), "main", "legacy-key", &cache)
				.unwrap()
				.unwrap();
			assert_eq!(found.id, original.id);
			assert_eq!(found.args, original.args);
			let guard = cache.lock().unwrap();
			assert!(guard.hits.is_empty());
			assert_eq!(guard.known.len(), 1);
			let binding = &guard.known[&("main".to_owned(), "legacy-key".to_owned())];
			assert_eq!(binding.id, original.id);
			assert!(!binding.strict);
		}
	}
}

#[test]
fn strict_cached_reader_rejects_fifo_swap_without_blocking() {
	const CHILD: &str = "HEPTA_TEST_CACHED_READER_FIFO_CHILD";
	if std::env::var_os(CHILD).is_none() {
		// A regression must fail within this isolated child, not hang libtest or
		// leave an unreapable worker holding one of the four registry permits.
		let full = concat!(
			module_path!(),
			"::strict_cached_reader_rejects_fifo_swap_without_blocking"
		);
		let name = full.split_once("::").unwrap().1;
		let mut child = std::process::Command::new(std::env::current_exe().unwrap())
			.args([name, "--exact", "--nocapture", "--test-threads=1"])
			.env(CHILD, "1")
			.stdout(std::process::Stdio::piped())
			.stderr(std::process::Stdio::piped())
			.spawn()
			.unwrap();
		let deadline = std::time::Instant::now() + Duration::from_secs(5);
		let completed = loop {
			if child.try_wait().unwrap().is_some() {
				break true;
			}
			if std::time::Instant::now() >= deadline {
				child.kill().unwrap();
				break false;
			}
			std::thread::sleep(Duration::from_millis(10));
		};
		let output = child.wait_with_output().unwrap();
		assert!(
			completed,
			"strict cached reader blocked after the FIFO swap; isolated child killed"
		);
		assert!(
			output.status.success(),
			"stdout={} stderr={}",
			String::from_utf8_lossy(&output.stdout),
			String::from_utf8_lossy(&output.stderr)
		);
		assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"));
		return;
	}
	use std::os::unix::ffi::OsStrExt;
	let root = tempfile::tempdir().unwrap();
	let original = record("fifo-original", "fifo-key");
	let path = root.path().join("fifo-original.json");
	save_record_at(&path, &original).unwrap();
	let _hook = CachedStatHook::set(move || {
		std::fs::remove_file(&path).unwrap();
		let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
		assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
	});
	let error = read_verified_cached_record(root.path(), &original.id)
		.unwrap_err()
		.to_string();
	assert!(error.contains("identity changed before read"), "{error}");
}
