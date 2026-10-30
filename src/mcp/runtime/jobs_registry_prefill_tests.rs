// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! A complete cold scan may prefill only independently reverified strict peer identities.
use super::*;
use std::cell::Cell;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::panic::{catch_unwind, AssertUnwindSafe};

fn identity(key: &str) -> (String, String) {
	("fixture".to_owned(), key.to_owned())
}

fn record(key: &str) -> JobRecord {
	serde_json::from_value(json!({
		"execution_mode":"operator", "system_jobctl":false,
		"id":format!("original-{key}"), "host":"fixture",
		"ssh_target":"never-connect.invalid", "unit":format!("unit-{key}"),
		"remote_job_dir":format!("/never-launch/{key}"), "executable":"/usr/bin/true",
		"args":[], "cwd":null, "env_keys":[], "created_unix_ms":1,
		"idempotency_key":key, "request_fingerprint":1,
		"request_digest":"a".repeat(64), "launch_state":"launched", "launch_error":null
	}))
	.unwrap()
}

fn write(root: &Path, record: &JobRecord) {
	save_record_at(&root.join(format!("{}.json", record.id)), record).unwrap();
}

struct Fixture {
	root: tempfile::TempDir,
	cache: Mutex<ReuseHitCache>,
}

impl Fixture {
	fn new(peers: &[&str]) -> Self {
		let fixture = Self {
			root: tempfile::tempdir().unwrap(),
			cache: Mutex::new(ReuseHitCache::default()),
		};
		for key in std::iter::once("leader").chain(peers.iter().copied()) {
			write(fixture.root.path(), &record(key));
		}
		assert!(registry_has_content_watch(
			&registry_epoch(fixture.root.path()).unwrap()
		));
		for key in std::iter::once("leader").chain(peers.iter().copied()) {
			let found = find_idempotent_in(fixture.root.path(), "fixture", key, &fixture.cache)
				.unwrap()
				.unwrap();
			assert_eq!(found.id, format!("original-{key}"));
			assert!(fixture.cache.lock().unwrap().known[&identity(key)].strict);
		}
		fixture
	}

	fn invalidate(&self) -> RegistryEpoch {
		std::fs::write(self.root.path().join("invalidate.marker"), b"changed").unwrap();
		let epoch = registry_epoch(self.root.path()).unwrap();
		// The real entry path performs this invalidation before its cold scan.
		// Helper tests start at that same state, with real strict ownership.
		let mut cache = self.cache.lock().unwrap();
		cache.hits.clear();
		cache.epoch = Some(epoch);
		epoch
	}

	fn scan(&self, peers: &[&str]) -> (RegistryEpoch, Vec<RegistryColdTarget>) {
		let epoch = self.invalidate();
		let mut cohort: Vec<_> = peers
			.iter()
			.map(|key| RegistryColdTarget {
				identity: identity(key),
				seen: false,
				candidate: None,
			})
			.collect();
		let (found, scanned) = scan_idempotent_binding_cohort(
			self.root.path(),
			"fixture",
			"leader",
			Some("original-leader"),
			&registry_epoch,
			RegistryScanObserver {
				cohort: &mut cohort,
				after_scan: |_| {},
			},
		)
		.unwrap();
		assert_eq!(found.unwrap().id, "original-leader");
		assert_eq!(epoch, scanned);
		(epoch, cohort)
	}

	fn known(&self) -> HashMap<(String, String), (String, bool)> {
		self.cache
			.lock()
			.unwrap()
			.known
			.iter()
			.map(|(identity, binding)| (identity.clone(), (binding.id.clone(), binding.strict)))
			.collect()
	}

	fn assert_idle(&self) {
		let cache = self.cache.lock().unwrap();
		let state = cache.cold.state.lock().unwrap();
		assert!(state.demands.is_empty());
		assert!(state.hints.is_empty());
		assert!(state.active.is_none());
	}
}

#[test]
fn cold_leader_prefills_strict_predictions_without_retaining_demand_or_hints() {
	let fixture = Fixture::new(&["first", "second"]);
	let known = fixture.known();
	std::fs::write(fixture.root.path().join("invalidate.marker"), b"changed").unwrap();
	let found = find_idempotent_in(fixture.root.path(), "fixture", "leader", &fixture.cache)
		.unwrap()
		.unwrap();
	assert_eq!(found.id, "original-leader");
	assert_eq!(fixture.known(), known);
	{
		let cache = fixture.cache.lock().unwrap();
		assert_eq!(cache.hits.len(), 3);
		for key in ["leader", "first", "second"] {
			assert_eq!(cache.hits[&identity(key)], format!("original-{key}"));
		}
		// Only the actual cold leader advances recency; the peers keep their order.
		assert_eq!(
			cache.recent_cold,
			VecDeque::from([identity("first"), identity("second"), identity("leader")])
		);
	}
	fixture.assert_idle();
	for key in ["first", "second"] {
		assert_eq!(
			find_idempotent_in(fixture.root.path(), "fixture", key, &fixture.cache)
				.unwrap()
				.unwrap()
				.id,
			format!("original-{key}")
		);
	}
	fixture.assert_idle();
}

#[test]
fn prefill_changes_only_hits_for_already_strict_matching_ownership() {
	let fixture = Fixture::new(&["healthy", "legacy", "missing", "rebound"]);
	write(fixture.root.path(), &record("unknown"));
	let (epoch, cohort) = fixture.scan(&["healthy", "legacy", "missing", "rebound", "unknown"]);
	{
		let mut cache = fixture.cache.lock().unwrap();
		cache.known.get_mut(&identity("legacy")).unwrap().strict = false;
		cache.known.remove(&identity("missing"));
		cache.known.get_mut(&identity("rebound")).unwrap().id = "different-original".into();
	}
	let known = fixture.known();
	let recent = fixture.cache.lock().unwrap().recent_cold.clone();
	prefill_scanned_strict_peers(
		fixture.root.path(),
		&fixture.cache,
		epoch,
		epoch,
		&cohort,
		&registry_epoch,
	)
	.unwrap();
	assert_eq!(fixture.known(), known);
	let cache = fixture.cache.lock().unwrap();
	assert_eq!(
		cache.hits,
		HashMap::from([(identity("healthy"), "original-healthy".into())])
	);
	assert_eq!(cache.recent_cold, recent);
	drop(cache);
	fixture.assert_idle();
}

#[test]
fn prefill_rejects_every_changed_persisted_field_without_rejecting_healthy_peer() {
	let original = serde_json::to_value(record("changed")).unwrap();
	let mutations = [
		("execution_mode", json!("isolated")),
		("system_jobctl", json!(true)),
		("id", json!("other-original")),
		("host", json!("other-host")),
		("ssh_target", json!("other-target.invalid")),
		("unit", json!("other-unit")),
		("remote_job_dir", json!("/never-launch/other-original")),
		("executable", json!("/usr/bin/false")),
		("args", json!(["different"])),
		("cwd", json!("/never-launch/changed")),
		("env_keys", json!(["CHANGED"])),
		("created_unix_ms", json!(2)),
		("idempotency_key", Value::Null),
		("request_fingerprint", json!(2)),
		("request_digest", json!("b".repeat(64))),
		("launch_state", json!("pending")),
		("launch_error", json!("unacknowledged launch")),
	];
	assert_eq!(original.as_object().unwrap().len(), mutations.len());
	for (field, replacement) in mutations {
		let fixture = Fixture::new(&["changed", "healthy"]);
		let (epoch, cohort) = fixture.scan(&["changed", "healthy"]);
		let known = fixture.known();
		let mut changed = original.clone();
		assert_ne!(changed[field], replacement, "fixture must change {field}");
		changed[field] = replacement;
		std::fs::write(
			fixture.root.path().join("original-changed.json"),
			serde_json::to_vec(&changed).unwrap(),
		)
		.unwrap();
		// Keep the probe fixed to isolate full-binding verification from watcher
		// invalidation. Both files still pass the independent strict inode reader.
		assert!(read_verified_cached_record(fixture.root.path(), "original-changed").is_ok());
		prefill_scanned_strict_peers(
			fixture.root.path(),
			&fixture.cache,
			epoch,
			epoch,
			&cohort,
			&|_| Ok(epoch),
		)
		.unwrap();
		assert_eq!(fixture.known(), known, "{field}");
		let cache = fixture.cache.lock().unwrap();
		assert!(!cache.hits.contains_key(&identity("changed")), "{field}");
		assert_eq!(
			cache.hits[&identity("healthy")],
			"original-healthy",
			"{field}"
		);
	}
}

#[test]
fn prefill_accepts_equivalent_json_after_independent_strict_read() {
	let fixture = Fixture::new(&["peer"]);
	let (epoch, cohort) = fixture.scan(&["peer"]);
	let compact = serde_json::to_vec(&serde_json::to_value(record("peer")).unwrap()).unwrap();
	let path = fixture.root.path().join("original-peer.json");
	assert_ne!(std::fs::read(&path).unwrap(), compact);
	std::fs::write(path, compact).unwrap();
	prefill_scanned_strict_peers(
		fixture.root.path(),
		&fixture.cache,
		epoch,
		epoch,
		&cohort,
		&|_| Ok(epoch),
	)
	.unwrap();
	assert_eq!(
		fixture.cache.lock().unwrap().hits[&identity("peer")],
		"original-peer"
	);
}

#[test]
fn prefill_skips_unsafe_missing_and_corrupt_peers_without_downgrading_known() {
	for failure in [
		"mode", "oversize", "symlink", "hardlink", "corrupt", "missing",
	] {
		let fixture = Fixture::new(&["unsafe", "healthy"]);
		let (epoch, cohort) = fixture.scan(&["unsafe", "healthy"]);
		let known = fixture.known();
		let path = fixture.root.path().join("original-unsafe.json");
		match failure {
			"mode" => {
				std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap()
			}
			"oversize" => {
				let mut oversized = record("unsafe");
				oversized.args = vec!["x".repeat(MAX_CACHED_RECORD_BYTES as usize)];
				write(fixture.root.path(), &oversized);
			}
			"symlink" => {
				let other = fixture.root.path().join("original.saved");
				std::fs::rename(&path, &other).unwrap();
				symlink(other, &path).unwrap();
			}
			"hardlink" => {
				std::fs::hard_link(&path, fixture.root.path().join("alias.link")).unwrap()
			}
			"corrupt" => std::fs::write(&path, b"{broken").unwrap(),
			"missing" => std::fs::remove_file(&path).unwrap(),
			_ => unreachable!(),
		}
		assert!(read_verified_cached_record(fixture.root.path(), "original-unsafe").is_err());
		prefill_scanned_strict_peers(
			fixture.root.path(),
			&fixture.cache,
			epoch,
			epoch,
			&cohort,
			&|_| Ok(epoch),
		)
		.unwrap();
		assert_eq!(fixture.known(), known, "{failure}");
		{
			let cache = fixture.cache.lock().unwrap();
			assert!(!cache.hits.contains_key(&identity("unsafe")), "{failure}");
			assert_eq!(
				cache.hits[&identity("healthy")],
				"original-healthy",
				"{failure}"
			);
		}
		assert!(
			find_idempotent_in(fixture.root.path(), "fixture", "unsafe", &fixture.cache).is_err()
		);
		assert_eq!(fixture.known(), known, "{failure}");
	}
}

#[test]
fn cold_leader_skips_duplicate_pending_and_unsafe_predictions() {
	let fixture = Fixture::new(&["duplicate", "pending", "unsafe", "healthy"]);
	for index in 0..2 {
		let mut duplicate = record("duplicate");
		duplicate.id = format!("duplicate-copy-{index}");
		write(fixture.root.path(), &duplicate);
	}
	let mut pending = record("pending");
	pending.launch_state = "pending".into();
	write(fixture.root.path(), &pending);
	std::fs::set_permissions(
		fixture.root.path().join("original-unsafe.json"),
		std::fs::Permissions::from_mode(0o644),
	)
	.unwrap();
	let known = fixture.known();
	assert_eq!(
		find_idempotent_in(fixture.root.path(), "fixture", "leader", &fixture.cache)
			.unwrap()
			.unwrap()
			.id,
		"original-leader"
	);
	assert_eq!(fixture.known(), known);
	{
		let cache = fixture.cache.lock().unwrap();
		assert_eq!(cache.hits.len(), 2);
		assert_eq!(cache.hits[&identity("healthy")], "original-healthy");
		for key in ["duplicate", "pending", "unsafe"] {
			assert!(!cache.hits.contains_key(&identity(key)), "{key}");
		}
	}
	assert!(
		find_idempotent_in(fixture.root.path(), "fixture", "duplicate", &fixture.cache).is_err()
	);
	assert!(find_idempotent_in(fixture.root.path(), "fixture", "unsafe", &fixture.cache).is_err());
	fixture.assert_idle();
}

#[test]
fn failed_complete_scan_never_prefills_an_earlier_healthy_prediction() {
	for failure in ["corrupt-neighbor", "duplicate-leader"] {
		let fixture = Fixture::new(&["healthy"]);
		let known = fixture.known();
		if failure == "corrupt-neighbor" {
			std::fs::write(fixture.root.path().join("corrupt.json"), b"{broken").unwrap();
		} else {
			let mut duplicate = record("leader");
			duplicate.id = "second-leader".into();
			write(fixture.root.path(), &duplicate);
		}
		assert!(
			find_idempotent_in(fixture.root.path(), "fixture", "leader", &fixture.cache).is_err()
		);
		assert!(fixture.cache.lock().unwrap().hits.is_empty(), "{failure}");
		assert_eq!(fixture.known(), known, "{failure}");
		fixture.assert_idle();
	}
}

#[test]
fn leader_ownership_refusal_after_scan_prevents_peer_prefill() {
	let fixture = Fixture::new(&["peer"]);
	fixture.invalidate();
	let result = find_idempotent_in_with_probe(
		fixture.root.path(),
		"fixture",
		"leader",
		&fixture.cache,
		registry_epoch,
		|| {
			fixture
				.cache
				.lock()
				.unwrap()
				.known
				.get_mut(&identity("leader"))
				.unwrap()
				.id = "replacement-leader".into();
		},
	);
	assert!(result
		.unwrap_err()
		.to_string()
		.contains("previous idempotency binding missing or changed"));
	assert!(fixture.cache.lock().unwrap().hits.is_empty());
	fixture.assert_idle();
}

#[test]
fn prefill_requires_watched_initial_scan_and_both_auxiliary_epochs_to_agree() {
	for failure in [
		"initial",
		"no-watch",
		"before",
		"after",
		"before-error",
		"after-error",
	] {
		let fixture = Fixture::new(&["peer"]);
		let (epoch, cohort) = fixture.scan(&["peer"]);
		let mut changed = epoch;
		changed.changed_nanos = changed.changed_nanos.wrapping_add(1);
		let initial = if failure == "initial" { changed } else { epoch };
		let mut scanned = epoch;
		if failure == "no-watch" {
			scanned.content = None;
		}
		let initial = if failure == "no-watch" {
			scanned
		} else {
			initial
		};
		let probes = Cell::new(0);
		prefill_scanned_strict_peers(
			fixture.root.path(),
			&fixture.cache,
			initial,
			scanned,
			&cohort,
			&|_| {
				probes.set(probes.get() + 1);
				assert!(fixture.cache.try_lock().is_ok());
				match (failure, probes.get()) {
					("before", 1) | ("after", 2) => Ok(changed),
					("before-error", 1) | ("after-error", 2) => {
						bail!("injected auxiliary epoch failure")
					}
					_ => Ok(epoch),
				}
			},
		)
		.unwrap();
		assert!(fixture.cache.lock().unwrap().hits.is_empty(), "{failure}");
		assert_eq!(
			probes.get(),
			match failure {
				"initial" | "no-watch" => 0,
				"before" | "before-error" => 1,
				_ => 2,
			},
			"{failure}"
		);
	}
}

#[test]
fn prefill_declines_a_complete_scan_retried_into_a_new_epoch() {
	let fixture = Fixture::new(&["peer"]);
	let initial = fixture.invalidate();
	let mut cohort = vec![RegistryColdTarget {
		identity: identity("peer"),
		seen: false,
		candidate: None,
	}];
	let attempts = Cell::new(0);
	let (found, scanned) = scan_idempotent_binding_cohort(
		fixture.root.path(),
		"fixture",
		"leader",
		Some("original-leader"),
		&registry_epoch,
		RegistryScanObserver {
			cohort: &mut cohort,
			after_scan: |attempt| {
				attempts.set(attempts.get() + 1);
				if attempt == 0 {
					std::fs::write(fixture.root.path().join("retry.marker"), b"changed").unwrap();
				}
			},
		},
	)
	.unwrap();
	assert_eq!(found.unwrap().id, "original-leader");
	assert_eq!(attempts.get(), 2);
	assert_ne!(initial, scanned);
	assert!(cohort[0].candidate.is_some());
	// Even if another lookup has already installed the new cache generation,
	// this leader's original admission epoch cannot authorize peer prefill.
	fixture.cache.lock().unwrap().epoch = Some(scanned);
	prefill_scanned_strict_peers(
		fixture.root.path(),
		&fixture.cache,
		initial,
		scanned,
		&cohort,
		&|_| panic!("mismatched original epoch must decline before auxiliary reads"),
	)
	.unwrap();
	assert!(fixture.cache.lock().unwrap().hits.is_empty());
}

#[test]
fn prefill_rechecks_cache_root_epoch_and_strict_binding_at_commit() {
	for change in ["root", "epoch", "missing", "id", "strict", "existing-hit"] {
		let fixture = Fixture::new(&["peer"]);
		let (epoch, cohort) = fixture.scan(&["peer"]);
		let probes = Cell::new(0);
		prefill_scanned_strict_peers(
			fixture.root.path(),
			&fixture.cache,
			epoch,
			epoch,
			&cohort,
			&|_| {
				probes.set(probes.get() + 1);
				let mut cache = fixture.cache.try_lock().unwrap();
				if probes.get() == 2 {
					match change {
						"root" => cache.root = Some(fixture.root.path().join("different-root")),
						"epoch" => {
							let mut changed = epoch;
							changed.inode = changed.inode.wrapping_add(1);
							cache.epoch = Some(changed);
						}
						"missing" => {
							cache.known.remove(&identity("peer"));
						}
						"id" => {
							cache.known.get_mut(&identity("peer")).unwrap().id = "new-owner".into()
						}
						"strict" => cache.known.get_mut(&identity("peer")).unwrap().strict = false,
						"existing-hit" => {
							cache.hits.insert(identity("peer"), "existing-hit".into());
						}
						_ => unreachable!(),
					}
				}
				Ok(epoch)
			},
		)
		.unwrap();
		assert_eq!(probes.get(), 2, "{change}");
		let cache = fixture.cache.lock().unwrap();
		if change == "existing-hit" {
			assert_eq!(cache.hits[&identity("peer")], "existing-hit");
		} else {
			assert!(cache.hits.is_empty(), "{change}");
		}
		if change == "missing" {
			assert!(!cache.known.contains_key(&identity("peer")));
		} else if change == "id" {
			assert_eq!(cache.known[&identity("peer")].id, "new-owner");
		} else if change == "strict" {
			assert!(!cache.known[&identity("peer")].strict);
		}
	}
}

#[test]
fn prefill_does_not_expand_full_known_or_hit_budgets() {
	let fixture = Fixture::new(&["first", "second"]);
	let (epoch, cohort) = fixture.scan(&["first", "second"]);
	{
		let mut cache = fixture.cache.lock().unwrap();
		for index in 0..MAX_REUSE_HITS - cache.known.len() {
			cache.known.insert(
				identity(&format!("retained-{index}")),
				KnownReuseBinding {
					id: format!("retained-original-{index}"),
					strict: false,
				},
			);
		}
	}
	let known = fixture.known();
	assert_eq!(known.len(), MAX_REUSE_HITS);
	prefill_scanned_strict_peers(
		fixture.root.path(),
		&fixture.cache,
		epoch,
		epoch,
		&cohort,
		&registry_epoch,
	)
	.unwrap();
	assert_eq!(fixture.known(), known);
	assert_eq!(fixture.cache.lock().unwrap().hits.len(), 2);
	{
		let mut cache = fixture.cache.lock().unwrap();
		cache.hits.clear();
		for index in 0..MAX_REUSE_HITS {
			cache.hits.insert(
				identity(&format!("occupied-{index}")),
				format!("occupied-{index}"),
			);
		}
	}
	let hits = fixture.cache.lock().unwrap().hits.clone();
	prefill_scanned_strict_peers(
		fixture.root.path(),
		&fixture.cache,
		epoch,
		epoch,
		&cohort,
		&|_| panic!("full hit cache must decline before auxiliary reads"),
	)
	.unwrap();
	assert_eq!(fixture.cache.lock().unwrap().hits, hits);
	assert_eq!(fixture.known(), known);
}

#[test]
fn prefill_observes_hit_capacity_filled_during_auxiliary_reads() {
	for remaining in [0, 1] {
		let fixture = Fixture::new(&["first", "second"]);
		let (epoch, cohort) = fixture.scan(&["first", "second"]);
		let known = fixture.known();
		let probes = Cell::new(0);
		prefill_scanned_strict_peers(
			fixture.root.path(),
			&fixture.cache,
			epoch,
			epoch,
			&cohort,
			&|_| {
				probes.set(probes.get() + 1);
				if probes.get() == 2 {
					let mut cache = fixture.cache.try_lock().unwrap();
					for index in 0..MAX_REUSE_HITS - remaining {
						cache.hits.insert(
							identity(&format!("occupied-{index}")),
							format!("occupied-{index}"),
						);
					}
				}
				Ok(epoch)
			},
		)
		.unwrap();
		assert_eq!(probes.get(), 2);
		assert_eq!(fixture.known(), known);
		let cache = fixture.cache.lock().unwrap();
		assert_eq!(cache.hits.len(), MAX_REUSE_HITS);
		assert_eq!(
			["first", "second"]
				.iter()
				.filter(|key| cache.hits.contains_key(&identity(key)))
				.count(),
			remaining
		);
		for index in 0..MAX_REUSE_HITS - remaining {
			assert_eq!(
				cache.hits[&identity(&format!("occupied-{index}"))],
				format!("occupied-{index}")
			);
		}
	}
}

#[test]
fn auxiliary_verification_panic_publishes_no_peer_prefix_and_cleans_leader_state() {
	let fixture = Fixture::new(&["first", "second"]);
	fixture.invalidate();
	let known = fixture.known();
	let scans = fixture.cache.lock().unwrap().cold.clone();
	let auxiliary_probes = Cell::new(0);
	let panicked = catch_unwind(AssertUnwindSafe(|| {
		let _follower = RegistryColdDemand::register(scans.clone(), "fixture", "first")
			.unwrap()
			.unwrap();
		find_idempotent_in_with_probe(
			fixture.root.path(),
			"fixture",
			"leader",
			&fixture.cache,
			|root| {
				let epoch = registry_epoch(root)?;
				let leader_verified = fixture
					.cache
					.try_lock()
					.unwrap()
					.hits
					.contains_key(&identity("leader"));
				if leader_verified {
					auxiliary_probes.set(auxiliary_probes.get() + 1);
					assert!(scans.state.try_lock().unwrap().active.is_some());
					if auxiliary_probes.get() == 2 {
						panic!("injected panic after all peer reads and before publication");
					}
				}
				Ok(epoch)
			},
			|| {},
		)
		.unwrap();
	}));
	assert!(panicked.is_err());
	assert_eq!(auxiliary_probes.get(), 2);
	assert!(scans.gate.is_poisoned());
	assert!(!fixture.cache.is_poisoned());
	assert_eq!(fixture.known(), known);
	{
		let cache = fixture.cache.lock().unwrap();
		// The original leader's normal positive hit was earned before prefill.
		assert_eq!(
			cache.hits,
			HashMap::from([(identity("leader"), "original-leader".into())])
		);
	}
	fixture.assert_idle();
	let refused =
		find_idempotent_in(fixture.root.path(), "fixture", "first", &fixture.cache).unwrap_err();
	assert!(refused
		.to_string()
		.contains("job registry cold scan unavailable"));
	fixture.assert_idle();
}

#[test]
fn prefill_preserves_cache_poison_refusal() {
	let fixture = Fixture::new(&["peer"]);
	let (epoch, cohort) = fixture.scan(&["peer"]);
	assert!(catch_unwind(AssertUnwindSafe(|| {
		let _cache = fixture.cache.lock().unwrap();
		panic!("injected cache poison");
	}))
	.is_err());
	let error = prefill_scanned_strict_peers(
		fixture.root.path(),
		&fixture.cache,
		epoch,
		epoch,
		&cohort,
		&registry_epoch,
	)
	.unwrap_err();
	assert!(error.to_string().contains("reuse cache unavailable"));
	assert!(fixture
		.cache
		.lock()
		.err()
		.unwrap()
		.into_inner()
		.hits
		.is_empty());
}
