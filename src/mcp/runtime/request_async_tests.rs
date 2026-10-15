// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Private filesystem and parser fixtures only: no runtime initialization,
//! SSH, live jobs, background dispatch, or business effects.
use super::*;
use serde_json::json;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{symlink, OpenOptionsExt, PermissionsExt};
use std::sync::{Arc, Barrier};
use std::thread;

fn fixture_id(number: u64) -> String {
	format!("{number:064x}")
}

fn fixture_owner() -> String {
	fixture_id(0xeeee)
}

fn fixture_policy() -> String {
	fixture_id(0xbeef)
}

fn fixture_binding(number: u64) -> Binding {
	Binding {
		request_id: fixture_id(number),
		owner: fixture_owner(),
		tool_name: "host_health".into(),
		accepted_unix_ms: 1000 + number as u128,
		key_hash: fixture_id(10_000 + number),
		request_hash: fixture_id(0xfeed),
		policy_binding: fixture_policy(),
	}
}

fn private_root() -> tempfile::TempDir {
	let root = tempfile::tempdir().unwrap();
	fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
	root
}

fn journal_path(root: &Path, binding: &Binding) -> PathBuf {
	root.join(STORE_NAME)
		.join(format!("{}.json", binding.key_hash))
}

fn private_write(path: &Path, bytes: &[u8]) {
	let mut file = OpenOptions::new()
		.write(true)
		.create_new(true)
		.mode(0o600)
		.open(path)
		.unwrap();
	file.write_all(bytes).unwrap();
	file.sync_all().unwrap();
}

fn require_new(reservation: Reservation) -> Binding {
	match reservation {
		Reservation::New(binding) => binding,
		Reservation::Existing(_) => panic!("fixture expected one fresh admission permit"),
	}
}

fn require_existing(reservation: Reservation) -> Binding {
	match reservation {
		Reservation::Existing(binding) => binding,
		Reservation::New(_) => panic!("a reserved key must never acquire another admission permit"),
	}
}

fn require_same(left: &Binding, right: &Binding) {
	assert!(
		left == right,
		"the complete immutable reservation must remain identical"
	);
}

fn journal_names(root: &Path) -> Vec<String> {
	let mut names: Vec<_> = fs::read_dir(root.join(STORE_NAME))
		.unwrap()
		.map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
		.filter(|name| name.ends_with(".json"))
		.collect();
	names.sort();
	names
}

#[test]
fn fresh_reservation_is_private_durable_and_readable_by_key_and_id() {
	use std::os::unix::fs::MetadataExt;
	let root = private_root();
	let proposed = fixture_binding(1);
	let binding = require_new(reserve_at(root.path(), proposed.clone()).unwrap());
	require_same(&binding, &proposed);
	let path = journal_path(root.path(), &binding);
	let directory = path.parent().unwrap();
	assert_eq!(fs::metadata(directory).unwrap().mode() & 0o7777, 0o700);
	let metadata = fs::metadata(&path).unwrap();
	assert_eq!(metadata.mode() & 0o7777, 0o600);
	assert_eq!(metadata.nlink(), 1);
	assert!(metadata.len() <= 4096);
	let persisted: Binding = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
	require_same(&persisted, &binding);
	let by_key = lookup_key_at(
		root.path(),
		&binding.owner,
		&binding.key_hash,
		&binding.request_hash,
		&binding.policy_binding,
	)
	.unwrap()
	.unwrap();
	let by_id = lookup_id_at(
		root.path(),
		&binding.owner,
		&binding.request_id,
		&binding.policy_binding,
	)
	.unwrap()
	.unwrap();
	require_same(&by_key, &binding);
	require_same(&by_id, &binding);
}

#[test]
fn repeat_of_pending_reservation_returns_original_identity_without_readmission() {
	let root = private_root();
	let first = require_new(reserve_at(root.path(), fixture_binding(2)).unwrap());
	let before = fs::read(journal_path(root.path(), &first)).unwrap();
	// Deliberately never create audit/results or launch a worker: this models a
	// crash or admission failure immediately after the key reservation.
	let mut retry = first.clone();
	retry.request_id = fixture_id(999_002);
	retry.accepted_unix_ms += 90_000;
	let repeated = require_existing(reserve_at(root.path(), retry).unwrap());
	require_same(&repeated, &first);
	assert_eq!(fs::read(journal_path(root.path(), &first)).unwrap(), before);
	assert!(!root.path().join("request-audit").exists());
	assert!(!root.path().join("request-results").exists());
}

#[test]
fn receipt_absence_never_rebinds_a_used_key() {
	let root = private_root();
	let first = require_new(reserve_at(root.path(), fixture_binding(3)).unwrap());
	// Audit/result retention is separate and may expire. The journal tombstone
	// remains authoritative even when neither receipt store exists.
	for replacement_id in 200..205 {
		let mut retry = first.clone();
		retry.request_id = fixture_id(replacement_id);
		let existing = require_existing(reserve_at(root.path(), retry).unwrap());
		require_same(&existing, &first);
	}
	assert_eq!(journal_names(root.path()).len(), 1);
}

#[test]
fn same_key_parameter_tool_or_policy_conflicts_are_refused_without_mutation() {
	let root = private_root();
	let first = require_new(reserve_at(root.path(), fixture_binding(4)).unwrap());
	let before = fs::read(journal_path(root.path(), &first)).unwrap();
	for conflict in 0..3 {
		let mut changed = first.clone();
		changed.request_id = fixture_id(400 + conflict);
		match conflict {
			0 => changed.request_hash = fixture_id(0xfeed + 1),
			1 => changed.tool_name = "host_list".into(),
			_ => changed.policy_binding = fixture_id(0xbeef + 1),
		}
		assert!(reserve_at(root.path(), changed).is_err());
		assert_eq!(fs::read(journal_path(root.path(), &first)).unwrap(), before);
	}
	assert!(lookup_key_at(
		root.path(),
		&first.owner,
		&first.key_hash,
		&fixture_id(0xfeed + 1),
		&first.policy_binding,
	)
	.is_err());
	assert!(lookup_key_at(
		root.path(),
		&first.owner,
		&first.key_hash,
		&first.request_hash,
		&fixture_id(0xbeef + 1),
	)
	.is_err());
	assert_eq!(journal_names(root.path()).len(), 1);
}

#[test]
fn wrong_owner_and_current_policy_cannot_read_a_reserved_identity() {
	let root = private_root();
	let first = require_new(reserve_at(root.path(), fixture_binding(5)).unwrap());
	let foreign = fixture_id(0xdddd);
	let by_id = lookup_id_at(
		root.path(),
		&foreign,
		&first.request_id,
		&first.policy_binding,
	);
	assert!(by_id.is_err() || by_id.unwrap().is_none());
	let by_key = lookup_key_at(
		root.path(),
		&foreign,
		&first.key_hash,
		&first.request_hash,
		&first.policy_binding,
	);
	assert!(by_key.is_err() || by_key.unwrap().is_none());
	assert!(lookup_id_at(
		root.path(),
		&first.owner,
		&first.request_id,
		&fixture_id(0xbeef + 1),
	)
	.is_err());
}

#[test]
fn owner_scoped_key_hashes_do_not_expose_or_alias_another_credentials_key() {
	let root = private_root();
	let key = "same-client-key-7dc16ec7bf9348d78c8d687665396f08";
	let mut a = fixture_binding(6);
	a.key_hash = key_hash(&a.owner, key);
	let mut b = fixture_binding(7);
	b.owner = fixture_id(0xdddd);
	b.key_hash = key_hash(&b.owner, key);
	assert_ne!(a.key_hash, b.key_hash);
	let first = require_new(reserve_at(root.path(), a).unwrap());
	let second = require_new(reserve_at(root.path(), b).unwrap());
	assert_ne!(first.request_id, second.request_id);
	assert_eq!(journal_names(root.path()).len(), 2);
	let refused = lookup_id_at(
		root.path(),
		&second.owner,
		&first.request_id,
		&first.policy_binding,
	);
	assert!(refused.is_err() || refused.unwrap().is_none());
}

#[test]
fn one_generated_identity_cannot_be_bound_to_two_different_keys() {
	let root = private_root();
	let first = require_new(reserve_at(root.path(), fixture_binding(8)).unwrap());
	let mut collision = fixture_binding(9);
	collision.request_id = first.request_id.clone();
	assert!(reserve_at(root.path(), collision).is_err());
	assert_eq!(journal_names(root.path()).len(), 1);
}

#[test]
fn journal_contains_hashes_and_identity_but_never_raw_key_or_operation_parameters() {
	let root = private_root();
	let raw_key = "V9_PRIVATE_KEY_SENTINEL_57bec25b5f794cab9012c5c45d760d11";
	let raw_host = "V9_PRIVATE_HOST_PARAMETER_SENTINEL";
	let request = ReadRequest::HostHealth(super::super::health::HostHealthParams {
		host: raw_host.into(),
	});
	let mut proposed = fixture_binding(10);
	proposed.key_hash = key_hash(&proposed.owner, raw_key);
	proposed.request_hash = request_hash(&request).unwrap();
	let binding = require_new(reserve_at(root.path(), proposed).unwrap());
	let bytes = fs::read(journal_path(root.path(), &binding)).unwrap();
	let text = std::str::from_utf8(&bytes).unwrap();
	assert!(!text.contains(raw_key));
	assert!(!text.contains(raw_host));
	let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
	let mut fields: Vec<_> = parsed
		.as_object()
		.unwrap()
		.keys()
		.map(String::as_str)
		.collect();
	fields.sort();
	assert_eq!(
		fields,
		vec![
			"accepted_unix_ms",
			"key_hash",
			"owner",
			"policy_binding",
			"request_hash",
			"request_id",
			"tool_name",
		]
	);
}

#[test]
fn private_journal_rejects_corrupt_record_and_unknown_fields_without_repair() {
	for unknown_field in [false, true] {
		let root = private_root();
		let first = require_new(reserve_at(root.path(), fixture_binding(11)).unwrap());
		let path = journal_path(root.path(), &first);
		fs::remove_file(&path).unwrap();
		let bytes = if unknown_field {
			let mut record = serde_json::to_value(&first).unwrap();
			record["raw_parameters"] = json!({"host":"FORBIDDEN"});
			serde_json::to_vec(&record).unwrap()
		} else {
			b"{truncated private journal".to_vec()
		};
		private_write(&path, &bytes);
		assert!(reserve_at(root.path(), first.clone()).is_err());
		assert!(lookup_id_at(
			root.path(),
			&first.owner,
			&first.request_id,
			&first.policy_binding,
		)
		.is_err());
		assert_eq!(fs::read(&path).unwrap(), bytes);
	}
}

#[test]
fn oversized_record_is_refused_even_when_json_would_otherwise_parse() {
	let root = private_root();
	let first = require_new(reserve_at(root.path(), fixture_binding(12)).unwrap());
	let path = journal_path(root.path(), &first);
	fs::remove_file(&path).unwrap();
	let mut bytes = vec![b' '; 4097];
	bytes.extend(serde_json::to_vec(&first).unwrap());
	private_write(&path, &bytes);
	assert!(reserve_at(root.path(), first.clone()).is_err());
	assert_eq!(fs::metadata(path).unwrap().len(), bytes.len() as u64);
}

#[test]
fn record_symlink_hardlink_fifo_and_wide_permissions_fail_closed() {
	for forbidden in ["symlink", "hardlink", "fifo", "wide"] {
		let root = private_root();
		let first = require_new(reserve_at(root.path(), fixture_binding(13)).unwrap());
		let path = journal_path(root.path(), &first);
		match forbidden {
			"symlink" => {
				fs::remove_file(&path).unwrap();
				let outside = root.path().join("unrelated-private.json");
				private_write(&outside, &serde_json::to_vec(&first).unwrap());
				symlink(&outside, &path).unwrap();
			}
			"hardlink" => {
				fs::hard_link(&path, root.path().join("unrelated-hardlink.json")).unwrap();
			}
			"fifo" => {
				fs::remove_file(&path).unwrap();
				let component = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
				assert_eq!(unsafe { libc::mkfifo(component.as_ptr(), 0o600) }, 0);
			}
			_ => {
				fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
			}
		}
		// This also requires O_NONBLOCK when opening a possibly special inode:
		// a FIFO must be refused without waiting for a writer.
		assert!(
			reserve_at(root.path(), first.clone()).is_err(),
			"{forbidden}"
		);
		assert!(
			lookup_id_at(
				root.path(),
				&first.owner,
				&first.request_id,
				&first.policy_binding,
			)
			.is_err(),
			"{forbidden}"
		);
	}
}

#[test]
fn wider_journal_directory_permissions_are_refused() {
	let root = private_root();
	let first = require_new(reserve_at(root.path(), fixture_binding(14)).unwrap());
	fs::set_permissions(
		root.path().join(STORE_NAME),
		fs::Permissions::from_mode(0o755),
	)
	.unwrap();
	assert!(reserve_at(root.path(), first.clone()).is_err());
	assert!(lookup_id_at(
		root.path(),
		&first.owner,
		&first.request_id,
		&first.policy_binding,
	)
	.is_err());
}

#[test]
fn replaced_journal_directory_cannot_turn_old_key_into_fresh_admission() {
	let root = private_root();
	let first = require_new(reserve_at(root.path(), fixture_binding(15)).unwrap());
	let original = root.path().join(STORE_NAME);
	let moved = root.path().join("original-journal-preserved");
	fs::rename(&original, &moved).unwrap();
	fs::create_dir(&original).unwrap();
	fs::set_permissions(&original, fs::Permissions::from_mode(0o700)).unwrap();
	assert!(reserve_at(root.path(), first.clone()).is_err());
	assert!(lookup_key_at(
		root.path(),
		&first.owner,
		&first.key_hash,
		&first.request_hash,
		&first.policy_binding,
	)
	.is_err());
	assert!(lookup_id_at(
		root.path(),
		&first.owner,
		&first.request_id,
		&first.policy_binding,
	)
	.is_err());
	assert!(moved.join(format!("{}.json", first.key_hash)).is_file());
	assert!(journal_names(root.path()).is_empty());
}

#[test]
fn journal_parent_symlink_and_replaced_symlink_directory_are_refused() {
	let root = private_root();
	let first = require_new(reserve_at(root.path(), fixture_binding(16)).unwrap());
	let original = root.path().join(STORE_NAME);
	let moved = root.path().join("preserved-journal");
	fs::rename(&original, &moved).unwrap();
	symlink(&moved, &original).unwrap();
	assert!(reserve_at(root.path(), first.clone()).is_err());
	let alias = root.path().join("root-alias");
	symlink(root.path(), &alias).unwrap();
	assert!(lookup_key_at(
		&alias,
		&first.owner,
		&first.key_hash,
		&first.request_hash,
		&first.policy_binding,
	)
	.is_err());
}

#[test]
fn owner_capacity_preserves_existing_key_lookup_and_refuses_new_key_without_eviction() {
	let root = private_root();
	let first = fixture_binding(1000);
	for offset in 0..MAX_OWNER_KEYS {
		require_new(reserve_at(root.path(), fixture_binding(1000 + offset as u64)).unwrap());
	}
	let names = journal_names(root.path());
	assert_eq!(names.len(), MAX_OWNER_KEYS);
	let mut retry = first.clone();
	retry.request_id = fixture_id(999_100);
	require_same(
		&require_existing(reserve_at(root.path(), retry).unwrap()),
		&first,
	);
	assert!(reserve_at(root.path(), fixture_binding(900_100)).is_err());
	assert_eq!(journal_names(root.path()), names);
	let by_key = lookup_key_at(
		root.path(),
		&first.owner,
		&first.key_hash,
		&first.request_hash,
		&first.policy_binding,
	)
	.unwrap()
	.unwrap();
	require_same(&by_key, &first);
}

#[test]
fn global_capacity_preserves_existing_keys_and_rejects_new_owner_without_eviction() {
	let root = private_root();
	let mut first = fixture_binding(2000);
	first.owner = fixture_id(5000);
	for offset in 0..MAX_GLOBAL_KEYS {
		let mut candidate = fixture_binding(2000 + offset as u64);
		candidate.owner = fixture_id(5000 + (offset / MAX_OWNER_KEYS) as u64);
		require_new(reserve_at(root.path(), candidate).unwrap());
	}
	let names = journal_names(root.path());
	assert_eq!(names.len(), MAX_GLOBAL_KEYS);
	let mut retry = first.clone();
	retry.request_id = fixture_id(999_200);
	require_same(
		&require_existing(reserve_at(root.path(), retry).unwrap()),
		&first,
	);
	let mut new_owner = fixture_binding(900_200);
	new_owner.owner = fixture_id(90_000);
	assert!(reserve_at(root.path(), new_owner).is_err());
	assert_eq!(journal_names(root.path()), names);
}

#[test]
fn concurrent_identical_key_reservations_generate_exactly_one_new_permit() {
	let root = private_root();
	let barrier = Arc::new(Barrier::new(12));
	let handles: Vec<_> = (0..12)
		.map(|index| {
			let path = root.path().to_path_buf();
			let barrier = barrier.clone();
			thread::spawn(move || {
				let mut candidate = fixture_binding(30 + index);
				candidate.key_hash = fixture_id(55_555);
				barrier.wait();
				reserve_at(&path, candidate).unwrap()
			})
		})
		.collect();
	let mut fresh = 0;
	let mut identities = Vec::new();
	for handle in handles {
		match handle.join().unwrap() {
			Reservation::New(binding) => {
				fresh += 1;
				identities.push(binding);
			}
			Reservation::Existing(binding) => identities.push(binding),
		}
	}
	assert_eq!(fresh, 1);
	assert_eq!(identities.len(), 12);
	for binding in &identities[1..] {
		require_same(binding, &identities[0]);
	}
	assert_eq!(journal_names(root.path()).len(), 1);
}

#[test]
fn generated_id_and_owner_key_hashes_are_bounded_and_domain_separated() {
	let a = next_id().unwrap();
	let b = next_id().unwrap();
	assert_ne!(a, b);
	for generated in [a, b] {
		assert_eq!(generated.len(), 64);
		assert!(generated
			.bytes()
			.all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
	}
	let owner = fixture_owner();
	let other_owner = fixture_id(0xdddd);
	let key = "7d5efdfd21d74fd6b6ceec3da27a88a076b2e2b6a5d64f2ba4e0e3cb097e900f";
	let hashed = key_hash(&owner, key);
	assert_eq!(hashed.len(), 64);
	assert_eq!(hashed, key_hash(&owner, key));
	assert_ne!(hashed, key_hash(&other_owner, key));
	assert_ne!(hashed, key_hash(&owner, &format!("{key}a")));
	assert_ne!(hashed, key);
	assert!(valid_key(key));
	assert!(!valid_key(""));
	assert!(!valid_key("newline\nkey"));
	assert!(!valid_key("nul\0key"));
	assert!(!valid_key(&"a".repeat(4097)));
}

#[test]
fn typed_request_hash_is_stable_and_changes_with_operation_or_host() {
	let a = ReadRequest::HostHealth(super::super::health::HostHealthParams {
		host: "main".into(),
	});
	let b = ReadRequest::HostHealth(super::super::health::HostHealthParams { host: "mac".into() });
	let list = ReadRequest::HostList(super::super::inspect::HostListParams {});
	let config =
		ReadRequest::EffectiveConfig(super::super::effective_config::EffectiveConfigParams {});
	let hash = request_hash(&a).unwrap();
	assert_eq!(hash, request_hash(&a).unwrap());
	assert_ne!(hash, request_hash(&b).unwrap());
	assert_ne!(hash, request_hash(&list).unwrap());
	assert_ne!(request_hash(&list).unwrap(), request_hash(&config).unwrap());
	let decoded: ReadRequest = serde_json::from_value(json!({
		"arguments":{"host":"main"}, "tool":"host_health",
	}))
	.unwrap();
	assert_eq!(hash, request_hash(&decoded).unwrap());
}

#[test]
fn start_parser_admits_only_three_explicit_typed_read_operations() {
	let key = "7d5efdfd21d74fd6b6ceec3da27a88a076b2e2b6a5d64f2ba4e0e3cb097e900f";
	for operation in [
		json!({"tool":"host_list","arguments":{}}),
		json!({"tool":"effective_config","arguments":{}}),
		json!({"tool":"host_health","arguments":{"host":"main"}}),
	] {
		assert!(serde_json::from_value::<RequestStartParams>(json!({
			"operation":operation, "idempotency_key":key,
		}))
		.is_ok());
	}
	for operation in [
		json!({"tool":"shell_start","arguments":{"host":"main","command":"true"}}),
		json!({"tool":"request_start","arguments":{}}),
		json!({"tool":"request_cancel","arguments":{"request_id":fixture_id(1)}}),
		json!({"tool":"Host_health","arguments":{"host":"main"}}),
		json!({"tool":"host_health","arguments":{"host":"main","command":"true"}}),
		json!({"tool":"host_health","arguments":{"host":"main","owner":fixture_owner()}}),
		json!({"tool":"host_health","arguments":{"host":12}}),
		json!({"tool":"host_health","arguments":{}}),
		json!({"tool":"host_list","arguments":{"host":"main"}}),
		json!({"tool":"effective_config","arguments":{"policy":{}}}),
		json!({"tool":"host_health","arguments":{"host":"main"},"owner":fixture_owner()}),
	] {
		assert!(serde_json::from_value::<RequestStartParams>(json!({
			"operation":operation, "idempotency_key":key,
		}))
		.is_err());
	}
	assert!(serde_json::from_value::<RequestStartParams>(json!({
		"operation":{"tool":"host_list","arguments":{}},
		"idempotency_key":key, "owner":fixture_owner(),
	}))
	.is_err());
}

#[test]
fn cancel_parser_never_accepts_pid_host_signal_command_or_selected_owner() {
	let valid = json!({"request_id":fixture_id(1)});
	assert!(serde_json::from_value::<RequestCancelParams>(valid.clone()).is_ok());
	for (field, value) in [
		("pid", json!(1234)),
		("host", json!("main")),
		("signal", json!("KILL")),
		("command", json!("kill 1234")),
		("owner", json!(fixture_owner())),
	] {
		let mut spoofed = valid.clone();
		spoofed[field] = value;
		assert!(serde_json::from_value::<RequestCancelParams>(spoofed).is_err());
	}
	assert!(serde_json::from_value::<RequestCancelParams>(json!({})).is_err());
}

#[test]
#[serial_test::serial]
fn one_owner_can_hold_four_actual_registry_slots_and_drop_releases_capacity() {
	let owner = next_id().unwrap();
	let mut slots: Vec<_> = (0..OWNER_ACTIVE)
		.map(|_| Slot::take(&owner).unwrap())
		.collect();
	assert!(Slot::take(&owner).is_err());
	assert_eq!(
		registry().unwrap().reserved.get(&owner).copied(),
		Some(OWNER_ACTIVE)
	);
	drop(slots.pop().unwrap());
	let replacement = Slot::take(&owner).unwrap();
	drop(replacement);
	drop(slots);
	assert!(!registry().unwrap().reserved.contains_key(&owner));
}

#[test]
#[serial_test::serial]
fn two_owners_fill_eight_actual_registry_slots_but_existing_storage_stays_readable() {
	let a = next_id().unwrap();
	let b = next_id().unwrap();
	let c = next_id().unwrap();
	let root = private_root();
	let mut candidate = fixture_binding(777_000);
	candidate.owner = a.clone();
	let existing = require_new(reserve_at(root.path(), candidate).unwrap());
	let mut slots = Vec::new();
	for owner in [&a, &b] {
		for _ in 0..OWNER_ACTIVE {
			slots.push(Slot::take(owner).unwrap());
		}
	}
	assert_eq!(slots.len(), GLOBAL_ACTIVE);
	assert!(Slot::take(&c).is_err());
	let found = lookup_key_at(
		root.path(),
		&existing.owner,
		&existing.key_hash,
		&existing.request_hash,
		&existing.policy_binding,
	)
	.unwrap()
	.unwrap();
	require_same(&found, &existing);
	let mut retry = existing.clone();
	retry.request_id = next_id().unwrap();
	require_same(
		&require_existing(reserve_at(root.path(), retry).unwrap()),
		&existing,
	);
	assert_eq!(journal_names(root.path()).len(), 1);
	drop(slots);
	for owner in [&a, &b, &c] {
		assert!(!registry().unwrap().reserved.contains_key(owner));
	}
	drop(Slot::take(&c).unwrap());
	assert!(!registry().unwrap().reserved.contains_key(&c));
}

fn occupancy_path(root: &Path, binding: &Binding) -> PathBuf {
	root.join(STORE_NAME)
		.join(".occupied")
		.join(format!("{}.json", binding.key_hash))
}

#[test]
fn deleted_primary_cannot_rebind_a_used_key_or_expose_old_identity() {
	let root = private_root();
	let first = require_new(reserve_at(root.path(), fixture_binding(801_000)).unwrap());
	let occupancy = occupancy_path(root.path(), &first);
	let occupied_before = fs::read(&occupancy).unwrap();
	fs::remove_file(journal_path(root.path(), &first)).unwrap();
	let mut retry = first.clone();
	retry.request_id = next_id().unwrap();
	retry.accepted_unix_ms += 1000;
	assert!(reserve_at(root.path(), retry).is_err());
	assert!(lookup_key_at(
		root.path(),
		&first.owner,
		&first.key_hash,
		&first.request_hash,
		&first.policy_binding,
	)
	.is_err());
	assert!(lookup_id_at(
		root.path(),
		&first.owner,
		&first.request_id,
		&first.policy_binding,
	)
	.is_err());
	assert_eq!(fs::read(occupancy).unwrap(), occupied_before);
	assert!(!journal_path(root.path(), &first).exists());
}

#[test]
fn full_owner_occupancy_never_reclaims_capacity_when_one_primary_is_deleted() {
	let root = private_root();
	let first = fixture_binding(810_000);
	for index in 0..MAX_OWNER_KEYS {
		require_new(reserve_at(root.path(), fixture_binding(810_000 + index as u64)).unwrap());
	}
	let primary = journal_path(root.path(), &first);
	let original = fs::read(&primary).unwrap();
	fs::remove_file(&primary).unwrap();
	assert_eq!(
		fs::read_dir(root.path().join(STORE_NAME).join(".occupied"))
			.unwrap()
			.count(),
		MAX_OWNER_KEYS,
	);
	assert!(reserve_at(root.path(), fixture_binding(900_500)).is_err());
	let mut retry = first.clone();
	retry.request_id = next_id().unwrap();
	assert!(reserve_at(root.path(), retry).is_err());
	assert!(!primary.exists());
	assert!(!occupancy_path(root.path(), &fixture_binding(900_500)).exists());
	// Restoring the exact missing primary repairs the owned fixture only; the
	// occupied quota remains full and never grants a replacement key permit.
	private_write(&primary, &original);
	assert!(reserve_at(root.path(), fixture_binding(900_501)).is_err());
	assert_eq!(journal_names(root.path()).len(), MAX_OWNER_KEYS);
}

#[test]
fn durable_occupancy_only_partial_publication_never_creates_a_new_permit() {
	let root = private_root();
	require_new(reserve_at(root.path(), fixture_binding(820_000)).unwrap());
	let pending = fixture_binding(820_001);
	let occupancy = occupancy_path(root.path(), &pending);
	private_write(&occupancy, &serde_json::to_vec(&pending).unwrap());
	assert!(!journal_path(root.path(), &pending).exists());
	let mut retry = pending.clone();
	retry.request_id = next_id().unwrap();
	assert!(reserve_at(root.path(), retry).is_err());
	assert!(lookup_key_at(
		root.path(),
		&pending.owner,
		&pending.key_hash,
		&pending.request_hash,
		&pending.policy_binding,
	)
	.is_err());
	assert!(lookup_id_at(
		root.path(),
		&pending.owner,
		&pending.request_id,
		&pending.policy_binding,
	)
	.is_err());
	require_same(
		&serde_json::from_slice::<Binding>(&fs::read(occupancy).unwrap()).unwrap(),
		&pending,
	);
	assert!(!journal_path(root.path(), &pending).exists());
}

#[test]
fn removed_occupied_directory_is_not_recreated_as_an_empty_namespace() {
	let root = private_root();
	let first = require_new(reserve_at(root.path(), fixture_binding(830_000)).unwrap());
	let directory = root.path().join(STORE_NAME).join(".occupied");
	fs::remove_dir_all(&directory).unwrap();
	assert!(reserve_at(root.path(), first.clone()).is_err());
	assert!(lookup_key_at(
		root.path(),
		&first.owner,
		&first.key_hash,
		&first.request_hash,
		&first.policy_binding,
	)
	.is_err());
	assert!(
		!directory.exists(),
		"an anchored deleted directory must not be silently recreated"
	);
	assert!(journal_path(root.path(), &first).is_file());
}

#[test]
fn replaced_or_symlinked_occupied_directory_refuses_every_old_binding() {
	for replace_with_symlink in [false, true] {
		let root = private_root();
		let first = require_new(reserve_at(root.path(), fixture_binding(840_000)).unwrap());
		let directory = root.path().join(STORE_NAME).join(".occupied");
		let preserved = root.path().join("preserved-original-occupancy");
		fs::rename(&directory, &preserved).unwrap();
		if replace_with_symlink {
			symlink(&preserved, &directory).unwrap();
		} else {
			fs::create_dir(&directory).unwrap();
			fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
		}
		assert!(reserve_at(root.path(), first.clone()).is_err());
		assert!(lookup_id_at(
			root.path(),
			&first.owner,
			&first.request_id,
			&first.policy_binding,
		)
		.is_err());
		assert!(preserved.join(format!("{}.json", first.key_hash)).is_file());
		assert!(journal_path(root.path(), &first).is_file());
	}
}

#[test]
fn primary_occupancy_identity_conflict_is_refused_without_overwriting_either() {
	let root = private_root();
	let first = require_new(reserve_at(root.path(), fixture_binding(850_000)).unwrap());
	let occupancy = occupancy_path(root.path(), &first);
	let occupied_before = fs::read(&occupancy).unwrap();
	let primary = journal_path(root.path(), &first);
	fs::remove_file(&primary).unwrap();
	let mut changed = first.clone();
	changed.request_id = next_id().unwrap();
	changed.accepted_unix_ms += 1;
	let replacement = serde_json::to_vec(&changed).unwrap();
	private_write(&primary, &replacement);
	assert!(reserve_at(root.path(), first.clone()).is_err());
	assert!(lookup_key_at(
		root.path(),
		&first.owner,
		&first.key_hash,
		&first.request_hash,
		&first.policy_binding,
	)
	.is_err());
	assert!(lookup_id_at(
		root.path(),
		&first.owner,
		&first.request_id,
		&first.policy_binding,
	)
	.is_err());
	assert_eq!(fs::read(occupancy).unwrap(), occupied_before);
	assert_eq!(fs::read(primary).unwrap(), replacement);
}

#[test]
fn missing_single_occupancy_record_cannot_fall_back_to_primary_or_new_admission() {
	let root = private_root();
	let first = require_new(reserve_at(root.path(), fixture_binding(860_000)).unwrap());
	let primary = journal_path(root.path(), &first);
	let before = fs::read(&primary).unwrap();
	fs::remove_file(occupancy_path(root.path(), &first)).unwrap();
	assert!(reserve_at(root.path(), first.clone()).is_err());
	assert!(lookup_key_at(
		root.path(),
		&first.owner,
		&first.key_hash,
		&first.request_hash,
		&first.policy_binding,
	)
	.is_err());
	assert!(lookup_id_at(
		root.path(),
		&first.owner,
		&first.request_id,
		&first.policy_binding,
	)
	.is_err());
	assert_eq!(fs::read(primary).unwrap(), before);
}

#[test]
fn audit_identity_must_match_all_four_reserved_identity_fields() {
	let binding = fixture_binding(870_000);
	assert!(check_audit_identity(&binding, &binding.identity()).is_ok());
	for changed_field in 0..4 {
		let mut observed = binding.identity();
		match changed_field {
			0 => observed.request_id = fixture_id(870_001),
			1 => observed.owner = fixture_id(0xdddd),
			2 => observed.tool_name = "host_list".into(),
			_ => observed.accepted_unix_ms += 1,
		}
		assert!(check_audit_identity(&binding, &observed).is_err());
	}
}

#[test]
fn held_external_journal_flock_refuses_instead_of_waiting_or_mutating() {
	use std::os::fd::AsRawFd;
	use std::sync::mpsc;
	use std::time::Duration;
	let root = private_root();
	let binding = require_new(reserve_at(root.path(), fixture_binding(880_000)).unwrap());
	let lock_path = root.path().join(STORE_NAME).join(".lock");
	let external = OpenOptions::new()
		.read(true)
		.write(true)
		.open(lock_path)
		.unwrap();
	assert_eq!(
		unsafe { libc::flock(external.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
		0,
	);
	let before = fs::read(journal_path(root.path(), &binding)).unwrap();
	let (sender, receiver) = mpsc::channel();
	let path = root.path().to_path_buf();
	let retry = binding.clone();
	let worker = thread::spawn(move || {
		let read = lookup_key_at(
			&path,
			&retry.owner,
			&retry.key_hash,
			&retry.request_hash,
			&retry.policy_binding,
		);
		let admission = reserve_at(&path, retry);
		sender.send((read, admission)).unwrap();
	});
	// Allow unrelated filesystem tests to finish their process-wide STORE_LOCK
	// work, but bound a mistakenly blocking flock. Release our owned lock before
	// joining on any failure so this regression never strands a test thread.
	let response = receiver.recv_timeout(Duration::from_secs(30));
	drop(external);
	worker.join().unwrap();
	let (read, admission) = response.expect("journal flock must return bounded refusal");
	assert!(read.is_err() && admission.is_err());
	assert_eq!(
		fs::read(journal_path(root.path(), &binding)).unwrap(),
		before
	);
	require_same(
		&lookup_key_at(
			root.path(),
			&binding.owner,
			&binding.key_hash,
			&binding.request_hash,
			&binding.policy_binding,
		)
		.unwrap()
		.unwrap(),
		&binding,
	);
}

fn intent_path(root: &Path, binding: &Binding) -> PathBuf {
	root.join(STORE_NAME)
		.join(".intents")
		.join(format!("{}.json", binding.request_id))
}

#[test]
fn both_key_markers_deleted_do_not_erase_independent_intent_history() {
	let root = private_root();
	let first = require_new(reserve_at(root.path(), fixture_binding(890_000)).unwrap());
	let intent = intent_path(root.path(), &first);
	let before = fs::read(&intent).unwrap();
	fs::remove_file(journal_path(root.path(), &first)).unwrap();
	fs::remove_file(occupancy_path(root.path(), &first)).unwrap();
	let mut retry = first.clone();
	retry.request_id = next_id().unwrap();
	assert!(reserve_at(root.path(), retry).is_err());
	assert!(lookup_key_at(
		root.path(),
		&first.owner,
		&first.key_hash,
		&first.request_hash,
		&first.policy_binding,
	)
	.is_err());
	assert!(lookup_id_at(
		root.path(),
		&first.owner,
		&first.request_id,
		&first.policy_binding,
	)
	.is_err());
	assert_eq!(fs::read(intent).unwrap(), before);
	assert!(journal_names(root.path()).is_empty());
}

#[test]
fn intent_only_durable_partial_publication_never_reconstructs_a_permit() {
	let root = private_root();
	require_new(reserve_at(root.path(), fixture_binding(891_000)).unwrap());
	let partial = fixture_binding(891_001);
	let intent = intent_path(root.path(), &partial);
	private_write(&intent, &serde_json::to_vec(&partial).unwrap());
	let before = fs::read(&intent).unwrap();
	let mut retry = partial.clone();
	retry.request_id = next_id().unwrap();
	assert!(reserve_at(root.path(), retry).is_err());
	assert!(lookup_key_at(
		root.path(),
		&partial.owner,
		&partial.key_hash,
		&partial.request_hash,
		&partial.policy_binding,
	)
	.is_err());
	assert!(lookup_id_at(
		root.path(),
		&partial.owner,
		&partial.request_id,
		&partial.policy_binding,
	)
	.is_err());
	assert_eq!(fs::read(intent).unwrap(), before);
	assert!(!journal_path(root.path(), &partial).exists());
	assert!(!occupancy_path(root.path(), &partial).exists());
}

#[test]
fn missing_intent_record_or_directory_refuses_existing_key_and_identity() {
	for remove_directory in [false, true] {
		let root = private_root();
		let first = require_new(reserve_at(root.path(), fixture_binding(892_000)).unwrap());
		let intent = intent_path(root.path(), &first);
		if remove_directory {
			fs::remove_dir_all(intent.parent().unwrap()).unwrap();
		} else {
			fs::remove_file(&intent).unwrap();
		}
		assert!(reserve_at(root.path(), first.clone()).is_err());
		assert!(lookup_key_at(
			root.path(),
			&first.owner,
			&first.key_hash,
			&first.request_hash,
			&first.policy_binding,
		)
		.is_err());
		assert!(lookup_id_at(
			root.path(),
			&first.owner,
			&first.request_id,
			&first.policy_binding,
		)
		.is_err());
		assert!(!intent.exists());
		assert!(journal_path(root.path(), &first).is_file());
		assert!(occupancy_path(root.path(), &first).is_file());
	}
}

#[test]
fn replaced_intents_directory_does_not_create_a_fresh_history_namespace() {
	let root = private_root();
	let first = require_new(reserve_at(root.path(), fixture_binding(893_000)).unwrap());
	let original = root.path().join(STORE_NAME).join(".intents");
	let preserved = root.path().join("preserved-original-intents");
	fs::rename(&original, &preserved).unwrap();
	fs::create_dir(&original).unwrap();
	fs::set_permissions(&original, fs::Permissions::from_mode(0o700)).unwrap();
	assert!(reserve_at(root.path(), first.clone()).is_err());
	assert!(lookup_id_at(
		root.path(),
		&first.owner,
		&first.request_id,
		&first.policy_binding,
	)
	.is_err());
	assert!(preserved
		.join(format!("{}.json", first.request_id))
		.is_file());
	assert_eq!(fs::read_dir(original).unwrap().count(), 0);
}

#[test]
fn intent_corruption_identity_mismatch_symlink_hardlink_and_wide_mode_refuse() {
	for fault in ["corrupt", "identity", "symlink", "hardlink", "wide"] {
		let root = private_root();
		let first = require_new(reserve_at(root.path(), fixture_binding(894_000)).unwrap());
		let intent = intent_path(root.path(), &first);
		match fault {
			"corrupt" => {
				fs::remove_file(&intent).unwrap();
				private_write(&intent, b"{corrupt-owned-intent");
			}
			"identity" => {
				fs::remove_file(&intent).unwrap();
				let mut changed = first.clone();
				changed.accepted_unix_ms += 1;
				private_write(&intent, &serde_json::to_vec(&changed).unwrap());
			}
			"symlink" => {
				fs::remove_file(&intent).unwrap();
				let target = root.path().join("private-intent-target.json");
				private_write(&target, &serde_json::to_vec(&first).unwrap());
				symlink(target, &intent).unwrap();
			}
			"hardlink" => {
				fs::hard_link(&intent, root.path().join("private-intent-hardlink.json")).unwrap();
			}
			_ => fs::set_permissions(&intent, fs::Permissions::from_mode(0o644)).unwrap(),
		}
		assert!(reserve_at(root.path(), first.clone()).is_err(), "{fault}");
		assert!(
			lookup_id_at(
				root.path(),
				&first.owner,
				&first.request_id,
				&first.policy_binding,
			)
			.is_err(),
			"{fault}"
		);
	}
}

#[test]
fn replaced_or_deleted_lock_path_refuses_while_original_flock_remains_held() {
	use std::os::fd::AsRawFd;
	use std::os::unix::fs::MetadataExt;
	for lock_name in [".controller.lock", ".lock"] {
		for replace_path in [false, true] {
			let root = private_root();
			let first = require_new(reserve_at(root.path(), fixture_binding(895_000)).unwrap());
			let path = root.path().join(STORE_NAME).join(lock_name);
			let held = OpenOptions::new()
				.read(true)
				.write(true)
				.open(&path)
				.unwrap();
			let observer = OpenOptions::new()
				.read(true)
				.write(true)
				.open(&path)
				.unwrap();
			let identity = held.metadata().unwrap();
			assert_eq!(
				unsafe { libc::flock(held.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
				0,
			);
			assert_eq!(
				unsafe { libc::flock(observer.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
				-1,
			);
			fs::remove_file(&path).unwrap();
			if replace_path {
				private_write(&path, b"");
				let changed = path.metadata().unwrap();
				assert!(changed.dev() != identity.dev() || changed.ino() != identity.ino());
			}
			assert!(locked_store(root.path()).is_err());
			assert!(acquire_controller(root.path()).is_err());
			assert!(reserve_at(root.path(), first.clone()).is_err());
			// Both independent descriptors still name the original unlinked
			// inode; the original controller/metadata lock has not been released.
			assert_eq!(held.metadata().unwrap().ino(), identity.ino());
			assert_eq!(held.metadata().unwrap().nlink(), 0);
			assert_eq!(
				unsafe { libc::flock(observer.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
				-1,
			);
			if !replace_path {
				assert!(
					!path.exists(),
					"anchored lock must not be silently recreated"
				);
			}
			drop(observer);
			drop(held);
		}
	}
}

#[test]
fn nonempty_pinned_locks_refuse_without_clearing_or_repairing_same_inode() {
	use std::os::unix::fs::MetadataExt;
	for name in [".lock", ".controller.lock"] {
		let root = private_root();
		let first = require_new(reserve_at(root.path(), fixture_binding(896_000)).unwrap());
		let path = root.path().join(STORE_NAME).join(name);
		let before = path.metadata().unwrap();
		let mut original = OpenOptions::new().write(true).open(&path).unwrap();
		original.write_all(b"owned-private-nonempty-lock").unwrap();
		original.sync_all().unwrap();
		let damaged = fs::read(&path).unwrap();
		assert_eq!(path.metadata().unwrap().ino(), before.ino());
		assert!(store(root.path()).is_err(), "{name}");
		assert!(
			lookup_id_at(
				root.path(),
				&first.owner,
				&first.request_id,
				&first.policy_binding
			)
			.is_err(),
			"{name}"
		);
		assert!(acquire_controller(root.path()).is_err(), "{name}");
		assert_eq!(
			fs::read(&path).unwrap(),
			damaged,
			"never clear or repair {name}"
		);
		let after = path.metadata().unwrap();
		assert_eq!((after.dev(), after.ino()), (before.dev(), before.ino()));
	}
}

#[test]
fn reserved_root_names_in_history_children_refuse_complete_inventory() {
	for child in [".occupied", ".intents", ".outcomes"] {
		for reserved_name in [".lock", ".outcomes", ".controller.lock"] {
			let root = private_root();
			let first = require_new(reserve_at(root.path(), fixture_binding(897_000)).unwrap());
			let path = root.path().join(STORE_NAME).join(child).join(reserved_name);
			private_write(&path, b"owned-private-invalid-child-entry");
			let (dir, _lock) = locked_store(root.path()).unwrap();
			assert!(bindings(&dir).is_err(), "{child}/{reserved_name}");
			drop(_lock);
			drop(dir);
			assert!(
				lookup_id_at(
					root.path(),
					&first.owner,
					&first.request_id,
					&first.policy_binding
				)
				.is_err(),
				"{child}/{reserved_name}"
			);
			assert!(
				reserve_at(root.path(), fixture_binding(897_001)).is_err(),
				"{child}/{reserved_name}"
			);
			assert_eq!(
				fs::read(&path).unwrap(),
				b"owned-private-invalid-child-entry"
			);
			assert!(!journal_path(root.path(), &fixture_binding(897_001)).exists());
			assert!(!intent_path(root.path(), &fixture_binding(897_001)).exists());
		}
	}
}

#[test]
fn malformed_immutable_binding_is_not_published() {
	let root = private_root();
	for field in 0..6 {
		let mut candidate = fixture_binding(100 + field);
		match field {
			0 => candidate.request_id = "../../request".into(),
			1 => candidate.owner = "unverified-caller".into(),
			2 => candidate.key_hash = "KEY".into(),
			3 => candidate.request_hash = "PARAMS".into(),
			4 => candidate.policy_binding = "POLICY".into(),
			_ => candidate.tool_name = "shell_start".into(),
		}
		assert!(reserve_at(root.path(), candidate).is_err());
	}
	assert!(!root.path().join(STORE_NAME).exists() || journal_names(root.path()).is_empty());
}

#[cfg(target_os = "linux")]
#[test]
fn metadata_lock_drop_unlocks_while_a_forked_child_holds_the_descriptor() {
	use std::os::fd::{AsRawFd, FromRawFd};
	let root = private_root();
	let (dir, lease) = locked_store(root.path()).unwrap();
	let mut ready = [0; 2];
	assert_eq!(
		unsafe { libc::pipe2(ready.as_mut_ptr(), libc::O_CLOEXEC) },
		0
	);
	let read_end = unsafe { File::from_raw_fd(ready[0]) };
	let write_end = unsafe { File::from_raw_fd(ready[1]) };
	let pid = unsafe { libc::fork() };
	assert!(pid >= 0);
	if pid == 0 {
		// Only async-signal-safe libc calls after fork; no Rust allocation or drops.
		unsafe {
			libc::close(read_end.as_raw_fd());
			let byte = [1u8];
			if libc::write(write_end.as_raw_fd(), byte.as_ptr().cast(), 1) != 1 {
				libc::_exit(2);
			}
			loop {
				libc::pause();
			}
		}
	}
	struct OwnedChild(Option<libc::pid_t>);
	impl OwnedChild {
		fn assert_alive(&mut self) {
			let pid = self.0.unwrap();
			let mut observation: libc::siginfo_t = unsafe { std::mem::zeroed() };
			let result = unsafe {
				libc::waitid(
					libc::P_PID,
					pid as libc::id_t,
					&mut observation,
					libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
				)
			};
			if result < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD) {
				// No longer our unreaped child: never signal a possibly reused pid.
				self.0 = None;
			}
			assert_eq!(result, 0);
			assert_eq!(unsafe { observation.si_pid() }, 0);
		}
	}
	impl Drop for OwnedChild {
		fn drop(&mut self) {
			if let Some(pid) = self.0.take() {
				unsafe {
					libc::kill(pid, libc::SIGKILL);
					while libc::waitpid(pid, std::ptr::null_mut(), 0) < 0 {
						if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
							break;
						}
					}
				}
			}
		}
	}
	let mut child = OwnedChild(Some(pid));
	drop(write_end);
	let mut poll = libc::pollfd {
		fd: read_end.as_raw_fd(),
		events: libc::POLLIN,
		revents: 0,
	};
	assert_eq!(unsafe { libc::poll(&mut poll, 1, 5000) }, 1);
	let mut byte = [0u8];
	assert_eq!(
		unsafe { libc::read(read_end.as_raw_fd(), byte.as_mut_ptr().cast(), 1) },
		1
	);
	assert_eq!(byte, [1]);
	child.assert_alive();
	drop(lease);
	let (same_dir, next_lease) = locked_store(root.path()).unwrap();
	use std::os::unix::fs::MetadataExt;
	assert_eq!(
		dir.metadata().unwrap().ino(),
		same_dir.metadata().unwrap().ino()
	);
	// The child has not exec'd or exited, so CLOEXEC alone cannot release this lock.
	child.assert_alive();
	drop(next_lease);
	drop(child);
}
