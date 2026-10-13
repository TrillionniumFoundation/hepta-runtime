// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Lookup admission and concurrent bounded eviction fixtures only.
use super::*;
use std::os::unix::fs::PermissionsExt;

fn private_root() -> tempfile::TempDir {
	let root = tempfile::tempdir().unwrap();
	std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
	root
}
fn completed(root: &Path, owner: &str) -> String {
	let ticket = begin_at(root, owner, "host_list").unwrap();
	let id = ticket.request_id().to_owned();
	finish_sync(ticket, AuditCompletion::Completed).unwrap();
	id
}
#[test]
fn owned_lookup_is_pinned_before_its_own_full_quota_admission_and_concurrent_eviction() {
	let root = private_root();
	let owner = "a".repeat(64);
	let oldest = completed(root.path(), &owner);
	for _ in 1..MAX_OWNER {
		completed(root.path(), &owner);
	}
	let lookup = begin_with_read_at(root.path(), &owner, "request_result", Some(&oldest)).unwrap();
	assert!(is_active(&oldest).unwrap());
	let path = root.path().to_path_buf();
	let owner2 = owner.clone();
	std::thread::spawn(move || {
		for _ in 0..12 {
			completed(&path, &owner2);
		}
	})
	.join()
	.unwrap();
	assert_eq!(
		observation_at(root.path(), &owner, &oldest).unwrap().state,
		"completed"
	);
	finish_sync(lookup, AuditCompletion::Completed).unwrap();
	assert!(!is_active(&oldest).unwrap());
	completed(root.path(), &owner);
	assert!(observation_at(root.path(), &owner, &oldest).is_err());
}
#[test]
fn read_pins_are_independent_of_dispatch_active_state_and_other_reads() {
	let root = private_root();
	let owner = "b".repeat(64);
	let dispatch = begin_at(root.path(), &owner, "host_health").unwrap();
	let id = dispatch.request_id().to_owned();
	let one = begin_with_read_at(root.path(), &owner, "request_result", Some(&id)).unwrap();
	let two = begin_with_read_at(root.path(), &owner, "request_status", Some(&id)).unwrap();
	finish_sync(dispatch, AuditCompletion::Completed).unwrap();
	assert!(is_active(&id).unwrap());
	finish_sync(one, AuditCompletion::Completed).unwrap();
	assert!(is_active(&id).unwrap());
	finish_sync(two, AuditCompletion::Completed).unwrap();
	assert!(!is_active(&id).unwrap());
}
#[test]
fn unowned_expired_malformed_or_nonlookup_pin_is_refused_before_eviction() {
	let root = private_root();
	let owner = "c".repeat(64);
	let other = "d".repeat(64);
	let id = completed(root.path(), &owner);
	for _ in 1..MAX_OWNER {
		completed(root.path(), &owner);
	}
	for (who, tool, target) in [
		(&other, "request_result", id.as_str()),
		(&owner, "request_result", "x"),
		(&owner, "request_result", &"e".repeat(64)),
		(&owner, "host_list", id.as_str()),
	] {
		assert!(begin_with_read_at(root.path(), who, tool, Some(target)).is_err());
	}
	assert!(observation_at(root.path(), &owner, &id).is_ok());
	assert!(!is_active(&id).unwrap());
}

#[test]
fn a_read_pin_never_changes_crashed_unknown_dispatch_to_accepted() {
	let root = private_root();
	let owner = "f".repeat(64);
	let dispatch = begin_at(root.path(), &owner, "host_health").unwrap();
	let id = dispatch.request_id().to_owned();
	drop(dispatch);
	let lookup = begin_with_read_at(root.path(), &owner, "request_status", Some(&id)).unwrap();
	assert!(is_active(&id).unwrap());
	assert!(!is_dispatch_active(&id).unwrap());
	assert_eq!(
		observation_at(root.path(), &owner, &id).unwrap().state,
		"unknown"
	);
	drop(lookup);
}
