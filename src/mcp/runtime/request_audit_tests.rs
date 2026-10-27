// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Metadata-only request audit privacy, ownership, lifecycle and storage fault tests.
use super::*;
use std::os::unix::fs::{symlink, PermissionsExt};

fn owner(value: char) -> String {
	value.to_string().repeat(64)
}
fn page(root: &Path, session: &str, after_id: Option<String>, limit: u16) -> Value {
	serde_json::from_str(
		&history_at(
			root,
			session,
			RequestHistoryParams {
				after_id,
				limit: Some(limit),
			},
		)
		.unwrap(),
	)
	.unwrap()
}
fn root() -> tempfile::TempDir {
	let root = tempfile::Builder::new()
		.tempdir_in(std::env::temp_dir().canonicalize().unwrap())
		.unwrap();
	std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
	root
}

#[test]
fn wide_state_root_is_refused_without_repair_or_partial_audit_creation() {
	let temporary = root();
	std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
	let error = prepare_at(temporary.path()).unwrap_err();
	assert!(error
		.to_string()
		.contains("private request audit directory refused"));
	assert_eq!(
		std::fs::metadata(temporary.path())
			.unwrap()
			.permissions()
			.mode() & 0o7777,
		0o755
	);
	assert_eq!(std::fs::read_dir(temporary.path()).unwrap().count(), 0);
	std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
	prepare_at(temporary.path()).unwrap();
}

#[test]
fn startup_preparation_creates_no_request_and_keeps_existing_identity() {
	let temporary = root();
	prepare_at(temporary.path()).unwrap();
	assert_eq!(
		page(temporary.path(), &owner('b'), None, 32)["requests"],
		json!([])
	);
	let ticket = begin_at(temporary.path(), &owner('b'), "host_list").unwrap();
	let id = ticket.request_id().to_owned();
	finish_sync(ticket, AuditCompletion::Completed).unwrap();
	let path = temporary
		.path()
		.join(ARCHIVE_NAME)
		.join(format!("{id}.json"));
	let bytes = std::fs::read(&path).unwrap();
	prepare_at(temporary.path()).unwrap();
	assert_eq!(std::fs::read(&path).unwrap(), bytes);
	std::fs::remove_file(temporary.path().join(ARCHIVE_ANCHOR)).unwrap();
	assert!(prepare_at(temporary.path()).is_err());
	assert!(!temporary.path().join(ARCHIVE_ANCHOR).exists());
	assert_eq!(std::fs::read(path).unwrap(), bytes);
}

#[test]
fn warm_hot_cache_does_not_reread_unrelated_payloads_but_exact_lookup_refuses_corruption() {
	let temporary = root();
	let session = owner('8');
	let first = begin_at(temporary.path(), &session, "host_list").unwrap();
	let id = first.request_id().to_owned();
	finish_sync(first, AuditCompletion::Completed).unwrap();
	let path = temporary.path().join(STORE_NAME).join(format!("{id}.json"));
	let original = std::fs::read(&path).unwrap();
	let guard = store_lock().unwrap();
	let directory = open_store(temporary.path()).unwrap();
	cache_hot(&directory, &entries(&directory).unwrap()).unwrap();
	// An in-place edit does not change the parent directory stamp. New identities
	// do not need this unrelated payload; reading its exact identity still refuses.
	std::fs::write(&path, b"invalid historical payload").unwrap();
	let (cached, _) = hot_snapshot(temporary.path(), &directory).unwrap();
	assert_eq!(cached.len(), 1);
	assert_eq!(cached[0].request_id, id);
	drop(guard);
	assert!(observation_at(temporary.path(), &session, &id).is_err());
	assert_eq!(std::fs::read(&path).unwrap(), b"invalid historical payload");
	std::fs::write(&path, original).unwrap();
}

#[test]
fn hot_cache_revalidates_changed_namespace_instead_of_trusting_stale_membership() {
	let temporary = root();
	let session = owner('8');
	let ticket = begin_at(temporary.path(), &session, "host_list").unwrap();
	finish_sync(ticket, AuditCompletion::Completed).unwrap();
	let unexpected = temporary.path().join(STORE_NAME).join("unexpected-entry");
	std::fs::write(&unexpected, b"PRIVATE_NAMESPACE_SENTINEL").unwrap();
	assert!(begin_at(temporary.path(), &session, "host_list").is_err());
	assert_eq!(
		std::fs::read(&unexpected).unwrap(),
		b"PRIVATE_NAMESPACE_SENTINEL"
	);
	std::fs::remove_file(&unexpected).unwrap();
	let ticket = begin_at(temporary.path(), &session, "host_list").unwrap();
	finish_sync(ticket, AuditCompletion::Completed).unwrap();
}

#[test]
fn a_live_archive_scan_does_not_hold_the_global_admission_lock_between_records() {
	let temporary = root();
	let session = owner('8');
	for _ in 0..8 {
		let ticket = begin_at(temporary.path(), &session, "host_list").unwrap();
		finish_sync(ticket, AuditCompletion::Completed).unwrap();
	}
	let archive = open_archive(temporary.path()).unwrap();
	// Other tests share STORE_LOCK while fsyncing large fixtures. This budget
	// detects a stuck fixture; channels below prove the required admission order.
	let wait = std::time::Duration::from_secs(60);
	let (started_tx, started_rx) = std::sync::mpsc::channel();
	let (continue_tx, continue_rx) = std::sync::mpsc::channel();
	let scanner = std::thread::spawn(move || {
		let mut first = true;
		scan_archive(&archive, |_| {
			if first {
				first = false;
				started_tx.send(())?;
				// Only the test coordinator releases this visitor. A local timeout
				// must not unlock the scanner and let a blocked admission appear valid.
				continue_rx.recv()?;
			}
			Ok(())
		})
	});
	if let Err(error) = started_rx.recv_timeout(wait) {
		drop(continue_tx);
		let cleanup = scanner.join();
		panic!("archive scanner did not reach its first visitor: {error}; cleanup: {cleanup:?}");
	}

	let admission_root = temporary.path().to_path_buf();
	let (admitted_tx, admitted_rx) = std::sync::mpsc::channel();
	let admitter = std::thread::spawn(move || {
		let result = (|| -> Result<()> {
			let ticket = begin_at(&admission_root, &session, "host_health")?;
			finish_sync(ticket, AuditCompletion::Completed)
		})();
		let _ = admitted_tx.send(result);
	});
	// Capture success while the visitor is still parked. Always release and
	// join both threads before asserting, including a real lock-scope regression.
	let admitted_while_paused = admitted_rx.recv_timeout(wait);
	let resumed = continue_tx.send(());
	let scan_result = scanner.join();
	let admission_result = admitter.join();
	resumed.expect("archive visitor exited before the coordinator released it");
	scan_result.expect("archive scanner panicked").unwrap();
	admission_result.expect("admission worker panicked");
	admitted_while_paused
		.expect("new admission did not finish while the archive visitor was paused")
		.unwrap();
}

#[test]
fn disposable_hot_namespace_cache_eviction_never_refuses_new_or_old_roots() {
	let roots: Vec<_> = (0..18).map(|_| root()).collect();
	let session = owner('8');
	let mut first = None;
	for temporary in &roots {
		let ticket = begin_at(temporary.path(), &session, "host_list").unwrap();
		let id = ticket.request_id().to_owned();
		finish_sync(ticket, AuditCompletion::Completed).unwrap();
		if first.is_none() {
			let path = temporary
				.path()
				.join(ARCHIVE_NAME)
				.join(format!("{id}.json"));
			first = Some((path.clone(), std::fs::read(path).unwrap()));
		}
	}
	let ticket = begin_at(roots[0].path(), &session, "host_health").unwrap();
	finish_sync(ticket, AuditCompletion::Completed).unwrap();
	let (path, original) = first.unwrap();
	assert_eq!(std::fs::read(path).unwrap(), original);
}

#[test]
fn durable_unknown_maps_to_live_accepted_then_completed_without_sensitive_fields() {
	let temporary = root();
	let session = owner('1');
	let ticket = begin_at(temporary.path(), &session, "binary_write").unwrap();
	let id = ticket.request_id().to_owned();
	let raw = std::fs::read_to_string(temporary.path().join(STORE_NAME).join(format!("{id}.json")))
		.unwrap();
	let persisted: Value = serde_json::from_str(&raw).unwrap();
	assert_eq!(persisted["state"], "unknown");
	assert_eq!(
		page(temporary.path(), &session, None, 32)["requests"][0]["state"],
		"accepted"
	);
	finish_sync(ticket, AuditCompletion::Completed).unwrap();
	let history = page(temporary.path(), &session, None, 32);
	assert_eq!(history["requests"][0]["state"], "completed");
	assert!(history["requests"][0]["elapsed_ms"].is_u64());
	let allowed = [
		"request_id",
		"tool_name",
		"state",
		"accepted_unix_ms",
		"elapsed_ms",
	];
	assert_eq!(
		history["requests"][0].as_object().unwrap().len(),
		allowed.len()
	);
	assert!(history["requests"][0]
		.as_object()
		.unwrap()
		.keys()
		.all(|key| allowed.contains(&key.as_str())));
	let public = serde_json::to_string(&history).unwrap();
	assert!(!public.contains(&session));
	assert!(!public.contains("binary_path"));
	assert!(!public.contains("parameters"));
	assert!(!public.contains("output"));
	assert!(!public.contains("ssh_target"));
	assert!(!public.contains("error_text"));
	assert!(wire_size(&history).unwrap() < MAX_PAGE_BYTES);
}

#[test]
fn cancellation_drop_and_completion_write_failure_remain_unknown_without_replay() {
	let temporary = root();
	let session = owner('2');
	let dropped = begin_at(temporary.path(), &session, "shell_start").unwrap();
	let id = dropped.request_id().to_owned();
	drop(dropped);
	assert_eq!(
		page(temporary.path(), &session, None, 32)["requests"][0]["state"],
		"unknown"
	);
	let ticket = begin_at(temporary.path(), &session, "binary_write").unwrap();
	let failed_id = ticket.request_id().to_owned();
	let store = temporary.path().join(STORE_NAME);
	std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o500)).unwrap();
	assert!(finish_sync(ticket, AuditCompletion::Completed).is_err());
	std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o700)).unwrap();
	let history = page(temporary.path(), &session, None, 32);
	assert_eq!(history["requests"].as_array().unwrap().len(), 2);
	assert!(history["requests"]
		.as_array()
		.unwrap()
		.iter()
		.all(|row| row["state"] == "unknown"));
	assert!(history["requests"]
		.as_array()
		.unwrap()
		.iter()
		.any(|row| row["request_id"] == failed_id));
	assert!(history["requests"]
		.as_array()
		.unwrap()
		.iter()
		.any(|row| row["request_id"] == id));
	assert_eq!(history["automatic_operation_retry"], false);
}

#[test]
fn same_account_fresh_session_cannot_read_or_use_other_session_cursor() {
	let temporary = root();
	let first = owner('3');
	let other = owner('4');
	let ticket = begin_at(temporary.path(), &first, "host_health").unwrap();
	let id = ticket.request_id().to_owned();
	finish_sync(ticket, AuditCompletion::Failed).unwrap();
	assert_eq!(
		page(temporary.path(), &other, None, 32)["requests"],
		json!([])
	);
	let error = history_at(
		temporary.path(),
		&other,
		RequestHistoryParams {
			after_id: Some(id),
			limit: None,
		},
	)
	.unwrap_err()
	.to_string();
	assert_eq!(
		error,
		"request history cursor expired or unavailable to this session"
	);
	assert!(!error.contains("host_health"));
	assert!(!error.contains(&first));
	assert!(begin_at(temporary.path(), "caller-selected-owner", "host_health").is_err());
}

#[test]
fn page_cursors_are_independent_and_evicted_rows_are_explicitly_rejected() {
	let temporary = root();
	let session = owner('5');
	let mut oldest = None;
	for index in 0..MAX_OWNER + 1 {
		let ticket = begin_at(temporary.path(), &session, "host_list").unwrap();
		if index == 0 {
			oldest = Some(ticket.request_id().to_owned());
		}
		finish_sync(ticket, AuditCompletion::Completed).unwrap();
	}
	let first = page(temporary.path(), &session, None, 7);
	let cursor = first["next_after_id"].as_str().unwrap().to_owned();
	let second = page(temporary.path(), &session, Some(cursor), 7);
	assert_ne!(
		first["requests"][0]["request_id"],
		second["requests"][0]["request_id"]
	);
	assert_eq!(page(temporary.path(), &session, None, 7), first);
	assert!(history_at(
		temporary.path(),
		&session,
		RequestHistoryParams {
			after_id: oldest,
			limit: None
		}
	)
	.is_err());
	assert_eq!(
		entries(&open_store(temporary.path()).unwrap())
			.unwrap()
			.len(),
		MAX_OWNER
	);
}

#[test]
fn archived_dispatch_and_read_pin_survive_hot_eviction_without_new_dispatch() {
	let temporary = root();
	let session = owner('5');
	let ticket = begin_at(temporary.path(), &session, "host_list").unwrap();
	let identity = ticket.identity();
	finish_sync(ticket, AuditCompletion::Completed).unwrap();
	for _ in 0..MAX_OWNER + 5 {
		let ticket = begin_at(temporary.path(), &session, "view").unwrap();
		finish_sync(ticket, AuditCompletion::Completed).unwrap();
	}
	assert!(!temporary
		.path()
		.join(STORE_NAME)
		.join(format!("{}.json", identity.request_id))
		.exists());
	let observed = observation_at(temporary.path(), &session, &identity.request_id).unwrap();
	assert_eq!(observed.state, "completed");
	assert_eq!(observed.identity.tool_name, "host_list");
	assert_eq!(
		observed.identity.accepted_unix_ms,
		identity.accepted_unix_ms
	);
	validate_identity_at(temporary.path(), &identity).unwrap();
	let read = begin_with_read_at(
		temporary.path(),
		&session,
		"request_result",
		Some(&identity.request_id),
	)
	.unwrap();
	finish_sync(read, AuditCompletion::Completed).unwrap();
	assert!(begin_with_read_at(
		temporary.path(),
		&owner('6'),
		"request_status",
		Some(&identity.request_id),
	)
	.is_err());
	assert!(optional_observation_at(temporary.path(), &owner('6'), &identity.request_id).is_err());
	assert!(begin_reserved_at(temporary.path(), identity.clone()).is_err());
	let mut changed = identity;
	changed.accepted_unix_ms += 1;
	assert!(validate_identity_at(temporary.path(), &changed).is_err());
}

#[test]
fn archived_lookup_refuses_corruption_identity_conflict_and_lost_anchor() {
	for fault in [
		"corrupt_archive",
		"foreign_archive",
		"changed_hot",
		"lost_anchor",
	] {
		let temporary = root();
		let session = owner('5');
		let ticket = begin_at(temporary.path(), &session, "host_list").unwrap();
		let identity = ticket.identity();
		finish_sync(ticket, AuditCompletion::Completed).unwrap();
		let path = temporary
			.path()
			.join(ARCHIVE_NAME)
			.join(format!("{}.json", identity.request_id));
		match fault {
			"corrupt_archive" => std::fs::write(path, b"broken").unwrap(),
			"foreign_archive" | "changed_hot" => {
				let path = if fault == "changed_hot" {
					temporary
						.path()
						.join(STORE_NAME)
						.join(format!("{}.json", identity.request_id))
				} else {
					path
				};
				let mut record: Record =
					serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
				record.owner = owner('6');
				std::fs::write(path, serde_json::to_vec(&record).unwrap()).unwrap();
			}
			"lost_anchor" => std::fs::remove_file(temporary.path().join(ARCHIVE_ANCHOR)).unwrap(),
			_ => unreachable!(),
		}
		assert!(observation_at(temporary.path(), &session, &identity.request_id).is_err());
		assert!(optional_observation_at(temporary.path(), &session, &identity.request_id).is_err());
		assert!(validate_identity_at(temporary.path(), &identity).is_err());
	}
}

#[test]
fn archived_completion_wins_over_unknown_hot_after_failed_hot_publication() {
	let temporary = root();
	let session = owner('5');
	let ticket = begin_at(temporary.path(), &session, "host_list").unwrap();
	let identity = ticket.identity();
	let store = temporary.path().join(STORE_NAME);
	std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o500)).unwrap();
	assert!(finish_sync(ticket, AuditCompletion::Completed).is_err());
	std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o700)).unwrap();
	assert_eq!(
		observation_at(temporary.path(), &session, &identity.request_id)
			.unwrap()
			.state,
		"completed"
	);
}

#[test]
fn active_retention_never_erases_intents_or_refuses_archive_only_admission() {
	let temporary = root();
	let session = owner('6');
	let mut tickets = Vec::new();
	for _ in 0..MAX_OWNER {
		tickets.push(begin_at(temporary.path(), &session, "process_start").unwrap());
	}
	let overflow = begin_at(temporary.path(), &session, "process_start").unwrap();
	assert!(!overflow.hot_present);
	assert_eq!(
		observation_at(temporary.path(), &session, overflow.request_id())
			.unwrap()
			.state,
		"accepted"
	);
	finish_sync(overflow, AuditCompletion::Completed).unwrap();
	assert_eq!(
		entries(&open_store(temporary.path()).unwrap())
			.unwrap()
			.len(),
		MAX_OWNER
	);
	drop(tickets);
	assert!(begin_at(temporary.path(), &session, "process_start").is_ok());
	for index in 0..MAX_GLOBAL + 20 {
		let session = format!("{index:064x}");
		let ticket = begin_at(temporary.path(), &session, "host_list").unwrap();
		finish_sync(ticket, AuditCompletion::Completed).unwrap();
	}
	assert_eq!(
		entries(&open_store(temporary.path()).unwrap())
			.unwrap()
			.len(),
		MAX_GLOBAL
	);
}

#[test]
fn existing_wide_modes_symlinks_hardlinks_special_files_and_unknown_fields_fail_closed() {
	let temporary = root();
	let session = owner('7');
	let store = temporary.path().join(STORE_NAME);
	std::fs::create_dir(&store).unwrap();
	std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o755)).unwrap();
	assert!(begin_at(temporary.path(), &session, "host_list").is_err());
	assert_eq!(
		std::fs::metadata(&store).unwrap().permissions().mode() & 0o777,
		0o755
	);
	std::fs::remove_dir(&store).unwrap();
	let outside = root();
	symlink(outside.path(), &store).unwrap();
	assert!(begin_at(temporary.path(), &session, "host_list").is_err());
	std::fs::remove_file(&store).unwrap();
	let ticket = begin_at(temporary.path(), &session, "host_list").unwrap();
	let id = ticket.request_id().to_owned();
	drop(ticket);
	let path = store.join(format!("{id}.json"));
	let duplicate = outside.path().join("hardlink");
	std::fs::hard_link(&path, &duplicate).unwrap();
	assert!(history_at(
		temporary.path(),
		&session,
		RequestHistoryParams {
			after_id: None,
			limit: None
		}
	)
	.is_err());
	std::fs::remove_file(&duplicate).unwrap();
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
	assert!(history_at(
		temporary.path(),
		&session,
		RequestHistoryParams {
			after_id: None,
			limit: None
		}
	)
	.is_err());
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
	let mut value: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
	value["parameters"] = json!({"secret":"forbidden"});
	std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
	assert!(history_at(
		temporary.path(),
		&session,
		RequestHistoryParams {
			after_id: None,
			limit: None
		}
	)
	.is_err());
	assert!(serde_json::from_value::<RequestHistoryParams>(json!({"owner":"spoof"})).is_err());
	assert!(!valid_tool("tool\nsecret"));
	assert!(!valid_tool(&"s".repeat(65)));
}

#[test]
fn interrupted_private_staging_is_recovered_without_unsafe_hardlink_cleanup() {
	let temporary = root();
	let session = owner('8');
	let ticket = begin_at(temporary.path(), &session, "host_health").unwrap();
	let id = ticket.request_id().to_owned();
	drop(ticket);
	let store = temporary.path().join(STORE_NAME);
	let path = store.join(format!("{id}.json"));
	let staging = store.join(format!(".{id}-{}.tmp", owner('9')));
	std::fs::hard_link(&path, &staging).unwrap();
	assert_eq!(
		page(temporary.path(), &session, None, 32)["requests"][0]["state"],
		"unknown"
	);
	assert!(!staging.exists());
	let bad = store.join(format!(".{}-{}.tmp", owner('a'), owner('b')));
	std::fs::hard_link(&path, &bad).unwrap();
	assert!(history_at(
		temporary.path(),
		&session,
		RequestHistoryParams {
			after_id: None,
			limit: None
		}
	)
	.is_err());
	assert!(bad.exists());
}

#[test]
fn caller_pages_and_actual_wire_envelope_have_hard_limits() {
	let temporary = root();
	let session = owner('a');
	assert!(history_at(
		temporary.path(),
		&session,
		RequestHistoryParams {
			after_id: None,
			limit: Some(0)
		}
	)
	.is_err());
	assert!(history_at(
		temporary.path(),
		&session,
		RequestHistoryParams {
			after_id: None,
			limit: Some(33)
		}
	)
	.is_err());
	let empty = wire_size(&json!({"payload":""})).unwrap();
	assert_eq!(
		wire_size(&json!({"payload":"x".repeat(MAX_PAGE_BYTES-empty)})).unwrap(),
		MAX_PAGE_BYTES
	);
	assert!(
		wire_size(&json!({"payload":"\\\"".repeat(MAX_PAGE_BYTES/5)})).unwrap() > MAX_PAGE_BYTES
	);
}

#[test]
fn directory_scan_failure_is_not_mistaken_for_empty_history_or_retention_capacity() {
	assert!(!directory_scan_result(false, 0).unwrap());
	assert!(directory_scan_result(true, 0).unwrap());
	assert!(directory_scan_result(false, libc::EIO).is_err());
	assert!(directory_scan_result(false, libc::EINTR).is_err());
}

fn reserved_identity(tool: &str) -> RequestIdentity {
	RequestIdentity {
		request_id: new_id().unwrap(),
		owner: owner('a'),
		tool_name: tool.into(),
		accepted_unix_ms: 1700000000123,
	}
}

#[test]
fn v9_reserved_dto_family_stays_closed_when_v10_native_auditing_is_added() {
	for tool in ["host_list", "host_health", "effective_config"] {
		let temporary = root();
		let identity = reserved_identity(tool);
		let ticket = begin_reserved_at(temporary.path(), identity.clone()).unwrap();
		assert_eq!(ticket.record.request_id, identity.request_id);
		assert_eq!(ticket.record.owner, identity.owner);
		assert_eq!(ticket.record.tool_name, identity.tool_name);
		assert_eq!(ticket.record.accepted_unix_ms, identity.accepted_unix_ms);
		assert!(begin_operation_reserved_at(temporary.path(), reserved_identity(tool)).is_err());
		finish_sync(ticket, AuditCompletion::Completed).unwrap();
	}
	for tool in [
		"file_info",
		"read_multiple_files",
		"binary_read",
		"process_status",
		"process_read",
		"process_wait",
		"process_list",
		"hardware_snapshot",
		"service_status",
		"network_inspect",
	] {
		let temporary = root();
		assert!(begin_reserved_at(temporary.path(), reserved_identity(tool)).is_err());
		assert!(!temporary.path().join(STORE_NAME).exists());
	}
}

#[test]
fn v10_reserved_native_family_persists_full_original_identity_and_never_recreates_ticket() {
	for tool in [
		"file_info",
		"read_multiple_files",
		"binary_read",
		"process_status",
		"process_read",
		"process_wait",
		"process_list",
		"hardware_snapshot",
		"service_status",
		"network_inspect",
	] {
		let temporary = root();
		let identity = reserved_identity(tool);
		let ticket = begin_operation_reserved_at(temporary.path(), identity.clone()).unwrap();
		let name = format!("{}.json", identity.request_id);
		let record = read_record(&ticket.directory, &name).unwrap();
		assert_eq!(record.request_id, identity.request_id);
		assert_eq!(record.owner, identity.owner);
		assert_eq!(record.tool_name, identity.tool_name);
		assert_eq!(record.accepted_unix_ms, identity.accepted_unix_ms);
		let path = temporary.path().join(STORE_NAME).join(&name);
		let before = std::fs::read(&path).unwrap();
		assert!(begin_operation_reserved_at(temporary.path(), identity.clone()).is_err());
		assert_eq!(std::fs::read(&path).unwrap(), before);
		finish_sync(ticket, AuditCompletion::Completed).unwrap();
		let directory = open_store(temporary.path()).unwrap();
		assert!(matches!(
			read_record(&directory, &name).unwrap().state,
			DurableState::Completed
		));
	}
}

#[test]
fn v10_native_reserved_audit_refuses_effects_controls_and_invalid_authority_before_disk() {
	for tool in [
		"process_start",
		"process_cancel",
		"host_signal",
		"binary_write",
		"privileged_action",
		"operation_start",
		"operation_status",
		"request_start",
		"maintenance_apply",
		"arbitrary_tool",
	] {
		let temporary = root();
		assert!(begin_operation_reserved_at(temporary.path(), reserved_identity(tool)).is_err());
		assert!(!temporary.path().join(STORE_NAME).exists());
	}
	for field in 0..2 {
		let temporary = root();
		let mut identity = reserved_identity("file_info");
		if field == 0 {
			identity.owner = "../caller".into();
		} else {
			identity.request_id = "../caller".into();
		}
		assert!(begin_operation_reserved_at(temporary.path(), identity).is_err());
		assert!(!temporary.path().join(STORE_NAME).exists());
	}
}

#[test]
fn archive_preserves_evicted_history_and_lifetime_counts_without_cross_owner_leakage() {
	let temporary = root();
	let session = owner('7');
	let other = owner('8');
	let mut ids = Vec::new();
	for number in 0..MAX_OWNER + 3 {
		let ticket = begin_at(temporary.path(), &session, "file_info").unwrap();
		ids.push(ticket.request_id().to_owned());
		finish_sync(
			ticket,
			if number == 0 {
				AuditCompletion::Failed
			} else {
				AuditCompletion::Completed
			},
		)
		.unwrap();
	}
	let ticket = begin_at(temporary.path(), &other, "host_list").unwrap();
	finish_sync(ticket, AuditCompletion::Completed).unwrap();
	let stats: Value =
		serde_json::from_str(&usage_stats_at(temporary.path(), &session).unwrap()).unwrap();
	assert_eq!(stats["total_requests"], (MAX_OWNER + 3) as u64);
	assert_eq!(stats["failed"], 1);
	assert_eq!(stats["completed"], (MAX_OWNER + 2) as u64);
	assert_eq!(stats["tool_counts"]["file_info"], (MAX_OWNER + 3) as u64);
	assert!(stats["tool_counts"].get("host_list").is_none());
	assert!(!serde_json::to_string(&stats).unwrap().contains(&other));
	let mut cursor = None;
	let mut seen = Vec::new();
	loop {
		let text = archive_history_at(
			temporary.path(),
			&session,
			RequestHistoryParams {
				after_id: cursor,
				limit: Some(17),
			},
		)
		.unwrap();
		let value: Value = serde_json::from_str(&text).unwrap();
		seen.extend(
			value["requests"]
				.as_array()
				.unwrap()
				.iter()
				.map(|row| row["request_id"].as_str().unwrap().to_owned()),
		);
		cursor = value["next_after_id"].as_str().map(str::to_owned);
		if cursor.is_none() {
			break;
		}
	}
	assert_eq!(seen.len(), ids.len());
	assert!(ids.iter().all(|id| seen.contains(id)));
	assert!(!temporary
		.path()
		.join(STORE_NAME)
		.join(format!("{}.json", ids[0]))
		.exists());
	assert!(temporary
		.path()
		.join(ARCHIVE_NAME)
		.join(format!("{}.json", ids[0]))
		.exists());
	assert!(archive_history_at(
		temporary.path(),
		&other,
		RequestHistoryParams {
			after_id: Some(ids[0].clone()),
			limit: None
		}
	)
	.is_err());
}

#[test]
fn archive_symlink_and_corrupt_metadata_refuse_without_disclosure_or_hot_deletion() {
	let temporary = root();
	let session = owner('7');
	let ticket = begin_at(temporary.path(), &session, "file_info").unwrap();
	let id = ticket.request_id().to_owned();
	finish_sync(ticket, AuditCompletion::Completed).unwrap();
	let archive_file = temporary
		.path()
		.join(ARCHIVE_NAME)
		.join(format!("{id}.json"));
	std::fs::remove_file(&archive_file).unwrap();
	let outside = temporary.path().join("outside");
	std::fs::write(&outside, "SECRET_SENTINEL").unwrap();
	symlink(&outside, &archive_file).unwrap();
	assert!(usage_stats_at(temporary.path(), &session).is_err());
	assert!(observation_at(temporary.path(), &session, &id).is_err());
	{
		let _guard = store_lock().unwrap();
		let stamp = archive_stamp(&open_store(temporary.path()).unwrap()).unwrap();
		HOT_CACHE
			.get()
			.unwrap()
			.lock()
			.unwrap()
			.retain(|entry| entry.stamp != stamp);
	}
	let independent = begin_at(temporary.path(), &session, "file_info").unwrap();
	finish_sync(independent, AuditCompletion::Completed).unwrap();
	for _ in 0..MAX_OWNER + 2 {
		let independent = begin_at(temporary.path(), &session, "file_info").unwrap();
		finish_sync(independent, AuditCompletion::Completed).unwrap();
	}
	assert!(temporary
		.path()
		.join(STORE_NAME)
		.join(format!("{id}.json"))
		.exists());
	assert_eq!(
		std::fs::read_to_string(&outside).unwrap(),
		"SECRET_SENTINEL"
	);
}

#[test]
fn reserved_archived_identity_cannot_redispatch_after_hot_eviction() {
	for tool in ["host_list", "file_info"] {
		let temporary = root();
		let identity = reserved_identity(tool);
		let begin = |identity| {
			if tool == "host_list" {
				begin_reserved_at(temporary.path(), identity)
			} else {
				begin_operation_reserved_at(temporary.path(), identity)
			}
		};
		let ticket = begin(identity.clone()).unwrap();
		finish_sync(ticket, AuditCompletion::Completed).unwrap();
		for _ in 0..MAX_OWNER {
			let ticket = begin_at(temporary.path(), &identity.owner, "host_list").unwrap();
			finish_sync(ticket, AuditCompletion::Completed).unwrap();
		}
		let filename = format!("{}.json", identity.request_id);
		assert!(!temporary.path().join(STORE_NAME).join(&filename).exists());
		let archived = std::fs::read(temporary.path().join(ARCHIVE_NAME).join(&filename)).unwrap();
		let error = match begin(identity) {
			Err(error) => error.to_string(),
			Ok(_) => panic!("archived reserved identity must not acquire another dispatch ticket"),
		};
		assert!(error.contains("already archived"));
		assert!(!temporary.path().join(STORE_NAME).join(&filename).exists());
		assert_eq!(
			archived,
			std::fs::read(temporary.path().join(ARCHIVE_NAME).join(filename)).unwrap()
		);
	}
}

#[test]
fn archive_growth_has_no_lifetime_admission_quota_and_keeps_original_bytes() {
	let temporary = root();
	let session = owner('7');
	let first = begin_at(temporary.path(), &session, "host_list").unwrap();
	let id = first.request_id().to_owned();
	finish_sync(first, AuditCompletion::Completed).unwrap();
	let path = temporary
		.path()
		.join(ARCHIVE_NAME)
		.join(format!("{id}.json"));
	let original = std::fs::read(&path).unwrap();
	for _ in 0..MAX_OWNER + 8 {
		let ticket = begin_at(temporary.path(), &session, "host_list").unwrap();
		finish_sync(ticket, AuditCompletion::Completed).unwrap();
	}
	assert_eq!(std::fs::read(&path).unwrap(), original);
	assert_eq!(
		observation_at(temporary.path(), &session, &id)
			.unwrap()
			.state,
		"completed"
	);
	let usage: Value =
		serde_json::from_str(&usage_stats_at(temporary.path(), &session).unwrap()).unwrap();
	assert_eq!(usage["total_requests"], MAX_OWNER + 9);
}

#[test]
fn unrelated_archive_corruption_is_not_a_lifetime_gate_but_reads_fail_closed() {
	let temporary = root();
	let session = owner('7');
	let ticket = begin_at(temporary.path(), &session, "host_list").unwrap();
	finish_sync(ticket, AuditCompletion::Completed).unwrap();
	let unknown = temporary.path().join(ARCHIVE_NAME).join("unknown-entry");
	std::fs::write(&unknown, b"PRIVATE_SENTINEL").unwrap();
	assert!(usage_stats_at(temporary.path(), &session).is_err());
	let ticket = begin_at(temporary.path(), &session, "host_list").unwrap();
	finish_sync(ticket, AuditCompletion::Completed).unwrap();
	assert_eq!(std::fs::read(&unknown).unwrap(), b"PRIVATE_SENTINEL");
	std::fs::remove_file(&unknown).unwrap();
	let usage: Value =
		serde_json::from_str(&usage_stats_at(temporary.path(), &session).unwrap()).unwrap();
	assert_eq!(usage["total_requests"], 2);
}

#[test]
fn archive_recovers_verified_interrupted_link_publication_before_seed_reads() {
	use std::os::unix::fs::MetadataExt;
	let temporary = root();
	let session = owner('7');
	let ticket = begin_at(temporary.path(), &session, "host_list").unwrap();
	let identity = ticket.request_id().to_owned();
	finish_sync(ticket, AuditCompletion::Completed).unwrap();
	let path = temporary
		.path()
		.join(ARCHIVE_NAME)
		.join(format!("{identity}.json"));
	let staging = temporary
		.path()
		.join(ARCHIVE_NAME)
		.join(format!(".{identity}-{}.tmp", new_id().unwrap()));
	std::fs::hard_link(&path, &staging).unwrap();
	assert_eq!(std::fs::metadata(&path).unwrap().nlink(), 2);
	let stats: Value =
		serde_json::from_str(&usage_stats_at(temporary.path(), &session).unwrap()).unwrap();
	assert_eq!(stats["total_requests"], 1);
	assert_eq!(stats["completed"], 1);
	assert!(!staging.exists());
	assert_eq!(std::fs::metadata(&path).unwrap().nlink(), 1);
	let ticket = begin_at(temporary.path(), &session, "host_list").unwrap();
	finish_sync(ticket, AuditCompletion::Completed).unwrap();
}

#[test]
fn archive_root_or_anchor_removal_and_replacement_refuse_without_recreating_history() {
	for replacement in ["missing", "replaced", "anchor-missing", "anchor-copy"] {
		let temporary = root();
		let session = owner('7');
		let ticket = begin_at(temporary.path(), &session, "host_list").unwrap();
		let identity = ticket.request_id().to_owned();
		finish_sync(ticket, AuditCompletion::Completed).unwrap();
		let archive = temporary.path().join(ARCHIVE_NAME);
		let held = temporary.path().join("held-original-archive");
		match replacement {
			"missing" => std::fs::rename(&archive, &held).unwrap(),
			"replaced" => {
				std::fs::rename(&archive, &held).unwrap();
				std::fs::create_dir(&archive).unwrap();
				std::fs::set_permissions(&archive, std::fs::Permissions::from_mode(0o700)).unwrap();
			}
			"anchor-missing" => {
				std::fs::remove_file(temporary.path().join(ARCHIVE_ANCHOR)).unwrap()
			}
			_ => {
				let target = root();
				std::fs::copy(
					temporary.path().join(ARCHIVE_ANCHOR),
					target.path().join(ARCHIVE_ANCHOR),
				)
				.unwrap();
				std::fs::set_permissions(
					target.path().join(ARCHIVE_ANCHOR),
					std::fs::Permissions::from_mode(0o600),
				)
				.unwrap();
				assert!(open_archive(target.path()).is_err());
				continue;
			}
		}
		assert!(
			usage_stats_at(temporary.path(), &session).is_err(),
			"{replacement}"
		);
		assert!(
			begin_at(temporary.path(), &session, "host_list").is_err(),
			"{replacement}"
		);
		assert!(temporary
			.path()
			.join(STORE_NAME)
			.join(format!("{identity}.json"))
			.exists());
		if replacement == "missing" {
			assert!(!archive.exists());
		}
	}
}
