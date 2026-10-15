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
	tempfile::Builder::new()
		.tempdir_in(std::env::temp_dir().canonicalize().unwrap())
		.unwrap()
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
fn active_retention_cannot_erase_outstanding_intents_and_global_growth_is_bounded() {
	let temporary = root();
	let session = owner('6');
	let mut tickets = Vec::new();
	for _ in 0..MAX_OWNER {
		tickets.push(begin_at(temporary.path(), &session, "process_start").unwrap());
	}
	assert!(begin_at(temporary.path(), &session, "process_start").is_err());
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
