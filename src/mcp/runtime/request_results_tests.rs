// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Private filesystem fixtures only: no runtime initialization, SSH or live jobs.
use super::*;
use rmcp::model::{ContentBlock, ErrorCode};
use std::fs::{self, OpenOptions};
use std::os::unix::fs::{symlink, OpenOptionsExt, PermissionsExt};

fn id(number: u64) -> String {
	format!("{number:064x}")
}
fn owner() -> String {
	"a".repeat(64)
}
fn policy() -> String {
	"b".repeat(64)
}
fn identity(number: u64, tool: &str) -> RequestIdentity {
	RequestIdentity {
		request_id: id(number),
		owner: owner(),
		tool_name: tool.into(),
		accepted_unix_ms: 1000 + number as u128,
	}
}
fn private_root() -> tempfile::TempDir {
	let root = tempfile::tempdir().unwrap();
	fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
	root
}

#[test]
fn startup_preparation_validates_all_shards_and_never_recreates_missing_members() {
	let root = private_root();
	prepare_at(root.path()).unwrap();
	let path = root.path().join(ARCHIVE_STORE_NAME).join(ARCHIVE_NAME);
	assert_eq!(std::fs::read_dir(&path).unwrap().count(), 256);
	let anchor = std::fs::read(root.path().join(ARCHIVE_ANCHOR)).unwrap();
	prepare_at(root.path()).unwrap();
	assert_eq!(
		std::fs::read(root.path().join(ARCHIVE_ANCHOR)).unwrap(),
		anchor
	);
	std::fs::remove_dir(path.join("fe")).unwrap();
	assert!(prepare_at(root.path()).is_err());
	assert!(!path.join("fe").exists());
}

#[test]
fn startup_preparation_refuses_lost_anchor_and_archive_after_introduction() {
	let root = private_root();
	prepare_at(root.path()).unwrap();
	std::fs::remove_file(root.path().join(ARCHIVE_ANCHOR)).unwrap();
	std::fs::remove_dir_all(root.path().join(ARCHIVE_STORE_NAME)).unwrap();
	assert!(prepare_at(root.path()).is_err());
	assert!(!root.path().join(ARCHIVE_ANCHOR).exists());
	assert!(!root.path().join(ARCHIVE_STORE_NAME).exists());
}

#[test]
fn cached_anchor_refuses_changed_bytes_even_when_file_metadata_stamp_matches() {
	use std::os::unix::fs::MetadataExt;
	let root = private_root();
	prepare_at(root.path()).unwrap();
	let base = open_root(root.path()).unwrap();
	let original = read_anchor(&base).unwrap();
	let path = root.path().join(ARCHIVE_ANCHOR);
	let mut corrupt = fs::read(&path).unwrap();
	*corrupt.last_mut().unwrap() = b'!';
	fs::write(&path, &corrupt).unwrap();
	let metadata = path.metadata().unwrap();
	// Model a timestamp alias deterministically, rather than sleeping until a
	// particular filesystem clock tick. The cached parsed anchor remains original.
	let stamp = AnchorStamp {
		device: metadata.dev(),
		inode: metadata.ino(),
		length: metadata.len(),
		modified: (metadata.mtime(), metadata.mtime_nsec()),
		changed: (metadata.ctime(), metadata.ctime_nsec()),
	};
	{
		let mut cache = ANCHOR_CACHE.get().unwrap().lock().unwrap();
		cache.retain(|(entry, _)| (entry.device, entry.inode) != (stamp.device, stamp.inode));
		if cache.len() >= 16 {
			cache.pop_front();
		}
		cache.push_back((stamp, original));
	}
	assert!(read_anchor(&base).is_err());
	assert!(prepare_at(root.path()).is_err());
	assert_eq!(fs::read(path).unwrap(), corrupt);
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
fn audit(root: &Path, request: &RequestIdentity) {
	let directory = root.join("request-audit");
	if !directory.exists() {
		fs::create_dir(&directory).unwrap();
		fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
	}
	// Preserve the original six-field on-disk audit schema.
	private_write(
		&directory.join(format!("{}.json", request.request_id)),
		&serde_json::to_vec(&json!({
			"request_id": request.request_id, "owner": request.owner,
			"tool_name": request.tool_name, "state": "unknown",
			"accepted_unix_ms": request.accepted_unix_ms, "elapsed_ms": null
		}))
		.unwrap(),
	);
}
fn admit(root: &Path, number: u64) -> (RequestIdentity, ResultIntent) {
	let request = identity(number, "host_health");
	audit(root, &request);
	let intent = admit_at(root, request.clone(), policy()).unwrap();
	(request, intent)
}
fn fixture_result(request: &RequestIdentity) -> CallToolResult {
	let mut response = Ok(CallToolResult::success(vec![ContentBlock::text(
		"{\n  \"schema\": \"fixture-original\",\n  \"text\": \"中文 🦊\\nexact bytes\"\n}",
	)])
	.into());
	attach_identity(&mut response, &request.request_id);
	match response.unwrap() {
		CallToolResponse::Complete(result) => result,
		_ => panic!("fixture response must be complete"),
	}
}
fn store_fixture(mut intent: ResultIntent, result: &CallToolResult) -> Vec<u8> {
	// Low-level storage fixture; does not claim that this DTO passed admission.
	let bytes = serde_json::to_vec(result).unwrap();
	intent.record.state = ResultState::Stored;
	intent.record.payload_bytes = Some(bytes.len());
	intent.record.payload_sha256 = Some(digest(&bytes));
	intent.record.payload_base64 = Some(base64(&bytes));
	let _guard = record_lock(&intent.record.request_id).unwrap();
	save(&intent.directory, &intent.record, true).unwrap();
	bytes
}
fn result_path(root: &Path, request: &RequestIdentity) -> PathBuf {
	root.join(ARCHIVE_STORE_NAME)
		.join(ARCHIVE_NAME)
		.join(&request.request_id[..2])
		.join(format!("{}.json", request.request_id))
}
fn result_directory(root: &Path, request: &RequestIdentity) -> File {
	File::open(result_path(root, request).parent().unwrap()).unwrap()
}

fn unwrap_complete(response: &Result<CallToolResponse, ErrorData>) -> &CallToolResult {
	match response.as_ref().unwrap() {
		CallToolResponse::Complete(result) => result,
		_ => panic!("fixture response must be complete"),
	}
}
fn error_response(data: Option<Value>) -> Result<CallToolResponse, ErrorData> {
	Err(ErrorData::new(
		ErrorCode::INVALID_PARAMS,
		"fixture refusal",
		data,
	))
}

#[test]
fn result_tools_have_a_small_non_recursive_allowlist() {
	for tool in ["host_list", "host_health", "effective_config"] {
		assert!(eligible(tool));
	}
	for tool in [
		"request_history",
		"request_status",
		"request_result",
		"process_status",
		"process_wait",
		"process_cancel",
		"process_read",
		"process_start",
		"shell_start",
		"pty_read",
		"view",
		"Host_health",
		"_unknown_tool",
	] {
		assert!(!eligible(tool), "{tool}");
	}
	let root = private_root();
	for (index, tool) in ["request_history", "request_status", "request_result"]
		.iter()
		.enumerate()
	{
		let request = identity(100 + index as u64, tool);
		audit(root.path(), &request);
		assert!(admit_at(root.path(), request, policy()).is_err());
	}
}

#[test]
fn request_parameters_reject_unknown_fields_and_owner_selection() {
	assert!(serde_json::from_value::<RequestStatusParams>(json!({"request_id":id(1)})).is_ok());
	assert!(serde_json::from_value::<RequestResultParams>(
		json!({"request_id":id(1),"offset":0,"limit":1})
	)
	.is_ok());
	for extra in [
		"owner",
		"host",
		"credential",
		"parameters",
		"stdin",
		"command",
	] {
		let mut value = json!({"request_id":id(1)});
		value[extra] = json!("caller-controlled");
		assert!(serde_json::from_value::<RequestStatusParams>(value.clone()).is_err());
		assert!(serde_json::from_value::<RequestResultParams>(value).is_err());
	}
}

#[test]
fn private_stored_snapshot_roundtrips_original_native_envelope_exactly() {
	let root = private_root();
	let (request, intent) = admit(root.path(), 1);
	let original = fixture_result(&request);
	let original_bytes = serde_json::to_vec(&original).unwrap();
	let saved = store_fixture(intent, &original);
	assert_eq!(saved, original_bytes);
	let record = lookup_at(root.path(), &request, &policy())
		.unwrap()
		.unwrap();
	assert_eq!(result_state(Some(&record), "host_health"), "stored");
	let recovered = unbase64(record.payload_base64.as_deref().unwrap()).unwrap();
	assert_eq!(recovered, original_bytes);
	assert_eq!(record.payload_bytes, Some(original_bytes.len()));
	assert_eq!(record.payload_sha256, Some(digest(&original_bytes)));
	let decoded: CallToolResult = serde_json::from_slice(&recovered).unwrap();
	assert_eq!(decoded, original);
	let raw: Value =
		serde_json::from_slice(&fs::read(result_path(root.path(), &request)).unwrap()).unwrap();
	assert_eq!(raw["payload_bytes"], original_bytes.len());
	assert!(raw.get("parameters").is_none());
	assert!(raw.get("credential").is_none());
	assert!(raw.get("stdout").is_none());
	assert_eq!(raw["payload_sha256"], digest(&recovered));
	// Pagination preserves UTF-8 bytes even where individual pages split a codepoint.
	let mut joined = Vec::new();
	for chunk in recovered.chunks(7) {
		joined.extend(unbase64(&base64(chunk)).unwrap());
	}
	assert_eq!(joined, original_bytes);
}

#[test]
fn lookup_is_bound_to_owner_policy_tool_and_acceptance_identity() {
	let root = private_root();
	let (request, intent) = admit(root.path(), 2);
	store_fixture(intent, &fixture_result(&request));
	for changed in 0..4 {
		let mut other = request.clone();
		let binding = if changed == 1 {
			"c".repeat(64)
		} else {
			policy()
		};
		match changed {
			0 => other.owner = "d".repeat(64),
			2 => other.tool_name = "host_list".into(),
			3 => other.accepted_unix_ms += 1,
			_ => {}
		}
		let error = match lookup_at(root.path(), &other, &binding) {
			Ok(_) => panic!("changed authority was admitted"),
			Err(error) => error.to_string(),
		};
		assert_eq!(
			error,
			"request result unavailable to this scope or current policy"
		);
		assert!(!error.contains(&request.request_id));
		assert!(!error.contains(&request.owner));
		assert!(!error.contains(&policy()));
	}
	assert!(
		lookup_at(root.path(), &identity(222, "host_health"), &policy())
			.unwrap()
			.is_none()
	);
}

#[test]
fn malformed_admission_identity_fails_before_storage() {
	let root = private_root();
	for changed in 0..4 {
		let mut request = identity(3, "host_health");
		let binding = if changed == 3 {
			"not-a-policy".into()
		} else {
			policy()
		};
		match changed {
			0 => request.request_id = "../outside".into(),
			1 => request.owner = "caller".into(),
			2 => request.tool_name = "process_read".into(),
			_ => {}
		}
		assert!(admit_at(root.path(), request, binding).is_err());
	}
	assert!(!root.path().join(STORE_NAME).exists());
}

#[test]
fn controller_crash_leaves_unknown_without_payload_or_automatic_replay() {
	let root = private_root();
	let (request, intent) = admit(root.path(), 4);
	drop(intent);
	let record = lookup_at(root.path(), &request, &policy())
		.unwrap()
		.unwrap();
	assert_eq!(result_state(Some(&record), "host_health"), "unknown");
	assert!(record.payload_base64.is_none());
	assert!(record.payload_sha256.is_none());
	assert!(record.payload_bytes.is_none());
	assert!(admit_at(root.path(), request.clone(), policy()).is_err());
	let raw = fs::read_to_string(result_path(root.path(), &request)).unwrap();
	assert!(!raw.contains("command"));
	assert!(!raw.contains("stdin"));
	assert!(!raw.contains("retry"));
}

#[test]
fn missing_completion_and_untrusted_output_never_become_stored() {
	let root = private_root();
	let (none, intent) = admit(root.path(), 5);
	assert_eq!(complete_sync(intent, None).unwrap(), "not_completed");
	let record = lookup_at(root.path(), &none, &policy()).unwrap().unwrap();
	assert_eq!(result_state(Some(&record), "host_health"), "not_completed");
	assert!(record.payload_base64.is_none());
	let (untrusted, intent) = admit(root.path(), 6);
	let output =
		CallToolResult::success(vec![ContentBlock::text("SECRET stdout argv env password")]);
	assert_eq!(
		complete_sync(intent, Some(output)).unwrap(),
		"not_retained_dto"
	);
	let record = lookup_at(root.path(), &untrusted, &policy())
		.unwrap()
		.unwrap();
	assert_eq!(
		result_state(Some(&record), "host_health"),
		"not_retained_dto"
	);
	assert!(record.payload_base64.is_none());
	let raw = fs::read_to_string(result_path(root.path(), &untrusted)).unwrap();
	assert!(!raw.contains("SECRET"));
}

#[test]
fn oversized_native_result_records_overflow_without_retaining_output() {
	let root = private_root();
	let (request, intent) = admit(root.path(), 7);
	let oversized =
		CallToolResult::success(vec![ContentBlock::text("x".repeat(MAX_RESULT_BYTES + 1))]);
	assert_eq!(complete_sync(intent, Some(oversized)).unwrap(), "overflow");
	let record = lookup_at(root.path(), &request, &policy())
		.unwrap()
		.unwrap();
	assert_eq!(result_state(Some(&record), "host_health"), "overflow");
	assert!(record.payload_base64.is_none());
	assert!(record.payload_bytes.is_none());
	assert!(record.payload_sha256.is_none());
	assert!(
		fs::metadata(result_path(root.path(), &request))
			.unwrap()
			.len() < 2048
	);
}

#[test]
fn missing_audit_metadata_never_deletes_or_rebinds_retained_original_bytes() {
	let root = private_root();
	let (old, intent) = admit(root.path(), 8);
	store_fixture(intent, &fixture_result(&old));
	fs::remove_file(
		root.path()
			.join("request-audit")
			.join(format!("{}.json", old.request_id)),
	)
	.unwrap();
	let (current, _) = admit(root.path(), 9);
	assert!(result_path(root.path(), &old).exists());
	let old_record = lookup_at(root.path(), &old, &policy()).unwrap().unwrap();
	assert_eq!(
		unbase64(old_record.payload_base64.as_deref().unwrap()).unwrap(),
		serde_json::to_vec(&fixture_result(&old)).unwrap()
	);
	assert!(admit_at(root.path(), old, policy()).is_err());
	assert!(lookup_at(root.path(), &current, &policy())
		.unwrap()
		.is_some());
}

#[test]
fn result_admission_requires_exact_scoped_audit_identity_not_only_existing_id() {
	let root = private_root();
	let request = identity(81, "host_health");
	audit(root.path(), &request);
	for changed in 0..3 {
		let mut other = request.clone();
		match changed {
			0 => other.owner = "c".repeat(64),
			1 => other.tool_name = "host_list".into(),
			2 => other.accepted_unix_ms += 1,
			_ => unreachable!(),
		}
		assert!(admit_at(root.path(), other, policy()).is_err());
	}
	assert!(entries(&open_store(root.path()).unwrap())
		.unwrap()
		.is_empty());
	assert!(admit_at(root.path(), request, policy()).is_ok());
}

#[test]
fn retained_bytes_and_policy_remain_bound_after_hot_metadata_eviction() {
	let root = private_root();
	let (request, intent) = admit(root.path(), 82);
	let original = store_fixture(intent, &fixture_result(&request));
	// The admission lookup introduced a pinned archive. Populate its unchanged
	// six-field receipt as an on-disk fixture, then remove only the hot member.
	let filename = format!("{}.json", request.request_id);
	private_write(
		&root.path().join("request-archive-v11").join(&filename),
		&fs::read(root.path().join("request-audit").join(&filename)).unwrap(),
	);
	fs::remove_file(root.path().join("request-audit").join(&filename)).unwrap();
	for number in 100..235 {
		let current = identity(number, "process_read");
		audit(root.path(), &current);
	}
	request_audit::validate_identity_at(root.path(), &request).unwrap();
	let (_, next) = admit(root.path(), 999);
	drop(next);
	let record = lookup_at(root.path(), &request, &policy())
		.unwrap()
		.unwrap();
	assert_eq!(
		unbase64(record.payload_base64.as_deref().unwrap()).unwrap(),
		original
	);
	assert!(lookup_at(root.path(), &request, &"c".repeat(64)).is_err());
	let mut foreign = request.clone();
	foreign.owner = "c".repeat(64);
	assert!(lookup_at(root.path(), &foreign, &policy()).is_err());
	assert!(admit_at(root.path(), request, policy()).is_err());
}

#[test]
fn owner_unknown_history_beyond_128_keeps_identity_and_does_not_block_new_admission() {
	let root = private_root();
	let (first, first_intent) = admit(root.path(), 1);
	drop(first_intent);
	let path = result_path(root.path(), &first);
	let original = fs::read(&path).unwrap();
	for number in 2..=160 {
		let (_, intent) = admit(root.path(), number);
		drop(intent);
	}
	assert_eq!(fs::read(&path).unwrap(), original);
	assert!(retained_unknown(root.path(), &first));
	assert!(admit_at(root.path(), first.clone(), policy()).is_err());
	for changed in 0..3 {
		let mut wrong = first.clone();
		match changed {
			0 => wrong.owner = "c".repeat(64),
			1 => wrong.tool_name = "host_list".into(),
			_ => wrong.accepted_unix_ms += 1,
		}
		assert!(admit_at(root.path(), wrong, policy()).is_err());
	}
}
fn retained_unknown(root: &Path, request: &RequestIdentity) -> bool {
	let record = lookup_at(root, request, &policy()).unwrap().unwrap();
	record.state == ResultState::Unknown && record.payload_base64.is_none()
}

#[test]
fn global_unknown_history_beyond_512_accepts_new_owner_without_rewriting_old_records() {
	let root = private_root();
	let mut first = None;
	for number in 1..=540 {
		let mut request = identity(number, "host_health");
		request.owner = id(number);
		audit(root.path(), &request);
		drop(admit_at(root.path(), request.clone(), policy()).unwrap());
		if first.is_none() {
			first = Some((
				request.clone(),
				fs::read(result_path(root.path(), &request)).unwrap(),
			));
		}
	}
	let (request, raw) = first.unwrap();
	assert_eq!(fs::read(result_path(root.path(), &request)).unwrap(), raw);
	assert!(retained_unknown(root.path(), &request));
}

#[test]
fn quota_ack_preserves_original_sync_success_without_claiming_new_result_retention() {
	let request = identity(2001, "host_list");
	let original = fixture_result(&request);
	let mut response = Ok(original.clone().into());
	attach_ack(&mut response, "not_retained_quota", true);
	let result = unwrap_complete(&response);
	assert_eq!(result.content, original.content);
	assert_eq!(result.is_error, original.is_error);
	assert_eq!(
		result.meta.as_ref().unwrap()[ID_META]["request_id"],
		request.request_id
	);
	assert_eq!(
		result.meta.as_ref().unwrap()[ACK_META]["result_state"],
		"not_retained_quota"
	);
	assert_eq!(
		result.meta.as_ref().unwrap()[ACK_META]["audit_completion_durable"],
		true
	);
	assert_eq!(
		result.meta.as_ref().unwrap()[ACK_META]["automatic_retry"],
		false
	);
}

#[test]
fn result_inode_symlinks_hardlinks_writable_and_oversized_files_are_refused() {
	for kind in ["symlink", "hardlink", "writable", "overflow"] {
		let root = private_root();
		let (request, intent) = admit(root.path(), 10);
		drop(intent);
		let file = result_path(root.path(), &request);
		match kind {
			"symlink" => {
				let outside = root.path().join("outside");
				fs::rename(&file, &outside).unwrap();
				symlink(&outside, &file).unwrap();
			}
			"hardlink" => fs::hard_link(&file, root.path().join("extra-link")).unwrap(),
			"writable" => fs::set_permissions(&file, fs::Permissions::from_mode(0o620)).unwrap(),
			"overflow" => {
				OpenOptions::new()
					.write(true)
					.open(&file)
					.unwrap()
					.set_len((MAX_RECORD_BYTES + 1) as u64)
					.unwrap();
			}
			_ => unreachable!(),
		}
		assert!(
			lookup_at(root.path(), &request, &policy()).is_err(),
			"{kind}"
		);
	}
}

#[test]
fn symlinked_store_and_ancestor_are_never_followed() {
	let root = private_root();
	let destination = root.path().join("destination");
	fs::create_dir(&destination).unwrap();
	fs::set_permissions(&destination, fs::Permissions::from_mode(0o700)).unwrap();
	symlink(&destination, root.path().join(STORE_NAME)).unwrap();
	assert!(open_store(root.path()).is_err());
	let linked_root = root.path().join("linked-root");
	symlink(&destination, &linked_root).unwrap();
	assert!(open_store(&linked_root).is_err());
	assert!(fs::read_dir(&destination).unwrap().next().is_none());
}

#[test]
fn special_inode_and_malformed_record_are_refused_without_blocking() {
	let root = private_root();
	let (request, intent) = admit(root.path(), 11);
	drop(intent);
	let directory = result_directory(root.path(), &request);
	let file = result_path(root.path(), &request);
	fs::remove_file(&file).unwrap();
	fs::create_dir(&file).unwrap();
	assert!(lookup_at(root.path(), &request, &policy()).is_err());
	fs::remove_dir(&file).unwrap();
	private_write(&file, b"{malformed");
	assert!(read_record(&directory, &format!("{}.json", request.request_id)).is_err());
	fs::remove_file(&file).unwrap();
	let mut raw = json!({
		"request_id":request.request_id,"owner":request.owner,"tool_name":"host_health",
		"accepted_unix_ms":request.accepted_unix_ms,"policy_binding":policy(),"state":"unknown",
		"payload_base64":null,"payload_bytes":null,"payload_sha256":null
	});
	raw["parameters"] = json!({"credential":"SECRET"});
	private_write(&file, &serde_json::to_vec(&raw).unwrap());
	assert!(read_record(&directory, &format!("{}.json", request.request_id)).is_err());
}

#[test]
fn verified_interrupted_staging_is_removed_without_changing_published_bytes() {
	let root = private_root();
	let (request, intent) = admit(root.path(), 12);
	let original = store_fixture(intent, &fixture_result(&request));
	let directory = result_directory(root.path(), &request);
	let file = result_path(root.path(), &request);
	let staging = result_path(root.path(), &request)
		.parent()
		.unwrap()
		.join(format!(".{}-{}.tmp", request.request_id, id(991)));
	fs::hard_link(&file, &staging).unwrap();
	let records = entries(&directory).unwrap();
	assert_eq!(records.len(), 1);
	assert!(!staging.exists());
	let recovered = unbase64(records[0].payload_base64.as_deref().unwrap()).unwrap();
	assert_eq!(recovered, original);
	let abandoned = result_path(root.path(), &request)
		.parent()
		.unwrap()
		.join(format!(".{}-{}.tmp", id(913), id(992)));
	private_write(&abandoned, b"interrupted publication");
	assert_eq!(entries(&directory).unwrap().len(), 1);
	assert!(!abandoned.exists());
}

#[test]
fn unexpected_staging_names_permissions_and_unrelated_links_are_refused() {
	for kind in ["name", "writable", "wrong-hardlink"] {
		let root = private_root();
		let (request, intent) = admit(root.path(), 13);
		drop(intent);
		let directory = result_directory(root.path(), &request);
		let staging =
			result_path(root.path(), &request)
				.parent()
				.unwrap()
				.join(if kind == "name" {
					".not-a-valid-staging.tmp".into()
				} else {
					format!(".{}-{}.tmp", request.request_id, id(993))
				});
		private_write(&staging, b"untrusted staging");
		if kind == "writable" {
			fs::set_permissions(&staging, fs::Permissions::from_mode(0o640)).unwrap();
		}
		if kind == "wrong-hardlink" {
			fs::hard_link(&staging, root.path().join("unrelated-hardlink")).unwrap();
		}
		assert!(entries(&directory).is_err(), "{kind}");
		assert!(
			staging.exists(),
			"refused staging must remain for inspection"
		);
	}
}

#[test]
fn repeated_directory_scans_do_not_share_a_stale_cursor() {
	let root = private_root();
	let (first, a) = admit(root.path(), 14);
	drop(a);
	let directory = result_directory(root.path(), &first);
	assert_eq!(entries(&directory).unwrap().len(), 1);
	let (_, b) = admit(root.path(), 15);
	drop(b);
	for _ in 0..3 {
		assert_eq!(entries(&directory).unwrap().len(), 2);
	}
}

#[test]
fn completion_storage_relocation_preserves_response_identity_and_original_content() {
	let root = private_root();
	let (request, intent) = admit(root.path(), 16);
	let mut response = Ok(fixture_result(&request).into());
	let before = unwrap_complete(&response).content.clone();
	let archive = root.path().join("moved-results");
	let shard = result_path(root.path(), &request)
		.parent()
		.unwrap()
		.to_path_buf();
	fs::rename(shard.clone(), &archive).unwrap();
	fs::create_dir(shard.clone()).unwrap();
	fs::set_permissions(shard.clone(), fs::Permissions::from_mode(0o700)).unwrap();
	assert!(complete_sync(intent, Some(unwrap_complete(&response).clone())).is_err());
	attach_ack(&mut response, "unknown", false);
	let value = unwrap_complete(&response);
	assert_eq!(value.content, before);
	assert_eq!(
		value.meta.as_ref().unwrap()[ID_META]["request_id"],
		request.request_id
	);
	assert_eq!(
		value.meta.as_ref().unwrap()[ID_META]["automatic_retry"],
		false
	);
	assert_eq!(
		value.meta.as_ref().unwrap()[ACK_META]["result_state"],
		"unknown"
	);
	assert_eq!(
		value.meta.as_ref().unwrap()[ACK_META]["audit_completion_durable"],
		false
	);
	let old: Value = serde_json::from_slice(
		&fs::read(archive.join(format!("{}.json", request.request_id))).unwrap(),
	)
	.unwrap();
	assert_eq!(old["state"], "unknown");
	assert!(old["payload_base64"].is_null());
}

#[test]
fn completion_storage_permissions_failure_keeps_same_identity_and_unknown_intent() {
	let root = private_root();
	let (request, intent) = admit(root.path(), 17);
	let mut response = Ok(fixture_result(&request).into());
	let before = unwrap_complete(&response).content.clone();
	fs::set_permissions(
		root.path().join(STORE_NAME),
		fs::Permissions::from_mode(0o750),
	)
	.unwrap();
	assert!(complete_sync(intent, Some(unwrap_complete(&response).clone())).is_err());
	attach_ack(&mut response, "unknown", false);
	assert_eq!(unwrap_complete(&response).content, before);
	assert_eq!(
		unwrap_complete(&response).meta.as_ref().unwrap()[ID_META]["request_id"],
		request.request_id
	);
	fs::set_permissions(
		root.path().join(STORE_NAME),
		fs::Permissions::from_mode(0o700),
	)
	.unwrap();
	assert_eq!(
		result_state(
			lookup_at(root.path(), &request, &policy())
				.unwrap()
				.as_ref(),
			"host_health"
		),
		"unknown"
	);
}

#[test]
fn server_identity_preserves_complete_result_content_and_existing_metadata() {
	let original = CallToolResult::structured(json!({"stdout":"caller-visible original"}));
	let mut original = original;
	let mut meta = MetaObject::new();
	meta.insert("fixture/existing".into(), json!({"key":"unchanged"}));
	meta.insert(ID_META.into(), json!({"prior":"collision"}));
	original.meta = Some(meta);
	let before_content = original.content.clone();
	let before_structured = original.structured_content.clone();
	let mut response = Ok(original.into());
	attach_identity(&mut response, &id(18));
	attach_ack(&mut response, "not_retained_policy", true);
	let value = unwrap_complete(&response);
	assert_eq!(value.content, before_content);
	assert_eq!(value.structured_content, before_structured);
	assert_eq!(
		value.meta.as_ref().unwrap()["fixture/existing"],
		json!({"key":"unchanged"})
	);
	assert_eq!(value.meta.as_ref().unwrap()[ID_META]["request_id"], id(18));
	assert_eq!(
		value.meta.as_ref().unwrap()[ID_META]["original_metadata"],
		json!({"prior":"collision"})
	);
}

#[test]
fn error_identity_and_ack_preserve_none_null_string_array_and_object_data() {
	let examples = vec![
		None,
		Some(Value::Null),
		Some(json!("prior text")),
		Some(json!([1, "two", null])),
		Some(json!({"kind":"prior error","nested":{"a":[1,2]}})),
	];
	for previous in examples {
		let mut response = error_response(previous.clone());
		attach_identity(&mut response, &id(19));
		attach_ack(&mut response, "not_completed", false);
		let error = response.unwrap_err();
		assert_eq!(error.code, ErrorCode::INVALID_PARAMS);
		assert_eq!(error.message, "fixture refusal");
		let data = error.data.unwrap();
		assert_eq!(data[ID_META]["request_id"], id(19));
		assert_eq!(data[ID_META]["automatic_retry"], false);
		assert_eq!(data[ACK_META]["audit_completion_durable"], false);
		match previous {
			Some(Value::Object(object)) => {
				for (key, value) in object {
					assert_eq!(data[&key], value);
				}
			}
			Some(value) => assert_eq!(data["original_error_data"], value),
			None => assert!(data.get("original_error_data").is_none()),
		}
	}
}

#[test]
fn error_identity_and_ack_keep_both_namespaced_collisions() {
	let mut previous = json!({"kind":"original"});
	previous[ID_META] = json!({"identity":"original collision"});
	previous[ACK_META] = json!({"retention":"original collision"});
	let mut response = error_response(Some(previous));
	attach_identity(&mut response, &id(20));
	attach_ack(&mut response, "unknown", false);
	let error = response.unwrap_err();
	let data = error.data.unwrap();
	assert_eq!(data["kind"], "original");
	assert_eq!(data[ID_META]["request_id"], id(20));
	assert_eq!(
		data[ID_META]["original_metadata"],
		json!({"identity":"original collision"})
	);
	assert_eq!(
		data[ACK_META]["original_metadata"],
		json!({"retention":"original collision"})
	);
}

#[test]
fn result_ack_preserves_existing_ack_metadata_on_collision() {
	let mut value = CallToolResult::success(vec![ContentBlock::text("original result")]);
	let mut meta = MetaObject::new();
	meta.insert(ACK_META.into(), json!("prior ack metadata"));
	value.meta = Some(meta);
	let mut response = Ok(value.into());
	attach_identity(&mut response, &id(21));
	attach_ack(&mut response, "unknown", false);
	assert_eq!(
		unwrap_complete(&response).meta.as_ref().unwrap()[ACK_META]["original_metadata"],
		json!("prior ack metadata")
	);
}

#[test]
fn base64_roundtrips_edge_lengths_and_rejects_noncanonical_or_overflow_payloads() {
	for length in [0, 1, 2, 3, 4, 5, 127, 128, 129, 16384, MAX_RESULT_BYTES] {
		let bytes = (0..length)
			.map(|index| (index % 256) as u8)
			.collect::<Vec<_>>();
		assert_eq!(unbase64(&base64(&bytes)).unwrap(), bytes);
	}
	for text in [
		"A", "AAA", "!!!!", "A===", "====", "AB==", "AAF=", "YQ==YQ==", "YQ=+",
	] {
		assert!(unbase64(text).is_err(), "{text}");
	}
	assert!(unbase64(&base64(&vec![0; MAX_RESULT_BYTES + 1])).is_err());
}

#[test]
fn lookup_state_never_claims_legacy_or_ineligible_output_is_retained() {
	assert_eq!(
		result_state(None, "host_list"),
		"not_retained_legacy_or_unavailable"
	);
	assert_eq!(result_state(None, "request_result"), "not_retained_policy");
	assert_eq!(result_state(None, "process_read"), "not_retained_policy");
	assert!(serde_json::from_str::<Record>(r#"{"request_id":"bad"}"#).is_err());
}

#[test]
fn final_metadata_budget_preserves_exact_boundary_or_returns_bounded_same_id_refusal() {
	for (tool, cap) in [
		("effective_config", 256 * 1024),
		("request_result", 64 * 1024),
		("request_status", 64 * 1024),
	] {
		let mut response = Ok(CallToolResult::success(vec![ContentBlock::text("")]).into());
		attach_identity(&mut response, &id(123));
		let mut preview = response.clone();
		attach_ack(&mut preview, "durability_unknown_not_dispatched", false);
		let overhead = serde_json::to_vec(unwrap_complete(&preview)).unwrap().len();
		let text = "x".repeat(cap - overhead);
		response = Ok(CallToolResult::success(vec![ContentBlock::text(text)]).into());
		attach_identity(&mut response, &id(123));
		reserve_final_wire(&mut response, tool, &id(123));
		attach_ack(&mut response, "durability_unknown_not_dispatched", false);
		assert_eq!(
			serde_json::to_vec(unwrap_complete(&response))
				.unwrap()
				.len(),
			cap
		);
		let mut over = Ok(CallToolResult::success(vec![ContentBlock::text(
			"x".repeat(cap - overhead + 1),
		)])
		.into());
		attach_identity(&mut over, &id(123));
		reserve_final_wire(&mut over, tool, &id(123));
		let error = over.as_ref().unwrap_err();
		assert_eq!(error.data.as_ref().unwrap()[ID_META]["request_id"], id(123));
		assert!(error.message.contains("original result was not retained"));
		assert!(serde_json::to_vec(error).unwrap().len() < 1024);
	}
	for tool in [
		"search_results",
		"read_multiple_files",
		"process_list",
		"view",
		"request_history",
	] {
		assert!(!exposes_identity(tool));
	}
}
#[test]
fn corrupt_stored_payload_and_payload_on_unknown_are_refused_even_for_status_lookup() {
	for mutate in 0..3 {
		let root = private_root();
		let (request, intent) = admit(root.path(), 900 + mutate);
		let result = fixture_result(&request);
		store_fixture(intent, &result);
		let path = result_path(root.path(), &request);
		let mut record: Record = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
		match mutate {
			0 => record.payload_bytes = Some(MAX_RESULT_BYTES + 1),
			1 => record.payload_sha256 = Some("c".repeat(64)),
			_ => record.state = ResultState::Unknown,
		}
		fs::write(path, serde_json::to_vec(&record).unwrap()).unwrap();
		assert!(lookup_at(root.path(), &request, &policy()).is_err());
	}
}

#[test]
fn retention_overflow_includes_final_ack_budget_without_losing_original_response() {
	let root = private_root();
	let (request, intent) = admit(root.path(), 950);
	let mut response = Ok(CallToolResult::success(vec![ContentBlock::text("")]).into());
	attach_identity(&mut response, &request.request_id);
	let overhead = serde_json::to_vec(unwrap_complete(&response))
		.unwrap()
		.len();
	response = Ok(CallToolResult::success(vec![ContentBlock::text(
		"x".repeat(MAX_RESULT_BYTES - overhead),
	)])
	.into());
	attach_identity(&mut response, &request.request_id);
	let before = serde_json::to_vec(unwrap_complete(&response)).unwrap();
	assert_eq!(before.len(), MAX_RESULT_BYTES);
	assert_eq!(
		complete_sync(intent, Some(unwrap_complete(&response).clone())).unwrap(),
		"overflow"
	);
	assert_eq!(
		serde_json::to_vec(unwrap_complete(&response)).unwrap(),
		before
	);
	let stored = lookup_at(root.path(), &request, &policy())
		.unwrap()
		.unwrap();
	assert!(stored.state == ResultState::Overflow && stored.payload_base64.is_none());
}
