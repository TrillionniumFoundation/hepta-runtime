// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! The unpaginated projection must preserve the former full-record inventory contract.
use super::*;

fn record(id: &str, host: &str, created_unix_ms: u128) -> JobRecord {
	let mut record: JobRecord = serde_json::from_value(json!({
		"id":id,"host":host,"created_unix_ms":0,"execution_mode":"operator",
		"system_jobctl":false,"ssh_target":"PRIVATE_SSH","unit":"PRIVATE_UNIT",
		"remote_job_dir":"/PRIVATE_REMOTE","executable":"/PRIVATE_EXECUTABLE",
		"args":["PRIVATE_ARGUMENT"],"cwd":"/PRIVATE_CWD","env_keys":["PRIVATE_ENV"],
		"idempotency_key":"PRIVATE_KEY","request_fingerprint":7,
		"request_digest":"a".repeat(64),"launch_state":"launched","launch_error":null
	}))
	.unwrap();
	record.created_unix_ms = created_unix_ms;
	record
}

fn write_bytes(path: &Path, bytes: &[u8]) {
	let mut options = OpenOptions::new();
	options.create_new(true).write(true);
	#[cfg(unix)]
	{
		use std::os::unix::fs::OpenOptionsExt;
		options.mode(0o600);
	}
	options.open(path).unwrap().write_all(bytes).unwrap();
}

fn write_record(root: &Path, record: &JobRecord) -> PathBuf {
	let path = root.join(format!("{}.json", record.id));
	write_bytes(&path, &serde_json::to_vec(record).unwrap());
	path
}

fn fixture_paths_in_encounter_order(root: &Path, count: usize) -> Vec<PathBuf> {
	for index in 0..count {
		write_bytes(&root.join(format!("slot-{index}.json")), b"{}");
	}
	// Subsequent writes replace bytes, not directory entries. Place the source
	// refusal after the otherwise oversized/unserializable row in this fixture's
	// observed enumeration so an eager wire conversion cannot hide the refusal.
	let paths: Vec<_> = std::fs::read_dir(root)
		.unwrap()
		.map(|entry| entry.unwrap().path())
		.collect();
	assert_eq!(paths.len(), count);
	paths
}

fn legacy_response(root: &Path, host: Option<&str>) -> Result<String> {
	// These are the unchanged former production reader, sort, filter and wire
	// serializer. Keep this oracle independent of the projected scan and formatter.
	let records: Vec<_> = all_records_in(root)?
		.into_iter()
		.filter(|record| host.is_none_or(|host| record.host == host))
		.collect();
	job_inventory_response(&records)
}

fn projected_response(root: &Path, host: Option<&str>) -> Result<String> {
	job_inventory_rows_response(&list_job_rows_in(root, host)?)
}

fn wire(text: &str) -> Vec<u8> {
	serde_json::to_vec(&rmcp::model::CallToolResult::success(vec![
		rmcp::model::ContentBlock::text(text.to_owned()),
	]))
	.unwrap()
}

fn assert_same_response(root: &Path, host: Option<&str>) -> Value {
	let legacy = legacy_response(root, host).unwrap();
	let projected = projected_response(root, host).unwrap();
	assert_eq!(projected.as_bytes(), legacy.as_bytes());
	assert_eq!(wire(&projected), wire(&legacy));
	let value: Value = serde_json::from_str(&projected).unwrap();
	assert_eq!(value["inventory_complete"], true);
	assert_eq!(value["status_authoritative"], false);
	let rows = value["jobs"].as_array().unwrap();
	assert_eq!(value["total"].as_u64().unwrap() as usize, rows.len());
	assert_eq!(value.as_object().unwrap().len(), 4);
	for row in rows {
		assert_eq!(
			row.as_object()
				.unwrap()
				.keys()
				.map(String::as_str)
				.collect::<Vec<_>>(),
			[
				"created_unix_ms",
				"execution_mode",
				"host",
				"id",
				"launch_state"
			]
		);
	}
	value
}

fn assert_same_refusal(root: &Path, host: Option<&str>, reason: &str) {
	let legacy = legacy_response(root, host).unwrap_err();
	let projected = projected_response(root, host).unwrap_err();
	assert_eq!(format!("{projected:#}"), format!("{legacy:#}"));
	assert!(projected.to_string().contains(reason), "{projected:#}");
}

#[test]
fn unpaginated_projection_preserves_exact_wire_host_filters_and_timestamp_ties() {
	let root = tempfile::tempdir().unwrap();
	let hosts = ["main", "rog", "mac"];
	for index in 0..24 {
		let mut value = record(
			&format!("entry-{:02}", 23 - index),
			hosts[index % hosts.len()],
			((index * 7) % 5) as u128,
		);
		if index % 2 == 1 {
			value.execution_mode = ExecutionMode::Isolated;
		}
		value.launch_state = ["launched", "pending", "unknown\n\"observed\""][index % 3].into();
		write_record(root.path(), &value);
	}
	for host in [
		None,
		Some("main"),
		Some("rog"),
		Some("mac"),
		Some("unselected"),
	] {
		let value = assert_same_response(root.path(), host);
		let rows = value["jobs"].as_array().unwrap();
		assert!(rows.windows(2).all(|pair| {
			pair[0]["created_unix_ms"].as_u64().unwrap()
				<= pair[1]["created_unix_ms"].as_u64().unwrap()
		}));
		assert!(rows
			.iter()
			.all(|row| host.is_none_or(|host| row["host"] == host)));
	}
	// The equal-timestamp order is directory encounter order, not an added ID
	// tiebreaker. Compare it directly with this unchanged fixture's enumeration.
	let encountered: Vec<String> = std::fs::read_dir(root.path())
		.unwrap()
		.map(|entry| {
			let path = entry.unwrap().path();
			read_record_at(&path, path.file_stem().unwrap().to_str().unwrap()).unwrap()
		})
		.filter(|record| record.host == "main" && record.created_unix_ms == 1)
		.map(|record| record.id)
		.collect();
	let projected = list_job_rows_in(root.path(), Some("main")).unwrap();
	let tied: Vec<_> = projected
		.into_iter()
		.filter(|record| record.created_unix_ms == 1)
		.map(|record| record.id)
		.collect();
	assert!(!encountered.is_empty());
	assert_eq!(tied, encountered);
}

#[test]
fn large_private_fields_do_not_enter_the_retained_public_projection_or_response() {
	let root = tempfile::tempdir().unwrap();
	let mut original_bytes = Vec::new();
	for index in 0..12 {
		let mut value = record(&format!("private-{index:02}"), "main", (12 - index) as u128);
		value.args = vec![
			"PRIVATE_ARGUMENT".repeat(4096),
			"PRIVATE_UNICODE_内容".repeat(512),
		];
		value.cwd = Some("/PRIVATE_CWD".repeat(512));
		value.remote_job_dir = "/PRIVATE_REMOTE".repeat(512);
		value.ssh_target = "PRIVATE_SSH".repeat(512);
		value.executable = "/PRIVATE_EXECUTABLE".repeat(512);
		value.env_keys = vec!["PRIVATE_ENV".repeat(1024)];
		value.launch_error = Some("PRIVATE_ERROR".repeat(1024));
		let path = write_record(root.path(), &value);
		original_bytes.push((path.clone(), std::fs::read(path).unwrap()));
	}
	let rows = list_job_rows_in(root.path(), None).unwrap();
	assert_eq!(rows.len(), 12);
	let value = assert_same_response(root.path(), None);
	assert!(!value.to_string().contains("PRIVATE_"));
	for (path, bytes) in original_bytes {
		assert_eq!(std::fs::read(path).unwrap(), bytes);
	}
}

#[test]
fn unselected_wide_timestamps_and_ignored_fields_preserve_the_compatibility_result() {
	let root = tempfile::tempdir().unwrap();
	write_record(root.path(), &record("selected", "main", 2));
	let other = record("unselected", "rog", u128::from(u64::MAX) + 1);
	write_record(root.path(), &other);
	let path = write_record(root.path(), &record("unknown-fields", "rog", 1));
	let mut raw: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
	raw["future_private_field"] = json!({"nested":[true,null,"ignored"]});
	std::fs::write(&path, serde_json::to_vec(&raw).unwrap()).unwrap();
	let value = assert_same_response(root.path(), Some("main"));
	assert_eq!(value["total"], 1);
	assert_eq!(value["jobs"][0]["id"], "selected");
	assert_eq!(
		assert_same_response(root.path(), Some("absent"))["total"],
		0
	);
}

#[test]
fn invalid_discarded_fields_still_refuse_an_unselected_host() {
	let root = tempfile::tempdir().unwrap();
	write_record(root.path(), &record("selected", "main", 1));
	let path = write_record(root.path(), &record("unselected", "rog", 2));
	let mut raw: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
	raw["args"] = json!([17]);
	std::fs::write(&path, serde_json::to_vec(&raw).unwrap()).unwrap();
	assert_same_refusal(root.path(), Some("main"), "corrupt job record");
}

#[test]
fn full_source_refusal_precedes_selected_wide_timestamp_serialization() {
	let root = tempfile::tempdir().unwrap();
	let paths = fixture_paths_in_encounter_order(root.path(), 2);
	let id = paths[0].file_stem().unwrap().to_str().unwrap();
	let wide = record(id, "main", u128::from(u64::MAX) + 1);
	std::fs::write(&paths[0], serde_json::to_vec(&wide).unwrap()).unwrap();
	std::fs::write(&paths[1], b"{truncated").unwrap();
	assert_same_refusal(root.path(), Some("main"), "corrupt job record");
}

#[test]
fn compatibility_inventory_accepts_private_payloads_above_the_strict_cache_limit() {
	let root = tempfile::tempdir().unwrap();
	let mut value = record("large-compatible", "main", 3);
	value.args = vec!["x".repeat(MAX_CACHED_RECORD_BYTES as usize + 37)];
	let path = write_record(root.path(), &value);
	assert!(std::fs::metadata(&path).unwrap().len() > MAX_CACHED_RECORD_BYTES);
	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt;
		std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
	}
	assert_eq!(assert_same_response(root.path(), None)["total"], 1);
}

#[test]
fn inventory_keeps_non_json_staging_files_untouched_and_empty_results_complete() {
	let root = tempfile::tempdir().unwrap();
	let staging = root.path().join("uncommitted.json.tmp.7");
	write_bytes(&staging, b"not a committed JSON receipt");
	std::fs::create_dir(root.path().join("unrelated-directory")).unwrap();
	assert_eq!(assert_same_response(root.path(), None)["total"], 0);
	assert_eq!(
		std::fs::read(staging).unwrap(),
		b"not a committed JSON receipt"
	);
}

#[test]
fn inventory_keeps_the_exact_one_mib_wire_boundary_and_whole_result_refusal() {
	const BUDGET: usize = 1024 * 1024;
	let root = tempfile::tempdir().unwrap();
	let mut value = record("wire-boundary", "main", 1);
	value.launch_state.clear();
	let empty_text = job_inventory_response(std::slice::from_ref(&value)).unwrap();
	let overhead = wire(&empty_text).len();
	value.launch_state = "x".repeat(BUDGET - overhead);
	let path = write_record(root.path(), &value);
	let projected = projected_response(root.path(), None).unwrap();
	assert_eq!(wire(&projected).len(), BUDGET);
	assert_eq!(projected, legacy_response(root.path(), None).unwrap());
	value.launch_state.push('x');
	std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
	assert_same_refusal(root.path(), None, "No partial inventory returned");
}

#[test]
fn over_budget_projection_still_validates_neighbors_and_host_filter_can_narrow_the_result() {
	let root = tempfile::tempdir().unwrap();
	let paths = fixture_paths_in_encounter_order(root.path(), 3);
	for (index, path) in paths.iter().enumerate() {
		let id = path.file_stem().unwrap().to_str().unwrap();
		let mut value = record(id, if index == 1 { "main" } else { "rog" }, index as u128);
		if index == 0 {
			value.launch_state = "x".repeat(1024 * 1024);
		}
		std::fs::write(path, serde_json::to_vec(&value).unwrap()).unwrap();
	}
	assert_same_refusal(root.path(), None, "No partial inventory returned");
	assert_eq!(assert_same_response(root.path(), Some("main"))["total"], 1);
	std::fs::write(&paths[2], b"{truncated").unwrap();
	for host in [None, Some("main"), Some("absent")] {
		assert_same_refusal(root.path(), host, "corrupt job record");
	}
}

#[test]
fn oversized_receipts_and_mismatched_filenames_keep_the_original_refusals() {
	for case in ["oversized", "identity"] {
		let root = tempfile::tempdir().unwrap();
		write_record(root.path(), &record("selected", "main", 1));
		let path = root.path().join("unselected.json");
		if case == "oversized" {
			write_bytes(&path, b"");
			OpenOptions::new()
				.write(true)
				.open(&path)
				.unwrap()
				.set_len(MAX_JOB_RECORD_BYTES + 1)
				.unwrap();
		} else {
			write_bytes(
				&path,
				&serde_json::to_vec(&record("different-id", "rog", 2)).unwrap(),
			);
		}
		let reason = if case == "oversized" {
			"invalid or oversized durable job record"
		} else {
			"filename/identity mismatch"
		};
		assert_same_refusal(root.path(), Some("main"), reason);
	}
}

#[cfg(unix)]
#[test]
fn unselected_nonregular_hardlinked_and_non_utf8_receipts_are_not_skipped() {
	use std::os::unix::ffi::{OsStrExt, OsStringExt};
	use std::os::unix::fs::symlink;
	for case in ["symlink", "hardlink", "directory", "fifo", "filename"] {
		let root = tempfile::tempdir().unwrap();
		write_record(root.path(), &record("selected", "main", 1));
		let path = root.path().join("unselected.json");
		let reason = match case {
			"symlink" => {
				let held = root.path().join("held-receipt.bin");
				write_bytes(
					&held,
					&serde_json::to_vec(&record("unselected", "rog", 2)).unwrap(),
				);
				symlink(&held, &path).unwrap();
				"unsafe durable job record type"
			}
			"hardlink" => {
				write_record(root.path(), &record("unselected", "rog", 2));
				std::fs::hard_link(&path, root.path().join("held-receipt.bin")).unwrap();
				"unsafe durable job receipt ownership or inode"
			}
			"directory" => {
				std::fs::create_dir(&path).unwrap();
				"unsafe durable job record type"
			}
			"fifo" => {
				let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
				assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
				"unsafe durable job record type"
			}
			"filename" => {
				let name = std::ffi::OsString::from_vec(b"non-utf8-\xff.json".to_vec());
				write_bytes(
					&root.path().join(name),
					b"not decoded before filename refusal",
				);
				"invalid durable job record name"
			}
			_ => unreachable!(),
		};
		assert_same_refusal(root.path(), Some("main"), reason);
	}
}
