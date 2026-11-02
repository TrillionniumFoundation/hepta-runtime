// Copyright 2026 TrillionniumFoundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Durable preview cold-recovery and corruption/atomic-publish regressions.

use super::*;

fn sample(path: &str) -> Value {
	rea::inspect_bytes(b"\0asm\x01\0\0\0", path).expect("WASM preview")
}

#[tokio::test]
async fn native_preview_store_restores_after_new_reader() {
	let dir = tempfile::tempdir().expect("private state");
	let record = sample("/controlled/model.wasm");
	let id = record["native_evidence_id"]
		.as_str()
		.expect("id")
		.to_string();
	let receipt = retain_record(&record, dir.path()).await.expect("persist");
	assert_eq!(receipt["native_evidence_id"], id);
	assert_eq!(receipt["reused"], false);
	assert_eq!(receipt["rea_evidence_compatible"], false);
	let restored = read_record(&id, dir.path()).await.expect("cold read");
	assert_eq!(restored, record);

	let receipt = retain_record(&record, dir.path()).await.expect("reuse");
	assert_eq!(receipt["reused"], true);
	let restored = read_record(&id, dir.path()).await.expect("subsequent read");
	assert_eq!(restored, record);

	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt;
		let store = dir.path().join("rea-preview-v1");
		let entry = store.join(format!("{id}.json"));
		assert_eq!(
			std::fs::metadata(store)
				.expect("store")
				.permissions()
				.mode() & 0o777,
			0o700
		);
		assert_eq!(
			std::fs::metadata(entry)
				.expect("record")
				.permissions()
				.mode() & 0o777,
			0o600
		);
	}
}

#[tokio::test]
async fn same_digest_from_two_selected_paths_never_overwrites_first_capture() {
	let dir = tempfile::tempdir().expect("state");
	let a = sample("/controlled/origin_a");
	let b = sample("/controlled/origin_b");
	assert_eq!(a["native_evidence_id"], b["native_evidence_id"]);
	let (first, second) =
		tokio::join!(retain_record(&a, dir.path()), retain_record(&b, dir.path()));
	let first = first.expect("first");
	let second = second.expect("second");
	assert_ne!(first["reused"], second["reused"]);
	let id = a["native_evidence_id"].as_str().expect("id");
	let saved = read_record(id, dir.path())
		.await
		.expect("verified saved record");
	assert!(
		saved["subject"]["local_path"] == "/controlled/origin_a"
			|| saved["subject"]["local_path"] == "/controlled/origin_b"
	);
	let contents = std::fs::read_dir(dir.path().join("rea-preview-v1"))
		.expect("store entries")
		.count();
	assert_eq!(
		contents, 1,
		"staging files must be removed after link publication"
	);
}

#[tokio::test]
async fn corrupt_store_never_returns_data_or_overwrites_it_on_retry() {
	let dir = tempfile::tempdir().expect("state");
	let record = sample("/controlled/original");
	let id = record["native_evidence_id"]
		.as_str()
		.expect("id")
		.to_string();
	retain_record(&record, dir.path()).await.expect("retain");
	let name = dir.path().join("rea-preview-v1").join(format!("{id}.json"));
	tokio::fs::write(&name, b"{\"store_format\":\"tampered\"}")
		.await
		.expect("inject corruption");
	let before = tokio::fs::read(&name).await.expect("corrupted bytes");
	assert!(read_record(&id, dir.path()).await.is_err());
	assert!(retain_record(&record, dir.path()).await.is_err());
	assert_eq!(tokio::fs::read(&name).await.expect("still damaged"), before);
}

#[tokio::test]
async fn changed_uncommitted_metadata_cannot_reuse_existing_record() {
	let dir = tempfile::tempdir().expect("state");
	let a = sample("/controlled/original");
	retain_record(&a, dir.path()).await.expect("retain");
	let mut b = a.clone();
	b["limitations"] = json!(["a producer with different declared coverage"]);
	assert!(retain_record(&b, dir.path()).await.is_err());
	let id = a["native_evidence_id"].as_str().expect("id");
	assert_eq!(
		read_record(id, dir.path()).await.expect("still original"),
		a
	);
}

#[test]
fn malformed_native_id_and_semantic_digest_are_rejected_before_lookup() {
	for id in [
		"",
		"../outside",
		"hepta_rea_preview_v1_",
		"hepta_rea_preview_v1_0123",
		"hepta_rea_preview_v1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	] {
		assert!(id_suffix(id).is_err(), "{id}");
	}
	let mut record = sample("/controlled/model");
	record["normalized_result"]["format"] = json!("elf");
	assert!(report_identity(&record).is_err());
	let mut record = sample("/controlled/model");
	record["coverage"]["status"] = json!("complete");
	assert!(report_identity(&record).is_err());
	let mut record = sample("/controlled/model");
	record["rea_evidence_compatible"] = json!(true);
	assert!(report_identity(&record).is_err());
}

#[tokio::test]
async fn missing_stored_identity_does_not_create_a_record() {
	let state = tempfile::tempdir().expect("state");
	let id = format!("{}{}", ID_PREFIX, "a".repeat(64));
	assert!(read_record(&id, state.path()).await.is_err());
	assert!(!state.path().join("rea-preview-v1").exists());
}

#[cfg(unix)]
#[tokio::test]
async fn symlinked_or_world_readable_store_directory_is_refused() {
	use std::os::unix::fs::PermissionsExt;
	let state = tempfile::tempdir().expect("state");
	let other = tempfile::tempdir().expect("other");
	let link = state.path().join("rea-preview-v1");
	std::os::unix::fs::symlink(other.path(), &link).expect("symlink");
	assert!(retain_record(&sample("/selected"), state.path())
		.await
		.is_err());
	std::fs::remove_file(&link).expect("remove symlink");
	std::fs::create_dir(&link).expect("open dir");
	std::fs::set_permissions(&link, std::fs::Permissions::from_mode(0o755)).expect("loose policy");
	assert!(retain_record(&sample("/selected"), state.path())
		.await
		.is_err());
}

#[test]
fn durable_envelope_rejects_duplicate_json_and_unknown_members() {
	let record = sample("/controlled/original");
	let id = record["native_evidence_id"].as_str().expect("id");
	let envelope = make_envelope(&record).expect("sealed envelope");
	assert!(verify_envelope(&envelope, id).is_ok());
	let original = "\"store_format\":\"hepta.rea.preview-store.v1\"";
	let text = String::from_utf8(envelope).expect("utf-8 JSON");
	assert!(text.contains(original));
	let duplicate = text.replacen(original, &format!("{original},{original}"), 1);
	assert!(verify_envelope(duplicate.as_bytes(), id).is_err());
	let mut unexpected: Value = serde_json::from_str(&text).expect("object");
	unexpected["extra"] = json!(true);
	assert!(verify_envelope(&serde_json::to_vec(&unexpected).expect("json"), id).is_err());
}

#[tokio::test]
async fn repeated_concurrent_first_publications_never_expose_a_wide_permission_window() {
	for round in 0..24 {
		let state = tempfile::tempdir().expect("isolated new state");
		let report = sample("/controlled/admitted.wasm");
		let (a, b, c, d) = tokio::join!(
			retain_record(&report, state.path()),
			retain_record(&report, state.path()),
			retain_record(&report, state.path()),
			retain_record(&report, state.path())
		);
		let mut published = 0;
		for result in [a, b, c, d] {
			let receipt = result.unwrap_or_else(|error| panic!("round {round}: {error}"));
			assert_eq!(receipt["status"], "retained");
			if receipt["reused"] == false {
				published += 1;
			}
		}
		assert_eq!(published, 1, "only one exclusive hard link can publish");
		#[cfg(unix)]
		{
			use std::os::unix::fs::PermissionsExt;
			let mode = std::fs::metadata(state.path().join("rea-preview-v1"))
				.expect("created store root")
				.permissions()
				.mode();
			assert_eq!(
				mode & 0o077,
				0,
				"private mode must be atomic on round {round}"
			);
		}
	}
}

#[test]
fn store_quota_counts_existing_records_and_abandoned_staging_bytes() {
	let root = tempfile::tempdir().expect("store");
	let one = root.path().join("one.json");
	let two = root.path().join("two.json");
	std::fs::write(&one, b"one").expect("one");
	std::fs::write(&two, b"two").expect("two");
	assert!(enforce_quota(root.path(), 1, 2, 1024).is_err());
	assert!(enforce_quota(root.path(), 1, 3, 1024).is_ok());
	let abandoned = root.path().join(".abandoned.tmp");
	std::fs::write(&abandoned, b"uncommitted").expect("abandoned");
	assert!(enforce_quota(root.path(), 1, 3, 10).is_err());
}

#[tokio::test]
async fn total_byte_quota_is_enforced_without_replacing_prior_data() {
	let state = tempfile::tempdir().expect("state");
	let report = sample("/controlled/valid.wasm");
	let id = report["native_evidence_id"]
		.as_str()
		.expect("id")
		.to_string();
	retain_record(&report, state.path())
		.await
		.expect("initial retain");
	let root = state.path().join("rea-preview-v1");
	let orphan = root.join(".uncommitted-large.tmp");
	let file = std::fs::OpenOptions::new()
		.create_new(true)
		.write(true)
		.open(&orphan)
		.expect("sparse test staging file");
	file.set_len(MAX_STORED_BYTES + 1)
		.expect("sparse file length");
	let another = rea::inspect_bytes(b"\0asm\x01\0\0\0additional", "/controlled/another")
		.expect("different source digest");
	assert_ne!(another["native_evidence_id"], id);
	assert!(retain_record(&another, state.path()).await.is_err());
	assert_eq!(
		read_record(&id, state.path()).await.expect("old content"),
		report
	);
	let reused = retain_record(&report, state.path())
		.await
		.expect("reuse at capacity");
	assert_eq!(reused["reused"], true);
	std::fs::remove_file(&orphan).expect("remove orphan");
	assert!(retain_record(&another, state.path()).await.is_ok());
}

#[cfg(unix)]
#[tokio::test]
async fn external_hardlinks_cannot_reuse_or_read_retained_previews() {
	let state = tempfile::tempdir().expect("state");
	let record = sample("/controlled/admitted.wasm");
	let id = record["native_evidence_id"].as_str().expect("id");
	retain_record(&record, state.path()).await.expect("initial record");
	let root = state.path().join("rea-preview-v1");
	let filename = root.join(format!("{id}.json"));
	let external = state.path().join("external-link.json");
	std::fs::hard_link(&filename, &external).expect("create external hardlink");
	assert!(read_record(id, state.path()).await.is_err());
	assert!(retain_record(&record, state.path()).await.is_err());
	assert!(enforce_quota(&root, 1, MAX_STORED_RECORDS, MAX_STORED_BYTES).is_err());
	std::fs::remove_file(&external).expect("remove hardlink");
	assert_eq!(read_record(id, state.path()).await.expect("recovered"), record);
}
