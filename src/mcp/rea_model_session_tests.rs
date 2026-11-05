// Copyright 2026 Muvon Un Limited
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

//! Snapshot identity, cold reconstruction, bounded reuse and corruption tests.

use super::*;
use std::io::{Seek, SeekFrom, Write};
use tempfile::TempDir;

fn fixture(tensors: usize, elements: usize) -> Vec<u8> {
	let mut entries = serde_json::Map::new();
	for number in 0..tensors {
		entries.insert(
			format!("t{number:04}"),
			json!({"dtype":"F32","shape":[elements],
			"data_offsets":[number * elements * 4,(number + 1) * elements * 4]}),
		);
	}
	entries.insert(
		"__metadata__".into(),
		json!({"producer":"independent-test-fixture"}),
	);
	let mut header = serde_json::to_vec(&entries).unwrap();
	while !header.len().is_multiple_of(8) {
		header.push(b' ');
	}
	let mut bytes = (header.len() as u64).to_le_bytes().to_vec();
	bytes.extend(header);
	for number in 0..tensors {
		for element in 0..elements {
			bytes.extend_from_slice(&(number as f32 + element as f32 / 16.0).to_le_bytes());
		}
	}
	bytes
}

fn environment() -> (TempDir, Scope) {
	let temp = tempfile::tempdir().unwrap();
	let workspace = temp.path().join("workspace");
	std::fs::create_dir(&workspace).unwrap();
	let scope = Scope {
		state: temp.path().join("state"),
		roots: vec![workspace],
		owner_sha256: hash(b"authenticated-owner-a"),
		policy_sha256: hash(b"complete-policy-a"),
	};
	(temp, scope)
}

fn source(scope: &Scope, bytes: &[u8]) -> OpenModelSessionParams {
	let path = scope.roots[0].join("model.safetensors");
	std::fs::write(&path, bytes).unwrap();
	OpenModelSessionParams {
		path: path.to_str().unwrap().to_owned(),
		expected_sha256: hash(bytes),
	}
}

fn query_params(id: &str, offset: usize, limit: usize) -> QueryModelSessionParams {
	QueryModelSessionParams {
		session_id: id.to_owned(),
		collection: Collection::Tensors,
		offset,
		limit,
	}
}

fn raw_read(id: &str, offset: u64, length: usize) -> ReadModelSessionParams {
	ReadModelSessionParams {
		session_id: id.to_owned(),
		tensor_name: None,
		offset,
		length,
	}
}

fn parse(output: String) -> Value {
	serde_json::from_str(&output).unwrap()
}
fn id(receipt: &Value) -> &str {
	receipt["session_id"].as_str().unwrap()
}

// Public entry requires the real effect-owner AdmissionPermit. These store
// unit tests use an explicit no-op admission; lifecycle tests below additionally
// supply a real independently locked owner file through the same generic path.
async fn open_at(scope: &Scope, params: &OpenModelSessionParams) -> Result<Value> {
	open_with_admission(scope, params, ()).await
}

#[tokio::test]
async fn retained_pages_and_ranges_survive_source_removal_and_scope_reconstruction() {
	let (_temp, scope) = environment();
	let params = source(&scope, &fixture(130, 2));
	let receipt = open_at(&scope, &params).await.unwrap();
	assert_eq!(receipt["directory_parses_this_open"], 1);
	assert_eq!(receipt["full_source_hash_passes_this_open"], 1);
	let first = parse(
		query_at(&scope, query_params(id(&receipt), 63, 66))
			.await
			.unwrap(),
	);
	assert_eq!(first["index_pages_read"], 3);
	assert_eq!(first["snapshot_payload_bytes_read"], 0);
	assert_eq!(first["directory_parse_count"], 0);
	assert_eq!(first["result"]["rows"].as_array().unwrap().len(), 66);
	assert_eq!(first["result"]["rows"][0]["name"], "t0063");
	assert_eq!(first["result"]["rows"][65]["name"], "t0128");
	let restored_scope = Scope {
		state: scope.state.clone(),
		roots: scope.roots.clone(),
		owner_sha256: scope.owner_sha256.clone(),
		policy_sha256: scope.policy_sha256.clone(),
	};
	std::fs::remove_file(&params.path).unwrap();
	let restored = parse(
		query_at(&restored_scope, query_params(id(&receipt), 63, 66))
			.await
			.unwrap(),
	);
	assert_eq!(first, restored);
	let output = parse(
		read_at(
			&restored_scope,
			ReadModelSessionParams {
				session_id: id(&receipt).into(),
				tensor_name: Some("t0063".into()),
				offset: 0,
				length: 8,
			},
		)
		.await
		.unwrap(),
	);
	let expected = [63_f32.to_le_bytes(), 63.0625_f32.to_le_bytes()].concat();
	assert_eq!(output["bytes_hex"], super::super::digest_hex(&expected));
	assert_eq!(output["sha256"], hash(&expected));
	assert_eq!(output["directory_parse_count"], 0);
	assert_eq!(output["complete_snapshot_rehashed_this_read"], false);
}

#[tokio::test]
async fn original_mutation_keeps_snapshot_stable_and_new_capture_requires_new_hash() {
	let (_temp, scope) = environment();
	let bytes = fixture(2, 8);
	let params = source(&scope, &bytes);
	let receipt = open_at(&scope, &params).await.unwrap();
	let previous = parse(
		read_at(&scope, raw_read(id(&receipt), 0, 16))
			.await
			.unwrap(),
	);
	let mut changed = bytes.clone();
	*changed.last_mut().unwrap() ^= 1;
	std::fs::write(&params.path, &changed).unwrap();
	assert!(open_at(&scope, &params)
		.await
		.unwrap_err()
		.to_string()
		.contains("SHA-256"));
	assert_eq!(
		previous,
		parse(
			read_at(&scope, raw_read(id(&receipt), 0, 16))
				.await
				.unwrap()
		)
	);
	let revised = open_at(
		&scope,
		&OpenModelSessionParams {
			path: params.path.clone(),
			expected_sha256: hash(&changed),
		},
	)
	.await
	.unwrap();
	assert_ne!(id(&receipt), id(&revised));
	assert_eq!(std::fs::read(&params.path).unwrap(), changed);
	let root = store::root_path(&scope.state).unwrap();
	assert!(std::fs::read_dir(root).unwrap().all(|e| !e
		.unwrap()
		.file_name()
		.to_string_lossy()
		.starts_with(".stage")));
}

#[tokio::test]
async fn owner_policy_and_current_roots_are_rechecked_after_restart() {
	let (_temp, scope) = environment();
	let params = source(&scope, &fixture(1, 2));
	let receipt = open_at(&scope, &params).await.unwrap();
	let mut other = Scope {
		state: scope.state.clone(),
		roots: scope.roots.clone(),
		owner_sha256: hash(b"owner-b"),
		policy_sha256: scope.policy_sha256.clone(),
	};
	assert!(query_at(&other, query_params(id(&receipt), 0, 1))
		.await
		.is_err());
	assert!(read_at(&other, raw_read(id(&receipt), 0, 1)).await.is_err());
	other.owner_sha256 = scope.owner_sha256.clone();
	other.policy_sha256 = hash(b"changed-policy");
	assert!(query_at(&other, query_params(id(&receipt), 0, 1))
		.await
		.is_err());
	other.policy_sha256 = scope.policy_sha256.clone();
	other.roots.clear();
	assert!(query_at(&other, query_params(id(&receipt), 0, 1))
		.await
		.is_err());
}

#[tokio::test]
async fn touched_chunks_are_verified_without_claiming_unread_chunks_were_checked() {
	let (_temp, scope) = environment();
	let bytes = fixture(1, CHUNK_BYTES);
	let params = source(&scope, &bytes);
	let receipt = open_at(&scope, &params).await.unwrap();
	let result = parse(
		read_at(&scope, raw_read(id(&receipt), CHUNK_BYTES as u64 - 17, 64))
			.await
			.unwrap(),
	);
	assert_eq!(
		result["bytes_hex"],
		super::super::digest_hex(&bytes[CHUNK_BYTES - 17..CHUNK_BYTES + 47])
	);
	assert_eq!(result["verified_chunk_indices"], json!([0, 1]));
	assert_eq!(result["snapshot_payload_bytes_read"], 2 * CHUNK_BYTES);
	let snapshot = store::root_path(&scope.state)
		.unwrap()
		.join(id(&receipt))
		.join("snapshot.bin");
	let corrupt_at = 3 * CHUNK_BYTES;
	let mut file = std::fs::OpenOptions::new()
		.write(true)
		.open(&snapshot)
		.unwrap();
	file.seek(SeekFrom::Start(corrupt_at as u64)).unwrap();
	file.write_all(&[bytes[corrupt_at] ^ 0x80]).unwrap();
	file.sync_all().unwrap();
	let unaffected = parse(read_at(&scope, raw_read(id(&receipt), 0, 8)).await.unwrap());
	assert_eq!(unaffected["verified_chunk_indices"], json!([0]));
	assert_eq!(unaffected["complete_snapshot_rehashed_this_read"], false);
	assert!(
		read_at(&scope, raw_read(id(&receipt), corrupt_at as u64, 1))
			.await
			.unwrap_err()
			.to_string()
			.contains("chunk")
	);
	assert!(query_at(&scope, query_params(id(&receipt), 0, 1))
		.await
		.is_ok());
	assert!(
		open_at(&scope, &params).await.is_err(),
		"reuse validates all stored chunks"
	);
}

#[tokio::test]
async fn damaged_index_and_manifest_never_return_cached_success() {
	let (_temp, scope) = environment();
	let params = source(&scope, &fixture(2, 2));
	let receipt = open_at(&scope, &params).await.unwrap();
	let directory = store::root_path(&scope.state).unwrap().join(id(&receipt));
	let page = directory.join("tensors-0000.json");
	let original = std::fs::read(&page).unwrap();
	let mut corrupt = original.clone();
	corrupt[0] ^= 1;
	std::fs::write(&page, corrupt).unwrap();
	assert!(query_at(&scope, query_params(id(&receipt), 0, 1))
		.await
		.unwrap_err()
		.to_string()
		.contains("digest"));
	std::fs::write(&page, &original).unwrap();
	assert!(query_at(&scope, query_params(id(&receipt), 0, 1))
		.await
		.is_ok());
	let path = directory.join("manifest.json");
	let mut document: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
	document["source_sha256"] = json!("0".repeat(64));
	std::fs::write(&path, serde_json::to_vec(&document).unwrap()).unwrap();
	assert!(query_at(&scope, query_params(id(&receipt), 0, 1))
		.await
		.is_err());
}

#[tokio::test]
async fn unchanged_concurrent_open_publishes_one_stable_session() {
	let (_temp, scope) = environment();
	let params = source(&scope, &fixture(65, 2));
	let (a, b) = tokio::join!(open_at(&scope, &params), open_at(&scope, &params));
	let a = a.unwrap();
	let b = b.unwrap();
	assert_eq!(id(&a), id(&b));
	assert_ne!(a["reused"], b["reused"]);
	let entries: Vec<_> = std::fs::read_dir(store::root_path(&scope.state).unwrap())
		.unwrap()
		.map(|e| e.unwrap().file_name())
		.collect();
	assert_eq!(entries.len(), 1);
	assert_eq!(entries[0].to_str().unwrap(), id(&a));
}

#[tokio::test]
async fn state_paths_symlinks_wrong_hashes_and_invalid_ranges_are_refused() {
	use std::os::unix::fs::symlink;
	let (_temp, mut scope) = environment();
	let params = source(&scope, &fixture(1, 4));
	let receipt = open_at(&scope, &params).await.unwrap();
	let alias = scope.roots[0].join("alias.safetensors");
	symlink(&params.path, &alias).unwrap();
	assert!(open_at(
		&scope,
		&OpenModelSessionParams {
			path: alias.to_str().unwrap().into(),
			expected_sha256: params.expected_sha256.clone(),
		}
	)
	.await
	.is_err());
	scope.roots.push(scope.state.parent().unwrap().to_owned());
	let snapshot = store::root_path(&scope.state)
		.unwrap()
		.join(id(&receipt))
		.join("snapshot.bin");
	assert!(open_at(
		&scope,
		&OpenModelSessionParams {
			path: snapshot.to_str().unwrap().into(),
			expected_sha256: params.expected_sha256.clone(),
		}
	)
	.await
	.unwrap_err()
	.to_string()
	.contains("runtime state"));
	assert!(
		read_at(&scope, raw_read(id(&receipt), 0, MAX_READ_BYTES + 1))
			.await
			.is_err()
	);
	assert!(read_at(&scope, raw_read(id(&receipt), u64::MAX, 1))
		.await
		.is_err());
	assert!(query_at(&scope, query_params(id(&receipt), 2, 1))
		.await
		.is_err());
	assert!(query_at(&scope, query_params("../escape", 0, 1))
		.await
		.is_err());
	let mut invalid = params.clone();
	invalid.expected_sha256 = "a".repeat(64);
	assert!(open_at(&scope, &invalid).await.is_err());
}

#[tokio::test]
async fn private_inode_rules_apply_to_recovered_indexes_and_snapshot_reads() {
	let (_temp, scope) = environment();
	let params = source(&scope, &fixture(1, 4));
	let receipt = open_at(&scope, &params).await.unwrap();
	let directory = store::root_path(&scope.state).unwrap().join(id(&receipt));
	let snapshot = directory.join("snapshot.bin");
	let alias = scope.roots[0].join("snapshot-alias");
	std::fs::hard_link(&snapshot, &alias).unwrap();
	assert!(read_at(&scope, raw_read(id(&receipt), 0, 1)).await.is_err());
	std::fs::remove_file(alias).unwrap();
	assert!(read_at(&scope, raw_read(id(&receipt), 0, 1)).await.is_ok());
	std::fs::hard_link(
		directory.join("tensors-0000.json"),
		scope.roots[0].join("page-alias"),
	)
	.unwrap();
	assert!(query_at(&scope, query_params(id(&receipt), 0, 1))
		.await
		.is_err());
}

#[tokio::test]
async fn incomplete_staging_counts_toward_both_storage_budgets() {
	let (_temp, scope) = environment();
	let root = store::root(&scope.state, true).await.unwrap();
	for _ in 0..MAX_SESSION_COUNT {
		store::staging(&root).await.unwrap();
	}
	assert!(store::admit_quota(&root, 1)
		.await
		.unwrap_err()
		.to_string()
		.contains("count"));
	let (_temp2, scope2) = environment();
	let root2 = store::root(&scope2.state, true).await.unwrap();
	let stage = store::staging(&root2).await.unwrap();
	store::create_private(&stage.join("snapshot.bin"))
		.await
		.unwrap()
		.set_len(MAX_STORE_BYTES + 1)
		.await
		.unwrap();
	assert!(store::admit_quota(&root2, 1)
		.await
		.unwrap_err()
		.to_string()
		.contains("byte"));
	assert!(load(&scope2, ".stage").await.is_err());
}

#[tokio::test]
async fn query_summary_exposes_recovery_scope_without_loading_payload_or_index_pages() {
	let (_temp, scope) = environment();
	let params = source(&scope, &fixture(1, 4));
	let receipt = open_at(&scope, &params).await.unwrap();
	let mut params = query_params(id(&receipt), 0, 1);
	params.collection = Collection::Summary;
	let result = parse(query_at(&scope, params).await.unwrap());
	assert_eq!(result["index_pages_read"], 0);
	assert_eq!(result["snapshot_payload_bytes_read"], 0);
	assert_eq!(result["capabilities"]["snapshot_source_is_live"], false);
	assert_eq!(result["capabilities"]["automatic_eviction"], false);
	let claimed = result["result_sha256"].as_str().unwrap().to_owned();
	let mut body = result;
	body.as_object_mut().unwrap().remove("result_sha256");
	assert_eq!(hash(&serde_json::to_vec(&body).unwrap()), claimed);
}

#[tokio::test]
async fn identical_open_recovers_at_capacity_without_another_directory_parse() {
	let (_temp, scope) = environment();
	let params = source(&scope, &fixture(1, 4));
	let initial = open_at(&scope, &params).await.unwrap();
	let root = store::root_path(&scope.state).unwrap();
	for _ in 1..MAX_SESSION_COUNT {
		store::staging(&root).await.unwrap();
	}
	let restored = open_at(&scope, &params).await.unwrap();
	assert_eq!(id(&initial), id(&restored));
	assert_eq!(restored["reused"], true);
	assert_eq!(restored["directory_parses_this_open"], 0);
	assert_eq!(restored["full_source_hash_passes_this_open"], 1);
}

struct TestOwnerGuard {
	lock: Option<std::fs::File>,
	released: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Drop for TestOwnerGuard {
	fn drop(&mut self) {
		drop(self.lock.take());
		if let Some(released) = self.released.take() {
			let _ = released.send(());
		}
	}
}

fn exclusive_lock_available(file: &std::fs::File) -> bool {
	use std::os::fd::AsRawFd;
	if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
		assert_eq!(unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) }, 0);
		true
	} else {
		assert_eq!(
			std::io::Error::last_os_error().kind(),
			std::io::ErrorKind::WouldBlock
		);
		false
	}
}

async fn cancelled_commit_keeps_both_guards_until_sync(phase: store::CommitPhase) {
	use std::os::fd::AsRawFd;
	use std::os::unix::fs::OpenOptionsExt;
	use std::sync::atomic::{AtomicBool, Ordering};
	use std::sync::Arc;
	let (_temp, scope) = environment();
	let root = store::root(&scope.state, true).await.unwrap();
	let stage = store::staging(&root).await.unwrap();
	store::write_private(&stage.join("ready"), b"complete staged bytes")
		.await
		.unwrap();
	let destination = root.join(format!("{ID_PREFIX}{}", "a".repeat(64)));
	let store_lock = store::lock(&root).await.unwrap();
	let store_probe = std::fs::File::open(&root).unwrap();
	let owner_path = scope.state.join("synthetic-owner.lock");
	let owner_lock = std::fs::OpenOptions::new()
		.read(true)
		.write(true)
		.create_new(true)
		.mode(0o600)
		.open(&owner_path)
		.unwrap();
	assert_eq!(
		unsafe { libc::flock(owner_lock.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) },
		0
	);
	let owner_probe = std::fs::File::open(&owner_path).unwrap();
	let (released_tx, released_rx) = tokio::sync::oneshot::channel();
	let guards = store::PublishGuards::new(
		store_lock,
		TestOwnerGuard {
			lock: Some(owner_lock),
			released: Some(released_tx),
		},
	);
	let reached = Arc::new(tokio::sync::Notify::new());
	let worker_reached = reached.clone();
	let synced = Arc::new(AtomicBool::new(false));
	let worker_synced = synced.clone();
	let (resume_tx, resume_rx) = std::sync::mpsc::channel();
	let task_stage = stage.clone();
	let task_destination = destination.clone();
	let task = tokio::spawn(async move {
		store::publish_with_checkpoint(&task_stage, &task_destination, guards, move |current| {
			if current == store::CommitPhase::AfterParentSync {
				worker_synced.store(true, Ordering::SeqCst);
			}
			if current == phase {
				worker_reached.notify_one();
				resume_rx
					.recv_timeout(Duration::from_secs(10))
					.context("test did not release final commit")?;
			}
			Ok(())
		})
		.await
	});
	tokio::time::timeout(Duration::from_secs(10), reached.notified())
		.await
		.unwrap();
	assert_eq!(
		destination.exists(),
		phase == store::CommitPhase::BeforeParentSync
	);
	assert!(!synced.load(Ordering::SeqCst));
	task.abort();
	assert!(task.await.unwrap_err().is_cancelled());
	assert!(!exclusive_lock_available(&store_probe));
	assert!(!exclusive_lock_available(&owner_probe));
	assert!(
		!synced.load(Ordering::SeqCst),
		"cancellation cannot manufacture a confirmed durable receipt"
	);
	resume_tx.send(()).unwrap();
	tokio::time::timeout(Duration::from_secs(10), released_rx)
		.await
		.unwrap()
		.unwrap();
	assert!(synced.load(Ordering::SeqCst));
	assert!(exclusive_lock_available(&store_probe));
	assert!(exclusive_lock_available(&owner_probe));
	assert!(!stage.exists());
	assert_eq!(
		std::fs::read(destination.join("ready")).unwrap(),
		b"complete staged bytes"
	);
}

#[tokio::test]
async fn cancelling_before_rename_keeps_owner_and_store_guards_through_actual_commit() {
	cancelled_commit_keeps_both_guards_until_sync(store::CommitPhase::BeforeRename).await;
}

#[tokio::test]
async fn cancelling_after_rename_keeps_owner_and_store_guards_until_parent_fsync() {
	cancelled_commit_keeps_both_guards_until_sync(store::CommitPhase::BeforeParentSync).await;
}

#[tokio::test]
async fn unconfirmed_post_rename_commit_never_returns_a_success_receipt() {
	let (_temp, scope) = environment();
	let root = store::root(&scope.state, true).await.unwrap();
	let stage = store::staging(&root).await.unwrap();
	store::write_private(&stage.join("ready"), b"complete")
		.await
		.unwrap();
	let destination = root.join(format!("{ID_PREFIX}{}", "b".repeat(64)));
	let guards = store::PublishGuards::new(store::lock(&root).await.unwrap(), ());
	let result = store::publish_with_checkpoint(&stage, &destination, guards, |phase| {
		if phase == store::CommitPhase::BeforeParentSync {
			bail!("injected failure before directory fsync")
		}
		Ok(())
	})
	.await;
	assert!(result
		.unwrap_err()
		.to_string()
		.contains("did not confirm durability"));
	assert!(
		destination.exists(),
		"visible does not imply confirmed durable"
	);
	let guards = store::PublishGuards::new(store::lock(&root).await.unwrap(), ());
	store::confirm_existing(guards).await.unwrap();
}

#[tokio::test]
async fn discovery_filters_other_owners_and_old_policies_without_reading_original_sources() {
	let (_temp, scope) = environment();
	assert_eq!(parse(list_at(&scope).await.unwrap())["sessions"], json!([]));
	let params = source(&scope, &fixture(1, 4));
	let own = open_at(&scope, &params).await.unwrap();
	let mut other = Scope {
		state: scope.state.clone(),
		roots: scope.roots.clone(),
		owner_sha256: hash(b"another-authenticated-owner"),
		policy_sha256: scope.policy_sha256.clone(),
	};
	let other_owner = open_at(&other, &params).await.unwrap();
	other.owner_sha256 = scope.owner_sha256.clone();
	other.policy_sha256 = hash(b"another-administrator-policy");
	let other_policy = open_at(&other, &params).await.unwrap();
	std::fs::remove_file(&params.path).unwrap();
	let recovered = Scope {
		state: scope.state.clone(),
		roots: scope.roots.clone(),
		owner_sha256: scope.owner_sha256.clone(),
		policy_sha256: scope.policy_sha256.clone(),
	};
	let listing = parse(list_at(&recovered).await.unwrap());
	let rows = listing["sessions"].as_array().unwrap();
	assert_eq!(rows.len(), 1);
	assert_eq!(rows[0]["session_id"], id(&own));
	assert_eq!(rows[0]["snapshot_sha256"], params.expected_sha256);
	assert_eq!(rows[0]["format"], "safetensors");
	assert_eq!(rows[0]["source_required"], false);
	assert_eq!(listing["source_bytes_read"], 0);
	assert_eq!(listing["snapshot_payload_bytes_read"], 0);
	let serialized = serde_json::to_string(&listing).unwrap();
	assert!(!serialized.contains(id(&other_owner)));
	assert!(!serialized.contains(id(&other_policy)));
	let changed_policy_listing = parse(list_at(&other).await.unwrap());
	assert_eq!(
		changed_policy_listing["sessions"].as_array().unwrap().len(),
		1
	);
	assert_eq!(
		changed_policy_listing["sessions"][0]["session_id"],
		id(&other_policy)
	);
}

#[tokio::test]
async fn discovery_reports_damaged_missing_and_unsupported_manifests_as_unknown_store_state() {
	let (_temp, scope) = environment();
	let params = source(&scope, &fixture(1, 4));
	let receipt = open_at(&scope, &params).await.unwrap();
	let directory = store::root_path(&scope.state).unwrap().join(id(&receipt));
	let manifest_path = directory.join("manifest.json");
	let original = std::fs::read(&manifest_path).unwrap();
	std::fs::write(&manifest_path, b"{").unwrap();
	assert!(list_at(&scope)
		.await
		.unwrap_err()
		.to_string()
		.contains("damaged manifest"));
	std::fs::remove_file(&manifest_path).unwrap();
	assert!(list_at(&scope)
		.await
		.unwrap_err()
		.to_string()
		.contains("unavailable"));
	store::write_private(&manifest_path, &original)
		.await
		.unwrap();
	assert_eq!(
		parse(list_at(&scope).await.unwrap())["sessions"]
			.as_array()
			.unwrap()
			.len(),
		1
	);
	let mut future_manifest: Manifest = serde_json::from_slice(&original).unwrap();
	future_manifest.schema.push_str("-future");
	let future_directory = directory.with_file_name(identity(&future_manifest).unwrap());
	std::fs::write(
		&manifest_path,
		serde_json::to_vec(&future_manifest).unwrap(),
	)
	.unwrap();
	std::fs::rename(&directory, &future_directory).unwrap();
	assert!(list_at(&scope)
		.await
		.unwrap_err()
		.to_string()
		.contains("unsupported schema"));
	std::fs::rename(&future_directory, &directory).unwrap();
	std::fs::write(&manifest_path, &original).unwrap();
	std::fs::remove_file(directory.join("snapshot.bin")).unwrap();
	assert!(list_at(&scope)
		.await
		.unwrap_err()
		.to_string()
		.contains("snapshot is unavailable"));
}

#[tokio::test]
async fn gguf_quantized_snapshot_restores_verified_ranges_and_keeps_historical_ranges_unknown() {
	let mut bytes = b"GGUF".to_vec();
	bytes.extend_from_slice(&3_u32.to_le_bytes());
	bytes.extend_from_slice(&2_u64.to_le_bytes());
	bytes.extend_from_slice(&0_u64.to_le_bytes());
	for (name, dtype, elements, offset) in
		[("weights", 2_u32, 64_u64, 0_u64), ("historical", 9, 32, 64)]
	{
		bytes.extend_from_slice(&(name.len() as u64).to_le_bytes());
		bytes.extend_from_slice(name.as_bytes());
		bytes.extend_from_slice(&1_u32.to_le_bytes());
		bytes.extend_from_slice(&elements.to_le_bytes());
		bytes.extend_from_slice(&dtype.to_le_bytes());
		bytes.extend_from_slice(&offset.to_le_bytes());
	}
	bytes.resize(bytes.len().div_ceil(32) * 32, 0);
	let data_offset = bytes.len() as u64;
	bytes.extend(0_u8..104);
	let (_temp, scope) = environment();
	let params = source(&scope, &bytes);
	let receipt = open_at(&scope, &params).await.unwrap();
	let restored_scope = Scope {
		state: scope.state.clone(),
		roots: scope.roots.clone(),
		owner_sha256: scope.owner_sha256.clone(),
		policy_sha256: scope.policy_sha256.clone(),
	};
	std::fs::remove_file(&params.path).unwrap();
	let restored = parse(
		query_at(&restored_scope, query_params(id(&receipt), 0, 2))
			.await
			.unwrap(),
	);
	assert_eq!(restored["directory_parse_count"], 0);
	assert_eq!(restored["result"]["rows"][0]["dtype"], "Q4_0");
	assert_eq!(restored["result"]["rows"][0]["byte_length"], 36);
	assert_eq!(
		restored["result"]["rows"][0]["storage_length_verified"],
		true
	);
	assert_eq!(restored["result"]["rows"][1]["dtype"], "Q8_1");
	assert!(restored["result"]["rows"][1]["byte_length"].is_null());
	assert_eq!(
		restored["result"]["rows"][1]["storage_length_verified"],
		false
	);
	let read = ReadModelSessionParams {
		session_id: id(&receipt).into(),
		tensor_name: Some("weights".into()),
		offset: 34,
		length: 2,
	};
	let result = parse(read_at(&restored_scope, read.clone()).await.unwrap());
	assert_eq!(result["bytes_hex"], "2223");
	assert_eq!(result["directory_parse_count"], 0);
	assert!(read_at(
		&restored_scope,
		ReadModelSessionParams { offset: 35, ..read }
	)
	.await
	.is_err());
	assert!(read_at(
		&restored_scope,
		ReadModelSessionParams {
			session_id: id(&receipt).into(),
			tensor_name: Some("historical".into()),
			offset: 0,
			length: 1,
		}
	)
	.await
	.is_err());
	let raw = parse(
		read_at(
			&restored_scope,
			raw_read(id(&receipt), data_offset + 64, 40),
		)
		.await
		.unwrap(),
	);
	assert_eq!(
		raw["bytes_hex"],
		super::super::digest_hex(&(64_u8..104).collect::<Vec<_>>())
	);
}
