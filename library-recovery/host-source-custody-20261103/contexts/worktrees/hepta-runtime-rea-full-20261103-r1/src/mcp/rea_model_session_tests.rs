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
