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

//! Controller admission, streaming content identity and stale-page/range tests.

use super::*;
use tokio::io::AsyncWriteExt;

fn request() -> parser::WorkerRequest {
	parser::WorkerRequest::Inspect {
		collection: Collection::Tensors,
		offset: 0,
		limit: 64,
	}
}

fn no_expected() -> ExpectedIdentity<'static> {
	ExpectedIdentity {
		version: None,
		header: None,
		full: None,
	}
}

async fn fixture(path: &Path, payload_size: u64) -> Vec<u8> {
	let header = serde_json::to_vec(&json!({
		"weights":{"dtype":"U8","shape":[payload_size],"data_offsets":[0,payload_size]}
	}))
	.expect("header");
	let mut prefix = (header.len() as u64).to_le_bytes().to_vec();
	prefix.extend_from_slice(&header);
	let mut file = tokio::fs::File::create(path).await.expect("fixture");
	file.write_all(&prefix).await.expect("write header");
	file.set_len(prefix.len() as u64 + payload_size)
		.await
		.expect("sparse payload");
	file.flush().await.expect("flush fixture");
	prefix
}

#[tokio::test]
#[cfg(unix)]
async fn header_only_and_streaming_full_hash_are_distinct_for_large_real_file() {
	let workspace = tempfile::tempdir().expect("workspace");
	let path = workspace.path().join("model.safetensors");
	let roots = [workspace.path().to_path_buf()];
	let payload_size = 40_u64 * 1024 * 1024;
	let prefix = fixture(&path, payload_size).await;
	let header = execute_with_roots(&path, &roots, request(), no_expected(), HashMode::Header)
		.await
		.expect("large model header");
	assert!(header["source"]["full_sha256"].is_null());
	assert_eq!(
		header["source"]["header_sha256"],
		digest_hex(&Sha256::digest(&prefix))
	);
	assert_eq!(
		header["source"]["identity_scope"],
		"header_and_descriptor_observation"
	);
	let version = header["source"]["observed_version"]
		.as_str()
		.expect("version");
	let header_digest = header["source"]["header_sha256"]
		.as_str()
		.expect("header digest");
	let full = execute_with_roots(
		&path,
		&roots,
		request(),
		ExpectedIdentity {
			version: Some(version),
			header: Some(header_digest),
			full: None,
		},
		HashMode::Full,
	)
	.await
	.expect("streamed full hash");
	let mut expected = Sha256::new();
	expected.update(&prefix);
	let zeros = [0_u8; 64 * 1024];
	for _ in 0..payload_size / zeros.len() as u64 {
		expected.update(zeros);
	}
	assert_eq!(
		full["source"]["full_sha256"],
		digest_hex(&expected.finalize())
	);
	assert_eq!(full["source"]["identity_scope"], "full_file");
	assert_eq!(
		full["source"]["header_sha256"],
		header["source"]["header_sha256"]
	);
	assert_ne!(
		full["source"]["full_sha256"],
		full["source"]["header_sha256"]
	);
	assert_eq!(full["coverage"], header["coverage"]);
}

#[tokio::test]
#[cfg(unix)]
async fn read_requires_fresh_descriptor_header_and_optional_full_content_identity() {
	let workspace = tempfile::tempdir().expect("workspace");
	let path = workspace.path().join("model.safetensors");
	let roots = [workspace.path().to_path_buf()];
	fixture(&path, 8).await;
	let first = execute_with_roots(&path, &roots, request(), no_expected(), HashMode::Full)
		.await
		.expect("initial identity");
	let version = first["source"]["observed_version"]
		.as_str()
		.expect("version");
	let header = first["source"]["header_sha256"].as_str().expect("header");
	let full = first["source"]["full_sha256"].as_str().expect("full");
	let read = || parser::WorkerRequest::Read {
		tensor_name: Some("weights".to_string()),
		offset: 0,
		length: 4,
	};
	let result = execute_with_roots(
		&path,
		&roots,
		read(),
		ExpectedIdentity {
			version: Some(version),
			header: Some(header),
			full: Some(full),
		},
		HashMode::Header,
	)
	.await
	.expect("bound read");
	assert_eq!(result["result"]["bytes_hex"], "00000000");
	let wrong = "0".repeat(64);
	assert!(execute_with_roots(
		&path,
		&roots,
		read(),
		ExpectedIdentity {
			version: Some(version),
			header: Some(&wrong),
			full: None,
		},
		HashMode::Header
	)
	.await
	.is_err());
	assert!(execute_with_roots(
		&path,
		&roots,
		read(),
		ExpectedIdentity {
			version: Some(version),
			header: Some(header),
			full: Some(&wrong),
		},
		HashMode::Header
	)
	.await
	.is_err());
	// A replacement with identical bytes must not reuse an earlier descriptor
	// observation token. Header equality alone cannot authorize continuation.
	let replacement = workspace.path().join("replacement");
	fixture(&replacement, 8).await;
	tokio::fs::rename(&replacement, &path)
		.await
		.expect("replace source inode");
	assert!(execute_with_roots(
		&path,
		&roots,
		read(),
		ExpectedIdentity {
			version: Some(version),
			header: Some(header),
			full: None,
		},
		HashMode::Header
	)
	.await
	.is_err());
}

#[tokio::test]
#[cfg(unix)]
async fn descriptor_policy_rejects_symlinks_and_outside_roots_for_model_reads() {
	let workspace = tempfile::tempdir().expect("workspace");
	let outside = tempfile::tempdir().expect("outside");
	let external = outside.path().join("model.safetensors");
	fixture(&external, 8).await;
	let link = workspace.path().join("model-link");
	tokio::fs::symlink(&external, &link)
		.await
		.expect("symlink fixture");
	let roots = [workspace.path().to_path_buf()];
	for path in [&link, &external] {
		assert!(
			execute_with_roots(path, &roots, request(), no_expected(), HashMode::Header)
				.await
				.is_err()
		);
	}
}

#[tokio::test]
async fn public_continuation_contract_rejects_unbound_pages_before_runtime_access() {
	let params = InspectModelArtifactParams {
		path: "/unused".to_string(),
		collection: Collection::Tensors,
		offset: 1,
		limit: 1,
		hash: HashMode::Header,
		expected_version: None,
		expected_header_sha256: None,
	};
	let error = inspect_model_artifact(params)
		.await
		.expect_err("unbound page");
	assert!(error.to_string().contains("continuation pages require"));
}

#[test]
fn response_limit_refuses_oversized_metadata_without_transport_truncation() {
	let report = json!({"payload":"x".repeat(MAX_RESPONSE_BYTES)});
	assert!(encode_report(&report).is_err());
	assert!(validate_digest(&"0".repeat(63), "digest").is_err());
	assert!(validate_digest(&"G".repeat(64), "digest").is_err());
	assert!(validate_version(&format!("mfv1_{}", "a".repeat(64))).is_ok());
}
