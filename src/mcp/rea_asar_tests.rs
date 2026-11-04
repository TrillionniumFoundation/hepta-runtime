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

//! ASAR descriptor/header commitments, workspace admission and cancellation.

use super::*;

fn fixture() -> Vec<u8> {
	let header =
		br#"{"files":{"main.js":{"size":17,"offset":"0"},"empty":{"size":0,"offset":"17"}}}"#;
	let aligned = header.len().div_ceil(4) * 4;
	let mut bytes = Vec::new();
	for n in [
		4,
		8 + aligned as u32,
		4 + aligned as u32,
		header.len() as u32,
	] {
		bytes.extend_from_slice(&n.to_le_bytes());
	}
	bytes.extend_from_slice(header);
	bytes.resize(16 + aligned, 0);
	bytes.extend_from_slice(b"export const a=1;");
	bytes
}

#[tokio::test]
#[cfg(unix)]
async fn asar_pagination_and_reads_require_the_same_descriptor_and_header() {
	let root = tempfile::tempdir().expect("root");
	let path = root.path().join("app.asar");
	tokio::fs::write(&path, fixture()).await.expect("fixture");
	let path_str = path.to_str().expect("path");
	let roots = [root.path().to_path_buf()];
	let ct = CancellationToken::new();
	let first = inspect_with_roots(
		path_str,
		parser::Request::Index {
			offset: 0,
			limit: 1,
		},
		None,
		None,
		&roots,
		&ct,
	)
	.await
	.expect("index");
	let version = first["source"]["observed_version"]
		.as_str()
		.expect("version");
	let header = first["source"]["header_sha256"].as_str().expect("digest");
	assert!(inspect_with_roots(
		path_str,
		parser::Request::Index {
			offset: 1,
			limit: 1
		},
		None,
		None,
		&roots,
		&ct
	)
	.await
	.is_err());
	let second = inspect_with_roots(
		path_str,
		parser::Request::Index {
			offset: 1,
			limit: 1,
		},
		Some(version),
		Some(header),
		&roots,
		&ct,
	)
	.await
	.expect("pinned page");
	assert_eq!(second["result"]["rows"][0]["path"], "main.js");
	let selected = AsarSource {
		member: "main.js".into(),
		expected_version: version.into(),
		expected_header_sha256: header.into(),
	};
	let (bytes, provenance) = read_javascript_source(path_str, &selected, &roots, &ct)
		.await
		.expect("source");
	assert_eq!(bytes, b"export const a=1;");
	assert_eq!(provenance["member_sha256"], hex(&Sha256::digest(&bytes)));
	assert_eq!(
		provenance["graph_identity_includes_archive_metadata"],
		false
	);
	let mut stale = selected.clone();
	stale.expected_header_sha256 = "0".repeat(64);
	assert!(read_javascript_source(path_str, &stale, &roots, &ct)
		.await
		.is_err());
	let replacement = root.path().join("replacement.asar");
	tokio::fs::write(&replacement, fixture())
		.await
		.expect("replacement");
	tokio::fs::rename(&replacement, &path)
		.await
		.expect("replace identical bytes");
	assert!(read_javascript_source(path_str, &selected, &roots, &ct)
		.await
		.is_err());
}

#[tokio::test]
#[cfg(unix)]
async fn asar_admission_rejects_outside_paths_and_symlinks_and_observes_payload_changes() {
	let root = tempfile::tempdir().expect("root");
	let outside = tempfile::tempdir().expect("outside");
	let path = outside.path().join("app.asar");
	tokio::fs::write(&path, fixture()).await.expect("fixture");
	let link = root.path().join("link.asar");
	tokio::fs::symlink(&path, &link).await.expect("symlink");
	let roots = [root.path().to_path_buf()];
	let ct = CancellationToken::new();
	for path in [&path, &link] {
		assert!(inspect_with_roots(
			path.to_str().expect("path"),
			parser::Request::Index {
				offset: 0,
				limit: 1
			},
			None,
			None,
			&roots,
			&ct
		)
		.await
		.is_err());
	}
	let local = root.path().join("app.asar");
	tokio::fs::write(&local, fixture()).await.expect("local");
	let text = local.to_str().expect("path");
	let first = inspect_with_roots(
		text,
		parser::Request::Index {
			offset: 0,
			limit: 1,
		},
		None,
		None,
		&roots,
		&ct,
	)
	.await
	.expect("index");
	let mut changed = fixture();
	*changed.last_mut().expect("payload") = b'2';
	tokio::fs::write(&local, changed)
		.await
		.expect("payload replacement");
	assert!(inspect_with_roots(
		text,
		parser::Request::Read {
			member: "main.js".into(),
			offset: 0,
			length: 17,
			require_complete: true
		},
		first["source"]["observed_version"].as_str(),
		first["source"]["header_sha256"].as_str(),
		&roots,
		&ct
	)
	.await
	.is_err());
}

#[tokio::test]
async fn asar_cancelled_request_fails_before_runtime_or_file_admission() {
	let ct = CancellationToken::new();
	ct.cancel();
	let request = InspectAsarParams {
		path: "/must-not-open".into(),
		offset: 0,
		limit: 1,
		expected_version: None,
		expected_header_sha256: None,
	};
	let error = inspect_asar(request, ct.clone())
		.await
		.expect_err("cancelled");
	assert_eq!(error.to_string(), "ASAR inspection cancelled");
	let result = inspect_with_roots(
		"/must-not-open",
		parser::Request::Index {
			offset: 0,
			limit: 1,
		},
		None,
		None,
		&[],
		&ct,
	)
	.await;
	assert_eq!(
		result.expect_err("cancel before policy").to_string(),
		"ASAR inspection cancelled"
	);
}

#[test]
fn asar_identity_and_output_bounds_are_explicit() {
	for pair in [
		(None, None),
		(Some("asv1_x"), Some("a")),
		(Some("asv1_x"), None),
	] {
		assert!(validate_identity(pair.0, pair.1, true).is_err());
	}
	assert!(validate_identity(
		Some(&format!("asv1_{}", "a".repeat(64))),
		Some(&"b".repeat(64)),
		true
	)
	.is_ok());
	assert!(render(&json!({"too_large":"x".repeat(MAX_RESPONSE_BYTES)})).is_err());
	assert!(unhex("0").is_err());
	assert!(unhex("G0").is_err());
	assert_eq!(unhex("00ff").expect("bytes"), [0, 255]);
}
