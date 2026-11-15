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

//! Archive-controller content commitments and descriptor continuation checks.

use super::*;
const SAMPLE: &[u8] = include_bytes!("../../tests/fixtures/rea_artifact_sample.apk");

fn params(path: &Path) -> InspectArchiveParams {
	InspectArchiveParams {
		path: path.to_string_lossy().into_owned(),
		filter: ArchiveFilter::All,
		offset: 0,
		limit: 1,
		hash: ArchiveHashMode::Index,
		expected_version: None,
		expected_directory_sha256: None,
	}
}

#[tokio::test]
#[cfg(unix)]
async fn archive_pages_bind_descriptor_and_directory_while_full_hash_binds_payload() {
	let root = tempfile::tempdir().expect("root");
	let path = root.path().join("sample.apk");
	tokio::fs::write(&path, SAMPLE).await.expect("fixture");
	let roots = [root.path().to_path_buf()];
	let first = inspect_with_roots(params(&path), &roots)
		.await
		.expect("first page");
	assert!(first["source"]["full_sha256"].is_null());
	let mut next = params(&path);
	next.offset = 1;
	next.expected_version = first["source"]["observed_version"]
		.as_str()
		.map(str::to_string);
	next.expected_directory_sha256 = first["source"]["central_directory_sha256"]
		.as_str()
		.map(str::to_string);
	next.hash = ArchiveHashMode::Full;
	let second = inspect_with_roots(next.clone(), &roots)
		.await
		.expect("bound next page");
	assert_eq!(second["result"]["rows"][0]["name"], "classes.dex");
	assert_eq!(
		second["source"]["full_sha256"],
		hex(&Sha256::digest(SAMPLE))
	);
	assert_eq!(first["coverage"], second["coverage"]);
	let replacement = root.path().join("replacement.apk");
	tokio::fs::write(&replacement, SAMPLE)
		.await
		.expect("same-content new inode");
	tokio::fs::rename(&replacement, &path)
		.await
		.expect("replace inode");
	assert!(inspect_with_roots(next, &roots).await.is_err());
}

#[tokio::test]
#[cfg(unix)]
async fn archive_root_and_symlink_policy_is_reused() {
	let root = tempfile::tempdir().expect("root");
	let outside = tempfile::tempdir().expect("outside");
	let path = outside.path().join("sample.apk");
	tokio::fs::write(&path, SAMPLE).await.expect("fixture");
	let link = root.path().join("link.apk");
	tokio::fs::symlink(&path, &link).await.expect("symlink");
	let roots = [root.path().to_path_buf()];
	assert!(inspect_with_roots(params(&path), &roots).await.is_err());
	assert!(inspect_with_roots(params(&link), &roots).await.is_err());
}

#[test]
fn archive_continuations_require_valid_paired_identity() {
	let mut request = params(Path::new("/unused"));
	request.offset = 1;
	assert!(validate_params(&request).is_err());
	request.expected_version = Some(format!("afv1_{}", "a".repeat(64)));
	assert!(validate_params(&request).is_err());
	request.expected_directory_sha256 = Some("b".repeat(64));
	assert!(validate_params(&request).is_ok());
}
