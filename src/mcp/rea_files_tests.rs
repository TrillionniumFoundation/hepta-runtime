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

//! File-descriptor admission and traversal regression tests.

use super::*;

#[tokio::test]
#[cfg(unix)]
async fn reads_nested_regular_file_but_not_unsafe_paths() {
	let work = tempfile::tempdir().expect("workspace");
	let target = work.path().join("sub");
	tokio::fs::create_dir(&target).await.expect("subdirectory");
	let file = target.join("evidence.json");
	tokio::fs::write(&file, b"approved").await.expect("write");
	let roots = vec![work.path().to_path_buf()];
	assert_eq!(
		read_bounded(&file, &roots, 128).await.expect("read"),
		b"approved"
	);
	assert!(read_bounded(&file, &roots, 3).await.is_err());
	assert!(
		read_bounded(&work.path().join("sub/../sub/evidence.json"), &roots, 128)
			.await
			.is_err()
	);
	assert!(read_bounded(work.path(), &roots, 128).await.is_err());
	assert!(read_bounded(Path::new("sub/evidence.json"), &roots, 128)
		.await
		.is_err());
}

#[tokio::test]
#[cfg(unix)]
async fn disallows_symlink_to_inside_or_outside_even_if_contents_are_valid() {
	let work = tempfile::tempdir().expect("workspace");
	let outside = tempfile::tempdir().expect("outside");
	let inside = work.path().join("safe");
	let external = outside.path().join("secret");
	tokio::fs::write(&inside, b"inside").await.expect("inside");
	tokio::fs::write(&external, b"outside")
		.await
		.expect("outside");
	std::os::unix::fs::symlink(&inside, work.path().join("inside-link")).expect("inside symlink");
	std::os::unix::fs::symlink(&external, work.path().join("outside-link"))
		.expect("outside symlink");
	std::os::unix::fs::symlink(outside.path(), work.path().join("directory-link"))
		.expect("directory symlink");
	let roots = vec![work.path().to_path_buf()];
	for path in [
		work.path().join("inside-link"),
		work.path().join("outside-link"),
		work.path().join("directory-link/secret"),
		external,
	] {
		assert!(
			read_bounded(&path, &roots, 128).await.is_err(),
			"{}",
			path.display()
		);
	}
}
