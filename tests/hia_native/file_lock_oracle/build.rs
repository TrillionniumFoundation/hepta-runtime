// Copyright 2026 Muvon Un Limited
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

//! Copy complete unchanged original lock owner and PathSource key bodies.

fn main() {
	let root = std::path::PathBuf::from(std::env::var_os("HIA_REFERENCE_RUNTIME").unwrap());
	let destination = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
	let source = std::fs::read_to_string(root.join("src/mcp/fs/text_editing.rs")).unwrap();
	let begin = source
		.find("// Thread-safe file locking infrastructure")
		.unwrap();
	let end = source[begin..].find("/// Test-only visibility").unwrap() + begin;
	let owner = &source[begin..end];
	assert_eq!(
		owner
			.matches("pub(crate) async fn acquire_file_lock(")
			.count(),
		1
	);
	std::fs::write(destination.join("file_lock_original.rs"), owner).unwrap();
	let remote = std::fs::read_to_string(root.join("src/mcp/fs/remote.rs")).unwrap();
	let begin = remote
		.find("#[derive(Debug, Clone)]\npub enum PathSource {")
		.unwrap();
	let end = remote[begin..].find("\nimpl PathSource {").unwrap() + begin;
	std::fs::write(
		destination.join("path_source_original.rs"),
		&remote[begin..end],
	)
	.unwrap();
	let begin = remote.find("\tpub fn lock_key(&self) -> String {").unwrap();
	let end = remote[begin..].find("\n\t/// Human-readable path").unwrap() + begin;
	std::fs::write(
		destination.join("path_key_original.rs"),
		format!("impl PathSource {{\n{}\n}}\n", &remote[begin..end]),
	)
	.unwrap();
	println!(
		"cargo:rerun-if-changed={}",
		root.join("src/mcp/fs/text_editing.rs").display()
	);
	println!(
		"cargo:rerun-if-changed={}",
		root.join("src/mcp/fs/remote.rs").display()
	);
	println!("cargo:rerun-if-env-changed=HIA_REFERENCE_RUNTIME");
}
