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

//! Compile the complete unchanged atomic-write owner from its retained source.

fn main() {
	let root = std::path::PathBuf::from(std::env::var_os("HIA_REFERENCE_RUNTIME").unwrap());
	let path = root.join("src/mcp/fs/text_editing.rs");
	let source = std::fs::read_to_string(&path).unwrap();
	let start = source.find("pub async fn atomic_write(").unwrap();
	let end = start + source[start..].find("\nconst LF_ENDING:").unwrap();
	let original = &source[start..end];
	assert_eq!(original.matches("pub async fn atomic_write(").count(), 1);
	assert!(original.ends_with("}\n"));
	let target = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
	std::fs::write(target.join("atomic_write_original.rs"), original).unwrap();
	println!("cargo:rerun-if-changed={}", path.display());
	println!("cargo:rerun-if-env-changed=HIA_REFERENCE_RUNTIME");
}
