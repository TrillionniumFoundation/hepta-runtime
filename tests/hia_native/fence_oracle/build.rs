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
//! Compile the entire unchanged original owner, followed by access-only glue.
use std::{env, fs, path::PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
	let root =
		PathBuf::from(env::var_os("HIA_REFERENCE_RUNTIME").ok_or("reference root required")?);
	let here = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").ok_or("manifest root required")?);
	let out = PathBuf::from(env::var_os("OUT_DIR").ok_or("output root required")?);
	let original_path = root.join("src/mcp/runtime/effect_owner_fence.rs");
	let access_path = here.join("original_access.rs");
	let original = fs::read_to_string(&original_path)?;
	let access = fs::read_to_string(&access_path)?;
	fs::write(
		out.join("original_effect_fence_reference.rs"),
		format!("#[allow(dead_code)]\nmod original {{\n{original}\n{access}\n}}\n"),
	)?;
	fs::write(out.join("original_effect_fence.rs"), original)?;
	println!("cargo:rerun-if-env-changed=HIA_REFERENCE_RUNTIME");
	println!("cargo:rerun-if-changed={}", original_path.display());
	println!("cargo:rerun-if-changed={}", access_path.display());
	Ok(())
}
