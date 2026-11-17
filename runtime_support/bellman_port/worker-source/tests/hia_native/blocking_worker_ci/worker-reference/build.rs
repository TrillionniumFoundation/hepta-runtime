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
//! Append an observer without editing the target module or its identity bytes.

use std::{env, fs, path::PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
	let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").ok_or("missing manifest root")?);
	let root = manifest.parent().and_then(|p| p.parent()).ok_or("missing hia_native root")?;
	let original = root.join("blocking_worker/reference/weight_bellman.rs");
	let observer = manifest.join("trace_access.rs");
	let output = PathBuf::from(env::var_os("OUT_DIR").ok_or("missing OUT_DIR")?);
	let raw = fs::read(&original)?;
	fs::write(output.join("weight_bellman.rs"), &raw)?;
	let mut combined = raw;
	combined.extend_from_slice(b"\n");
	combined.extend_from_slice(&fs::read(&observer)?);
	let path = output.join("original_bellman_with_observer.rs");
	fs::write(&path, combined)?;
	fs::write(output.join("module.rs"), format!("#[allow(dead_code)]\n#[path = {:?}]\nmod original;\n", path))?;
	println!("cargo:rerun-if-changed={}", original.display());
	println!("cargo:rerun-if-changed={}", observer.display());
	Ok(())
}
