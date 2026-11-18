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
//! Preserve the owner and five acquisition test bodies; strip only test attributes.
use std::{env, fs, path::PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
	let root =
		PathBuf::from(env::var_os("HIA_REFERENCE_RUNTIME").ok_or("reference root required")?);
	let here = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").ok_or("manifest root required")?);
	let out = PathBuf::from(env::var_os("OUT_DIR").ok_or("output root required")?);
	let original_path = root.join("src/mcp/runtime/effect_owner_fence.rs");
	let cases_path = root.join("src/mcp/runtime/effect_owner_fence_acquisition_tests.rs");
	let original = fs::read_to_string(&original_path)?;
	let cases = fs::read_to_string(&cases_path)?;
	if cases.matches("#[test]\n").count() != 2
		|| cases
			.matches("#[tokio::test(flavor = \"current_thread\")]\n")
			.count() != 3
	{
		return Err("original test registration shape changed".into());
	}
	let bodies = cases
		.replace("#[test]\n", "")
		.replace("#[tokio::test(flavor = \"current_thread\")]\n", "");
	let access = fs::read_to_string(here.join("original_async_access.rs"))?;
	let runner = fs::read_to_string(here.join("original_async_runner.rs"))?;
	// Inner docs on access snippets are comments when appended after the owner.
	let access = access.replacen("//!", "//", 1);
	let runner = runner.replacen("//!", "//", 1);
	fs::write(out.join("original_effect_fence_async_reference.rs"), format!(
        "#[allow(dead_code)]\nmod original {{\n{original}\n{access}\nmod acquisition_cases {{\n{bodies}\n{runner}\n}}\n}}\n"))?;
	fs::write(out.join("original_effect_fence.rs"), original)?;
	fs::write(
		out.join("original_effect_fence_acquisition_tests.rs"),
		cases,
	)?;
	fs::write(out.join("original_acquisition_bodies.rs"), bodies)?;
	println!("cargo:rerun-if-env-changed=HIA_REFERENCE_RUNTIME");
	for path in [
		&original_path,
		&cases_path,
		&here.join("original_async_access.rs"),
		&here.join("original_async_runner.rs"),
	] {
		println!("cargo:rerun-if-changed={}", path.display());
	}
	Ok(())
}
