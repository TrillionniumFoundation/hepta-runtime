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
//! Build an oracle from unchanged original auth owners and access-only shims.
use std::{env, fs, path::PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
	let root =
		PathBuf::from(env::var_os("HIA_REFERENCE_RUNTIME").ok_or("reference root required")?);
	let here = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").ok_or("manifest root required")?);
	let output = PathBuf::from(env::var_os("OUT_DIR").ok_or("output root required")?);
	let caller_path = root.join("src/mcp/runtime/caller_scope.rs");
	let crypto_path = root.join("src/mcp/runtime/operation_crypto.rs");
	let search_path = root.join("src/mcp/runtime/search_jobs.rs");
	let main_path = root.join("src/main.rs");
	let caller = fs::read_to_string(&caller_path)?;
	let crypto = fs::read_to_string(&crypto_path)?;
	let search = fs::read_to_string(&search_path)?;
	let main = fs::read_to_string(&main_path)?;
	let auth_begin = main
		.find("#[derive(Clone)]\nstruct HttpAuth {")
		.ok_or("original HttpAuth start missing")?;
	let auth_end = main[auth_begin..]
		.find("/// Run the MCP server over HTTP")
		.ok_or("original auth end missing")?
		+ auth_begin;
	let auth = &main[auth_begin..auth_end];
	let owner_begin = search
		.find("pub fn new_owner_id() -> Result<String> {")
		.ok_or("original owner start missing")?;
	let owner_end = search[owner_begin..]
		.find("\nfn instance()")
		.ok_or("original owner end missing")?
		+ owner_begin;
	let owner = &search[owner_begin..owner_end];
	let access_path = here.join("original_access.rs");
	let crypto_access_path = here.join("crypto_access.rs");
	let access = fs::read_to_string(&access_path)?;
	let crypto_access = fs::read_to_string(&crypto_access_path)?;
	let generated = format!(
		"#[allow(dead_code)]\nmod mcp {{\npub mod runtime {{\npub mod operation_crypto {{\n{crypto}\n{crypto_access}\n}}\npub mod caller_scope {{\n{caller}\n{access}\n}}\npub mod owner_reference {{\nuse anyhow::{{Context, Result}};\nuse std::io::Read;\n{owner}\n}}\n}}\n}}\n{auth}"
	);
	fs::write(output.join("original_authority_reference.rs"), generated)?;
	fs::write(output.join("original_auth_segment.rs"), auth)?;
	fs::write(output.join("original_owner_segment.rs"), owner)?;
	println!("cargo:rerun-if-env-changed=HIA_REFERENCE_RUNTIME");
	for path in [
		caller_path,
		crypto_path,
		search_path,
		main_path,
		access_path,
		crypto_access_path,
	] {
		println!("cargo:rerun-if-changed={}", path.display());
	}
	Ok(())
}
