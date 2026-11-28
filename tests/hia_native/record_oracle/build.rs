// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Retain the complete original crypto module verbatim inside a test-only module.
use std::{env, fs, path::PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
	let root =
		PathBuf::from(env::var_os("HIA_REFERENCE_RUNTIME").ok_or("reference root required")?);
	let original = root.join("src/mcp/runtime/operation_crypto.rs");
	let shim = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").ok_or("manifest root required")?)
		.join("original_access.rs");
	let output = PathBuf::from(env::var_os("OUT_DIR").ok_or("output root required")?)
		.join("original_operation_reference.rs");
	let source = fs::read_to_string(&original)?;
	let access = fs::read_to_string(&shim)?;
	fs::write(
		output,
		format!("#[allow(dead_code)]\nmod original {{\n{source}\n{access}\n}}\n"),
	)?;
	println!("cargo:rerun-if-env-changed=HIA_REFERENCE_RUNTIME");
	println!("cargo:rerun-if-changed={}", original.display());
	println!("cargo:rerun-if-changed={}", shim.display());
	Ok(())
}
