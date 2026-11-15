// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! macOS arm64 must refuse native parsers when their mandatory resource profile is unavailable.
//!
//! These are refusal tests. Successful parsing, resource bounds and syscall
//! isolation remain qualified by the existing Linux worker integration tests.

#![cfg(all(target_os = "macos", target_arch = "aarch64", feature = "remote-fs"))]

use std::fs::File;
use std::io::Write;
use std::process::{Command, Stdio};

fn assert_resource_refusal(arguments: &[&str], expected: &str) {
	let mut fixture = tempfile::NamedTempFile::new().expect("private inert fixture");
	let bytes = b"untrusted parser input must not bypass resource admission";
	fixture.write_all(bytes).expect("write fixture");
	fixture.flush().expect("flush fixture");
	let output = Command::new(env!("CARGO_BIN_EXE_hepta-runtime"))
		.args(arguments)
		.env_clear()
		.current_dir("/")
		.stdin(Stdio::from(
			File::open(fixture.path()).expect("read-only fixture descriptor"),
		))
		.stdout(Stdio::piped())
		.stderr(Stdio::piped())
		.output()
		.expect("run shipped worker");
	assert!(!output.status.success(), "resource refusal became success");
	assert!(
		output.stdout.is_empty(),
		"refusal published a partial report"
	);
	let diagnostic = String::from_utf8(output.stderr).expect("UTF-8 diagnostic");
	assert!(diagnostic.contains(expected), "{diagnostic}");
	assert!(
		diagnostic.contains("Invalid argument (os error 22)"),
		"{diagnostic}"
	);
	assert_eq!(std::fs::read(fixture.path()).unwrap(), bytes);
}

#[test]
fn binary_worker_preserves_mandatory_limits_on_macos_arm64() {
	assert_resource_refusal(
		&["rea-worker", "--selected-path", "/display-only/inert.bin"],
		"failed to establish Rust REA worker resource limits",
	);
}

#[test]
fn model_worker_preserves_mandatory_limits_on_macos_arm64() {
	assert_resource_refusal(
		&["rea-model-worker", "--request", "{}"],
		"cannot establish model parser resource limits",
	);
}

#[test]
fn archive_worker_preserves_mandatory_limits_on_macos_arm64() {
	assert_resource_refusal(
		&["rea-archive-worker", "--request", "{}"],
		"cannot establish archive parser resource limits",
	);
}

#[test]
fn asar_worker_preserves_mandatory_limits_on_macos_arm64() {
	assert_resource_refusal(
		&["rea-asar-worker", "--request", "{}"],
		"cannot establish ASAR worker resource limits",
	);
}

#[test]
fn javascript_worker_preserves_mandatory_limits_on_macos_arm64() {
	assert_resource_refusal(
		&["rea-javascript-worker"],
		"cannot establish AST worker resource limits",
	);
}
