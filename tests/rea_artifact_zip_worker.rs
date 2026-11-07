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

//! Real inherited-fd worker qualification with independent zipfile fixtures.

// macOS arm64 refuses this finite-address-space worker profile before parsing.
// The exact shipped-binary refusal is covered by rea_macos_resource_refusal.rs.
#![cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
#![cfg(unix)]
#![cfg(feature = "remote-fs")]

use serde_json::{json, Value};
use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn real_archive_worker_indexes_inert_apk_roles_without_verification_claims() {
	let mut fixture = tempfile::NamedTempFile::new().expect("fixture");
	fixture
		.write_all(include_bytes!("fixtures/rea_artifact_sample.apk"))
		.expect("archive");
	fixture.flush().expect("flush");
	let file = std::fs::File::open(fixture.path()).expect("readonly descriptor");
	let result = Command::new(env!("CARGO_BIN_EXE_hepta-runtime"))
		.arg("rea-archive-worker")
		.arg("--request")
		.arg(json!({"filter":"native_library","offset":0,"limit":1}).to_string())
		.env_clear()
		.current_dir("/")
		.stdin(Stdio::from(file))
		.stdout(Stdio::piped())
		.stderr(Stdio::piped())
		.output()
		.expect("worker");
	assert!(
		result.status.success(),
		"{}",
		String::from_utf8_lossy(&result.stderr)
	);
	let report: Value = serde_json::from_slice(&result.stdout).expect("record");
	assert_eq!(
		report["result"]["rows"][0]["name"],
		"lib/arm64-v8a/libfixture.so"
	);
	assert_eq!(report["result"]["rows"][0]["content_verified"], false);
	assert_eq!(report["coverage"]["signatures"], "not_verified");
}

#[test]
fn real_archive_worker_rejects_truncation_without_partial_stdout() {
	let mut fixture = tempfile::NamedTempFile::new().expect("fixture");
	fixture.write_all(b"PK\x03\x04").expect("truncated header");
	fixture.flush().expect("flush");
	let result = Command::new(env!("CARGO_BIN_EXE_hepta-runtime"))
		.arg("rea-archive-worker")
		.arg("--request")
		.arg(json!({"filter":"all","offset":0,"limit":1}).to_string())
		.env_clear()
		.current_dir("/")
		.stdin(Stdio::from(
			std::fs::File::open(fixture.path()).expect("readonly descriptor"),
		))
		.stdout(Stdio::piped())
		.stderr(Stdio::piped())
		.output()
		.expect("worker");
	assert!(!result.status.success());
	assert!(result.stdout.is_empty());
}
