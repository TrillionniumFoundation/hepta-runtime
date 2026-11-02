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

//! Exercised shipped Rust binary (not the test harness): real worker framing,
//! process isolation setup, limit rejection and error-only stderr.

use std::io::Write;
use std::process::{Command, Output, Stdio};

fn invoke_worker(bytes: &[u8]) -> Output {
	let exe = env!("CARGO_BIN_EXE_hepta-runtime");
	let mut process = Command::new(exe)
		.arg("rea-worker")
		.arg("--selected-path=/controlled/worker.wasm")
		.env_clear()
		.stdin(Stdio::piped())
		.stdout(Stdio::piped())
		.stderr(Stdio::piped())
		.spawn()
		.expect("start real REA worker binary");
	let mut stdin = process.stdin.take().expect("worker stdin");
	stdin.write_all(bytes).expect("supply raw bytes");
	drop(stdin);
	process.wait_with_output().expect("worker completes")
}

#[test]
fn real_worker_handles_wasm_and_reports_non_rea_evidence() {
	let outcome = invoke_worker(b"\0asm\x01\0\0\0");
	assert!(outcome.status.success(), "{:?}", outcome.stderr);
	assert!(outcome.stderr.is_empty(), "successful worker must not emit stderr");
	let report: serde_json::Value =
		serde_json::from_slice(&outcome.stdout).expect("worker response JSON");
	assert_eq!(report["normalized_result"]["format"], "wasm");
	assert_eq!(report["normalized_result"]["header_facts"]["binary_version"], 1);
	assert_eq!(report["rea_evidence_compatible"], false);
	assert_eq!(report["coverage"]["status"], "partial");
}

#[test]
fn real_worker_rejects_truncated_elf_without_partial_stdout() {
	let outcome = invoke_worker(b"\x7fELF\x02\x01\x01");
	assert!(!outcome.status.success(), "invalid artifact must fail closed");
	assert!(outcome.stdout.is_empty(), "no partial record on parse failure");
	assert!(!outcome.stderr.is_empty(), "failure should be diagnosable");
}

#[test]
fn real_worker_refuses_more_than_32_mib_without_allocating_unboundedly() {
	let input = vec![0; 32 * 1024 * 1024 + 1];
	let outcome = invoke_worker(&input);
	assert!(!outcome.status.success());
	assert!(outcome.stdout.is_empty());
}
