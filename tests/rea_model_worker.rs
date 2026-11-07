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

//! Exercise the shipped inherited-fd worker on a model larger than its address
//! space limit. These generated model fixtures contain no executable code.

// macOS arm64 refuses this finite-address-space worker profile before parsing.
// The exact shipped-binary refusal is covered by rea_macos_resource_refusal.rs.
#![cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
#![cfg(unix)]
#![cfg(feature = "remote-fs")]
use serde_json::{json, Value};
use std::fs::File;
use std::io::{Seek, SeekFrom, Write};
use std::process::{Command, Output, Stdio};

fn invoke(file: File, request: Value) -> Output {
	Command::new(env!("CARGO_BIN_EXE_hepta-runtime"))
		.arg("rea-model-worker")
		.arg("--request")
		.arg(request.to_string())
		.env_clear()
		.current_dir("/")
		.stdin(Stdio::from(file))
		.stdout(Stdio::piped())
		.stderr(Stdio::piped())
		.output()
		.expect("worker completes")
}

#[test]
fn real_model_worker_handles_four_gib_without_loading_payload() {
	let mut file = tempfile::NamedTempFile::new().expect("fixture");
	let size = 4_u64 * 1024 * 1024 * 1024;
	let header =
		serde_json::to_vec(&json!({"w":{"dtype":"U8","shape":[size],"data_offsets":[0,size]}}))
			.expect("header");
	file.write_all(&(header.len() as u64).to_le_bytes())
		.expect("length");
	file.write_all(&header).expect("header bytes");
	file.as_file_mut()
		.set_len(8 + header.len() as u64 + size)
		.expect("sparse model");
	file.as_file_mut().seek(SeekFrom::End(-2)).expect("tail");
	file.write_all(&[0xab, 0xcd]).expect("tail bytes");
	file.flush().expect("flush");
	let output = invoke(
		File::open(file.path()).expect("readonly fd"),
		json!({"operation":"inspect","collection":"tensors","offset":0,"limit":1}),
	);
	assert!(
		output.status.success(),
		"{}",
		String::from_utf8_lossy(&output.stderr)
	);
	assert!(output.stdout.len() < 4096);
	let report: Value = serde_json::from_slice(&output.stdout).expect("JSON");
	assert_eq!(report["result"]["rows"][0]["byte_length"], size);
	let output = invoke(
		File::open(file.path()).expect("readonly fd"),
		json!({"operation":"read","tensor_name":"w","offset":size-2,"length":2}),
	);
	assert!(
		output.status.success(),
		"{}",
		String::from_utf8_lossy(&output.stderr)
	);
	let report: Value = serde_json::from_slice(&output.stdout).expect("JSON");
	assert_eq!(report["result"]["bytes_hex"], "abcd");
}

#[test]
fn real_model_worker_refuses_write_capable_descriptor() {
	let file = tempfile::NamedTempFile::new().expect("fixture");
	let output = invoke(
		file.as_file().try_clone().expect("read/write fd"),
		json!({"operation":"inspect","collection":"summary","offset":0,"limit":1}),
	);
	assert!(!output.status.success());
	assert!(output.stdout.is_empty());
	assert!(String::from_utf8_lossy(&output.stderr).contains("read-only regular-file"));
}

#[test]
fn real_model_worker_rejects_malformed_header_without_partial_stdout() {
	let mut file = tempfile::NamedTempFile::new().expect("fixture");
	file.write_all(&u64::MAX.to_le_bytes())
		.expect("oversized declaration");
	file.flush().expect("flush");
	let output = invoke(
		File::open(file.path()).expect("readonly fd"),
		json!({"operation":"inspect","collection":"summary","offset":0,"limit":1}),
	);
	assert!(!output.status.success());
	assert!(output.stdout.is_empty());
}

#[test]
fn real_worker_retains_a_complete_directory_larger_than_an_mcp_page() {
	let mut file = tempfile::NamedTempFile::new().expect("fixture");
	let mut tensors = serde_json::Map::new();
	for number in 0..9000usize {
		tensors.insert(
			format!("tensor_{number:05}"),
			json!({
				"dtype":"F32","shape":[1],"data_offsets":[number * 4, (number + 1) * 4]
			}),
		);
	}
	let header = serde_json::to_vec(&tensors).expect("header");
	file.write_all(&(header.len() as u64).to_le_bytes())
		.expect("header size");
	file.write_all(&header).expect("header");
	file.as_file_mut()
		.set_len(8 + header.len() as u64 + 9000 * 4)
		.expect("payload");
	file.flush().expect("flush");
	let output = invoke(
		File::open(file.path()).expect("readonly snapshot"),
		json!({"operation":"directory"}),
	);
	assert!(
		output.status.success(),
		"{}",
		String::from_utf8_lossy(&output.stderr)
	);
	assert!(
		output.stdout.len() > 1024 * 1024,
		"complete index must exceed the normal MCP response cap"
	);
	assert!(output.stdout.len() < 64 * 1024 * 1024);
	let report: Value = serde_json::from_slice(&output.stdout).expect("directory");
	assert_eq!(report["operation"], "index_model_artifact");
	assert_eq!(
		report["result"]["tensors"].as_array().expect("rows").len(),
		9000
	);
	assert_eq!(report["result"]["tensors"][8999]["name"], "tensor_08999");
}
