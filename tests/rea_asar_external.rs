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

//! Shipped MCP/descriptor-worker ASAR reads and explicit-source AST integration.

#![cfg(all(feature = "remote-fs", unix))]

use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

fn runtime_binary() -> PathBuf {
	let path = std::env::var_os("HEPTA_ASAR_TEST_RUNTIME")
		.map(PathBuf::from)
		.unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_hepta-runtime")));
	assert!(path.is_absolute());
	path
}

fn fixture(header: &Value, data: &[u8]) -> Vec<u8> {
	let raw = serde_json::to_vec(header).expect("header");
	let aligned = raw.len().div_ceil(4) * 4;
	let mut bytes = Vec::new();
	for n in [4, 8 + aligned as u32, 4 + aligned as u32, raw.len() as u32] {
		bytes.extend_from_slice(&n.to_le_bytes());
	}
	bytes.extend_from_slice(&raw);
	bytes.resize(16 + aligned, 0);
	bytes.extend_from_slice(data);
	bytes
}

struct RunningMcp {
	child: Child,
	stdin: ChildStdin,
	replies: Receiver<String>,
}

impl RunningMcp {
	fn start(config: &Path) -> Self {
		let mut child = Command::new(runtime_binary())
			.args(["mcp", "--runtime-config"])
			.arg(config)
			.env_clear()
			.current_dir("/")
			.stdin(Stdio::piped())
			.stdout(Stdio::piped())
			.stderr(Stdio::null())
			.spawn()
			.expect("MCP");
		let stdin = child.stdin.take().expect("stdin");
		let stdout = child.stdout.take().expect("stdout");
		let (send, replies) = mpsc::channel();
		std::thread::spawn(move || {
			for line in BufReader::new(stdout).lines() {
				let Ok(line) = line else { break };
				if send.send(line).is_err() {
					break;
				}
			}
		});
		let mut mcp = Self {
			child,
			stdin,
			replies,
		};
		mcp.request(
			1,
			"initialize",
			json!({"protocolVersion":"2026-07-28","capabilities":{},
			"clientInfo":{"name":"hepta-asar-e2e","version":"1"}}),
		);
		writeln!(
			mcp.stdin,
			"{}",
			json!({"jsonrpc":"2.0","method":"notifications/initialized","params":{}})
		)
		.expect("initialized");
		mcp.stdin.flush().expect("flush");
		mcp
	}
	fn request(&mut self, id: u64, method: &str, params: Value) -> Value {
		writeln!(
			self.stdin,
			"{}",
			json!({"jsonrpc":"2.0","id":id,"method":method,"params":params})
		)
		.expect("request");
		self.stdin.flush().expect("flush");
		for _ in 0..64 {
			let line = self
				.replies
				.recv_timeout(Duration::from_secs(30))
				.expect("bounded reply");
			let response: Value = serde_json::from_str(&line).expect("JSON");
			if response["id"] == id {
				assert!(response.get("error").is_none(), "{response}");
				return response["result"].clone();
			}
		}
		panic!("too many unrelated MCP replies");
	}
	fn call(&mut self, id: u64, name: &str, arguments: Value) -> Value {
		self.request(id, "tools/call", json!({"name":name,"arguments":arguments}))
	}
}

impl Drop for RunningMcp {
	fn drop(&mut self) {
		let _ = self.child.kill();
		let _ = self.child.wait();
	}
}
fn report(reply: Value) -> Value {
	assert_ne!(reply["isError"], true, "{reply}");
	serde_json::from_str(reply["content"][0]["text"].as_str().expect("text")).expect("report")
}

#[test]
fn real_asar_worker_requires_readonly_regular_fd_and_emits_no_partial_malformed_report() {
	let root = tempfile::tempdir().expect("root");
	let path = root.path().join("app.asar");
	let good = fixture(
		&json!({"files":{"main.js":{"size":3,"offset":"0"}}}),
		b"abc",
	);
	std::fs::write(&path, &good).expect("fixture");
	let invoke = |file: std::fs::File| {
		Command::new(runtime_binary())
			.args(["rea-asar-worker", "--request"])
			.arg(json!({"operation":"index","offset":0,"limit":1}).to_string())
			.env_clear()
			.current_dir("/")
			.stdin(Stdio::from(file))
			.output()
			.expect("worker")
	};
	let success = invoke(std::fs::File::open(&path).expect("readonly"));
	assert!(
		success.status.success(),
		"{}",
		String::from_utf8_lossy(&success.stderr)
	);
	let result: Value = serde_json::from_slice(&success.stdout).expect("worker output");
	assert_eq!(result["result"]["rows"][0]["path"], "main.js");
	let denied = invoke(
		std::fs::OpenOptions::new()
			.read(true)
			.write(true)
			.open(&path)
			.expect("writable"),
	);
	assert!(!denied.status.success());
	assert!(denied.stdout.is_empty());
	std::fs::write(&path, &good[..12]).expect("truncate");
	let denied = invoke(std::fs::File::open(&path).expect("readonly"));
	assert!(!denied.status.success());
	assert!(denied.stdout.is_empty());
}

#[test]
fn actual_asar_mcp_and_graph_bind_explicit_members_preserve_plain_graph_identity_and_recover() {
	let root = tempfile::tempdir().expect("root");
	let workspace = root.path().join("workspace");
	std::fs::create_dir(&workspace).expect("workspace");
	let marker = workspace.join("must-not-run");
	let main=format!("import {{answer}} from './util.js'; export const main=answer; require('node:fs').writeFileSync({},'bad');",json!(marker));
	let util = "export const answer=7;";
	std::fs::write(workspace.join("main.js"), &main).expect("main source");
	std::fs::write(workspace.join("util.js"), util).expect("util source");
	let mut data = main.as_bytes().to_vec();
	data.extend_from_slice(util.as_bytes());
	let bytes = fixture(
		&json!({"files":{
			"main.js":{"offset":"0","size":main.len()},"util.js":{"offset":main.len().to_string(),"size":util.len()},
			"alias.js":{"link":"main.js"},"external.js":{"unpacked":true,"size":1}
		}}),
		&data,
	);
	let archive = workspace.join("app.asar");
	std::fs::write(&archive, &bytes).expect("archive");
	let config = root.path().join("policy.json");
	std::fs::write(&config,serde_json::to_vec(&json!({"state_dir":root.path().join("state"),
		"controller_workspace_roots":[workspace],"hosts":{"never-connect":{"ssh_target":"never-connect-invalid",
		"remote_state_dir":root.path().join("remote-state"),"allow_execute":false,"allow_pty":false,"allow_write":false,"allow_job_network":false}}})).expect("config JSON")).expect("config");
	let mut prior_graph = None;
	for iteration in 0..2 {
		let mut mcp = RunningMcp::start(&config);
		let tools = mcp.request(2, "tools/list", json!({}));
		for name in ["rea_inspect_asar", "rea_read_asar_member"] {
			assert!(tools["tools"]
				.as_array()
				.expect("tools")
				.iter()
				.any(|t| t["name"] == name));
		}
		let first = report(mcp.call(3, "rea_inspect_asar", json!({"path":archive,"limit":1})));
		assert_eq!(first["entry_count"], 4);
		assert_eq!(first["external_files_opened"], false);
		let version = &first["source"]["observed_version"];
		let header = &first["source"]["header_sha256"];
		let unbound = mcp.call(
			4,
			"rea_inspect_asar",
			json!({"path":archive,"offset":1,"limit":1}),
		);
		assert_eq!(unbound["isError"], true);
		let second = report(mcp.call(
			5,
			"rea_inspect_asar",
			json!({"path":archive,"offset":1,"limit":3,
			"expected_version":version,"expected_header_sha256":header}),
		));
		assert!(second["result"]["next_offset"].is_null());
		let selected = report(mcp.call(
			6,
			"rea_read_asar_member",
			json!({"path":archive,"member":"main.js","length":6,
			"expected_version":version,"expected_header_sha256":header}),
		));
		assert_eq!(selected["result"]["bytes_hex"], "696d706f7274");
		assert_eq!(selected["result"]["declared_integrity_verified"], false);
		let plain=report(mcp.call(7,"rea_inspect_javascript_graph",json!({"sources":[
			{"id":"main.js","path":workspace.join("main.js")},{"id":"util.js","path":workspace.join("util.js")}],"collection":"imports"})));
		let sources: Vec<_> = ["main.js", "util.js"]
			.into_iter()
			.map(|member| {
				json!({"id":member,"path":archive,
			"asar":{"member":member,"expected_version":version,"expected_header_sha256":header}})
			})
			.collect();
		let packed = report(mcp.call(
			8,
			"rea_inspect_javascript_graph",
			json!({"sources":sources,"collection":"imports"}),
		));
		assert_eq!(packed["graph_sha256"], plain["graph_sha256"]);
		assert_eq!(packed["sources"], plain["sources"]);
		assert_eq!(packed["rows"], plain["rows"]);
		assert!(plain.get("archive_sources").is_none());
		assert_eq!(
			packed["archive_sources"]
				.as_array()
				.expect("provenance")
				.len(),
			2
		);
		assert_eq!(packed["javascript_executed"], false);
		assert!(!marker.exists());
		if let Some(previous) = &prior_graph {
			assert_eq!(previous, &packed["graph_sha256"]);
		} else {
			prior_graph = Some(packed["graph_sha256"].clone());
		}
		for (i, name) in ["alias.js", "external.js"].iter().enumerate() {
			let denied = mcp.call(
				9 + i as u64,
				"rea_read_asar_member",
				json!({"path":archive,"member":name,
				"expected_version":version,"expected_header_sha256":header}),
			);
			assert_eq!(denied["isError"], true);
		}
		let mut stale = sources.clone();
		stale[0]["asar"]["expected_header_sha256"] = json!("0".repeat(64));
		assert_eq!(
			mcp.call(11, "rea_inspect_javascript_graph", json!({"sources":stale}))["isError"],
			true
		);
		let mut duplicate = sources.clone();
		duplicate[1]["asar"]["member"] = json!("main.js");
		assert_eq!(
			mcp.call(
				12,
				"rea_inspect_javascript_graph",
				json!({"sources":duplicate})
			)["isError"],
			true
		);
		let recovered = report(mcp.call(
			13,
			"rea_inspect_javascript_graph",
			json!({"sources":sources,"collection":"imports"}),
		));
		assert_eq!(recovered["graph_sha256"], packed["graph_sha256"]);
		if iteration == 1 {
			let replacement = workspace.join("replacement.asar");
			std::fs::write(&replacement, &bytes).expect("replacement");
			std::fs::rename(replacement, &archive).expect("replace inode");
			assert_eq!(
				mcp.call(
					14,
					"rea_read_asar_member",
					json!({"path":archive,"member":"main.js",
				"expected_version":version,"expected_header_sha256":header})
				)["isError"],
				true
			);
		}
	}
}
