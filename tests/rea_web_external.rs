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

//! Shipped stdio MCP coverage for saved HAR and literal package declarations.
//! Fixtures are authored offline and the configured remote host cannot execute.

#![cfg(all(feature = "remote-fs", unix))]

use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

struct RunningMcp {
	child: Child,
	stdin: ChildStdin,
	replies: Receiver<String>,
}

impl RunningMcp {
	fn start(path: &std::path::Path) -> Self {
		let mut child = Command::new(env!("CARGO_BIN_EXE_hepta-runtime"))
			.arg("mcp")
			.arg("--runtime-config")
			.arg(path)
			.env_clear()
			.current_dir("/")
			.stdin(Stdio::piped())
			.stdout(Stdio::piped())
			.stderr(Stdio::null())
			.spawn()
			.expect("start shipped MCP executable");
		let stdin = child.stdin.take().expect("stdin");
		let stdout = child.stdout.take().expect("stdout");
		let (sender, replies) = mpsc::channel();
		std::thread::spawn(move || {
			for line in BufReader::new(stdout).lines() {
				let Ok(line) = line else { break };
				if sender.send(line).is_err() {
					break;
				}
			}
		});
		Self {
			child,
			stdin,
			replies,
		}
	}

	fn send(&mut self, message: &Value) {
		writeln!(self.stdin, "{message}").expect("MCP write");
		self.stdin.flush().expect("MCP flush");
	}

	fn request(&mut self, id: i64, method: &str, params: Value) -> Value {
		self.send(&json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}));
		for _ in 0..64 {
			let line = self
				.replies
				.recv_timeout(Duration::from_secs(15))
				.expect("MCP reply");
			let message: Value = serde_json::from_str(&line).expect("MCP JSON");
			if message["id"] == id {
				assert!(message.get("error").is_none(), "protocol error: {message}");
				return message["result"].clone();
			}
		}
		panic!("too many unrelated MCP notifications");
	}

	fn initialize(&mut self) {
		self.request(
			1,
			"initialize",
			json!({
				"protocolVersion":"2026-07-28",
				"capabilities":{},
				"clientInfo":{"name":"hepta-saved-observation-e2e","version":"0.1.0"}
			}),
		);
		self.send(&json!({"jsonrpc":"2.0","method":"notifications/initialized","params":{}}));
	}

	fn call(&mut self, id: i64, name: &str, arguments: Value) -> Value {
		self.request(id, "tools/call", json!({"name":name,"arguments":arguments}))
	}
}

impl Drop for RunningMcp {
	fn drop(&mut self) {
		let _ = self.child.kill();
		let _ = self.child.wait();
	}
}

fn report(reply: &Value) -> Value {
	assert_ne!(reply["isError"], true, "tool failure: {reply}");
	let text = reply["content"][0]["text"].as_str().expect("text result");
	serde_json::from_str(text).expect("analysis report")
}

#[test]
fn offline_capture_package_and_restart_keep_original_sources_and_never_execute_targets() {
	let root = tempfile::tempdir().expect("root");
	let workspace = root.path().join("workspace");
	std::fs::create_dir(&workspace).expect("workspace");
	let capture_path = workspace.join("owned.har");
	let package_path = workspace.join("package.json");
	let outside_path = root.path().join("outside.har");
	let marker = workspace.join("must-not-run");
	let capture = json!({"log":{"version":"1.2","entries":[{
		"request":{
			"method":"GET",
			"url":"https://owned.invalid/recorded",
			"headers":[{"name":"Authorization","value":"fixture-private-header"}]
		},
		"response":{
			"status":200,
			"headers":[{"name":"Content-Type","value":"text/plain"}],
			"content":{"mimeType":"text/plain","size":3,"encoding":"base64","text":"YWJj"}
		}
	}]}});
	let bytes = serde_json::to_vec(&capture).expect("capture bytes");
	std::fs::write(&capture_path, &bytes).expect("capture");
	std::fs::write(&outside_path, &bytes).expect("outside");
	std::fs::write(
		&package_path,
		serde_json::to_vec(&json!({
			"name":"owned-offline-fixture",
			"main":"dist/main.js",
			"devDependencies":{"electron":"1.0.0"},
			"scripts":{"install":format!("touch {}",marker.display())}
		}))
		.expect("package bytes"),
	)
	.expect("package");
	let config_path = root.path().join("policy.json");
	std::fs::write(
		&config_path,
		serde_json::to_vec(&json!({
			"state_dir":root.path().join("state"),
			"controller_workspace_roots":[workspace],
			"hosts":{"never-connect":{
				"ssh_target":"never-connect-invalid",
				"remote_state_dir":root.path().join("remote-state"),
				"allow_execute":false,
				"allow_pty":false,
				"allow_write":false,
				"allow_job_network":false
			}}
		}))
		.expect("policy"),
	)
	.expect("policy write");

	let mut original_sha = None;
	for iteration in 0..2 {
		let mut mcp = RunningMcp::start(&config_path);
		mcp.initialize();
		let listing = mcp.request(2, "tools/list", json!({}));
		let names: Vec<_> = listing["tools"]
			.as_array()
			.expect("listing")
			.iter()
			.filter_map(|tool| tool["name"].as_str())
			.collect();
		for name in [
			"rea_inspect_web_capture",
			"rea_compare_web_captures",
			"rea_replay_web_entry",
			"rea_inspect_javascript_package",
		] {
			assert!(names.contains(&name), "missing tool {name}");
		}
		let inspected = report(&mcp.call(
			3,
			"rea_inspect_web_capture",
			json!({
				"path":capture_path, "limit":1
			}),
		));
		assert_eq!(inspected["entry_count"], 1);
		assert!(!inspected.to_string().contains("fixture-private-header"));
		let sha = inspected["source"]["sha256"]
			.as_str()
			.expect("source hash")
			.to_owned();
		if let Some(original) = &original_sha {
			assert_eq!(original, &sha, "restart must not change content identity");
		} else {
			original_sha = Some(sha.clone());
		}
		let replayed = report(&mcp.call(
			4,
			"rea_replay_web_entry",
			json!({
				"source":{"path":capture_path,"sha256":sha},
				"entry_index":0
			}),
		));
		assert_eq!(replayed["body"]["bytes_hex"], "59574a6a");
		assert_eq!(replayed["body"]["har_encoding"], "base64");
		assert_eq!(replayed["network_requests"], 0);
		assert_eq!(replayed["application_state_inferred"], false);
		let compared = report(&mcp.call(
			5,
			"rea_compare_web_captures",
			json!({
				"before":{"path":capture_path,"sha256":sha},
				"after":{"path":capture_path,"sha256":sha}
			}),
		));
		assert_eq!(compared["counts"]["unchanged"], 1);
		assert_eq!(compared["difference_count"], 0);
		let package = report(&mcp.call(
			6,
			"rea_inspect_javascript_package",
			json!({
				"path":package_path
			}),
		));
		assert_eq!(package["summary"]["main_declaration"], "dist/main.js");
		assert_eq!(
			package["summary"]["electron_dependency_declarations"][0]["name"],
			"electron"
		);
		assert_eq!(package["javascript_executed"], false);
		assert!(!marker.exists());
		let denied = mcp.call(7, "rea_inspect_web_capture", json!({"path":outside_path}));
		assert_eq!(denied["isError"], true);
		let stale = mcp.call(
			8,
			"rea_replay_web_entry",
			json!({
				"source":{"path":capture_path,"sha256":"0".repeat(64)},
				"entry_index":0
			}),
		);
		assert_eq!(stale["isError"], true);
		if iteration == 1 {
			std::fs::write(&capture_path, b"{}").expect("change source");
			let changed = mcp.call(
				9,
				"rea_replay_web_entry",
				json!({
					"source":{"path":capture_path,"sha256":sha},
					"entry_index":0
				}),
			);
			assert_eq!(changed["isError"], true);
		}
	}
}
