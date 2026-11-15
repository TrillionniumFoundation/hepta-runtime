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

//! Shipped stdio MCP coverage for fixed APK/JAR manifest inspection.
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
				"clientInfo":{"name":"hepta-application-manifest-e2e","version":"0.1.0"}
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
fn real_owned_packages_are_read_only_discoverable_and_hash_bound_across_restart() {
	let root = tempfile::tempdir().expect("root");
	let workspace = root.path().join("workspace");
	std::fs::create_dir(&workspace).expect("workspace");
	let apk = workspace.join("owned.apk");
	let jar = workspace.join("owned.jar");
	let outside = root.path().join("outside.jar");
	let apk_bytes = include_bytes!("fixtures/rea_application/owned-aapt.apk");
	let jar_bytes = include_bytes!("fixtures/rea_application/owned.jar");
	std::fs::write(&apk, apk_bytes).expect("APK");
	std::fs::write(&jar, jar_bytes).expect("JAR");
	std::fs::write(&outside, jar_bytes).expect("outside");
	let config_path = root.path().join("policy.json");
	std::fs::write(
		&config_path,
		serde_json::to_vec(&json!({
			"state_dir":root.path().join("state"),
			"controller_workspace_roots":[workspace],
			"hosts":{"never-connect":{
				"ssh_target":"never-connect-invalid",
				"remote_state_dir":root.path().join("remote-state"),
				"allow_execute":false,"allow_pty":false,"allow_write":false,"allow_job_network":false
			}}
		}))
		.expect("config"),
	)
	.expect("policy");
	let mut source_hash = None;
	for _ in 0..2 {
		let mut mcp = RunningMcp::start(&config_path);
		mcp.initialize();
		let listing = mcp.request(2, "tools/list", json!({}));
		let tool = listing["tools"]
			.as_array()
			.expect("tools")
			.iter()
			.find(|tool| tool["name"] == "rea_inspect_application")
			.expect("registered application tool");
		assert_eq!(tool["annotations"]["readOnlyHint"], true);
		let apk_report = report(&mcp.call(
			3,
			"rea_inspect_application",
			json!({
				"path":apk,"kind":"apk","collection":"components","limit":2,
				"expected_sha256":source_hash
			}),
		));
		assert_eq!(
			apk_report["summary"]["package"]["value"],
			"org.hepta.fixture"
		);
		assert_eq!(apk_report["manifest"]["crc32_verified"], true);
		assert_eq!(apk_report["next_offset"], 2);
		let current = apk_report["source"]["sha256"]
			.as_str()
			.expect("SHA")
			.to_owned();
		if let Some(previous) = &source_hash {
			assert_eq!(previous, &current, "stable across MCP restart");
		}
		source_hash = Some(current.clone());
		let continuation = report(&mcp.call(
			4,
			"rea_inspect_application",
			json!({
				"path":apk,"kind":"apk","collection":"components","offset":2,"limit":2,"expected_sha256":current
			}),
		));
		assert_eq!(continuation["offset"], 2);
		assert_eq!(continuation["rows"].as_array().expect("rows").len(), 2);
		assert_eq!(
			mcp.call(
				5,
				"rea_inspect_application",
				json!({
					"path":apk,"kind":"apk","collection":"components","offset":2
				})
			)["isError"],
			true
		);
		assert_eq!(
			mcp.call(
				6,
				"rea_inspect_application",
				json!({
					"path":apk,"kind":"apk","expected_sha256":"0".repeat(64)
				})
			)["isError"],
			true
		);
		let jar_report = report(&mcp.call(
			7,
			"rea_inspect_application",
			json!({
				"path":jar,"kind":"jar","collection":"attributes"
			}),
		));
		assert_eq!(jar_report["summary"]["main_class"], "org.hepta.Fixture");
		assert_eq!(jar_report["summary"]["class_files_inspected"], false);
		assert_eq!(jar_report["coverage"]["signatures"], "not verified");
		assert_eq!(
			mcp.call(
				8,
				"rea_inspect_application",
				json!({
					"path":outside,"kind":"jar"
				})
			)["isError"],
			true
		);
	}
	assert_eq!(std::fs::read(&apk).expect("unchanged APK"), apk_bytes);
	assert_eq!(std::fs::read(&jar).expect("unchanged JAR"), jar_bytes);
}
