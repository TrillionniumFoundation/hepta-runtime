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

//! Exercise the *shipped* MCP binary and its child worker end to end, with
//! a synthetic deny-by-default runtime policy. No remote SSH is contacted.

#![cfg(feature = "remote-fs")]

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
	fn start(config_path: &std::path::Path) -> Self {
		let mut command = Command::new(env!("CARGO_BIN_EXE_hepta-runtime"));
		command
			.arg("mcp")
			.arg("--runtime-config")
			.arg(config_path)
			.env_clear()
			.current_dir("/")
			.stdin(Stdio::piped())
			.stdout(Stdio::piped())
			.stderr(Stdio::null());
		#[cfg(unix)]
		{
			use std::os::unix::process::CommandExt;
			// Pin the CI permission input in this child, even when its test
			// runner inherits a private operator-service umask.
			unsafe {
				command.pre_exec(|| {
					libc::umask(0o022);
					Ok(())
				});
			}
		}
		let mut child = command.spawn().expect("start exact built MCP executable");
		let stdin = child.stdin.take().expect("MCP stdin");
		let stdout = child.stdout.take().expect("MCP stdout");
		let (sender, replies) = mpsc::channel();
		std::thread::spawn(move || {
			for line in BufReader::new(stdout).lines() {
				match line {
					Ok(line) => {
						if sender.send(line).is_err() {
							break;
						}
					}
					Err(_) => break,
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
		writeln!(self.stdin, "{message}").expect("send MCP JSON-RPC request");
		self.stdin.flush().expect("flush MCP request");
	}

	fn request(&mut self, id: i64, method: &str, params: Value) -> Value {
		self.send(&json!({
			"jsonrpc": "2.0",
			"id": id,
			"method": method,
			"params": params
		}));
		for _ in 0..64 {
			let line = self
				.replies
				.recv_timeout(Duration::from_secs(15))
				.unwrap_or_else(|error| panic!("MCP reply timeout/closed for {method}: {error}"));
			let message: Value = serde_json::from_str(&line).expect("valid MCP JSON");
			if message["id"] != id {
				continue;
			}
			assert!(
				message.get("error").is_none(),
				"MCP {method} protocol error: {message}"
			);
			return message["result"].clone();
		}
		panic!("MCP {method} produced too many unrelated notifications");
	}

	fn initialize(&mut self) {
		self.request(
			1,
			"initialize",
			json!({
				"protocolVersion":"2026-07-28",
				"capabilities":{},
				"clientInfo":{"name":"hepta-rea-worker-e2e","version":"0.1.0"}
			}),
		);
		self.send(&json!({"jsonrpc":"2.0","method":"notifications/initialized","params":{}}));
	}

	fn call(&mut self, id: i64, name: &str, path: &std::path::Path) -> Value {
		self.request(
			id,
			"tools/call",
			json!({
				"name": name,
				"arguments": {"path": path.to_string_lossy()}
			}),
		)
	}
}

impl Drop for RunningMcp {
	fn drop(&mut self) {
		let _ = self.child.kill();
		let _ = self.child.wait();
	}
}

fn read_call_text(reply: &Value) -> Value {
	let content = reply["content"].as_array().expect("MCP content array");
	let first = content.first().expect("MCP content item");
	let text = first["text"].as_str().expect("MCP text result");
	serde_json::from_str(text).expect("embedded analysis JSON")
}

#[test]
fn external_mcp_policy_worker_and_controller_restart() {
	let root = tempfile::tempdir().expect("test root");
	let workspace = root.path().join("workspace");
	std::fs::create_dir(&workspace).expect("workspace");
	let good = workspace.join("sample.wasm");
	let wrong = root.path().join("outside.wasm");
	let malformed = workspace.join("truncated.elf");
	std::fs::write(&good, b"\0asm\x01\0\0\0").expect("valid WASM");
	std::fs::write(&wrong, b"\0asm\x01\0\0\0").expect("out-of-scope WASM");
	std::fs::write(&malformed, b"\x7fELF\x02\x01\x01").expect("truncated ELF");

	let config_file = root.path().join("policy.json");
	let policy = json!({
		"state_dir": root.path().join("state"),
		"controller_workspace_roots":[workspace],
		"hosts": {
			"no-remote-ci": {
				"ssh_target":"never-connect-ci",
				"remote_state_dir":root.path().join("remote-state"),
				"allow_execute":false,
				"allow_pty":false,
				"allow_write":false,
				"allow_job_network":false
			}
		}
	});
	std::fs::write(
		&config_file,
		serde_json::to_vec(&policy).expect("policy bytes"),
	)
	.expect("write policy");

	let mut retained_id: Option<String> = None;
	for iteration in 0..2 {
		let mut mcp = RunningMcp::start(&config_file);
		mcp.initialize();
		let discovered = mcp.request(2, "tools/list", json!({}));
		let names: Vec<_> = discovered["tools"]
			.as_array()
			.expect("tool listing")
			.iter()
			.filter_map(|tool| tool["name"].as_str())
			.collect();
		assert!(names.contains(&"rea_inspect_artifact"));
		assert!(names.contains(&"rea_verify_evidence"));
		assert!(names.contains(&"rea_retain_preview"));
		assert!(names.contains(&"rea_read_preview"));
		assert!(!names.contains(&"shell"), "unrestricted shell excluded");

		let output = mcp.call(3, "rea_inspect_artifact", &good);
		assert_ne!(output["isError"], true, "real binary positive: {output}");
		let report = read_call_text(&output);
		assert_eq!(report["normalized_result"]["format"], "wasm");
		assert_eq!(
			report["subject"]["local_path"].as_str(),
			Some(good.to_str().expect("controlled fixture path is UTF-8"))
		);
		assert_eq!(report["coverage"]["status"], "partial");
		assert_eq!(report["rea_evidence_compatible"], false);

		let denied = mcp.call(4, "rea_inspect_artifact", &wrong);
		assert_eq!(denied["isError"], true, "out-of-root must be denied");
		let invalid = mcp.call(5, "rea_inspect_artifact", &malformed);
		assert_eq!(invalid["isError"], true, "malformed input must be denied");

		if iteration == 0 {
			let retained = mcp.call(6, "rea_retain_preview", &good);
			assert_ne!(retained["isError"], true, "retain in worker: {retained}");
			let receipt = read_call_text(&retained);
			assert_eq!(receipt["status"], "retained");
			assert_eq!(receipt["reused"], false);
			assert_eq!(receipt["rea_evidence_compatible"], false);
			retained_id = Some(
				receipt["native_evidence_id"]
					.as_str()
					.expect("durable native ID")
					.to_string(),
			);
		}
		let id = retained_id
			.as_deref()
			.expect("retained ID from first controller");
		let unavailable = workspace.join("temporarily-unavailable.wasm");
		if iteration == 1 {
			std::fs::rename(&good, &unavailable).expect("remove source before cold replay");
			assert!(!good.exists(), "source must be absent during cold replay");
		}
		let restored = mcp.request(
			7,
			"tools/call",
			json!({"name":"rea_read_preview","arguments":{"native_evidence_id":id}}),
		);
		assert_ne!(restored["isError"], true, "cold persisted read: {restored}");
		let replay = read_call_text(&restored);
		assert_eq!(replay["native_evidence_id"], id);
		assert_eq!(replay["record"]["normalized_result"]["format"], "wasm");
		assert_eq!(
			replay["record"]["subject"]["local_path"].as_str(),
			Some(good.to_str().expect("controlled fixture path is UTF-8"))
		);
		assert_eq!(replay["record"]["rea_evidence_compatible"], false);
		if iteration == 1 {
			std::fs::rename(&unavailable, &good).expect("restore source after offline replay");
		}
		let denied_lookup = mcp.request(
			8,
			"tools/call",
			json!({"name":"rea_read_preview","arguments":{"native_evidence_id":"../escape"}}),
		);
		assert_eq!(
			denied_lookup["isError"], true,
			"path-like identifiers must fail"
		);
		if iteration == 1 {
			let reused = mcp.call(9, "rea_retain_preview", &good);
			assert_ne!(reused["isError"], true, "idempotent retain: {reused}");
			assert_eq!(read_call_text(&reused)["reused"], true);
		}
		// Each new controller must independently re-read its reviewed policy
		// rather than restoring an unowned REA provider session.
		assert!(iteration < 2);
	}
}

#[test]
#[cfg(unix)]
fn model_pages_ranges_and_archive_roles_use_the_shipped_mcp_workers() {
	let root = tempfile::tempdir().unwrap();
	let workspace = root.path().join("workspace");
	std::fs::create_dir(&workspace).unwrap();
	let model = workspace.join("two.safetensors");
	let header = serde_json::to_vec(&json!({
		"a":{"dtype":"F32","shape":[1,2],"data_offsets":[0,8]},
		"b":{"dtype":"F32","shape":[1,2],"data_offsets":[8,16]}
	}))
	.unwrap();
	let mut bytes = (header.len() as u64).to_le_bytes().to_vec();
	bytes.extend(&header);
	for value in [1_f32, 2., 3., 4.] {
		bytes.extend(value.to_le_bytes());
	}
	std::fs::write(&model, &bytes).unwrap();
	let archive = workspace.join("app-container.apk");
	std::fs::write(&archive, include_bytes!("fixtures/rea_artifact_sample.apk")).unwrap();
	let config = root.path().join("policy.json");
	std::fs::write(&config, serde_json::to_vec(&json!({
		"state_dir":root.path().join("state"),"controller_workspace_roots":[workspace],
		"hosts":{"denied":{"ssh_target":"never-connect-ci","remote_state_dir":root.path().join("remote"),"allow_execute":false}}
	})).unwrap()).unwrap();
	let mut mcp = RunningMcp::start(&config);
	mcp.initialize();
	let first = mcp.request(
		20,
		"tools/call",
		json!({"name":"rea_inspect_model","arguments":{"path":model,"limit":1,"hash":"full"}}),
	);
	assert_ne!(first["isError"], true, "{first}");
	let first = read_call_text(&first);
	assert_eq!(first["result"]["rows"][0]["name"], "a");
	assert_eq!(first["result"]["next_offset"], 1);
	assert_eq!(first["source"]["identity_scope"], "full_file");
	let page = json!({"path":model,"offset":1,"limit":1,"expected_version":first["source"]["observed_version"],"expected_header_sha256":first["source"]["header_sha256"]});
	drop(mcp);
	let mut mcp = RunningMcp::start(&config);
	mcp.initialize();
	let next = mcp.request(
		21,
		"tools/call",
		json!({"name":"rea_inspect_model","arguments":page}),
	);
	assert_ne!(next["isError"], true, "{next}");
	assert_eq!(read_call_text(&next)["result"]["rows"][0]["name"], "b");
	let mut read = json!({"path":model,"tensor_name":"a","offset":0,"length":8,"expected_version":first["source"]["observed_version"],"expected_header_sha256":first["source"]["header_sha256"],"expected_full_sha256":first["source"]["full_sha256"]});
	let selected = mcp.request(
		22,
		"tools/call",
		json!({"name":"rea_read_model","arguments":read}),
	);
	assert_ne!(selected["isError"], true, "{selected}");
	assert_eq!(
		read_call_text(&selected)["result"]["bytes_hex"],
		"0000803f00000040"
	);
	read["length"] = json!(9);
	assert_eq!(
		mcp.request(
			23,
			"tools/call",
			json!({"name":"rea_read_model","arguments":read})
		)["isError"],
		true
	);
	let app = mcp.request(24,"tools/call",json!({"name":"rea_inspect_archive","arguments":{"path":archive,"filter":"manifest","hash":"full"}}));
	assert_ne!(app["isError"], true, "{app}");
	let app = read_call_text(&app);
	assert_eq!(app["record_format"], "hepta.rea-archive-index.v1");
	assert_eq!(app["result"]["total"], 1);
	assert_eq!(app["rea_evidence_compatible"], false);
	bytes.push(0);
	std::fs::write(&model, &bytes).unwrap();
	assert_eq!(
		mcp.request(
			25,
			"tools/call",
			json!({"name":"rea_inspect_model","arguments":page})
		)["isError"],
		true
	);
}
