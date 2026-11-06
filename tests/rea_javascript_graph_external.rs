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

//! Actual shipped MCP -> bounded AST worker tests over authored JS/TS/Electron
//! fixtures, with independent Babel expected observations and denial cases.

#![cfg(all(feature = "remote-fs", unix))]

use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

struct RunningMcp {
	child: Child,
	stdin: ChildStdin,
	replies: Receiver<String>,
}

fn runtime_binary() -> PathBuf {
	let path = std::env::var_os("HEPTA_JS_AST_TEST_RUNTIME")
		.map(PathBuf::from)
		.unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_hepta-runtime")));
	assert!(
		path.is_absolute(),
		"test runtime override must be an absolute path"
	);
	path
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
			.expect("start shipped runtime");
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
			json!({
				"protocolVersion":"2026-07-28","capabilities":{},
				"clientInfo":{"name":"hepta-js-ast-e2e","version":"1"}
			}),
		);
		mcp.send(&json!({"jsonrpc":"2.0","method":"notifications/initialized","params":{}}));
		mcp
	}

	fn send(&mut self, value: &Value) {
		writeln!(self.stdin, "{value}").expect("write request");
		self.stdin.flush().expect("flush request");
	}

	fn request(&mut self, id: i64, method: &str, params: Value) -> Value {
		self.send(&json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}));
		for _ in 0..64 {
			let line = self
				.replies
				.recv_timeout(Duration::from_secs(30))
				.expect("bounded MCP reply");
			let message: Value = serde_json::from_str(&line).expect("MCP JSON");
			if message["id"] == id {
				assert!(message.get("error").is_none(), "protocol error: {message}");
				return message["result"].clone();
			}
		}
		panic!("too many unrelated notifications");
	}

	fn call(&mut self, id: i64, arguments: Value) -> Value {
		self.request(
			id,
			"tools/call",
			json!({
				"name":"rea_inspect_javascript_graph","arguments":arguments
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

fn report(reply: Value) -> Value {
	assert_ne!(reply["isError"], true, "tool error: {reply}");
	serde_json::from_str(reply["content"][0]["text"].as_str().expect("text")).expect("graph JSON")
}

fn fixture_paths() -> PathBuf {
	let path = std::env::var_os("HEPTA_JS_AST_FIXTURE_DIR")
		.map(PathBuf::from)
		.unwrap_or_else(|| {
			Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/rea_javascript")
		});
	assert!(
		path.is_absolute(),
		"test fixture override must be an absolute path"
	);
	path
}

fn selected_sources(workspace: &Path, marker: &Path) -> Vec<Value> {
	let fixtures = fixture_paths();
	let manifest: Value = serde_json::from_slice(
		&std::fs::read(fixtures.join("manifest.json")).expect("fixture manifest"),
	)
	.expect("manifest JSON");
	manifest["sources"].as_array().expect("sources").iter().map(|source| {
		let file = source["file"].as_str().expect("filename");
		let original = std::fs::read_to_string(fixtures.join(file)).expect("source fixture");
		let bytes = original.replace("\"HEPTA_AST_EXECUTION_MARKER\"", &json!(marker).to_string());
		let path = workspace.join(file);
		std::fs::write(&path, bytes).expect("owned source");
		json!({"id":source["id"],"path":path,"syntax":source["syntax"],"module_kind":source["module_kind"]})
	}).collect()
}

fn normalized_imports(rows: &Value) -> Vec<Value> {
	let mut values: Vec<_> = rows
		.as_array()
		.expect("rows")
		.iter()
		.map(|row| {
			json!({
				"source_id":row["source_id"],"span":row["span"],"kind":row["kind"],
				"specifier":row["specifier"],"type_only":row["type_only"],"bindings":row["bindings"]
			})
		})
		.collect();
	values.sort_by_key(Value::to_string);
	values
}

#[test]
fn actual_mcp_worker_matches_babel_imports_preserves_unknowns_and_never_executes() {
	let root = tempfile::tempdir().expect("root");
	let workspace = root.path().join("workspace");
	std::fs::create_dir(&workspace).expect("workspace");
	let marker = workspace.join("must-not-run");
	let sources = selected_sources(&workspace, &marker);
	std::fs::copy(
		fixture_paths().join("package.json"),
		workspace.join("package.json"),
	)
	.expect("owned package declaration fixture");
	let outside = root.path().join("outside.js");
	std::fs::write(&outside, "export const outside = true;").expect("outside");
	let symlink = workspace.join("symlink.js");
	std::os::unix::fs::symlink(&outside, &symlink).expect("symlink");
	let config = root.path().join("policy.json");
	std::fs::write(
		&config,
		serde_json::to_vec(&json!({
			"state_dir":root.path().join("state"),"controller_workspace_roots":[workspace],
			"hosts":{"never-connect":{
				"ssh_target":"never-connect-invalid","remote_state_dir":root.path().join("remote-state"),
				"allow_execute":false,"allow_pty":false,"allow_write":false,"allow_job_network":false
			}}
		}))
		.expect("policy JSON"),
	)
	.expect("policy");
	let reference: Value = serde_json::from_slice(
		&std::fs::read(fixture_paths().join("reference.json"))
			.expect("actual independent Babel oracle"),
	)
	.expect("reference JSON");
	assert_eq!(
		reference["status"], "pass",
		"independent fixture qualification must pass"
	);
	let mut expected_imports = reference["expected"]["imports"]
		.as_array()
		.expect("Babel imports")
		.clone();
	expected_imports.sort_by_key(Value::to_string);
	let mut identity = None;
	for iteration in 0..2 {
		let mut mcp = RunningMcp::start(&config);
		let package = report(mcp.request(
			20,
			"tools/call",
			json!({
				"name":"rea_inspect_javascript_package",
				"arguments":{"path":workspace.join("package.json"),"collection":"entries"}
			}),
		));
		assert_eq!(package["summary"]["main_declaration"], "main.ts");
		assert_eq!(package["entry_files_opened"], false);
		assert_eq!(package["javascript_executed"], false);
		let listing = mcp.request(2, "tools/list", json!({}));
		assert!(listing["tools"]
			.as_array()
			.expect("tools")
			.iter()
			.any(|tool| tool["name"] == "rea_inspect_javascript_graph"));
		let imports = report(mcp.call(
			3,
			json!({"sources":sources,"collection":"imports","limit":256}),
		));
		assert_eq!(normalized_imports(&imports["rows"]), expected_imports);
		assert_eq!(imports["parser"]["name"], "oxc");
		assert_eq!(imports["parser"]["semantic_syntax_checks"], true);
		assert_eq!(imports["javascript_executed"], false);
		assert_eq!(imports["complete_application_graph"], false);
		let hash = imports["graph_sha256"]
			.as_str()
			.expect("graph identity")
			.to_owned();
		if let Some(previous) = &identity {
			assert_eq!(previous, &hash);
		} else {
			identity = Some(hash.clone());
		}
		let edges = report(mcp.call(
			4,
			json!({"sources":sources,"collection":"ipc_edges","expected_graph_sha256":hash}),
		));
		assert_eq!(
			edges["total_rows"],
			reference["comparisons"]["ipc_edges"]["expected_count"]
		);
		for edge in edges["rows"].as_array().expect("candidate edges") {
			assert_eq!(edge["process_pair_proven"], false);
		}
		let unknowns = report(mcp.call(5, json!({"sources":sources,"collection":"unknowns"})));
		assert!(unknowns["total_rows"].as_u64().expect("unknown count") > 0);
		assert!(
			!marker.exists(),
			"source-side writeFileSync must never execute"
		);
		let unbound_page = mcp.call(
			6,
			json!({"sources":sources,"collection":"imports","offset":1}),
		);
		assert_eq!(unbound_page["isError"], true);
		let bound_page = report(mcp.call(7, json!({"sources":sources,"collection":"imports","offset":1,"limit":1,"expected_graph_sha256":hash})));
		assert_eq!(bound_page["offset"], 1);
		for (index, path) in [&outside, &symlink].iter().enumerate() {
			let denied = mcp.call(
				8 + index as i64,
				json!({"sources":[{"id":"denied.js","path":path}]}),
			);
			assert_eq!(denied["isError"], true);
		}
		if iteration == 1 {
			std::fs::write(workspace.join("util.js"), "export const answer=99;")
				.expect("changed source");
			let stale = mcp.call(
				10,
				json!({"sources":sources,"collection":"imports","offset":1,"expected_graph_sha256":hash}),
			);
			assert_eq!(
				stale["isError"], true,
				"every selected source belongs to continuation identity"
			);
			std::fs::write(workspace.join("bad.js"), "const x = ;").expect("bad source");
			let invalid = mcp.call(
				11,
				json!({"sources":[{"id":"bad.js","path":workspace.join("bad.js")}]}),
			);
			assert_eq!(invalid["isError"], true);
			std::fs::write(workspace.join("large.js"), vec![b' '; 1024 * 1024 + 1])
				.expect("large source");
			let oversized = mcp.call(
				12,
				json!({"sources":[{"id":"large.js","path":workspace.join("large.js")}]}),
			);
			assert_eq!(oversized["isError"], true);
			std::fs::write(workspace.join("nodes.js"), "0;".repeat(100_001))
				.expect("AST budget fixture");
			let node_budget = mcp.call(
				14,
				json!({"sources":[{"id":"nodes.js","path":workspace.join("nodes.js")}]}),
			);
			assert_eq!(
				node_budget["isError"], true,
				"worker must enforce AST node budget"
			);
			assert!(
				node_budget["content"][0]["text"]
					.as_str()
					.expect("budget error")
					.contains("200000 AST nodes"),
				"budget refusal must identify the AST node limit"
			);
			let recovered = report(mcp.call(13, json!({"sources":[sources[2].clone()]})));
			assert_eq!(recovered["counts"]["sources"], 1);
		}
	}
}

#[test]
fn actual_mcp_preserves_type_modifier_scope_and_recovers_after_invalid_typescript() {
	let root = tempfile::tempdir().expect("root");
	let workspace = root.path().join("workspace");
	std::fs::create_dir(&workspace).expect("workspace");
	let source = workspace.join("fixture.ts");
	let text = "import type { Foo } from './types';\nimport { type Bar } from './types';\nexport type { Foo } from './types';\nexport { type Bar } from './types';";
	std::fs::write(&source, text).expect("TypeScript source");
	let config = root.path().join("policy.json");
	std::fs::write(
		&config,
		serde_json::to_vec(&json!({
			"state_dir":root.path().join("state"),"controller_workspace_roots":[workspace],
			"hosts":{"never-connect":{
				"ssh_target":"never-connect-invalid","remote_state_dir":root.path().join("remote-state"),
				"allow_execute":false,"allow_pty":false,"allow_write":false,"allow_job_network":false
			}}
		}))
		.expect("policy JSON"),
	)
	.expect("policy");
	let arguments = json!({
		"sources":[{"id":"fixture.ts","path":source,"syntax":"typescript","module_kind":"module"}],
		"collection":"imports","limit":16
	});
	let mut mcp = RunningMcp::start(&config);
	let initial = report(mcp.call(2, arguments.clone()));
	assert_eq!(
		initial["analysis_profile"],
		"hepta.javascript-selected-source-graph.v4"
	);
	assert_eq!(initial["total_rows"], 4);
	let scopes: Vec<_> = initial["rows"]
		.as_array()
		.expect("dependency rows")
		.iter()
		.map(|row| {
			assert_eq!(row["type_only"], true);
			assert_eq!(row["runtime_resolution_proven"], false);
			row["type_only_scope"]
				.as_str()
				.expect("type modifier scope")
		})
		.collect();
	assert_eq!(
		scopes,
		[
			"declaration",
			"named_specifiers",
			"declaration",
			"named_specifiers"
		]
	);
	std::fs::write(&source, "export type { from './types';").expect("invalid syntax fixture");
	let invalid = mcp.call(3, arguments.clone());
	assert_eq!(invalid["isError"], true);
	std::fs::write(&source, text).expect("restore valid captured bytes");
	let recovered = report(mcp.call(4, arguments));
	assert_eq!(recovered["graph_sha256"], initial["graph_sha256"]);
	assert_eq!(recovered["rows"], initial["rows"]);
}
