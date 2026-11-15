// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Shipped stdio MCP -> original SSH job owner -> real resident CPU worker.
//! The opt-in test requires an existing authorized localhost SSH identity and
//! an explicitly supplied isolated Python environment; it installs nothing.

#![cfg(feature = "remote-fs")]

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

struct Mcp {
	child: Child,
	stdin: ChildStdin,
	replies: Receiver<String>,
	sequence: u64,
}

impl Mcp {
	fn start(config: &Path) -> Self {
		let mut child = Command::new(env!("CARGO_BIN_EXE_hepta-runtime"))
			.args(["mcp", "--runtime-config"])
			.arg(config)
			.stdin(Stdio::piped())
			.stdout(Stdio::piped())
			.stderr(Stdio::inherit())
			.spawn()
			.expect("start shipped MCP binary");
		let stdin = child.stdin.take().unwrap();
		let stdout = child.stdout.take().unwrap();
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
		let mut server = Self {
			child,
			stdin,
			replies,
			sequence: 0,
		};
		server.request("initialize",json!({"protocolVersion":"2026-07-28","capabilities":{},"clientInfo":{"name":"weight-owner-e2e","version":"1"}}));
		server.send(&json!({"jsonrpc":"2.0","method":"notifications/initialized","params":{}}));
		server
	}
	fn send(&mut self, value: &Value) {
		writeln!(self.stdin, "{value}").unwrap();
		self.stdin.flush().unwrap();
	}
	fn request(&mut self, method: &str, params: Value) -> Value {
		self.sequence += 1;
		let id = self.sequence;
		self.send(&json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}));
		for _ in 0..64 {
			let line = self
				.replies
				.recv_timeout(Duration::from_secs(60))
				.expect("bounded MCP reply");
			let response: Value = serde_json::from_str(&line).unwrap();
			if response["id"] != id {
				continue;
			}
			assert!(
				response.get("error").is_none(),
				"protocol error: {response}"
			);
			return response["result"].clone();
		}
		panic!("too many unrelated MCP notifications");
	}
	fn call_raw(&mut self, tool: &str, args: Value) -> Value {
		self.request("tools/call", json!({"name":tool,"arguments":args}))
	}
	fn call(&mut self, tool: &str, args: Value) -> Value {
		let result = self.call_raw(tool, args);
		assert_ne!(result["isError"], true, "{tool} failed: {result}");
		serde_json::from_str(result["content"][0]["text"].as_str().unwrap())
			.expect("typed JSON tool result")
	}
	fn worker_reply(&mut self, session: &str, request: Option<&str>) -> Value {
		let deadline = Instant::now() + Duration::from_secs(90);
		let mut stdout = String::new();
		let mut offset = 0u64;
		loop {
			let mut args = json!({"session_id":session,"stdout_offset":offset,"stderr_offset":0,"limit":65536});
			if let Some(request) = request {
				args["request_id"] = json!(request);
			}
			let read = self.call("weight_read", args);
			stdout.push_str(read["stdout"]["text"].as_str().unwrap_or_default());
			offset = read["stdout"]["next_offset"].as_u64().unwrap();
			if let Some(line) = stdout.lines().find(|line| !line.trim().is_empty()) {
				if let Ok(reply) = serde_json::from_str::<Value>(line) {
					return reply;
				}
			}
			assert!(
				Instant::now() < deadline,
				"worker response deadline; read={read}"
			);
			std::thread::sleep(Duration::from_millis(100));
		}
	}
	fn worker_call(&mut self, session: &str, request: &str, op: &str, params: Value) -> Value {
		self.call(
			"weight_call",
			json!({"session_id":session,"request_id":request,"op":op,"params":params}),
		);
		let result = self.worker_reply(session, Some(request));
		assert_eq!(result["ok"], true, "worker rejected {op}: {result}");
		result["result"].clone()
	}
}

impl Drop for Mcp {
	fn drop(&mut self) {
		let _ = self.child.kill();
		let _ = self.child.wait();
	}
}

fn sha(data: &[u8]) -> String {
	Sha256::digest(data)
		.iter()
		.map(|byte| format!("{byte:02x}"))
		.collect()
}

fn fixture(path: &Path) -> String {
	let mut header = serde_json::to_vec(
		&json!({"0.weight":{"dtype":"F32","shape":[2,2],"data_offsets":[0,16]}}),
	)
	.unwrap();
	while !header.len().is_multiple_of(8) {
		header.push(b' ');
	}
	let mut bytes = (header.len() as u64).to_le_bytes().to_vec();
	bytes.extend(header);
	for value in [1_f32, 0., 0., 1.] {
		bytes.extend(value.to_le_bytes());
	}
	std::fs::write(path, &bytes).unwrap();
	sha(&bytes)
}

fn binary_sha(path: &Path) -> String {
	let mut stream = std::fs::File::open(path).unwrap();
	let mut hash = Sha256::new();
	let mut buffer = [0u8; 64 * 1024];
	loop {
		let length = stream.read(&mut buffer).unwrap();
		if length == 0 {
			break;
		}
		hash.update(&buffer[..length]);
	}
	hash.finalize()
		.iter()
		.map(|byte| format!("{byte:02x}"))
		.collect()
}

fn test_config(root: &Path, python: &Path, worker: &Path, native: bool) -> Value {
	let identity = Command::new(python)
		.arg(worker)
		.arg("--print-identity")
		.output()
		.expect("worker identity");
	assert!(
		identity.status.success(),
		"worker identity failed: {}",
		String::from_utf8_lossy(&identity.stderr)
	);
	let identity: Value = serde_json::from_slice(&identity.stdout).unwrap();
	let worker_parent = worker.parent().unwrap();
	// This opt-in localhost fixture uses the existing operator job owner. It does
	// not qualify the separately installed, privileged isolated-mode helper.
	let mut config = json!({
		"state_dir":root.join("controller-state"),"controller_workspace_roots":[root],
		"hosts":{"local":{"ssh_target":"localhost","execution_mode":"operator","remote_state_dir":root.join("jobs"),"allow_execute":true,"allow_write":true,"allow_job_network":true,"allow_detached_fallback":false,"allowed_read_path_prefixes":[root,worker_parent],"allowed_write_path_prefixes":[root]}},
		"weight_workers":{"cpu":{"host":"local","python_executable":python,"worker_path":worker,"worker_sha256":sha(&std::fs::read(worker).unwrap()),"worker_package_sha256":identity["package_sha256"],"session_root":root.join("sessions"),"input_roots":[root],"allowed_providers":["torch_sequential"],"max_lifetime_seconds":300,"max_request_ms":120000,"max_active_sessions":1,"max_requests_per_session":16}}
	});
	if native {
		let binary = std::fs::canonicalize(env!("CARGO_BIN_EXE_hepta-runtime")).unwrap();
		config["hosts"]["local"]["allowed_read_path_prefixes"]
			.as_array_mut()
			.unwrap()
			.push(json!(binary));
		config["weight_workers"]["cpu"]["native_client"] =
			json!({"executable":binary,"sha256":binary_sha(&binary)});
	}
	config
}

#[test]
#[ignore = "requires explicit CPU Python, source worker and authorized localhost SSH"]
fn real_resident_worker_reuses_jobs_across_mcp_restart_and_rejects_rebinding() {
	qualify_resident_worker(false);
}

#[test]
#[ignore = "requires explicit CPU Python, source worker, native binary and authorized localhost SSH"]
fn native_client_preserves_real_forward_and_original_jobs_across_mcp_restart() {
	qualify_resident_worker(true);
}

fn qualify_resident_worker(native: bool) {
	assert_eq!(
		std::env::var("HEPTA_WEIGHT_REAL_SSH").as_deref(),
		Ok("1"),
		"explicit real-host qualification required"
	);
	let python =
		PathBuf::from(std::env::var("HEPTA_WEIGHT_TEST_PYTHON").expect("isolated Python path"));
	let worker =
		PathBuf::from(std::env::var("HEPTA_WEIGHT_TEST_WORKER").expect("exact source worker path"));
	assert!(python.is_absolute() && worker.is_absolute());
	let temp = tempfile::Builder::new().prefix("hwe-").tempdir().unwrap();
	let root = temp.path();
	std::fs::create_dir(root.join("sessions")).unwrap();
	let weights = root.join("identity.safetensors");
	let weight_sha = fixture(&weights);
	let config_path = root.join("config.json");
	std::fs::write(
		&config_path,
		serde_json::to_vec(&test_config(root, &python, &worker, native)).unwrap(),
	)
	.unwrap();
	let mut server = Mcp::start(&config_path);
	let tools = server.request("tools/list", json!({}));
	let names: Vec<&str> = tools["tools"]
		.as_array()
		.unwrap()
		.iter()
		.filter_map(|t| t["name"].as_str())
		.collect();
	for tool in [
		"weight_profiles",
		"weight_open",
		"weight_call",
		"weight_status",
		"weight_read",
		"weight_close",
	] {
		assert!(names.contains(&tool));
	}
	assert!(!names.contains(&"shell"));
	let profiles = server.call("weight_profiles", json!({}));
	assert_eq!(
		profiles["profiles"][0]["client_transport"],
		if native {
			"native_rust"
		} else {
			"python_compat"
		}
	);
	let open = json!({"profile":"cpu","idempotency_key":"fixture-001","params":{"provider":"torch_sequential","idle_timeout_s":240,"model":{"architecture":{"layers":[{"type":"Linear","in_features":2,"out_features":2,"bias":false}]},"weights_path":weights,"weights_sha256":weight_sha}}});
	let admitted = server.call("weight_open", open.clone());
	let session = admitted["session_id"].as_str().unwrap().to_owned();
	let opened = server.worker_reply(&session, None);
	assert_eq!(opened["ok"], true, "{opened}");
	assert_eq!(opened["result"]["training_allowed"], false);
	assert_eq!(opened["result"]["production_activation_allowed"], false);
	drop(server);
	let mut server = Mcp::start(&config_path);
	let recovered = server.call("weight_open", open.clone());
	assert_eq!(
		admitted["job_id"], recovered["job_id"],
		"controller restart must reuse the original model job"
	);
	let mut changed = open.clone();
	changed["params"]["cpu_threads"] = json!(1);
	assert_eq!(server.call_raw("weight_open", changed)["isError"], true);
	let inspect_args = json!({"session_id":session,"request_id":"inspect-1","op":"inspect","params":{"hash":true}});
	let first = server.call("weight_call", inspect_args.clone());
	let inspected = server.worker_reply(&session, Some("inspect-1"));
	assert_eq!(inspected["ok"], true);
	let second = server.call("weight_call", inspect_args.clone());
	assert_eq!(first["job_id"], second["job_id"]);
	let mut wrong = inspect_args;
	wrong["params"]["hash"] = json!(false);
	assert_eq!(server.call_raw("weight_call", wrong)["isError"], true);
	let probe = server.worker_call(
		&session,
		"probe-1",
		"probe",
		json!({"inputs":{"x":[[1.,2.]]}}),
	);
	let replay = server.call(
		"weight_call",
		json!({"session_id":session,"request_id":"probe-1","op":"probe","params":{"inputs":{"x":[[1.,2.]]}}}),
	);
	let replayed = server.worker_reply(&session, Some("probe-1"));
	assert_eq!(
		replayed["result"], probe,
		"probe retry returns its original artifact"
	);
	assert_eq!(replay["request_id"], "probe-1");
	let values = server.worker_call(
		&session,
		"query-1",
		"query",
		json!({"artifact_id":probe["outputs"]["artifact_id"],"tensor":"output"}),
	);
	assert_eq!(values["values"], json!([1., 2.]));
	let another = json!({"profile":"cpu","idempotency_key":"fixture-002","params":open["params"]});
	assert_eq!(
		server.call_raw("weight_open", another)["isError"],
		true,
		"active session lease is bounded"
	);
	let closed = server.call("weight_close", json!({"session_id":session}));
	assert_eq!(closed["closed_to_new_calls"], true);
	let terminal = server.call(
		"weight_status",
		json!({"session_id":session,"wait_seconds":30}),
	);
	assert!(
		matches!(terminal["state"].as_str(), Some("cancelled" | "succeeded")),
		"{terminal}"
	);
	assert_eq!(
		server.call_raw("weight_open", open)["isError"],
		true,
		"closed identity cannot relaunch"
	);
	assert_eq!(
		sha(&std::fs::read(weights).unwrap()),
		weight_sha,
		"parent bytes unchanged"
	);
	assert_eq!(probe["total_forward_examples"], 1);
	println!(
		"WEIGHT_MCP_QUALIFICATION {}",
		json!({
			"schema":"hepta.weight.mcp-qualification.v1",
			"host_execution_mode":"operator",
			"client_transport":if native { "native_rust" } else { "python_compat" },
			"session_id":session,
			"resident_job_id":admitted["job_id"],
			"recovered_job_id":recovered["job_id"],
			"inspect_job_id":first["job_id"],
			"inspect_replay_job_id":second["job_id"],
			"probe_job_id":replay["job_id"],
			"total_forward_examples":probe["total_forward_examples"],
			"query_values":values["values"],
			"terminal_state":terminal["state"],
			"source_weights_sha256":weight_sha,
			"model_id":opened["result"]["model_id"],
			"worker_sha256":admitted["worker_sha256"],
			"worker_package_sha256":admitted["worker_package_sha256"],
			"checks":["controller_restart_original_job","same_id_replay","changed_input_rejected","one_real_forward","artifact_query","session_budget","close_observed_terminal","source_unchanged"]
		})
	);
}
