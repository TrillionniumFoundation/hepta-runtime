// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Explicit CPU qualification through the shipped MCP binary, with independently
//! loaded safetensors and real PyTorch linear outputs. No package installation.

#![cfg(all(feature = "remote-fs", target_os = "linux"))]

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::{BufRead, BufReader, Write};
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
			.expect("shipped MCP binary");
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
		let mut result = Self {
			child,
			stdin,
			replies,
			sequence: 0,
		};
		result.request("initialize", json!({"protocolVersion":"2026-07-28","capabilities":{},"clientInfo":{"name":"native-linear-cpu-qualification","version":"1"}}));
		result.send(&json!({"jsonrpc":"2.0","method":"notifications/initialized","params":{}}));
		result
	}
	fn send(&mut self, value: &Value) {
		writeln!(self.stdin, "{value}").unwrap();
		self.stdin.flush().unwrap();
	}
	fn request(&mut self, method: &str, args: Value) -> Value {
		self.sequence += 1;
		let id = self.sequence;
		self.send(&json!({"jsonrpc":"2.0","id":id,"method":method,"params":args}));
		let deadline = Instant::now() + Duration::from_secs(60);
		for _ in 0..64 {
			let remaining = deadline
				.checked_duration_since(Instant::now())
				.expect("MCP reply deadline");
			let line = self
				.replies
				.recv_timeout(remaining)
				.expect("bounded MCP reply");
			let reply: Value = serde_json::from_str(&line).unwrap();
			if reply["id"] == id {
				assert!(reply.get("error").is_none(), "MCP protocol error: {reply}");
				return reply["result"].clone();
			}
		}
		panic!("too many unrelated MCP notifications");
	}
	fn raw(&mut self, tool: &str, args: Value) -> Value {
		self.request("tools/call", json!({"name":tool,"arguments":args}))
	}
	fn call(&mut self, tool: &str, args: Value) -> Value {
		let reply = self.raw(tool, args);
		assert_ne!(reply["isError"], true, "{tool}: {reply}");
		serde_json::from_str(reply["content"][0]["text"].as_str().unwrap()).unwrap()
	}
}

impl Drop for Mcp {
	fn drop(&mut self) {
		let _ = self.child.kill();
		let _ = self.child.wait();
	}
}

fn sha(bytes: &[u8]) -> String {
	Sha256::digest(bytes)
		.iter()
		.map(|byte| format!("{byte:02x}"))
		.collect()
}

fn fixture() -> Vec<u8> {
	let mut header =
		serde_json::to_vec(&json!({"weight":{"dtype":"F32","shape":[2,2],"data_offsets":[0,16]}}))
			.unwrap();
	while !header.len().is_multiple_of(8) {
		header.push(b' ');
	}
	let mut bytes = (header.len() as u64).to_le_bytes().to_vec();
	bytes.extend(header);
	for value in [1_f32, -3., 0., 4.] {
		bytes.extend(value.to_le_bytes());
	}
	bytes
}

fn torch_reference(python: &Path, model: &Path, inputs: &Value, bias: &Value) -> Value {
	let script = r#"
import hashlib, json, sys
import torch
from safetensors.torch import load_file
torch.set_num_threads(1)
request = json.load(sys.stdin)
weights = load_file(request['path'], device='cpu')['weight']
inputs = torch.tensor(request['inputs'], dtype=torch.float32)
bias = None if request['bias'] is None else torch.tensor(request['bias'], dtype=torch.float32)
with torch.no_grad():
    outputs = torch.nn.functional.linear(inputs, weights, bias)
with open(request['path'], 'rb') as handle:
    digest = hashlib.sha256(handle.read()).hexdigest()
print(json.dumps({'outputs':outputs.tolist(),'source_sha256':digest,'torch_version':torch.__version__}))
"#;
	let mut child = Command::new(python)
		.args(["-I", "-c", script])
		.env("OMP_NUM_THREADS", "1")
		.env("MKL_NUM_THREADS", "1")
		.stdin(Stdio::piped())
		.stdout(Stdio::piped())
		.stderr(Stdio::piped())
		.spawn()
		.expect("explicit isolated CPU Python");
	let mut stdin = child.stdin.take().unwrap();
	serde_json::to_writer(
		&mut stdin,
		&json!({"path":model,"inputs":inputs,"bias":bias}),
	)
	.unwrap();
	drop(stdin);
	let deadline = Instant::now() + Duration::from_secs(60);
	loop {
		if child.try_wait().unwrap().is_some() {
			break;
		}
		if Instant::now() >= deadline {
			let _ = child.kill();
			let _ = child.wait();
			panic!("real PyTorch comparison exceeded its deadline");
		}
		std::thread::sleep(Duration::from_millis(20));
	}
	let output = child.wait_with_output().unwrap();
	assert!(
		output.status.success(),
		"PyTorch failed: {}",
		String::from_utf8_lossy(&output.stderr)
	);
	serde_json::from_slice(&output.stdout).unwrap()
}

fn forward_path(
	server: &mut Mcp,
	path: &Path,
	digest: &str,
	inputs: &Value,
	bias: &Value,
) -> Value {
	server.call("weight_linear_forward", json!({"source":{"kind":"path","path":path,"expected_sha256":digest,"tensor_name":"weight"},"inputs":inputs,"bias":bias}))
}

fn forward_artifact(server: &mut Mcp, id: &Value, inputs: &Value) -> Value {
	server.call(
		"weight_linear_forward",
		json!({"source":{"kind":"artifact","artifact_id":id,"tensor_name":"weight"},"inputs":inputs}),
	)
}

fn patch_args(path: &Path, digest: &str, replacement: &str) -> Value {
	json!({"path":path,"expected_sha256":digest,"tensor_name":"weight","edits":[{"index":0,"expected_hex":"0000803f","replacement_hex":replacement}]})
}

#[test]
#[ignore = "requires HEPTA_WEIGHT_TEST_PYTHON pointing to an existing CPU torch + safetensors environment"]
fn native_linear_mcp_matches_real_pytorch_across_noop_patch_restore() {
	let python =
		PathBuf::from(std::env::var("HEPTA_WEIGHT_TEST_PYTHON").expect("explicit CPU Python path"));
	assert!(python.is_absolute());
	let temp = tempfile::tempdir().unwrap();
	let source = temp.path().join("linear.safetensors");
	let original = fixture();
	let digest = sha(&original);
	std::fs::write(&source, &original).unwrap();
	let config = temp.path().join("runtime.json");
	std::fs::write(&config, serde_json::to_vec(&json!({
		"state_dir":temp.path().join("controller-state"),"controller_workspace_roots":[temp.path()],
		"hosts":{"unused":{"ssh_target":"unused.invalid","remote_state_dir":temp.path().join("unused-state"),"allow_execute":false}},
		"weight_workers":{}
	})).unwrap()).unwrap();
	let mut server = Mcp::start(&config);
	let tools = server.request("tools/list", json!({}));
	let names: Vec<&str> = tools["tools"]
		.as_array()
		.unwrap()
		.iter()
		.filter_map(|tool| tool["name"].as_str())
		.collect();
	for tool in [
		"weight_artifact_patch",
		"weight_artifact_restore",
		"weight_linear_forward",
		"weight_guarded_linear_patch",
		"weight_linear_ridge_plan",
	] {
		assert!(
			names.contains(&tool),
			"native tool missing without Python profiles: {tool}"
		);
	}
	assert!(!names.contains(&"weight_open"));
	let inputs = json!([[-2., 1.], [0.5, 2.], [3., -1.]]);
	let before = forward_path(&mut server, &source, &digest, &inputs, &Value::Null);
	let torch_before = torch_reference(&python, &source, &inputs, &Value::Null);
	assert_eq!(before["outputs"], torch_before["outputs"]);
	assert_eq!(before["source_sha256"], torch_before["source_sha256"]);
	let bias = json!([0.25, -0.5]);
	let biased = forward_path(&mut server, &source, &digest, &inputs, &bias);
	assert_eq!(
		biased["outputs"],
		torch_reference(&python, &source, &inputs, &bias)["outputs"]
	);
	let noop = server.call(
		"weight_artifact_patch",
		patch_args(&source, &digest, "0000803f"),
	);
	assert_eq!(noop["exact_no_op"], true);
	assert_eq!(noop["sha256"], digest);
	assert_eq!(
		forward_artifact(&mut server, &noop["artifact_id"], &inputs)["outputs"],
		before["outputs"]
	);
	let patched = server.call(
		"weight_artifact_patch",
		patch_args(&source, &digest, "00000040"),
	);
	let retry = server.call(
		"weight_artifact_patch",
		patch_args(&source, &digest, "00000040"),
	);
	assert_eq!(retry["artifact_id"], patched["artifact_id"]);
	assert_eq!(retry["reused"], true);
	let after = forward_artifact(&mut server, &patched["artifact_id"], &inputs);
	let torch_after = torch_reference(
		&python,
		Path::new(patched["artifact_path"].as_str().unwrap()),
		&inputs,
		&Value::Null,
	);
	assert_eq!(after["outputs"], torch_after["outputs"]);
	assert_eq!(after["source_sha256"], torch_after["source_sha256"]);
	let targets = [-7_f64, -5., 9.];
	let mse = |result: &Value| {
		result["outputs"]
			.as_array()
			.unwrap()
			.iter()
			.zip(targets)
			.map(|(row, target)| (row[0].as_f64().unwrap() - target).powi(2))
			.sum::<f64>()
			/ 3.
	};
	assert!(mse(&before) > 4.);
	assert_eq!(mse(&after), 0.);
	for index in 0..3 {
		assert_eq!(before["outputs"][index][1], after["outputs"][index][1]);
	}
	let restored = server.call(
		"weight_artifact_restore",
		json!({"artifact_id":patched["artifact_id"]}),
	);
	let recovered = forward_artifact(&mut server, &restored["artifact_id"], &inputs);
	assert_eq!(recovered["outputs"], before["outputs"]);
	assert_eq!(recovered["source_sha256"], digest);
	let restored_path = Path::new(restored["artifact_path"].as_str().unwrap());
	assert_eq!(
		torch_reference(&python, restored_path, &inputs, &Value::Null)["outputs"],
		recovered["outputs"]
	);
	assert_eq!(std::fs::read(restored_path).unwrap(), original);
	assert_eq!(std::fs::read(&source).unwrap(), original);
	let forbidden_state_path = server.raw("weight_linear_forward", json!({"source":{"kind":"path","path":restored_path,"expected_sha256":digest,"tensor_name":"weight"},"inputs":inputs}));
	assert_eq!(forbidden_state_path["isError"], true);
	let guarded_args = json!({
		"patch":patch_args(&source,&digest,"00000040"),"inputs":inputs,
		"objective":{"kind":"squared_error","targets":[[-7.,4.],[-5.,8.],[9.,-4.]]},
		"minimum_gain":0.0,"constraints":[{"kind":"preserve","column":1,"max_absolute_change":0.0}]
	});
	let guarded = server.call("weight_guarded_linear_patch", guarded_args.clone());
	assert_eq!(guarded["outcome"], "accepted_on_supplied_rows");
	assert_eq!(guarded["primary_after"], 0.0);
	assert_eq!(guarded["candidate"]["sha256"], patched["sha256"]);
	let mut bad_args = guarded_args;
	bad_args["patch"]["edits"][0]["replacement_hex"] = json!("000000c0");
	let rejected = server.call("weight_guarded_linear_patch", bad_args);
	assert_eq!(rejected["outcome"], "rejected_and_restored");
	let recovered_path = Path::new(rejected["restoration"]["artifact_path"].as_str().unwrap());
	assert_eq!(
		torch_reference(&python, recovered_path, &inputs, &Value::Null)["outputs"],
		before["outputs"]
	);
	assert_eq!(std::fs::read(recovered_path).unwrap(), original);
	assert_eq!(std::fs::read(&source).unwrap(), original);
	println!(
		"WEIGHT_NATIVE_GUARDED_PATCH_QUALIFICATION {}",
		json!({
			"positive_outcome":guarded["outcome"],"negative_outcome":rejected["outcome"],
			"original_sha256":digest,"restored_sha256":rejected["restoration"]["sha256"],
			"real_pytorch_restored_outputs_match":true,"original_source_unchanged":true,
			"scope":"constructed F32 linear fixture; independent model capability improvement not established"
		})
	);
	println!(
		"WEIGHT_NATIVE_PYTORCH_LINEAR_QUALIFICATION {}",
		json!({
			"torch_version":torch_before["torch_version"],"parent_sha256":digest,"patched_sha256":patched["sha256"],"restored_sha256":restored["sha256"],
			"held_out_mse_before":mse(&before),"held_out_mse_after":mse(&after),"protected_output_column_equal":true,
			"exact_no_op_equal":true,"restored_all_bytes_equal":true,"rust_matches_pytorch":true,
			"scope":"fixed two-input/two-output F32 linear fixture; no general model migration or automatic repair claim"
		})
	);
}
