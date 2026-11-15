// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Real stdio MCP -> existing SSH owner -> pinned static worker qualification.
//! Only this test's own Rust build products are inspected. A separately pinned
//! synthetic backend exercises live cancellation; it is not GNU parity evidence.
//! This fixture explicitly qualifies the existing localhost operator owner;
//! deployment of the separate privileged isolated jobctl helper is not covered.
#![cfg(all(feature = "remote-fs", target_os = "linux"))]

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
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
	fn start(config: &Path, authority: &Path) -> Self {
		let mut child = Command::new(env!("CARGO_BIN_EXE_hepta-runtime"))
			.args(["mcp", "--runtime-config"])
			.arg(config)
			.env("HEPTA_EFFECT_OWNER_FENCE_DIR", authority)
			.env("HEPTA_EFFECT_OWNER_SELF", "v4")
			.env("HEPTA_EFFECT_OWNER_FENCE_REQUIRED", "1")
			.stdin(Stdio::piped())
			.stdout(Stdio::piped())
			.stderr(Stdio::inherit())
			.spawn()
			.expect("start the actual static MCP controller");
		let stdin = child.stdin.take().unwrap();
		let stdout = child.stdout.take().unwrap();
		let (sender, replies) = mpsc::channel();
		std::thread::spawn(move || {
			for line in BufReader::new(stdout).lines() {
				let Ok(line) = line else {
					break;
				};
				if sender.send(line).is_err() {
					break;
				}
			}
		});
		let mut result = Self {
			child,
			stdin,
			replies,
			sequence: 0,
		};
		result.request("initialize", json!({"protocolVersion":"2026-07-28","capabilities":{},"clientInfo":{"name":"static-owner-e2e","version":"1"}}));
		result.send(&json!({"jsonrpc":"2.0","method":"notifications/initialized","params":{}}));
		result
	}
	fn send(&mut self, value: &Value) {
		writeln!(self.stdin, "{value}").unwrap();
		self.stdin.flush().unwrap();
	}
	fn request(&mut self, method: &str, params: Value) -> Value {
		self.sequence += 1;
		let id = self.sequence;
		self.send(&json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}));
		let deadline = Instant::now() + Duration::from_secs(60);
		loop {
			let line = self
				.replies
				.recv_timeout(deadline.saturating_duration_since(Instant::now()))
				.expect("bounded MCP reply");
			let reply: Value = serde_json::from_str(&line).unwrap();
			if reply["id"] != id {
				continue;
			}
			assert!(reply.get("error").is_none(), "MCP protocol error: {reply}");
			return reply["result"].clone();
		}
	}
	fn call_raw(&mut self, name: &str, arguments: Value) -> Value {
		self.request("tools/call", json!({"name":name,"arguments":arguments}))
	}
	fn call(&mut self, name: &str, arguments: Value) -> Value {
		let result = self.call_raw(name, arguments);
		assert_ne!(result["isError"], true, "{name}: {result}");
		serde_json::from_str(result["content"][0]["text"].as_str().unwrap()).unwrap()
	}
	fn complete(&mut self, request: &Value) -> Value {
		let deadline = Instant::now() + Duration::from_secs(60);
		loop {
			let read = self.call("rea_static_read", request.clone());
			if read["complete"] == true {
				return read;
			}
			if Instant::now() >= deadline {
				let status = self.call_raw("rea_static_status", request.clone());
				panic!("static output did not complete: {read}; original status: {status}");
			}
			std::thread::sleep(Duration::from_millis(100));
		}
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

fn private_dir(path: &Path) {
	std::fs::create_dir(path).unwrap();
	std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}

fn write_private(path: &Path, bytes: &[u8]) {
	std::fs::write(path, bytes).unwrap();
	std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

fn set_private_fence(authority: &Path, root: &Path, phase: &str) {
	use std::os::fd::AsRawFd;
	let lock = std::fs::OpenOptions::new()
		.read(true)
		.write(true)
		.open(authority.join(".owner.lock"))
		.unwrap();
	assert_eq!(unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) }, 0);
	let next = authority.join(".owner-next.json");
	write_private(&next,&serde_json::to_vec(&json!({"schema":"hepta-effect-owner-fence-v1","owner":"v4","epoch":1,"phase":phase,"state_root":root.join("controller-state"),"predecessor_state_root":null})).unwrap());
	std::fs::File::open(&next).unwrap().sync_all().unwrap();
	std::fs::rename(&next, authority.join(".owner.json")).unwrap();
	std::fs::File::open(authority).unwrap().sync_all().unwrap();
}

fn compile(source: &Path, output: &Path, object: bool) {
	let mut command = Command::new("rustc");
	command
		.arg("--edition=2021")
		.arg("-Cdebuginfo=0")
		.arg("-Cpanic=abort");
	if object {
		command.args(["--crate-type=lib", "--emit=obj"]);
	} else {
		command.arg("-Cstrip=symbols");
	}
	let result = command.arg(source).arg("-o").arg(output).output().unwrap();
	assert!(
		result.status.success(),
		"owned fixture compilation failed: {}",
		String::from_utf8_lossy(&result.stderr)
	);
}

fn profile(root: &Path, backend: &Path, version: &str, operations: Value) -> Value {
	let runtime = PathBuf::from(env!("CARGO_BIN_EXE_hepta-runtime"));
	json!({"host":"local","runtime_executable":runtime,"runtime_sha256":sha(&std::fs::read(&runtime).unwrap()),
		"provider":"gnu_readelf","backend_executable":backend,"backend_sha256":sha(&std::fs::read(backend).unwrap()),
		"backend_version":version,"working_directory":root,"input_roots":[root],"allowed_operations":operations,
		"max_artifact_bytes":67108864,"max_output_bytes":65536,"timeout_seconds":45,"memory_max_bytes":536870912})
}

fn request(profiles: &Value, profile: &str, key: &str, operation: &str, artifact: &Path) -> Value {
	let admitted = profiles["profiles"]
		.as_array()
		.unwrap()
		.iter()
		.find(|p| p["profile"] == profile)
		.unwrap();
	json!({"profile":profile,"profile_sha256":admitted["profile_sha256"],"idempotency_key":key,"operation":operation,
		"artifact_path":artifact,"artifact_sha256":sha(&std::fs::read(artifact).unwrap())})
}

fn process_identity(pid: u32) -> Option<String> {
	let text = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
	let suffix = text.rsplit_once(')')?.1;
	Some(suffix.split_whitespace().nth(19)?.to_owned())
}

#[test]
#[ignore = "requires HEPTA_REA_STATIC_REAL_SSH=1, existing localhost SSH/systemd and installed GNU readelf/rustc"]
fn static_mcp_preserves_original_jobs_across_restart_and_cancels_live_owned_backend() {
	assert_eq!(
		std::env::var("HEPTA_REA_STATIC_REAL_SSH").as_deref(),
		Ok("1")
	);
	let temporary = tempfile::Builder::new()
		.prefix("hepta-static-mcp-")
		.tempdir()
		.unwrap();
	// Keep the explicitly opted-in run's private original job evidence on either
	// success or panic. A failed qualification must remain diagnosable.
	let retained = temporary.keep();
	let root = retained.as_path();
	println!("REA_STATIC_TEST_STATE {}", root.display());
	for name in ["controller-state", "jobs", "authority"] {
		private_dir(&root.join(name));
	}
	let source = root.join("owned.rs");
	std::fs::write(&source, "#[no_mangle]\npub static HEPTA_STATIC_MARKER: i32 = 17;\nextern \"C\" { fn puts(p: *const i8) -> i32; }\n#[no_mangle]\npub unsafe extern \"C\" fn hepta_static_fixture(p: *const i8) -> i32 { puts(p) + HEPTA_STATIC_MARKER }\n").unwrap();
	let artifact = root.join("owned.o");
	compile(&source, &artifact, true);
	let artifact_sha = sha(&std::fs::read(&artifact).unwrap());
	let ready = root.join("cancel-ready");
	let attempts = root.join("cancel-attempts");
	let slow_source = root.join("controlled_backend.rs");
	std::fs::write(&slow_source, format!(r#"
use std::io::Write;
fn main() {{
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("--version") {{ println!("GNU readelf (Hepta cancellation fixture) 1"); return; }}
    assert_eq!(args.get(1).map(String::as_str),Some("--file-header"));
    let pid=std::process::id();
    let stat=std::fs::read_to_string("/proc/self/stat").unwrap();
    let start=stat.rsplit_once(')').unwrap().1.split_whitespace().nth(19).unwrap();
    let mut attempts=std::fs::OpenOptions::new().create(true).append(true).open({attempts}).unwrap();
    writeln!(attempts,"{{pid}}").unwrap(); attempts.sync_all().unwrap();
    std::fs::write({ready},format!("{{pid}}:{{start}}")).unwrap();
    std::thread::sleep(std::time::Duration::from_secs(40));
    println!("ELF Header: controlled cancellation fixture");
}}
"#, attempts=serde_json::to_string(&attempts).unwrap(), ready=serde_json::to_string(&ready).unwrap())).unwrap();
	let slow_backend = root.join("controlled-backend");
	compile(&slow_source, &slow_backend, false);
	let readelf = PathBuf::from("/usr/bin/readelf");
	let version = Command::new(&readelf)
		.arg("--version")
		.env_clear()
		.env("LC_ALL", "C")
		.output()
		.unwrap();
	assert!(version.status.success() && version.stderr.is_empty());
	let version = String::from_utf8(version.stdout)
		.unwrap()
		.lines()
		.next()
		.unwrap()
		.to_owned();
	let runtime = PathBuf::from(env!("CARGO_BIN_EXE_hepta-runtime"));
	let config = json!({
		"state_dir":root.join("controller-state"),"controller_workspace_roots":[root],
		"hosts":{"local":{"ssh_target":"localhost","platform":"linux","execution_mode":"operator","remote_state_dir":root.join("jobs"),
			"allow_execute":true,"allow_write":true,"allow_job_network":true,"allow_detached_fallback":false,
			"allowed_read_path_prefixes":[root,runtime.parent().unwrap(),"/usr/bin"],"allowed_write_path_prefixes":[root]}},
		"rea_static_profiles":{
			"gnu":profile(root,&readelf,&version,json!(["headers","sections","symbols","relocations","notes"])),
			"cancellation_fixture":profile(root,&slow_backend,"GNU readelf (Hepta cancellation fixture) 1",json!(["headers"]))
		}
	});
	let config_path = root.join("config.json");
	write_private(&config_path, &serde_json::to_vec(&config).unwrap());
	let authority = root.join("authority");
	write_private(&authority.join(".owner.lock"), b"");
	set_private_fence(&authority, root, "admitting");
	let mut server = Mcp::start(&config_path, &authority);
	let catalog = server.request("tools/list", json!({}));
	let names: Vec<_> = catalog["tools"]
		.as_array()
		.unwrap()
		.iter()
		.filter_map(|t| t["name"].as_str())
		.collect();
	for name in [
		"rea_static_profiles",
		"rea_static_start",
		"rea_static_status",
		"rea_static_read",
		"rea_static_cancel",
	] {
		assert!(names.contains(&name));
	}
	assert!(!names.contains(&"shell"));
	let profiles = server.call("rea_static_profiles", json!({}));
	let header_request = request(&profiles, "gnu", "owned-headers", "headers", &artifact);
	let admitted = server.call("rea_static_start", header_request.clone());
	println!("REA_STATIC_ADMISSION {admitted}");
	assert_eq!(admitted["job"]["execution_mode"], "operator");
	assert_eq!(admitted["job"]["system_jobctl"], false);
	let original_job = admitted["job"]["id"].as_str().unwrap().to_owned();
	let replay = server.call("rea_static_start", header_request.clone());
	assert_eq!(replay["job"]["id"], original_job);
	assert_eq!(replay["reused"], true);
	let first = server.complete(&header_request);
	assert_eq!(first["process_succeeded"], true, "{first}");
	assert!(first["report"]["stdout"]
		.as_str()
		.unwrap()
		.contains("ELF Header"));
	assert!(first["report"]["summary"]["observations"]
		.as_array()
		.unwrap()
		.iter()
		.any(|fact| fact["field"] == "elf_class" && fact["value"] == "ELF64"));
	assert_eq!(first["report"]["subject"]["sha256"], artifact_sha);
	drop(server);
	let mut server = Mcp::start(&config_path, &authority);
	let recovered = server.call("rea_static_start", header_request.clone());
	assert_eq!(recovered["job"]["id"], original_job);
	assert_eq!(
		server.complete(&header_request),
		first,
		"restart must read the original complete result"
	);
	let mut changed = header_request.clone();
	changed["operation"] = json!("sections");
	assert_eq!(
		server.call_raw("rea_static_start", changed)["isError"],
		true,
		"same owner key must reject changed operation"
	);
	let mut wrong_pin = header_request.clone();
	wrong_pin["profile_sha256"] = json!("0".repeat(64));
	assert_eq!(
		server.call_raw("rea_static_start", wrong_pin)["isError"],
		true
	);
	let mut absent = header_request.clone();
	absent["idempotency_key"] = json!("never-submitted");
	assert_eq!(
		server.call_raw("rea_static_status", absent)["isError"],
		true,
		"observation must not submit a job"
	);
	let mut semantic = Vec::new();
	for (op, expected) in [
		("sections", ".text"),
		("symbols", "hepta_static_fixture"),
		("relocations", "puts"),
	] {
		let req = request(&profiles, "gnu", &format!("owned-{op}"), op, &artifact);
		let launch = server.call("rea_static_start", req.clone());
		let result = server.complete(&req);
		assert_eq!(result["process_succeeded"], true, "{result}");
		assert!(
			result["report"]["stdout"]
				.as_str()
				.unwrap()
				.contains(expected),
			"missing real {op} fact: {result}"
		);
		semantic.push(json!({"operation":op,"job_id":launch["job"]["id"],"expected_fact":expected,"report_id":result["report"]["native_report_id"]}));
	}
	let live_request = request(
		&profiles,
		"cancellation_fixture",
		"controlled-live-cancel",
		"headers",
		&artifact,
	);
	let live = server.call("rea_static_start", live_request.clone());
	let ready_deadline = Instant::now() + Duration::from_secs(15);
	while !ready.exists() {
		assert!(
			Instant::now() < ready_deadline,
			"controlled backend did not enter its live operation"
		);
		std::thread::sleep(Duration::from_millis(50));
	}
	let marker = std::fs::read_to_string(&ready).unwrap();
	let (pid, start) = marker.split_once(':').unwrap();
	let pid: u32 = pid.parse().unwrap();
	assert_eq!(process_identity(pid).as_deref(), Some(start));
	drop(server);
	let mut server = Mcp::start(&config_path, &authority);
	let live_recovered = server.call("rea_static_start", live_request.clone());
	assert_eq!(live_recovered["job"]["id"], live["job"]["id"]);
	assert_eq!(
		std::fs::read_to_string(&attempts).unwrap().lines().count(),
		1,
		"recovery restarted the backend"
	);
	set_private_fence(&authority, root, "frozen");
	assert_eq!(
		server.complete(&header_request),
		first,
		"frozen admission must preserve completed observation"
	);
	let frozen_live = server.call("rea_static_status", live_request.clone());
	assert_eq!(frozen_live["job"]["id"], live["job"]["id"]);
	assert_eq!(
		server.call_raw("rea_static_start", live_request.clone())["isError"],
		true,
		"frozen starts must use observation explicitly"
	);
	let mut frozen_new = header_request.clone();
	frozen_new["idempotency_key"] = json!("frozen-never-submitted");
	assert_eq!(
		server.call_raw("rea_static_start", frozen_new.clone())["isError"],
		true
	);
	assert_eq!(
		server.call_raw("rea_static_status", frozen_new)["isError"],
		true,
		"frozen denial must not allocate a binding"
	);
	let cancel = server.call("rea_static_cancel", live_request.clone());
	assert_eq!(cancel["cancellation_requested"], true);
	assert_eq!(cancel["termination_confirmed"], false);
	let terminated = server.complete(&live_request);
	assert_eq!(terminated["process_succeeded"], false);
	let terminal = server.call("rea_static_status", live_request.clone());
	assert!(
		matches!(
			terminal["status"]["state"].as_str(),
			Some("cancelled" | "failed")
		),
		"{terminal}"
	);
	let reap_deadline = Instant::now() + Duration::from_secs(10);
	while process_identity(pid).as_deref() == Some(start) {
		assert!(
			Instant::now() < reap_deadline,
			"original controlled backend process survived cancellation"
		);
		std::thread::sleep(Duration::from_millis(50));
	}
	set_private_fence(&authority, root, "admitting");
	let after = server.call("rea_static_start", live_request);
	assert_eq!(after["job"]["id"], live["job"]["id"]);
	assert_eq!(
		std::fs::read_to_string(&attempts).unwrap().lines().count(),
		1
	);
	assert_eq!(
		sha(&std::fs::read(&artifact).unwrap()),
		artifact_sha,
		"source build artifact changed"
	);
	println!(
		"REA_STATIC_MCP_QUALIFICATION {}",
		json!({
			"schema":"hepta.rea.static-mcp-qualification.v1","runtime_sha256":config["rea_static_profiles"]["gnu"]["runtime_sha256"],
			"execution_mode":"operator","isolated_system_jobctl_qualified":false,"retained_state":root,
			"backend_sha256":config["rea_static_profiles"]["gnu"]["backend_sha256"],"backend_version":version,
			"artifact_sha256":artifact_sha,"artifact_execution_count":0,"original_job_id":original_job,"restart_job_id":recovered["job"]["id"],
			"semantic_checks":semantic,"controlled_cancel_job":live["job"]["id"],"controlled_cancel_recovered_job":live_recovered["job"]["id"],
			"controlled_backend_attempts":1,"controlled_backend_original_process_gone":true,
			"cancellation_backend_scope":"independently compiled pinned synthetic lifecycle fixture; not GNU parity",
			"terminal_state":terminal["status"]["state"],"rea_full_parity":false,
			"checks":["actual_gnu_header_sections_symbols_relocations","controller_restart_original_result","same_key_no_relaunch","changed_operation_rejected","profile_rebinding_rejected","observation_no_submit","live_controller_restart","frozen_admission_blocks_new_start","frozen_original_result_and_status_readable","frozen_original_job_cancel","stored_original_job_cancel","source_bytes_unchanged"]
		})
	);
}
