// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Original isolated-owner group custody and scratch recovery on owned fixtures.

use super::engine_owner::directory as engine_directory;
use super::*;
use std::os::unix::process::CommandExt;

// Compile the real worker consumer into this producer contract test. Its async
// entry is unused here. Linux adoption fixtures use the production nonce issuer.
#[allow(dead_code)]
#[path = "mcp/rea_engine_scratch.rs"]
mod worker_scratch;

#[cfg(target_os = "linux")]
fn engine_record(nonce: String) -> Record {
	Record {
		job_id: "owned-job".into(),
		unit: "hepta-job-owned-job.service".into(),
		request_digest: "fixture".into(),
		boot_id: "original-boot".into(),
		nonce,
		invocation_id: Some("original-invocation".into()),
		launch_state: "launched".into(),
		created_unix_ms: 1,
		terminal_protocol: Some(TerminalProtocol::CapturedV1),
	}
}

#[cfg(target_os = "linux")]
#[test]
fn production_nonce_is_accepted_by_the_real_worker_and_terminal_projection() {
	let temp = tempfile::tempdir().unwrap();
	let record = engine_record(launch_nonce().unwrap());
	let owner =
		engine_owner::ScratchOwner::prepare(temp.path(), &record.job_id, &record.nonce).unwrap();
	let work = worker_scratch::create(
		temp.path(),
		"ghidra",
		Some(owner.binding.to_string()),
		Some(record.job_id.clone()),
	)
	.unwrap();
	assert_eq!(work.cleanup_owner(), "durable_job");
	assert!(work.is_dir());
	let claim: Value = json_file(&temp.path().join("engine-scratch/claim.json")).unwrap();
	assert_eq!(claim["owner"]["launch_nonce"], record.nonce);
	assert_eq!(record.nonce.len(), 32);
	let mut command = Command::new("/bin/true");
	let (child, capture) = spawn_supervised(&mut command, temp.path(), false).unwrap();
	let outcome = finish_supervision(child, capture, Duration::from_secs(3), || false).unwrap();
	let receipt = Exit::new(
		&record.job_id,
		record.nonce.clone(),
		0,
		false,
		false,
		TerminalProtocol::CapturedV1,
		outcome.capture,
	);
	publish_terminal(temp.path(), &receipt).unwrap();
	let projected = completion_at(&record, temp.path()).unwrap().unwrap();
	assert_eq!(projected["launch_nonce"], record.nonce);
	assert_eq!(projected["terminal_publication_confirmed"], true);
	assert_eq!(projected["output_durable"], true);
}

#[cfg(target_os = "linux")]
#[test]
fn restricted_group_visibility_preserves_unknown_and_readable_retention() {
	let temp = tempfile::tempdir().unwrap();
	let mut record = engine_record(launch_nonce().unwrap());
	let owner =
		engine_owner::ScratchOwner::prepare(temp.path(), &record.job_id, &record.nonce).unwrap();
	let sentinel = temp.path().join("engine-scratch/owned-data");
	fs::write(&sentinel, b"retained").unwrap();
	let mut command = Command::new("/bin/true");
	command.process_group(0);
	let (child, capture) = spawn_supervised(&mut command, temp.path(), false).unwrap();
	let failure = finish_supervision_with_group_stop(
		child,
		capture,
		Duration::from_secs(3),
		|| false,
		true,
		|_| {
			engine_owner::confirm_group_visibility("31 25 0:27 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw,hidepid=invisible\n")
		},
	);
	assert!(retain_engine_supervision_failure(temp.path(), &owner, failure).is_err());
	assert!(!temp.path().join("exit.json").exists());
	let retained_before = fs::read(temp.path().join("engine-scratch.retained.json")).unwrap();
	let status = status_at(
		&mut record,
		temp.path(),
		|| Ok("original-boot".into()),
		|_| Ok((BTreeMap::new(), false)),
	)
	.unwrap();
	assert_eq!(status["outcome"], "unknown");
	assert_eq!(status["status_authoritative"], false);
	assert_eq!(status["terminal_publication_confirmed"], false);
	assert_eq!(
		status["scratch_cleanup_publication"],
		"retained_without_terminal"
	);
	assert_eq!(status["scratch_cleanup"]["state"], "retained");
	assert_eq!(status["scratch_cleanup"]["removed"], false);
	assert_eq!(
		status["scratch_cleanup"]["original_process_group_stopped"],
		false
	);
	assert!(status["scratch_cleanup"]["error"]
		.as_str()
		.unwrap()
		.contains("visibility is restricted"));
	let read = read_output_at(&record, temp.path(), 0, 0, 16384).unwrap();
	assert_eq!(read["scratch_cleanup"], status["scratch_cleanup"]);
	assert_ne!(read["output_complete"], true);
	assert_eq!(fs::read(&sentinel).unwrap(), b"retained");
	assert_eq!(
		fs::read(temp.path().join("engine-scratch.retained.json")).unwrap(),
		retained_before
	);
	let mut false_positive = status["scratch_cleanup"].clone();
	false_positive["removed"] = json!(true);
	atomic(
		&temp.path().join("engine-scratch.retained.json"),
		&false_positive,
	)
	.unwrap();
	assert!(retained_engine_scratch_at(&record, temp.path()).is_err());
	assert!(sentinel.exists());
}

#[cfg(target_os = "linux")]
#[test]
fn engine_scratch_owner_stops_original_group_before_reap_and_publishes_cleanup() {
	let temp = tempfile::tempdir().unwrap();
	let owner =
		engine_owner::ScratchOwner::prepare(temp.path(), "owned-job", &launch_nonce().unwrap())
			.unwrap();
	let script = r#"import json,os,pathlib,subprocess,sys,time
owner=json.loads(sys.argv[1]); root=pathlib.Path(owner['path'])
(root/'claim.json').write_text(json.dumps({'schema':'hepta.rea.engine-scratch-claim.v1','owner':owner,'worker_pid':os.getpid(),'engine':'ghidra'}))
(root/'claim.json').chmod(0o600)
child=subprocess.Popen(['/bin/sleep','5'],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
(root/'ready').write_text(str(child.pid))
time.sleep(5)
"#;
	let mut command = Command::new("/usr/bin/python3");
	command
		.args(["-c", script, &owner.binding.to_string()])
		.process_group(0);
	let (child, capture) = spawn_supervised(&mut command, temp.path(), false).unwrap();
	let pid = child.child.id();
	let ready = temp.path().join("engine-scratch/ready");
	let until = Instant::now() + Duration::from_secs(3);
	while !ready.exists() && Instant::now() < until {
		std::thread::sleep(Duration::from_millis(10));
	}
	assert!(ready.exists());
	let outcome = finish_supervision_with_engine_group(
		child,
		capture,
		Duration::from_secs(10),
		|| true,
		true,
	)
	.unwrap();
	assert!(outcome.cancelled && outcome.engine_group_stopped);
	assert_eq!(outcome.status.signal(), Some(libc::SIGKILL));
	let receipt = owner.finish(pid, outcome.engine_group_stopped);
	assert_eq!(receipt["state"], "removed");
	assert_eq!(receipt["worker_adopted"], true);
	assert_eq!(receipt["durable"], true);
	assert!(!temp.path().join("engine-scratch").exists());
}

#[cfg(target_os = "linux")]
#[test]
fn engine_scratch_lost_child_custody_never_authorizes_numeric_group_cleanup() {
	let temp = tempfile::tempdir().unwrap();
	let owner =
		engine_owner::ScratchOwner::prepare(temp.path(), "owned-job", &launch_nonce().unwrap())
			.unwrap();
	let mut child = Command::new("/bin/true").process_group(0).spawn().unwrap();
	let pid = child.id();
	child.wait().unwrap();
	assert!(engine_owner::stop_original_group(pid).is_err());
	let receipt = owner.finish(pid, false);
	assert_eq!(receipt["state"], "retained");
	assert_eq!(receipt["removed"], false);
	assert!(temp.path().join("engine-scratch").exists());
}

#[cfg(not(target_os = "linux"))]
#[test]
fn unsupported_engine_launch_refuses_before_state_changes_or_group_signals() {
	let temp = tempfile::tempdir().unwrap();
	let state = fs::canonicalize(temp.path()).unwrap();
	let sentinel = state.join("sentinel");
	fs::write(&sentinel, b"original state").unwrap();
	let expected = "Isolated job launch requires Linux";
	assert_eq!(launch_nonce().unwrap_err().to_string(), expected);
	for interactive in [false, true] {
		let request: Request = serde_json::from_value(json!({
			"op":"start", "job_id":"unsupported-job", "executable":"/bin/true",
			"cwd":state,
		}))
		.unwrap();
		assert_eq!(
			start(request, interactive).unwrap_err().to_string(),
			expected
		);
		assert_eq!(
			supervise("unsupported-job", interactive)
				.unwrap_err()
				.to_string(),
			expected
		);
	}
	assert_eq!(
		engine_owner::ScratchOwner::prepare(&state, "unsupported-job", "unissued")
			.err()
			.unwrap()
			.to_string(),
		"Static engine scratch lifecycle requires Linux"
	);
	let mut child = Command::new("/bin/sleep")
		.arg("5")
		.process_group(0)
		.spawn()
		.unwrap();
	let refusal = engine_owner::stop_original_group(child.id());
	let observed = child.try_wait();
	let _ = child.kill();
	let reaped = child.wait();
	assert_eq!(
		refusal.unwrap_err().to_string(),
		"Static engine scratch lifecycle requires Linux"
	);
	assert!(observed.unwrap().is_none());
	reaped.unwrap();
	assert_eq!(fs::read_dir(&state).unwrap().count(), 1);
	assert_eq!(fs::read(sentinel).unwrap(), b"original state");
}
