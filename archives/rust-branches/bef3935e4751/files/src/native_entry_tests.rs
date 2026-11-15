// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Real owner/idempotency path with an isolated SSH peer fixture. The entry
//! guards record ordering only; production grant validation belongs to the host.

use super::*;
use crate::mcp::runtime::config::{init_runtime, RuntimeConfig};
use serde_json::{json, Value};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

const CHILD_ROOT: &str = "HEPTA_TEST_NATIVE_ENTRY_ROOT";

struct Guard(PathBuf);
impl Guard {
	fn new(path: PathBuf) -> Result<Self> {
		std::fs::write(&path, b"entry-live")?;
		Ok(Self(path))
	}
}
impl Drop for Guard {
	fn drop(&mut self) {
		let _ = std::fs::remove_file(&self.0);
	}
}

fn request(key: &str) -> ProcessStartParams {
	serde_json::from_value(
		json!({"host":"fixture", "executable":"/usr/bin/true", "idempotency_key":key}),
	)
	.unwrap()
}

async fn child(root: &Path) -> Result<()> {
	let config: RuntimeConfig = serde_json::from_value(json!({
		"state_dir":root.join("state"),"hosts":{"fixture":{
			"ssh_target":"isolated-test-peer","remote_state_dir":"/tmp/native-entry-fixture",
			"platform":"linux","execution_mode":"isolated","allow_execute":true
		}}
	}))?;
	init_runtime(config)?;
	let trace = root.join("ssh-trace.jsonl");
	let params = request("original-denied-operation");
	let exact = serde_json::to_vec(&params)?;
	let entered = AtomicUsize::new(0);
	let denied: Value = serde_json::from_str(
		&execute_or_observe_with_entry(params.clone(), |actual| -> Result<()> {
			entered.fetch_add(1, Ordering::SeqCst);
			assert_eq!(serde_json::to_vec(actual).unwrap(), exact);
			bail!("host revoked the original grant after durable preparation")
		})
		.await?,
	)?;
	assert_eq!(entered.load(Ordering::SeqCst), 1);
	assert!(!tokio::fs::try_exists(&trace).await?);
	assert_eq!(denied["job"]["launch_state"], "launch_unknown");
	let original_job = denied["job"]["id"].as_str().unwrap().to_string();
	let observed: Value = serde_json::from_str(
		&execute_or_observe_with_entry(params, |_| -> Result<()> {
			bail!("an existing uncertain job must never consume another entry")
		})
		.await?,
	)?;
	assert_eq!(observed["job"]["id"], original_job);
	assert_eq!(observed["reused"], true);
	assert_eq!(observed["retried_launch"], false);
	// Abrupt cancellation after the real durable record but before SSH leaves
	// an isolated/jobctl `pending` record. The compatibility API can reconcile
	// such a record by launching; this checked native API must only observe it.
	let stopped = tokio::spawn(async {
		execute_or_observe_with_entry(request("original-pending-operation"), |_| -> Result<()> {
			panic!("fixture stop after durable preparation and before physical spawn")
		})
		.await
	});
	assert!(stopped.await.unwrap_err().is_panic());
	let mut records = tokio::fs::read_dir(root.join("state/jobs")).await?;
	let mut pending_id = None;
	while let Some(record) = records.next_entry().await? {
		if record
			.path()
			.extension()
			.is_some_and(|extension| extension == "json")
		{
			let value: Value = serde_json::from_slice(&tokio::fs::read(record.path()).await?)?;
			if value["idempotency_key"] == "original-pending-operation" {
				assert_eq!(value["launch_state"], "pending");
				assert_eq!(value["system_jobctl"], true);
				pending_id = value["id"].as_str().map(str::to_string);
			}
		}
	}
	let pending_id = pending_id.unwrap();
	let pending: Value = serde_json::from_str(
		&execute_or_observe_with_entry(request("original-pending-operation"), |_| -> Result<()> {
			bail!("an inherited pending job must not reenter physical dispatch")
		})
		.await?,
	)?;
	assert_eq!(pending["job"]["id"], pending_id);
	assert_eq!(pending["retried_launch"], false);
	let guard_path = root.join("guard-live");
	let started: Value = serde_json::from_str(
		&execute_or_observe_with_entry(request("original-allowed-operation"), |_| {
			Guard::new(guard_path.clone())
		})
		.await?,
	)?;
	assert_eq!(started["job"]["launch_state"], "launched");
	assert!(!tokio::fs::try_exists(&guard_path).await?);
	let events = tokio::fs::read_to_string(&trace).await?;
	let events: Vec<Value> = events
		.lines()
		.map(serde_json::from_str)
		.collect::<serde_json::Result<_>>()?;
	assert_eq!(events.len(), 3);
	assert_eq!(events[0]["kind"], "observation");
	assert_eq!(events[0]["job_id"], original_job);
	assert_eq!(events[1]["kind"], "observation");
	assert_eq!(events[1]["job_id"], pending_id);
	assert_eq!(events[2]["kind"], "launch");
	assert_eq!(events[2]["job_id"], started["job"]["id"]);
	assert_eq!(events[2]["guard_live"], true);
	let original = request("original-allowed-operation");
	let terminal = observe_terminal_output(&original, 4096).await?.unwrap();
	assert!(terminal.matches_request(&original)?);
	assert_eq!(terminal.job_id(), started["job"]["id"].as_str().unwrap());
	assert_eq!(terminal.outcome(), NativeJobOutcome::Succeeded);
	assert_eq!(terminal.exit_code(), 0);
	let (stdout, stderr) = terminal.into_streams();
	assert_eq!(stdout, b"native");
	assert!(stderr.is_empty());
	let mut substituted = original.clone();
	substituted.args.push("changed".to_string());
	assert!(observe_terminal_output(&substituted, 4096).await.is_err());
	tokio::fs::write(root.join("incomplete-output"), b"1").await?;
	assert!(observe_terminal_output(&original, 4096).await.is_err());
	tokio::fs::remove_file(root.join("incomplete-output")).await?;
	tokio::fs::write(root.join("change-after-read"), b"1").await?;
	assert!(observe_terminal_output(&original, 4096).await.is_err());
	let events = tokio::fs::read_to_string(&trace).await?;
	let events = events
		.lines()
		.map(serde_json::from_str::<Value>)
		.collect::<serde_json::Result<Vec<_>>>()?;
	assert_eq!(
		events
			.iter()
			.filter(|event| event["kind"] == "launch")
			.count(),
		1
	);
	Ok(())
}

#[tokio::test]
async fn checked_native_entry_retains_original_job_and_never_relaunches() {
	if let Some(root) = std::env::var_os(CHILD_ROOT) {
		child(Path::new(&root)).await.unwrap();
		return;
	}
	let temp = tempfile::tempdir().unwrap();
	let root = tokio::fs::canonicalize(temp.path()).await.unwrap();
	for name in ["bin", "state", "authority"] {
		let path = root.join(name);
		tokio::fs::create_dir(&path).await.unwrap();
		tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
			.await
			.unwrap();
	}
	let fence = root.join("authority");
	for (name, bytes) in [
		(".owner.lock", Vec::new()),
		(".owner.json", serde_json::to_vec(&json!({"schema":"hepta-effect-owner-fence-v1","owner":"v4","epoch":1,"phase":"admitting","state_root":root.join("state"),"predecessor_state_root":null})).unwrap()),
	] {
		let path = fence.join(name);
		tokio::fs::write(&path, bytes).await.unwrap();
		tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).await.unwrap();
	}
	let ssh = root.join("bin/ssh");
	tokio::fs::write(&ssh, r#"#!/usr/bin/env python3
import json, os, pathlib, sys
request = json.load(sys.stdin)
root = pathlib.Path(os.environ['HEPTA_TEST_NATIVE_ENTRY_ROOT'])
launch = 'executable' in request
guard = (root / 'guard-live').exists()
event = {'kind': 'launch' if launch else 'observation', 'job_id': request['job_id'], 'guard_live': guard}
with (root / 'ssh-trace.jsonl').open('a') as stream:
    stream.write(json.dumps(event) + '\n')
if launch:
    if not guard:
        raise SystemExit('entry guard was not retained at actual SSH peer')
    (root / 'launched-job').write_text(request['job_id'])
    print(json.dumps({'ok': True, 'backend': 'systemd_system', 'status': {'job_id': request['job_id']}}))
elif (root / 'launched-job').exists() and (root / 'launched-job').read_text() == request['job_id']:
    if request.get('op') == 'read':
        def page(name, data):
            offset = request.get(name + '_offset', 0)
            out = data[offset:offset + request['limit']]
            return {'offset': offset, 'next_offset': offset + len(out), 'size': len(data), 'eof': offset + len(out) == len(data), 'bytes_hex': out.hex()}
        print(json.dumps({'job_id': request['job_id'], 'stdout': page('stdout', b'native'), 'stderr': page('stderr', b'')}))
        if (root / 'change-after-read').exists():
            (root / 'changed-nonce').write_text('1')
    else:
        print(json.dumps({'job_id': request['job_id'], 'state': 'succeeded', 'status_authoritative': True,
            'terminal_publication_protocol': 1, 'terminal_publication_confirmed': True,
            'output_complete': not (root / 'incomplete-output').exists(), 'output_durable': True,
            'launch_nonce': ('b' if (root / 'changed-nonce').exists() else 'a') * 32,
            'at_unix_ms': 123, 'exit_code': 0, 'timed_out': False, 'cancelled': False,
            'log_bytes': {'stdout': {'stored': 6, 'seen': 6}, 'stderr': {'stored': 0, 'seen': 0}},
            'log_truncated': {'stdout': False, 'stderr': False}, 'log_errors': {'stdout': None, 'stderr': None},
            'log_synced': {'stdout': True, 'stderr': True}}))
else:
    print(json.dumps({'job_id': request['job_id'], 'state': 'launch_unknown', 'status_authoritative': False, 'automatic_retry': False}))
"#).await.unwrap();
	tokio::fs::set_permissions(&ssh, std::fs::Permissions::from_mode(0o700))
		.await
		.unwrap();
	let mut paths = vec![root.join("bin")];
	paths.extend(std::env::split_paths(
		&std::env::var_os("PATH").unwrap_or_default(),
	));
	let output = tokio::process::Command::new(std::env::current_exe().unwrap())
		.arg("--exact")
		.arg("native::entry_tests::checked_native_entry_retains_original_job_and_never_relaunches")
		.arg("--nocapture")
		.env(CHILD_ROOT, &root)
		.env("PATH", std::env::join_paths(paths).unwrap())
		.env("HEPTA_EFFECT_OWNER_FENCE_DIR", &fence)
		.env("HEPTA_EFFECT_OWNER_SELF", "v4")
		.env("HEPTA_EFFECT_OWNER_FENCE_REQUIRED", "1")
		.output()
		.await
		.unwrap();
	assert!(
		output.status.success(),
		"isolated native entry fixture failed:\n{}\n{}",
		String::from_utf8_lossy(&output.stdout),
		String::from_utf8_lossy(&output.stderr)
	);
}
