// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0

use super::*;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};

fn run_fake_sudo(script: &str, timeout_seconds: f64) -> Value {
	let dir = tempfile::tempdir().unwrap();
	let sudo = dir.path().join("sudo");
	std::fs::write(&sudo, script).unwrap();
	let mut permissions = std::fs::metadata(&sudo).unwrap().permissions();
	permissions.set_mode(0o700);
	std::fs::set_permissions(&sudo, permissions).unwrap();

	let old_path = std::env::var("PATH").unwrap_or_default();
	let path = format!("{}:{old_path}", dir.path().display());
	let mut child = Command::new("python3")
		.arg("-c")
		.arg(PRIVILEGED_CODE)
		.env("PATH", path)
		.stdin(Stdio::piped())
		.stdout(Stdio::piped())
		.stderr(Stdio::piped())
		.spawn()
		.unwrap();
	let input = json!({"executable": "/bin/true", "timeout_seconds": timeout_seconds});
	child
		.stdin
		.take()
		.unwrap()
		.write_all(input.to_string().as_bytes())
		.unwrap();
	let output = child.wait_with_output().unwrap();
	assert!(
		output.status.success(),
		"Python privileged action failed: {}",
		String::from_utf8_lossy(&output.stderr)
	);
	serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn privileged_timeout_with_stdout_is_json_serializable() {
	let output = run_fake_sudo("#!/bin/sh\nprintf 'started\\n'\nexec sleep 4\n", 1.0);
	assert_eq!(output["exit_code"], 124);
	assert_eq!(output["stdout"], "started\n");
}

#[test]
fn privileged_non_utf8_output_is_json_serializable() {
	let output = run_fake_sudo("#!/bin/sh\nprintf '\\377'\n", 1.0);
	assert_eq!(output["exit_code"], 0);
	assert_eq!(output["stdout"], "\u{fffd}");
}
