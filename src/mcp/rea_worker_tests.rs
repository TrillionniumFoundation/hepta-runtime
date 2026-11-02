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

//! Adversarial child stdout/stderr capture tests; these run real subprocesses.

use super::*;

#[tokio::test]
async fn capped_reader_never_buffers_more_than_one_extra_byte() {
	let error = read_capped(tokio::io::repeat(b'X'), 1024, "stdout")
		.await
		.expect_err("continuous output must be rejected");
	assert!(error.to_string().contains("stdout exceeds 1024 byte limit"));
	let empty = read_capped(tokio::io::empty(), 8, "stderr")
		.await
		.expect("empty stream");
	assert!(empty.is_empty());
}

#[cfg(unix)]
#[tokio::test]
async fn real_child_stdout_and_stderr_are_collected_without_wait_with_output() {
	let mut child = Command::new("sh");
	child
		.arg("-c")
		.arg("printf ok; printf warning >&2")
		.stdin(Stdio::piped())
		.stdout(Stdio::piped())
		.stderr(Stdio::piped())
		.kill_on_drop(true);
	let mut child = child.spawn().expect("launch test child");
	let (stdout, stderr, status) = collect_child_output(&mut child, Vec::new())
		.await
		.expect("capture child");
	assert!(status.success());
	assert_eq!(stdout, b"ok");
	assert_eq!(stderr, b"warning");
}

#[cfg(unix)]
#[tokio::test]
async fn real_child_endless_stderr_is_killed_and_reaped_at_limit() {
	let mut child = Command::new("sh");
	child
		.arg("-c")
		.arg("while :; do printf '12345678901234567890123456789012' >&2; done")
		.stdin(Stdio::piped())
		.stdout(Stdio::piped())
		.stderr(Stdio::piped())
		.kill_on_drop(true);
	let mut child = child.spawn().expect("launch noisy child");
	let result = tokio::time::timeout(
		Duration::from_secs(5),
		collect_child_output(&mut child, Vec::new()),
	)
	.await
	.expect("bounded capture must finish before deadline");
	let error = result.expect_err("noisy stderr must fail");
	assert!(
		error
			.to_string()
			.contains("stderr exceeds 65536 byte limit"),
		"{error}"
	);
	assert!(child.try_wait().expect("poll reaped child").is_some());
}

#[cfg(unix)]
#[tokio::test]
async fn real_child_endless_stdout_is_killed_and_reaped_at_limit() {
	let mut child = Command::new("sh");
	child
		.arg("-c")
		.arg("while :; do printf '12345678901234567890123456789012'; done")
		.stdin(Stdio::piped())
		.stdout(Stdio::piped())
		.stderr(Stdio::piped())
		.kill_on_drop(true);
	let mut child = child.spawn().expect("launch noisy child");
	let result = tokio::time::timeout(
		Duration::from_secs(5),
		collect_child_output(&mut child, Vec::new()),
	)
	.await
	.expect("bounded capture must finish before deadline");
	let error = result.expect_err("noisy stdout must fail");
	assert!(
		error
			.to_string()
			.contains("stdout exceeds 262144 byte limit"),
		"{error}"
	);
	assert!(child.try_wait().expect("poll reaped child").is_some());
}

#[test]
fn controller_authenticates_worker_preview_against_captured_bytes_and_path() {
	let captured = b"\0asm\x01\0\0\0";
	let selected = "/admitted/original.wasm";
	let identity: [u8; 32] = Sha256::digest(captured).into();
	let report =
		crate::mcp::rea::inspect_bytes(captured, selected).expect("native preview reference");
	verify_worker_report(&report, &identity, captured.len(), selected)
		.expect("valid report binds exact admitted bytes");

	let mut substituted = report.clone();
	substituted["subject"]["local_path"] = serde_json::json!("/different/path");
	assert!(verify_worker_report(&substituted, &identity, captured.len(), selected).is_err());

	let mut forged_digest = report.clone();
	forged_digest["subject"]["sha256"] = serde_json::json!("0".repeat(64));
	assert!(verify_worker_report(&forged_digest, &identity, captured.len(), selected).is_err());

	let mut modified = report.clone();
	modified["normalized_result"]["header_facts"]["binary_version"] = serde_json::json!(999);
	assert!(verify_worker_report(&modified, &identity, captured.len(), selected).is_err());

	let mut injected = report.clone();
	injected["unexpected"] = serde_json::json!("untrusted");
	assert!(verify_worker_report(&injected, &identity, captured.len(), selected).is_err());

	let alternate: [u8; 32] = Sha256::digest(b"other bytes").into();
	assert!(verify_worker_report(&report, &alternate, captured.len(), selected).is_err());
	assert!(verify_worker_report(&report, &identity, captured.len() + 1, selected).is_err());
}
