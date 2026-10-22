// Copyright 2026 Muvon Un Limited
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

//! Negative and concurrency regressions for bounded SSH subprocess capture.

use super::*;
use tokio::io::AsyncWriteExt;

#[tokio::test]
async fn stream_accepts_exact_byte_budget() -> Result<()> {
	let (mut sender, receiver) = tokio::io::duplex(16);
	let producer = tokio::spawn(async move { sender.write_all(b"abcd").await });
	let output = read_limited(receiver, 4).await?;
	producer.await??;
	assert_eq!(output, b"abcd");
	Ok(())
}

#[tokio::test]
async fn stream_rejects_first_byte_beyond_budget() -> Result<()> {
	let (mut sender, receiver) = tokio::io::duplex(16);
	let producer = tokio::spawn(async move { sender.write_all(b"abcdef").await });
	let refused = read_limited(receiver, 5).await;
	producer.await??;
	assert!(refused.is_err());
	Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn capture_drains_stdout_before_stdin_is_consumed() -> Result<()> {
	// The child fills stdout first, then consumes a large stdin. Writing stdin
	// to completion before draining stdout hangs on ordinary pipe capacities.
	let mut command = Command::new("sh");
	command.arg("-c").arg(
		"dd if=/dev/zero bs=8192 count=32 2>/dev/null; cat >/dev/null; printf done >&2",
	);
	let input = vec![b'x'; 1024 * 1024];
	let output = capture_command(command, &input, Duration::from_secs(10), "local").await?;
	assert!(output.status.success());
	assert_eq!(output.stdout.len(), 32 * 8192);
	assert_eq!(output.stderr, b"done");
	Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn capture_rejects_over_limit_child_output() -> Result<()> {
	let mut command = Command::new("sh");
	command
		.arg("-c")
		.arg("dd if=/dev/zero bs=8192 count=1025 2>/dev/null");
	let error = capture_command(command, b"", Duration::from_secs(10), "local")
		.await
		.expect_err("8 MiB + 8192 bytes must be rejected");
	assert!(error.to_string().contains("8 MiB"));
	Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn capture_timeout_terminates_child() -> Result<()> {
	let mut command = Command::new("sh");
	command.arg("-c").arg("exec sleep 5");
	let error = capture_command(command, b"", Duration::from_millis(100), "local")
		.await
		.expect_err("sleep must exceed the execution deadline");
	assert!(error.to_string().contains("timed out"));
	Ok(())
}
