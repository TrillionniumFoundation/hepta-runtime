// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Exercise the real non-test binary's canonical descriptor parser entry.

use anyhow::{bail, Result};
use serde_json::{json, Value};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[test]
fn canonical_parser_accepts_readonly_fd_under_stricter_inherited_limits() -> Result<()> {
	let root = std::env::temp_dir().join(format!("hepta-lifecycle-parser-{}", std::process::id()));
	std::fs::create_dir(&root)?;
	let result = (|| -> Result<()> {
		let path = root.join("source.safetensors");
		let header = serde_json::to_vec(&json!({"x":{
			"dtype":"F64","shape":[1],"data_offsets":[0,8]}}))?;
		let mut output = OpenOptions::new()
			.write(true)
			.create_new(true)
			.mode(0o600)
			.open(&path)?;
		output.write_all(&(header.len() as u64).to_le_bytes())?;
		output.write_all(&header)?;
		output.write_all(&1.0_f64.to_le_bytes())?;
		drop(output);
		let mut command = Command::new(env!("CARGO_BIN_EXE_hepta-weight-lifecycle-study"));
		command
			.arg("rea-model-worker")
			.arg("--request")
			.arg(r#"{"operation":"read","tensor_name":"x","offset":0,"length":1}"#)
			.env_clear()
			.current_dir("/")
			.stdin(Stdio::from(File::open(path)?))
			.stdout(Stdio::piped())
			.stderr(Stdio::piped());
		unsafe {
			command.pre_exec(|| {
				for (resource, limit) in
					[(libc::RLIMIT_CPU, 1), (libc::RLIMIT_AS, 256 * 1024 * 1024)]
				{
					let value = libc::rlimit {
						rlim_cur: limit,
						rlim_max: limit,
					};
					if libc::setrlimit(resource, &value) != 0 {
						return Err(std::io::Error::last_os_error());
					}
				}
				Ok(())
			});
		}
		let mut child = command.spawn()?;
		let deadline = Instant::now() + Duration::from_secs(5);
		while child.try_wait()?.is_none() {
			if Instant::now() >= deadline {
				child.kill()?;
				child.wait()?;
				bail!("canonical parser integration exceeded its five-second deadline");
			}
			std::thread::sleep(Duration::from_millis(5));
		}
		let output = child.wait_with_output()?;
		if !output.status.success() {
			bail!(
				"canonical parser failed: {}",
				String::from_utf8_lossy(&output.stderr)
			);
		}
		let report: Value = serde_json::from_slice(&output.stdout)?;
		assert_eq!(report["format"], "safetensors");
		assert_eq!(report["result"]["tensor"]["name"], "x");
		assert_eq!(report["result"]["tensor"]["dtype"], "F64");
		assert_eq!(report["result"]["length"], 1);
		assert_eq!(report["result"]["bytes_hex"], "00");
		Ok(())
	})();
	std::fs::remove_dir_all(root)?;
	result
}
