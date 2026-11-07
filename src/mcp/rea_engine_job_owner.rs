// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Static-engine scratch for the existing isolated job supervisor, never a new owner.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::fs::File;
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::{Duration, Instant};

#[path = "rea_engine_directory.rs"]
pub(crate) mod directory;
use directory::Directory;

pub(crate) fn selected(args: &[String], input: Option<&str>) -> bool {
	if args != ["rea-static-worker"] {
		return false;
	}
	let Some(value) = input.and_then(|text| serde_json::from_str::<Value>(text).ok()) else {
		return false;
	};
	value["schema"] == "hepta.rea.static-request.v1"
		&& matches!(
			value["profile"]["provider"].as_str(),
			Some("jadx" | "ghidra")
		)
}

pub(crate) struct ScratchOwner {
	directory: Directory,
	pub(crate) binding: Value,
}

impl ScratchOwner {
	pub(crate) fn prepare(state: &Path, job_id: &str, nonce: &str) -> Result<Self> {
		let directory = Directory::create(state, "engine-scratch")?;
		let (device, inode) = directory.identity();
		let binding = json!({
			"schema":"hepta.rea.engine-scratch-owner.v1", "job_id":job_id,
			"launch_nonce":nonce, "path":directory.path, "device":device, "inode":inode
		});
		Ok(Self { directory, binding })
	}

	fn claim(&self, pid: u32) -> Result<bool> {
		let fd = unsafe {
			libc::openat(
				self.directory.file.as_raw_fd(),
				c"claim.json".as_ptr(),
				libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
			)
		};
		if fd < 0 {
			return Err(std::io::Error::last_os_error()).context("worker claim unavailable");
		}
		let file = unsafe { File::from_raw_fd(fd) };
		let info = file.metadata()?;
		if !info.is_file()
			|| info.nlink() != 1
			|| info.uid() != unsafe { libc::geteuid() }
			|| info.mode() & 0o777 != 0o600
			|| info.len() > 16384
		{
			bail!("invalid worker adoption file");
		}
		let mut bytes = Vec::new();
		file.take(16385).read_to_end(&mut bytes)?;
		if bytes.len() > 16384 {
			bail!("worker claim exceeds its bound");
		}
		let value: Value = serde_json::from_slice(&bytes)?;
		Ok(value["schema"] == "hepta.rea.engine-scratch-claim.v1"
			&& value["owner"] == self.binding
			&& value["worker_pid"] == pid
			&& matches!(value["engine"].as_str(), Some("ghidra" | "jadx")))
	}

	pub(crate) fn retained(&self, reason: &str) -> Value {
		json!({
			"schema":"hepta.rea.engine-scratch-cleanup.v1", "job_id":self.binding["job_id"],
			"launch_nonce":self.binding["launch_nonce"], "directory":"engine-scratch",
			"device":self.binding["device"], "inode":self.binding["inode"],
			"state":"retained", "removed":false, "durable":false, "worker_adopted":false,
			"original_process_group_stopped":false, "original_child_reaped":false, "error":reason
		})
	}

	pub(crate) fn finish(self, pid: u32, group_stopped: bool) -> Value {
		let mut receipt = self.retained("original process group unconfirmed; no cleanup submitted");
		if !group_stopped {
			return receipt;
		}
		receipt["original_process_group_stopped"] = json!(true);
		receipt["original_child_reaped"] = json!(true);
		let result = (|| -> Result<()> {
			let (device, inode) = self.directory.identity();
			let original = Directory::open(&self.directory.path, device, inode)?;
			receipt["worker_adopted"] = json!(self.claim(pid).unwrap_or(false));
			receipt["state"] = json!("incomplete");
			original.remove()?;
			Ok(())
		})();
		match result {
			Ok(()) => {
				receipt["state"] = json!("removed");
				receipt["removed"] = json!(true);
				receipt["durable"] = json!(true);
				if let Some(object) = receipt.as_object_mut() {
					object.remove("error");
				}
			}
			Err(error) => receipt["error"] = json!(format!("{error:#}")),
		}
		receipt
	}
}

/// This is called only while `OriginalChild` still owns the unreaped leader.
pub(crate) fn original_exited(pid: u32) -> Result<bool> {
	let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
	if unsafe {
		libc::waitid(
			libc::P_PID,
			pid,
			&mut info,
			libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
		)
	} != 0
	{
		return Err(std::io::Error::last_os_error()).context("original engine child custody lost");
	}
	let observed = unsafe { info.si_pid() };
	if observed == 0 {
		return Ok(false);
	}
	if observed != pid as i32
		|| !matches!(
			info.si_code,
			libc::CLD_EXITED | libc::CLD_KILLED | libc::CLD_DUMPED
		) {
		bail!("original engine child exit is unconfirmed");
	}
	Ok(true)
}

fn members(group: i32, deadline: Instant) -> Result<Vec<i32>> {
	let mut members = Vec::new();
	for (count, entry) in std::fs::read_dir("/proc")?.enumerate() {
		if count > 100_000 || Instant::now() >= deadline {
			bail!("engine group observation budget exceeded");
		}
		let entry = entry?;
		let Some(pid) = entry
			.file_name()
			.to_str()
			.and_then(|s| s.parse::<i32>().ok())
		else {
			continue;
		};
		let file = match File::open(entry.path().join("stat")) {
			Ok(file) => file,
			Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
			Err(error) => return Err(error).context("engine group visibility unconfirmed"),
		};
		let mut bytes = Vec::new();
		file.take(16385).read_to_end(&mut bytes)?;
		if bytes.len() > 16384 {
			bail!("engine process identity exceeds its bound");
		}
		let end = bytes
			.iter()
			.rposition(|b| *b == b')')
			.context("engine process identity malformed")?;
		let fields: Vec<_> = std::str::from_utf8(&bytes[end + 1..])?
			.split_whitespace()
			.collect();
		if fields
			.get(2)
			.context("engine process group absent")?
			.parse::<i32>()?
			== group && !matches!(fields.first(), Some(&"Z") | Some(&"X"))
		{
			members.push(pid);
		}
	}
	Ok(members)
}

/// Preserve the existing process-visibility hardening and refuse partial scans.
pub(crate) fn confirm_group_visibility(mounts: &str) -> Result<()> {
	let mut proc_seen = false;
	for line in mounts.lines() {
		let fields: Vec<_> = line.split_whitespace().collect();
		if fields.get(4) == Some(&"/proc") {
			proc_seen = true;
			for option in fields.iter().skip(5).flat_map(|field| field.split(',')) {
				if option.starts_with("hidepid=") && !matches!(option, "hidepid=0" | "hidepid=off")
				{
					bail!("engine original-group visibility is restricted");
				}
			}
		}
	}
	if !proc_seen {
		bail!("engine original-group proc mount is unconfirmed");
	}
	Ok(())
}

/// Stops residual engine descendants before reaping releases the original PGID.
/// An observation failure or timeout retains scratch and grants no later signal.
pub(crate) fn stop_original_group(pid: u32) -> Result<()> {
	directory::require_supported_platform()?;
	let mut mounts = Vec::new();
	File::open("/proc/self/mountinfo")?
		.take(1048577)
		.read_to_end(&mut mounts)?;
	if mounts.len() > 1048576 {
		bail!("engine mount observation exceeds its bound");
	}
	confirm_group_visibility(std::str::from_utf8(&mounts)?)?;
	let group = i32::try_from(pid).context("engine process group exceeds PID range")?;
	let deadline = Instant::now() + Duration::from_secs(2);
	loop {
		let exited = original_exited(pid)?;
		if exited && members(group, deadline)?.is_empty() {
			return Ok(());
		}
		if unsafe { libc::kill(-group, libc::SIGKILL) } != 0 {
			let error = std::io::Error::last_os_error();
			if error.raw_os_error() != Some(libc::ESRCH) {
				return Err(error).context("engine group stop unconfirmed");
			}
		}
		if Instant::now() >= deadline {
			bail!("original engine group did not stop");
		}
		std::thread::sleep(Duration::from_millis(10));
	}
}
