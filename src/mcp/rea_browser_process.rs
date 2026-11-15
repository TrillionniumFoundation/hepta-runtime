// Copyright 2026 Muvon Un Limited
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
//! Exclusive child custody and bounded original-process-group cleanup.

use super::input::{open_at, Directory};
use anyhow::{bail, Context, Result};
use std::fs::File;
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

static CANCELLED: AtomicBool = AtomicBool::new(false);

extern "C" fn cancel_signal(_: libc::c_int) {
	CANCELLED.store(true, Ordering::Relaxed);
}

pub(super) fn check_cancelled() -> Result<()> {
	if CANCELLED.load(Ordering::Relaxed) {
		bail!("browser capture cancelled; recover the original durable job, automatic_retry=false");
	}
	Ok(())
}

/// Used only in the dedicated synchronous helper; never installed in the MCP server.
pub(super) struct Signals {
	old: Vec<(i32, libc::sigaction)>,
}

impl Signals {
	pub fn install() -> Result<Self> {
		CANCELLED.store(false, Ordering::Relaxed);
		let mut old = Vec::new();
		for signal in [libc::SIGTERM, libc::SIGINT] {
			// SAFETY: zero is a valid initial sigaction, then the handler and mask are set.
			let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
			let mut previous: libc::sigaction = unsafe { std::mem::zeroed() };
			action.sa_sigaction = cancel_signal as *const () as usize;
			unsafe {
				libc::sigemptyset(&mut action.sa_mask);
			}
			// SAFETY: both structures are initialized and live for this call.
			if unsafe { libc::sigaction(signal, &action, &mut previous) } != 0 {
				let guard = Self { old };
				drop(guard);
				return Err(std::io::Error::last_os_error())
					.context("capture cancellation handler unavailable");
			}
			old.push((signal, previous));
		}
		Ok(Self { old })
	}
}

impl Drop for Signals {
	fn drop(&mut self) {
		for (signal, action) in &self.old {
			// SAFETY: restoring exactly the previous handler; no captured state remains.
			unsafe {
				libc::sigaction(*signal, action, std::ptr::null_mut());
			}
		}
	}
}

pub(super) struct OwnedChrome {
	child: Child,
	pub pid: i32,
	reaped: bool,
	lost: bool,
}

fn preflight() -> Result<()> {
	// SAFETY: sigaction with null action only inspects the process configuration.
	let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
	if unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut action) } != 0 {
		return Err(std::io::Error::last_os_error())
			.context("cannot inspect child-reaping configuration");
	}
	if action.sa_sigaction != libc::SIG_DFL || action.sa_flags & libc::SA_NOCLDWAIT != 0 {
		bail!("private Chrome requires exclusive child reaping and default SIGCHLD without SA_NOCLDWAIT");
	}
	let mut bytes = Vec::new();
	File::open("/proc/self/mountinfo")?
		.take(1024 * 1024 + 1)
		.read_to_end(&mut bytes)?;
	if bytes.len() > 1024 * 1024 {
		bail!("proc mount observation exceeded its budget");
	}
	let mountinfo = std::str::from_utf8(&bytes)?;
	for line in mountinfo.lines() {
		let parts: Vec<_> = line.split_whitespace().collect();
		if parts.get(4) == Some(&"/proc") {
			for option in parts.iter().skip(5).flat_map(|part| part.split(',')) {
				if let Some(value) = option.strip_prefix("hidepid=") {
					if !matches!(value, "0" | "off") {
						bail!("private Chrome requires visible /proc process-group membership");
					}
				}
			}
		}
	}
	Ok(())
}

fn private_environment(command: &mut Command, profile: &Directory) -> Result<Vec<Directory>> {
	// The system launcher writes XDG files before exec. User-data-dir alone does
	// not contain those effects; the existing profile owner must own these too.
	let mut directories = Vec::with_capacity(4);
	for (variable, name) in [
		("HOME", "home"),
		("XDG_DATA_HOME", "xdg-data"),
		("XDG_CONFIG_HOME", "xdg-config"),
		("XDG_CACHE_HOME", "xdg-cache"),
	] {
		let directory = profile
			.create_child(name)
			.with_context(|| format!("cannot create private Chrome {variable} directory"))?;
		command.env(variable, &directory.path);
		directories.push(directory);
	}
	verify_environment(profile, &directories)?;
	Ok(directories)
}

fn verify_environment(profile: &Directory, directories: &[Directory]) -> Result<()> {
	profile.verify_location()?;
	for directory in directories {
		directory.verify_location()?;
	}
	Ok(())
}

fn spawn_in_custody(
	command: &mut Command,
	custody: &mut Option<OwnedChrome>,
	profile: &Directory,
	environment: &[Directory],
) -> Result<()> {
	if custody.is_some() {
		bail!("private Chrome launch refuses to replace existing child custody");
	}
	let child = command
		.spawn()
		.context("independent system Google Chrome failed to start")?;
	// On this Linux-only path Child::id originates from the positive pid_t
	// returned by spawn. Do not insert a fallible step before custody publication.
	let pid = child.id() as i32;
	*custody = Some(OwnedChrome {
		child,
		pid,
		reaped: false,
		lost: false,
	});
	verify_environment(profile, environment)
		.context("Chrome profile or environment path changed during launch; outcome unconfirmed")
}

impl OwnedChrome {
	pub fn launch(profile: &Directory, custody: &mut Option<Self>) -> Result<UnixStream> {
		if custody.is_some() {
			bail!("private Chrome launch refuses to replace existing child custody");
		}
		profile.verify_location()?;
		preflight()?;
		check_cancelled()?;
		let (parent, child_pipe) = UnixStream::pair()?;
		parent.set_nonblocking(true)?;
		// A high CLOEXEC duplicate prevents dup2(3)/dup2(4) from clobbering its source.
		let raw = unsafe { libc::fcntl(child_pipe.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 64) };
		if raw < 0 {
			return Err(std::io::Error::last_os_error())
				.context("cannot reserve Chrome pipe descriptor");
		}
		// SAFETY: fcntl returned a newly owned descriptor.
		let pipe = unsafe { File::from_raw_fd(raw) };
		let mut command = Command::new("/usr/bin/google-chrome");
		let environment = private_environment(&mut command, profile)?;
		command.args([
			"--headless=new",
			"--remote-debugging-pipe",
			"--no-first-run",
			"--no-default-browser-check",
			"--disable-background-networking",
			"--disable-component-update",
			"--disable-sync",
			"--disable-default-apps",
			"--metrics-recording-only",
			"--disable-extensions",
			"--disable-dev-shm-usage",
			"--password-store=basic",
			"--use-mock-keychain",
		]);
		command.arg(format!("--user-data-dir={}", profile.path.display()));
		command
			.arg("about:blank")
			.stdin(Stdio::null())
			.stdout(Stdio::null())
			.stderr(Stdio::null());
		// SAFETY: the post-fork closure performs only async-signal-safe syscalls;
		// child pipe 3/4 follow Chromium's documented remote-debugging-pipe protocol.
		unsafe {
			command.pre_exec(move || {
				if libc::setsid() < 0 || libc::dup2(raw, 3) < 0 || libc::dup2(raw, 4) < 0 {
					return Err(std::io::Error::last_os_error());
				}
				Ok(())
			});
		}
		spawn_in_custody(&mut command, custody, profile, &environment)?;
		drop(pipe);
		drop(child_pipe);
		Ok(parent)
	}

	/// Observe without reaping, retaining the original PID/PGID even after exit.
	pub fn observe_exit(&mut self) -> Result<Option<i32>> {
		if self.reaped || self.lost {
			bail!("private Chrome child custody lost; refusing numeric group signal");
		}
		// SAFETY: initialized output and a positive PID owned exclusively by this object.
		let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
		let result = unsafe {
			libc::waitid(
				libc::P_PID,
				self.pid as u32,
				&mut info,
				libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
			)
		};
		if result != 0 {
			let error = std::io::Error::last_os_error();
			if error.raw_os_error() == Some(libc::ECHILD) {
				self.lost = true;
			}
			return Err(error).context("Chrome child observation failed; cleanup unconfirmed");
		}
		// SAFETY: waitid populated the child-status fields (or left zero with WNOHANG).
		let pid = unsafe { info.si_pid() };
		if pid == 0 {
			return Ok(None);
		}
		if pid != self.pid
			|| !matches!(
				info.si_code,
				libc::CLD_EXITED | libc::CLD_KILLED | libc::CLD_DUMPED
			) {
			bail!("Chrome retained child exit witness is unconfirmed");
		}
		let status = unsafe { info.si_status() };
		Ok(Some(if info.si_code == libc::CLD_EXITED {
			status
		} else {
			-status
		}))
	}

	pub fn cleanup(&mut self) -> Result<()> {
		if self.reaped {
			return Ok(());
		}
		let deadline = Instant::now() + Duration::from_secs(10);
		loop {
			self.observe_exit()?;
			// The unreaped child reserves the original group identity throughout cleanup.
			if unsafe { libc::kill(-self.pid, libc::SIGKILL) } != 0 {
				let error = std::io::Error::last_os_error();
				if error.raw_os_error() != Some(libc::ESRCH) {
					return Err(error).context("Chrome group cleanup unconfirmed");
				}
			}
			let exit = self.observe_exit()?;
			if exit.is_some() && live_group_members(self.pid, deadline)?.is_empty() {
				let expected = self
					.observe_exit()?
					.context("Chrome exit witness disappeared")?;
				let actual = self
					.child
					.wait()
					.context("Chrome final child reap unconfirmed")?;
				self.reaped = true;
				use std::os::unix::process::ExitStatusExt;
				let code = actual
					.code()
					.unwrap_or_else(|| -actual.signal().unwrap_or(0));
				if code != expected {
					bail!("Chrome final reap differs from retained witness");
				}
				return Ok(());
			}
			if Instant::now() >= deadline {
				bail!("Chrome original process-group termination unconfirmed");
			}
			std::thread::sleep(Duration::from_millis(10));
		}
	}
}

impl Drop for OwnedChrome {
	fn drop(&mut self) {
		if !self.reaped && !self.lost {
			let _ = self.cleanup();
		}
	}
}

fn live_group_members(group: i32, deadline: Instant) -> Result<Vec<i32>> {
	let mut members = Vec::new();
	for (count, entry) in std::fs::read_dir("/proc")?.enumerate() {
		if count > 100_000 || Instant::now() >= deadline {
			bail!("Chrome group observation exceeded its budget");
		}
		let entry = entry?;
		let Some(pid) = entry
			.file_name()
			.to_str()
			.and_then(|s| s.parse::<i32>().ok())
		else {
			continue;
		};
		let mut file = match File::open(entry.path().join("stat")) {
			Ok(file) => file,
			Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
			Err(error) => return Err(error).context("Chrome group observation unconfirmed"),
		};
		let mut bytes = Vec::new();
		Read::by_ref(&mut file)
			.take(16_385)
			.read_to_end(&mut bytes)?;
		if bytes.len() > 16_384 {
			bail!("process stat exceeds observation bound");
		}
		let end = bytes
			.iter()
			.rposition(|b| *b == b')')
			.context("malformed process stat")?;
		let text = std::str::from_utf8(&bytes[end + 1..])?;
		let fields: Vec<_> = text.split_whitespace().collect();
		let pgid: i32 = fields.get(2).context("missing process group")?.parse()?;
		if pgid == group && !matches!(fields.first(), Some(&"Z") | Some(&"X")) {
			members.push(pid);
		}
	}
	Ok(members)
}

pub(super) fn remove_profile(parent: &Directory, profile: &Directory) -> Result<()> {
	use std::ffi::CString;
	use std::os::unix::ffi::OsStrExt;
	fn clear(dir: &File, count: &mut usize, depth: usize, deadline: Instant) -> Result<()> {
		if depth > 32 {
			bail!("Chrome profile cleanup depth exceeded");
		}
		for entry in std::fs::read_dir(format!("/proc/self/fd/{}", dir.as_raw_fd()))? {
			*count += 1;
			if *count > 100_000 || Instant::now() >= deadline {
				bail!("Chrome profile cleanup budget exceeded");
			}
			let entry = entry?;
			let name = entry.file_name();
			let name_c = CString::new(name.as_bytes())?;
			let mut flags = 0;
			if entry.file_type()?.is_dir() {
				let name = name.to_str().context("non-UTF8 profile directory")?;
				let child = open_at(dir, name, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
				clear(&child, count, depth + 1, deadline)?;
				flags = libc::AT_REMOVEDIR;
			}
			// SAFETY: an observed direct child name, relative to a retained directory FD.
			if unsafe { libc::unlinkat(dir.as_raw_fd(), name_c.as_ptr(), flags) } != 0 {
				return Err(std::io::Error::last_os_error())
					.context("Chrome profile cleanup unconfirmed");
			}
		}
		Ok(())
	}
	let name = profile
		.path
		.file_name()
		.and_then(|p| p.to_str())
		.context("invalid owned profile name")?;
	parent.verify_location()?;
	profile.verify_location()?;
	let current = open_at(&parent.file, name, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
	let expected = profile.file.metadata()?;
	let actual = current.metadata()?;
	if expected.dev() != actual.dev() || expected.ino() != actual.ino() {
		bail!("Chrome profile directory identity changed; cleanup unconfirmed");
	}
	clear(
		&profile.file,
		&mut 0,
		0,
		Instant::now() + Duration::from_secs(10),
	)?;
	parent.verify_location()?;
	profile.verify_location()?;
	let name_c = CString::new(name)?;
	if unsafe { libc::unlinkat(parent.file.as_raw_fd(), name_c.as_ptr(), libc::AT_REMOVEDIR) } != 0
	{
		return Err(std::io::Error::last_os_error()).context("Chrome profile removal unconfirmed");
	}
	parent.file.sync_all()?;
	Ok(())
}

#[cfg(test)]
#[path = "rea_browser_process_tests.rs"]
mod tests;
