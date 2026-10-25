// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Standalone Linux x86_64 post-spawn proof diagnostic; std only.
//!
//! Fixed workload: 2,000 /usr/bin/true, then 3,000 /usr/bin/ssh -G commands.
//! ssh -G prints configuration and exits; -F /dev/null and disabled hostname
//! canonicalization avoid profile configuration and connection attempts.
//! No retries, signals to numeric PIDs, inherited environment, or user input.
//! Every successfully spawned Child is waited on before output or another spawn.
//!
//! This reproduces the source read order and proof predicate, with the actual
//! pre_exec parent-death fence to force Rust's fork/exec path. It does not
//! reproduce Tokio scheduling, Core's registry bookkeeping, or historical events.
//! A completed run exits 0 even when proof=false is observed: inspect the JSONL.
//! Exit 2 = preflight/pin refusal, 3 = spawn failure, 4 = wait failure, 5 = output.

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
compile_error!("This diagnostic requires Linux x86_64 (pidfd_open syscall 434)");

use std::ffi::{c_int, c_long, c_uint, c_ulong};
use std::fs;
use std::io::{self, BufWriter, Write};
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::PathBuf;
use std::process::{Command, ExitStatus, Stdio};

const SYS_PIDFD_OPEN: c_long = 434;
const PR_SET_PDEATHSIG: c_int = 1;
const SIGKILL: c_ulong = 9;
const TRUE_COUNT: usize = 2_000;
const SSH_COUNT: usize = 3_000;

unsafe extern "C" {
	fn syscall(number: c_long, ...) -> c_long;
	fn getpid() -> c_int;
	fn getppid() -> c_int;
	fn geteuid() -> c_uint;
	fn prctl(option: c_int, ...) -> c_int;
	fn _exit(status: c_int) -> !;
}

#[derive(Clone, Copy)]
struct Failure {
	stage: &'static str,
	errno: Option<i32>,
}

impl Failure {
	fn io(stage: &'static str, error: io::Error) -> Self {
		Self {
			stage,
			errno: error.raw_os_error(),
		}
	}

	fn plain(stage: &'static str) -> Self {
		Self { stage, errno: None }
	}
}

#[derive(Default)]
struct IdentityRead {
	failure: Option<Failure>,
	exe: Option<(u64, u64)>,
	uid: Option<u32>,
	argv: Option<Vec<u8>>,
}

// Source order is deliberate: stat read -> tail -> birth parse -> exe metadata
// -> /proc/<pid> metadata/uid -> cmdline. Do not insert sleeps or re-reads here.
fn process_identity(pid: u32) -> IdentityRead {
	let mut observed = IdentityRead::default();
	let result = (|| -> Result<(), Failure> {
		let root = PathBuf::from(format!("/proc/{pid}"));
		let status =
			fs::read_to_string(root.join("stat")).map_err(|e| Failure::io("stat_read", e))?;
		let tail = status
			.rsplit_once(')')
			.ok_or_else(|| Failure::plain("stat_tail"))?
			.1;
		let _birth: u64 = tail
			.split_ascii_whitespace()
			.nth(19)
			.ok_or_else(|| Failure::plain("birth_missing"))?
			.parse()
			.map_err(|_| Failure::plain("birth_parse"))?;
		let exe = fs::metadata(root.join("exe")).map_err(|e| Failure::io("exe_metadata", e))?;
		observed.exe = Some((exe.dev(), exe.ino()));
		observed.uid = Some(
			fs::metadata(&root)
				.map_err(|e| Failure::io("proc_metadata", e))?
				.uid(),
		);
		observed.argv =
			Some(fs::read(root.join("cmdline")).map_err(|e| Failure::io("cmdline_read", e))?);
		Ok(())
	})();
	observed.failure = result.err();
	observed
}

fn preflight() -> Result<(), Failure> {
	let native = unsafe { getpid() };
	if native <= 0 || native as u32 != std::process::id() {
		return Err(Failure::plain("getpid_std_mismatch"));
	}
	let link = fs::read_link("/proc/self").map_err(|e| Failure::io("proc_self_link_read", e))?;
	let link_pid: u32 = link
		.to_str()
		.ok_or_else(|| Failure::plain("proc_self_link_parse"))?
		.parse()
		.map_err(|_| Failure::plain("proc_self_link_parse"))?;
	if link_pid != native as u32 {
		return Err(Failure::plain("proc_self_link_mismatch"));
	}
	for (path, read_stage, parse_stage, mismatch_stage) in [
		(
			PathBuf::from("/proc/self/stat"),
			"proc_self_stat_read",
			"proc_self_stat_parse",
			"proc_self_stat_mismatch",
		),
		(
			PathBuf::from(format!("/proc/{native}/stat")),
			"proc_numeric_stat_read",
			"proc_numeric_stat_parse",
			"proc_numeric_stat_mismatch",
		),
	] {
		let stat = fs::read_to_string(path).map_err(|e| Failure::io(read_stage, e))?;
		let pid: u32 = stat
			.split_ascii_whitespace()
			.next()
			.ok_or_else(|| Failure::plain(parse_stage))?
			.parse()
			.map_err(|_| Failure::plain(parse_stage))?;
		if pid != native as u32 {
			return Err(Failure::plain(mismatch_stage));
		}
	}
	Ok(())
}

struct Case {
	category: &'static str,
	program: &'static str,
	args: &'static [&'static str],
	count: usize,
	inode: (u64, u64),
	expected: Vec<u8>,
}

impl Case {
	fn new(
		category: &'static str,
		program: &'static str,
		args: &'static [&'static str],
		count: usize,
	) -> Result<Self, Failure> {
		let exe = fs::metadata(program).map_err(|e| Failure::io("binary_pin", e))?;
		if !exe.is_file() {
			return Err(Failure::plain("binary_not_regular"));
		}
		let expected = std::iter::once(program)
			.chain(args.iter().copied())
			.flat_map(|arg| arg.as_bytes().iter().copied().chain([0]))
			.collect();
		Ok(Self {
			category,
			program,
			args,
			count,
			inode: (exe.dev(), exe.ino()),
			expected,
		})
	}

	fn command(&self) -> Command {
		let mut command = Command::new(self.program);
		command
			.args(self.args)
			.env_clear()
			.env("PATH", "/usr/bin:/bin")
			.env("LANG", "C")
			.env("SHELL", "/bin/sh")
			.stdin(Stdio::null())
			.stdout(Stdio::null())
			.stderr(Stdio::null());
		let controller = unsafe { getpid() };
		// Same syscall-only pre_exec fence as Core::command. Its presence is
		// essential: the default std Command may otherwise use posix_spawn.
		unsafe {
			command.pre_exec(move || {
				if prctl(
					PR_SET_PDEATHSIG,
					SIGKILL,
					0 as c_ulong,
					0 as c_ulong,
					0 as c_ulong,
				) != 0 || getppid() != controller
				{
					_exit(127);
				}
				Ok(())
			});
		}
		command
	}
}

fn jbool(value: Option<bool>) -> &'static str {
	match value {
		Some(true) => "true",
		Some(false) => "false",
		None => "null",
	}
}

fn jint(value: Option<i32>) -> String {
	value.map_or_else(|| "null".to_owned(), |n| n.to_string())
}

fn jstage(value: Option<Failure>) -> String {
	value.map_or_else(|| "null".to_owned(), |e| format!("\"{}\"", e.stage))
}

fn exit_code(status: Option<&ExitStatus>) -> Option<i32> {
	status.and_then(ExitStatus::code)
}

fn exit_signal(status: Option<&ExitStatus>) -> Option<i32> {
	status.and_then(ExitStatusExt::signal)
}

#[derive(Default)]
struct Counts {
	attempted: usize,
	spawned: usize,
	reaped: usize,
	proof_false: usize,
	pidfd_failed: usize,
	identity_failed: usize,
	empty_argv: usize,
	terminal_false: usize,
	terminal_failed: usize,
	exit_unsuccessful: usize,
}

fn emit_refusal(out: &mut impl Write, failure: Failure) -> io::Result<()> {
	writeln!(
		out,
		"{{\"kind\":\"preflight\",\"passed\":false,\"stage\":\"{}\",\"errno\":{}}}",
		failure.stage,
		jint(failure.errno)
	)
}

fn run(out: &mut impl Write) -> io::Result<i32> {
	if let Err(failure) = preflight() {
		emit_refusal(out, failure)?;
		return Ok(2);
	}
	let cases = [
		Case::new("true", "/usr/bin/true", &[], TRUE_COUNT),
		Case::new(
			"ssh_g",
			"/usr/bin/ssh",
			&[
				"-G",
				"-F",
				"/dev/null",
				"-o",
				"CanonicalizeHostname=no",
				"localhost",
			],
			SSH_COUNT,
		),
	];
	// Pin both executables before admitting any child.
	if let Some(failure) = cases.iter().find_map(|case| case.as_ref().err().copied()) {
		emit_refusal(out, failure)?;
		return Ok(2);
	}
	writeln!(
		out,
		"{{\"kind\":\"preflight\",\"schema\":\"hepta-postspawn-proof-probe/v1\",\"passed\":true,\"proc_self_getpid_agree\":true,\"pre_exec_parent_death_fence\":true,\"true_attempts\":{},\"ssh_g_attempts\":{},\"spawn_limit\":{},\"historical_attribution\":false}}",
		TRUE_COUNT,
		SSH_COUNT,
		TRUE_COUNT + SSH_COUNT
	)?;
	out.flush()?;
	let mut total = Counts::default();
	let mut stop_code = 0;
	'cases: for case_result in cases {
		let case = match case_result {
			Ok(case) => case,
			Err(_) => unreachable!("pins were checked before the first spawn"),
		};
		for _ in 0..case.count {
			total.attempted += 1;
			let mut child = match case.command().spawn() {
				Ok(child) => child,
				Err(error) => {
					writeln!(
						out,
						"{{\"kind\":\"attempt\",\"sequence\":{},\"command\":\"{}\",\"spawn_ok\":false,\"spawn_errno\":{}}}",
						total.attempted,
						case.category,
						jint(error.raw_os_error())
					)?;
					stop_code = 3;
					break 'cases;
				}
			};

			// Critical sequence mirrors Core::spawn. No output, delay, retry,
			// or additional /proc read is inserted before the proof decision.
			let pid = child.id();
			let fd = unsafe { syscall(SYS_PIDFD_OPEN, c_long::from(pid), 0 as c_long) };
			let pidfd_errno = if fd < 0 {
				io::Error::last_os_error().raw_os_error()
			} else {
				None
			};
			let pidfd = if fd < 0 {
				None
			} else {
				Some(unsafe { OwnedFd::from_raw_fd(fd as i32) })
			};
			let identity = process_identity(pid);
			let identity_ok = identity.failure.is_none();
			// Preserve the production short circuit, including no geteuid()
			// syscall when identity collection itself has failed.
			let matches = identity_ok
				&& identity.uid.is_some_and(|uid| uid == unsafe { geteuid() })
				&& identity.exe == Some(case.inode)
				&& identity
					.argv
					.as_ref()
					.is_some_and(|argv| argv == &case.expected);
			let terminal = child.try_wait();
			let terminal_ok = terminal.is_ok();
			let done = terminal.as_ref().ok().map(Option::is_some);
			let proof = pidfd.is_some() && terminal_ok && (done == Some(true) || matches);

			// Even a failed proof or try_wait uses the original Child. wait()
			// also works after try_wait() has already reaped and cached status.
			// There is never a signal or a new numeric-PID-based Child handle.
			let waited = child.wait();
			let wait_ok = waited.is_ok();
			let status = waited.as_ref().ok();
			// Detailed diagnostic comparisons happen after the proof and wait,
			// so partial identity errors do not add syscalls before try_wait.
			let uid_match = identity.uid.map(|uid| uid == unsafe { geteuid() });
			let exe_match = identity.exe.map(|inode| inode == case.inode);
			let argv_match = identity.argv.as_ref().map(|argv| argv == &case.expected);
			let argv_empty = identity.argv.as_ref().map(Vec::is_empty);
			let terminal_errno = terminal.as_ref().err().and_then(io::Error::raw_os_error);
			let wait_errno = waited.as_ref().err().and_then(io::Error::raw_os_error);
			total.spawned += 1;
			total.reaped += usize::from(wait_ok);
			total.proof_false += usize::from(!proof);
			total.pidfd_failed += usize::from(pidfd.is_none());
			total.identity_failed += usize::from(!identity_ok);
			total.empty_argv += usize::from(argv_empty == Some(true));
			total.terminal_false += usize::from(done == Some(false));
			total.terminal_failed += usize::from(!terminal_ok);
			total.exit_unsuccessful += usize::from(status.is_some_and(|s| !s.success()));

			writeln!(
				out,
				"{{\"kind\":\"attempt\",\"sequence\":{},\"command\":\"{}\",\"spawn_ok\":true,\"pidfd_ok\":{},\"pidfd_errno\":{},\"identity_ok\":{},\"identity_stage\":{},\"identity_errno\":{},\"uid_match\":{},\"exe_match\":{},\"argv_match\":{},\"argv_empty\":{},\"matches\":{},\"terminal_ok\":{},\"terminal_done\":{},\"terminal_false\":{},\"terminal_errno\":{},\"proof\":{},\"wait_ok\":{},\"wait_errno\":{},\"exit_code\":{},\"exit_signal\":{}}}",
				total.attempted,
				case.category,
				pidfd.is_some(),
				jint(pidfd_errno),
				identity_ok,
				jstage(identity.failure),
				jint(identity.failure.and_then(|e| e.errno)),
				jbool(uid_match),
				jbool(exe_match),
				jbool(argv_match),
				jbool(argv_empty),
				matches,
				terminal_ok,
				jbool(done),
				done == Some(false),
				jint(terminal_errno),
				proof,
				wait_ok,
				jint(wait_errno),
				jint(exit_code(status)),
				jint(exit_signal(status))
			)?;
			// Drop the owned descriptor only after the original child is waited.
			drop(pidfd);
			if !wait_ok {
				stop_code = 4;
				break 'cases;
			}
		}
	}
	writeln!(
		out,
		"{{\"kind\":\"summary\",\"completed\":{},\"stop_code\":{},\"attempted\":{},\"spawned\":{},\"reaped\":{},\"proof_false\":{},\"pidfd_failed\":{},\"identity_failed\":{},\"empty_argv\":{},\"terminal_false\":{},\"terminal_failed\":{},\"exit_unsuccessful\":{},\"historical_attribution\":false}}",
		stop_code == 0 && total.attempted == TRUE_COUNT + SSH_COUNT,
		stop_code,
		total.attempted,
		total.spawned,
		total.reaped,
		total.proof_false,
		total.pidfd_failed,
		total.identity_failed,
		total.empty_argv,
		total.terminal_false,
		total.terminal_failed,
		total.exit_unsuccessful
	)?;
	out.flush()?;
	Ok(stop_code)
}

fn main() {
	let mut out = BufWriter::new(io::stdout().lock());
	let code = match run(&mut out) {
		Ok(code) => code,
		Err(_) => 5, // No raw error strings (which could include private paths).
	};
	// Every spawned Child had wait() called. A wait error stops the probe and
	// leaves cleanup uncertain in its receipt; no signal-based fallback exists.
	// Explicit flush also covers a preflight refusal.
	let code = if out.flush().is_err() { 5 } else { code };
	std::process::exit(code);
}
