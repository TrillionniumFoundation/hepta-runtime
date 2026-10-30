// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Closed systemd job capability: only setup is privileged; workloads use DynamicUser.
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
const ROOT: &str = "/var/lib/hepta-runtime-jobctl";
const POLICY: &str = "/etc/hepta-runtime/job-policy.json";
const HELPER: &str = "/usr/local/libexec/hepta-runtime-jobctl";
const INPUT_MAX: u64 = 1_048_576;
const LOG_MAX: u64 = 16 * 1024 * 1024;
const LOG_BUFFER: usize = 8192;
const LOG_READS_PER_TURN: usize = 8;
const OUTPUT_DRAIN: Duration = Duration::from_millis(200);
const OBSERVATION_POLL: Duration = Duration::from_millis(20);
static STOP: AtomicBool = AtomicBool::new(false);
extern "C" fn on_signal(_: libc::c_int) {
	STOP.store(true, Ordering::SeqCst);
}
fn signals() {
	unsafe {
		for sig in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP] {
			libc::signal(sig, on_signal as *const () as libc::sighandler_t);
		}
	}
}
fn now() -> u128 {
	SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.unwrap_or_default()
		.as_millis()
}
fn boot() -> Result<String> {
	Ok(fs::read_to_string("/proc/sys/kernel/random/boot_id")?
		.trim()
		.to_owned())
}
fn safe_id(id: &str) -> bool {
	!id.is_empty() && id.len() <= 96 && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}
fn digest(v: &impl Serialize) -> Result<String> {
	Ok(bytes_digest(&serde_json::to_vec(v)?))
}
fn bytes_digest(bytes: &[u8]) -> String {
	bytes_hex(&Sha256::digest(bytes))
}
// Both callers pass bounded bytes: a SHA-256 digest or one capped log page.
// Keep the lowercase wire format without a temporary String per input byte.
fn bytes_hex(bytes: &[u8]) -> String {
	const DIGITS: &[u8; 16] = b"0123456789abcdef";
	let mut hex = String::with_capacity(bytes.len() * 2);
	for &byte in bytes {
		hex.push(char::from(DIGITS[usize::from(byte >> 4)]));
		hex.push(char::from(DIGITS[usize::from(byte & 15)]));
	}
	hex
}
fn atomic(path: &Path, value: &impl Serialize) -> Result<()> {
	atomic_write(
		path,
		|file| {
			serde_json::to_writer(&mut *file, value)?;
			file.write_all(b"\n")?;
			Ok(())
		},
		|| {
			if let Some(parent) = path.parent() {
				File::open(parent)?.sync_all()?;
			}
			Ok(())
		},
	)
}
fn atomic_write(
	path: &Path,
	write: impl FnOnce(&mut File) -> Result<()>,
	sync_parent: impl FnOnce() -> Result<()>,
) -> Result<()> {
	let tmp = path.with_extension(format!("tmp-{}", std::process::id()));
	let mut f = OpenOptions::new()
		.write(true)
		.create_new(true)
		.mode(0o600)
		.open(&tmp)?;
	let result = (|| -> Result<()> {
		write(&mut f)?;
		f.sync_all()?;
		fs::rename(&tmp, path)?;
		sync_parent()?;
		Ok(())
	})();
	if result.is_err() {
		let _ = fs::remove_file(tmp);
	}
	result
}
fn dispatch_after_launch_namespace_sync<T>(
	registry: &Path,
	submit: impl FnOnce() -> Result<T>,
) -> Result<T> {
	let parent = registry.parent().context("job registry parent missing")?;
	let registry = File::open(registry).context("open job registry before dispatch")?;
	let parent = File::open(parent).context("open job registry parent before dispatch")?;
	dispatch_after_launch_namespace_sync_with_parents(&registry, &parent, submit)
}
fn dispatch_after_launch_namespace_sync_with_parents<T>(
	registry: &File,
	parent: &File,
	submit: impl FnOnce() -> Result<T>,
) -> Result<T> {
	// Atomic spec/record writes already synchronized the job directory. Commit
	// its new name in ROOT, then ROOT's name in /var/lib if Lock created ROOT.
	// A failed barrier leaves the original pending record and never submits.
	registry
		.sync_all()
		.context("sync job registry before dispatch")?;
	parent
		.sync_all()
		.context("sync job registry parent before dispatch")?;
	submit()
}
fn json_bytes(path: &Path) -> Result<Vec<u8>> {
	let f = OpenOptions::new()
		.read(true)
		.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
		.open(path)?;
	let metadata = f.metadata()?;
	if !metadata.is_file() || metadata.len() > INPUT_MAX {
		bail!("not a bounded regular JSON file");
	}
	let mut bytes = Vec::new();
	f.take(INPUT_MAX + 1).read_to_end(&mut bytes)?;
	if bytes.len() as u64 > INPUT_MAX {
		bail!("JSON file grew beyond its bound");
	}
	Ok(bytes)
}
fn json_file<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
	let f = OpenOptions::new()
		.read(true)
		.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
		.open(path)?;
	let metadata = f.metadata()?;
	if !metadata.is_file() || metadata.len() > INPUT_MAX {
		bail!("not a bounded regular JSON file");
	}
	Ok(serde_json::from_reader(f.take(INPUT_MAX + 1))?)
}
struct Lock(File);
impl Lock {
	fn acquire() -> Result<Self> {
		fs::create_dir_all(ROOT)?;
		fs::set_permissions(ROOT, fs::Permissions::from_mode(0o700))?;
		let f = OpenOptions::new()
			.create(true)
			.truncate(false)
			.read(true)
			.write(true)
			.mode(0o600)
			.open(format!("{ROOT}/lock"))?;
		use std::os::fd::AsRawFd;
		if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX) } != 0 {
			return Err(std::io::Error::last_os_error().into());
		}
		Ok(Self(f))
	}
}
impl Drop for Lock {
	fn drop(&mut self) {
		use std::os::fd::AsRawFd;
		unsafe {
			libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
		}
	}
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
	workspace: PathBuf,
	#[serde(default)]
	allow_network: bool,
	#[serde(default = "default_timeout")]
	max_timeout_seconds: u64,
	#[serde(default = "default_cpu")]
	max_cpu_percent: u16,
	#[serde(default = "default_memory")]
	max_memory_bytes: u64,
}
fn default_timeout() -> u64 {
	3600
}
fn default_cpu() -> u16 {
	100
}
fn default_memory() -> u64 {
	1024 * 1024 * 1024
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
	op: String,
	job_id: String,
	#[serde(default)]
	executable: String,
	#[serde(default)]
	args: Vec<String>,
	#[serde(default)]
	cwd: Option<String>,
	#[serde(default)]
	env: BTreeMap<String, String>,
	#[serde(default)]
	stdin: Option<String>,
	#[serde(default)]
	timeout_seconds: Option<u64>,
	#[serde(default)]
	nice: Option<u8>,
	#[serde(default)]
	cpu_quota_percent: Option<u16>,
	#[serde(default)]
	memory_max_bytes: Option<u64>,
	#[serde(default)]
	stdout_offset: u64,
	#[serde(default)]
	stderr_offset: u64,
	#[serde(default)]
	limit: Option<u64>,
}
#[derive(Clone, Serialize, Deserialize)]
struct Record {
	job_id: String,
	unit: String,
	request_digest: String,
	boot_id: String,
	nonce: String,
	invocation_id: Option<String>,
	launch_state: String,
	created_unix_ms: u128,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	terminal_protocol: Option<TerminalProtocol>,
}
#[derive(Serialize, Deserialize)]
struct Spec {
	request: Request,
	nonce: String,
	boot_id: String,
	workspace: String,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	terminal_protocol: Option<TerminalProtocol>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum TerminalProtocol {
	#[serde(rename = "captured_v1")]
	CapturedV1,
	#[serde(rename = "pty_v1")]
	PtyV1,
}
impl TerminalProtocol {
	fn for_interactive(interactive: bool) -> Self {
		if interactive {
			Self::PtyV1
		} else {
			Self::CapturedV1
		}
	}
	fn for_spec(declared: Option<Self>, interactive: bool) -> Result<Self> {
		let actual = Self::for_interactive(interactive);
		if declared.is_some_and(|expected| expected != actual) {
			bail!("supervisor capture protocol mismatch");
		}
		Ok(actual)
	}
}
#[derive(Serialize, Deserialize)]
struct Exit {
	job_id: String,
	nonce: String,
	exit_code: i32,
	timed_out: bool,
	cancelled: bool,
	at_unix_ms: u128,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	terminal_protocol: Option<TerminalProtocol>,
	#[serde(default)]
	output_complete: Option<bool>,
	#[serde(default)]
	output_durable: Option<bool>,
	#[serde(default)]
	capture: Option<OutputCapture>,
}

#[derive(Serialize, Deserialize)]
struct TerminalWitness {
	job_id: String,
	nonce: String,
	terminal_protocol: TerminalProtocol,
	exit_sha256: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct StreamCapture {
	seen: u64,
	saved: u64,
	eof: bool,
	truncated: bool,
	drain_timeout: bool,
	read_error: Option<String>,
	write_error: Option<String>,
	sync_error: Option<String>,
	synced: bool,
}
impl StreamCapture {
	fn complete(&self) -> bool {
		self.eof
			&& !self.truncated
			&& !self.drain_timeout
			&& self.read_error.is_none()
			&& self.write_error.is_none()
			&& self.sync_error.is_none()
			&& self.seen == self.saved
	}
}

#[derive(Debug, Serialize, Deserialize)]
struct OutputCapture {
	stdout: StreamCapture,
	stderr: StreamCapture,
}
impl OutputCapture {
	fn complete(&self) -> bool {
		self.stdout.complete() && self.stderr.complete()
	}
	fn durable(&self) -> bool {
		self.complete() && self.stdout.synced && self.stderr.synced
	}
	fn not_started(error: &str) -> Self {
		let stream = || StreamCapture {
			read_error: Some(format!(
				"capture unavailable before workload spawn: {error}"
			)),
			..StreamCapture::default()
		};
		Self {
			stdout: stream(),
			stderr: stream(),
		}
	}
}

impl Exit {
	fn new(
		job_id: &str,
		nonce: String,
		exit_code: i32,
		timed_out: bool,
		cancelled: bool,
		terminal_protocol: TerminalProtocol,
		capture: Option<OutputCapture>,
	) -> Self {
		Self {
			job_id: job_id.to_owned(),
			nonce,
			exit_code,
			timed_out,
			cancelled,
			at_unix_ms: now(),
			terminal_protocol: Some(terminal_protocol),
			output_complete: capture.as_ref().map(OutputCapture::complete),
			output_durable: capture.as_ref().map(OutputCapture::durable),
			capture,
		}
	}
}

fn publish_terminal(directory: &Path, receipt: &Exit) -> Result<()> {
	let parent = File::open(directory)?;
	publish_terminal_with_parents(directory, receipt, &parent, &parent)
}

fn publish_terminal_with_parents(
	directory: &Path,
	receipt: &Exit,
	exit_parent: &File,
	witness_parent: &File,
) -> Result<()> {
	let protocol = receipt
		.terminal_protocol
		.context("new terminal receipt lacks protocol")?;
	validate_capture(receipt, Some(protocol))?;
	let mut bytes = serde_json::to_vec(receipt)?;
	bytes.push(b'\n');
	if bytes.len() as u64 > INPUT_MAX {
		bail!("terminal receipt exceeds its bound");
	}
	// Both log files have already completed their real file syncs and closed.
	// This directory barrier also covers their names. An Exit rename alone is
	// not authority: no witness may be created until this barrier succeeds.
	atomic_write(
		&directory.join("exit.json"),
		|file| Ok(file.write_all(&bytes)?),
		|| Ok(exit_parent.sync_all()?),
	)?;
	let witness = TerminalWitness {
		job_id: receipt.job_id.clone(),
		nonce: receipt.nonce.clone(),
		terminal_protocol: protocol,
		exit_sha256: bytes_digest(&bytes),
	};
	// A visible matching witness proves the preceding Exit directory barrier
	// returned successfully, not that the witness's own final barrier survived
	// power loss. Missing evidence after restart always remains unknown.
	atomic_write(
		&directory.join("exit.witness"),
		|file| {
			serde_json::to_writer(&mut *file, &witness)?;
			file.write_all(b"\n")?;
			Ok(())
		},
		|| Ok(witness_parent.sync_all()?),
	)
}
fn record_path(id: &str) -> PathBuf {
	Path::new(ROOT).join(id).join("record.json")
}
fn data_dir(id: &str) -> PathBuf {
	PathBuf::from(format!("/var/lib/hepta-job-{id}"))
}
fn load_record(id: &str) -> Result<Record> {
	if !safe_id(id) {
		bail!("invalid owned job ID");
	}
	let r: Record = json_file(&record_path(id)).context("unknown owned job")?;
	if r.job_id != id || r.unit != format!("hepta-job-{id}.service") {
		bail!("job identity mismatch");
	}
	Ok(r)
}
fn policy() -> Result<Policy> {
	let m = fs::symlink_metadata(POLICY)?;
	if !m.is_file() || m.uid() != 0 || m.mode() & 0o022 != 0 {
		bail!("policy must be root-owned and not group/other writable");
	}
	let mut p: Policy = json_file(Path::new(POLICY))?;
	p.workspace = fs::canonicalize(&p.workspace)?;
	if !p.workspace.starts_with("/var/lib/hepta-runtime/workspaces")
		|| p.max_timeout_seconds == 0
		|| p.max_timeout_seconds > 604800
		|| p.max_cpu_percent == 0
		|| p.max_cpu_percent > 1000
		|| p.max_memory_bytes < 67108864
	{
		bail!("invalid administrator job policy");
	}
	Ok(p)
}
fn validate(q: &mut Request, p: &Policy) -> Result<()> {
	if !safe_id(&q.job_id) {
		bail!("invalid job ID");
	}
	if !Path::new(&q.executable).is_absolute()
		|| q.executable.contains('\0')
		|| q.args.len() > 256
		|| q.args.iter().any(|a| a.len() > 65536 || a.contains('\0'))
		|| q.env.len() > 64
	{
		bail!("invalid executable/arguments");
	}
	let cwd = fs::canonicalize(q.cwd.as_deref().map(Path::new).unwrap_or(&p.workspace))?;
	if !cwd.starts_with(&p.workspace) {
		bail!("cwd escapes administrator workspace");
	}
	q.cwd = Some(cwd.to_string_lossy().into_owned());
	for (k, v) in &q.env {
		if k.is_empty()
			|| k.as_bytes()[0].is_ascii_digit()
			|| !k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
			|| v.len() > 65536
			|| v.contains('\0')
			|| [
				"CREDENTIALS_DIRECTORY",
				"STATE_DIRECTORY",
				"INVOCATION_ID",
				"NOTIFY_SOCKET",
			]
			.contains(&k.as_str())
		{
			bail!("invalid environment");
		}
	}
	if q.timeout_seconds
		.is_some_and(|v| v == 0 || v > p.max_timeout_seconds)
		|| q.cpu_quota_percent
			.is_some_and(|v| v == 0 || v > p.max_cpu_percent)
		|| q.memory_max_bytes
			.is_some_and(|v| v < 67108864 || v > p.max_memory_bytes)
		|| q.nice.is_some_and(|v| v > 19)
	{
		bail!("requested resources exceed administrator caps");
	}
	q.timeout_seconds = Some(q.timeout_seconds.unwrap_or(p.max_timeout_seconds));
	Ok(())
}
fn properties(r: &Record) -> Result<BTreeMap<String, String>> {
	let out=Command::new("/usr/bin/systemctl").args(["show","--no-pager","--property=LoadState,ActiveState,SubState,Result,InvocationID,Description,ExecMainStatus,ExecMainCode","--",&r.unit]).output()?;
	Ok(String::from_utf8_lossy(&out.stdout)
		.lines()
		.filter_map(|l| l.split_once('=').map(|(k, v)| (k.to_owned(), v.to_owned())))
		.collect())
}
fn bind_invocation(r: &mut Record, p: &BTreeMap<String, String>) -> Result<bool> {
	if p.get("LoadState").map(String::as_str) == Some("not-found") {
		return Ok(false);
	}
	if p.get("Description") != Some(&format!("Hepta Runtime {} {}", r.job_id, r.nonce)) {
		bail!("unit ownership mismatch: refusing operation");
	}
	let inv = p
		.get("InvocationID")
		.filter(|s| !s.is_empty())
		.context("unit has no invocation identity")?;
	if let Some(expected) = &r.invocation_id {
		if expected != inv {
			bail!("unit incarnation changed: refusing operation");
		}
	} else {
		r.invocation_id = Some(inv.clone());
		atomic(&record_path(&r.job_id), r)?;
	}
	Ok(true)
}
fn validate_capture(e: &Exit, protocol: Option<TerminalProtocol>) -> Result<()> {
	if e.terminal_protocol != protocol {
		bail!("terminal protocol mismatch");
	}
	match protocol {
		Some(TerminalProtocol::CapturedV1) => {
			let capture = e
				.capture
				.as_ref()
				.context("new captured receipt lacks stream evidence")?;
			if e.output_complete != Some(capture.complete())
				|| e.output_durable != Some(capture.durable())
				|| [&capture.stdout, &capture.stderr]
					.into_iter()
					.any(|stream| stream.saved > LOG_MAX || stream.saved > stream.seen)
			{
				bail!("inconsistent output capture receipt");
			}
		}
		Some(TerminalProtocol::PtyV1) | None => {
			if e.capture.is_some() || e.output_complete.is_some() || e.output_durable.is_some() {
				bail!("legacy or PTY receipt cannot claim file capture");
			}
		}
	}
	Ok(())
}

struct ConfirmedExit {
	receipt: Exit,
	witnessed: bool,
}

enum TerminalObservation {
	Missing,
	Pending(&'static str),
	Confirmed(Box<ConfirmedExit>),
}

fn observe_terminal(r: &Record, directory: &Path) -> Result<TerminalObservation> {
	let path = directory.join("exit.json");
	if !path.try_exists()? {
		return Ok(TerminalObservation::Missing);
	}
	let bytes = match json_bytes(&path) {
		Ok(bytes) => bytes,
		Err(error) if r.terminal_protocol.is_none() => return Err(error),
		Err(_) => return Ok(TerminalObservation::Pending("terminal_receipt_unreadable")),
	};
	let receipt: Exit = match serde_json::from_slice(&bytes) {
		Ok(receipt) => receipt,
		Err(error) if r.terminal_protocol.is_none() => return Err(error.into()),
		Err(_) => return Ok(TerminalObservation::Pending("terminal_receipt_invalid")),
	};
	if receipt.job_id != r.job_id || receipt.nonce != r.nonce {
		bail!("exit identity mismatch");
	}
	if r.terminal_protocol.is_some() && r.terminal_protocol != receipt.terminal_protocol {
		return Ok(TerminalObservation::Pending("terminal_protocol_mismatch"));
	}
	// Old records can observe a newly upgraded supervisor's versioned receipt.
	// Only an old record AND an old, unmarked, capture-free Exit use legacy
	// semantics. Removing fields from a new receipt cannot downgrade a new job.
	if validate_capture(&receipt, receipt.terminal_protocol).is_err() {
		return Ok(TerminalObservation::Pending("terminal_capture_invalid"));
	}
	let witnessed = if let Some(protocol) = receipt.terminal_protocol {
		let witness: TerminalWitness = match json_file(&directory.join("exit.witness")) {
			Ok(witness) => witness,
			Err(_) => return Ok(TerminalObservation::Pending("terminal_witness_unavailable")),
		};
		if witness.job_id != r.job_id
			|| witness.nonce != r.nonce
			|| witness.terminal_protocol != protocol
			|| witness.exit_sha256 != bytes_digest(&bytes)
		{
			return Ok(TerminalObservation::Pending("terminal_witness_mismatch"));
		}
		true
	} else {
		false
	};
	Ok(TerminalObservation::Confirmed(Box::new(ConfirmedExit {
		receipt,
		witnessed,
	})))
}

fn capture_metadata(r: &Record, terminal: Option<&ConfirmedExit>) -> Result<Value> {
	let exit = terminal.map(|terminal| &terminal.receipt);
	if let Some(e) = exit {
		if e.job_id != r.job_id || e.nonce != r.nonce {
			bail!("exit identity mismatch");
		}
		if r.terminal_protocol.is_some() && r.terminal_protocol != e.terminal_protocol {
			bail!("terminal protocol mismatch");
		}
		if e.terminal_protocol.is_some() && !terminal.is_some_and(|value| value.witnessed) {
			bail!("new terminal receipt is not witnessed");
		}
		validate_capture(e, e.terminal_protocol)?;
	}
	// Old receipts and PTYs have no file-capture evidence. A current file EOF
	// must never synthesize complete/durable output for either of them.
	Ok(json!({
		"terminal_receipt_observed":exit.is_some(),
		"terminal_publication":match terminal {
			Some(value) if value.witnessed => "confirmed",
			Some(_) => "legacy_unknown",
			None => "not_observed",
		},
		"terminal_publication_confirmed":terminal.filter(|value| value.witnessed).map(|_| true),
		"output_complete":exit.and_then(|e| e.output_complete),
		"output_durable":exit.and_then(|e| e.output_durable),
		"capture":exit.and_then(|e| e.capture.as_ref()),
	}))
}

fn publication_pending(r: &Record, reason: &str) -> Result<Value> {
	let mut value = capture_metadata(r, None)?;
	value["job_id"] = json!(r.job_id);
	value["state"] = json!("finalizing");
	value["outcome"] = json!("unknown");
	value["status_authoritative"] = json!(false);
	value["automatic_retry"] = json!(false);
	value["terminal_receipt_observed"] = json!(true);
	value["terminal_publication"] = json!("publication_pending");
	value["terminal_publication_confirmed"] = json!(false);
	value["reason"] = json!(reason);
	value["backend"] = json!("systemd_system");
	Ok(value)
}

fn completed_result(r: &Record, terminal: &ConfirmedExit) -> Result<Value> {
	let e = &terminal.receipt;
	let mut value = capture_metadata(r, Some(terminal))?;
	let state = if e.timed_out {
		"timed_out"
	} else if e.cancelled || (e.terminal_protocol.is_none() && r.launch_state == "cancelled") {
		"cancelled"
	} else if e.exit_code == 0 {
		if e.capture.is_some()
			&& (e.output_complete != Some(true) || e.output_durable != Some(true))
		{
			"failed"
		} else {
			"succeeded"
		}
	} else {
		"failed"
	};
	value["job_id"] = json!(r.job_id);
	value["state"] = json!(state);
	value["exit_code"] = json!(e.exit_code);
	if state == "failed" && e.exit_code == 0 {
		value["reason"] = json!("output_capture_incomplete_or_not_durable");
	}
	value["timed_out"] = json!(e.timed_out);
	value["cancelled"] = json!(state == "cancelled");
	value["automatic_retry"] = json!(false);
	value["backend"] = json!("systemd_system");
	Ok(value)
}

fn completion_at(r: &Record, directory: &Path) -> Result<Option<Value>> {
	match observe_terminal(r, directory)? {
		TerminalObservation::Missing => Ok(None),
		TerminalObservation::Pending(reason) => Ok(Some(publication_pending(r, reason)?)),
		TerminalObservation::Confirmed(terminal) => Ok(Some(completed_result(r, &terminal)?)),
	}
}

fn missing_terminal_result(r: &Record, state: &str, reason: &str) -> Result<Value> {
	let mut value = capture_metadata(r, None)?;
	value["job_id"] = json!(r.job_id);
	value["state"] = json!(state);
	value["reason"] = json!(reason);
	value["outcome"] = json!("unknown");
	value["status_authoritative"] = json!(false);
	value["automatic_retry"] = json!(false);
	value["terminal_publication_confirmed"] = json!(false);
	value["backend"] = json!("systemd_system");
	Ok(value)
}

fn status_at(
	r: &mut Record,
	directory: &Path,
	current_boot: impl FnOnce() -> Result<String>,
	probe: impl FnOnce(&mut Record) -> Result<(BTreeMap<String, String>, bool)>,
) -> Result<Value> {
	// Completed results remain valid across a target reboot. Only in-flight
	// processes are lost; never replay a completed job to reconstruct its state.
	if let Some(completed) = completion_at(r, directory)? {
		return Ok(completed);
	}
	if r.boot_id != current_boot()? {
		if let Some(completed) = completion_at(r, directory)? {
			return Ok(completed);
		}
		if r.terminal_protocol.is_some() {
			return missing_terminal_result(r, "lost", "target_reboot");
		}
		return Ok(
			json!({"job_id":r.job_id,"state":"lost","reason":"target_reboot","backend":"systemd_system"}),
		);
	}
	// The supervisor may publish its receipt while systemctl is observing the
	// unit, including a --collect removal or a failed observation. Re-read the
	// owned receipt before interpreting that snapshot or propagating its error.
	let observation = probe(r);
	if let Some(completed) = completion_at(r, directory)? {
		return Ok(completed);
	}
	let (p, present) = observation?;
	let state = if r.launch_state == "cancelled" {
		"cancelled"
	} else if present
		&& ["active", "activating", "deactivating"]
			.contains(&p.get("ActiveState").map(String::as_str).unwrap_or(""))
	{
		"running"
	} else if present && p.get("ActiveState").map(String::as_str) == Some("failed") {
		"failed"
	} else {
		"lost"
	};
	if r.terminal_protocol.is_some() && state != "running" {
		let mut value = missing_terminal_result(r, "finalizing", "terminal_receipt_missing")?;
		value["systemd"] = json!(p);
		value["launch_state"] = json!(r.launch_state);
		return Ok(value);
	}
	Ok(
		json!({"job_id":r.job_id,"state":state,"backend":"systemd_system","systemd":p,"launch_state":r.launch_state}),
	)
}

fn status(id: &str) -> Result<Value> {
	let mut r = load_record(id)?;
	status_at(&mut r, &data_dir(id), boot, |r| {
		let p = properties(r)?;
		let present = bind_invocation(r, &p)?;
		Ok((p, present))
	})
}
fn read_part(
	directory: &Path,
	name: &str,
	offset: u64,
	limit: u64,
	expected_saved: Option<u64>,
) -> Result<Value> {
	let mut f = match OpenOptions::new()
		.read(true)
		.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
		.open(directory.join(name))
	{
		Ok(f) => f,
		Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
			if expected_saved.is_some() {
				bail!("confirmed capture log is missing");
			}
			if offset != 0 {
				bail!("cursor exceeds absent log");
			}
			return Ok(
				json!({"offset":0,"next_offset":0,"size":0,"eof":true,"text":"","bytes_hex":""}),
			);
		}
		Err(e) => return Err(e.into()),
	};
	let m = f.metadata()?;
	if !m.is_file() {
		bail!("refusing non-regular log");
	}
	let size = m.len();
	if expected_saved.is_some_and(|saved| saved != size) {
		bail!("confirmed capture log length differs from saved bytes");
	}
	if offset > size {
		bail!("cursor exceeds log length; refusing silent rewind");
	}
	f.seek(SeekFrom::Start(offset))?;
	let mut bytes = Vec::new();
	let limit = limit.clamp(1, 16384);
	Read::by_ref(&mut f).take(limit).read_to_end(&mut bytes)?;
	if expected_saved.is_some()
		&& (f.metadata()?.len() != size || bytes.len() as u64 != limit.min(size - offset))
	{
		bail!("confirmed capture log changed while reading");
	}
	let hex = bytes_hex(&bytes);
	Ok(
		json!({"offset":offset,"next_offset":offset+bytes.len()as u64,"size":size,"eof":offset+bytes.len()as u64>=size,"text":String::from_utf8_lossy(&bytes),"bytes_hex":hex,"log_limit_bytes":LOG_MAX}),
	)
}

fn read_output(r: &Record, stdout_offset: u64, stderr_offset: u64, limit: u64) -> Result<Value> {
	read_output_at(r, &data_dir(&r.job_id), stdout_offset, stderr_offset, limit)
}

fn read_output_at(
	r: &Record,
	directory: &Path,
	stdout_offset: u64,
	stderr_offset: u64,
	limit: u64,
) -> Result<Value> {
	let observation = observe_terminal(r, directory)?;
	let (mut value, capture) = match &observation {
		TerminalObservation::Missing => (capture_metadata(r, None)?, None),
		TerminalObservation::Pending(reason) => (publication_pending(r, reason)?, None),
		TerminalObservation::Confirmed(terminal) => (
			capture_metadata(r, Some(terminal))?,
			terminal.receipt.capture.as_ref(),
		),
	};
	value["job_id"] = json!(r.job_id);
	value["stdout"] = read_part(
		directory,
		"stdout.log",
		stdout_offset,
		limit,
		capture.map(|c| c.stdout.saved),
	)?;
	value["stderr"] = read_part(
		directory,
		"stderr.log",
		stderr_offset,
		limit,
		capture.map(|c| c.stderr.saved),
	)?;
	Ok(value)
}
fn cancel(id: &str) -> Result<Value> {
	let _lock = Lock::acquire()?;
	let mut r = load_record(id)?;
	if r.boot_id != boot()? {
		bail!("target rebooted: refusing to cancel old job");
	}
	let p = properties(&r)?;
	if !bind_invocation(&mut r, &p)?
		|| !["active", "activating", "deactivating"]
			.contains(&p.get("ActiveState").map(String::as_str).unwrap_or(""))
	{
		return Ok(json!({"job_id":id,"result":"already_exited"}));
	}
	let out = Command::new("/usr/bin/systemctl")
		.args(["stop", "--", &r.unit])
		.output()?;
	if !out.status.success() {
		bail!(
			"owned unit stop failed: {}",
			String::from_utf8_lossy(&out.stderr)
		);
	}
	r.launch_state = "cancelled".to_owned();
	atomic(&record_path(id), &r)?;
	Ok(json!({"job_id":id,"result":"stop_requested","invocation_id":r.invocation_id}))
}
fn start(mut q: Request, interactive: bool) -> Result<Value> {
	let p = policy()?;
	validate(&mut q, &p)?;
	let lock = Lock::acquire()?;
	let path = record_path(&q.job_id);
	let hash = digest(&q)?;
	if path.exists() {
		let r = load_record(&q.job_id)?;
		if hash != r.request_digest {
			bail!("job ID already bound to a different request");
		}
		return Ok(
			json!({"ok":true,"reused_remote":true,"backend":"systemd_system","status":status(&q.job_id)?}),
		);
	}
	if fs::read_dir(ROOT)?
		.filter_map(|e| e.ok())
		.filter(|e| e.path().is_dir())
		.count()
		>= 128
	{
		bail!("retained job limit reached; administrator must archive completed jobs");
	}
	let dir = path.parent().context("record directory")?;
	fs::create_dir_all(dir)?;
	fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
	let nonce = fs::read_to_string("/proc/sys/kernel/random/uuid")?
		.trim()
		.to_owned();
	let mut r = Record {
		job_id: q.job_id.clone(),
		unit: format!("hepta-job-{}.service", q.job_id),
		request_digest: hash,
		boot_id: boot()?,
		nonce: nonce.clone(),
		invocation_id: None,
		launch_state: "pending".to_owned(),
		created_unix_ms: now(),
		terminal_protocol: Some(TerminalProtocol::for_interactive(interactive)),
	};
	let spec_path = dir.join("spec.json");
	atomic(
		&spec_path,
		&Spec {
			request: q.clone(),
			nonce,
			boot_id: r.boot_id.clone(),
			workspace: p.workspace.to_string_lossy().into_owned(),
			terminal_protocol: r.terminal_protocol,
		},
	)?;
	atomic(&path, &r)?;
	let mut cmd = Command::new("/usr/bin/systemd-run");
	cmd.args(["--quiet", "--collect", "--unit", &r.unit]);
	if interactive {
		cmd.args(["--pty", "--wait"]);
	}
	let props=vec![
 format!("Description=Hepta Runtime {} {}",r.job_id,r.nonce),"DynamicUser=yes".to_owned(),
        "Slice=hepta-runtime-jobs.slice".to_owned(),"SupplementaryGroups=hepta-workspace".to_owned(),
 format!("StateDirectory=hepta-job-{}",q.job_id),"StateDirectoryMode=0700".to_owned(),format!("LoadCredential=spec:{}",spec_path.display()),
 format!("BindPaths={}:/workspace",p.workspace.display()),"WorkingDirectory=/workspace".to_owned(),
 "InaccessiblePaths=-/var/lib/hepta-runtime -/etc/hepta-runtime -/run/user -/run/dbus -/run/systemd/private -/run/docker.sock -/run/libvirt".to_owned(),
 "ProtectHome=yes".to_owned(),"ProtectSystem=strict".to_owned(),"PrivateTmp=yes".to_owned(),"PrivateDevices=yes".to_owned(),"NoNewPrivileges=yes".to_owned(),"CapabilityBoundingSet=".to_owned(),"RestrictSUIDSGID=yes".to_owned(),"ProtectKernelTunables=yes".to_owned(),"ProtectKernelModules=yes".to_owned(),"ProtectControlGroups=yes".to_owned(),"RestrictRealtime=yes".to_owned(),"LockPersonality=yes".to_owned(),"ProtectProc=invisible".to_owned(),"KillMode=control-group".to_owned(),"TimeoutStopSec=3s".to_owned(),"TasksMax=64".to_owned(),"UMask=0007".to_owned(),"MemorySwapMax=0".to_owned(),
 format!("CPUQuota={}%",q.cpu_quota_percent.unwrap_or(p.max_cpu_percent)),format!("MemoryMax={}",q.memory_max_bytes.unwrap_or(p.max_memory_bytes)),format!("Nice={}",q.nice.unwrap_or(10)),format!("RuntimeMaxSec={}s",q.timeout_seconds.unwrap_or(p.max_timeout_seconds)+10)];
	for prop in props {
		cmd.args(["--property", &prop]);
	}
	if !p.allow_network {
		cmd.args([
			"--property",
			"PrivateNetwork=yes",
			"--property",
			"RestrictAddressFamilies=AF_UNIX AF_NETLINK",
		]);
	}
	cmd.args([
		"--",
		HELPER,
		if interactive {
			"supervise-pty"
		} else {
			"supervise"
		},
		&q.job_id,
	]);
	let mut pty_child: Option<Child> = None;
	dispatch_after_launch_namespace_sync(Path::new(ROOT), || {
		if interactive {
			signals();
			pty_child = Some(cmd.spawn()?);
			for _ in 0..100 {
				if properties(&r)?
					.get("InvocationID")
					.is_some_and(|v| !v.is_empty())
				{
					break;
				}
				std::thread::sleep(Duration::from_millis(10));
			}
		} else {
			let out = cmd.output()?;
			if !out.status.success() {
				r.launch_state = "launch_failed".to_owned();
				atomic(&path, &r)?;
				bail!(
					"systemd launch failed: {}",
					String::from_utf8_lossy(&out.stderr)
				);
			}
		}
		Ok(())
	})?;
	r.launch_state = "launched".to_owned();
	let props = properties(&r)?;
	let _ = bind_invocation(&mut r, &props)?;
	atomic(&path, &r)?;
	drop(lock);
	if let Some(mut child) = pty_child {
		loop {
			if let Some(e) = child.try_wait()? {
				return Ok(json!({"pty_exit_code":e.code()}));
			}
			if STOP.load(Ordering::SeqCst) {
				let _ = cancel(&q.job_id);
				let _ = child.kill();
				let _ = child.wait();
				break;
			}
			std::thread::sleep(Duration::from_millis(25));
		}
	}
	Ok(
		json!({"ok":true,"backend":"systemd_system","unit":r.unit,"invocation_id":r.invocation_id,"workspace":"/workspace"}),
	)
}
fn capture_pipe() -> std::io::Result<(File, File)> {
	let mut fds = [-1; 2];
	#[cfg(target_os = "linux")]
	let result = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
	#[cfg(not(target_os = "linux"))]
	let result = unsafe { libc::pipe(fds.as_mut_ptr()) };
	if result != 0 {
		return Err(std::io::Error::last_os_error());
	}
	// Own both descriptors before any fallible setup. Only the read end is
	// nonblocking; workload stdout/stderr preserve ordinary blocking writes.
	let reader = unsafe { File::from_raw_fd(fds[0]) };
	let writer = unsafe { File::from_raw_fd(fds[1]) };
	#[cfg(not(target_os = "linux"))]
	for fd in [reader.as_raw_fd(), writer.as_raw_fd()] {
		let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
		if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
			return Err(std::io::Error::last_os_error());
		}
	}
	let flags = unsafe { libc::fcntl(reader.as_raw_fd(), libc::F_GETFL) };
	if flags < 0
		|| unsafe { libc::fcntl(reader.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
	{
		return Err(std::io::Error::last_os_error());
	}
	Ok((reader, writer))
}

struct CaptureStream {
	reader: Option<File>,
	writer: File,
	buffer: [u8; LOG_BUFFER],
	report: StreamCapture,
}
impl CaptureStream {
	fn new(reader: File, writer: File) -> Self {
		Self {
			reader: Some(reader),
			writer,
			buffer: [0; LOG_BUFFER],
			report: StreamCapture::default(),
		}
	}
	fn fail_read(&mut self, error: String) {
		self.report.read_error.get_or_insert(error);
		self.reader.take();
	}
	fn read_ready(&mut self) {
		// A hot stdout cannot starve stderr, cancellation or the child timeout.
		for _ in 0..LOG_READS_PER_TURN {
			let Some(reader) = self.reader.as_mut() else {
				break;
			};
			let n = match reader.read(&mut self.buffer) {
				Ok(0) => {
					self.report.eof = true;
					self.reader.take();
					break;
				}
				Ok(n) => n,
				Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
				Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
				Err(error) => {
					self.fail_read(error.to_string());
					break;
				}
			};
			let Some(seen) = self.report.seen.checked_add(n as u64) else {
				self.fail_read("observed output byte count overflow".into());
				break;
			};
			self.report.seen = seen;
			self.report.truncated |= seen > LOG_MAX;
			let keep = if self.report.write_error.is_none() {
				(LOG_MAX - self.report.saved).min(n as u64) as usize
			} else {
				0
			};
			let mut written = 0;
			while written < keep {
				match self.writer.write(&self.buffer[written..keep]) {
					Ok(0) => {
						self.report.write_error = Some("output write made no progress".into());
						break;
					}
					Ok(bytes) => {
						written += bytes;
						self.report.saved += bytes as u64;
					}
					Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
					Err(error) => {
						self.report.write_error = Some(error.to_string());
						break;
					}
				}
			}
		}
	}
	fn expire(&mut self) {
		if self.reader.take().is_some() {
			self.report.drain_timeout = true;
		}
	}
	fn finish(mut self) -> StreamCapture {
		self.reader.take();
		match self.writer.sync_all() {
			Ok(()) => self.report.synced = true,
			Err(error) => self.report.sync_error = Some(error.to_string()),
		}
		// No capture worker survives this close or the terminal publication.
		drop(self.writer);
		self.report
	}
}

struct Capture {
	streams: [CaptureStream; 2],
}
impl Capture {
	fn prepare(command: &mut Command, state: &Path) -> Result<Self> {
		let log = |name: &str| {
			OpenOptions::new()
				.write(true)
				.create_new(true)
				.mode(0o600)
				.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
				.open(state.join(name))
		};
		let stdout = log("stdout.log").context("create original stdout log before spawn")?;
		let stderr = log("stderr.log").context("create original stderr log before spawn")?;
		let (out_reader, out_writer) = capture_pipe()?;
		let (err_reader, err_writer) = capture_pipe()?;
		command
			.stdout(Stdio::from(out_writer))
			.stderr(Stdio::from(err_writer));
		Ok(Self {
			streams: [
				CaptureStream::new(out_reader, stdout),
				CaptureStream::new(err_reader, stderr),
			],
		})
	}
	fn finished(&self) -> bool {
		self.streams.iter().all(|stream| stream.reader.is_none())
	}
	fn poll(&mut self, wait: Duration) {
		let mut fds = self.streams.each_ref().map(|stream| libc::pollfd {
			fd: stream.reader.as_ref().map_or(-1, AsRawFd::as_raw_fd),
			events: libc::POLLIN,
			revents: 0,
		});
		let result = unsafe {
			libc::poll(
				fds.as_mut_ptr(),
				fds.len() as _,
				wait.as_millis().min(i32::MAX as u128) as i32,
			)
		};
		if result < 0 {
			let error = std::io::Error::last_os_error();
			if error.kind() != std::io::ErrorKind::Interrupted {
				for stream in &mut self.streams {
					if stream.reader.is_some() {
						stream.fail_read(format!("poll: {error}"));
					}
				}
			}
			return;
		}
		for (stream, fd) in self.streams.iter_mut().zip(fds) {
			if fd.revents & libc::POLLNVAL != 0 {
				stream.fail_read("poll rejected the original output descriptor".into());
			} else if fd.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
				// HUP may arrive together with the final bytes; read through EOF.
				stream.read_ready();
			}
		}
	}
	fn expire(&mut self) {
		for stream in &mut self.streams {
			stream.expire();
		}
	}
	fn finish(self) -> OutputCapture {
		let [stdout, stderr] = self.streams;
		OutputCapture {
			stdout: stdout.finish(),
			stderr: stderr.finish(),
		}
	}
}

struct OriginalChild {
	child: Child,
	reaped: bool,
}
impl OriginalChild {
	fn try_wait(&mut self) -> std::io::Result<Option<ExitStatus>> {
		let result = self.child.try_wait()?;
		self.reaped |= result.is_some();
		Ok(result)
	}
	fn stop_and_wait(&mut self) -> std::io::Result<ExitStatus> {
		if let Some(status) = self.try_wait()? {
			return Ok(status);
		}
		// The original Child has not been reaped. Never signal a saved PID or
		// a group after observing its leader's exit.
		if let Err(error) = self.child.kill() {
			if let Some(status) = self.try_wait()? {
				return Ok(status);
			}
			return Err(error);
		}
		let status = self.child.wait()?;
		self.reaped = true;
		Ok(status)
	}
}
impl Drop for OriginalChild {
	fn drop(&mut self) {
		if !self.reaped {
			// An unconfirmed original wait cannot authorize a guessed signal.
			if let Ok(None) = self.try_wait() {
				let _ = self.stop_and_wait();
			}
		}
	}
}

fn spawn_supervised(
	command: &mut Command,
	state: &Path,
	interactive: bool,
) -> Result<(OriginalChild, Option<Capture>)> {
	let capture = if interactive {
		None
	} else {
		Some(Capture::prepare(command, state)?)
	};
	let result = command.spawn();
	if capture.is_some() {
		// Command retains explicitly supplied write ends even after spawn.
		// Close those parent copies now so only workload writers control EOF.
		command.stdout(Stdio::null()).stderr(Stdio::null());
	}
	Ok((
		OriginalChild {
			child: result?,
			reaped: false,
		},
		capture,
	))
}

struct Supervision {
	status: ExitStatus,
	timed_out: bool,
	cancelled: bool,
	capture: Option<OutputCapture>,
}

fn finish_supervision(
	mut child: OriginalChild,
	mut capture: Option<Capture>,
	timeout: Duration,
	cancel_requested: impl Fn() -> bool,
) -> Result<Supervision> {
	let begin = Instant::now();
	let mut status = None;
	let mut timed_out = false;
	let mut cancelled = false;
	let mut drain_until = None;
	loop {
		if status.is_none() {
			status = child.try_wait()?;
			if status.is_none() {
				cancelled |= cancel_requested();
				timed_out = begin.elapsed() >= timeout;
				if cancelled || timed_out {
					status = Some(child.stop_and_wait()?);
				}
			}
			if status.is_some() {
				drain_until = Some(Instant::now() + OUTPUT_DRAIN);
			}
		}
		if status.is_some() && capture.as_ref().is_none_or(Capture::finished) {
			break;
		}
		if drain_until.is_some_and(|deadline| Instant::now() >= deadline) {
			if let Some(output) = &mut capture {
				output.expire();
			}
			break;
		}
		let wait = drain_until.map_or(OBSERVATION_POLL, |deadline| {
			deadline
				.saturating_duration_since(Instant::now())
				.min(OBSERVATION_POLL)
		});
		if let Some(output) = &mut capture {
			output.poll(wait);
		} else {
			std::thread::sleep(wait);
		}
	}
	// The pipe deadline never renews. Synchronization is a real filesystem
	// barrier, not a cancellable background task or a claim of bounded disk I/O.
	Ok(Supervision {
		status: status.context("original child exit unavailable")?,
		timed_out,
		cancelled: cancelled || cancel_requested(),
		capture: capture.map(Capture::finish),
	})
}
fn supervise(id: &str, interactive: bool) -> Result<()> {
	if unsafe { libc::geteuid() } == 0 {
		bail!("supervisor must never execute as root");
	}
	signals();
	let spec: Spec =
		json_file(&PathBuf::from(std::env::var("CREDENTIALS_DIRECTORY")?).join("spec"))?;
	if spec.request.job_id != id || spec.boot_id != boot()? {
		bail!("supervisor identity mismatch");
	}
	let protocol = TerminalProtocol::for_spec(spec.terminal_protocol, interactive)?;
	// An old Spec remains executable only through its existing launch path;
	// this upgrade emits a witnessed receipt without issuing a new dispatch.
	let state = PathBuf::from(std::env::var("STATE_DIRECTORY")?);
	let q = spec.request;
	let cwd =
		Path::new(q.cwd.as_deref().unwrap_or(&spec.workspace)).strip_prefix(&spec.workspace)?;
	let exe = if Path::new(&q.executable).starts_with(&spec.workspace) {
		Path::new("/workspace").join(Path::new(&q.executable).strip_prefix(&spec.workspace)?)
	} else {
		PathBuf::from(&q.executable)
	};
	let mut cmd = Command::new(exe);
	cmd.args(&q.args)
		.current_dir(Path::new("/workspace").join(cwd))
		.env_clear()
		.env("PATH", "/usr/bin:/bin")
		.env("HOME", "/tmp")
		.env("LANG", "C.UTF-8")
		.env("TERM", "xterm-256color")
		.envs(&q.env)
		.env("HEPTA_RUNTIME_JOB_ID", id);
	if interactive {
		cmd.stdin(Stdio::inherit())
			.stdout(Stdio::inherit())
			.stderr(Stdio::inherit());
	} else {
		let input = state.join("stdin.bin");
		if let Some(text) = &q.stdin {
			fs::write(&input, text)?;
			cmd.stdin(File::open(&input)?);
		} else {
			cmd.stdin(Stdio::null());
		}
	}
	let (child, capture) = match spawn_supervised(&mut cmd, &state, interactive) {
		Ok(started) => started,
		Err(e) => {
			let capture = (!interactive).then(|| OutputCapture::not_started(&format!("{e:#}")));
			publish_terminal(
				&state,
				&Exit::new(id, spec.nonce, 127, false, false, protocol, capture),
			)?;
			return Err(e);
		}
	};
	let outcome = finish_supervision(
		child,
		capture,
		Duration::from_secs(q.timeout_seconds.unwrap_or(3600)),
		|| STOP.load(Ordering::SeqCst),
	)?;
	let code = if outcome.timed_out {
		124
	} else {
		outcome
			.status
			.code()
			.unwrap_or(128 + outcome.status.signal().unwrap_or(0))
	};
	let receipt = Exit::new(
		id,
		spec.nonce,
		code,
		outcome.timed_out,
		outcome.cancelled,
		protocol,
		outcome.capture,
	);
	publish_terminal(&state, &receipt)?;
	supervisor_capture_result(&receipt)?;
	Ok(())
}

fn supervisor_capture_result(receipt: &Exit) -> Result<()> {
	if receipt.exit_code == 0
		&& receipt.terminal_protocol == Some(TerminalProtocol::CapturedV1)
		&& (receipt.output_complete != Some(true) || receipt.output_durable != Some(true))
	{
		bail!("workload exited with code 0 but output capture was incomplete or not durable; retained original exit, no retry");
	}
	Ok(())
}
fn run() -> Result<()> {
	let args: Vec<String> = std::env::args().collect();
	if args.len() == 3 && ["supervise", "supervise-pty"].contains(&args[1].as_str()) {
		return supervise(&args[2], args[1] == "supervise-pty");
	}
	if args.len() != 1 || unsafe { libc::geteuid() } != 0 {
		bail!("control requires exact no-argument sudo capability");
	}
	let mut input = Vec::new();
	let mut byte = [0u8; 1];
	let mut stdin = std::io::stdin();
	loop {
		if stdin.read(&mut byte)? == 0 || byte[0] == b'\n' {
			break;
		}
		input.push(byte[0]);
		if input.len() as u64 > INPUT_MAX {
			bail!("request too large");
		}
	}
	let q: Request = serde_json::from_slice(&input)?;
	if !safe_id(&q.job_id) {
		bail!("invalid owned job ID");
	}
	let v = match q.op.as_str() {
		"start" => start(q, false)?,
		"pty" => start(q, true)?,
		"status" => {
			let _lock = Lock::acquire()?;
			status(&q.job_id)?
		}
		"read" => {
			let record = load_record(&q.job_id)?;
			read_output(
				&record,
				q.stdout_offset,
				q.stderr_offset,
				q.limit.unwrap_or(16384),
			)?
		}
		"cancel" => cancel(&q.job_id)?,
		_ => bail!("unknown closed capability"),
	};
	println!("{}", serde_json::to_string(&v)?);
	Ok(())
}
fn main() {
	if let Err(e) = run() {
		eprintln!("jobctl: {e:#}");
		std::process::exit(1);
	}
}
#[cfg(test)]
#[path = "../jobctl_tests.rs"]
mod tests;
