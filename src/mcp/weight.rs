// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Weight experiment sessions over the existing durable process owner.
//!
//! Session records bind policy, request bytes and original job references. They
//! are a coordinator index, not another process executor or promotion authority.
//! Models remain in a worker; bounded clients communicate over its Unix socket.

use anyhow::{anyhow, bail, Context, Result};
use rmcp::schemars;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::runtime::config::{runtime_config, RuntimeConfig};
use super::runtime::jobs::{
	self, ProcessCancelParams, ProcessReadParams, ProcessStartParams, ProcessWaitParams,
};
use super::weight_config::WeightWorkerProfile;

const MAX_REQUEST_BYTES: usize = 64 * 1024;
const MAX_RECORD_BYTES: usize = 128 * 1024;
const MAX_STATE_BYTES: u64 = 64 * 1024 * 1024;
static STAGING_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WeightOpenParams {
	/// Administrator-configured worker profile, never an executable or SSH target.
	pub profile: String,
	/// Stable identity. Reuse exactly after a timeout; changed input is rejected.
	pub idempotency_key: String,
	/// Provider-specific open parameters. Output roots and budgets are policy-owned.
	pub params: Value,
}

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WeightOperation {
	Inspect,
	Probe,
	Intervene,
	Analyze,
	Patch,
	Seal,
	Query,
}

#[derive(Clone, Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WeightCallParams {
	pub session_id: String,
	/// Stable per-session request identity; different payloads cannot reuse it.
	pub request_id: String,
	pub op: WeightOperation,
	pub params: Value,
}

#[derive(Clone, Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WeightStatusParams {
	pub session_id: String,
	/// Omit for the resident worker; otherwise observe the original request job.
	pub request_id: Option<String>,
	/// Bounded owner observation only, at most 30 seconds; never a relaunch.
	pub wait_seconds: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WeightReadParams {
	pub session_id: String,
	pub request_id: Option<String>,
	pub stdout_offset: Option<u64>,
	pub stderr_offset: Option<u64>,
	/// Byte limit per stream, capped at 64 KiB; continue with returned offsets.
	pub limit: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WeightCloseParams {
	pub session_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct SessionIntent {
	schema: String,
	session_id: String,
	profile_name: String,
	profile_digest: String,
	profile: WeightWorkerProfile,
	request_digest: String,
	worker_request: Value,
	socket_path: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct JobBinding {
	schema: String,
	session_id: String,
	request_digest: String,
	host: String,
	job_id: String,
}

fn sha(bytes: &[u8]) -> String {
	Sha256::digest(bytes)
		.iter()
		.map(|byte| format!("{byte:02x}"))
		.collect()
}
fn digest(value: &impl Serialize) -> Result<String> {
	Ok(sha(&serde_json::to_vec(value)?))
}

fn check_request_id(value: &str) -> Result<()> {
	if value.is_empty()
		|| value.len() > 128
		|| !value
			.bytes()
			.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
	{
		bail!("request identity must be 1..128 ASCII letters, digits, dot, underscore or dash");
	}
	Ok(())
}

fn check_session_id(value: &str) -> Result<()> {
	if value.len() != 27
		|| !value.starts_with("ws_")
		|| !value[3..]
			.bytes()
			.all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
	{
		bail!("invalid weight session identity");
	}
	Ok(())
}

fn bounded_request(value: &Value) -> Result<String> {
	let text = serde_json::to_string(value)?;
	if text.len() > MAX_REQUEST_BYTES {
		bail!("weight request exceeds 64 KiB; use artifact references");
	}
	Ok(text + "\n")
}

fn bounded_uint(
	params: &Value,
	name: &str,
	default: u64,
	minimum: u64,
	maximum: u64,
) -> Result<u64> {
	let value = match params.get(name) {
		Some(value) => value
			.as_u64()
			.ok_or_else(|| anyhow!("{name} must be an unsigned integer"))?,
		None => default.min(maximum),
	};
	if !(minimum..=maximum).contains(&value) {
		bail!("{name} is outside the configured budget");
	}
	Ok(value)
}

fn prepare_intent(config: &RuntimeConfig, input: WeightOpenParams) -> Result<SessionIntent> {
	check_request_id(&input.idempotency_key)?;
	let profile = config
		.weight_workers
		.get(&input.profile)
		.ok_or_else(|| anyhow!("unknown or disabled weight worker profile"))?
		.clone();
	let mut params = input.params;
	let object = params
		.as_object()
		.ok_or_else(|| anyhow!("open params must be an object"))?;
	for name in [
		"output_root",
		"input_roots",
		"artifact_root",
		"run_dir",
		"socket",
		"session_id",
	] {
		if object.contains_key(name) {
			bail!("{name} is owned by the configured worker profile");
		}
	}
	let provider = object
		.get("provider")
		.and_then(Value::as_str)
		.ok_or_else(|| anyhow!("open requires a provider name"))?;
	if !profile.allowed_providers.iter().any(|p| p == provider) {
		bail!("provider is not allowed by the worker profile");
	}
	let request_digest = digest(&json!({"profile":input.profile,"params":params}))?;
	let key_digest = digest(&json!({"profile":input.profile,"key":input.idempotency_key}))?;
	let session_id = format!("ws_{}", &key_digest[..24]);
	let session_dir = Path::new(&profile.session_root).join(&session_id);
	let socket_path = session_dir
		.join("worker.sock")
		.to_string_lossy()
		.into_owned();
	let timeout = bounded_uint(&params, "timeout_ms", 120_000, 1000, profile.max_request_ms)?;
	let idle = bounded_uint(
		&params,
		"idle_timeout_s",
		900,
		1,
		profile.max_lifetime_seconds.min(3600),
	)?;
	let threads = bounded_uint(
		&params,
		"cpu_threads",
		2,
		1,
		u64::from(profile.max_cpu_threads),
	)?;
	let memory = bounded_uint(
		&params,
		"max_memory_bytes",
		profile.max_memory_bytes,
		256 * 1024 * 1024,
		profile.max_memory_bytes,
	)?;
	let object = params
		.as_object_mut()
		.ok_or_else(|| anyhow!("open params must be an object"))?;
	object.insert("output_root".into(), json!(session_dir.join("artifacts")));
	object.insert("input_roots".into(), json!(profile.input_roots));
	object.insert("timeout_ms".into(), json!(timeout));
	object.insert("idle_timeout_s".into(), json!(idle));
	object.insert("cpu_threads".into(), json!(threads));
	object.insert("max_memory_bytes".into(), json!(memory));
	let worker_request = json!({"id":"open","op":"open","session_id":session_id,"params":params});
	bounded_request(&worker_request)?;
	Ok(SessionIntent {
		schema: "hepta.weight.session.v1".into(),
		session_id,
		profile_name: input.profile,
		profile_digest: digest(&profile)?,
		profile,
		request_digest,
		worker_request,
		socket_path,
	})
}

fn thread_env(threads: u64, worker_sha256: &str) -> BTreeMap<String, String> {
	let mut env = BTreeMap::new();
	for key in [
		"OMP_NUM_THREADS",
		"MKL_NUM_THREADS",
		"OPENBLAS_NUM_THREADS",
		"GOTO_NUM_THREADS",
		"NUMEXPR_NUM_THREADS",
	] {
		env.insert(key.into(), threads.to_string());
	}
	env.insert("PYTHONUNBUFFERED".into(), "1".into());
	env.insert("PYTHONDONTWRITEBYTECODE".into(), "1".into());
	env.insert("HEPTA_WEIGHT_WORKER_SHA256".into(), worker_sha256.into());
	env
}

fn worker_start(intent: &SessionIntent) -> Result<ProcessStartParams> {
	let p = &intent.profile;
	let threads = intent.worker_request["params"]["cpu_threads"]
		.as_u64()
		.ok_or_else(|| anyhow!("stored thread budget missing"))?;
	Ok(ProcessStartParams {
		host: p.host.clone(),
		executable: p.python_executable.clone(),
		args: with_package_pin(
			p,
			vec![
				p.worker_path.clone(),
				"--serve".into(),
				"--socket".into(),
				intent.socket_path.clone(),
				"--session-id".into(),
				intent.session_id.clone(),
				"--expected-worker-sha256".into(),
				p.worker_sha256.clone(),
				"--max-request-ms".into(),
				p.max_request_ms.to_string(),
				"--lifetime-s".into(),
				p.max_lifetime_seconds.to_string(),
			],
		),
		cwd: Some(p.session_root.clone()),
		env: thread_env(threads, &p.worker_sha256),
		stdin: Some(bounded_request(&intent.worker_request)?),
		timeout_seconds: Some(p.max_lifetime_seconds),
		idempotency_key: Some(format!("weight-worker-{}", intent.session_id)),
		nice: Some(10),
		cpu_quota_percent: Some((threads * 100) as u16),
		memory_max_bytes: Some(p.max_memory_bytes),
	})
}

fn client_start(
	intent: &SessionIntent,
	request: &Value,
	request_id: &str,
	timeout: u64,
) -> Result<ProcessStartParams> {
	let p = &intent.profile;
	let (executable, args) = if let Some(client) = &p.native_client {
		(
			client.executable.clone(),
			with_package_pin(
				p,
				vec![
					"weight-client".into(),
					"--socket".into(),
					intent.socket_path.clone(),
					"--session-id".into(),
					intent.session_id.clone(),
					"--timeout-ms".into(),
					timeout.to_string(),
					"--connect-timeout-ms".into(),
					"30000".into(),
					"--worker-path".into(),
					p.worker_path.clone(),
					"--expected-worker-sha256".into(),
					p.worker_sha256.clone(),
					"--expected-client-sha256".into(),
					client.sha256.clone(),
				],
			),
		)
	} else {
		(
			p.python_executable.clone(),
			with_package_pin(
				p,
				vec![
					p.worker_path.clone(),
					"--client".into(),
					"--socket".into(),
					intent.socket_path.clone(),
					"--timeout-ms".into(),
					timeout.to_string(),
					"--connect-timeout-ms".into(),
					"30000".into(),
					"--expected-worker-sha256".into(),
					p.worker_sha256.clone(),
				],
			),
		)
	};
	let mut env = thread_env(1, &p.worker_sha256);
	if p.native_client.is_some() {
		// A transport helper does not need one Tokio worker for every host CPU.
		env.insert("TOKIO_WORKER_THREADS".into(), "1".into());
	}
	Ok(ProcessStartParams {
		host: p.host.clone(),
		executable,
		args,
		cwd: Some(p.session_root.clone()),
		env,
		stdin: Some(bounded_request(request)?),
		// Native admission bounds stdin (5s), code pins (30s), connection (30s)
		// and the exchange separately. Python compatibility keeps its old job spec.
		timeout_seconds: Some(
			timeout.div_ceil(1000) + if p.native_client.is_some() { 75 } else { 40 },
		),
		idempotency_key: Some(format!(
			"weight-call-{}-{}",
			intent.session_id,
			&sha(request_id.as_bytes())[..24]
		)),
		nice: Some(10),
		cpu_quota_percent: Some(50),
		memory_max_bytes: Some(512 * 1024 * 1024),
	})
}

fn with_package_pin(profile: &WeightWorkerProfile, mut args: Vec<String>) -> Vec<String> {
	if let Some(pin) = &profile.worker_package_sha256 {
		args.extend(["--expected-package-sha256".into(), pin.clone()]);
	}
	args
}

async fn private_directory(path: &Path) -> Result<()> {
	let mut builder = tokio::fs::DirBuilder::new();
	#[cfg(unix)]
	builder.mode(0o700);
	match builder.create(path).await {
		Ok(()) => {}
		Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
		Err(e) => return Err(e.into()),
	}
	let meta = tokio::fs::symlink_metadata(path).await?;
	if !meta.is_dir() || meta.file_type().is_symlink() {
		bail!("weight state directory must be a regular directory");
	}
	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt;
		if meta.permissions().mode() & 0o077 != 0 {
			bail!("weight state directory must be private");
		}
	}
	Ok(())
}

async fn state_directory() -> Result<PathBuf> {
	let path = runtime_config()?.state_dir.join("weight-sessions-v1");
	private_directory(&path).await?;
	Ok(path)
}

/// The index fence covers only receipt accounting/publication, never remote I/O.
async fn lock_state(root: &Path) -> Result<std::fs::File> {
	lock_named(root, "owner.lock").await
}

/// Distinct sessions proceed independently; one session preserves call/close order.
async fn lock_session(root: &Path, session: &str) -> Result<std::fs::File> {
	check_session_id(session)?;
	lock_named(root, &format!("{session}.lock")).await
}

async fn lock_named(root: &Path, name: &str) -> Result<std::fs::File> {
	let mut options = tokio::fs::OpenOptions::new();
	options.create(true).read(true).write(true);
	#[cfg(unix)]
	options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
	let file = options.open(root.join(name)).await?;
	let meta = file.metadata().await?;
	if !meta.is_file() {
		bail!("weight owner lock is not a regular file");
	}
	let file = file.into_std().await;
	#[cfg(unix)]
	{
		use std::os::fd::AsRawFd;
		let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
		loop {
			// Nonblocking flock does no path traversal and cannot block the executor.
			if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
				break;
			}
			let error = std::io::Error::last_os_error();
			if error.kind() != std::io::ErrorKind::WouldBlock {
				return Err(error.into());
			}
			if tokio::time::Instant::now() >= deadline {
				bail!("weight coordinator is busy; retry the same identity");
			}
			tokio::time::sleep(std::time::Duration::from_millis(10)).await;
		}
	}
	#[cfg(not(unix))]
	bail!("weight session ownership requires a qualified Unix host");
	Ok(file)
}

async fn read_record<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
	let mut options = tokio::fs::OpenOptions::new();
	options.read(true);
	#[cfg(unix)]
	options.custom_flags(libc::O_NOFOLLOW);
	let file = options
		.open(path)
		.await
		.with_context(|| format!("weight record missing: {}", path.display()))?;
	let meta = file.metadata().await?;
	if !meta.is_file() || meta.len() > MAX_RECORD_BYTES as u64 {
		bail!("invalid or oversized weight state record");
	}
	#[cfg(unix)]
	{
		use std::os::unix::fs::MetadataExt;
		if meta.nlink() != 1 || meta.mode() & 0o077 != 0 {
			bail!("weight state record is not private and singly linked");
		}
	}
	let mut bytes = Vec::new();
	file.take((MAX_RECORD_BYTES + 1) as u64)
		.read_to_end(&mut bytes)
		.await?;
	if bytes.len() > MAX_RECORD_BYTES {
		bail!("weight state grew beyond its bound");
	}
	let wrapper: Value = serde_json::from_slice(&bytes)?;
	let object = wrapper
		.as_object()
		.ok_or_else(|| anyhow!("weight record envelope invalid"))?;
	if object.len() != 2 || wrapper["sha256"] != digest(&wrapper["payload"])? {
		bail!("weight record integrity mismatch");
	}
	Ok(serde_json::from_value(wrapper["payload"].clone())?)
}

/// Create-only publication; retry must reproduce identical semantic bytes.
async fn publish_record<T: Serialize + serde::de::DeserializeOwned + PartialEq>(
	root: &Path,
	name: &str,
	value: &T,
) -> Result<()> {
	let final_path = root.join(name);
	if tokio::fs::try_exists(&final_path).await? {
		let prior: T = read_record(&final_path).await?;
		if prior != *value {
			bail!("weight identity is already bound to different content");
		}
		tokio::fs::File::open(root).await?.sync_all().await?;
		return Ok(());
	}
	let payload = serde_json::to_value(value)?;
	let bytes = serde_json::to_vec(&json!({"sha256":digest(&payload)?,"payload":payload}))?;
	if bytes.len() > MAX_RECORD_BYTES {
		bail!("weight state record exceeds its byte bound");
	}
	let mut entries = tokio::fs::read_dir(root).await?;
	let mut stored_bytes = 0u64;
	while let Some(entry) = entries.next_entry().await? {
		let meta = tokio::fs::symlink_metadata(entry.path()).await?;
		if !meta.is_file() || meta.file_type().is_symlink() {
			bail!("unexpected entry in the private weight index");
		}
		stored_bytes = stored_bytes
			.checked_add(meta.len())
			.ok_or_else(|| anyhow!("weight index byte overflow"))?;
	}
	if stored_bytes.saturating_add(bytes.len() as u64) > MAX_STATE_BYTES {
		bail!("weight index reached its 64 MiB quota; owner archival required");
	}
	let seq = STAGING_SEQUENCE.fetch_add(1, Ordering::Relaxed);
	let time = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)?
		.as_nanos();
	let staging = root.join(format!(".pending-{}-{time}-{seq}", std::process::id()));
	let mut options = tokio::fs::OpenOptions::new();
	options.write(true).create_new(true);
	#[cfg(unix)]
	options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
	let mut file = options.open(&staging).await?;
	file.write_all(&bytes).await?;
	file.sync_all().await?;
	drop(file);
	let publication = publish_no_replace(&staging, &final_path).await;
	if let Err(error) = publication {
		match tokio::fs::remove_file(&staging).await {
			Ok(()) => {}
			Err(cleanup) if cleanup.kind() == std::io::ErrorKind::NotFound => {}
			Err(cleanup) => return Err(cleanup.into()),
		}
		if error.kind() != std::io::ErrorKind::AlreadyExists {
			return Err(error.into());
		}
		let prior: T = read_record(&final_path).await?;
		if prior != *value {
			bail!("concurrent weight identity conflict");
		}
	}
	tokio::fs::File::open(root).await?.sync_all().await?;
	Ok(())
}

/// A rename is one namespace transition: no crash can publish a two-link inode.
/// NOREPLACE keeps conflicting requests immutable even before a caller observes it.
async fn publish_no_replace(staging: &Path, destination: &Path) -> std::io::Result<()> {
	#[cfg(target_os = "linux")]
	{
		use std::os::unix::ffi::OsStrExt;
		let staging = staging.to_owned();
		let destination = destination.to_owned();
		tokio::task::spawn_blocking(move || {
			let from = std::ffi::CString::new(staging.as_os_str().as_bytes())
				.map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
			let to = std::ffi::CString::new(destination.as_os_str().as_bytes())
				.map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
			// Both C strings remain alive throughout this atomic filesystem operation.
			let result = unsafe {
				libc::renameat2(
					libc::AT_FDCWD,
					from.as_ptr(),
					libc::AT_FDCWD,
					to.as_ptr(),
					libc::RENAME_NOREPLACE,
				)
			};
			if result == 0 {
				Ok(())
			} else {
				Err(std::io::Error::last_os_error())
			}
		})
		.await
		.map_err(std::io::Error::other)?
	}
	#[cfg(not(target_os = "linux"))]
	{
		let _ = (staging, destination);
		Err(std::io::Error::new(
			std::io::ErrorKind::Unsupported,
			"weight record publication requires a qualified Linux controller",
		))
	}
}

fn intent_name(session: &str) -> String {
	format!("{session}.intent.json")
}
fn worker_name(session: &str) -> String {
	format!("{session}.worker.json")
}
fn call_name(session: &str, request: &str) -> String {
	format!("{session}.call-{}.json", sha(request.as_bytes()))
}

fn call_intent_name(session: &str, request: &str) -> String {
	format!("{session}.call-intent-{}.json", sha(request.as_bytes()))
}
fn close_name(session: &str) -> String {
	format!("{session}.closed.json")
}

async fn load_intent(root: &Path, session: &str, require_current: bool) -> Result<SessionIntent> {
	check_session_id(session)?;
	let intent: SessionIntent = read_record(&root.join(intent_name(session))).await?;
	if intent.schema != "hepta.weight.session.v1"
		|| intent.session_id != session
		|| intent.profile_digest != digest(&intent.profile)?
	{
		bail!("weight session identity mismatch");
	}
	if require_current {
		let current = runtime_config()?
			.weight_workers
			.get(&intent.profile_name)
			.ok_or_else(|| anyhow!("weight profile no longer enabled"))?;
		if digest(current)? != intent.profile_digest {
			bail!("weight profile changed; stored session cannot receive new effects");
		}
	}
	Ok(intent)
}

async fn load_binding(
	root: &Path,
	intent: &SessionIntent,
	request: Option<&str>,
) -> Result<JobBinding> {
	let name = if let Some(request) = request.filter(|request| *request != "open") {
		check_request_id(request)?;
		call_name(&intent.session_id, request)
	} else {
		worker_name(&intent.session_id)
	};
	let binding: JobBinding = read_record(&root.join(name)).await?;
	if binding.schema != "hepta.weight.job-binding.v1"
		|| binding.session_id != intent.session_id
		|| binding.host != intent.profile.host
	{
		bail!("weight job binding mismatch");
	}
	Ok(binding)
}

fn bind_job(intent: &SessionIntent, request_digest: String, reply: &str) -> Result<JobBinding> {
	let result: Value = serde_json::from_str(reply)?;
	let job_id = result["job"]["id"]
		.as_str()
		.ok_or_else(|| anyhow!("durable owner omitted original job identity"))?;
	if result["job"]["host"] != intent.profile.host {
		bail!("durable owner returned a different host");
	}
	Ok(JobBinding {
		schema: "hepta.weight.job-binding.v1".into(),
		session_id: intent.session_id.clone(),
		request_digest,
		host: intent.profile.host.clone(),
		job_id: job_id.into(),
	})
}

fn receipt(intent: &SessionIntent, binding: &JobBinding, request_id: &str) -> Result<String> {
	Ok(serde_json::to_string(
		&json!({"schema":"hepta.weight.job-receipt.v1","session_id":intent.session_id,"request_id":request_id,"host":binding.host,"job_id":binding.job_id,"request_sha256":binding.request_digest,"profile_sha256":intent.profile_digest,"worker_sha256":intent.profile.worker_sha256,"worker_package_sha256":intent.profile.worker_package_sha256,"state":"admitted","terminal_observed":false,"result_tool":"weight_read","status_tool":"weight_status","production_eligible":false}),
	)?)
}

async fn publish_session_intent(root: &Path, intent: &SessionIntent) -> Result<()> {
	// Every live session needs its original intent. A retained-record count must
	// not become another active-session gate or require deleting those identities.
	let _index = lock_state(root).await?;
	publish_record(root, &intent_name(&intent.session_id), intent).await
}

pub async fn open(input: WeightOpenParams) -> Result<String> {
	let intent = prepare_intent(runtime_config()?, input)?;
	let root = state_directory().await?;
	let _session = lock_session(&root, &intent.session_id).await?;
	if tokio::fs::try_exists(root.join(close_name(&intent.session_id))).await? {
		bail!("weight session is already closed; its identity cannot be relaunched");
	}
	publish_session_intent(&root, &intent).await?;
	let reply = jobs::start_job(worker_start(&intent)?).await?;
	let binding = bind_job(&intent, digest(&intent.worker_request)?, &reply)?;
	publish_record(&root, &worker_name(&intent.session_id), &binding).await?;
	receipt(&intent, &binding, "open")
}

pub fn profiles() -> Result<String> {
	let values: Vec<Value> = runtime_config()?.weight_workers.iter().map(|(name, p)| json!({"profile":name,"host":p.host,"providers":p.allowed_providers,"worker_sha256":p.worker_sha256,"worker_package_sha256":p.worker_package_sha256,"client_transport":if p.native_client.is_some(){"native_rust"}else{"python_compat"},"native_client_sha256":p.native_client.as_ref().map(|c|&c.sha256),"max_memory_bytes":p.max_memory_bytes,"max_cpu_threads":p.max_cpu_threads,"max_lifetime_seconds":p.max_lifetime_seconds,"max_request_ms":p.max_request_ms,"max_active_sessions":null,"legacy_max_active_sessions":p.max_active_sessions,"max_requests_per_session":p.max_requests_per_session})).collect();
	Ok(serde_json::to_string(
		&json!({"profiles":values,"authority":"isolated_experiment_only"}),
	)?)
}

pub async fn call(input: WeightCallParams) -> Result<String> {
	check_request_id(&input.request_id)?;
	if input.request_id == "open" || input.request_id == "close" {
		bail!("reserved weight request identity");
	}
	let root = state_directory().await?;
	let _session = lock_session(&root, &input.session_id).await?;
	let intent = load_intent(&root, &input.session_id, true).await?;
	if tokio::fs::try_exists(root.join(close_name(&intent.session_id))).await? {
		bail!("weight session is closed");
	}
	load_binding(&root, &intent, None).await?;
	let mut params = input.params;
	if !params.is_object() {
		bail!("weight params must be an object");
	}
	let timeout = bounded_uint(
		&params,
		"timeout_ms",
		120_000,
		1000,
		intent.profile.max_request_ms,
	)?;
	params["timeout_ms"] = json!(timeout);
	let request =
		json!({"id":input.request_id,"op":input.op,"session_id":input.session_id,"params":params});
	bounded_request(&request)?;
	let request_digest = digest(&request)?;
	let record_name = call_name(&intent.session_id, &input.request_id);
	if tokio::fs::try_exists(root.join(&record_name)).await? {
		let previous = load_binding(&root, &intent, Some(&input.request_id)).await?;
		if previous.request_digest != request_digest {
			bail!("weight request identity is already bound to different content");
		}
		return receipt(&intent, &previous, &input.request_id);
	}
	let call_intent = call_intent_name(&intent.session_id, &input.request_id);
	let prefix = format!("{}.call-intent-", intent.session_id);
	let mut entries = tokio::fs::read_dir(&root).await?;
	let mut calls = 0usize;
	while let Some(entry) = entries.next_entry().await? {
		if entry.file_name().to_string_lossy().starts_with(&prefix) {
			calls += 1;
		}
	}
	if calls >= intent.profile.max_requests_per_session
		&& !tokio::fs::try_exists(root.join(&call_intent)).await?
	{
		bail!("weight session request budget exhausted");
	}
	// Reserve exact request bytes and budget before a possibly applied operation.
	// A crashed admission reconciles only the original durable process key.
	publish_record(&root, &call_intent, &request).await?;
	let reply =
		jobs::start_job(client_start(&intent, &request, &input.request_id, timeout)?).await?;
	let binding = bind_job(&intent, request_digest, &reply)?;
	publish_record(&root, &record_name, &binding).await?;
	receipt(&intent, &binding, &input.request_id)
}

pub async fn status(input: WeightStatusParams) -> Result<String> {
	let root = state_directory().await?;
	let intent = load_intent(&root, &input.session_id, false).await?;
	let binding = load_binding(&root, &intent, input.request_id.as_deref()).await?;
	jobs::wait_job(ProcessWaitParams {
		host: binding.host,
		job_id: binding.job_id,
		timeout_seconds: Some(input.wait_seconds.unwrap_or(0).min(30)),
	})
	.await
}

pub async fn read(input: WeightReadParams) -> Result<String> {
	let root = state_directory().await?;
	let intent = load_intent(&root, &input.session_id, false).await?;
	let binding = load_binding(&root, &intent, input.request_id.as_deref()).await?;
	jobs::read_job(ProcessReadParams {
		host: binding.host,
		job_id: binding.job_id,
		stdout_offset: input.stdout_offset,
		stderr_offset: input.stderr_offset,
		limit: Some(input.limit.unwrap_or(16_384).clamp(1, 65_536)),
	})
	.await
}

pub async fn close(input: WeightCloseParams) -> Result<String> {
	let root = state_directory().await?;
	let _session = lock_session(&root, &input.session_id).await?;
	let intent = load_intent(&root, &input.session_id, false).await?;
	let binding = load_binding(&root, &intent, None).await?;
	publish_record(
		&root,
		&close_name(&intent.session_id),
		&json!({"session_id":intent.session_id,"worker_job_id":binding.job_id,"state":"close_requested"}),
	)
	.await?;
	let result = jobs::cancel_job(ProcessCancelParams {
		host: binding.host,
		job_id: binding.job_id,
		grace_seconds: Some(10),
	})
	.await?;
	Ok(serde_json::to_string(
		&json!({"session_id":intent.session_id,"closed_to_new_calls":true,"cancellation":serde_json::from_str::<Value>(&result)?,"terminal_confirmation":"weight_status"}),
	)?)
}

#[cfg(all(test, target_os = "linux"))]
#[path = "weight_tests.rs"]
mod tests;
