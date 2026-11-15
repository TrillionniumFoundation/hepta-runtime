// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Fixed static-analysis profiles over the existing durable process owner.
//!
//! The complete original request is the recovery handle. Observation and
//! cancellation resolve that request through `native`; there is no second job
//! registry or supervisor. Backend text is retained as text, not REA Evidence.

use anyhow::{anyhow, bail, Context, Result};
use rmcp::schemars;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path};

use super::runtime::config::{runtime_config, valid_name, Platform, RuntimeConfig};
use super::runtime::jobs::ProcessStartParams;

#[path = "rea_static_summary.rs"]
pub(crate) mod summary;

pub(crate) const MAX_WORKER_REQUEST: usize = 64 * 1024;
pub(crate) const MAX_RESULT_BYTES: usize = 512 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum StaticProvider {
	GnuReadelf,
	GnuObjdump,
}

#[derive(
	Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum StaticOperation {
	Headers,
	Sections,
	Symbols,
	Notes,
	Relocations,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReaStaticProfile {
	pub host: String,
	pub runtime_executable: String,
	pub runtime_sha256: String,
	pub provider: StaticProvider,
	pub backend_executable: String,
	pub backend_sha256: String,
	/// Exact first line of the admitted backend's `--version` output under LC_ALL=C.
	pub backend_version: String,
	pub working_directory: String,
	pub input_roots: Vec<String>,
	pub allowed_operations: Vec<StaticOperation>,
	#[serde(default = "default_artifact_bytes")]
	pub max_artifact_bytes: u64,
	#[serde(default = "default_output_bytes")]
	pub max_output_bytes: usize,
	#[serde(default = "default_timeout")]
	pub timeout_seconds: u64,
	#[serde(default = "default_memory")]
	pub memory_max_bytes: u64,
}

fn default_artifact_bytes() -> u64 {
	64 * 1024 * 1024
}
fn default_output_bytes() -> usize {
	32 * 1024
}
fn default_timeout() -> u64 {
	30
}
fn default_memory() -> u64 {
	512 * 1024 * 1024
}

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReaStaticRequest {
	/// Administrator-configured GNU readelf/objdump profile; never a command.
	pub profile: String,
	/// Exact profile identity returned by rea_static_profiles; prevents host/version rebinding.
	pub profile_sha256: String,
	/// Keep this key and all parameters unchanged after uncertainty or restart.
	pub idempotency_key: String,
	pub operation: StaticOperation,
	/// Absolute path of an owned build artifact inside the profile's input roots.
	pub artifact_path: String,
	/// Required identity of the bytes to inspect. A mismatch prevents backend use.
	pub artifact_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WorkerRequest {
	pub schema: String,
	pub profile: ReaStaticProfile,
	pub request: ReaStaticRequest,
	pub protected_roots: Vec<String>,
}

pub(crate) fn sha256(bytes: &[u8]) -> String {
	Sha256::digest(bytes)
		.iter()
		.map(|byte| format!("{byte:02x}"))
		.collect()
}

pub(crate) fn is_sha256(value: &str) -> bool {
	value.len() == 64
		&& value
			.bytes()
			.all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub(crate) fn absolute_normal_path(value: &str) -> bool {
	Path::new(value).is_absolute()
		&& value.len() <= 4096
		&& !value.contains(['\0', '\n', '\r'])
		&& !value.split('/').any(|part| part == "." || part == "..")
		&& !Path::new(value)
			.components()
			.any(|p| matches!(p, Component::ParentDir | Component::CurDir))
}

fn inside(path: &str, roots: &[String]) -> bool {
	roots.iter().any(|root| Path::new(path).starts_with(root))
}

impl StaticProvider {
	pub(crate) fn supports(self, operation: StaticOperation) -> bool {
		self != Self::GnuObjdump || operation != StaticOperation::Notes
	}

	/// No caller-controlled flags, output paths, plugins, scripts or disassembly.
	pub(crate) fn arguments(
		self,
		operation: StaticOperation,
		artifact: &str,
	) -> Result<Vec<String>> {
		if !self.supports(operation) {
			bail!("this static backend does not support the selected operation");
		}
		let flag = match (self, operation) {
			(Self::GnuReadelf, StaticOperation::Headers) => "--file-header",
			(Self::GnuReadelf, StaticOperation::Sections) => "--section-headers",
			(Self::GnuReadelf, StaticOperation::Symbols) => "--symbols",
			(Self::GnuReadelf, StaticOperation::Notes) => "--notes",
			(Self::GnuReadelf, StaticOperation::Relocations) => "--relocs",
			(Self::GnuObjdump, StaticOperation::Headers) => "--file-headers",
			(Self::GnuObjdump, StaticOperation::Sections) => "--section-headers",
			(Self::GnuObjdump, StaticOperation::Symbols) => "--syms",
			(Self::GnuObjdump, StaticOperation::Relocations) => "--reloc",
			(Self::GnuObjdump, StaticOperation::Notes) => {
				bail!("GNU objdump note inspection is unsupported")
			}
		};
		let mut args = vec![flag.to_owned()];
		if self == Self::GnuReadelf {
			args.push("--wide".into());
		}
		args.extend(["--".into(), artifact.into()]);
		Ok(args)
	}
}

pub(crate) fn validate_profile(profile: &ReaStaticProfile) -> Result<()> {
	if !valid_name(&profile.host) {
		bail!("static profile requires a configured host name");
	}
	for path in [
		&profile.runtime_executable,
		&profile.backend_executable,
		&profile.working_directory,
	]
	.into_iter()
	.chain(&profile.input_roots)
	{
		if !absolute_normal_path(path) {
			bail!("static profile paths must be absolute and normalized");
		}
	}
	if !is_sha256(&profile.runtime_sha256) || !is_sha256(&profile.backend_sha256) {
		bail!("static profile requires runtime and backend SHA-256 pins");
	}
	let expected_prefix = match profile.provider {
		StaticProvider::GnuReadelf => "GNU readelf ",
		StaticProvider::GnuObjdump => "GNU objdump ",
	};
	if !profile.backend_version.starts_with(expected_prefix)
		|| profile.backend_version.len() > 512
		|| profile.backend_version.contains(['\0', '\n', '\r'])
	{
		bail!("static profile requires the exact GNU backend version line");
	}
	if profile.input_roots.is_empty()
		|| profile.input_roots.len() > 16
		|| profile.allowed_operations.is_empty()
		|| profile
			.allowed_operations
			.iter()
			.any(|op| !profile.provider.supports(*op))
		|| profile
			.allowed_operations
			.iter()
			.collect::<BTreeSet<_>>()
			.len() != profile.allowed_operations.len()
	{
		bail!("static profile requires bounded roots and distinct supported operations");
	}
	if !(1..=512 * 1024 * 1024).contains(&profile.max_artifact_bytes)
		|| !(1024..=64 * 1024).contains(&profile.max_output_bytes)
		|| !(1..=120).contains(&profile.timeout_seconds)
		|| !(256 * 1024 * 1024..=2 * 1024 * 1024 * 1024).contains(&profile.memory_max_bytes)
		|| profile.memory_max_bytes < profile.max_artifact_bytes + 128 * 1024 * 1024
	{
		bail!("static profile resource limits are outside the admitted bounds");
	}
	Ok(())
}

pub fn validate_profiles(config: &RuntimeConfig) -> Result<()> {
	if !config.rea_static_profiles.is_empty() && !cfg!(target_os = "linux") {
		bail!("static backend profiles currently require a Linux controller");
	}
	if config.rea_static_profiles.len() > 16 {
		bail!("at most 16 static backend profiles are supported");
	}
	for (name, profile) in &config.rea_static_profiles {
		if !valid_name(name) {
			bail!("invalid static profile name");
		}
		validate_profile(profile)?;
		let host = config.host(&profile.host)?;
		if host.platform != Platform::Linux || !host.allow_execute {
			bail!("static profiles require an executing configured Linux host");
		}
		if !host.allowed_cwd_prefixes.is_empty()
			&& !inside(&profile.working_directory, &host.allowed_cwd_prefixes)
		{
			bail!("static profile cwd exceeds its host policy");
		}
		for path in [&profile.runtime_executable, &profile.backend_executable]
			.into_iter()
			.chain(&profile.input_roots)
		{
			if !inside(path, &host.allowed_read_path_prefixes)
				|| inside(path, &host.protected_path_prefixes)
			{
				bail!("static profile exceeds its host read policy");
			}
		}
	}
	Ok(())
}

pub(crate) fn validate_worker_request(input: &WorkerRequest) -> Result<()> {
	if input.schema != "hepta.rea.static-request.v1" {
		bail!("unsupported static worker request schema");
	}
	validate_profile(&input.profile)?;
	let request = &input.request;
	if !valid_name(&request.profile)
		|| request.idempotency_key.is_empty()
		|| request.idempotency_key.len() > 128
		|| !request
			.idempotency_key
			.bytes()
			.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
	{
		bail!("static request requires stable bounded profile and request identities");
	}
	if request.profile_sha256 != sha256(&serde_json::to_vec(&input.profile)?) {
		bail!("static profile changed; retain and observe the original owner job instead of relaunching");
	}
	if !absolute_normal_path(&request.artifact_path)
		|| !inside(&request.artifact_path, &input.profile.input_roots)
		|| inside(&request.artifact_path, &input.protected_roots)
		|| !is_sha256(&request.artifact_sha256)
		|| !input
			.profile
			.allowed_operations
			.contains(&request.operation)
	{
		bail!("static artifact identity, root or operation is not admitted");
	}
	if input.protected_roots.len() > 128
		|| input
			.protected_roots
			.iter()
			.any(|p| !absolute_normal_path(p))
	{
		bail!("static protected-root policy is invalid");
	}
	Ok(())
}

fn prepare_request(
	config: &RuntimeConfig,
	request: ReaStaticRequest,
) -> Result<ProcessStartParams> {
	let profile = config
		.rea_static_profiles
		.get(&request.profile)
		.ok_or_else(|| anyhow!("unknown or disabled static backend profile"))?
		.clone();
	let host = config.host(&profile.host)?;
	let worker = WorkerRequest {
		schema: "hepta.rea.static-request.v1".into(),
		profile,
		protected_roots: host.protected_path_prefixes.clone(),
		request,
	};
	validate_worker_request(&worker)?;
	let stdin = serde_json::to_string(&worker)? + "\n";
	if stdin.len() > MAX_WORKER_REQUEST {
		bail!("static request exceeds 64 KiB");
	}
	// The key does not include payload bytes: changing payload under the same key
	// must collide at the existing owner instead of launching a fresh analysis.
	let key = sha256(
		serde_json::to_string(&json!({
			"profile":worker.request.profile,"key":worker.request.idempotency_key
		}))?
		.as_bytes(),
	);
	Ok(ProcessStartParams {
		host: worker.profile.host.clone(),
		executable: worker.profile.runtime_executable.clone(),
		args: vec!["rea-static-worker".into()],
		cwd: Some(worker.profile.working_directory.clone()),
		env: BTreeMap::from([
			("LC_ALL".into(), "C".into()),
			("TOKIO_WORKER_THREADS".into(), "1".into()),
		]),
		stdin: Some(stdin),
		timeout_seconds: Some(worker.profile.timeout_seconds + 5),
		idempotency_key: Some(format!("rea-static-{key}")),
		nice: Some(10),
		cpu_quota_percent: Some(100),
		memory_max_bytes: Some(worker.profile.memory_max_bytes),
	})
}

pub fn profiles() -> Result<String> {
	let profiles: Vec<_> = runtime_config()?.rea_static_profiles.iter().map(|(name,p)| Ok(json!({
		"profile":name,"profile_sha256":sha256(&serde_json::to_vec(p)?),"host":p.host,"provider":p.provider,"backend_version":p.backend_version,
		"runtime_sha256":p.runtime_sha256,"backend_sha256":p.backend_sha256,
		"operations":p.allowed_operations,"max_artifact_bytes":p.max_artifact_bytes,
		"max_output_bytes_per_stream":p.max_output_bytes,"timeout_seconds":p.timeout_seconds,
		"memory_max_bytes":p.memory_max_bytes
	}))).collect::<Result<Vec<_>>>()?;
	Ok(serde_json::to_string(
		&json!({"profiles":profiles,"rea_full_parity":false}),
	)?)
}

pub async fn start(request: ReaStaticRequest) -> Result<String> {
	let params = prepare_request(runtime_config()?, request)?;
	crate::native::execute_or_observe(params).await
}

pub async fn status(request: ReaStaticRequest) -> Result<String> {
	let params = prepare_request(runtime_config()?, request)?;
	crate::native::observe_request(params)
		.await?
		.context("original static request not found; observation did not submit work")
}

pub async fn read(request: ReaStaticRequest) -> Result<String> {
	let params = prepare_request(runtime_config()?, request)?;
	let Some(output) = crate::native::observe_terminal_output(&params, MAX_RESULT_BYTES).await?
	else {
		return Ok(serde_json::to_string(
			&json!({"state":"pending_or_unknown","complete":false,"observation_only":true}),
		)?);
	};
	let job = output.job_id().to_owned();
	let exit_code = output.exit_code();
	let (stdout, stderr) = output.into_streams();
	let report = if stdout.is_empty() {
		if exit_code == 0 {
			bail!("successful static worker omitted its report");
		}
		Value::Null
	} else {
		let report = serde_json::from_slice::<Value>(&stdout)
			.context("static worker output was not a complete JSON record")?;
		let worker: WorkerRequest = serde_json::from_str(
			params
				.stdin
				.as_deref()
				.context("original static request absent")?,
		)?;
		validate_report(&report, &worker, exit_code)?;
		report
	};
	Ok(serde_json::to_string(&json!({
		"job_id":job,"exit_code":exit_code,"process_succeeded":exit_code==0,
		"complete":true,"observation_only":true,"report":report,
		"worker_stderr":String::from_utf8_lossy(&stderr),"rea_evidence_compatible":false
	}))?)
}

fn validate_report(report: &Value, input: &WorkerRequest, exit_code: i32) -> Result<()> {
	let mut body = report.clone();
	let id = body
		.as_object_mut()
		.context("static report must be an object")?
		.remove("native_report_id")
		.context("static report identity absent")?;
	let expected_id = format!(
		"hepta_rea_static_v1_{}",
		sha256(&serde_json::to_vec(&body)?)
	);
	if id != expected_id
		|| report["schema"] != "hepta.rea.static-report.v1"
		|| report["request_sha256"] != sha256(&serde_json::to_vec(input)?)
		|| report["runtime_sha256"] != input.profile.runtime_sha256
		|| report["provider"] != serde_json::to_value(input.profile.provider)?
		|| report["operation"] != serde_json::to_value(input.request.operation)?
		|| report["backend"]["sha256"] != input.profile.backend_sha256
		|| report["backend"]["version"] != input.profile.backend_version
		|| report["subject"]["sha256"] != input.request.artifact_sha256
		|| report["subject"]["selected_path"] != input.request.artifact_path
		|| report["subject"]["snapshot"] != "sealed_linux_memfd"
		|| report["output_complete"] != true
		|| report["rea_evidence_compatible"] != false
		|| report["backend_success"].as_bool() != Some(exit_code == 0)
		|| report["coverage"]
			!= json!({"scope":"selected_static_backend_operation","status":"partial"})
	{
		bail!("static report is not bound to its admitted request and complete backend outcome");
	}
	let size = report["subject"]["size_bytes"]
		.as_u64()
		.context("static subject size absent")?;
	if size > input.profile.max_artifact_bytes {
		bail!("static report subject exceeds the admitted bound");
	}
	for stream in ["stdout", "stderr"] {
		let text = report[stream]
			.as_str()
			.context("static report stream is not text")?;
		if text.len() > input.profile.max_output_bytes
			|| report[format!("{stream}_sha256")] != sha256(text.as_bytes())
			|| report[format!("{stream}_bytes")].as_u64() != Some(text.len() as u64)
		{
			bail!("static report stream integrity mismatch");
		}
	}
	if report["summary"]
		!= summary::selected_fields(
			input.profile.provider,
			input.request.operation,
			report["stdout"]
				.as_str()
				.context("static summary source absent")?,
			exit_code == 0,
		) {
		bail!("static selected-field summary differs from its retained backend text");
	}
	Ok(())
}

pub async fn cancel(request: ReaStaticRequest) -> Result<String> {
	let params = prepare_request(runtime_config()?, request)?;
	crate::native::cancel_request(&params, 3).await?;
	Ok(serde_json::to_string(
		&json!({"cancellation_requested":true,"termination_confirmed":false,"observe_with":"rea_static_status"}),
	)?)
}

#[cfg(test)]
#[path = "rea_provider_tests.rs"]
mod tests;
