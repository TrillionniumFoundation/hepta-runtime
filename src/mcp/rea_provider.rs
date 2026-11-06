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

#[path = "rea_engine_profile.rs"]
pub(crate) mod engine_profile;
pub use engine_profile::GhidraEngineProfile;

#[path = "rea_static_summary.rs"]
pub(crate) mod summary;

#[path = "rea_ghidra_contract.rs"]
pub(crate) mod ghidra_contract;

pub(crate) const MAX_WORKER_REQUEST: usize = 64 * 1024;
pub(crate) const MAX_RESULT_BYTES: usize = 512 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum StaticProvider {
	GnuReadelf,
	GnuObjdump,
	Jadx,
	Ghidra,
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
	Classes,
	Sources,
	Inventory,
	Functions,
	Function,
	Decompile,
	Xrefs,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct JavaEngineProfile {
	pub java_home: String,
	pub jar_path: String,
	pub jar_sha256: String,
	pub engine_version: String,
	/// Distribution provenance, independently verified when the admin installs it.
	pub release_archive_sha256: String,
	/// Exact relative JRE files and their pins; system shared libraries remain outside this set.
	pub runtime_files: BTreeMap<String, String>,
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
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub java_engine: Option<JavaEngineProfile>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub ghidra_engine: Option<GhidraEngineProfile>,
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
	/// Administrator-configured static backend profile; never a command.
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
	/// Internal Ghidra address in canonical lowercase 0x hexadecimal. Revisions 2/3
	/// require an exact function entry; revision 4 also resolves an address in its body.
	/// Required only for function/decompile/xrefs. Absent fields preserve old request identities.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub function_address: Option<String>,
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
		match self {
			Self::GnuReadelf => matches!(
				operation,
				StaticOperation::Headers
					| StaticOperation::Sections
					| StaticOperation::Symbols
					| StaticOperation::Notes
					| StaticOperation::Relocations
			),
			Self::GnuObjdump => matches!(
				operation,
				StaticOperation::Headers
					| StaticOperation::Sections
					| StaticOperation::Symbols
					| StaticOperation::Relocations
			),
			Self::Jadx => matches!(
				operation,
				StaticOperation::Classes | StaticOperation::Sources
			),
			Self::Ghidra => matches!(
				operation,
				StaticOperation::Inventory
					| StaticOperation::Functions
					| StaticOperation::Function
					| StaticOperation::Decompile
					| StaticOperation::Xrefs
			),
		}
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
			_ => bail!("this operation requires its fixed engine bridge"),
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
		StaticProvider::Jadx => "openjdk 21.",
		StaticProvider::Ghidra => "openjdk 25.",
	};
	if !profile.backend_version.starts_with(expected_prefix)
		|| profile.backend_version.len() > 512
		|| profile.backend_version.contains(['\0', '\n', '\r'])
	{
		bail!("static profile requires its exact admitted backend version line");
	}
	match (&profile.java_engine, profile.provider) {
		(Some(engine), StaticProvider::Jadx) => {
			if !absolute_normal_path(&engine.java_home)
				|| !absolute_normal_path(&engine.jar_path)
				|| profile.backend_executable != format!("{}/bin/java", engine.java_home)
				|| !is_sha256(&engine.jar_sha256)
				|| !is_sha256(&engine.release_archive_sha256)
				|| engine.engine_version != "1.5.6"
				|| engine.runtime_files.len() > 16
				|| profile.max_artifact_bytes > 32 * 1024 * 1024
				|| profile.memory_max_bytes < 768 * 1024 * 1024
			{
				bail!("JADX profile requires the pinned 1.5.6 jar, Java 21 installation and bounded resources");
			}
			for required in [
				"release",
				"lib/modules",
				"lib/server/libjvm.so",
				"lib/libjava.so",
				"lib/libzip.so",
				"lib/libnio.so",
				"lib/libjli.so",
			] {
				if !engine.runtime_files.contains_key(required) {
					bail!("JADX runtime manifest is missing {required}");
				}
			}
			for (relative, digest) in &engine.runtime_files {
				if relative.is_empty()
					|| Path::new(relative).is_absolute()
					|| !absolute_normal_path(&format!("{}/{relative}", engine.java_home))
					|| !is_sha256(digest)
				{
					bail!("JADX runtime manifest has an invalid path or digest");
				}
			}
		}
		(None, StaticProvider::GnuReadelf | StaticProvider::GnuObjdump) => {}
		(None, StaticProvider::Ghidra) => engine_profile::validate_ghidra(profile)?,
		_ => bail!("Java engine settings must match an admitted Java provider"),
	}
	if profile.provider != StaticProvider::Ghidra && profile.ghidra_engine.is_some() {
		bail!("Ghidra installation settings require the fixed Ghidra provider");
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
		if let Some(engine) = &profile.java_engine {
			let runtime_paths: Vec<_> = engine
				.runtime_files
				.keys()
				.map(|relative| format!("{}/{relative}", engine.java_home))
				.collect();
			for path in [&engine.java_home, &engine.jar_path]
				.into_iter()
				.chain(&runtime_paths)
			{
				if !inside(path, &host.allowed_read_path_prefixes)
					|| inside(path, &host.protected_path_prefixes)
				{
					bail!("Java engine profile exceeds its host read policy");
				}
			}
		}
		if let Some(engine) = &profile.ghidra_engine {
			for path in engine_profile::policy_paths(engine) {
				if !inside(&path, &host.allowed_read_path_prefixes)
					|| inside(&path, &host.protected_path_prefixes)
				{
					bail!("Ghidra engine profile exceeds its host read policy");
				}
			}
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
	ghidra_contract::validate_selection(input.profile.provider, request)?;
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
		"memory_max_bytes":p.memory_max_bytes,"java_engine":p.java_engine,"ghidra_engine":p.ghidra_engine
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
	let outcome = output.outcome();
	let state = match outcome {
		crate::native::NativeJobOutcome::Succeeded => "succeeded",
		crate::native::NativeJobOutcome::Failed => "failed",
		crate::native::NativeJobOutcome::Cancelled => "cancelled",
		crate::native::NativeJobOutcome::TimedOut => "timed_out",
	};
	let process_succeeded = outcome == crate::native::NativeJobOutcome::Succeeded;
	let scratch_cleanup = output.scratch_cleanup().cloned();
	let cleanup_complete = scratch_cleanup.as_ref().map(|receipt| {
		receipt["state"] == "removed"
			&& receipt["durable"] == true
			&& receipt["worker_adopted"] == true
	});
	let (stdout, stderr) = output.into_streams();
	let mut report_error = None;
	let report = if stdout.is_empty() {
		if process_succeeded {
			bail!("successful static worker omitted its report");
		}
		Value::Null
	} else {
		let validated = (|| -> Result<Value> {
			let report = serde_json::from_slice::<Value>(&stdout)
				.context("static worker output was not a complete JSON record")?;
			let worker: WorkerRequest = serde_json::from_str(
				params
					.stdin
					.as_deref()
					.context("original static request absent")?,
			)?;
			validate_report(&report, &worker, exit_code)?;
			if scratch_cleanup.is_some() != (report["scratch"]["cleanup_owner"] == "durable_job") {
				bail!("static report and original owner disagree on scratch lifecycle");
			}
			Ok(report)
		})();
		match validated {
			Ok(report) => report,
			Err(error) if !process_succeeded => {
				// Cancellation can interrupt the final JSON write. Keep the original
				// failed/cancelled output queryable without accepting a partial report.
				report_error = Some(format!("{error:#}"));
				Value::Null
			}
			Err(error) => return Err(error),
		}
	};
	Ok(serde_json::to_string(&json!({
		"job_id":job,"state":state,"exit_code":exit_code,"process_succeeded":process_succeeded,
		"complete":true,"observation_only":true,"report":report,
		"scratch_cleanup":scratch_cleanup,"cleanup_complete":cleanup_complete,
		"worker_stdout":report_error.as_ref().map(|_| String::from_utf8_lossy(&stdout)),
		"report_error":report_error,
		"worker_stderr":String::from_utf8_lossy(&stderr),"rea_evidence_compatible":false
	}))?)
}

fn valid_worker_scratch(report: &Value) -> bool {
	let scratch = &report["scratch"];
	match scratch.get("cleanup_owner") {
		None => {
			scratch["removed_after_operation"] == true && scratch.get("cleanup_pending").is_none()
		}
		Some(Value::String(owner)) if owner == "durable_job" => {
			scratch["removed_after_operation"] == false && scratch["cleanup_pending"] == true
		}
		Some(Value::String(owner)) if owner == "standalone_worker" => {
			scratch["removed_after_operation"] == true && scratch["cleanup_pending"] == false
		}
		_ => false,
	}
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
	if input.profile.provider == StaticProvider::Jadx {
		if report["java_engine"] != serde_json::to_value(&input.profile.java_engine)?
			|| report["bridge_sha256"] != sha256(include_str!("rea_jadx_bridge.java").as_bytes())
			|| report["backend"]["snapshot"] != "verified_installed_inode"
			|| report["network_syscalls_denied"] != true
			|| !valid_worker_scratch(report)
		{
			bail!("JADX report does not retain the admitted engine, bridge and cleanup identities");
		}
		if exit_code == 0 {
			let observation: Value = serde_json::from_str(
				report["stdout"]
					.as_str()
					.context("JADX observation source absent")?,
			)?;
			let engine = input
				.profile
				.java_engine
				.as_ref()
				.context("JADX engine profile absent")?;
			if observation["schema"] != "hepta.rea.jadx-observation.v1"
				|| observation["operation"] != serde_json::to_value(input.request.operation)?
				|| observation["engine_version"] != engine.engine_version
				|| observation["target_executed"] != false
				|| observation["external_plugins_loaded"] != false
				|| observation["source_semantics_validated"] != false
			{
				bail!("JADX observation does not match its admitted semantics");
			}
		}
	}
	if input.profile.provider == StaticProvider::Ghidra {
		if report["ghidra_engine"] != serde_json::to_value(&input.profile.ghidra_engine)?
			|| report["bridge_sha256"]
				!= sha256(
					ghidra_contract::bridge(
						input.request.operation,
						input
							.profile
							.ghidra_engine
							.as_ref()
							.context("Ghidra installation identity absent")?
							.bridge_revision,
					)?
					.as_bytes(),
				) || report["backend"]["snapshot"] != "verified_installed_inode"
			|| report["installation_snapshot"] != "verified_installed_paths"
			|| report["network_syscalls_denied"] != true
			|| !valid_worker_scratch(report)
		{
			bail!("Ghidra report does not retain its admitted installation, bridge and cleanup identities");
		}
		if exit_code == 0 {
			let observation: Value = serde_json::from_str(
				report["stdout"]
					.as_str()
					.context("Ghidra observation source absent")?,
			)?;
			ghidra_contract::validate_observation(
				&observation,
				input,
				report["subject"]["size_bytes"]
					.as_u64()
					.context("Ghidra captured size absent")?,
			)?;
		}
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
