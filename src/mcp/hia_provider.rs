// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Pinned HIA tools over the existing durable native process owner.
//!
//! The administrator selects one installation and private operator namespace.
//! Model arguments never select an executable, host, storage root or authority.
//! Exact retries observe the original job. Even a first-call race uses native's
//! no-relaunch entry path; a timeout or incomplete report cannot become success.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::Path;

use super::hia_contract::{self, sha256, MAX_WORKER_BYTES};
use super::runtime::config::{runtime_config, valid_name, HostConfig, Platform, RuntimeConfig};
use super::runtime::jobs::ProcessStartParams;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HiaWorkerProfile {
	pub host: String,
	pub python_executable: String,
	/// Trusted installed Hepta source root. No caller-controlled PYTHONPATH is accepted.
	pub working_directory: String,
	/// Private store shared by this configured operator authority across sessions.
	pub state_root: String,
	#[serde(default)]
	pub artifact_roots: Vec<String>,
	/// Exact sorted source inventory returned by the installed worker's manifest command.
	pub worker_sha256: String,
	pub backend_sha256: String,
	pub catalog_sha256: String,
	/// Optional administrator-selected manifest for pinned native helper images.
	/// Omitted legacy fields must not change durable profile/request identities.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub native_helpers_manifest: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub native_helpers_sha256: Option<String>,
	#[serde(default = "default_timeout")]
	pub timeout_seconds: u64,
	#[serde(default = "default_memory")]
	pub memory_max_bytes: u64,
}

fn default_timeout() -> u64 {
	120
}
fn default_memory() -> u64 {
	1024 * 1024 * 1024
}

fn inside(path: &str, roots: &[String]) -> bool {
	roots.iter().any(|root| Path::new(path).starts_with(root))
}

pub(super) fn validate_profile(config: &RuntimeConfig) -> Result<()> {
	let Some(profile) = &config.hia_worker else {
		return Ok(());
	};
	if !valid_name(&profile.host) {
		bail!("invalid HIA worker host alias");
	}
	let host = config.host(&profile.host)?;
	if host.platform != Platform::Linux || !host.allow_execute || !host.allow_write {
		bail!("HIA worker requires an executing, writable configured Linux host");
	}
	if ![
		&profile.worker_sha256,
		&profile.backend_sha256,
		&profile.catalog_sha256,
	]
	.into_iter()
	.all(|digest| super::rea_provider::is_sha256(digest))
	{
		bail!("HIA worker requires exact lowercase SHA256 installation pins");
	}
	if profile.catalog_sha256 != hia_contract::catalog_sha256() {
		bail!("HIA worker catalog differs from the runtime's registered tool contract");
	}
	match (
		&profile.native_helpers_manifest,
		&profile.native_helpers_sha256,
	) {
		(None, None) => {}
		(Some(path), Some(digest)) => {
			if !super::rea_provider::is_sha256(digest)
				|| !super::rea_provider::absolute_normal_path(path)
				|| !inside(path, &host.allowed_read_path_prefixes)
				|| inside(path, &host.protected_path_prefixes)
				|| Path::new(path).starts_with(&profile.state_root)
			{
				bail!(
					"HIA native helpers require an exact digest and permitted installation path outside mutable state"
				);
			}
		}
		_ => bail!("HIA native helper manifest and digest must be configured together"),
	}
	if !(1..=3600).contains(&profile.timeout_seconds)
		|| !(64 * 1024 * 1024..=16 * 1024 * 1024 * 1024).contains(&profile.memory_max_bytes)
		|| profile.artifact_roots.len() > 32
	{
		bail!("HIA worker resource limits exceed the admitted profile bounds");
	}
	for path in [
		&profile.python_executable,
		&profile.working_directory,
		&profile.state_root,
	]
	.into_iter()
	.chain(&profile.artifact_roots)
	{
		if !super::rea_provider::absolute_normal_path(path)
			|| !inside(path, &host.allowed_read_path_prefixes)
			|| inside(path, &host.protected_path_prefixes)
		{
			bail!("HIA profile path exceeds the configured host read policy");
		}
	}
	if profile.state_root == "/"
		|| !inside(&profile.state_root, &host.allowed_write_path_prefixes)
		|| Path::new(&profile.working_directory).starts_with(&profile.state_root)
		|| Path::new(&profile.state_root).starts_with(&profile.working_directory)
	{
		bail!("HIA state requires a writable private root disjoint from the installed source");
	}
	if !host.allowed_cwd_prefixes.is_empty()
		&& !inside(&profile.working_directory, &host.allowed_cwd_prefixes)
	{
		bail!("HIA installation exceeds its host execution roots");
	}
	Ok(())
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WorkerRequest {
	schema: String,
	tool: String,
	arguments: Value,
	request_sha256: String,
	profile_sha256: String,
	catalog_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkerReport {
	schema: String,
	tool: String,
	request_sha256: String,
	profile_sha256: String,
	catalog_sha256: String,
	worker_sha256: String,
	backend_sha256: String,
	#[serde(default)]
	native_helpers_sha256: Option<String>,
	complete: bool,
	response: Value,
}

pub(super) struct PreparedRequest {
	pub(super) params: ProcessStartParams,
	worker: WorkerRequest,
	profile: HiaWorkerProfile,
}

/// Sort every object, independently of serde_json's optional map-order feature.
fn canonical(value: &Value) -> Result<Vec<u8>> {
	fn write(value: &Value, out: &mut Vec<u8>) -> Result<()> {
		match value {
			Value::Object(object) => {
				out.push(b'{');
				let mut items: Vec<_> = object.iter().collect();
				items.sort_by_key(|(left, _)| *left);
				for (index, (key, value)) in items.into_iter().enumerate() {
					if index != 0 {
						out.push(b',');
					}
					serde_json::to_writer(&mut *out, key)?;
					out.push(b':');
					write(value, out)?;
				}
				out.push(b'}');
			}
			Value::Array(array) => {
				out.push(b'[');
				for (index, value) in array.iter().enumerate() {
					if index != 0 {
						out.push(b',');
					}
					write(value, out)?;
				}
				out.push(b']');
			}
			_ => serde_json::to_writer(out, value)?,
		}
		Ok(())
	}
	let mut out = Vec::new();
	write(value, &mut out)?;
	Ok(out)
}

struct CapturePath<'a> {
	selected: String,
	same_host: bool,
	explicit_identity: bool,
	host: &'a HostConfig,
}

impl CapturePath<'_> {
	fn allowed(&self, profile: &HiaWorkerProfile) -> bool {
		self.same_host
			&& !self.explicit_identity
			&& super::rea_provider::absolute_normal_path(&self.selected)
			&& inside(&self.selected, &profile.artifact_roots)
			&& inside(&self.selected, &self.host.allowed_read_path_prefixes)
			&& !inside(&self.selected, &self.host.protected_path_prefixes)
	}

	fn apply(self, arguments: &mut Value, allowed: bool) -> Result<()> {
		if !allowed {
			bail!("HIA capture path is outside its fixed worker and artifact policy");
		}
		arguments["source"]["path"] = json!(self.selected);
		Ok(())
	}
}

fn resolve_capture_path<'a>(
	arguments: &Value,
	workdir: &Path,
	profile: &HiaWorkerProfile,
	config: &'a RuntimeConfig,
) -> Result<Option<CapturePath<'a>>> {
	if arguments["source"]["kind"] != "path" {
		return Ok(None);
	}
	let path = arguments["source"]["path"]
		.as_str()
		.context("artifact path missing")?;
	let resolved = super::fs::remote::resolve_path_source(path, workdir);
	let (alias, selected, user_explicit, port_explicit) = match resolved {
		super::fs::PathSource::Remote {
			host,
			path,
			user_explicit,
			port_explicit,
			..
		} => (host, path, user_explicit, port_explicit),
		super::fs::PathSource::Local(path) => {
			// Bare absolute paths are on the configured worker host. A relative
			// controller workdir must never silently select a different machine.
			if !arguments["source"]["path"]
				.as_str()
				.is_some_and(|path| path.starts_with('/'))
			{
				bail!("HIA capture requires an absolute worker path or its registered SSH URI");
			}
			(
				profile.host.clone(),
				path.to_str()
					.context("HIA capture path is not UTF-8")?
					.to_owned(),
				false,
				false,
			)
		}
	};
	let (name, host) = config
		.host_by_alias(&alias)
		.context("HIA capture host is not configured")?;
	Ok(Some(CapturePath {
		selected,
		same_host: name == profile.host,
		explicit_identity: user_explicit || port_explicit,
		host,
	}))
}

fn admit_request<'a>(
	config: &'a RuntimeConfig,
	tool: &str,
	arguments: Value,
	workdir: &Path,
) -> Result<AdmittedRequest<'a>> {
	validate_profile(config)?;
	hia_contract::validate_input(tool, &arguments)?;
	let original = canonical(&arguments)?;
	let profile = config
		.hia_worker
		.as_ref()
		.context("HIA tools are disabled; configure a pinned HIA worker")?
		.clone();
	if tool != "hia_describe"
		&& tool != "hia_resource_read"
		&& arguments["catalog_sha256"] != profile.catalog_sha256
	{
		bail!("HIA catalog changed; discover the current contract before creating a request");
	}
	let capture = if tool == "hia_artifact" {
		resolve_capture_path(&arguments, workdir, &profile, config)?
	} else {
		None
	};
	Ok(AdmittedRequest {
		original,
		profile,
		arguments,
		capture,
	})
}

struct AdmittedRequest<'a> {
	original: Vec<u8>,
	profile: HiaWorkerProfile,
	arguments: Value,
	capture: Option<CapturePath<'a>>,
}

pub(super) fn prepare_request(
	config: &RuntimeConfig,
	tool: &str,
	arguments: Value,
	workdir: &Path,
) -> Result<PreparedRequest> {
	let AdmittedRequest {
		original,
		profile,
		mut arguments,
		capture,
	} = admit_request(config, tool, arguments, workdir)?;
	if let Some(capture) = capture {
		let allowed = capture.allowed(&profile);
		capture.apply(&mut arguments, allowed)?;
	}
	prepare_reference(tool, original, profile, arguments)
}

fn prepare_reference(
	tool: &str,
	original: Vec<u8>,
	profile: HiaWorkerProfile,
	arguments: Value,
) -> Result<PreparedRequest> {
	let transport_arguments_sha256 = sha256(&original);
	let profile_sha256 = sha256(&canonical(&serde_json::to_value(&profile)?)?);
	let body = json!({
		"schema":"hia-agent-worker-request-v1", "tool":tool, "arguments":arguments,
		"profile_sha256":profile_sha256, "catalog_sha256":profile.catalog_sha256,
	});
	let request_sha256 = sha256(&canonical(&body)?);
	let worker = WorkerRequest {
		schema: "hia-agent-worker-request-v1".into(),
		tool: tool.into(),
		arguments,
		request_sha256: request_sha256.clone(),
		profile_sha256,
		catalog_sha256: profile.catalog_sha256.clone(),
	};
	// Payload and profile are deliberately absent for mutations: an altered
	// request with the same tool/key must collide in the durable owner.
	let identity = match worker.arguments.get("request_key").and_then(Value::as_str) {
		Some(key) => json!({"tool":tool,"key":key}),
		None => json!({"tool":tool,"readonly_request_sha256":request_sha256}),
	};
	let key = format!("hia-agent-{}", sha256(&canonical(&identity)?));
	let mut stdin = String::from_utf8(canonical(&serde_json::to_value(&worker)?)?)?;
	stdin.push('\n');
	assemble_request(worker, profile, transport_arguments_sha256, key, stdin)
}

#[cfg(target_os = "linux")]
async fn prepare_native_request(
	config: &RuntimeConfig,
	tool: &str,
	arguments: Value,
	workdir: &Path,
) -> Result<PreparedRequest> {
	let AdmittedRequest {
		original,
		profile,
		mut arguments,
		capture,
	} = admit_request(config, tool, arguments, workdir)?;
	if let Some(capture) = capture {
		let allowed = if super::hia_request_prepare::capture_policy_selected() {
			super::hia_request_prepare::admit_capture_path(
				&capture.selected,
				capture.same_host,
				capture.explicit_identity,
				[
					&profile.artifact_roots,
					&capture.host.allowed_read_path_prefixes,
					&capture.host.protected_path_prefixes,
				],
			)
			.await?
		} else {
			capture.allowed(&profile)
		};
		capture.apply(&mut arguments, allowed)?;
	}
	if !super::hia_request_prepare::selected() {
		return prepare_reference(tool, original, profile, arguments);
	}
	let profile_wire = canonical(&serde_json::to_value(&profile)?)?;
	let normalized = canonical(&arguments)?;
	let tool_wire = serde_json::to_vec(tool)?;
	let key_wire = match arguments.get("request_key").and_then(Value::as_str) {
		Some(key) => serde_json::to_vec(key)?,
		None => Vec::new(),
	};
	let encoded = super::hia_request_prepare::encode(
		&profile.catalog_sha256,
		[&original, &profile_wire, &normalized, &tool_wire, &key_wire],
	)
	.await?;
	let worker = WorkerRequest {
		schema: "hia-agent-worker-request-v1".into(),
		tool: tool.into(),
		arguments,
		request_sha256: encoded.request_sha256,
		profile_sha256: encoded.profile_sha256,
		catalog_sha256: profile.catalog_sha256.clone(),
	};
	let prepared = assemble_request(
		worker,
		profile,
		encoded.transport_arguments_sha256,
		format!("hia-agent-{}", encoded.idempotency_digest),
		encoded.stdin,
	)?;
	tracing::info!(%tool, "Native HIA Worker request prepared");
	Ok(prepared)
}

fn assemble_request(
	worker: WorkerRequest,
	profile: HiaWorkerProfile,
	transport_arguments_sha256: String,
	key: String,
	stdin: String,
) -> Result<PreparedRequest> {
	if stdin.len() > MAX_WORKER_BYTES {
		bail!("HIA worker request exceeds 512 KiB");
	}
	let mut args = vec![
		"-B".into(),
		"-E".into(),
		"-s".into(),
		"-m".into(),
		"hepta.hia_agent_worker".into(),
		"--state-root".into(),
		profile.state_root.clone(),
		"--expected-worker-sha256".into(),
		profile.worker_sha256.clone(),
		"--expected-backend-sha256".into(),
		profile.backend_sha256.clone(),
		"--expected-catalog-sha256".into(),
		profile.catalog_sha256.clone(),
	];
	for root in &profile.artifact_roots {
		args.extend(["--artifact-root".into(), root.clone()]);
	}
	if let (Some(manifest), Some(digest)) = (
		&profile.native_helpers_manifest,
		&profile.native_helpers_sha256,
	) {
		args.extend([
			"--native-helpers-manifest".into(),
			manifest.clone(),
			"--expected-native-helpers-sha256".into(),
			digest.clone(),
		]);
	}
	args.push("--request-json-stdin".into());
	let params = ProcessStartParams {
		host: profile.host.clone(),
		executable: profile.python_executable.clone(),
		args,
		cwd: Some(profile.working_directory.clone()),
		env: BTreeMap::from([
			("LC_ALL".into(), "C.UTF-8".into()),
			// Preserve the original caller spelling even when path resolution
			// normalizes a registered SSH URI before sending it to the worker.
			(
				"HIA_TRANSPORT_ARGUMENTS_SHA256".into(),
				transport_arguments_sha256,
			),
		]),
		stdin: Some(stdin),
		timeout_seconds: Some(profile.timeout_seconds),
		idempotency_key: Some(key),
		nice: Some(0),
		cpu_quota_percent: Some(100),
		memory_max_bytes: Some(profile.memory_max_bytes),
	};
	Ok(PreparedRequest {
		params,
		worker,
		profile,
	})
}

fn validate_result_bindings(
	tool: &str,
	arguments: &Value,
	response: &Value,
	profile: &HiaWorkerProfile,
) -> Result<()> {
	if response["status"] != "completed" {
		return Ok(());
	}
	let result = &response["result"];
	let fields: &[&str] = match tool {
		"hia_read" => &["artifact"],
		"hia_context" => &["compiler_profile", "target_profile"],
		"hia_inspect" => &["program"],
		"hia_verify" => &["candidate", "subject"],
		"hia_emit" => &["candidate", "backend_profile"],
		"hia_evaluate" => &["baseline_artifact", "candidate_artifact"],
		"hia_adopt" | "hia_rollback" => &["target_slot"],
		_ => &[],
	};
	for field in fields {
		if result[field] != arguments[field] {
			bail!("HIA result is bound to a different {field}");
		}
	}
	if tool == "hia_verify" {
		let claims = arguments["claims"]
			.as_array()
			.context("HIA verification request omitted its claims")?;
		let checks = result["checks"]
			.as_array()
			.context("HIA verification result omitted its scoped checks")?;
		if checks.len() != claims.len()
			|| claims.iter().any(|claim| {
				checks
					.iter()
					.filter(|check| check["claim"] == *claim)
					.count() != 1
			}) {
			bail!("HIA verification result changed its requested claims");
		}
		let subject = arguments["subject"]
			.as_object()
			.context("HIA verification request omitted its subject")?;
		let mut installation = json!({
			"worker_sha256":profile.worker_sha256,
			"backend_sha256":profile.backend_sha256,
			"catalog_sha256":profile.catalog_sha256
		});
		if let Some(digest) = &profile.native_helpers_sha256 {
			installation["native_helpers_sha256"] = json!(digest);
		}
		for check in checks {
			for (field, value) in subject {
				if check["subject"][field] != *value {
					bail!("HIA proof scope changed its selected {field}");
				}
			}
			for field in ["candidate", "base_program", "context"] {
				if check["subject"][field] != arguments[field] {
					bail!("HIA proof scope is bound to a different {field}");
				}
			}
			if check["subject"]["base_core_sha256"].is_null() != arguments["base_program"].is_null()
			{
				bail!("HIA proof scope changed whether a base Core was selected");
			}
			if check["property"]["id"] != check["claim"]
				|| check["profile"] != arguments["validation_profile"]
				|| check["validator"] != arguments["validation_profile"]
			{
				bail!("HIA proof property or validation profile differs from its request");
			}
			if check["checker"]["installation"] != installation {
				bail!("HIA proof checker differs from the admitted installation");
			}
		}
	}
	if tool == "hia_describe" && result["catalog_sha256"] != profile.catalog_sha256 {
		bail!("HIA discovery changed the admitted catalog identity");
	}
	if tool == "hia_resource_read" && result["artifact"]["uri"] != arguments["uri"] {
		bail!("HIA resource result changed its exact issued URI");
	}
	if tool == "hia_candidate" {
		let base = if arguments["change"]["kind"] == "patch" {
			&arguments["change"]["base_program"]
		} else {
			&Value::Null
		};
		if result["base_program"] != *base {
			bail!("HIA candidate result changed its selected base");
		}
	}
	if matches!(tool, "hia_adopt" | "hia_rollback")
		&& result["previous"] != arguments["expected_current"]
	{
		bail!("HIA version result changed its compare-and-swap predecessor");
	}
	if tool == "hia_adopt" && result["active_artifact"] != arguments["candidate_artifact"] {
		bail!("HIA adoption result changed its selected native artifact");
	}
	Ok(())
}

fn validate_report(prepared: &PreparedRequest, stdout: &[u8], exit_code: i32) -> Result<Value> {
	if stdout.len() > MAX_WORKER_BYTES {
		bail!("HIA worker report exceeds its retention bound");
	}
	let report: WorkerReport =
		serde_json::from_slice(stdout).context("HIA worker omitted a complete typed report")?;
	let request = &prepared.worker;
	if exit_code != 0
		|| report.schema != "hia-agent-worker-report-v1"
		|| !report.complete
		|| report.tool != request.tool
		|| report.request_sha256 != request.request_sha256
		|| report.profile_sha256 != request.profile_sha256
		|| report.catalog_sha256 != request.catalog_sha256
		|| report.worker_sha256 != prepared.profile.worker_sha256
		|| report.backend_sha256 != prepared.profile.backend_sha256
		|| report.native_helpers_sha256 != prepared.profile.native_helpers_sha256
	{
		bail!("HIA terminal report does not match the exact admitted request and installed code");
	}
	if !matches!(
		report.response["status"].as_str(),
		Some("completed" | "rejected")
	) {
		bail!("HIA worker report did not publish a terminal domain result");
	}
	check_response(prepared, report.response)
}

fn check_response(prepared: &PreparedRequest, response: Value) -> Result<Value> {
	let request = &prepared.worker;
	hia_contract::validate_output(&request.tool, &response)?;
	validate_result_bindings(
		&request.tool,
		&request.arguments,
		&response,
		&prepared.profile,
	)?;
	Ok(response)
}

async fn admit_report(prepared: &PreparedRequest, stdout: &[u8], exit_code: i32) -> Result<Value> {
	if !super::hia_wire_candidate::terminal_selected() {
		return validate_report(prepared, stdout, exit_code);
	}
	if stdout.len() > MAX_WORKER_BYTES {
		bail!("HIA worker report exceeds its retention bound");
	}
	let request = &prepared.worker;
	let profile = &prepared.profile;
	let expected = json!({
		"tool": request.tool,
		"request_sha256": request.request_sha256,
		"profile_sha256": request.profile_sha256,
		"catalog_sha256": request.catalog_sha256,
		"worker_sha256": profile.worker_sha256,
		"backend_sha256": profile.backend_sha256,
		"native_helpers_sha256": profile.native_helpers_sha256,
		"arguments": request.arguments,
	});
	let response = super::hia_wire_candidate::admit_terminal(&expected, stdout, exit_code).await?;
	// HIA has already matched the prepared arguments to any completed result.
	// The independent owner schema remains mandatory before publication.
	hia_contract::validate_output(&request.tool, &response)?;
	Ok(response)
}

fn operation(prepared: &PreparedRequest, raw: &Value) -> Result<Value> {
	let job = raw
		.get("job")
		.context("native owner omitted original job record")?;
	let id = job["id"]
		.as_str()
		.context("native owner omitted original job identity")?;
	if !valid_name(id)
		|| job["host"] != prepared.params.host
		|| job["idempotency_key"].as_str() != prepared.params.idempotency_key.as_deref()
		|| job["request_digest"] != super::runtime::jobs::request_digest(&prepared.params)?
	{
		bail!("native owner record differs from the admitted HIA job");
	}
	Ok(json!({"host":prepared.params.host,"job_id":id,
		"request_sha256":prepared.worker.request_sha256,"report_artifact":null}))
}

#[cfg(target_os = "linux")]
async fn admit_operation(prepared: &PreparedRequest, raw: &Value) -> Result<Value> {
	use super::hia_request_prepare as hia;
	if !hia::job_operation_selected() {
		return operation(prepared, raw);
	}
	let job = raw
		.get("job")
		.context("native owner omitted original job record")?;
	let id = job["id"]
		.as_str()
		.context("native owner omitted original job identity")?;
	let key = prepared
		.params
		.idempotency_key
		.as_deref()
		.context("HIA request lacked its durable job key")?;
	let binding = super::runtime::jobs::owned_request_digest(&prepared.params).await?;
	hia::job_operation(
		[
			id,
			&prepared.params.host,
			job["host"].as_str().unwrap_or_default(),
			key,
			job["idempotency_key"].as_str().unwrap_or_default(),
		],
		[
			&binding,
			job["request_digest"].as_str().unwrap_or_default(),
			&prepared.worker.request_sha256,
		],
	)
	.await
}

enum PendingReason<'a> {
	OwnerState(u8),
	OwnerBindingMismatch,
	WorkerTerminated,
	RequestUnknown,
	ReportInvalid,
	ObservationUnavailable(&'a str),
}

impl PendingReason<'_> {
	#[cfg(target_os = "linux")]
	fn observations(&self) -> (u64, u64, &str) {
		match self {
			Self::OwnerState(flags) => (0, u64::from(*flags), ""),
			Self::OwnerBindingMismatch => (1, 0, ""),
			Self::WorkerTerminated => (2, 0, ""),
			Self::RequestUnknown => (3, 0, ""),
			Self::ReportInvalid => (4, 0, ""),
			Self::ObservationUnavailable(diagnostic) => (5, 0, diagnostic),
		}
	}

	fn legacy_error(&self) -> Option<(&'static str, std::borrow::Cow<'static, str>)> {
		let (code, message) = match self {
			Self::OwnerState(0) => return None,
			Self::OwnerState(_) => (
				"HIA_OPERATION_UNKNOWN",
				"The original job has no confirmed terminal outcome. Observe this same tool and request key; do not allocate a replacement.",
			),
			Self::OwnerBindingMismatch => (
				"HIA_OWNER_BINDING_MISMATCH",
				"Original native output binding changed; keep this request unchanged and observe it.",
			),
			Self::WorkerTerminated => (
				"HIA_WORKER_TERMINATED",
				"Original worker terminated without a successful bound domain report. Its operation remains available through process_status/read; do not relaunch it.",
			),
			Self::RequestUnknown => (
				"HIA_REQUEST_UNKNOWN",
				"The worker retained an uncertain durable intent or could not confirm native-child termination. Its original operation is preserved; do not repeat the effect with a new key.",
			),
			Self::ReportInvalid => (
				"HIA_REPORT_INVALID",
				"Original worker report is incomplete, mismatched or outside the declared schema. No domain success is admitted; retain and inspect this original job.",
			),
			Self::ObservationUnavailable(diagnostic) => {
				return Some(("HIA_OBSERVATION_UNAVAILABLE", format!(
					"Complete terminal output could not be authenticated. {diagnostic}. Observe this exact original request; a disconnected observation does not establish termination."
				).into()));
			}
		};
		Some((code, message.into()))
	}
}

async fn pending(
	prepared: &PreparedRequest,
	operation: Value,
	reason: PendingReason<'_>,
) -> Result<Value> {
	#[cfg(target_os = "linux")]
	if super::hia_request_prepare::job_pending_selected() {
		let (reason, unknown, diagnostic) = reason.observations();
		let response = super::hia_request_prepare::job_pending(
			reason,
			unknown,
			&operation,
			&prepared.worker.request_sha256,
			diagnostic,
		)
		.await?;
		hia_contract::validate_output(&prepared.worker.tool, &response)?;
		return Ok(response);
	}
	let error = reason.legacy_error();
	let mut response = json!({"contract_version":hia_contract::CONTRACT_VERSION,
		"request_id":format!("hia_{}",prepared.worker.request_sha256),
		"status":if error.is_some() { "unknown" } else { "accepted" },"operation":operation});
	if let Some((code, message)) = error {
		response["error"] = json!({"code":code,"phase":"runtime_observation","message":message,
			"retry_action":"observe_original","details_artifact":null});
	}
	hia_contract::validate_output(&prepared.worker.tool, &response)?;
	Ok(response)
}

async fn observation_unavailable(
	prepared: &PreparedRequest,
	operation: Value,
	error: &anyhow::Error,
) -> Result<Value> {
	let diagnostic = crate::native::observation_failure_diagnostic(error);
	// Neither the source error nor request stdin is safe to print here. The
	// diagnostic contains only fixed labels and bounded numeric observations.
	tracing::warn!(
		host = %prepared.params.host,
		job_id = operation["job_id"].as_str().unwrap_or("unavailable"),
		request_sha256 = %prepared.worker.request_sha256,
		diagnostic = %diagnostic,
		"Original HIA output observation failed"
	);
	pending(
		prepared,
		operation,
		PendingReason::ObservationUnavailable(&diagnostic),
	)
	.await
}

fn admission_failure(
	tool: &str,
	arguments: &Value,
	config: &RuntimeConfig,
	error: &str,
) -> Result<Value> {
	let catalog_changed = !matches!(tool, "hia_describe" | "hia_resource_read")
		&& config
			.hia_worker
			.as_ref()
			.is_some_and(|profile| arguments["catalog_sha256"] != profile.catalog_sha256);
	let digest = sha256(&canonical(&json!({"tool":tool,"arguments":arguments}))?);
	let message: String = error.chars().take(2048).collect();
	let response = json!({"contract_version":hia_contract::CONTRACT_VERSION,
		"request_id":format!("hia_{digest}"),"status":"rejected",
		"error":{"code":if catalog_changed { "HIA_CATALOG_CHANGED" } else { "HIA_ADMISSION_REFUSED" },
			"phase":"runtime_admission","message":message,
			"retry_action":if catalog_changed { "refresh_context" } else { "correct_input" },"details_artifact":null}});
	hia_contract::validate_output(tool, &response)?;
	Ok(response)
}

/// Existing bindings never enter an execution path, including after cancellation.
pub(super) async fn execute(tool: &str, arguments: Value, workdir: &Path) -> Result<Value> {
	let config = runtime_config()?;
	#[cfg(target_os = "linux")]
	let result = if super::hia_request_prepare::selected()
		|| super::hia_request_prepare::capture_policy_selected()
	{
		prepare_native_request(config, tool, arguments.clone(), workdir).await
	} else {
		prepare_request(config, tool, arguments.clone(), workdir)
	};
	#[cfg(not(target_os = "linux"))]
	let result = prepare_request(config, tool, arguments.clone(), workdir);
	let prepared = match result {
		Ok(prepared) => prepared,
		Err(error) => return admission_failure(tool, &arguments, config, &error.to_string()),
	};
	if super::hia_wire_candidate::schema_selected() {
		if let Err(error) = super::hia_wire_candidate::observe_schema(
			super::hia_wire_candidate::SchemaSide::Request,
			tool,
			&prepared.worker.catalog_sha256,
			&prepared.worker.arguments,
		)
		.await
		{
			return admission_failure(tool, &arguments, config, &error.to_string());
		}
	}
	#[cfg(target_os = "linux")]
	if super::hia_request_prepare::job_operation_selected() {
		super::hia_request_prepare::job_operation_image()?;
	}
	#[cfg(target_os = "linux")]
	if super::hia_request_prepare::job_pending_selected() {
		super::hia_request_prepare::job_pending_image()?;
	}
	let original = crate::native::observe_request(prepared.params.clone()).await?;
	let raw = match original {
		Some(raw) => raw,
		None => {
			// This variant forbids relaunch of an uncertain binding even if a
			// simultaneous request wins the owner lock after our observation.
			crate::native::execute_or_observe_with_entry(prepared.params.clone(), |_| Ok(()))
				.await?
		}
	};
	let raw: Value =
		serde_json::from_str(&raw).context("native owner returned an invalid observation")?;
	#[cfg(target_os = "linux")]
	let original_operation = admit_operation(&prepared, &raw).await?;
	#[cfg(not(target_os = "linux"))]
	let original_operation = operation(&prepared, &raw)?;
	match crate::native::observe_terminal_output(&prepared.params, MAX_WORKER_BYTES).await {
		Ok(Some(output)) => {
			if !output.matches_request(&prepared.params)?
				|| output.job_id() != original_operation["job_id"]
			{
				return pending(
					&prepared,
					original_operation,
					PendingReason::OwnerBindingMismatch,
				)
				.await;
			}
			let exit_code = output.exit_code();
			let succeeded = output.outcome() == crate::native::NativeJobOutcome::Succeeded;
			let (stdout, _stderr) = output.into_streams();
			if !succeeded {
				return pending(
					&prepared,
					original_operation,
					PendingReason::WorkerTerminated,
				)
				.await;
			}
			let report = admit_report(&prepared, &stdout, exit_code).await;
			let report = match report {
				Ok(response) if super::hia_wire_candidate::schema_selected() => {
					super::hia_wire_candidate::observe_schema(
						super::hia_wire_candidate::SchemaSide::Response,
						tool,
						&prepared.worker.catalog_sha256,
						&response,
					)
					.await
					.map(|()| response)
				}
				other => other,
			};
			match report {
				Ok(response)
					if response["status"] == "rejected"
						&& matches!(
							response["error"]["code"].as_str(),
							Some("E_HIA_REQUEST_UNKNOWN" | "E_HIA_TERMINATION_UNKNOWN")
						) =>
				{
					pending(&prepared, original_operation, PendingReason::RequestUnknown).await
				}
				Ok(response) => Ok(response),
				Err(_) => {
					pending(&prepared, original_operation, PendingReason::ReportInvalid).await
				}
			}
		}
		Ok(None) => {
			let flags = u8::from(raw["status"]["effect_outcome"] == "unknown")
				| (u8::from(raw["status"]["outcome"] == "unknown") << 1)
				| (u8::from(raw["job"]["launch_state"] == "unknown") << 2);
			pending(
				&prepared,
				original_operation,
				PendingReason::OwnerState(flags),
			)
			.await
		}
		Err(error) => observation_unavailable(&prepared, original_operation, &error).await,
	}
}

#[cfg(test)]
#[path = "hia_provider_tests.rs"]
mod tests;
