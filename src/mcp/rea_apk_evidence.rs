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

//! The frozen APK static contract over admitted bytes, complete retained
//! Evidence, and derived summaries/pages. See LICENSES/REA-MIT.txt for the
//! upstream protocol attribution. The legacy cryptographic preview is separate.

use super::rea_contract::{self, Failure};
use super::rea_evidence_session::{EvidenceSession, RetainedRecord};
use super::rea_response_order::RecordOrigin;
use super::{rea_apk_signature, rea_evidence, rea_files, runtime};
use rmcp::model::CallToolResult;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio_util::sync::CancellationToken;

#[path = "rea_apk_static_worker.rs"]
mod worker;

pub(super) const OP: &str = "inspect_apk_signature";
pub(super) const MAX_BYTES: u64 = 512 * 1024 * 1024;
pub(super) const MAX_WORKER_REPLY: usize = 8 * 1024 * 1024 + 1024;
const CAPACITY_ACTION: &str =
	"Review the reported parser capacity and select an input within those bounds.";
#[cfg(not(test))]
pub(super) const DEADLINE_MS: u64 = 30_000;

struct Input {
	path: String,
	complete: bool,
	view: Value,
}

impl Input {
	fn parse(raw: &Value) -> Result<Self, Failure> {
		super::rea_apk_mcp_input::validate(raw, None, None)?;
		let path = raw["path"]
			.as_str()
			.ok_or_else(|| {
				Failure::input(
					OP,
					vec![json!({"path":["path"],"reason":"invalid_type","expected":"string"})],
				)
			})?
			.to_owned();
		let complete = raw.get("detail").is_some_and(|value| value == "complete");
		let view = if let Some(view) = raw.get("view") {
			let mut selected = view.as_object().cloned().ok_or_else(|| {
				Failure::input(
					OP,
					vec![json!({"path":["view"],"reason":"invalid_type","expected":"object"})],
				)
			})?;
			selected.insert("kind".into(), json!("apk-signature"));
			Value::Object(selected)
		} else {
			json!({"kind":"summary"})
		};
		let view = rea_apk_signature::normalize_static_view(&view)
			.map_err(|error| view_failure(OP, error))?;
		Ok(Self {
			path,
			complete,
			view,
		})
	}
}

pub(super) fn active(cancellation: &CancellationToken) -> Result<(), Failure> {
	if cancellation.is_cancelled() {
		Err(Failure::cancelled(OP))
	} else {
		Ok(())
	}
}

fn file_limit(path: &str, grew: bool) -> Failure {
	let reason = if grew {
		format!("Selected artifact grew beyond its byte limit: {path}")
	} else {
		format!("Selected artifact exceeds {MAX_BYTES} bytes: {path}")
	};
	Failure::resource(
		OP,
		"file-size",
		&reason,
		json!({"max_input_bytes":MAX_BYTES}),
		false,
		"The size budget is fixed; select a smaller archive.",
	)
}

fn not_regular(path: &str) -> Failure {
	Failure::input(
		OP,
		vec![json!({"path":["path"],"reason":"invalid_format",
		"message":format!("Expected a regular file without a symlink: {path}")})],
	)
}

fn acquisition_failure(error: anyhow::Error, path: &str) -> Failure {
	let system = error
		.chain()
		.find_map(|cause| cause.downcast_ref::<std::io::Error>())
		.and_then(std::io::Error::raw_os_error);
	if let Some(code) = system {
		let name = match code {
			libc::EACCES => "EACCES",
			libc::EPERM => "EPERM",
			libc::ENOENT => "ENOENT",
			libc::ENOTDIR => "ENOTDIR",
			libc::ELOOP => "ELOOP",
			libc::ENAMETOOLONG => "ENAMETOOLONG",
			_ => "EIO",
		};
		if matches!(code, libc::EACCES | libc::EPERM) {
			return Failure::access(OP, path, name);
		}
		if code == libc::ELOOP {
			return not_regular(path);
		}
		if matches!(code, libc::ENOENT | libc::ENOTDIR | libc::ENAMETOOLONG) {
			return Failure::input(
				OP,
				vec![json!({"path":["path"],"reason":"invalid_value",
				"message":format!("No regular file can be read at the selected path ({name}): {path}.")})],
			);
		}
	}
	if error.to_string().contains("requires a regular file") {
		return not_regular(path);
	}
	Failure::adapter("apk-signature", OP)
}

async fn capture(
	path: &str,
	roots: &[PathBuf],
	cancellation: &CancellationToken,
) -> Result<(Vec<u8>, String), Failure> {
	active(cancellation)?;
	let (mut file, before) = rea_files::open_confined(Path::new(path), roots)
		.await
		.map_err(|error| acquisition_failure(error, path))?;
	if before.len() > MAX_BYTES {
		return Err(file_limit(path, false));
	}
	let mut bytes = Vec::new();
	bytes
		.try_reserve_exact(before.len() as usize)
		.map_err(|_| {
			Failure::resource(
				OP,
				"memory",
				"Host memory could not hold the admitted APK snapshot.",
				json!({"max_input_bytes":MAX_BYTES}),
				false,
				"Retry with sufficient memory or a smaller artifact.",
			)
		})?;
	let mut hash = Sha256::new();
	let mut chunk = vec![0_u8; 65536];
	loop {
		active(cancellation)?;
		let count = file
			.read(&mut chunk)
			.await
			.map_err(|error| acquisition_failure(error.into(), path))?;
		if count == 0 {
			break;
		}
		active(cancellation)?;
		if bytes.len() as u64 + count as u64 > MAX_BYTES {
			return Err(file_limit(path, true));
		}
		bytes.extend_from_slice(&chunk[..count]);
		hash.update(&chunk[..count]);
	}
	let after = file
		.metadata()
		.await
		.map_err(|error| acquisition_failure(error.into(), path))?;
	let (_current, current) = rea_files::open_confined(Path::new(path), roots)
		.await
		.map_err(|_| {
			Failure::changed(OP, path, &format!("Artifact changed during read: {path}"))
		})?;
	#[cfg(unix)]
	if bytes.len() as u64 != before.len()
		|| rea_files::ensure_unchanged(&before, &after).is_err()
		|| rea_files::ensure_unchanged(&before, &current).is_err()
	{
		return Err(Failure::changed(
			OP,
			path,
			&format!("Artifact changed during read: {path}"),
		));
	}
	active(cancellation)?;
	Ok((
		bytes,
		hash.finalize()
			.into_iter()
			.map(|byte| format!("{byte:02x}"))
			.collect(),
	))
}

fn parser_failure(error: rea_apk_signature::ApkInspectionError, path: &str) -> Failure {
	use rea_apk_signature::{ApkErrorTag, ApkResource};
	if error.operation.as_ref() != OP {
		return Failure::output(OP, "APK worker changed the operation identity.");
	}
	match error.tag {
		ApkErrorTag::AnalysisInputError => Failure::input(
			OP,
			vec![json!({"path":["path"],"reason":"invalid_value","message":error.reason})],
		),
		ApkErrorTag::AnalysisUnsupportedTargetError => {
			let mut failure = Failure::unsupported(OP, path, &error.reason);
			if let Some(action) = error.remediation_action {
				failure.0["remediation"]["action"] = json!(action.as_str());
			}
			failure
		}
		ApkErrorTag::AnalysisResourceConstraintError => {
			let (resource, retryable, action)=match error.resource {
				Some(ApkResource::Capacity)=>("capacity",true,CAPACITY_ACTION),
				Some(ApkResource::FileSize)=>("file-size",false,"The size budget is fixed; select a smaller archive."),
				Some(ApkResource::Memory)=>("memory",false,"Review the reported worker memory limits and available host memory. Retry with sufficient memory or a smaller artifact; REA retains tighter inherited limits."),
				Some(ApkResource::Cpu)=>("cpu",false,"Review the reported worker CPU limits and observed signal. Retry with sufficient CPU time or a smaller artifact; REA retains tighter inherited limits."),
				_=>return Failure::output(OP,"APK worker returned an unknown resource refusal."),
			};
			Failure::resource(
				OP,
				resource,
				&error.reason,
				json!(error.reported_limits),
				retryable,
				action,
			)
		}
		ApkErrorTag::AnalysisCancelledError => Failure::cancelled(OP),
		ApkErrorTag::AnalysisTimeoutError => error.timeout_ms.map_or_else(
			|| Failure::output(OP, "APK worker omitted its deadline."),
			|timeout| Failure::timeout(OP, timeout),
		),
		_ => Failure::output(OP, format!("Unexpected APK parser failure: {error}")),
	}
}

pub(super) fn view_failure(operation: &str, error: rea_apk_signature::ApkViewError) -> Failure {
	let issues = error
		.issues
		.into_iter()
		.map(serde_json::to_value)
		.collect::<Result<Vec<_>, _>>();
	match issues {
		Ok(issues) => Failure::input(operation, issues),
		Err(error) => Failure::output(operation, error.to_string()),
	}
}

fn complete_record(
	mut reply: Map<String, Value>,
	input: &Input,
	digest: &str,
	length: u64,
) -> Result<Value, Failure> {
	let report = reply
		.remove("report")
		.ok_or_else(|| Failure::output(OP, "APK worker omitted its complete report."))?;
	let limitations = reply
		.remove("limitations")
		.ok_or_else(|| Failure::output(OP, "APK worker omitted its limitations."))?;
	if !reply.is_empty()
		|| rea_apk_signature::validate_static_report(&report).is_err()
		|| report["artifact"]["path"] != input.path
		|| report["artifact"]["sha256"] != digest
		|| report["artifact"]["bytes"].as_u64() != Some(length)
		|| !limitations
			.as_array()
			.is_some_and(|items| items.iter().all(Value::is_string))
	{
		return Err(Failure::output(OP,"APK signature reader returned malformed data or changed the selected artifact identity."));
	}
	let format = if input.path.to_ascii_lowercase().ends_with(".apk") {
		"apk"
	} else {
		"zip"
	};
	let target = json!({"path":input.path,"format":format,"sha256":digest});
	let provider = json!({"id":"apk-signature","name":"REA APK signature reader","version":null});
	let mut observation = Map::new();
	observation.insert("operation".into(), json!(OP));
	observation.insert("parameters".into(), json!({"path":input.path}));
	observation.insert("result".into(), report);
	observation.insert("confidence".into(), json!("observed"));
	observation.insert(
		"locations".into(),
		json!([{"kind":"artifact-path","path":input.path}]),
	);
	observation.insert("limitations".into(), limitations);
	rea_evidence::create_record_owned(Some(&target), &provider, Value::Object(observation)).map_err(
		|error| Failure::output(OP, format!("APK Evidence construction failed: {error:#}")),
	)
}

pub(super) fn project_record(parent: &Value, view: &Value) -> Result<Value, Failure> {
	let id = parent["evidence_id"]
		.as_str()
		.ok_or_else(|| Failure::integrity("Parent Evidence identifier is missing."))?;
	let limitations = parent["limitations"]
		.as_array()
		.ok_or_else(|| Failure::integrity("Parent limitations are missing."))?
		.iter()
		.map(|value| {
			value
				.as_str()
				.map(str::to_owned)
				.ok_or_else(|| Failure::integrity("Parent limitation is not a string."))
		})
		.collect::<Result<Vec<_>, _>>()?;
	let subject = &parent["subject"];
	let mut projection = rea_apk_signature::project_static_view(
		&parent["normalized_result"],
		id,
		Some(subject),
		&limitations,
		view,
	)
	.map_err(|error| view_failure("inspect_analysis_view", error))?;
	let seal = rea_evidence::canonical_digest(&projection)
		.map_err(|error| Failure::integrity(error.to_string()))?;
	projection["view_digest"] = json!(seal);
	let target = if subject.is_null() {
		None
	} else {
		Some(
			json!({"path":subject["local_path"],"sha256":subject["digest"]["sha256"],"format":subject["format"],"architecture":subject["architecture"]}),
		)
	};
	let provider =
		json!({"id":"rea-analysis-view","name":"REA analysis view projection","version":"1"});
	let mut observation = Map::new();
	observation.insert("operation".into(), json!("inspect_analysis_view"));
	observation.insert("predicateType".into(), json!("rea.analysis-view"));
	observation.insert(
		"parameters".into(),
		json!({"parent_evidence_id":id,"view":view}),
	);
	observation.insert("confidence".into(), json!("derived"));
	observation.insert("authority".into(), parent["authority"].clone());
	observation.insert("limitations".into(), projection["limitations"].clone());
	observation.insert(
		"locations".into(),
		if projection["artifact"]["path"]
			.as_str()
			.is_some_and(|path| !path.is_empty())
		{
			json!([{"kind":"artifact-path","path":projection["artifact"]["path"]}])
		} else {
			json!([])
		},
	);
	observation.insert("evidenceLinks".into(), json!([id]));
	observation.insert("result".into(), projection);
	rea_evidence::create_record_owned(target.as_ref(), &provider, Value::Object(observation))
		.map_err(|error| {
			Failure::output(
				"inspect_analysis_view",
				format!("Analysis view Evidence construction failed: {error:#}"),
			)
		})
}

async fn execute(
	input: Input,
	roots: &[PathBuf],
	session: Arc<EvidenceSession>,
	cancellation: CancellationToken,
	owner_admission: Arc<runtime::effect_owner_fence::AdmissionPermit>,
) -> Result<RetainedRecord, Failure> {
	active(&cancellation)?;
	let (bytes, digest) = capture(&input.path, roots, &cancellation).await?;
	let length = bytes.len() as u64;
	let reply = worker::inspect_isolated(
		&input.path,
		&digest,
		Arc::new(bytes),
		&cancellation,
		Arc::clone(&owner_admission),
	)
	.await?;
	let Value::Object(mut reply) = reply else {
		return Err(Failure::output(
			OP,
			"APK worker returned a non-object response.",
		));
	};
	if let Some(failure) = reply.remove("failure") {
		if !reply.is_empty() {
			return Err(Failure::output(
				OP,
				"APK worker mixed failure and success fields.",
			));
		}
		let failure = serde_json::from_value(failure)
			.map_err(|error| Failure::output(OP, format!("Invalid APK worker failure: {error}")))?;
		return Err(parser_failure(failure, &input.path));
	}
	tokio::task::spawn_blocking(move || {
		let _admission = owner_admission;
		let parent = complete_record(reply, &input, &digest, length)?;
		let retained = session.record_with_origin(parent, RecordOrigin::NativeTool)?;
		if cancellation.is_cancelled() {
			return Err(Failure::cancelled(OP).partial(retained.reference));
		}
		if input.complete {
			return Ok(retained);
		}
		let id = retained.evidence["evidence_id"]
			.as_str()
			.ok_or_else(|| Failure::integrity("Retained parent identifier is missing."))?;
		let parent = session
			.lookup(id)?
			.ok_or_else(|| Failure::integrity("Completed APK parent is not retained."))?;
		let projected = project_record(&parent, &input.view)?;
		let view = session.record_with_origin(projected, RecordOrigin::ApkToolDerived)?;
		if cancellation.is_cancelled() {
			return Err(Failure::cancelled(OP).partial(view.reference));
		}
		Ok(view)
	})
	.await
	.map_err(|error| Failure::output(OP, format!("APK Evidence owner failed: {error}")))?
}

pub(super) async fn inspect(
	raw: Value,
	session: Arc<EvidenceSession>,
	cancellation: CancellationToken,
	owner_admission: Arc<runtime::effect_owner_fence::AdmissionPermit>,
) -> CallToolResult {
	if let Err(error) = active(&cancellation) {
		return error.wire();
	}
	let input = match Input::parse(&raw) {
		Ok(input) => input,
		Err(error) => return error.wire(),
	};
	let roots = match runtime::runtime_config() {
		Ok(config) => config.controller_workspace_roots.clone(),
		Err(error) => return Failure::output(OP, error.to_string()).wire(),
	};
	match execute(input, &roots, session, cancellation, owner_admission).await {
		Ok(retained) => rea_contract::success_borrowed(
			OP,
			retained.evidence.as_ref(),
			Some(retained.reference),
			retained.origin,
		),
		Err(error) => error.wire(),
	}
}

pub fn run_worker() -> anyhow::Result<()> {
	worker::serve_once()
}

#[cfg(test)]
#[path = "rea_apk_evidence_tests.rs"]
mod tests;
