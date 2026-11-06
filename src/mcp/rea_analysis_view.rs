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

//! Derive views from authenticated Evidence without reopening the artifact.
//! The current native projector covers APK summaries and signing pages.
//! A source resolver owns authentication; projection never treats input as
//! authenticated merely because it carries a digest-shaped identifier.

use super::rea_contract::{self, Failure};
use super::rea_evidence_file::{self, FileReadError, FileReason, NativeJsonLimits, OwnedJson};
use super::rea_evidence_session::EvidenceSession;
use super::rea_evidence_source::{self, SourceError};
use super::rea_mcp_transport::InlineEvidenceOrder;
use super::rea_response_order::RecordOrigin;
use super::{rea_apk_evidence, rea_apk_signature, runtime};
use rmcp::model::CallToolResult;
use serde_json::{json, Map, Value};
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_util::sync::CancellationToken;

pub(super) const OP: &str = "inspect_analysis_view";
const MAX_CONCURRENT_OWNERS: usize = 2;

/// One ownership object follows acquisition, authentication, projection and
/// encoding. A dropped async waiter cannot release a running blocking owner.
struct ViewOwnership {
	_admission: Arc<runtime::effect_owner_fence::AdmissionPermit>,
	_capacity: OwnedSemaphorePermit,
}

fn ownership(
	admission: Arc<runtime::effect_owner_fence::AdmissionPermit>,
	cancellation: &CancellationToken,
) -> Result<Arc<ViewOwnership>, Failure> {
	active(cancellation)?;
	static CAPACITY: OnceLock<Arc<Semaphore>> = OnceLock::new();
	let semaphore = CAPACITY.get_or_init(|| Arc::new(Semaphore::new(MAX_CONCURRENT_OWNERS)));
	let capacity = Arc::clone(semaphore).try_acquire_owned().map_err(|_| {
		Failure::resource(
			OP,
			"concurrency",
			"The native analysis view owner capacity is occupied.",
			json!({"native_profile":true,"concurrent_owners":MAX_CONCURRENT_OWNERS}),
			true,
			"Wait for active Evidence source and view owners to finish, then retry.",
		)
	})?;
	Ok(Arc::new(ViewOwnership {
		_admission: admission,
		_capacity: capacity,
	}))
}

fn file_failure(error: FileReadError, path: &str) -> Failure {
	match error {
		FileReadError::File { reason, .. } => {
			let (code, category, message) = match reason {
				FileReason::Missing => ("invalid_request", "invalid_input", "Evidence file does not exist at the selected path. Check the path and try again."),
				FileReason::NotFile => ("invalid_request", "invalid_input", "Evidence path does not point to a regular file. Choose a file and try again."),
				FileReason::Io => ("execution_failure", "execution_failure", "Evidence file could not be accessed. Check file permissions and try again."),
				FileReason::PathLimit => ("resource_constraint", "resource_constraint", "Filesystem path-length constraints prevented reading or atomic publication at the selected path. Choose a shorter local path."),
			};
			let mut failure = Failure(json!({"code":code,"category":category,
				"message":message,"retryable":false,"remediation":{"action":message},
				"details":{"operation":"read","reason":reason.as_str(),"path":path}}));
			if reason == FileReason::PathLimit {
				failure.0["details"]["boundary"] = json!("filesystem-path");
			}
			failure
		}
		FileReadError::InvalidJson {
			message,
			user_message,
		} => {
			let public_message = user_message.as_deref().unwrap_or(
				"Evidence file is not valid JSON. Repair or recreate the file and try again.",
			);
			Failure(
				json!({"code":"evidence_integrity_mismatch","category":"execution_failure",
				"message":public_message,"retryable":false,"remediation":{"action":public_message},
				"details":{"operation":"read","reason":"invalid-json","path":path,
					"content_issues":[{"path":[],"reason":"invalid_format","expected":"JSON","message":message}]}}),
			)
		}
		FileReadError::RootString(_) => {
			source_failure(rea_evidence_source::reject_string_root(false), Some(path))
		}
		FileReadError::Cancelled => Failure::cancelled(OP),
		FileReadError::NativeProfileGap { feature, details } => {
			let mut failure = profile_gap();
			failure.0["details"]["reason"] = json!(format!(
				"The native Rust Evidence file source profile does not yet cover {feature}."
			));
			failure.0["details"]["native_profile"] = json!({
				"boundary":"evidence-json-import","feature":feature,"details":details});
			failure
		}
		FileReadError::Cleanup {
			errno,
			primary,
			native_cleanup_incomplete,
		} => {
			let mut failure = Failure::output(
				OP,
				"The Evidence file owner could not confirm descriptor cleanup.",
			);
			failure.0["details"]["cleanup"] = json!("incomplete");
			failure.0["details"]["native_cleanup_incomplete"] = json!(native_cleanup_incomplete);
			failure.0["details"]["errno"] = json!(errno);
			failure.0["details"]["primary"] = json!(primary);
			failure
		}
		FileReadError::Unexpected { message } => Failure::output(OP, message),
	}
}

fn source_failure(error: SourceError, file_path: Option<&str>) -> Failure {
	match error {
		SourceError::InvalidRecord { mut issues, .. } => {
			if let Some(path) = file_path {
				let message = "The selected file does not contain valid Evidence. Repair or recreate the file and try again.";
				return Failure(json!({"code":"invalid_request","category":"invalid_input",
					"message":message,"retryable":false,"remediation":{"action":message},
					"details":{"operation":"read","reason":"wrong-kind","path":path,"content_issues":issues}}));
			}
			for issue in &mut issues {
				let Some(path) = issue.get_mut("path").and_then(Value::as_array_mut) else {
					return Failure::output(
						OP,
						"Evidence authentication returned an invalid issue path.",
					);
				};
				let mut prefixed = vec![json!("source"), json!("evidence")];
				prefixed.append(path);
				*path = prefixed;
			}
			Failure::input(OP, issues)
		}
		SourceError::InvalidBundle { message } => Failure(json!({
			"code":"evidence_integrity_mismatch","category":"integrity_mismatch",
			"message":message,"retryable":false,"remediation":{"action":message},
			"details":{"reason":"Evidence bundle validation failed"}})),
		SourceError::Selection { message } => {
			let mut failure = Failure::input(
				OP,
				vec![json!({"path":["source","evidence_id"],
				"reason":"invalid_value","message":message})],
			);
			failure.0["message"] = json!(message);
			failure
		}
		SourceError::ProfileGap { feature } => {
			let mut failure = profile_gap();
			failure.0["details"]["reason"] = json!(format!("The native Rust Evidence source authentication profile does not yet cover {feature}."));
			failure
		}
		SourceError::SchemaException { message } => Failure::schema_exception(message),
		SourceError::Internal { message } => Failure::output(OP, message),
	}
}

async fn authenticate_inline_owned(
	value: Value,
	order: Option<Arc<InlineEvidenceOrder>>,
	cancellation: CancellationToken,
	ownership: Arc<ViewOwnership>,
) -> Result<Arc<Value>, Failure> {
	active(&cancellation)?;
	let owner_token = cancellation.child_token();
	let cancel_on_drop = owner_token.clone().drop_guard();
	let completed = tokio::task::spawn_blocking(move || {
		let _ownership = ownership;
		active(&owner_token)?;
		let authenticated = if let Some(order) = order {
			let resolver = |path: &[Value]| order.keys(path);
			rea_evidence_source::authenticate_inline_with_order(value, Some(&resolver))
		} else {
			rea_evidence_source::authenticate_inline(value)
		};
		active(&owner_token)?;
		let mut authenticated = authenticated.map_err(|error| source_failure(error, None))?;
		let owned = Arc::get_mut(&mut authenticated).ok_or_else(|| {
			Failure::output(
				OP,
				"New inline Evidence unexpectedly has shared mutable ownership.",
			)
		})?;
		normalize_authenticated_numbers(owned, 0)?;
		active(&owner_token)?;
		Ok(authenticated)
	})
	.await;
	let _ = cancel_on_drop.disarm();
	completed.map_err(|error| {
		Failure::output(
			OP,
			format!("Inline Evidence authentication owner failed: {error}"),
		)
	})?
}

async fn authenticate_file_owned(
	file: OwnedJson,
	selected: Option<String>,
	cancellation: CancellationToken,
	ownership: Arc<ViewOwnership>,
) -> Result<Arc<Value>, Failure> {
	active(&cancellation)?;
	let owner_token = cancellation.child_token();
	let cancel_on_drop = owner_token.clone().drop_guard();
	let completed = tokio::task::spawn_blocking(move || {
		let _ownership = ownership;
		active(&owner_token)?;
		let OwnedJson {
			value,
			object_order,
			selected_path,
			input_bytes,
			sha256,
		} = file;
		tracing::debug!(operation = OP, input_bytes, input_sha256 = %sha256,
			"Authenticating a stable Evidence JSON acquisition");
		let resolver = |path: &[Value]| object_order.keys(path);
		let authenticated = rea_evidence_source::authenticate_file_with_order(
			value,
			&selected_path,
			selected.as_deref(),
			Some(&resolver),
		);
		active(&owner_token)?;
		authenticated.map_err(|error| source_failure(error, Some(&selected_path)))
	})
	.await;
	let _ = cancel_on_drop.disarm();
	completed.map_err(|error| {
		Failure::output(
			OP,
			format!("File Evidence authentication owner failed: {error}"),
		)
	})?
}

/// The original parser has only JavaScript Number. Authentication commits to
/// that representation already; retain it when an owned inline tree enters a
/// Rust projector as well. No strings, member order or semantic ID change.
fn normalize_authenticated_numbers(value: &mut Value, depth: usize) -> Result<(), Failure> {
	if depth > 128 {
		return Err(Failure::output(
			OP,
			"Authenticated Evidence exceeded its admitted JSON depth.",
		));
	}
	match value {
		Value::Number(number) => {
			let value = number
				.as_f64()
				.filter(|value| value.is_finite())
				.ok_or_else(|| {
					Failure::output(
						OP,
						"Authenticated Evidence has an unrepresentable JavaScript number.",
					)
				})?;
			*number = if value == 0.0 {
				serde_json::Number::from(0)
			} else if value.fract() == 0.0 && (0.0..18_446_744_073_709_551_616.0).contains(&value) {
				serde_json::Number::from(value as u64)
			} else if value.fract() == 0.0 && (-9_223_372_036_854_775_808.0..0.0).contains(&value) {
				serde_json::Number::from(value as i64)
			} else {
				serde_json::Number::from_f64(value).ok_or_else(|| {
					Failure::output(OP, "Authenticated JavaScript number conversion failed.")
				})?
			};
		}
		Value::Array(values) => {
			for value in values {
				normalize_authenticated_numbers(value, depth + 1)?;
			}
		}
		Value::Object(values) => {
			for value in values.values_mut() {
				normalize_authenticated_numbers(value, depth + 1)?;
			}
		}
		_ => {}
	}
	Ok(())
}

pub(super) fn profile_gap() -> Failure {
	let message =
		"This analysis is unavailable for the current target. Choose another analysis or target.";
	Failure(json!({
		"code":"capability_unavailable", "category":"unsupported_provider",
		"message":message, "retryable":false, "remediation":{"action":message},
		"details":{"provider_id":"rea-analysis-view", "operation":OP,
			"reason":"The native Rust profile does not yet implement this analysis view source or parent operation."}
	}))
}

fn missing_reference(id: &str) -> Failure {
	Failure(json!({
		"code":"evidence_integrity_mismatch", "category":"integrity_mismatch",
		"message":format!("Evidence {id} is not available from the selected source. Supply complete inline Evidence, re-run its producer, or select/import its bundle before using this reference."),
		"retryable":false,
		"remediation":{"action":"Use an exact Evidence reference available from the selected source, supply the complete inline Evidence, re-run its producer, or select/import its Evidence bundle. close_binary clears a server session's retained records."},
		"details":{"evidence_id":id,"reason":"missing","expected":"Evidence available to the selected source","actual":null}
	}))
}

pub(super) fn retained_source(session: &EvidenceSession, id: &str) -> Result<Arc<Value>, Failure> {
	session.lookup(id)?.ok_or_else(|| missing_reference(id))
}

fn unsupported_parent(parent: &Value) -> Failure {
	let operation = parent["operation"].as_str().unwrap_or_default();
	let path = parent["normalized_result"]["artifact"]["path"]
		.as_str()
		.or_else(|| parent["normalized_result"]["input_path"].as_str())
		.or_else(|| parent["evidence_id"].as_str())
		.unwrap_or_default();
	Failure::unsupported(OP, path, &format!(
		"Parent Evidence operation {} does not support analysis views. Use completed Evidence from a supported parent operation with a compatible view. For a summary receipt, use its normalized_result.parent_evidence_id rather than the receipt's own evidence_id.",
		json!(operation)
	))
}

fn project_completed(parent: &Value, view: &Value) -> Result<Value, Failure> {
	match parent["operation"].as_str() {
		Some("inspect_apk_signature") => {}
		// These are the other records currently produced in the native session.
		// The frozen upstream also rejects both as view parents.
		Some("inspect_analysis_view" | "inspect_elf_notes") => {
			return Err(unsupported_parent(parent))
		}
		_ => return Err(profile_gap()),
	}
	let view = rea_apk_signature::normalize_static_view(view)
		.map_err(|error| rea_apk_evidence::view_failure(OP, error))?;
	rea_apk_evidence::project_record(parent, &view)
}

fn active(cancellation: &CancellationToken) -> Result<(), Failure> {
	if cancellation.is_cancelled() {
		Err(Failure::cancelled(OP))
	} else {
		Ok(())
	}
}

/// The caller supplies an authenticated source, never an unchecked inline tree.
/// Imported parents are borrowed here; only the newly derived view is retained.
async fn project_owned(
	parent: Arc<Value>,
	view: Value,
	session: Arc<EvidenceSession>,
	cancellation: CancellationToken,
	ownership: Arc<ViewOwnership>,
) -> Result<CallToolResult, Failure> {
	active(&cancellation)?;
	let owner_token = cancellation.child_token();
	let cancel_on_drop = owner_token.clone().drop_guard();
	let finished = tokio::task::spawn_blocking(move || {
		let _ownership = ownership;
		active(&owner_token)?;
		let projected = project_completed(&parent, &view);
		// Cancellation during synchronous projection wins over its failure and
		// prevents a newly derived record from being published.
		active(&owner_token)?;
		let retained = session.record_if_active(
			projected?,
			RecordOrigin::AnalysisViewToolDerived,
			&owner_token,
			OP,
		)?;
		if owner_token.is_cancelled() {
			return Err(Failure::cancelled(OP).partial(retained.reference));
		}
		let response = rea_contract::success_borrowed(
			OP,
			retained.evidence.as_ref(),
			Some(retained.reference.clone()),
			retained.origin,
		);
		if owner_token.is_cancelled() {
			return Err(Failure::cancelled(OP).partial(retained.reference));
		}
		Ok(response)
	})
	.await;
	let _ = cancel_on_drop.disarm();
	finished.map_err(|error| Failure::output(OP, format!("Analysis view owner failed: {error}")))?
}

fn string_field(source: &mut Map<String, Value>, key: &str) -> Result<String, Failure> {
	match source.remove(key) {
		Some(Value::String(value)) => Ok(value),
		_ => Err(Failure::output(
			OP,
			format!("Validated Evidence source field {key} is unavailable."),
		)),
	}
}

async fn execute(
	params: Value,
	inline_order: Option<Arc<InlineEvidenceOrder>>,
	roots: Vec<PathBuf>,
	session: Arc<EvidenceSession>,
	cancellation: CancellationToken,
	ownership: Arc<ViewOwnership>,
) -> Result<CallToolResult, Failure> {
	active(&cancellation)?;
	let Value::Object(mut params) = params else {
		return Err(Failure::output(
			OP,
			"Validated analysis view arguments are unavailable.",
		));
	};
	let Some(Value::Object(mut source)) = params.remove("source") else {
		return Err(Failure::output(
			OP,
			"Validated Evidence source is unavailable.",
		));
	};
	let view = params
		.remove("view")
		.ok_or_else(|| Failure::output(OP, "Validated analysis view selection is unavailable."))?;
	let kind = string_field(&mut source, "kind")?;
	let parent = match kind.as_str() {
		"retained-evidence" => {
			retained_source(&session, &string_field(&mut source, "evidence_id")?)?
		}
		"inline" => {
			let evidence = source
				.remove("evidence")
				.ok_or_else(|| Failure::output(OP, "Validated inline Evidence is unavailable."))?;
			authenticate_inline_owned(
				evidence,
				inline_order,
				cancellation.clone(),
				Arc::clone(&ownership),
			)
			.await?
		}
		"evidence-file" => {
			let path = string_field(&mut source, "path")?;
			let selected = if source.contains_key("evidence_id") {
				Some(string_field(&mut source, "evidence_id")?)
			} else {
				None
			};
			let error_path = rea_evidence_file::normalized_error_path(&path)
				.map_err(|error| file_failure(error, &path))?;
			let file = rea_evidence_file::read_json(
				path,
				roots,
				cancellation.clone(),
				Arc::clone(&ownership),
				NativeJsonLimits::default(),
			)
			.await
			.map_err(|error| file_failure(error, &error_path))?;
			authenticate_file_owned(file, selected, cancellation.clone(), Arc::clone(&ownership))
				.await?
		}
		_ => {
			return Err(Failure::output(
				OP,
				"Validated Evidence source kind is unavailable.",
			))
		}
	};
	project_owned(parent, view, session, cancellation, ownership).await
}

/// Outer validation and protocol admission must complete before this owned
/// resolver is called. Importing a source never retains its parent implicitly.
pub(super) async fn inspect(
	params: Value,
	inline_order: Option<Arc<InlineEvidenceOrder>>,
	roots: Vec<PathBuf>,
	session: Arc<EvidenceSession>,
	cancellation: CancellationToken,
	admission: Arc<runtime::effect_owner_fence::AdmissionPermit>,
) -> CallToolResult {
	let ownership = match ownership(admission, &cancellation) {
		Ok(ownership) => ownership,
		Err(error) => return error.wire(),
	};
	match execute(
		params,
		inline_order,
		roots,
		session,
		cancellation,
		ownership,
	)
	.await
	{
		Ok(result) => result,
		Err(error) => error.wire(),
	}
}

#[cfg(test)]
#[path = "rea_analysis_view_tests.rs"]
mod tests;
