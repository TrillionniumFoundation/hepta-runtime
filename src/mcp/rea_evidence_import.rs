// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0

//! Public Evidence bundle import: acquire, authenticate, then atomically merge.
//! The blocking owner retains admission through descriptor cleanup, complete
//! graph authentication and the session publication point, even if its async
//! waiter is dropped. Imported payloads remain data and are never executed.

use super::rea_contract::{self, Failure};
use super::rea_evidence_file::{self, FileReadError, FileReason, NativeJsonLimits, OwnedJson};
use super::rea_evidence_session::{EvidenceSession, ImportCounts};
use super::rea_evidence_source::{self, ImportSourceError, SourceError};
use super::rea_response_encoding::{self, JsonView, ObjectOrder, PathComponent};
use super::runtime;
use rmcp::model::{CallToolResult, JsonObject};
use serde_json::{json, Map, Value};
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use tokio_util::sync::CancellationToken;

pub(super) const OP: &str = "import_evidence_bundle";

struct ImportOwnership {
	_admission: Arc<runtime::effect_owner_fence::AdmissionPermit>,
}

pub(super) fn input_schema() -> Arc<JsonObject> {
	static SCHEMA: OnceLock<Arc<JsonObject>> = OnceLock::new();
	SCHEMA
		.get_or_init(|| {
			Arc::new(
				serde_json::from_str(include_str!(
					"rea_contract_schemas/import_evidence_bundle.input.json"
				))
				.expect("frozen import input schema"),
			)
		})
		.clone()
}

pub(super) fn output_schema() -> Arc<JsonObject> {
	static SCHEMA: OnceLock<Arc<JsonObject>> = OnceLock::new();
	SCHEMA
		.get_or_init(|| {
			Arc::new(
				serde_json::from_str(include_str!(
					"rea_contract_schemas/import_evidence_bundle.output.json"
				))
				.expect("frozen import output schema"),
			)
		})
		.clone()
}

pub(super) fn error_result(error: Failure) -> CallToolResult {
	error.wire_with_order(&ImportFailureOrder)
}

/// Frozen public import failures use the analysis-error projector's envelope
/// and the input/read/bundle producers' diagnostic order. The provenance and
/// exact original MCP text are retained in rea_evidence_import_errors.json.
/// This resolver is deliberately local to import: arbitrary Provider details
/// and native-only extension payloads have no established upstream order.
struct ImportFailureOrder;
impl ObjectOrder for ImportFailureOrder {
	fn keys<'a>(
		&self,
		path: &[PathComponent<'_>],
		object: &'a Map<String, Value>,
	) -> anyhow::Result<Vec<&'a str>> {
		use PathComponent::{Index, Key};
		let order: &[&str] = match path {
			[Key("error")] => &[
				"code",
				"category",
				"message",
				"retryable",
				"remediation",
				"recovery",
				"details",
			],
			[Key("error"), Key("remediation")] => &["action"],
			[Key("error"), Key("recovery")] => &["kind", "operation"],
			[Key("error"), Key("details")] if object.contains_key("issues") => {
				&["operation", "issues"]
			}
			[Key("error"), Key("details")]
				if object.get("operation").and_then(Value::as_str) == Some("read") =>
			{
				&["operation", "reason", "boundary", "path", "content_issues"]
			}
			[Key("error"), Key("details")] => &["reason"],
			[Key("error"), Key("details"), Key("issues"), Index(_)] => &[
				"path", "reason", "message", "expected", "minimum", "maximum",
			],
			[Key("error"), Key("details"), Key("content_issues"), Index(_)] => {
				&["path", "reason", "expected", "message"]
			}
			_ => anyhow::bail!("No original Evidence import failure order for this object"),
		};
		rea_response_encoding::declared_keys(object, order)
	}
}

fn active(cancellation: &CancellationToken) -> Result<(), Failure> {
	if cancellation.is_cancelled() {
		Err(Failure::cancelled(OP))
	} else {
		Ok(())
	}
}

fn ownership(
	admission: Arc<runtime::effect_owner_fence::AdmissionPermit>,
	cancellation: &CancellationToken,
) -> Result<Arc<ImportOwnership>, Failure> {
	active(cancellation)?;
	Ok(Arc::new(ImportOwnership {
		_admission: admission,
	}))
}

fn profile_gap(feature: &str, details: Value) -> Failure {
	let message =
		"This analysis is unavailable for the current target. Choose another analysis or target.";
	Failure(
		json!({"code":"capability_unavailable","category":"unsupported_provider",
		"message":message,"retryable":false,"remediation":{"action":message},
		"details":{"provider_id":"rea-evidence-import","operation":OP,
			"reason":format!("The native Rust Evidence import profile does not yet cover {feature}."),
			"native_profile":{"boundary":"evidence-json-import","feature":feature,"details":details}}}),
	)
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
			let mut failure = Failure(
				json!({"code":code,"category":category,"message":message,"retryable":false,
				"remediation":{"action":message},"details":{"operation":"read","reason":reason.as_str(),"path":path}}),
			);
			if reason == FileReason::PathLimit {
				failure.0["details"]["boundary"] = json!("filesystem-path");
			}
			failure
		}
		FileReadError::InvalidJson {
			message,
			user_message,
		} => {
			let public = user_message.as_deref().unwrap_or(
				"Evidence file is not valid JSON. Repair or recreate the file and try again.",
			);
			Failure(
				json!({"code":"evidence_integrity_mismatch","category":"execution_failure","message":public,
				"retryable":false,"remediation":{"action":public},"details":{"operation":"read","reason":"invalid-json","path":path,
					"content_issues":[{"path":[],"reason":"invalid_format","expected":"JSON","message":message}]}}),
			)
		}
		FileReadError::RootString => source_failure(
			ImportSourceError::Source(rea_evidence_source::reject_string_root(true)),
			path,
		),
		FileReadError::Cancelled => Failure::cancelled(OP),
		FileReadError::NativeProfileGap { feature, details } => profile_gap(feature, details),
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

fn source_failure(error: ImportSourceError, path: &str) -> Failure {
	match error {
		ImportSourceError::SingleRecord { evidence_id } => {
			let message = format!("Expected an Evidence bundle with records and manifest arrays, but this JSON is one Evidence record ({evidence_id}). Export a session bundle with the MCP export_evidence_bundle tool and supply that file.");
			Failure(
				json!({"code":"invalid_request","category":"invalid_input","message":message,"retryable":false,
				"remediation":{"action":message},"details":{"operation":"read","reason":"wrong-kind","path":path}}),
			)
		}
		ImportSourceError::Source(SourceError::InvalidBundle { message }) => Failure(json!({
			"code":"evidence_integrity_mismatch","category":"integrity_mismatch","message":message,"retryable":false,
			"remediation":{"action":message},"details":{"reason":"Evidence bundle validation failed"}})),
		ImportSourceError::Source(SourceError::ProfileGap { feature }) => {
			profile_gap(feature, json!({}))
		}
		ImportSourceError::Source(SourceError::SchemaException { message }) => {
			Failure::schema_exception(message)
		}
		ImportSourceError::Source(error) => Failure::output(OP, error.to_string()),
	}
}

struct CountsOrder;
impl ObjectOrder for CountsOrder {
	fn keys<'a>(
		&self,
		path: &[PathComponent<'_>],
		object: &'a Map<String, Value>,
	) -> anyhow::Result<Vec<&'a str>> {
		match path {
			[] => rea_response_encoding::declared_keys(object, &["result"]),
			[PathComponent::Key("result")] => rea_response_encoding::declared_keys(
				object,
				&["imported", "unknowns_added", "total"],
			),
			_ => anyhow::bail!("Import counters contain an unexpected object"),
		}
	}
}

fn success(counts: ImportCounts) -> CallToolResult {
	let value = json!({"result":counts});
	rea_contract::deliver_view(
		OP,
		JsonView::Value(&value),
		Some(&CountsOrder),
		None,
		false,
		true,
		|| Ok(value.clone()),
	)
}

async fn authenticate_and_merge(
	file: OwnedJson,
	session: Arc<EvidenceSession>,
	cancellation: CancellationToken,
	ownership: Arc<ImportOwnership>,
) -> Result<ImportCounts, Failure> {
	active(&cancellation)?;
	let stop = cancellation.child_token();
	let cancel_on_drop = stop.clone().drop_guard();
	let result = tokio::task::spawn_blocking(move || {
		let _ownership = ownership;
		active(&stop)?;
		let OwnedJson { value, object_order, selected_path, input_bytes, sha256 } = file;
		tracing::debug!(operation = OP, input_bytes, input_sha256 = %sha256, "Authenticating complete Evidence bundle for atomic import");
		let error_path = rea_evidence_file::normalized_error_path(&selected_path)
			.map_err(|error| file_failure(error, &selected_path))?;
		let resolver = |path: &[Value]| object_order.keys(path);
		let candidate = rea_evidence_source::authenticate_import_with_order(value, Some(&resolver))
			.map_err(|error| source_failure(error, &error_path))?;
		active(&stop)?;
		let orders = object_order.into_record_orders().map_err(|error| file_failure(error, &error_path))?;
		session.import_if_active(candidate, orders, &stop)
	}).await;
	let _ = cancel_on_drop.disarm();
	result.map_err(|error| Failure::output(OP, format!("Evidence import owner failed: {error}")))?
}

pub(super) async fn import(
	params: Value,
	roots: Vec<PathBuf>,
	session: Arc<EvidenceSession>,
	cancellation: CancellationToken,
	admission: Arc<runtime::effect_owner_fence::AdmissionPermit>,
) -> CallToolResult {
	let run = async {
		let path = params["path"]
			.as_str()
			.ok_or_else(|| Failure::output(OP, "Validated import path is unavailable."))?;
		let error_path = rea_evidence_file::normalized_error_path(path)
			.map_err(|error| file_failure(error, path))?;
		let owner = ownership(admission, &cancellation)?;
		let file = rea_evidence_file::read_json(
			path.to_owned(),
			roots,
			cancellation.clone(),
			Arc::clone(&owner),
			NativeJsonLimits::default(),
		)
		.await
		.map_err(|error| file_failure(error, &error_path))?;
		authenticate_and_merge(file, session, cancellation, owner).await
	}
	.await;
	match run {
		Ok(counts) => success(counts),
		Err(error) => error_result(error),
	}
}

#[cfg(test)]
#[path = "rea_evidence_import_tests.rs"]
mod tests;
