// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0

//! Original text order for the independently observed Evidence import errors.
//! The 42-frame fixture covers 38 JSON errors and four plain SDK exceptions.
//! This is not a generic error schema or a JSON-RPC frame rewrite. Other
//! operations, unknown members and unobserved families keep their old projection.

use super::super::rea_response_encoding::{self as encoding, ObjectOrder, PathComponent};
use anyhow::{bail, Result};
use serde_json::{Map, Value};

const IMPORT: &str = "import_evidence_bundle";
const INPUT_MESSAGE: &str =
	"The arguments for MCP tool import_evidence_bundle do not match its advertised input schema.";
const INPUT_ACTION: &str = "Read the declared input schema or CLI usage for import_evidence_bundle; if using MCP and the catalog may be stale, call tools/list. Correct the listed fields, then retry. Do not repeat the unchanged call.";

#[derive(Clone, Copy)]
enum ImportFailure {
	InvalidJson,
	IntegrityReason,
	FileRead,
	InputSchema,
}

fn observed_input(error: &Value) -> Option<ImportFailure> {
	let details = error.get("details")?;
	let recovery = error.get("recovery")?;
	if error.get("message")?.as_str()? != INPUT_MESSAGE
		|| error.get("remediation")?.get("action")?.as_str()? != INPUT_ACTION
		|| details.get("operation")?.as_str()? != IMPORT
		|| recovery.get("kind")?.as_str()? != "inspect_input_contract"
		|| recovery.get("operation")?.as_str()? != IMPORT
	{
		return None;
	}
	let [issue] = details.get("issues")?.as_array()?.as_slice() else {
		return None;
	};
	if !issue.get("path")?.as_array()?.is_empty()
		|| issue.get("reason")?.as_str()? != "invalid_value"
		|| issue.get("message")?.as_str().is_none()
	{
		return None;
	}
	Some(ImportFailure::InputSchema)
}

fn observed_family(error: &Value) -> Option<ImportFailure> {
	if error.get("retryable")?.as_bool()? {
		return None;
	}
	let code = error.get("code")?.as_str()?;
	let category = error.get("category")?.as_str()?;
	if error.get("recovery").is_some() {
		if code != "invalid_request" || category != "invalid_input" {
			return None;
		}
		return observed_input(error);
	}
	if error.get("remediation")?.get("action")?.as_str()? != error.get("message")?.as_str()? {
		return None;
	}
	let details = error.get("details")?;
	match (code, category, details.get("reason")?.as_str()?) {
		("evidence_integrity_mismatch", "execution_failure", "invalid-json") => {
			if details.get("operation")?.as_str()? != "read"
				|| details.get("path")?.as_str().is_none()
			{
				return None;
			}
			let [issue] = details.get("content_issues")?.as_array()?.as_slice() else {
				return None;
			};
			if !issue.get("path")?.as_array()?.is_empty()
				|| issue.get("reason")?.as_str()? != "invalid_format"
				|| issue.get("expected")?.as_str()? != "JSON"
				|| issue.get("message")?.as_str().is_none()
			{
				return None;
			}
			Some(ImportFailure::InvalidJson)
		}
		(
			"evidence_integrity_mismatch",
			"integrity_mismatch",
			"Evidence bundle validation failed"
			| "Conflicting unknown revision"
			| "Evidence bundle unknown registry failed",
		) => Some(ImportFailure::IntegrityReason),
		("invalid_request", "invalid_input", "missing" | "not-file" | "wrong-kind") => {
			if details.get("operation")?.as_str()? != "read"
				|| details.get("path")?.as_str().is_none()
			{
				return None;
			}
			Some(ImportFailure::FileRead)
		}
		_ => None,
	}
}

pub(super) struct ImportFailureOrder(ImportFailure);

impl ObjectOrder for ImportFailureOrder {
	fn keys<'a>(
		&self,
		path: &[PathComponent<'_>],
		object: &'a Map<String, Value>,
	) -> Result<Vec<&'a str>> {
		use PathComponent::{Index, Key};
		let keys: &[&str] = match path {
			[Key("error")] if matches!(self.0, ImportFailure::InputSchema) => &[
				"code",
				"category",
				"message",
				"retryable",
				"remediation",
				"recovery",
				"details",
			],
			[Key("error")] => &[
				"code",
				"category",
				"message",
				"retryable",
				"remediation",
				"details",
			],
			[Key("error"), Key("remediation")] => &["action"],
			[Key("error"), Key("recovery")] if matches!(self.0, ImportFailure::InputSchema) => {
				&["kind", "operation"]
			}
			[Key("error"), Key("details")] => match self.0 {
				ImportFailure::InvalidJson => &["operation", "reason", "path", "content_issues"],
				ImportFailure::IntegrityReason => &["reason"],
				ImportFailure::FileRead => &["operation", "reason", "path"],
				ImportFailure::InputSchema => &["operation", "issues"],
			},
			[Key("error"), Key("details"), Key("content_issues"), Index(0)]
				if matches!(self.0, ImportFailure::InvalidJson) =>
			{
				&["path", "reason", "expected", "message"]
			}
			[Key("error"), Key("details"), Key("issues"), Index(0)]
				if matches!(self.0, ImportFailure::InputSchema) =>
			{
				&["path", "reason", "message"]
			}
			_ => bail!("Unobserved import failure object order"),
		};
		// This also rejects extra recovery/issue/detail fields. It never drops
		// data, borrows a successful Evidence order, or invents a fallback order.
		encoding::declared_keys(object, keys)
	}
}

/// The original operation/family must be established before using its order.
/// The shared encoder then requires every encountered object's complete key
/// set; an unknown member discards the attempted encoding and preserves the
/// previous complete diagnostic.
pub(super) fn import_order(error: &Value) -> Option<ImportFailureOrder> {
	observed_family(error).map(ImportFailureOrder)
}
