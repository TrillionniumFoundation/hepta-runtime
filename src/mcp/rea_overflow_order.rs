// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0

//! Exact error-text order for the two retained REA receive-buffer overflow forms.
//! Only the contract overflow path invokes this formatter. Unknown operations,
//! limits, fields or nested shapes retain the complete existing error projection.

use super::super::rea_response_encoding::{self as encoding, JsonView, ObjectOrder, PathComponent};
use anyhow::{bail, Result};
use serde_json::{Map, Value};

#[derive(Clone, Copy)]
enum Shape {
	RetainedApk,
	CompleteBundle,
}

const SUMMARY: &str = "The operation completed, but its complete MCP response exceeds the stdio response budget. The analysis result was not truncated.";
const RETAINED_NEXT: &str =
	"Export retained evidence to consume the complete analysis, or use complete CLI JSON output.";
const BUNDLE_NEXT: &str = "Discover retained records with get_evidence_bundle and detail: summary, then inspect compatible records through inspect_analysis_view using an exact Evidence reference. Export complete retained session evidence through export_evidence_bundle to a caller-selected path, or use complete CLI JSON output. The connection remains usable.";

fn observed(error: &Value) -> Option<Shape> {
	if error.get("code")?.as_str()? != "resource_constraint"
		|| error.get("category")?.as_str()? != "resource_constraint"
		|| error.get("retryable")?.as_bool()?
	{
		return None;
	}
	let details = error.get("details")?;
	if details.get("resource")?.as_str()? != "transport" {
		return None;
	}
	let (shape, next) = match details.get("operation")?.as_str()? {
		"inspect_apk_signature" => (Shape::RetainedApk, RETAINED_NEXT),
		"get_evidence_bundle" => (Shape::CompleteBundle, BUNDLE_NEXT),
		_ => return None,
	};
	let limits = details.get("reported_limits")?;
	let budget = (super::RESPONSE_BYTES - super::ENVELOPE_RESERVATION) as u64;
	if limits.get("boundary")?.as_str()? != "mcp-response"
		|| limits.get("constraint")?.as_str()? != "receive-buffer"
		|| limits.get("default_receive_buffer_bytes")?.as_u64()? != super::RESPONSE_BYTES as u64
		|| limits.get("result_budget_bytes")?.as_u64()? != budget
		|| limits.get("max_string_code_units")?.as_u64()?
			!= super::RESERVED_STRING_CODE_UNITS as u64
	{
		return None;
	}
	let bytes = limits.get("response_bytes_at_least")?.as_u64()?;
	let units = limits.get("response_code_units_at_least")?.as_u64()?;
	if bytes <= budget || units == 0 || units > bytes || bytes > 9_007_199_254_740_991 {
		return None;
	}
	if matches!(shape, Shape::RetainedApk) {
		let id = limits.get("evidence_id")?.as_str()?;
		let digest = id.strip_prefix("ev_")?;
		let reference = limits.get("evidence_reference")?;
		if digest.len() != 64
			|| !digest
				.bytes()
				.all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
			|| reference.get("kind")?.as_str()? != "retained-evidence"
			|| reference.get("evidence_id")?.as_str()? != id
		{
			return None;
		}
	}
	// A changed message or remediation is a new observed family, even if its
	// object keys look familiar. This gate does not infer a producer's order.
	let facts = format!(
		"The effective REA_MCP_MAX_RESPONSE_BYTES value is {} bytes (floor 10485760 bytes, 10 MiB). A change requires restarting the REA process and a matching client receive buffer. It does not raise REA's reserved single-string limit of {} UTF-16 code units or Node's single-string ceiling of {} UTF-16 code units. This release has no runtime override for either limit.",
		super::RESPONSE_BYTES,
		super::RESERVED_STRING_CODE_UNITS,
		super::NODE_STRING_CODE_UNITS
	);
	let message = format!("{SUMMARY} {facts} {next}");
	if error.get("message")?.as_str()? != message
		|| details.get("reason")?.as_str()? != message
		|| error.get("remediation")?.get("action")?.as_str()? != format!("{next} {facts}")
	{
		return None;
	}
	Some(shape)
}

struct OverflowOrder(Shape);

impl ObjectOrder for OverflowOrder {
	fn keys<'a>(
		&self,
		path: &[PathComponent<'_>],
		object: &'a Map<String, Value>,
	) -> Result<Vec<&'a str>> {
		use PathComponent::Key;
		let keys: &[&str] = match path {
			[Key("error")] => &[
				"code",
				"category",
				"message",
				"retryable",
				"remediation",
				"details",
			],
			[Key("error"), Key("remediation")] => &["action"],
			[Key("error"), Key("details")] => {
				&["operation", "resource", "reason", "reported_limits"]
			}
			[Key("error"), Key("details"), Key("reported_limits")] => match self.0 {
				Shape::RetainedApk => &[
					"boundary",
					"default_receive_buffer_bytes",
					"result_budget_bytes",
					"max_string_code_units",
					"response_bytes_at_least",
					"response_code_units_at_least",
					"constraint",
					"evidence_id",
					"evidence_reference",
				],
				Shape::CompleteBundle => &[
					"boundary",
					"default_receive_buffer_bytes",
					"result_budget_bytes",
					"max_string_code_units",
					"response_bytes_at_least",
					"response_code_units_at_least",
					"constraint",
				],
			},
			[Key("error"), Key("details"), Key("reported_limits"), Key("evidence_reference")]
				if matches!(self.0, Shape::RetainedApk) =>
			{
				&["kind", "evidence_id"]
			}
			_ => bail!("Unobserved response-overflow object order"),
		};
		// Validate the entire declared key set at every object, including empty
		// and missing objects. Extra data must fall back, never disappear.
		encoding::declared_keys(object, keys)
	}
}

pub(super) fn text(error: &Value) -> Option<String> {
	let shape = observed(error)?;
	let members = [("error", JsonView::Value(error))];
	let mut bytes = Vec::new();
	encoding::write_json_view(
		JsonView::Object(&members),
		&OverflowOrder(shape),
		super::super::rea_evidence::canonical_js_number,
		&mut bytes,
	)
	.ok()?;
	String::from_utf8(bytes).ok()
}
