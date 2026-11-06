// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0

//! Exact original error-text ordering for the admitted ELF/Evidence branches.
//!
//! The frozen npm analysisErrorProjection, ElfNotesProvider and ToolResultDelivery
//! producers establish these orders. The original text and source hashes are
//! retained in tests/fixtures/rea_elf_evidence_error_text.json. This is not an
//! order for arbitrary Provider diagnostics, import failures or native extensions.

use super::super::rea_response_encoding::{declared_keys, ObjectOrder, PathComponent};
use serde_json::{Map, Value};

pub(super) enum ElfEvidenceFailureOrder {
	Input,
	ElfBudget,
	ResponseBudget,
	UnsupportedView,
}

impl ElfEvidenceFailureOrder {
	pub(super) fn for_failure(error: &Value) -> Option<Self> {
		let details = error.get("details")?;
		match (
			error.get("code")?.as_str()?,
			details.get("operation")?.as_str()?,
		) {
			("invalid_request", "inspect_elf_notes") => Some(Self::Input),
			("unsupported_target", "inspect_analysis_view") => Some(Self::UnsupportedView),
			("resource_constraint", "inspect_elf_notes")
				if matches!(details.get("resource")?.as_str()?, "file-size" | "capacity") =>
			{
				Some(Self::ElfBudget)
			}
			("resource_constraint", "inspect_elf_notes" | "get_evidence_bundle")
				if details.get("resource")?.as_str()? == "transport"
					&& details.get("reported_limits")?.get("boundary")?.as_str()?
						== "mcp-response" =>
			{
				Some(Self::ResponseBudget)
			}
			_ => None,
		}
	}
}

impl ObjectOrder for ElfEvidenceFailureOrder {
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
			[Key("error"), Key("recovery")] if matches!(self, Self::Input) => {
				&["kind", "operation"]
			}
			[Key("error"), Key("details")] => match self {
				Self::Input => &["operation", "issues"],
				Self::ElfBudget | Self::ResponseBudget => {
					&["operation", "resource", "reason", "reported_limits"]
				}
				Self::UnsupportedView => &["operation", "path", "reason"],
			},
			[Key("error"), Key("details"), Key("issues"), Index(_)]
				if matches!(self, Self::Input) =>
			{
				&[
					"path", "reason", "message", "expected", "minimum", "maximum",
				]
			}
			[Key("error"), Key("details"), Key("reported_limits")]
				if matches!(self, Self::ElfBudget) =>
			{
				&["max_file_bytes", "max_entries"]
			}
			[Key("error"), Key("details"), Key("reported_limits")]
				if matches!(self, Self::ResponseBudget) =>
			{
				&[
					"boundary",
					"default_receive_buffer_bytes",
					"result_budget_bytes",
					"max_string_code_units",
					"response_bytes_at_least",
					"response_code_units_at_least",
					"constraint",
					"evidence_id",
					"evidence_reference",
				]
			}
			[Key("error"), Key("details"), Key("reported_limits"), Key("evidence_reference")]
				if matches!(self, Self::ResponseBudget) =>
			{
				&["kind", "evidence_id"]
			}
			_ => anyhow::bail!("No original ELF/Evidence failure order for this object"),
		};
		// An extra field rejects the whole attempted projection. Failure retains
		// its existing complete text instead of publishing a reordered prefix.
		declared_keys(object, order)
	}
}
