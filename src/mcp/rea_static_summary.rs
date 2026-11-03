// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Deterministic selected-field mapping from retained, pinned backend observations.
//! This is not an independent ELF parser or an upstream Evidence conversion.

use super::{StaticOperation, StaticProvider};
use serde_json::{json, Value};

const MAX_OBSERVATIONS: usize = 64;

pub(crate) fn selected_fields(
	provider: StaticProvider,
	operation: StaticOperation,
	stdout: &str,
	backend_success: bool,
) -> Value {
	if provider == StaticProvider::Ghidra {
		let observation = backend_success
			.then(|| serde_json::from_str::<Value>(stdout).ok())
			.flatten()
			.filter(|value| {
				operation == StaticOperation::Inventory
					&& value["schema"] == "hepta.rea.ghidra-observation.v1"
					&& value["operation"] == "inventory"
			});
		return json!({"schema":"hepta.rea.static-summary.v1","scope":"selected_ghidra_import_observations",
			"mapping_supported":observation.is_some(),
			"language_id":observation.as_ref().map(|value| &value["language_id"]),
			"compiler_spec_id":observation.as_ref().map(|value| &value["compiler_spec_id"]),
			"memory_block_count":observation.as_ref().map(|value| &value["memory_block_count"]),
			"symbol_table_count":observation.as_ref().map(|value| &value["symbol_table_count"]),
			"symbol_scan_complete":observation.as_ref().map(|value| &value["symbol_scan_complete"]),
			"inventory_rows_in_retained_stdout":true,"independent_binary_validation":false,"upstream_contract_equivalent":false,
			"limitations":["Facts describe the fixed ElfLoader import without auto-analysis, decompilation or target execution",
				"Only bounded memory and imported-symbol inventories are retained"]});
	}
	if provider == StaticProvider::Jadx {
		let observation = if backend_success {
			serde_json::from_str::<Value>(stdout).ok()
		} else {
			None
		};
		let expected = match operation {
			StaticOperation::Classes => "classes",
			StaticOperation::Sources => "sources",
			_ => "",
		};
		let observation = observation.filter(|value| {
			value["schema"] == "hepta.rea.jadx-observation.v1" && value["operation"] == expected
		});
		let classes:Vec<_>=observation.as_ref().and_then(|value|value["rows"].as_array()).into_iter().flatten().take(64).map(|row|json!({
			"class_name":row["class_name"],"class_name_complete":row["class_name_complete"],
			"declared_methods":row["declared_methods"],"source_sha256":row["source_sha256"],
			"source_utf8_bytes":row["source_utf8_bytes"],"source_preview_complete":row["source_preview_complete"]
		})).collect();
		return json!({"schema":"hepta.rea.static-summary.v1","scope":"selected_jadx_class_observations",
			"mapping_supported":observation.is_some(),"classes":classes,
			"observed_class_count":observation.as_ref().map(|value|&value["observed_class_count"]),
			"returned_class_count":observation.as_ref().map(|value|&value["returned_class_count"]),
			"omitted_class_count":observation.as_ref().map(|value|&value["omitted_class_count"]),
			"errors":observation.as_ref().map(|value|&value["errors"]),
			"warnings":observation.as_ref().map(|value|&value["warnings"]),
			"source_previews_in_retained_stdout":true,"independent_binary_validation":false,"upstream_contract_equivalent":false,
			"limitations":["Class/method/source observations come from the fixed JADX bridge; source correctness is not established",
				"Only returned rows are indexed; omitted classes and truncated names/source remain unobserved in this report"]});
	}
	let supported = backend_success
		&& provider == StaticProvider::GnuReadelf
		&& matches!(operation, StaticOperation::Headers | StaticOperation::Notes);
	let mut observations = Vec::new();
	let mut candidates = 0usize;
	let mut unmapped = 0usize;
	if supported {
		for (index, line) in stdout.lines().enumerate() {
			let Some((label, value)) = line.trim().split_once(':') else {
				continue;
			};
			let value = value.trim();
			let field = match (operation, label) {
				(StaticOperation::Headers, "Class") => "elf_class",
				(StaticOperation::Headers, "Data") => "elf_data_encoding",
				(StaticOperation::Headers, "OS/ABI") => "elf_os_abi",
				(StaticOperation::Headers, "ABI Version") => "elf_abi_version",
				(StaticOperation::Headers, "Type") => "elf_type",
				(StaticOperation::Headers, "Machine") => "elf_machine_label",
				(StaticOperation::Headers, "Entry point address") => "elf_entry_point_text",
				(StaticOperation::Notes, "Build ID") => "gnu_build_id_hex",
				_ => continue,
			};
			candidates += 1;
			if value.is_empty()
				|| value.len() > 512
				|| (field == "gnu_build_id_hex"
					&& (!value.len().is_multiple_of(2)
						|| !value.bytes().all(|b| b.is_ascii_hexdigit())))
			{
				unmapped += 1;
				continue;
			}
			if observations.len() < MAX_OBSERVATIONS {
				observations.push(json!({"field":field,"value":value,"stdout_line":index+1}));
			}
		}
	}
	let retained = observations.len();
	json!({
		"schema":"hepta.rea.static-summary.v1",
		"scope":"selected_gnu_readelf_text_fields",
		"mapping_supported":supported,
		"observations":observations,
		"candidate_count":candidates,"unmapped_candidate_count":unmapped,
		"truncated":candidates.saturating_sub(unmapped)>retained,
		"independent_binary_validation":false,"upstream_contract_equivalent":false,
		"limitations":["Values are observations of retained GNU stdout and identify their original line",
			"No ELF physical ranges, note descriptor hashes, table completeness or loader behavior are inferred",
			"An absent mapped field is not proof of absence from the artifact"]
	})
}

#[cfg(test)]
#[path = "rea_static_summary_tests.rs"]
mod tests;
