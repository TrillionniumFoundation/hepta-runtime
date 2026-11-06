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
	if provider == StaticProvider::Ghidra && operation != StaticOperation::Inventory {
		let expected = super::ghidra_contract::operation_name(operation).ok();
		let observation = backend_success
			.then(|| serde_json::from_str::<Value>(stdout).ok())
			.flatten()
			.filter(|value| {
				expected.is_some_and(|name| value["operation"] == name)
					&& (value["schema"] == "hepta.rea.ghidra-analysis.v1"
						|| (value["schema"] == "hepta.rea.ghidra-analysis.v2"
							&& value["bridge_revision"] == 4))
					&& value["analysis_completed"] == true
			});
		let mut summary = json!({"schema":"hepta.rea.static-summary.v1","scope":"selected_ghidra_function_observations",
			"mapping_supported":observation.is_some(),"operation":operation,
			"analysis_profile":observation.as_ref().map(|value| &value["analysis_profile"]),
			"language_id":observation.as_ref().map(|value| &value["language_id"]),
			"function_address_requested":observation.as_ref().map(|value| &value["function_address_requested"]),
			"function":observation.as_ref().map(|value| &value["function"]),
			"returned_functions":observation.as_ref().map(|value| &value["returned_functions"]),
			"function_scan_complete":observation.as_ref().map(|value| &value["function_scan_complete"]),
			"c_code_sha256":observation.as_ref().map(|value| &value["c_code_sha256"]),
			"c_code_complete":observation.as_ref().map(|value| &value["c_code_complete"]),
			"rows_and_code_in_retained_stdout":true,"independent_binary_validation":false,"upstream_contract_equivalent":false,
			"limitations":["Facts and C code are observations of the fixed restricted Ghidra analyzer/decompiler profile",
				"Unreturned functions/references and truncated C remain explicitly unobserved; source equivalence is not established"]});
		if let Some(value) =
			observation.filter(|value| value["schema"] == "hepta.rea.ghidra-analysis.v2")
		{
			summary["schema"] = json!("hepta.rea.static-summary.v2");
			for field in [
				"function_resolution",
				"function_inventory_scope",
				"returned_external_functions",
				"external_function_scan_complete",
				"analysis_options_format",
				"analysis_option_count",
				"analysis_options_sha256",
				"analysis_options_unchanged",
				"no_return_repair_applied",
				"decompilation_performed",
				"decompilation_scope",
				"auto_analysis_may_decompile",
				"native_child_cleanup_scope",
				"native_helper_observation_scope",
				"native_child_cleanup_confirmed",
				"observed_native_children",
				"observed_native_decompiler_children",
				"observed_explicit_decompiler_candidates",
			] {
				summary[field] = value[field].clone();
			}
		}
		return summary;
	}
	if provider == StaticProvider::Ghidra {
		let observation = backend_success
			.then(|| serde_json::from_str::<Value>(stdout).ok())
			.flatten()
			.filter(|value| {
				operation == StaticOperation::Inventory
					&& (value["schema"] == "hepta.rea.ghidra-observation.v1"
						|| value["schema"] == "hepta.rea.ghidra-observation.v2")
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
