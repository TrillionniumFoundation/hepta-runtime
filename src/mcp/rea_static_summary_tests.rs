// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Selected-field summaries preserve versioned provider boundaries.

use super::*;

#[test]
fn header_facts_point_to_exact_retained_lines_without_gpu_isa_claims() {
	let text = "ELF Header:\n  Class: ELF64\n  Machine: AMD GPU\n  Type: REL (Relocatable file)\n  Entry point address: 0x0\n";
	let mapped = selected_fields(
		StaticProvider::GnuReadelf,
		StaticOperation::Headers,
		text,
		true,
	);
	assert_eq!(
		mapped["observations"][1],
		json!({"field":"elf_machine_label","value":"AMD GPU","stdout_line":3})
	);
	assert_eq!(mapped["candidate_count"], 4);
	assert_eq!(mapped["independent_binary_validation"], false);
	assert_eq!(mapped["upstream_contract_equivalent"], false);
}

#[test]
fn notes_preserve_duplicate_observations_and_refuse_malformed_build_ids() {
	let text = " Build ID: 00112233\n Build ID: 00112233\n Build ID: xyz\n Build ID: abc\n";
	let mapped = selected_fields(
		StaticProvider::GnuReadelf,
		StaticOperation::Notes,
		text,
		true,
	);
	assert_eq!(mapped["observations"].as_array().unwrap().len(), 2);
	assert_eq!(mapped["observations"][0]["value"], "00112233");
	assert_eq!(mapped["observations"][1]["stdout_line"], 2);
	assert_eq!(mapped["candidate_count"], 4);
	assert_eq!(mapped["unmapped_candidate_count"], 2);
	assert_eq!(mapped["truncated"], false);
}

#[test]
fn limited_mapping_never_turns_unsupported_or_failed_output_into_facts() {
	for (provider, operation, success) in [
		(StaticProvider::GnuObjdump, StaticOperation::Headers, true),
		(StaticProvider::GnuReadelf, StaticOperation::Symbols, true),
		(StaticProvider::GnuReadelf, StaticOperation::Headers, false),
	] {
		let mapped = selected_fields(provider, operation, "Class: ELF64", success);
		assert_eq!(mapped["mapping_supported"], false);
		assert_eq!(mapped["observations"], json!([]));
	}
}

#[test]
fn bounded_note_mapping_reports_omitted_rows() {
	let text = "Build ID: 01234567\n".repeat(MAX_OBSERVATIONS + 1);
	let mapped = selected_fields(
		StaticProvider::GnuReadelf,
		StaticOperation::Notes,
		&text,
		true,
	);
	assert_eq!(
		mapped["observations"].as_array().unwrap().len(),
		MAX_OBSERVATIONS
	);
	assert_eq!(mapped["truncated"], true);
}

#[test]
fn ghidra_revision_four_summary_preserves_requested_and_resolved_address() {
	let value = json!({"schema":"hepta.rea.ghidra-analysis.v2","bridge_revision":4,
		"operation":"function","analysis_completed":true,"function_address_requested":"0x401001",
		"function":{"entry_address":"0x401000"},"function_resolution":"containing"});
	let mapped = selected_fields(
		StaticProvider::Ghidra,
		StaticOperation::Function,
		&value.to_string(),
		true,
	);
	assert_eq!(mapped["schema"], "hepta.rea.static-summary.v2");
	assert_eq!(mapped["mapping_supported"], true);
	assert_eq!(mapped["function_address_requested"], "0x401001");
	assert_eq!(mapped["function"]["entry_address"], "0x401000");
	assert_eq!(mapped["function_resolution"], "containing");
	assert_eq!(mapped["upstream_contract_equivalent"], false);
	let mut mismatched = value;
	mismatched["bridge_revision"] = json!(3);
	let refused = selected_fields(
		StaticProvider::Ghidra,
		StaticOperation::Function,
		&mismatched.to_string(),
		true,
	);
	assert_eq!(refused["mapping_supported"], false);
}

#[test]
fn ghidra_legacy_summary_does_not_gain_revision_four_fields() {
	let value = json!({"schema":"hepta.rea.ghidra-analysis.v1","bridge_revision":3,
		"operation":"functions","analysis_completed":true,"returned_functions":12});
	let mapped = selected_fields(
		StaticProvider::Ghidra,
		StaticOperation::Functions,
		&value.to_string(),
		true,
	);
	assert_eq!(mapped["schema"], "hepta.rea.static-summary.v1");
	assert!(mapped.get("returned_external_functions").is_none());
	assert!(mapped.get("function_resolution").is_none());
}

#[test]
fn default_profile_summary_does_not_claim_analysis_avoids_native_decompilation() {
	let value = json!({"schema":"hepta.rea.ghidra-analysis.v2","bridge_revision":4,
		"operation":"functions","analysis_completed":true,"decompilation_performed":false,
		"decompilation_scope":"explicit_selected_function","auto_analysis_may_decompile":true,
		"native_child_cleanup_scope":"private_bridge_jvm_all_descendants",
		"native_helper_observation_scope":"live_descendants_at_phase_boundaries",
		"observed_native_decompiler_children":1,"observed_explicit_decompiler_candidates":0});
	let mapped = selected_fields(
		StaticProvider::Ghidra,
		StaticOperation::Functions,
		&value.to_string(),
		true,
	);
	assert_eq!(mapped["decompilation_performed"], false);
	assert_eq!(mapped["decompilation_scope"], "explicit_selected_function");
	assert_eq!(mapped["auto_analysis_may_decompile"], true);
	assert_eq!(mapped["observed_native_decompiler_children"], 1);
	assert_eq!(
		mapped["native_helper_observation_scope"],
		"live_descendants_at_phase_boundaries"
	);
}

#[test]
fn revision_four_reference_summary_distinguishes_filtering_from_output_limits() {
	let mut value = json!({"schema":"hepta.rea.ghidra-analysis.v2","bridge_revision":4,
		"operation":"xrefs","analysis_completed":true,
		"incoming_scope":"selected_function_body_and_entry",
		"outgoing_scope":"selected_function_body_and_entry",
		"reference_scan_accounting":"raw-includes-entrypoint-filter-and-duplicates.v1",
		"reference_filter":"exclude-isEntryPointReference",
		"scanned_incoming_references":4,"filtered_incoming_entry_point_references":1,
		"duplicate_incoming_references_in_scan":0,"unique_incoming_references_in_scan":3,
		"returned_incoming_references":1,"budget_omitted_incoming_references":2,
		"omitted_incoming_references_in_scan":3,"incoming_scan_complete":true,
		"scanned_outgoing_references":2,"filtered_outgoing_entry_point_references":0,
		"duplicate_outgoing_references_in_scan":0,"unique_outgoing_references_in_scan":2,
		"returned_outgoing_references":2,"budget_omitted_outgoing_references":0,
		"omitted_outgoing_references_in_scan":0,"outgoing_scan_complete":true});
	let mapped = selected_fields(
		StaticProvider::Ghidra,
		StaticOperation::Xrefs,
		&value.to_string(),
		true,
	);
	assert_eq!(mapped["schema"], "hepta.rea.static-summary.v2");
	for field in [
		"incoming_scope",
		"outgoing_scope",
		"reference_scan_accounting",
		"reference_filter",
		"scanned_incoming_references",
		"filtered_incoming_entry_point_references",
		"duplicate_incoming_references_in_scan",
		"unique_incoming_references_in_scan",
		"returned_incoming_references",
		"budget_omitted_incoming_references",
		"omitted_incoming_references_in_scan",
		"incoming_scan_complete",
		"scanned_outgoing_references",
		"filtered_outgoing_entry_point_references",
		"duplicate_outgoing_references_in_scan",
		"unique_outgoing_references_in_scan",
		"returned_outgoing_references",
		"budget_omitted_outgoing_references",
		"omitted_outgoing_references_in_scan",
		"outgoing_scan_complete",
	] {
		assert_eq!(mapped[field], value[field], "{field}");
	}
	assert!(mapped["limitations"]
		.as_array()
		.unwrap()
		.iter()
		.any(|item| item
			.as_str()
			.unwrap()
			.contains("budget_omitted counts only unique")));
	assert_eq!(mapped["upstream_contract_equivalent"], false);
	assert!(mapped.get("incoming_references").is_none());
	for revision in [2, 3] {
		value["schema"] = json!("hepta.rea.ghidra-analysis.v1");
		value["bridge_revision"] = json!(revision);
		let legacy = selected_fields(
			StaticProvider::Ghidra,
			StaticOperation::Xrefs,
			&value.to_string(),
			true,
		);
		assert_eq!(legacy["schema"], "hepta.rea.static-summary.v1");
		assert!(legacy.get("reference_scan_accounting").is_none());
		assert!(legacy.get("budget_omitted_incoming_references").is_none());
	}
}
