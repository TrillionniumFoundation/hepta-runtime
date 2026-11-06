// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0

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
fn ghidra_instruction_summary_keeps_complete_window_scope_and_failed_output_unknown() {
	let fixture = include_str!("../../tests/fixtures/rea_ghidra_instructions/contract-window.json");
	for success in [true, false] {
		let mapped = selected_fields(
			StaticProvider::Ghidra,
			StaticOperation::Instructions,
			fixture,
			success,
		);
		assert_eq!(mapped["mapping_supported"], success);
		assert_eq!(
			mapped["complete_window_and_memory_bytes_in_retained_stdout"],
			success
		);
		assert_eq!(
			mapped["scope"],
			"complete_selected_ghidra_instruction_window"
		);
		assert_eq!(mapped["upstream_contract_equivalent"], false);
		assert_eq!(mapped["independent_binary_validation"], false);
		if success {
			assert_eq!(mapped["instruction_count"], 3);
			assert_eq!(mapped["instructions_complete"], true);
		} else {
			assert!(mapped["instruction_count"].is_null());
			assert!(mapped["instructions_complete"].is_null());
		}
	}
}
