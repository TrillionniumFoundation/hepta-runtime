// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Adversarial body-membership and namespace controls for revision 4 observations.

use super::*;
use serde_json::json;

fn named_row(address: &str, external: bool) -> Value {
	json!({"entry_address":address,"external":external,"thunk":false,
		"name":"owned","name_complete":true,"name_sha256":sha256(b"owned"),
		"signature":"int owned(void)","signature_complete":true,
		"signature_sha256":sha256(b"int owned(void)")})
}

fn selected() -> Value {
	let mut row = named_row("0x401000", false);
	row["body_min_address"] = json!("0x401000");
	row["body_max_address"] = json!("0x40102f");
	row["body_address_count"] = json!("32");
	row["body_range_count"] = json!(2);
	row["body_ranges_complete"] = json!(true);
	row["body_ranges"] = json!([
		{"min_address":"0x401000","max_address":"0x40100f"},
		{"min_address":"0x401020","max_address":"0x40102f"}
	]);
	json!({"function":row,"function_resolution":"containing"})
}

#[test]
fn containment_uses_inclusive_ranges_and_never_the_enclosing_min_max_span() {
	let value = selected();
	for address in ["0x401001", "0x40100f", "0x401020", "0x40102f"] {
		validate_selected(&value, address).unwrap();
	}
	for address in ["0x400fff", "0x401010", "0x401018", "0x40101f", "0x401030"] {
		assert!(validate_selected(&value, address).is_err(), "{address}");
	}
	let mut exact = value;
	exact["function_resolution"] = json!("entry");
	validate_selected(&exact, "0x401000").unwrap();
	assert!(validate_selected(&exact, "0x401001").is_err());
}

#[test]
fn complete_body_metadata_cannot_be_substituted_or_coerced() {
	let original = selected();
	for case in 0..15 {
		let mut value = original.clone();
		let row = &mut value["function"];
		match case {
			0 => row["body_ranges_complete"] = json!(false),
			1 => row["body_ranges_complete"] = json!(1),
			2 => row["body_range_count"] = json!(true),
			3 => row["body_range_count"] = json!(1),
			4 => row["body_address_count"] = json!(32),
			5 => row["body_address_count"] = json!("032"),
			6 => row["body_address_count"] = json!("48"),
			7 => row["body_min_address"] = json!("0x400fff"),
			8 => row["body_max_address"] = json!("0x401030"),
			9 => row["entry_address"] = json!("0x401018"),
			10 => row["external"] = json!(true),
			11 => row["body_ranges"][0]["min_address"] = json!("0x0401000"),
			12 => row["body_ranges"][0]["max_address"] = json!("EXTERNAL:0x40100f"),
			13 => row["body_ranges"][0]["invented_space"] = json!("ram"),
			14 => row["body_ranges"] = json!([]),
			_ => unreachable!(),
		}
		assert!(
			validate_selected(&value, "0x401001").is_err(),
			"case {case}"
		);
	}
}

#[test]
fn ranges_must_be_bounded_ordered_nonoverlapping_and_noninverted() {
	for ranges in [
		json!([{"min_address":"0x401020","max_address":"0x40102f"},
			{"min_address":"0x401000","max_address":"0x40100f"}]),
		json!([{"min_address":"0x401000","max_address":"0x40100f"},
			{"min_address":"0x40100f","max_address":"0x40102f"}]),
		json!([{"min_address":"0x401000","max_address":"0x400fff"}]),
		json!(vec![
			json!({"min_address":"0x401000","max_address":"0x40100f"});
			MAX_BODY_RANGES + 1
		]),
	] {
		let mut value = selected();
		value["function"]["body_range_count"] = json!(ranges.as_array().unwrap().len());
		value["function"]["body_ranges"] = ranges;
		assert!(validate_selected(&value, "0x401001").is_err());
	}
}

#[test]
fn upper_unsigned_addresses_do_not_wrap_or_become_signed_ranges() {
	let mut row = named_row("0xfffffffffffffff0", false);
	row["body_min_address"] = json!("0xfffffffffffffff0");
	row["body_max_address"] = json!("0xffffffffffffffff");
	row["body_address_count"] = json!("16");
	row["body_range_count"] = json!(1);
	row["body_ranges_complete"] = json!(true);
	row["body_ranges"] =
		json!([{"min_address":"0xfffffffffffffff0","max_address":"0xffffffffffffffff"}]);
	let mut value = json!({"function":row,"function_resolution":"containing"});
	validate_selected(&value, "0xffffffffffffffff").unwrap();
	value["function"]["body_ranges"][0]["min_address"] = json!("0x0");
	value["function"]["body_min_address"] = json!("0x0");
	value["function"]["body_address_count"] = json!("18446744073709551616");
	assert!(validate_selected(&value, "0xffffffffffffffff").is_err());
}

fn functions() -> Value {
	json!({"function_inventory_scope":"internal_and_external_separate",
		"functions":[named_row("0x1", false)],"returned_functions":1,
		"scanned_functions":1,"omitted_functions_in_scan":0,"function_scan_complete":true,
		"external_functions":[named_row("EXTERNAL:0x1", true)],"returned_external_functions":1,
		"scanned_external_functions":1,"omitted_external_functions_in_scan":0,
		"external_function_scan_complete":true})
}

#[test]
fn equal_offsets_in_distinct_address_spaces_remain_distinct_functions() {
	validate_functions(&functions()).unwrap();
	for address in [
		"0x1",
		"external:0x1",
		"EXTERNAL:00000001",
		"EXTERNAL:0x01",
		"EXTERNAL:0x10000000000000000",
	] {
		let mut value = functions();
		value["external_functions"][0]["entry_address"] = json!(address);
		assert!(validate_functions(&value).is_err(), "{address}");
	}
}

#[test]
fn inventory_count_kind_scope_duplicates_and_truncation_are_checked() {
	for case in 0..10 {
		let mut value = functions();
		match case {
			0 => value["function_inventory_scope"] = json!("all_functions"),
			1 => value["external_functions"][0]["external"] = json!(false),
			2 => value["returned_external_functions"] = json!(true),
			3 => value["scanned_external_functions"] = json!(4097),
			4 => value["external_function_scan_complete"] = json!(false),
			5 => value["external_function_scan_complete"] = json!(1),
			6 => value["omitted_external_functions_in_scan"] = json!(1),
			7 => value["scanned_functions"] = json!(0),
			8 => {
				value["external_functions"] = json!([
					named_row("EXTERNAL:0x1", true),
					named_row("EXTERNAL:0x1", true)
				]);
				value["returned_external_functions"] = json!(2);
				value["scanned_external_functions"] = json!(2);
			}
			9 => value["functions"] = json!([named_row("0x1", false), named_row("0x1", false)]),
			_ => unreachable!(),
		}
		assert!(validate_functions(&value).is_err(), "case {case}");
	}
	let mut bounded = functions();
	bounded["scanned_external_functions"] = json!(4096);
	bounded["omitted_external_functions_in_scan"] = json!(4095);
	bounded["external_function_scan_complete"] = json!(false);
	validate_functions(&bounded).unwrap();
}

#[test]
fn complete_names_and_signatures_must_match_their_digests() {
	for field in ["name", "signature"] {
		let mut value = functions();
		value["external_functions"][0][field] = json!("invented");
		assert!(validate_functions(&value).is_err());
		value["external_functions"][0][format!("{field}_complete")] = json!(false);
		validate_functions(&value).unwrap();
	}
}

fn default_options() -> Value {
	json!({
		"language_id":"x86:LE:64:default","compiler_spec_id":"gcc",
		"enabled_analyzers":super::super::ANALYZERS_1214_V4,
		"disabled_analyzers":super::super::DISABLED_ANALYZERS_1214_V4,
		"disabled_analyzer_count":4,
		"disabled_analyzers_sha256":sha256(
			&serde_json::to_vec(&super::super::DISABLED_ANALYZERS_1214_V4).unwrap()),
		"analysis_options_format":super::super::OPTIONS_FORMAT_1214_V4,
		"analysis_option_count":146,
		"analysis_options_sha256":super::super::OPTIONS_SHA256_1214_V4,
		"analysis_options_unchanged":true,"no_return_repair_applied":false
	})
}

#[test]
fn default_profile_rejects_other_languages_missing_options_and_analyzer_overrides() {
	let original = default_options();
	validate_analysis_options(&original).unwrap();
	for (field, replacement) in [
		("language_id", json!("x86:LE:32:default")),
		("compiler_spec_id", json!("default")),
		("enabled_analyzers", json!(super::super::ANALYZERS)),
		("disabled_analyzers", json!([])),
		("disabled_analyzer_count", json!(3)),
		("disabled_analyzer_count", json!(true)),
		("disabled_analyzers_sha256", json!("0".repeat(64))),
		("analysis_options_format", json!("unversioned")),
		("analysis_option_count", json!(145)),
		("analysis_option_count", json!("146")),
		("analysis_options_sha256", json!("0".repeat(64))),
		("analysis_options_unchanged", json!(false)),
		("no_return_repair_applied", json!(true)),
	] {
		let mut changed = original.clone();
		changed[field] = replacement;
		assert!(validate_analysis_options(&changed).is_err(), "{field}");
	}
	for field in original.as_object().unwrap().keys() {
		let mut changed = original.clone();
		changed.as_object_mut().unwrap().remove(field);
		assert!(validate_analysis_options(&changed).is_err(), "{field}");
	}
}

fn native_cleanup() -> Value {
	json!({
		"decompilation_scope":"explicit_selected_function","auto_analysis_may_decompile":true,
		"native_child_cleanup_scope":"private_bridge_jvm_all_descendants",
		"native_helper_observation_scope":"live_descendants_at_phase_boundaries",
		"native_child_cleanup_confirmed":true,"observed_native_children":1,
		"observed_native_decompiler_children":1,"observed_explicit_decompiler_candidates":0,
		"native_children":[{"pid":42,"parent_pid":41,"start_ticks":"123",
			"start_instant":"2026-11-06T12:00:00Z","command":"/pinned/decompile",
			"first_observed_phase":"after_analysis",
			"role_attribution":"phase_and_executable_inference","role":"auto_analysis_decompiler_candidate",
			"explicit_decompiler_candidate":false,"state_before_cleanup":"S",
			"term_sent":true,"kill_sent":false,"final_state":"absent","exit_confirmed":true,"failure":null}]
	})
}

#[test]
fn helper_cleanup_keeps_phase_inferences_separate_from_decompile_results() {
	let value = native_cleanup();
	// An analysis helper can be observed for any operation. A phase-difference
	// candidate is an inference, not a new mandatory proof of selected ownership.
	validate_native_cleanup(&value, false).unwrap();
	validate_native_cleanup(&value, true).unwrap();
	let mut empty = value;
	empty["native_children"] = json!([]);
	empty["observed_native_children"] = json!(0);
	empty["observed_native_decompiler_children"] = json!(0);
	validate_native_cleanup(&empty, false).unwrap();
	assert!(validate_native_cleanup(&empty, true).is_err());
}

#[test]
fn helper_cleanup_rejects_unreaped_states_identity_loss_and_forged_role_counts() {
	let original = native_cleanup();
	for (field, replacement) in [
		("pid", json!(true)),
		("parent_pid", json!(42)),
		("start_ticks", json!("0123")),
		("start_instant", json!(null)),
		("command", json!("")),
		("role_attribution", json!("proven_selected_ownership")),
		("role", json!("explicit_decompiler_candidate")),
		("explicit_decompiler_candidate", json!(true)),
		("first_observed_phase", json!("unobserved")),
		("term_sent", json!(1)),
		("exit_confirmed", json!(false)),
		("final_state", json!("zombie")),
		("final_state", json!("unknown")),
		("failure", json!(false)),
	] {
		let mut changed = original.clone();
		changed["native_children"][0][field] = replacement;
		assert!(validate_native_cleanup(&changed, true).is_err(), "{field}");
	}
	for (field, replacement) in [
		("decompilation_scope", json!("all_program_decompilation")),
		("auto_analysis_may_decompile", json!(false)),
		(
			"native_child_cleanup_scope",
			json!("current_interface_only"),
		),
		(
			"native_helper_observation_scope",
			json!("complete_process_history"),
		),
		("native_child_cleanup_confirmed", json!(false)),
		("observed_native_children", json!(0)),
		("observed_native_decompiler_children", json!(0)),
		("observed_explicit_decompiler_candidates", json!(1)),
	] {
		let mut changed = original.clone();
		changed[field] = replacement;
		assert!(validate_native_cleanup(&changed, true).is_err(), "{field}");
	}
	let mut duplicate = original.clone();
	duplicate["native_children"] = json!([
		original["native_children"][0],
		original["native_children"][0]
	]);
	duplicate["observed_native_children"] = json!(2);
	duplicate["observed_native_decompiler_children"] = json!(2);
	assert!(validate_native_cleanup(&duplicate, true).is_err());
}
