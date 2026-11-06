// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Adversarial body, namespace, reference-accounting and cleanup controls for revision 4.

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

fn reference_row(from: &str, to: &str, to_space: &str) -> Value {
	json!({"from_address":from,"to_address":to,"from_space":"ram","to_space":to_space,
		"reference_type":"DATA","source_type":"ANALYSIS","operand_index":0,
		"call":false,"primary":true,"entry_point_reference":false})
}

fn xrefs() -> Value {
	let mut value = selected();
	for (field, text) in [
		("incoming_scope", "selected_function_body_and_entry"),
		("outgoing_scope", "selected_function_body_and_entry"),
		("reference_default_address_space", "ram"),
		(
			"reference_address_format",
			"default-space-hex-or-utf8-space-unsigned64.v1",
		),
		("reference_filter", "exclude-isEntryPointReference"),
		("reference_deduplication", "from,to,type,operand,primary"),
		(
			"reference_order",
			"ghidra-address-from-to-type-operand-primary",
		),
		(
			"reference_scan_accounting",
			"raw-includes-entrypoint-filter-and-duplicates.v1",
		),
	] {
		value[field] = json!(text);
	}
	value["incoming_references"] = json!([reference_row("0x1234", "0x401001", "ram")]);
	value["outgoing_references"] = json!([reference_row(
		"0x401002",
		"stack:0xfffffffffffffff4",
		"stack"
	)]);
	for direction in ["incoming", "outgoing"] {
		for (field, count) in [
			(format!("scanned_{direction}_references"), 3),
			(format!("filtered_{direction}_entry_point_references"), 1),
			(format!("duplicate_{direction}_references_in_scan"), 1),
			(format!("unique_{direction}_references_in_scan"), 1),
			(format!("returned_{direction}_references"), 1),
			(format!("budget_omitted_{direction}_references"), 0),
			(format!("omitted_{direction}_references_in_scan"), 2),
		] {
			value[field] = json!(count);
		}
		value[format!("{direction}_scan_complete")] = json!(true);
	}
	value
}

#[test]
fn reference_spaces_use_unsigned_offsets_and_exact_utf8_percent_encoding() {
	for (space, address, expected) in [
		("ram", "0xffffffffffffffff", u64::MAX),
		("stack", "stack:0xfffffffffffffff4", u64::MAX - 11),
		("Reg λ", "Reg%20%CE%BB:0x2a", 42),
		("a:b%/", "a%3Ab%25%2F:0x0", 0),
		("._~-AZaz09", "._~-AZaz09:0x1", 1),
	] {
		let row = reference_row("0x1", address, space);
		assert_eq!(
			reference_endpoint(&row, "to_address", "to_space")
				.unwrap()
				.2,
			expected
		);
	}
	for (space, address) in [
		("ram", "ram:0x1"),
		("stack", "0xfffffffffffffff4"),
		("stack", "Stack[-0xc]"),
		("stack", "%73tack:0x1"),
		("stack", "stack:0x01"),
		("stack", "stack:0xA"),
		("stack", "stack:0x10000000000000000"),
		("stack", "stack:-0xc"),
		("Reg λ", "Reg%20%ce%bb:0x2a"),
		("Reg λ", "Reg λ:0x2a"),
		("a/b", "a%2fb:0x0"),
		("", ":0x1"),
	] {
		let row = reference_row("0x1", address, space);
		assert!(
			reference_endpoint(&row, "to_address", "to_space").is_err(),
			"{space} {address}"
		);
	}
}

#[test]
fn references_are_bound_to_actual_body_ranges_in_each_direction() {
	let original = xrefs();
	validate_xrefs(&original).unwrap();
	for direction in ["incoming", "outgoing"] {
		let field = if direction == "incoming" {
			"to_address"
		} else {
			"from_address"
		};
		let space = if direction == "incoming" {
			"to_space"
		} else {
			"from_space"
		};
		for address in ["0x401000", "0x40100f", "0x401020", "0x40102f"] {
			let mut value = original.clone();
			value[format!("{direction}_references")][0][field] = json!(address);
			validate_xrefs(&value).unwrap();
		}
		for address in ["0x400fff", "0x401010", "0x40101f", "0x401030"] {
			let mut value = original.clone();
			value[format!("{direction}_references")][0][field] = json!(address);
			assert!(validate_xrefs(&value).is_err(), "{direction} {address}");
		}
		let mut value = original.clone();
		value[format!("{direction}_references")][0][field] = json!("other:0x401000");
		value[format!("{direction}_references")][0][space] = json!("other");
		assert!(validate_xrefs(&value).is_err());
	}
}

#[test]
fn raw_reference_limit_includes_synthetic_and_duplicate_observations() {
	for complete in [false, true] {
		let mut filtered = xrefs();
		filtered["incoming_references"] = json!([]);
		filtered["scanned_incoming_references"] = json!(4096);
		filtered["filtered_incoming_entry_point_references"] = json!(4096);
		filtered["duplicate_incoming_references_in_scan"] = json!(0);
		filtered["unique_incoming_references_in_scan"] = json!(0);
		filtered["returned_incoming_references"] = json!(0);
		filtered["omitted_incoming_references_in_scan"] = json!(4096);
		filtered["incoming_scan_complete"] = json!(complete);
		validate_xrefs(&filtered).unwrap();
		for count in [4095, 4097] {
			let mut changed = filtered.clone();
			changed["scanned_incoming_references"] = json!(count);
			changed["filtered_incoming_entry_point_references"] = json!(count);
			changed["omitted_incoming_references_in_scan"] = json!(count);
			changed["incoming_scan_complete"] = json!(false);
			assert!(validate_xrefs(&changed).is_err(), "{count}");
		}
		let mut repeated = xrefs();
		repeated["scanned_incoming_references"] = json!(4096);
		repeated["filtered_incoming_entry_point_references"] = json!(0);
		repeated["duplicate_incoming_references_in_scan"] = json!(4095);
		repeated["omitted_incoming_references_in_scan"] = json!(4095);
		repeated["incoming_scan_complete"] = json!(complete);
		validate_xrefs(&repeated).unwrap();
		repeated["duplicate_incoming_references_in_scan"] = json!(4096);
		repeated["scanned_incoming_references"] = json!(4097);
		repeated["omitted_incoming_references_in_scan"] = json!(4096);
		assert!(validate_xrefs(&repeated).is_err());
	}
}

#[test]
fn reference_counts_refuse_type_coercions_overflow_and_unfounded_duplicates() {
	let original = xrefs();
	for field in [
		"scanned_incoming_references",
		"filtered_incoming_entry_point_references",
		"duplicate_incoming_references_in_scan",
		"unique_incoming_references_in_scan",
		"returned_incoming_references",
		"omitted_incoming_references_in_scan",
		"budget_omitted_incoming_references",
	] {
		for bad in [
			json!(u64::MAX),
			json!(true),
			json!(-1),
			json!(1.0),
			json!("1"),
			Value::Null,
		] {
			let mut value = original.clone();
			value[field] = bad;
			assert!(validate_xrefs(&value).is_err(), "{field}");
		}
	}
	let mut value = original;
	value["incoming_references"] = json!([]);
	value["scanned_incoming_references"] = json!(1);
	value["filtered_incoming_entry_point_references"] = json!(0);
	value["unique_incoming_references_in_scan"] = json!(0);
	value["returned_incoming_references"] = json!(0);
	value["omitted_incoming_references_in_scan"] = json!(1);
	assert!(validate_xrefs(&value).is_err());
}

#[test]
fn reference_budget_trimming_preserves_scan_facts_and_separate_omissions() {
	let mut value = xrefs();
	for direction in ["incoming", "outgoing"] {
		value[format!("{direction}_references")] = json!([]);
		value[format!("returned_{direction}_references")] = json!(0);
		value[format!("omitted_{direction}_references_in_scan")] = json!(3);
		value[format!("budget_omitted_{direction}_references")] = json!(1);
		validate_xrefs(&value).unwrap();
		for field in [
			format!("budget_omitted_{direction}_references"),
			format!("omitted_{direction}_references_in_scan"),
		] {
			let mut wrong = value.clone();
			wrong[field] = json!(0);
			assert!(validate_xrefs(&wrong).is_err());
		}
		let mut wrong = value.clone();
		wrong[format!("{direction}_scan_complete")] = json!(false);
		assert!(validate_xrefs(&wrong).is_err());
	}
}

#[test]
fn reference_identity_includes_primary_but_excludes_descriptive_fields() {
	let mut value = xrefs();
	let mut second = value["incoming_references"][0].clone();
	second["primary"] = json!(false);
	value["incoming_references"]
		.as_array_mut()
		.unwrap()
		.push(second);
	value["returned_incoming_references"] = json!(2);
	value["unique_incoming_references_in_scan"] = json!(2);
	value["duplicate_incoming_references_in_scan"] = json!(0);
	value["omitted_incoming_references_in_scan"] = json!(1);
	validate_xrefs(&value).unwrap();
	value["incoming_references"][1]["primary"] = json!(true);
	value["incoming_references"][1]["source_type"] = json!("USER_DEFINED");
	value["incoming_references"][1]["call"] = json!(true);
	assert!(validate_xrefs(&value).is_err());
	for (field, bad) in [
		("entry_point_reference", json!(true)),
		("entry_point_reference", json!(0)),
		("operand_index", json!(i64::from(i32::MAX) + 1)),
		("primary", json!(1)),
		("reference_type", json!("")),
		("source_type", Value::Null),
	] {
		let mut wrong = xrefs();
		wrong["incoming_references"][0][field] = bad;
		assert!(validate_xrefs(&wrong).is_err(), "{field}");
	}
	let mut wrong = xrefs();
	wrong["incoming_scope"] = json!("exact_function_entry");
	assert!(validate_xrefs(&wrong).is_err());
}

#[test]
fn actual_owned_original_reference_projection_fits_the_revision_four_contract() {
	let fixture: Value = serde_json::from_str(include_str!(
		"../../tests/fixtures/rea_ghidra_1214_owned_xrefs.json"
	))
	.unwrap();
	assert_eq!(
		fixture["qualification_scope"],
		"ordered_six_field_projection_only"
	);
	assert_eq!(fixture["full_evidence_equivalent"], false);
	for selector in ["entry", "interior"] {
		let case = &fixture["cases"][selector];
		let mut value = xrefs();
		let mut function = named_row("0x401106", false);
		function["body_min_address"] = json!("0x401106");
		function["body_max_address"] = json!("0x40111f");
		function["body_address_count"] = json!("26");
		function["body_range_count"] = json!(1);
		function["body_ranges_complete"] = json!(true);
		function["body_ranges"] = fixture["selected_body_ranges"].clone();
		value["function"] = function;
		value["function_resolution"] = json!(if selector == "entry" {
			"entry"
		} else {
			"containing"
		});
		for direction in ["incoming", "outgoing"] {
			let rows: Vec<_> = case[direction]["rows"]
				.as_array()
				.unwrap()
				.iter()
				.map(|oracle| {
					let mut row = oracle.clone();
					row["from_space"] = json!("ram");
					row["to_space"] = json!(if direction == "outgoing" {
						"stack"
					} else {
						"ram"
					});
					// Only six fields are real oracle data. These fields exercise the native validator.
					row["source_type"] = json!("ANALYSIS");
					row["entry_point_reference"] = json!(false);
					row
				})
				.collect();
			value[format!("{direction}_references")] = json!(rows);
			for (prefix, suffix, key) in [
				("scanned", "references", "scanned"),
				("filtered", "entry_point_references", "filtered_entry_point"),
				("duplicate", "references_in_scan", "duplicate"),
				("unique", "references_in_scan", "unique"),
				("returned", "references", "returned"),
				("omitted", "references_in_scan", "omitted"),
				("budget_omitted", "references", "budget_omitted"),
			] {
				value[format!("{prefix}_{direction}_{suffix}")] =
					fixture["native_count_expectations"][direction][key].clone();
			}
			value[format!("{direction}_scan_complete")] = json!(true);
		}
		validate_selected(&value, case["requested_address"].as_str().unwrap()).unwrap();
		validate_xrefs(&value).unwrap();
	}
}
