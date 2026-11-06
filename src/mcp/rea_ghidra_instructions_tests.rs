// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Trust-boundary and exact-budget cases for a complete instruction-window observation.

use super::*;
use serde_json::json;

fn fixture() -> Value {
	serde_json::from_str(include_str!(
		"../../tests/fixtures/rea_ghidra_instructions/contract-window.json"
	))
	.unwrap()
}

fn refresh_text(value: &mut Value) {
	let lines = value["instruction_window"]["instructions"]
		.as_array()
		.unwrap()
		.iter()
		.map(|line| line.as_str().unwrap())
		.collect::<Vec<_>>();
	let text = lines.join("\n");
	let count = lines.len();
	value["instruction_count"] = json!(count);
	value["instruction_text_utf8_bytes"] = json!(text.len());
	value["instruction_text_sha256"] = json!(sha256(text.as_bytes()));
}

#[test]
fn complete_instruction_window_preserves_non_contiguous_body_and_original_value_shape() {
	let value = fixture();
	validate(&value, "0x1000").unwrap();
	assert_eq!(
		value["instruction_window"]["procedure"]["body"]["ranges"]
			.as_array()
			.unwrap()
			.len(),
		2
	);
	assert_eq!(
		value["instruction_window"]["procedure"]["body"]["total_bytes"],
		7
	);
	assert_eq!(
		value["instruction_window"]["procedure"]["body"]["span_bytes"],
		17
	);
	assert_eq!(value["instruction_count"], 3);
}

#[test]
fn complete_empty_listing_is_an_observation_not_proof_of_absent_code() {
	let mut value = fixture();
	value["instruction_window"]["instructions"] = json!([]);
	value["instruction_bytes"] = json!([]);
	refresh_text(&mut value);
	validate(&value, "0x1000").unwrap();
	assert_eq!(
		value["instruction_window"]["limitations"][2],
		LIMITATIONS[2]
	);
}

#[test]
fn complete_instruction_count_accepts_the_exact_bound_and_refuses_one_more() {
	let mut value = fixture();
	for count in [4096usize, 4097] {
		let instructions: Vec<_> = (0..count)
			.map(|index| format!("0x{:x}: NOP", 0x1000 + index))
			.collect();
		let bytes: Vec<_> = (0..count)
			.map(
				|index| json!({"address":format!("0x{:x}", 0x1000 + index),"length":1,"bytes_hex":"90"}),
			)
			.collect();
		value["instruction_window"]["instructions"] = json!(instructions);
		value["instruction_bytes"] = json!(bytes);
		value["instruction_window"]["procedure"]["body"] = json!({
			"available":true,"provenance":"ghidra-function-body-address-set",
			"ranges":[{"start":"0x1000","end":format!("0x{:x}",0x1000+count-1)}],
			"total_bytes":count,"span_bytes":count,"non_contiguous":false,"contains_entry":true
		});
		value["function"]["body_address_count"] = json!(count.to_string());
		refresh_text(&mut value);
		assert_eq!(validate(&value, "0x1000").is_ok(), count == 4096);
	}
}

#[test]
fn complete_body_requires_ranges_not_an_enclosing_span() {
	for (pointer, replacement) in [
		("/instruction_window/procedure/body/total_bytes", json!(17)),
		("/instruction_window/procedure/body/span_bytes", json!(7)),
		(
			"/instruction_window/procedure/body/contains_entry",
			json!(false),
		),
		(
			"/instruction_window/procedure/body/non_contiguous",
			json!(false),
		),
		(
			"/instruction_window/procedure/body/ranges/1/start",
			json!("0x1006"),
		),
		(
			"/instruction_window/procedure/body/ranges/1/end",
			json!("0x100f"),
		),
		(
			"/instruction_window/procedure/body/ranges/0/end",
			json!("0x1010"),
		),
	] {
		let mut value = fixture();
		*value.pointer_mut(pointer).unwrap() = replacement;
		assert!(validate(&value, "0x1000").is_err(), "{pointer}");
	}
	let mut hole = fixture();
	hole["instruction_window"]["instructions"][2] = json!("0x1008: RET");
	hole["instruction_bytes"][2]["address"] = json!("0x1008");
	refresh_text(&mut hole);
	assert!(validate(&hole, "0x1000").is_err());
}

#[test]
fn instruction_byte_evidence_cannot_cross_body_edges_or_disagree_with_listing() {
	for (pointer, replacement) in [
		("/instruction_bytes/0/address", json!("0x1001")),
		("/instruction_bytes/0/length", json!(0)),
		("/instruction_bytes/0/bytes_hex", json!("b81100")),
		("/instruction_bytes/0/bytes_hex", json!("B811000000")),
		("/instruction_bytes/2/length", json!(2)),
		("/instruction_bytes/2/bytes_hex", json!("c390")),
		("/instruction_text_sha256", json!("0".repeat(64))),
		("/instruction_text_utf8_bytes", json!(0)),
	] {
		let mut value = fixture();
		*value.pointer_mut(pointer).unwrap() = replacement;
		assert!(validate(&value, "0x1000").is_err(), "{pointer}");
	}
	let mut crossing = fixture();
	crossing["instruction_bytes"][2]["length"] = json!(2);
	crossing["instruction_bytes"][2]["bytes_hex"] = json!("c390");
	assert!(validate(&crossing, "0x1000").is_err());
	let mut reordered = fixture();
	reordered["instruction_window"]["instructions"]
		.as_array_mut()
		.unwrap()
		.swap(0, 1);
	reordered["instruction_bytes"]
		.as_array_mut()
		.unwrap()
		.swap(0, 1);
	refresh_text(&mut reordered);
	assert!(validate(&reordered, "0x1000").is_err());
}

#[test]
fn incomplete_wrong_owner_or_decompiler_windows_are_not_successful_facts() {
	for (pointer, replacement) in [
		("/instructions_complete", json!(false)),
		("/omitted_instructions", json!(1)),
		("/instruction_count", json!(2)),
		("/decompiler_invoked", json!(true)),
		("/decompilation_performed", json!(true)),
		("/instruction_timeout_seconds", json!(11)),
		("/upstream_operation", json!("procedure_pseudo_code")),
		("/instruction_scope", json!("enclosing_address_span")),
		("/instruction_window/procedure/address", json!("0x1001")),
		(
			"/instruction_window/procedure/classification/external",
			json!(true),
		),
		(
			"/instruction_window/procedure/classification/thunk_target",
			json!("0x2000"),
		),
		("/instruction_window/procedure/body/available", json!(false)),
		(
			"/instruction_window/procedure/symbol/source",
			json!("guessed"),
		),
		("/function/name_sha256", json!("0".repeat(64))),
		("/function/body_address_count", json!("17")),
		("/instruction_window/limitations", json!([])),
	] {
		let mut value = fixture();
		*value.pointer_mut(pointer).unwrap() = replacement;
		assert!(validate(&value, "0x1000").is_err(), "{pointer}");
	}
	assert!(validate(&fixture(), "0x1001").is_err());
}

#[test]
fn named_spaces_preserve_canonical_coordinates_and_null_multi_space_span() {
	let mut value = fixture();
	let body = &mut value["instruction_window"]["procedure"]["body"];
	body["ranges"].as_array_mut().unwrap().push(json!({
		"start":"overlay%20text:0x1000","end":"overlay%20text:0x1002"
	}));
	body["total_bytes"] = json!(10);
	body["span_bytes"] = Value::Null;
	value["function"]["body_address_count"] = json!("10");
	validate(&value, "0x1000").unwrap();
	value["instruction_window"]["procedure"]["body"]["ranges"][2]["start"] =
		json!("overlay%2ftext:0x1000");
	assert!(validate(&value, "0x1000").is_err());
	assert!(coordinate("EXTERNAL:0xffffffffffffffff").is_ok());
	assert!(coordinate("space%3Aname:0x1").is_ok());
	for invalid in [
		"0x01",
		"EXTERNAL:0x00",
		"space name:0x1",
		"space%GG:0x1",
		":0x1",
	] {
		assert!(coordinate(invalid).is_err(), "{invalid}");
	}
}

#[test]
fn complete_text_fields_refuse_truncation_extra_fields_and_non_line_values() {
	for replacement in [
		json!(""),
		json!("0x1000: NOP\n0x1001: RET"),
		json!("a".repeat(4097)),
	] {
		let mut value = fixture();
		value["instruction_window"]["instructions"][0] = replacement;
		refresh_text(&mut value);
		assert!(validate(&value, "0x1000").is_err());
	}
	let mut extra = fixture();
	extra["instruction_window"]["truncated"] = json!(true);
	assert!(validate(&extra, "0x1000").is_err());
	let mut missing = fixture();
	missing["instruction_window"]["procedure"]
		.as_object_mut()
		.unwrap()
		.remove("symbol");
	assert!(validate(&missing, "0x1000").is_err());
	let mut long_name = fixture();
	long_name["instruction_window"]["procedure"]["name"] = json!("n".repeat(1025));
	long_name["function"]["name_sha256"] = json!(sha256("n".repeat(1025).as_bytes()));
	assert!(validate(&long_name, "0x1000").is_err());
}

#[test]
fn complete_joined_instruction_text_accepts_exact_utf8_budget_and_refuses_one_byte_more() {
	let mut value = fixture();
	let mut lines: Vec<_> = (0..17)
		.map(|index| format!("0x{:x}: {}", 0x1000 + index, "é".repeat(1923)))
		.collect();
	lines.last_mut().unwrap().push_str("aa");
	let bytes: Vec<_> = (0..17)
		.map(
			|index| json!({"address":format!("0x{:x}", 0x1000 + index),"length":1,"bytes_hex":"90"}),
		)
		.collect();
	value["instruction_window"]["procedure"]["body"] = json!({
		"available":true,"provenance":"ghidra-function-body-address-set",
		"ranges":[{"start":"0x1000","end":"0x1010"}],
		"total_bytes":17,"span_bytes":17,"non_contiguous":false,"contains_entry":true
	});
	value["function"]["body_address_count"] = json!("17");
	value["instruction_bytes"] = json!(bytes);
	value["instruction_window"]["instructions"] = json!(lines);
	refresh_text(&mut value);
	assert_eq!(value["instruction_text_utf8_bytes"], MAX_TEXT_BYTES);
	validate(&value, "0x1000").unwrap();
	lines.last_mut().unwrap().push('a');
	value["instruction_window"]["instructions"] = json!(lines);
	refresh_text(&mut value);
	assert_eq!(value["instruction_text_utf8_bytes"], MAX_TEXT_BYTES + 1);
	assert!(validate(&value, "0x1000").is_err());
}
