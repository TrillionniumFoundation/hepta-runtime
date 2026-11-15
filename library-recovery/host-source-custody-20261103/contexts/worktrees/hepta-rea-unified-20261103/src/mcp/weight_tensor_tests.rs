// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Exact element-format, identity and range regressions independent of file I/O.

use super::*;
use serde_json::json;

fn input(dtype: &str) -> (PatchTensorParams, Value) {
	let (bytes, size) = if dtype == "F32" {
		("0000803f", 16)
	} else {
		("003c", 8)
	};
	let params = PatchTensorParams {
		path: "/models/parent.safetensors".into(),
		expected_sha256: "a".repeat(64),
		tensor_name: "weight".into(),
		edits: vec![ExactElementEdit {
			index: 2,
			expected_hex: bytes.into(),
			replacement_hex: bytes.into(),
		}],
	};
	let report = json!({"format":"safetensors","source":{"size_bytes":128+size,"header_bytes":128},"result":{"tensor":{"name":"weight","dtype":dtype,"storage_length_verified":true,"file_offset":128,"byte_length":size}}});
	(params, report)
}

#[test]
fn exact_f32_f16_bf16_offsets_and_noop_bits_are_preserved() {
	for dtype in ["F32", "F16", "BF16"] {
		let (params, report) = input(dtype);
		let plan = prepare(&params, &report).unwrap();
		assert_eq!(
			plan.changes[0].expected_hex,
			plan.changes[0].replacement_hex
		);
		assert_eq!(
			plan.changes[0].file_offset,
			if dtype == "F32" { 136 } else { 132 }
		);
		assert_eq!(plan.dtype, dtype);
	}
}

#[test]
fn indices_lengths_unknown_layouts_and_nonfinite_values_are_refused() {
	let (mut params, mut report) = input("F32");
	params.edits[0].index = 4;
	assert!(prepare(&params, &report).is_err());
	params.edits[0].index = 2;
	params.edits.push(params.edits[0].clone());
	assert!(prepare(&params, &report).is_err());
	params.edits.pop();
	for value in ["0000807f", "0000c07f", "00", "ABCDEF00"] {
		params.edits[0].replacement_hex = value.into();
		assert!(prepare(&params, &report).is_err(), "{value}");
	}
	params.edits[0].replacement_hex = "0000803f".into();
	report["result"]["tensor"]["storage_length_verified"] = json!(false);
	assert!(prepare(&params, &report).is_err());
	for (dtype, nonfinite) in [("F16", "007c"), ("BF16", "807f")] {
		let (mut params, report) = input(dtype);
		params.edits[0].replacement_hex = nonfinite.into();
		assert!(prepare(&params, &report).is_err());
	}
	let (params, report) = input("I32");
	assert!(prepare(&params, &report).is_err());
}

#[test]
fn ordering_is_canonical_but_signed_zero_is_not_a_byte_noop() {
	let (mut params, report) = input("F32");
	params.edits.push(ExactElementEdit {
		index: 0,
		expected_hex: "00000080".into(),
		replacement_hex: "00000000".into(),
	});
	let plan = prepare(&params, &report).unwrap();
	assert_eq!(plan.changes[0].index, 0);
	assert_ne!(
		plan.changes[0].expected_hex,
		plan.changes[0].replacement_hex
	);
	params.edits.reverse();
	assert_eq!(prepare(&params, &report).unwrap(), plan);
}
