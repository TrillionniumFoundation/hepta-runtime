// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Controls for exact dyadic semantics, nonclaims and bounded rejection paths.
use super::*;

fn params(rows: usize, columns: usize, values: &[f32]) -> ExactRankParams {
	let raw: Vec<_> = values
		.iter()
		.flat_map(|value| value.to_le_bytes())
		.collect();
	ExactRankParams {
		rows,
		columns,
		f32_le_hex: digest_hex(&raw),
		expected_raw_sha256: sha(&raw),
		source_declaration: None,
	}
}
#[test]
fn near_singular_f32_matrix_has_exact_nonzero_minor() {
	let next = f32::from_bits(1.0f32.to_bits() + 1);
	let result = evaluate(params(2, 2, &[1.0, 1.0, 1.0, next])).unwrap();
	assert_eq!(result["status"], "EXACT_FULL_COLUMN_RANK");
	assert_eq!(result["only_zero_exact_preserving_contrast"], true);
	assert_eq!(result["proof"]["common_denominator_power_of_two"], 23);
	assert_eq!(
		result["proof"]["exact_integer_minor_determinant"],
		"8388608"
	);
}
#[test]
fn subnormal_and_signed_zero_are_decoded_without_float_arithmetic() {
	let result = evaluate(params(
		2,
		2,
		&[f32::from_bits(1), -0.0, 0.0, f32::from_bits(2)],
	))
	.unwrap();
	assert_eq!(result["proof"]["common_denominator_power_of_two"], 149);
	assert_eq!(result["proof"]["exact_integer_minor_determinant"], "2");
	assert_eq!(
		result["proof"]["rational_minor_denominator_power_of_two"],
		298
	);
}
#[test]
fn modular_deficiency_never_claims_exact_deficiency() {
	let mut input = params(3, 2, &[1.0, 2.0, 2.0, 4.0, 0.0, -0.0]);
	input.source_declaration = Some("caller claims full rank; this text is not evidence".into());
	let result = evaluate(input).unwrap();
	assert_eq!(result["status"], "UNKNOWN");
	assert_eq!(result["modular_rank_lower_bound"], 1);
	assert!(
		result["exact_rank"].is_null() && result["only_zero_exact_preserving_contrast"].is_null()
	);
	assert!(result["proof"].is_null());
	assert_eq!(result["source_declaration_independently_verified"], false);
}
#[test]
fn dimensions_hex_identity_and_nonfinite_values_are_rejected() {
	let mut input = params(1, 1, &[1.0]);
	input.rows = 129;
	assert!(evaluate(input).is_err());
	let mut input = params(1, 1, &[1.0]);
	input.f32_le_hex.pop();
	assert!(evaluate(input).is_err());
	let mut input = params(1, 1, &[1.0]);
	input.f32_le_hex.replace_range(0..1, "z");
	assert!(evaluate(input).is_err());
	let mut input = params(1, 1, &[1.0]);
	input.expected_raw_sha256 = "0".repeat(64);
	assert!(evaluate(input).is_err());
	for value in [f32::INFINITY, f32::NEG_INFINITY, f32::NAN] {
		assert!(evaluate(params(1, 1, &[value])).is_err());
	}
}
#[test]
fn duplicate_fields_and_supplied_certificates_are_rejected() {
	let raw =
		r#"{"rows":1,"rows":1,"columns":1,"f32_le_hex":"0000803f","expected_raw_sha256":"x"}"#;
	assert!(serde_json::from_str::<ExactRankParams>(raw).is_err());
	let raw = r#"{"rows":1,"columns":1,"f32_le_hex":"0000803f","expected_raw_sha256":"x","certificate":{"rank":1}}"#;
	assert!(serde_json::from_str::<ExactRankParams>(raw).is_err());
}
#[test]
fn deadline_and_work_budget_fail_without_a_partial_proof() {
	assert!(evaluate_with_deadline(params(1, 1, &[1.0]), Instant::now()).is_err());
	let mut budget = Budget {
		deadline: Instant::now() + MAX_TIME,
		used: 0,
		limit: 0,
	};
	assert!(evaluate_inner(params(1, 1, &[1.0]), &mut budget).is_err());
}
#[test]
fn original_pivot_rows_and_integer_sign_are_recorded() {
	let result = evaluate(params(3, 2, &[0.0, 0.0, 0.0, 2.0, 3.0, 0.0])).unwrap();
	assert_eq!(result["proof"]["pivot_original_rows"], json!([2, 1]));
	assert_eq!(result["proof"]["exact_integer_minor_determinant"], "6");
	assert_eq!(result["proof"]["common_denominator_power_of_two"], 0);
}
