// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Analytic positive, non-proof and malformed certificate cases.

use super::*;

fn encoded(values: &[f64]) -> String {
	hex(values
		.iter()
		.flat_map(|x| x.to_le_bytes())
		.collect::<Vec<_>>())
}

fn bind(params: &mut CertificateParams) {
	params.expected_checkpoint_sha256 = hex(Sha256::digest(params.checkpoint_json.as_bytes()));
	let mut hash = Sha256::new();
	hash.update(b"hepta.weight.continuation-witness.v1\0");
	hash.update((params.rows.len() as u64).to_le_bytes());
	for row in &params.rows {
		hash.update(row.source_row.to_le_bytes());
		hash.update(bytes(&row.state_sha256, 32).unwrap());
		hash.update(bytes(&row.teacher_table_sha256, 32).unwrap());
		hash.update(row.legal.map(u8::from));
		hash.update([row.target_action, row.competitor_action]);
		hash.update(bytes(&row.multiplier_f64_le_hex, 8).unwrap());
		hash.update(bytes(&row.hidden_f64_le_hex, 392).unwrap());
		hash.update(bytes(&row.teacher_q_f64_le_hex, 48).unwrap());
	}
	params.expected_witness_sha256 = hex(hash.finalize());
}

fn fixture(biases: [f64; 3]) -> CertificateParams {
	let mut h = vec![0.0; 49];
	h[48] = 1.0;
	let hidden = encoded(&h);
	let mut params = CertificateParams {
		semantics: SEMANTICS.into(),
		checkpoint_json: json!({"schema":"joint-policy-v1", "family":"renewal", "fit":7,
			"head_dimensions":[85,48,4],
			"network":{"w2":vec![vec![0.0;48];4], "b2":[biases[0],biases[1],biases[2],0.0]}})
		.to_string(),
		expected_checkpoint_sha256: String::new(),
		expected_witness_sha256: String::new(),
		source: CertificateSource {
			fit_id: 7,
			protocol_sha256: "01".repeat(32),
			feature_source_sha256: "02".repeat(32),
			teacher_source_sha256: "03".repeat(32),
			original_witness_record_sha256: "04".repeat(32),
		},
		rows: vec![CertificateRow {
			source_row: 0,
			state_sha256: "05".repeat(32),
			teacher_table_sha256: "06".repeat(32),
			hidden_sha256: hex(Sha256::digest(bytes(&hidden, 392).unwrap())),
			hidden_f64_le_hex: hidden,
			multiplier_f64_le_hex: encoded(&[1.0]),
			teacher_q_f64_le_hex: encoded(&[0., 1., 0., 0., 0., 0.]),
			legal: [false, true, true, false, false, false],
			target_action: 1,
			competitor_action: 2,
		}],
	};
	bind(&mut params);
	params
}

#[test]
fn exact_positive_and_no_training_claim() {
	let result = solve(&fixture([-1., 1., 0.])).unwrap();
	assert_eq!(result["proof"]["ideal_real"]["strict_separation"], true);
	assert_eq!(
		result["proof"]["f64_necessary_relaxation"]["strict_separation"],
		true
	);
	assert_eq!(
		result["proof"]["verdict"],
		"F64_NECESSARY_SYSTEM_INFEASIBLE"
	);
	assert_eq!(
		result["proof"]["radius_squared"],
		json!({"numerator_hex":"1","binary_exponent":-1,"denominator_hex":"1"})
	);
	assert_eq!(
		result["proof"]["ideal_real"]["d"],
		json!({"numerator_hex":"1","binary_exponent":1,"denominator_hex":"1"})
	);
	assert_eq!(result["external_source_authentication"], false);
	assert_eq!(result["hidden_or_teacher_program_reexecuted"], false);
	assert_eq!(result["production_eligible"], false);
}

#[test]
fn exact_equality_is_not_a_proof() {
	// d=1, ||v||^2=2, R^2=(1+1)/4=1/2, so the inequality is equality.
	let result = solve(&fixture([-1., 0., 1.])).unwrap();
	assert_eq!(result["proof"]["ideal_real"]["d_positive"], true);
	assert_eq!(result["proof"]["ideal_real"]["strict_separation"], false);
	assert_eq!(result["proof"]["verdict"], "NOT_CERTIFIED");
}

#[test]
fn negative_d_cannot_be_rescued_by_squaring() {
	let result = solve(&fixture([1., -1., 0.])).unwrap();
	assert_eq!(result["proof"]["ideal_real"]["d_positive"], false);
	assert_eq!(result["proof"]["verdict"], "NOT_CERTIFIED");
}

#[test]
fn zero_y_and_larger_radius_are_not_certificates() {
	for zero in [0.0, -0.0] {
		let mut params = fixture([-1., 1., 0.]);
		params.rows[0].multiplier_f64_le_hex = encoded(&[zero]);
		bind(&mut params);
		let result = solve(&params).unwrap();
		assert_eq!(result["proof"]["nonzero_multipliers"], 0);
		assert_eq!(result["proof"]["verdict"], "NOT_CERTIFIED");
	}
	assert_eq!(
		solve(&fixture([-1., 1., 10.])).unwrap()["proof"]["verdict"],
		"NOT_CERTIFIED"
	);
}

#[test]
fn subnormal_real_proof_does_not_claim_f64_qualification() {
	let tiny = f64::from_bits(1);
	let result = solve(&fixture([-tiny, tiny, 0.])).unwrap();
	assert_eq!(result["proof"]["verdict"], "IDEAL_REAL_ONLY_INFEASIBLE");
	assert_eq!(
		result["proof"]["f64_necessary_relaxation"]["strict_separation"],
		false
	);
}

#[test]
fn source_content_shape_and_semantics_mismatches_fail() {
	let base = fixture([-1., 1., 0.]);
	let mut p = base.clone();
	p.expected_checkpoint_sha256 = "00".repeat(32);
	assert!(solve(&p)
		.unwrap_err()
		.to_string()
		.contains("checkpoint SHA256"));
	let mut p = base.clone();
	p.expected_witness_sha256 = "00".repeat(32);
	assert!(solve(&p)
		.unwrap_err()
		.to_string()
		.contains("witness SHA256"));
	let mut p = base.clone();
	p.rows[0].hidden_sha256 = "00".repeat(32);
	assert!(solve(&p)
		.unwrap_err()
		.to_string()
		.contains("hidden bytes SHA256"));
	let mut p = base.clone();
	p.source.fit_id = 8;
	assert!(solve(&p).is_err());
	let mut p = base.clone();
	p.semantics = "f32_or_fma".into();
	assert!(solve(&p).is_err());
	let mut p = base.clone();
	p.checkpoint_json = p.checkpoint_json.replace("[85,48,4]", "[85,47,4]");
	bind(&mut p);
	assert!(solve(&p).is_err());
	let mut p = base.clone();
	p.source.protocol_sha256 = "not-a-sha".into();
	assert!(solve(&p).is_err());
	let mut p = base;
	p.checkpoint_json = p
		.checkpoint_json
		.replace("\"fit\":7", "\"fit\":7,\"fit\":7");
	bind(&mut p);
	assert!(solve(&p).is_err());
}

#[test]
fn invalid_numeric_encodings_and_hidden_bounds_fail() {
	for value in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -1.0] {
		let mut p = fixture([-1., 1., 0.]);
		p.rows[0].multiplier_f64_le_hex = encoded(&[value]);
		bind(&mut p);
		assert!(solve(&p).is_err());
	}
	for value in [
		f64::NAN,
		f64::INFINITY,
		1.0000000000000002,
		-1.0000000000000002,
	] {
		let mut p = fixture([-1., 1., 0.]);
		let mut h = vec![0.; 49];
		h[0] = value;
		h[48] = 1.;
		p.rows[0].hidden_f64_le_hex = encoded(&h);
		p.rows[0].hidden_sha256 = hex(Sha256::digest(
			bytes(&p.rows[0].hidden_f64_le_hex, 392).unwrap(),
		));
		bind(&mut p);
		assert!(solve(&p).is_err());
	}
	let mut p = fixture([-1., 1., 0.]);
	p.rows[0].hidden_f64_le_hex = encoded(&[0.; 49]);
	p.rows[0].hidden_sha256 = hex(Sha256::digest(
		bytes(&p.rows[0].hidden_f64_le_hex, 392).unwrap(),
	));
	bind(&mut p);
	assert!(solve(&p).is_err());
	assert!(solve(&fixture([-1., 1., 1e307])).is_err());
}

#[test]
fn target_tie_order_illegal_action_duplicates_and_bounds_fail() {
	let mut p = fixture([-1., 1., 0.]);
	p.rows[0].target_action = 2;
	p.rows[0].competitor_action = 1;
	p.rows[0].teacher_q_f64_le_hex = encoded(&[0., 1., 1., 0., 0., 0.]);
	bind(&mut p);
	assert!(solve(&p).is_err());
	let mut p = fixture([-1., 1., 0.]);
	p.rows[0].competitor_action = 3;
	bind(&mut p);
	assert!(solve(&p).is_err());
	let mut p = fixture([-1., 1., 0.]);
	p.rows.push(p.rows[0].clone());
	bind(&mut p);
	assert!(solve(&p).is_err());
	let mut p = fixture([-1., 1., 0.]);
	p.rows = vec![p.rows[0].clone(); MAX_ROWS + 1];
	assert!(solve(&p).is_err());
	let mut p = fixture([-1., 1., 0.]);
	p.checkpoint_json = " ".repeat(MAX_MODEL_BYTES + 1);
	assert!(solve(&p).is_err());
	let mut p = fixture([-1., 1., 0.]);
	p.rows.clear();
	assert!(solve(&p).is_err());
}

#[test]
fn unknown_fields_and_wrong_scalar_types_fail_deserialization() {
	let mut v = serde_json::to_value(fixture([-1., 1., 0.])).unwrap();
	v["unexpected_authorization"] = json!(true);
	assert!(serde_json::from_value::<CertificateParams>(v).is_err());
	let mut v = serde_json::to_value(fixture([-1., 1., 0.])).unwrap();
	v["rows"][0]["multiplier_f64_le_hex"] = json!(true);
	assert!(serde_json::from_value::<CertificateParams>(v).is_err());
}

#[tokio::test]
async fn actual_async_entry_serializes_bounded_exact_result() {
	let output = verify(fixture([-1., 1., 0.])).await.unwrap();
	assert!(output.len() < MAX_RESULT_BYTES);
	let result: Value = serde_json::from_str(&output).unwrap();
	assert_eq!(
		result["proof"]["verdict"],
		"F64_NECESSARY_SYSTEM_INFEASIBLE"
	);
}

#[test]
fn one_source_row_cannot_name_different_feature_or_state_data() {
	let mut p = fixture([-1., 1., 0.]);
	p.rows[0].legal[3] = true;
	let mut second = p.rows[0].clone();
	second.competitor_action = 3;
	second.state_sha256 = "ff".repeat(32);
	p.rows.push(second);
	bind(&mut p);
	assert!(solve(&p)
		.unwrap_err()
		.to_string()
		.contains("source row has conflicting"));
}

#[test]
fn checkpoint_decimal_parser_preserves_declared_binary64_bits() {
	let cases = [
		("0.1", 0x3fb999999999999a_u64),
		("1.2345678901234567", 0x3ff3c0ca428c59fb_u64),
		(
			"1.00000000000000011102230246251565404236316680908203125",
			0x3ff0000000000000_u64,
		),
		(
			"1.00000000000000011102230246251565404236316680908203126",
			0x3ff0000000000001_u64,
		),
		("2.2250738585072014e-308", 0x0010000000000000_u64),
		("4.9406564584124654e-324", 0x0000000000000001_u64),
		("-0.0", 0x8000000000000000_u64),
		("1.7976931348623157e308", 0x7fefffffffffffff_u64),
	];
	for (literal, expected) in cases {
		let mut params = fixture([-1., 1., 0.]);
		params.checkpoint_json = params.checkpoint_json.replace(
			"\"b2\":[-1.0,1.0,0.0,0.0]",
			&format!("\"b2\":[{literal},1.0,0.0,0.0]"),
		);
		bind(&mut params);
		let (center, _, _) = validate(&params, Instant::now() + Duration::from_secs(30)).unwrap();
		assert_eq!(center[48], expected, "{literal}");
	}
}
