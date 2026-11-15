// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0

use super::*;

#[test]
fn original_length_guards_coercions_origins_and_utf16_counts_match() {
	let fixture: Value = serde_json::from_str(include_str!(
		"../../tests/fixtures/rea_residual_unknown/reference-r2.json"
	))
	.unwrap();
	assert_eq!(fixture["source_unchanged"], true);
	let cases = fixture["length_checks"].as_array().unwrap();
	assert!(cases.len() >= 100);
	for case in cases {
		let mut validation = Validation::new(None);
		validation.min_length(Some(&case["input"]), &[], case["minimum"].as_u64().unwrap());
		if case["expected"]["throws"] == true {
			assert_eq!(
				validation.gap,
				Some("original-length-coercion-exception"),
				"{case}"
			);
			assert!(validation.issues.is_empty(), "{case}");
		} else {
			assert!(validation.gap.is_none(), "{case}");
			let issues: Vec<_> = validation
				.issues
				.iter()
				.map(|issue| json!({"path":issue.path,"message":issue.message}))
				.collect();
			assert_eq!(json!(issues), case["expected"]["issues"], "{case}");
		}
	}
}
