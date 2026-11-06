// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0

//! Unmodified npm-domain results, including normalization and ordered errors.
use super::*;

fn reference() -> Value {
	serde_json::from_str(include_str!(
		"../../tests/fixtures/rea_residual_unknown/reference-r2.json"
	))
	.unwrap()
}

#[test]
fn published_unknown_shapes_match_normalized_values_and_every_ordered_issue() {
	let reference = reference();
	assert_eq!(reference["source_unchanged"], true);
	let cases = reference["shapes"].as_array().unwrap();
	assert!(cases.len() >= 150);
	for case in cases {
		let name = case["name"].as_str().unwrap();
		let mut value = case["input"].clone();
		let resolver = |path: &[Value]| {
			case["key_orders"]
				.as_array()
				.unwrap()
				.iter()
				.find(|hint| hint["path"].as_array().unwrap().as_slice() == path)
				.map(|hint| {
					hint["keys"]
						.as_array()
						.unwrap()
						.iter()
						.map(|key| key.as_str().unwrap().to_owned())
						.collect::<Vec<_>>()
				})
		};
		let mut validation = Validation::new(Some(&resolver));
		validate_shape(&mut value, &[], &mut validation).unwrap();
		let issues: Vec<_> = validation
			.issues
			.iter()
			.map(|issue| json!({"path": &issue.path, "message": &issue.message}))
			.collect();
		let result = validation.finish();
		if case["expected"]["ok"] == true {
			assert!(result.is_ok(), "{name}: {result:?}");
			assert_eq!(value, case["expected"]["value"], "{name}: normalized value");
		} else {
			assert_eq!(json!(issues), case["expected"]["issues"], "{name}: issues");
			match result {
				Err(super::super::SourceError::InvalidRecord { description, .. }) => {
					assert_eq!(
						description, case["expected"]["description"],
						"{name}: description"
					);
				}
				other => panic!("{name}: expected original shape failure, received {other:?}"),
			}
		}
	}
}

#[test]
fn published_unknown_histories_references_and_resolution_requirements_match() {
	let reference = reference();
	let cases = reference["graphs"].as_array().unwrap();
	assert!(cases.len() >= 25);
	for case in cases {
		let name = case["name"].as_str().unwrap();
		let mut unknowns = case["unknowns"].as_array().unwrap().clone();
		for unknown in &mut unknowns {
			let mut validation = Validation::new(None);
			validate_shape(unknown, &[], &mut validation).unwrap();
			assert!(
				validation.finish().is_ok(),
				"{name}: original graph fixture shape"
			);
		}
		let records = case["records"].as_array().unwrap();
		for record in records {
			assert!(
				super::super::authenticate_inline(record.clone()).is_ok(),
				"{name}: original graph Evidence"
			);
		}
		let unknowns: Vec<_> = unknowns.iter().collect();
		let records: Vec<_> = records.iter().collect();
		let actual = validate_graph(&unknowns, &records);
		if case["expected"]["ok"] == true {
			assert!(actual.is_ok(), "{name}: {actual:?}");
		} else {
			assert_eq!(
				actual.unwrap_err(),
				case["expected"]["message"],
				"{name}: graph failure"
			);
		}
	}
}
