// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Boundary regressions checked against the installed REA 6.8.0 parser.

use super::*;

fn capture() -> Value {
	serde_json::from_str(include_str!(
		"../../tests/fixtures/rea_process_capture/minimal.json"
	))
	.unwrap()
}

fn failure(value: &Value) -> String {
	authenticate(value, None).unwrap_err().to_string()
}

#[test]
fn frozen_capture_commitments_use_the_parsed_projection_without_replacing_source() {
	let mut value = capture();
	authenticate(&value, None).unwrap();
	value["normalization"]["extra"] = json!({"retained":true});
	value["manifest"]["scenario"]["__proto__"] = json!("stripped by the upstream record schema");
	value["manifest"]["__proto__"] = json!("stripped by the upstream strict object schema");
	value["truncation_details"]["__proto__"] =
		json!("stripped by the upstream strict object schema");
	let before = value.clone();
	authenticate(&value, None).unwrap();
	assert_eq!(value, before);
	value["normalization"]["paths"] = json!(true);
	assert_eq!(
		failure(&value),
		"at manifest.normalization_sha256: commitment does not match its canonical value"
	);
}

#[test]
fn explicit_safe_integer_repeats_frozen_range_issues_without_repeating_type_errors() {
	for (number, expected) in [
		(json!(9007199254740992u64), "at normalization.time_bucket_ms: Too big: expected int to be <=9007199254740991 (2 more issues)"),
		(json!(-9007199254740992i64), "at normalization.time_bucket_ms: Too small: expected int to be >=-9007199254740991 (3 more issues)"),
		(json!(0.5), "at normalization.time_bucket_ms: Invalid input: expected int, received number"),
	] {
		let mut value = capture(); value["normalization"]["time_bucket_ms"] = number;
		assert_eq!(failure(&value), expected);
	}
}

#[test]
fn strict_object_unknown_keys_use_owned_source_order() {
	let mut value = capture();
	value["manifest"]["z"] = json!(1);
	value["manifest"]["a"] = json!(2);
	let order = |path: &[Value]| {
		if path == [json!("manifest")] {
			let mut keys: Vec<String> = value["manifest"]
				.as_object()
				.unwrap()
				.keys()
				.filter(|key| key.as_str() != "z" && key.as_str() != "a")
				.cloned()
				.collect();
			keys.extend(["z".into(), "a".into()]);
			Some(keys)
		} else {
			None
		}
	};
	assert_eq!(
		authenticate(&value, Some(&order)).unwrap_err().to_string(),
		"at manifest: Unrecognized keys: \"z\", \"a\""
	);
	assert!(matches!(
		authenticate(&value, None),
		Err(super::super::SourceError::ProfileGap { .. })
	));
}

#[test]
fn finalization_shape_refinement_and_cross_field_checks_both_survive_dirty_ranges() {
	let mut value = capture();
	value["manifest"]["scenario"]["finalization_ms"] = json!(10);
	value["manifest"]["comparison_contract"]["finalization_ms"] = json!(10);
	value["manifest"]["full_scenario_sha256"] =
		json!(record_digest(&value["manifest"]["scenario"]).unwrap());
	value["manifest"]["comparison_contract_sha256"] =
		json!(record_digest(&value["manifest"]["comparison_contract"]).unwrap());
	value["exit"] = json!({"code":null,"signal":null,"reason":"timeout","finalization":{
		"requested_ms":10,"elapsed_ms":11,"exit_code":0,"signals":[{"signal":"SIGTERM","sent_at_ms":0,"delivery":"signaled"}]
	}});
	authenticate(&value, None).unwrap();
	value["exit"]["finalization"]["elapsed_ms"] = Value::Null;
	assert_eq!(failure(&value), "at exit.finalization.exit_code: finalization exit_code requires an observed exit (1 more issues)");
	value["exit"]["finalization"]["requested_ms"] = json!(0.5);
	assert_eq!(
		failure(&value),
		"at exit.finalization.requested_ms: Invalid input: expected int, received number"
	);
}

#[test]
fn journal_references_share_javascript_zero_identity() {
	let mut value = capture();
	value["event_journal"] = json!([
		{"capture_order":0,"collection":"lifecycle","index":0},
		{"capture_order":1,"collection":"lifecycle","index":-0.0},
		{"capture_order":2,"collection":"filesystem_checkpoints","index":0},
		{"capture_order":3,"collection":"filesystem_checkpoints","index":1}
	]);
	assert_eq!(
		failure(&value),
		"at event_journal.1: journal references must be unique"
	);
}

#[test]
fn iso_dates_follow_zod_utc_calendar_and_precision() {
	for date in [
		"0000-02-29T00:00Z",
		"2024-02-29T23:59:59.001Z",
		"2026-01-01T00:00Z",
	] {
		let mut value = capture();
		value["manifest"]["started_at"] = json!(date);
		authenticate(&value, None).unwrap();
	}
	for date in [
		"1900-02-29T00:00Z",
		"2026-01-01T24:00Z",
		"2026-01-01T00:00:60Z",
		"2026-01-01T00:00+00:00",
		"2026-01-01T00:00Z\n",
	] {
		let mut value = capture();
		value["manifest"]["started_at"] = json!(date);
		assert_eq!(
			failure(&value),
			"at manifest.started_at: Invalid ISO datetime",
			"{date}"
		);
	}
}

#[test]
fn filesystem_coverage_cannot_claim_complete_missing_digest_or_unknown_source() {
	let mut value = capture();
	value["files_before"] = json!([{"path":"owned","mode":420,"size":1,"type":"file","sha256":null,"symlink_target":null}]);
	value["truncation_details"]["filesystem_before"]["files_limit"] = json!(1);
	assert_eq!(failure(&value), "at truncation_details.filesystem_before.hash_omissions: every retained regular file without a digest must have one matching omission reason");
	value["files_before"][0]["type"] = json!("future");
	assert_eq!(failure(&value), "at files_before.0.type: Invalid discriminator value. Expected 'file' | 'symlink' | 'directory' | 'other'");
}
