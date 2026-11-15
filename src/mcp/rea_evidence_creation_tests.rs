// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Independent frozen-npm producer records, plus identity and refusal boundaries.

use super::*;

#[test]
fn generated_records_equal_frozen_npm_producer_envelopes() {
	let fixtures: Value = serde_json::from_str(include_str!(
		"../../tests/fixtures/rea_evidence_creation.json"
	))
	.unwrap();
	let cases = fixtures["cases"].as_array().unwrap();
	assert!(cases.len() >= 12);
	for case in cases {
		let actual = create_record(case.get("target"), &case["provider"], &case["observation"])
			.unwrap_or_else(|error| panic!("{}: {error}", case["name"]));
		assert_eq!(actual, case["expected"], "{}", case["name"]);
		let projected = super::super::semantic_record_content(&actual).unwrap();
		assert_eq!(
			super::super::semantic_digest(&actual).unwrap(),
			super::super::canonical_sha(&projected).unwrap(),
			"streamed identity: {}",
			case["name"]
		);
	}
}

fn valid_input() -> (Value, Value, Value) {
	(
		json!({"path":"/fixtures/probe.elf","format":"elf","sha256":"11".repeat(32),"architecture":"x86_64"}),
		json!({"id":"rea-elf-notes","name":"REA ELF note parser","version":"1"}),
		json!({"operation":"inspect_elf_notes","parameters":{"path":"/fixtures/probe.elf"},"result":{"entry":7}}),
	)
}

#[test]
fn metadata_rebinding_preserves_identity_but_changed_parameters_do_not() {
	let (target, provider, observation) = valid_input();
	let first = create_record(Some(&target), &provider, &observation).unwrap();
	let mut moved = target.clone();
	moved["path"] = json!("/elsewhere/probe.elf");
	let second = create_record(Some(&moved), &provider, &observation).unwrap();
	assert_eq!(first["evidence_id"], second["evidence_id"]);
	assert_ne!(first["subject"], second["subject"]);
	let mut changed = observation;
	changed["parameters"]["path"] = moved["path"].clone();
	let third = create_record(Some(&moved), &provider, &changed).unwrap();
	assert_ne!(first["evidence_id"], third["evidence_id"]);
}

#[test]
fn producer_validates_schema_before_publishing_an_identity() {
	let (target, provider, observation) = valid_input();
	for (field, invalid) in [
		("confidence", json!("certain")),
		("authority", json!("unverified")),
		("parameters", json!([])),
		("locations", json!([{"kind":"file-offset","offset":-1}])),
		("evidenceLinks", json!(["ev_invalid"])),
		("limitations", json!([false])),
	] {
		let mut candidate = observation.clone();
		candidate[field] = invalid;
		assert!(
			create_record(Some(&target), &provider, &candidate).is_err(),
			"{field}"
		);
	}
	let mut nul = target.clone();
	nul["path"] = json!("/fixtures/probe\0.elf");
	assert!(create_record(Some(&nul), &provider, &observation).is_err());
	let mut git_only = target;
	git_only["format"] = json!("uf2");
	assert!(create_record(Some(&git_only), &provider, &observation).is_err());
}
