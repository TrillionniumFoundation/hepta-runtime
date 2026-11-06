// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use super::*;

#[test]
fn complete_session_and_summaries_match_frozen_npm() {
	let fixture: Value = serde_json::from_str(include_str!(
		"../../tests/fixtures/rea_evidence_session.json"
	))
	.unwrap();
	for case in fixture["cases"].as_array().unwrap() {
		let session = EvidenceSession::default();
		for record in case["records"].as_array().unwrap() {
			session.record(record.clone()).unwrap();
		}
		let wire = session.get_bundle(case["input"].clone());
		let text = &wire.content[0].as_text().unwrap().text;
		let result: Value = serde_json::from_str(text).unwrap();
		assert_eq!(result, case["expected"], "{}", case["name"]);
		if result.get("error").is_some() {
			assert_eq!(wire.is_error, Some(true));
			assert!(wire.structured_content.is_none());
		} else {
			assert_eq!(wire.structured_content, Some(result));
			assert!(wire.is_error.is_none());
		}
		assert_eq!(
			wire.meta.unwrap()["provenance"],
			json!({"untrusted_content":true,"source":"analysis_target"})
		);
	}
}

#[test]
fn tampered_record_is_never_published_and_sessions_are_independent() {
	let fixtures: Value = serde_json::from_str(include_str!(
		"../../tests/fixtures/rea_evidence_creation.json"
	))
	.unwrap();
	let record = fixtures["cases"][0]["expected"].clone();
	let first = EvidenceSession::default();
	let second = EvidenceSession::default();
	let mut changed = record.clone();
	changed["normalized_result"] = json!({"forged":true});
	assert!(first.record(changed).is_err());
	assert_eq!(first.state.lock().unwrap().records.len(), 0);
	first.record(record).unwrap();
	assert_eq!(first.state.lock().unwrap().records.len(), 1);
	assert_eq!(second.state.lock().unwrap().records.len(), 0);
}

#[test]
fn export_snapshot_matches_frozen_complete_bundles_without_a_newline() {
	let fixture: Value = serde_json::from_str(include_str!(
		"../../tests/fixtures/rea_evidence_session.json"
	))
	.unwrap();
	for case in fixture["cases"].as_array().unwrap() {
		let Some(expected) = case["expected"].get("result") else {
			continue;
		};
		if expected.get("kind").is_some() {
			continue;
		}
		let session = EvidenceSession::default();
		for record in case["records"].as_array().unwrap() {
			session.record(record.clone()).unwrap();
		}
		let snapshot = session.snapshot().unwrap();
		let mut actual = Vec::new();
		snapshot.write_canonical(&mut actual).unwrap();
		let mut canonical = String::new();
		// The older recursive reference is retained only in tests. This compares
		// every byte against the independently produced frozen bundle fixture.
		rea_evidence::canonical(expected, &mut canonical, 0).unwrap();
		assert_eq!(actual, canonical.as_bytes(), "{}", case["name"]);
		assert_eq!(
			snapshot.record_count(),
			expected["records"].as_array().unwrap().len()
		);
		assert_eq!(snapshot.unknown_count(), 0);
		assert_eq!(actual.last(), Some(&b'}'));
	}
}

#[test]
fn snapshot_is_immutable_and_shares_its_authenticated_payloads() {
	let fixtures: Value = serde_json::from_str(include_str!(
		"../../tests/fixtures/rea_evidence_creation.json"
	))
	.unwrap();
	let first = fixtures["cases"][0]["expected"].clone();
	let second = fixtures["cases"]
		.as_array()
		.unwrap()
		.iter()
		.map(|case| &case["expected"])
		.find(|record| record["evidence_id"] != first["evidence_id"])
		.unwrap()
		.clone();
	let session = EvidenceSession::default();
	let retained = session.record(first.clone()).unwrap();
	let snapshot = session.snapshot().unwrap();
	let id = first["evidence_id"].as_str().unwrap();
	assert!(Arc::ptr_eq(&retained.evidence, &snapshot.records[id]));
	assert!(Arc::ptr_eq(
		&retained.evidence,
		&session.lookup(id).unwrap().unwrap()
	));
	session.record(second).unwrap();
	assert_eq!(session.snapshot().unwrap().record_count(), 2);
	assert_eq!(snapshot.record_count(), 1);
	let mut bytes = Vec::new();
	snapshot.write_canonical(&mut bytes).unwrap();
	let decoded: Value = serde_json::from_slice(&bytes).unwrap();
	assert_eq!(decoded["records"], json!([first]));
	assert!(session
		.lookup(&format!("ev_{}", "f".repeat(64)))
		.unwrap()
		.is_none());
}

#[test]
fn snapshot_writer_failure_is_not_reported_as_complete() {
	struct RefusingWriter {
		bytes: usize,
	}
	impl std::io::Write for RefusingWriter {
		fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
			if self.bytes >= 25 {
				return Err(std::io::Error::other("deliberate destination failure"));
			}
			let count = bytes.len().min(25 - self.bytes);
			self.bytes += count;
			Ok(count)
		}
		fn flush(&mut self) -> std::io::Result<()> {
			Ok(())
		}
	}
	let snapshot = EvidenceSession::default().snapshot().unwrap();
	let mut output = RefusingWriter { bytes: 0 };
	let error = snapshot.write_canonical(&mut output).unwrap_err();
	assert!(error.to_string().contains("deliberate destination failure"));
	assert_eq!(output.bytes, 25);
}

#[test]
fn actual_frozen_node_export_bytes_match_the_native_snapshot_producer() {
	let record: Value = serde_json::from_str(include_str!(
		"../../tests/fixtures/rea_export_reference_record.json"
	))
	.unwrap();
	let expected = include_bytes!("../../tests/fixtures/rea_export_reference_complete.json");
	let session = EvidenceSession::default();
	session.record(record).unwrap();
	let snapshot = session.snapshot().unwrap();
	let mut actual = Vec::new();
	snapshot.write_canonical(&mut actual).unwrap();
	assert_eq!(actual.len(), 309_466);
	assert_eq!(actual, expected);
	assert_eq!(snapshot.record_count(), 1);
	assert_eq!(
		super::super::rea_source_map::sha256(&actual),
		"7e2114adf2d6f2d11e106cfa3c744230627dadd63e42a690c6995e8953cf5627"
	);
}

// Append to src/mcp/rea_evidence_session_tests.rs; keep the existing six tests.
// The payload is the unchanged frozen service record. No field, digest, or
// semantic ID is rewritten to manufacture a second record. Creation provenance
// is deliberately separate from JSON, as the actual two-entry-point oracle proves.

fn session_origin_object_keys_at(text: &str, path: &[&str]) -> Vec<String> {
	struct At<'a>(&'a [&'a str]);
	impl<'de> serde::de::DeserializeSeed<'de> for At<'_> {
		type Value = Vec<String>;
		fn deserialize<D: serde::Deserializer<'de>>(
			self,
			deserializer: D,
		) -> Result<Self::Value, D::Error> {
			deserializer.deserialize_any(self)
		}
	}
	impl<'de> serde::de::Visitor<'de> for At<'_> {
		type Value = Vec<String>;
		fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
			formatter.write_str("an object at the selected JSON path")
		}
		fn visit_map<A: serde::de::MapAccess<'de>>(
			self,
			mut map: A,
		) -> Result<Self::Value, A::Error> {
			if let Some((selected, remaining)) = self.0.split_first() {
				let mut found = None;
				while let Some(key) = map.next_key::<String>()? {
					if key == *selected {
						if found.is_some() {
							return Err(serde::de::Error::custom("duplicate selected member"));
						}
						found = Some(map.next_value_seed(At(remaining))?);
					} else {
						map.next_value::<serde::de::IgnoredAny>()?;
					}
				}
				found.ok_or_else(|| serde::de::Error::custom("selected member is missing"))
			} else {
				let mut keys = Vec::new();
				while let Some(key) = map.next_key::<String>()? {
					keys.push(key);
					map.next_value::<serde::de::IgnoredAny>()?;
				}
				Ok(keys)
			}
		}
		fn visit_seq<A: serde::de::SeqAccess<'de>>(
			self,
			mut sequence: A,
		) -> Result<Self::Value, A::Error> {
			let (selected, remaining) = self
				.0
				.split_first()
				.ok_or_else(|| serde::de::Error::custom("selected target is an array"))?;
			let selected = selected
				.parse::<usize>()
				.map_err(serde::de::Error::custom)?;
			for _ in 0..selected {
				if sequence.next_element::<serde::de::IgnoredAny>()?.is_none() {
					return Err(serde::de::Error::custom("selected array member is missing"));
				}
			}
			let keys = sequence
				.next_element_seed(At(remaining))?
				.ok_or_else(|| serde::de::Error::custom("selected array member is missing"))?;
			while sequence.next_element::<serde::de::IgnoredAny>()?.is_some() {}
			Ok(keys)
		}
	}
	let mut deserializer = serde_json::Deserializer::from_str(text);
	let keys = serde::de::DeserializeSeed::deserialize(At(path), &mut deserializer).unwrap();
	deserializer.end().unwrap();
	keys
}

#[test]
fn same_id_current_delivery_and_first_retention_keep_separate_creation_orders() {
	use super::super::rea_response_order::RecordOrigin;
	let fixture: Value = serde_json::from_str(include_str!(
		"../../tests/fixtures/rea_apk_signature/service-reference-r1.json"
	))
	.unwrap();
	let source = &fixture["cases"]
		.as_array()
		.unwrap()
		.iter()
		.find(|case| case["name"] == "rotation-signers-default")
		.unwrap()["expected"];
	assert_eq!(source["operation"], "inspect_analysis_view");
	assert_eq!(
		source["normalized_result"]["parent_operation"],
		"inspect_apk_signature"
	);
	assert_eq!(source["parameters"]["view"]["collection"], "signers");
	assert_eq!(source["parameters"]["view"].as_object().unwrap().len(), 4);
	rea_evidence::verify_record(source).unwrap();
	let id = source["evidence_id"].as_str().unwrap();
	let expected_keys = |origin| match origin {
		RecordOrigin::ApkToolDerived => ["kind", "offset", "limit", "collection"],
		RecordOrigin::AnalysisViewToolDerived => ["offset", "limit", "collection", "kind"],
		_ => panic!("This fixture has exactly the two verified derived creation origins"),
	};
	let check_current = |retained: &RetainedRecord, origin| {
		assert_eq!(retained.origin, origin);
		assert_eq!(retained.evidence.as_ref(), source);
		let operation = match origin {
			RecordOrigin::ApkToolDerived => "inspect_apk_signature",
			RecordOrigin::AnalysisViewToolDerived => "inspect_analysis_view",
			_ => unreachable!(),
		};
		let wire = rea_contract::success_borrowed(
			operation,
			retained.evidence.as_ref(),
			Some(retained.reference.clone()),
			retained.origin,
		);
		assert!(wire.is_error.is_none());
		assert_eq!(wire.structured_content.as_ref(), Some(source));
		let text = &wire.content[0].as_text().unwrap().text;
		assert_eq!(serde_json::from_str::<Value>(text).unwrap(), *source);
		assert_eq!(
			session_origin_object_keys_at(text, &["parameters", "view"]),
			expected_keys(origin)
		);
	};
	for (first_origin, current_origin) in [
		(
			RecordOrigin::ApkToolDerived,
			RecordOrigin::AnalysisViewToolDerived,
		),
		(
			RecordOrigin::AnalysisViewToolDerived,
			RecordOrigin::ApkToolDerived,
		),
	] {
		let session = EvidenceSession::default();
		let first = session
			.record_with_origin(source.clone(), first_origin)
			.unwrap();
		check_current(&first, first_origin);
		let current = session
			.record_with_origin(source.clone(), current_origin)
			.unwrap();
		assert_eq!(
			first.evidence["evidence_id"],
			current.evidence["evidence_id"]
		);
		assert!(!Arc::ptr_eq(&first.evidence, &current.evidence));
		check_current(&current, current_origin);
		{
			let state = session.state.lock().unwrap();
			let records = &state.records;
			assert_eq!(records.len(), 1);
			assert_eq!(records[id].origin, first_origin);
			assert!(Arc::ptr_eq(&records[id].evidence, &first.evidence));
			assert!(!Arc::ptr_eq(&records[id].evidence, &current.evidence));
		}
		assert!(Arc::ptr_eq(
			&session.lookup(id).unwrap().unwrap(),
			&first.evidence
		));
		let snapshot = session.snapshot().unwrap();
		assert!(Arc::ptr_eq(&snapshot.records[id], &first.evidence));
		let bundle = session.get_bundle(json!({}));
		assert!(bundle.is_error.is_none());
		let text = &bundle.content[0].as_text().unwrap().text;
		let parsed: Value = serde_json::from_str(text).unwrap();
		assert_eq!(parsed["result"]["records"], json!([source]));
		assert_eq!(bundle.structured_content, Some(parsed));
		assert_eq!(
			session_origin_object_keys_at(text, &["result", "records", "0", "parameters", "view"]),
			expected_keys(first_origin)
		);
	}
}
