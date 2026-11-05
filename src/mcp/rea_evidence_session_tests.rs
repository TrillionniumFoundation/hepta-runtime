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
	assert_eq!(first.records.lock().unwrap().len(), 0);
	first.record(record).unwrap();
	assert_eq!(first.records.lock().unwrap().len(), 1);
	assert_eq!(second.records.lock().unwrap().len(), 0);
}
