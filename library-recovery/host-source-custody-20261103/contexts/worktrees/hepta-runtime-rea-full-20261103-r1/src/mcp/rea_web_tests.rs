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

//! Saved-observation provenance, duplicate occurrence, bounded replay and
//! root-confinement regression tests using authored offline HAR fixtures.

use super::*;
use serde_json::json;

fn entry(url: &str, status: u16, body: Option<&str>) -> Value {
	let mut content = json!({"mimeType": "application/json", "size": 0});
	if let Some(text) = body {
		content["text"] = json!(text);
		content["size"] = json!(text.len());
	}
	json!({
		"startedDateTime": "2026-11-03T00:00:00Z",
		"request": {
			"method": "GET",
			"url": url,
			"headers": [{"name": "Authorization", "value": "fixture-secret"}],
			"cookies": [],
			"queryString": []
		},
		"response": {
			"status": status,
			"statusText": "recorded",
			"headers": [{"name": "Content-Type", "value": "application/json"}],
			"content": content
		}
	})
}

fn bytes(entries: Vec<Value>) -> Vec<u8> {
	serde_json::to_vec(&json!({
		"log": {
			"version": "1.2",
			"creator": {"name": "authored-test", "version": "1"},
			"entries": entries
		}
	}))
	.expect("fixture JSON")
}

fn capture(entries: Vec<Value>) -> parser::Capture {
	parser::parse_capture(&bytes(entries), None).expect("saved capture")
}

fn inspect_params() -> InspectWebCaptureParams {
	InspectWebCaptureParams {
		path: "/unused/fixture.har".into(),
		expected_sha256: None,
		offset: 0,
		limit: 64,
		method: None,
		url: None,
		status: None,
	}
}

fn replay_params(capture: &parser::Capture, entry_index: usize) -> ReplayWebEntryParams {
	ReplayWebEntryParams {
		source: WebCaptureSource {
			path: "/unused/fixture.har".into(),
			sha256: capture.sha256.clone(),
		},
		entry_index,
		body_offset: 0,
		body_length: 4096,
	}
}

#[test]
fn inventory_preserves_original_indices_and_omits_implicit_headers_and_bodies() {
	let capture = capture(vec![
		entry("https://owned.test/a", 200, Some("fixture-private-body")),
		entry("https://owned.test/b", 404, None),
		entry("https://owned.test/c", 200, Some("")),
	]);
	let mut params = inspect_params();
	params.status = Some(200);
	params.limit = 1;
	let first = parser::inspect(&capture, &params).expect("first filtered page");
	assert_eq!(first["matched_count"], 2);
	assert_eq!(first["entries"][0]["entry_index"], 0);
	assert_eq!(first["next_offset"], 1);
	let rendered = serde_json::to_string(&first).expect("render");
	assert!(!rendered.contains("fixture-secret"));
	assert!(!rendered.contains("fixture-private-body"));
	params.offset = 1;
	let second = parser::inspect(&capture, &params).expect("second filtered page");
	assert_eq!(second["entries"][0]["entry_index"], 2);
	assert_eq!(second["entries"][0]["body_recorded"], true);
	assert_eq!(second["entries"][0]["recorded_text_bytes"], 0);
	assert!(second["next_offset"].is_null());
}

#[test]
fn strict_container_and_duplicate_member_failures_do_not_become_empty_captures() {
	for source in [
		br#"{"log":{"version":"1.2","entries":[],"entries":[]}}"#.as_slice(),
		br#"{"log":{"version":"1.1","entries":[]}}"#.as_slice(),
		br#"{"log":{"version":"1.2"}}"#.as_slice(),
		br#"{"log":{"version":"1.2","entries":[{"request":{"method":"GET","method":"POST"}}]}}"#
			.as_slice(),
	] {
		assert!(parser::parse_capture(source, None).is_err());
	}
	let empty = capture(Vec::new());
	assert_eq!(empty.entries.len(), 0);
}

#[test]
fn invalid_selected_fields_and_resource_limits_are_refused() {
	let mut bad_method = entry("https://owned.test/a", 200, None);
	bad_method["request"]["method"] = json!("GET\nPOST");
	let mut bad_status = entry("https://owned.test/a", 200, None);
	bad_status["response"]["status"] = json!(600);
	let mut bad_body = entry("https://owned.test/a", 200, None);
	bad_body["response"]["content"]["text"] = json!({"not": "text"});
	let mut bad_size = entry("https://owned.test/a", 200, None);
	bad_size["response"]["content"]["size"] = json!(-1);
	for value in [bad_method, bad_status, bad_body, bad_size] {
		assert!(parser::parse_capture(&bytes(vec![value]), None).is_err());
	}
	assert!(parser::parse_capture(&vec![b' '; MAX_FILE_BYTES as usize + 1], None).is_err());
	let crowded = bytes(vec![
		entry("https://owned.test/a", 200, None);
		parser::MAX_ENTRIES + 1
	]);
	assert!(parser::parse_capture(&crowded, None).is_err());
}

#[test]
fn repeated_requests_are_paired_by_occurrence_without_collapsing_state() {
	let before = capture(vec![
		entry("https://owned.test/a", 200, Some("first")),
		entry("https://owned.test/a", 200, Some("second")),
	]);
	let after = capture(vec![
		entry("https://owned.test/a", 200, Some("first")),
		entry("https://owned.test/a", 201, Some("changed-second")),
	]);
	let report = parser::compare(&before, &after, 0, 64).expect("compare");
	assert_eq!(report["counts"]["unchanged"], 1);
	assert_eq!(report["counts"]["changed"], 1);
	assert_eq!(report["differences"][0]["request_occurrence"], 1);
	assert_eq!(report["differences"][0]["before"]["entry_index"], 1);
	assert_eq!(report["differences"][0]["after"]["entry_index"], 1);
	assert!(!report.to_string().contains("changed-second"));
}

#[test]
fn request_headers_participate_in_identity_and_are_not_implicitly_equated() {
	let before = capture(vec![entry("https://owned.test/a", 200, Some("same"))]);
	let mut different_request = entry("https://owned.test/a", 200, Some("same"));
	different_request["request"]["headers"][0]["value"] = json!("other-fixture-identity");
	let after = capture(vec![different_request]);
	let report = parser::compare(&before, &after, 0, 1).expect("compare page");
	assert_eq!(report["counts"]["added"], 1);
	assert_eq!(report["counts"]["removed"], 1);
	assert_eq!(report["counts"]["changed"], 0);
	assert_eq!(report["difference_count"], 2);
	assert_eq!(report["next_offset"], 1);
	assert!(parser::compare(&before, &after, 3, 1).is_err());
}

#[test]
fn replay_returns_exact_recorded_utf8_ranges_without_network_or_inferred_state() {
	let capture = capture(vec![entry("https://owned.test/a", 200, Some("A中Z"))]);
	let mut params = replay_params(&capture, 0);
	params.body_offset = 2;
	params.body_length = 2;
	let report = parser::replay(&capture, &params).expect("partial UTF-8 bytes");
	assert_eq!(report["body"]["bytes_hex"], "b8ad");
	assert_eq!(report["body"]["representation_byte_length"], 5);
	assert_eq!(report["body"]["next_offset"], 4);
	assert_eq!(report["network_requests"], 0);
	assert_eq!(report["javascript_executed"], false);
	assert_eq!(report["application_state_inferred"], false);
	assert!(report["response_metadata"]["content"].get("text").is_none());
	params.body_offset = 6;
	assert!(parser::replay(&capture, &params).is_err());
}

#[test]
fn absent_empty_and_encoded_bodies_have_distinct_observation_meanings() {
	let mut encoded = entry("https://owned.test/a", 200, Some("YWJj"));
	encoded["response"]["content"]["encoding"] = json!("base64");
	let capture = capture(vec![
		entry("https://owned.test/a", 200, None),
		entry("https://owned.test/b", 200, Some("")),
		encoded,
	]);
	let absent = parser::replay(&capture, &replay_params(&capture, 0)).expect("absent");
	let empty = parser::replay(&capture, &replay_params(&capture, 1)).expect("empty");
	let encoded = parser::replay(&capture, &replay_params(&capture, 2)).expect("encoded");
	assert_eq!(absent["body"]["recorded"], false);
	assert_eq!(empty["body"]["recorded"], true);
	assert_eq!(empty["body"]["representation_byte_length"], 0);
	assert_eq!(encoded["body"]["bytes_hex"], "59574a6a");
	assert_eq!(encoded["body"]["har_encoding"], "base64");
	assert_eq!(encoded["body"]["decoded_payload_verified"], false);
}

#[test]
fn public_validation_requires_full_identity_for_continuation_and_selected_replay() {
	let mut params = inspect_params();
	params.offset = 1;
	assert!(validate_inspect(&params).is_err());
	params.expected_sha256 = Some("a".repeat(64));
	assert!(validate_inspect(&params).is_ok());
	params.expected_sha256 = Some("A".repeat(64));
	assert!(validate_inspect(&params).is_err());
	let capture = capture(Vec::new());
	let mut replay = replay_params(&capture, 0);
	replay.body_length = 65_537;
	assert!(validate_replay(&replay).is_err());
}

#[test]
fn response_serialization_enforces_complete_result_budget() {
	assert!(encode(json!({"unbounded": "x".repeat(MAX_RESPONSE_BYTES)})).is_err());
}

#[tokio::test]
#[cfg(unix)]
async fn confined_reads_and_stale_source_identity_are_checked_on_real_files() {
	let workspace = tempfile::tempdir().expect("workspace");
	let outside = tempfile::tempdir().expect("outside");
	let roots = [workspace.path().to_path_buf()];
	let path = workspace.path().join("capture.har");
	let original = bytes(vec![entry("https://owned.test/a", 200, Some("first"))]);
	tokio::fs::write(&path, &original)
		.await
		.expect("write original");
	let mut params = inspect_params();
	params.path = path.to_string_lossy().into_owned();
	let first: Value = serde_json::from_str(
		&inspect_with_roots(params.clone(), &roots)
			.await
			.expect("confined inspection"),
	)
	.expect("report");
	let digest = first["source"]["sha256"].as_str().expect("source digest");
	let selected = ReplayWebEntryParams {
		source: WebCaptureSource {
			path: params.path.clone(),
			sha256: digest.into(),
		},
		entry_index: 0,
		body_offset: 0,
		body_length: 4096,
	};
	let replay: Value = serde_json::from_str(
		&replay_with_roots(selected.clone(), &roots)
			.await
			.expect("selected replay"),
	)
	.expect("replay report");
	assert_eq!(replay["body"]["bytes_hex"], "6669727374");
	tokio::fs::write(
		&path,
		bytes(vec![entry("https://owned.test/a", 200, Some("changed"))]),
	)
	.await
	.expect("replace content");
	assert!(replay_with_roots(selected, &roots).await.is_err());
	let external = outside.path().join("capture.har");
	tokio::fs::write(&external, original)
		.await
		.expect("outside");
	let link = workspace.path().join("linked.har");
	tokio::fs::symlink(&external, &link).await.expect("symlink");
	for rejected in [external, link] {
		params.path = rejected.to_string_lossy().into_owned();
		assert!(inspect_with_roots(params.clone(), &roots).await.is_err());
	}
}

#[tokio::test]
#[cfg(unix)]
async fn file_comparison_requires_both_original_capture_hashes() {
	let workspace = tempfile::tempdir().expect("workspace");
	let roots = [workspace.path().to_path_buf()];
	let old_path = workspace.path().join("old.har");
	let new_path = workspace.path().join("new.har");
	let old = bytes(vec![entry("https://owned.test/a", 200, None)]);
	let new = bytes(vec![entry("https://owned.test/a", 404, None)]);
	tokio::fs::write(&old_path, &old).await.expect("old");
	tokio::fs::write(&new_path, &new).await.expect("new");
	let mut params = CompareWebCapturesParams {
		before: WebCaptureSource {
			path: old_path.to_string_lossy().into_owned(),
			sha256: parser::digest(&old),
		},
		after: WebCaptureSource {
			path: new_path.to_string_lossy().into_owned(),
			sha256: parser::digest(&new),
		},
		offset: 0,
		limit: 64,
	};
	let report: Value = serde_json::from_str(
		&compare_with_roots(params.clone(), &roots)
			.await
			.expect("compare files"),
	)
	.expect("report");
	assert_eq!(report["counts"]["changed"], 1);
	params.after.sha256 = "0".repeat(64);
	assert!(compare_with_roots(params, &roots).await.is_err());
}
