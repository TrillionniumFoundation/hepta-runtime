// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0

//! Public import outcomes preserve schema failures and publish only authenticated bundles.

use super::*;

async fn permit() -> Arc<runtime::effect_owner_fence::AdmissionPermit> {
	Arc::new(
		runtime::effect_owner_fence::admit_new_effect()
			.await
			.unwrap(),
	)
}

fn payload(result: &CallToolResult) -> Value {
	serde_json::from_str(&result.content[0].as_text().unwrap().text).unwrap()
}

#[test]
fn original_public_import_error_text_matches_without_reparsing() {
	let fixture: Value = serde_json::from_str(include_str!(
		"../../tests/fixtures/rea_evidence_import_errors.json"
	))
	.unwrap();
	let cases = fixture["cases"].as_array().unwrap();
	assert_eq!(cases.len(), 38);
	for case in cases {
		let text = case["original_text"].as_str().unwrap();
		let original: Value = serde_json::from_str(text).unwrap();
		let result = error_result(Failure(original["error"].clone()));
		// This is the encoder boundary, before the real SDK applies negotiated
		// legacy resultType normalization. The public MCP differential compares
		// the entire actually transmitted CallToolResult without that shortcut.
		assert!(result
			.result_type
			.as_ref()
			.is_some_and(|kind| kind.is_complete()));
		assert_eq!(result.is_error, Some(true));
		assert!(result.structured_content.is_none());
		assert_eq!(
			serde_json::to_value(&result.meta).unwrap(),
			case["original_result"]["_meta"]
		);
		assert_eq!(
			serde_json::to_value(&result.content).unwrap(),
			case["original_result"]["content"],
			"{}",
			case["id"]
		);
	}
}

#[test]
fn native_extension_errors_keep_complete_diagnostics_without_guessed_order() {
	let failure = profile_gap("unpaired UTF-16 surrogate", json!({"offset":7}));
	let original = serde_json::to_value(failure.clone().wire()).unwrap();
	assert_eq!(
		serde_json::to_value(error_result(failure)).unwrap(),
		original
	);
	let failure = Failure::schema_exception("Cannot convert object to primitive value");
	let original = serde_json::to_value(failure.clone().wire()).unwrap();
	assert_eq!(
		serde_json::to_value(error_result(failure)).unwrap(),
		original
	);
}

#[test]
fn unrecognized_import_error_detail_does_not_publish_a_partial_text_prefix() {
	let mut failure = Failure::integrity("retained primary failure");
	failure.0["details"]["native_diagnostic"] = json!({"z":1,"a":2});
	let original = serde_json::to_value(failure.clone().wire()).unwrap();
	assert_eq!(
		serde_json::to_value(error_result(failure)).unwrap(),
		original
	);
}

async fn call(
	path: &std::path::Path,
	root: &std::path::Path,
	session: &Arc<EvidenceSession>,
	stop: CancellationToken,
) -> CallToolResult {
	import(
		json!({"path":path}),
		vec![root.to_owned()],
		Arc::clone(session),
		stop,
		permit().await,
	)
	.await
}

#[test]
fn import_schemas_and_argument_projection_keep_the_frozen_contract() {
	assert_eq!(input_schema()["required"], json!(["path"]));
	assert_eq!(input_schema()["additionalProperties"], false);
	assert_eq!(output_schema()["$id"], "urn:rea:tool-output:sha256:2530df2b57608db6e80da29b2a0731f1c240c7aaa6ee7fe3c85352b6c63495ec");
	let keys = vec!["path".to_owned(), "z".to_owned(), "a".to_owned()];
	let error = super::super::rea_mcp_input::import_ordered(
		&json!({"path":"relative","a":1,"z":2}),
		Some(&keys),
	)
	.unwrap_err();
	assert_eq!(
		error.0["details"]["issues"][0]["message"],
		"path: must be an absolute local filesystem path, Unrecognized keys: \"z\", \"a\""
	);
	assert_eq!(
		error_result(error).meta.unwrap()["provenance"]["source"],
		"analysis_target"
	);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn public_import_is_idempotent_replaces_metadata_and_keeps_cold_sessions_empty() {
	let dir = tempfile::tempdir().unwrap();
	let path = dir.path().join("bundle.json");
	let original: Value = serde_json::from_str(include_str!(
		"../../tests/fixtures/rea_export_reference_complete.json"
	))
	.unwrap();
	std::fs::write(&path, serde_json::to_vec(&original).unwrap()).unwrap();
	let session = Arc::new(EvidenceSession::default());
	let first = call(&path, dir.path(), &session, CancellationToken::new()).await;
	let count = original["records"].as_array().unwrap().len();
	assert_eq!(
		payload(&first),
		json!({"result":{"imported":count,"unknowns_added":0,"total":count}})
	);
	assert_eq!(
		first.meta.unwrap()["provenance"]["source"],
		"analysis_target"
	);
	let repeated = call(&path, dir.path(), &session, CancellationToken::new()).await;
	assert_eq!(
		payload(&repeated),
		json!({"result":{"imported":0,"unknowns_added":0,"total":count}})
	);
	let mut changed = original.clone();
	for record in changed["records"].as_array_mut().unwrap() {
		if !record["subject"].is_null() {
			record["subject"]["name"] = json!("changed display name");
			record["subject"]["local_path"] = json!("/moved/display-only");
		}
		record["caller_input_path"] = json!("/selected/caller-alias");
	}
	std::fs::write(&path, serde_json::to_vec(&changed).unwrap()).unwrap();
	let replaced = call(&path, dir.path(), &session, CancellationToken::new()).await;
	assert_eq!(
		payload(&replaced),
		json!({"result":{"imported":0,"unknowns_added":0,"total":count}})
	);
	let bundle = session.get_bundle(json!({}));
	assert_eq!(payload(&bundle), json!({"result":changed}));
	let mut exported = Vec::new();
	session
		.snapshot()
		.unwrap()
		.write_canonical(&mut exported)
		.unwrap();
	assert_eq!(serde_json::from_slice::<Value>(&exported).unwrap(), changed);
	let cold = EvidenceSession::default();
	assert_eq!(cold.snapshot().unwrap().record_count(), 0);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn invalid_candidate_and_precancelled_import_leave_existing_records_unchanged() {
	let dir = tempfile::tempdir().unwrap();
	let path = dir.path().join("bundle.json");
	let original: Value = serde_json::from_str(include_str!(
		"../../tests/fixtures/rea_export_reference_complete.json"
	))
	.unwrap();
	std::fs::write(&path, serde_json::to_vec(&original).unwrap()).unwrap();
	let session = Arc::new(EvidenceSession::default());
	assert!(call(&path, dir.path(), &session, CancellationToken::new())
		.await
		.is_error
		.is_none());
	let before = payload(&session.get_bundle(json!({})));
	let stop = CancellationToken::new();
	stop.cancel();
	let cancelled = call(&path, dir.path(), &session, stop).await;
	assert_eq!(payload(&cancelled)["error"]["code"], "cancelled");
	let mut broken = original.clone();
	broken["records"][0]["normalized_result"] = json!({"tampered":true});
	std::fs::write(&path, serde_json::to_vec(&broken).unwrap()).unwrap();
	assert_eq!(
		payload(&call(&path, dir.path(), &session, CancellationToken::new()).await)["error"]
			["code"],
		"evidence_integrity_mismatch"
	);
	assert_eq!(payload(&session.get_bundle(json!({}))), before);
	std::fs::write(&path, serde_json::to_vec(&original).unwrap()).unwrap();
	assert_eq!(
		payload(&call(&path, dir.path(), &session, CancellationToken::new()).await)["result"]
			["imported"],
		0
	);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn standalone_record_has_import_wrong_kind_and_is_not_implicitly_retained() {
	let dir = tempfile::tempdir().unwrap();
	let path = dir.path().join("record.json");
	std::fs::write(
		&path,
		include_bytes!("../../tests/fixtures/rea_export_reference_record.json"),
	)
	.unwrap();
	let session = Arc::new(EvidenceSession::default());
	let result = call(&path, dir.path(), &session, CancellationToken::new()).await;
	let failure = payload(&result);
	assert_eq!(failure["error"]["code"], "invalid_request");
	assert_eq!(
		failure["error"]["details"],
		json!({"operation":"read","reason":"wrong-kind","path":path})
	);
	assert!(failure["error"]["message"]
		.as_str()
		.unwrap()
		.starts_with("Expected an Evidence bundle with records and manifest arrays"));
	assert_eq!(session.snapshot().unwrap().record_count(), 0);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn original_length_coercion_exception_stays_plain_text_and_publishes_nothing() {
	let dir = tempfile::tempdir().unwrap();
	let path = dir.path().join("exception.json");
	let mut bundle: Value = serde_json::from_str(include_str!(
		"../../tests/fixtures/rea_export_reference_complete.json"
	))
	.unwrap();
	bundle["records"][0]["operation"] = json!({"length":{"toString":null}});
	std::fs::write(&path, serde_json::to_vec(&bundle).unwrap()).unwrap();
	let session = Arc::new(EvidenceSession::default());
	let result = call(&path, dir.path(), &session, CancellationToken::new()).await;
	assert_eq!(result.is_error, Some(true));
	assert_eq!(
		result.content[0].as_text().unwrap().text,
		"Cannot convert object to primitive value"
	);
	assert!(result.structured_content.is_none());
	assert_eq!(
		result.meta.unwrap()["provenance"]["source"],
		"analysis_target"
	);
	assert_eq!(session.snapshot().unwrap().record_count(), 0);
	let failure = super::super::rea_mcp_input::import_ordered(
		&json!({"path":{"length":{"toString":null}}}),
		None,
	)
	.unwrap_err();
	assert_eq!(failure.0, "Cannot convert object to primitive value");
	// The original schema throws before reaching unknown-key validation.
	// Later missing order metadata must not turn that exception into a gap.
	let mut record = bundle["records"][0].clone();
	record["z"] = json!(1);
	record["a"] = json!(2);
	assert!(matches!(
		rea_evidence_source::authenticate_inline(record),
		Err(SourceError::SchemaException { .. })
	));
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn standalone_record_fallback_does_not_swallow_unexpected_schema_exceptions() {
	let dir = tempfile::tempdir().unwrap();
	let path = dir.path().join("bare-exception.json");
	let mut record: Value = serde_json::from_str(include_str!(
		"../../tests/fixtures/rea_export_reference_record.json"
	))
	.unwrap();
	record["operation"] = json!({"length":{"toString":null}});
	std::fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
	let session = Arc::new(EvidenceSession::default());
	let result = call(&path, dir.path(), &session, CancellationToken::new()).await;
	assert_eq!(result.is_error, Some(true));
	assert_eq!(
		result.content[0].as_text().unwrap().text,
		"Cannot convert object to primitive value"
	);
	assert!(result.structured_content.is_none());
	assert_eq!(
		result.meta.unwrap()["provenance"]["source"],
		"analysis_target"
	);
	let snapshot = session.snapshot().unwrap();
	assert_eq!(snapshot.record_count(), 0);
	assert_eq!(snapshot.unknown_count(), 0);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn original_non_eof_and_root_string_failures_keep_complete_errors_and_session_contents() {
	let fixture: Value = serde_json::from_str(include_str!(
		"../../tests/fixtures/rea_evidence_file/syntax-reference-r1.json"
	))
	.unwrap();
	let dir = tempfile::tempdir().unwrap();
	let path = dir.path().join("invalid.json");
	let session = Arc::new(EvidenceSession::default());
	let before = payload(&session.get_bundle(json!({})));
	let cases = fixture["public_cases"].as_array().unwrap();
	assert_eq!(cases.len(), 15);
	for case in cases {
		let hex = case["input_hex"].as_str().unwrap();
		let bytes: Vec<u8> = (0..hex.len())
			.step_by(2)
			.map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
			.collect();
		tokio::fs::write(&path, &bytes).await.unwrap();
		let result = call(&path, dir.path(), &session, CancellationToken::new()).await;
		let mut expected = case["error"].clone();
		if let Some(error_path) = expected["details"].get_mut("path") {
			*error_path = json!(path);
		}
		assert_eq!(
			payload(&result),
			json!({"error": expected}),
			"{}",
			case["id"]
		);
		assert_eq!(result.is_error, Some(true));
		assert_eq!(
			payload(&session.get_bundle(json!({}))),
			before,
			"{}",
			case["id"]
		);
	}
	// Different valid root strings must reach the identical object-schema
	// refusal. Their content is neither replaced nor retained as Evidence.
	let expected = cases.last().unwrap()["error"].clone();
	for input in [r#""plain""#, r#""\uDC00""#, " \n\"\\uD800x\" \r\n"] {
		tokio::fs::write(&path, input).await.unwrap();
		let result = call(&path, dir.path(), &session, CancellationToken::new()).await;
		assert_eq!(payload(&result), json!({"error": expected}), "{input:?}");
		assert_eq!(payload(&session.get_bundle(json!({}))), before);
	}
}
