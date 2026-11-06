// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0

//! Regressions for authenticated source ownership and retained view recovery.

use super::*;

fn complete_parent() -> Value {
	let corpus: Value = serde_json::from_str(include_str!(
		"../../tests/fixtures/rea_apk_signature/service-reference-r1.json"
	))
	.unwrap();
	corpus["cases"]
		.as_array()
		.unwrap()
		.iter()
		.find(|case| case["name"] == "rotation-complete")
		.unwrap()["expected"]
		.clone()
}

async fn permit() -> Arc<runtime::effect_owner_fence::AdmissionPermit> {
	Arc::new(
		runtime::effect_owner_fence::admit_new_effect()
			.await
			.unwrap(),
	)
}

fn decoded(result: CallToolResult) -> Value {
	serde_json::to_value(result).unwrap()
}

#[tokio::test]
async fn cancellation_before_projection_preserves_the_parent_and_session_reuse() {
	let session = Arc::new(EvidenceSession::default());
	let parent = session
		.record_with_origin(complete_parent(), RecordOrigin::NativeTool)
		.unwrap();
	let arguments = json!({"source":parent.reference,"view":{"kind":"summary"}});
	let stop = CancellationToken::new();
	stop.cancel();
	let cancelled = decoded(
		inspect(
			arguments.clone(),
			None,
			Vec::new(),
			Arc::clone(&session),
			stop,
			permit().await,
		)
		.await,
	);
	assert_eq!(cancelled["isError"], true);
	let failure: Value =
		serde_json::from_str(cancelled["content"][0]["text"].as_str().unwrap()).unwrap();
	assert_eq!(failure["error"]["code"], "cancelled");
	assert_eq!(session.snapshot().unwrap().record_count(), 1);
	let resumed = decoded(
		inspect(
			arguments,
			None,
			Vec::new(),
			Arc::clone(&session),
			CancellationToken::new(),
			permit().await,
		)
		.await,
	);
	assert_ne!(resumed["isError"], true);
	assert_eq!(
		resumed["structuredContent"]["normalized_result"]["parent_evidence_id"],
		parent.evidence["evidence_id"]
	);
	assert_eq!(session.snapshot().unwrap().record_count(), 2);
	assert!(retained_source(
		&EvidenceSession::default(),
		parent.evidence["evidence_id"].as_str().unwrap()
	)
	.is_err());
}

#[tokio::test]
async fn inline_numbers_authenticate_before_projection_and_do_not_import_parent() {
	let mut parent = complete_parent();
	let id = parent["evidence_id"].clone();
	let bytes = parent["normalized_result"]["artifact"]["bytes"]
		.as_u64()
		.unwrap();
	parent["normalized_result"]["artifact"]["bytes"] = json!(bytes as f64);
	let session = Arc::new(EvidenceSession::default());
	let result = decoded(
		inspect(
			json!({"source":{"kind":"inline","evidence":parent},
		"view":{"kind":"apk-signature","collection":"signers","limit":1}}),
			None,
			Vec::new(),
			Arc::clone(&session),
			CancellationToken::new(),
			permit().await,
		)
		.await,
	);
	assert_ne!(result["isError"], true, "{result}");
	let view = &result["structuredContent"];
	assert_eq!(view["normalized_result"]["parent_evidence_id"], id);
	assert_eq!(
		view["normalized_result"]["items"].as_array().unwrap().len(),
		1
	);
	super::super::rea_evidence::verify_record(view).unwrap();
	assert_eq!(session.snapshot().unwrap().record_count(), 1);
	assert!(session.lookup(id.as_str().unwrap()).unwrap().is_none());
}

#[tokio::test]
async fn tampered_inline_record_is_not_published() {
	let mut parent = complete_parent();
	parent["normalized_result"]["artifact"]["bytes"] = json!(1);
	let session = Arc::new(EvidenceSession::default());
	let result = decoded(
		inspect(
			json!({"source":{"kind":"inline","evidence":parent},"view":{"kind":"summary"}}),
			None,
			Vec::new(),
			Arc::clone(&session),
			CancellationToken::new(),
			permit().await,
		)
		.await,
	);
	assert_eq!(result["isError"], true);
	assert_eq!(session.snapshot().unwrap().record_count(), 0);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn exported_file_source_authenticates_and_retains_only_the_derived_view() {
	let directory = tempfile::tempdir().unwrap();
	let path = directory.path().join("complete.json");
	let parent = complete_parent();
	tokio::fs::write(&path, serde_json::to_vec(&parent).unwrap())
		.await
		.unwrap();
	let session = Arc::new(EvidenceSession::default());
	let result = decoded(
		inspect(
			json!({"source":{"kind":"evidence-file","path":path},
		"view":{"kind":"apk-signature","collection":"signers","limit":1}}),
			None,
			vec![directory.path().to_owned()],
			Arc::clone(&session),
			CancellationToken::new(),
			permit().await,
		)
		.await,
	);
	assert_ne!(result["isError"], true, "{result}");
	assert_eq!(
		result["structuredContent"]["normalized_result"]["parent_evidence_id"],
		parent["evidence_id"]
	);
	assert_eq!(session.snapshot().unwrap().record_count(), 1);
	assert!(session
		.lookup(parent["evidence_id"].as_str().unwrap())
		.unwrap()
		.is_none());
}

#[test]
fn a_summary_receipt_cannot_replace_its_complete_parent() {
	let summary = project_completed(&complete_parent(), &json!({"kind":"summary"})).unwrap();
	assert_eq!(
		project_completed(&summary, &json!({"kind":"summary"}))
			.unwrap_err()
			.0["code"],
		"unsupported_target"
	);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn file_root_string_proof_preserves_the_existing_analysis_view_schema_refusal() {
	// Native integration consistency: real Node/REA fixture observations cover
	// import. This test does not claim a newly captured original analysis view.
	let directory = tempfile::tempdir().unwrap();
	let path = directory.path().join("root-string.json");
	let session = Arc::new(EvidenceSession::default());
	let mut ordinary = None;
	for bytes in [br#""plain""#.as_slice(), br#""\uD800""#.as_slice()] {
		std::fs::write(&path, bytes).unwrap();
		let result = inspect(
			json!({"source":{"kind":"evidence-file","path":path}, "view":{"kind":"summary"}}),
			None,
			vec![directory.path().to_owned()],
			Arc::clone(&session),
			CancellationToken::new(),
			permit().await,
		)
		.await;
		assert_eq!(result.is_error, Some(true));
		let text = result.content[0].as_text().unwrap().text.clone();
		let value: Value = serde_json::from_str(&text).unwrap();
		assert_eq!(value["error"]["details"]["reason"], "wrong-kind");
		assert_eq!(
			value["error"]["details"]["content_issues"],
			json!([{"path":[],"reason":"invalid_type","expected":"object"}])
		);
		if let Some(expected) = ordinary.as_ref() {
			assert_eq!(&text, expected);
		} else {
			ordinary = Some(text);
		}
		assert_eq!(session.snapshot().unwrap().record_count(), 0);
		assert_eq!(session.snapshot().unwrap().unknown_count(), 0);
	}
}
