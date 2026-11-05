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

fn empty_zip() -> Vec<u8> {
	let mut bytes = vec![0_u8; 22];
	bytes[..4].copy_from_slice(b"PK\x05\x06");
	bytes
}

#[test]
fn fallback_acquisition_error_matches_frozen_provider_projection() {
	let fixture: Value = serde_json::from_str(include_str!(
		"../../tests/fixtures/rea_common_error_reference.json"
	))
	.unwrap();
	let expected = fixture["cases"]
		.as_array()
		.unwrap()
		.iter()
		.find(|case| case["name"] == "apk-provider-adapter")
		.unwrap();
	let failure = acquisition_failure(
		std::io::Error::from_raw_os_error(libc::EIO).into(),
		"/private/selected.apk",
	);
	assert_eq!(failure.0, expected["expected"]);
	assert!(!failure.0.to_string().contains("/private/selected.apk"));
}

#[test]
fn complete_and_projected_evidence_match_real_frozen_service_from_artifact_bytes() {
	let fixture: Value = serde_json::from_str(include_str!(
		"../../tests/fixtures/rea_apk_signature/service-reference-r1.json"
	))
	.unwrap();
	assert_eq!(fixture["cases"].as_array().unwrap().len(), 16);
	for case in fixture["cases"].as_array().unwrap() {
		let bytes: &[u8] = match case["fixture"].as_str().unwrap() {
			"rotation-v31.apk" => {
				include_bytes!("../../tests/fixtures/rea_apk_signature/rotation-v31.apk")
			}
			"v1-v2-v3.apk" => include_bytes!("../../tests/fixtures/rea_apk_signature/v1-v2-v3.apk"),
			other => panic!("Unknown independently captured APK fixture: {other}"),
		};
		let digest = super::super::rea_source_map::sha256(bytes);
		assert_eq!(
			fixture["fixture_sources"][case["fixture"].as_str().unwrap()]["sha256"],
			digest
		);
		let raw: Value = serde_json::from_str(case["input_json"].as_str().unwrap()).unwrap();
		let input = Input::parse(&raw).unwrap();
		let inspected = rea_apk_signature::bind_static_path(
			rea_apk_signature::inspect_static(bytes).unwrap(),
			&input.path,
		)
		.unwrap();
		let reply = json!({"report":inspected.result,"limitations":inspected.limitations});
		let parent = complete_record(
			reply.as_object().unwrap().clone(),
			&input,
			&digest,
			bytes.len() as u64,
		)
		.unwrap();
		let result = if input.complete {
			parent
		} else {
			project_record(&parent, &input.view).unwrap()
		};
		assert_eq!(result, case["expected"], "{}", case["name"]);
	}
}

#[test]
fn completed_report_is_bound_before_evidence_can_be_retained() {
	let bytes = empty_zip();
	let digest = super::super::rea_source_map::sha256(&bytes);
	let input = Input::parse(&json!({"path":"/selected/probe.apk","detail":"complete"})).unwrap();
	let inspected = rea_apk_signature::bind_static_path(
		rea_apk_signature::inspect_static(&bytes).unwrap(),
		&input.path,
	)
	.unwrap();
	let reply = json!({"report":inspected.result,"limitations":inspected.limitations});
	let record = complete_record(
		reply.as_object().unwrap().clone(),
		&input,
		&digest,
		bytes.len() as u64,
	)
	.unwrap();
	rea_evidence::verify_record(&record).unwrap();
	assert_eq!(record["subject"]["format"], "apk");
	assert_eq!(record["parameters"], json!({"path":input.path}));
	assert_eq!(record["normalized_result"]["artifact"]["sha256"], digest);
	for altered in [
		{
			let mut value = reply.clone();
			value["report"]["artifact"]["path"] = json!("/other.apk");
			value
		},
		{
			let mut value = reply.clone();
			value["report"]["artifact"]["sha256"] = json!("f".repeat(64));
			value
		},
		{
			let mut value = reply.clone();
			value["report"]["artifact"]["bytes"] = json!(23);
			value
		},
		{
			let mut value = reply.clone();
			value["limitations"] = json!([null]);
			value
		},
		{
			let mut value = reply.clone();
			value["untrusted_extra"] = json!(true);
			value
		},
	] {
		assert!(complete_record(
			altered.as_object().unwrap().clone(),
			&input,
			&digest,
			bytes.len() as u64
		)
		.is_err());
	}
}

#[tokio::test]
async fn summary_retains_complete_parent_and_derived_view_in_one_session() {
	let directory = tempfile::tempdir().unwrap();
	let path = directory.path().join("probe.apk");
	tokio::fs::write(&path, empty_zip()).await.unwrap();
	let input = Input::parse(&json!({"path":path})).unwrap();
	let session = Arc::new(EvidenceSession::default());
	let owner = Arc::new(
		runtime::effect_owner_fence::admit_new_effect()
			.await
			.unwrap(),
	);
	let result = execute(
		input,
		&[directory.path().to_path_buf()],
		Arc::clone(&session),
		CancellationToken::new(),
		owner,
	)
	.await
	.unwrap();
	assert_eq!(result.evidence["operation"], "inspect_analysis_view");
	assert_eq!(result.evidence["normalized_result"]["kind"], "summary");
	let parent_id = result.evidence["parameters"]["parent_evidence_id"]
		.as_str()
		.unwrap();
	let parent = session.lookup(parent_id).unwrap().unwrap();
	assert_eq!(parent["operation"], OP);
	assert_eq!(parent["normalized_result"]["artifact"]["path"], json!(path));
	assert_eq!(session.snapshot().unwrap().record_count(), 2);
	rea_evidence::verify_record(&parent).unwrap();
	rea_evidence::verify_record(&result.evidence).unwrap();
	assert_eq!(result.evidence["evidence_links"], json!([parent_id]));
}

#[tokio::test]
async fn rejected_bytes_and_cancelled_capture_do_not_publish_records() {
	let directory = tempfile::tempdir().unwrap();
	let path = directory.path().join("broken.apk");
	tokio::fs::write(&path, b"this is not an archive")
		.await
		.unwrap();
	let input = Input::parse(&json!({"path":path,"detail":"complete"})).unwrap();
	let session = Arc::new(EvidenceSession::default());
	let owner = Arc::new(
		runtime::effect_owner_fence::admit_new_effect()
			.await
			.unwrap(),
	);
	let result = execute(
		input,
		&[directory.path().to_path_buf()],
		Arc::clone(&session),
		CancellationToken::new(),
		owner,
	)
	.await;
	let failure = match result {
		Ok(_) => panic!("malformed archive was retained"),
		Err(error) => error,
	};
	assert_eq!(failure.0["code"], "unsupported_target");
	assert_eq!(session.snapshot().unwrap().record_count(), 0);
	let cancelled = CancellationToken::new();
	cancelled.cancel();
	let missing = directory.path().join("never-opened.apk");
	let error = capture(
		missing.to_str().unwrap(),
		&[directory.path().to_path_buf()],
		&cancelled,
	)
	.await
	.unwrap_err();
	assert_eq!(error.0["code"], "cancelled");
}

#[cfg(unix)]
#[tokio::test]
async fn capture_rejects_symlinks_and_keeps_exact_caller_path() {
	let directory = tempfile::tempdir().unwrap();
	let path = directory.path().join("probe.apk");
	let link = directory.path().join("link.apk");
	tokio::fs::write(&path, empty_zip()).await.unwrap();
	std::os::unix::fs::symlink(&path, &link).unwrap();
	let failure = capture(
		link.to_str().unwrap(),
		&[directory.path().to_path_buf()],
		&CancellationToken::new(),
	)
	.await
	.unwrap_err();
	assert_eq!(failure.0["code"], "invalid_request");
	assert_eq!(
		failure.0["details"]["issues"][0]["reason"],
		"invalid_format"
	);
	let display = format!("{}/./probe.apk", directory.path().display());
	let (bytes, digest) = capture(
		&display,
		&[directory.path().to_path_buf()],
		&CancellationToken::new(),
	)
	.await
	.unwrap();
	assert_eq!(bytes, empty_zip());
	assert_eq!(digest, super::super::rea_source_map::sha256(&bytes));
}
