// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Owner-level cohort failure, recovery, budget and optimizer contract checks.

use super::*;

fn key(value: u8) -> String { format!("{value:02x}").repeat(32) }

fn encoded() -> Vec<u8> {
	let mut header = serde_json::to_vec(&json!({
		"weight":{"dtype":"F32","shape":[1,2],"data_offsets":[0,8]},
		"bias":{"dtype":"F32","shape":[1],"data_offsets":[8,12]}
	})).unwrap();
	while !header.len().is_multiple_of(8) { header.push(b' '); }
	let mut bytes = (header.len() as u64).to_le_bytes().to_vec();
	bytes.extend(header);
	for value in [1_f32, -3., 2.] { bytes.extend(value.to_le_bytes()); }
	bytes
}

fn member(name: &str, before: f32, after: f32) -> Member {
	Member { tensor_name: name.into(), edits: vec![ExactElementEdit {
		index: 0, expected_hex: hex(&before.to_le_bytes()), replacement_hex: hex(&after.to_le_bytes()),
	}], maximum_update_l2_norm: 1. }
}

fn parameters(path: &Path, bytes: &[u8]) -> PatchParams {
	PatchParams { request_id: key(1), path: path.to_string_lossy().into_owned(), expected_sha256: digest(bytes),
		identity: Identity { code_sha256: key(2), tensor_map_sha256: key(3), data_manifest_sha256: key(4), objective_sha256: key(5), dependency_manifest_sha256: key(6) },
		members: vec![member("weight",1.,2.),member("bias",2.,3.)], maximum_update_l2_norm: 1.5,
		training: TrainingContract::StatelessFresh { algorithm: StatelessAlgorithm::ProjectedGradientDescent, trainer_code_sha256: key(7), training_protocol_sha256: key(8) },
	}
}

async fn fixture() -> (tempfile::TempDir, PatchParams) {
	let temp = tempfile::tempdir().unwrap();
	let path = temp.path().join("base.safetensors");
	let bytes = encoded();
	tokio::fs::write(&path, &bytes).await.unwrap();
	let params = parameters(&path, &bytes);
	(temp, params)
}

async fn apply(temp: &tempfile::TempDir, params: PatchParams, point: Boundary) -> Result<Value> {
	apply_with_roots(params, &[temp.path().to_owned()], &temp.path().join("state"), None, None, point).await
}

async fn published_count(temp: &tempfile::TempDir) -> usize {
	let root = temp.path().join("state/weight-artifacts-v1");
	let Ok(mut files) = tokio::fs::read_dir(root).await else { return 0; };
	let mut count = 0;
	while let Some(entry) = files.next_entry().await.unwrap() {
		if valid_id(&entry.file_name().to_string_lossy()) { count += 1; }
	}
	count
}

#[tokio::test]
async fn whole_cohort_roundtrip_and_original_forward_owner_readback() {
	let (temp, params) = fixture().await;
	let result = apply(&temp, params.clone(), Boundary::None).await.unwrap();
	assert_eq!(result["members"], 2);
	assert_eq!(result["global_budget"]["elements_checked"], 2);
	assert_eq!(result["all_members_verified"], true);
	assert_eq!(result["production_eligible"], false);
	assert_eq!(result["incumbent_pointer_modified"], false);
	assert_eq!(result["optimizer_state_migrated"], false);
	assert_eq!(tokio::fs::read(&params.path).await.unwrap(), encoded());
	let id = result["artifact_id"].as_str().unwrap();
	let state = temp.path().join("state");
	let (mut pinned, meta, sha) = super::super::open_pinned_artifact(id, &state).await.unwrap();
	assert_eq!(file_hash(&mut pinned, meta.len()).await.unwrap(), sha);
	assert_eq!(sha, result["sha256"]);
	let repeated = apply(&temp, params, Boundary::None).await.unwrap();
	assert_eq!(result["artifact_id"], repeated["artifact_id"]);
	assert_eq!(repeated["reused"], true);
	let restored = restore_with_state(RestoreCohortParams {request_id:key(11), artifact_id:id.into()}, &state).await.unwrap();
	assert_eq!(tokio::fs::read(restored["artifact_path"].as_str().unwrap()).await.unwrap(), encoded());
	assert_eq!(restored["training_contract"]["policy"], "inference_only");
	assert!(restore_with_state(RestoreCohortParams {request_id:key(12),artifact_id:restored["artifact_id"].as_str().unwrap().into()}, &state).await.is_err());
	assert_eq!(published_count(&temp).await, 2);
}

#[tokio::test]
async fn one_global_budget_rejects_individually_valid_members() {
	let (temp, mut params) = fixture().await;
	params.maximum_update_l2_norm = 1.4;
	assert!(apply(&temp, params, Boundary::None).await.unwrap_err().to_string().contains("global"));
	assert_eq!(published_count(&temp).await, 0);
}

#[tokio::test]
async fn member_budget_and_one_wrong_expected_byte_reject_the_whole_group() {
	let (temp, mut params) = fixture().await;
	params.members[1].maximum_update_l2_norm = 0.5;
	assert!(apply(&temp, params.clone(), Boundary::None).await.is_err());
	params.members[1].maximum_update_l2_norm = 1.;
	params.members[1].edits[0].expected_hex = hex(&4_f32.to_le_bytes());
	params.members[1].edits[0].replacement_hex = hex(&5_f32.to_le_bytes());
	assert!(apply(&temp, params, Boundary::None).await.is_err());
	assert_eq!(published_count(&temp).await, 0);
}

#[tokio::test]
async fn original_total_cap_and_unique_tensor_rule_cannot_be_sharded_away() {
	let (temp, mut params) = fixture().await;
	params.members.push(params.members[0].clone());
	assert!(apply(&temp, params.clone(), Boundary::None).await.unwrap_err().to_string().contains("sharding"));
	params.members.pop();
	params.members[0].edits = (0..1024).map(|index| ExactElementEdit { index, expected_hex: "00000000".into(), replacement_hex:"00000000".into() }).collect();
	assert!(apply(&temp, params, Boundary::None).await.unwrap_err().to_string().contains("1024"));
	assert_eq!(published_count(&temp).await, 0);
}

#[tokio::test]
async fn continuation_policy_must_be_explicit_and_stateful_reuse_is_unrepresentable() {
	let (temp, params) = fixture().await;
	let mut missing = serde_json::to_value(&params).unwrap();
	missing.as_object_mut().unwrap().remove("training");
	assert!(serde_json::from_value::<PatchParams>(missing).is_err());
	for invalid in [json!({"policy":"preserve"}),json!({"policy":"stateless_fresh","algorithm":"projected_gradient_descent","trainer_code_sha256":key(7),"training_protocol_sha256":key(8),"old_optimizer_checkpoint":"momentum.pt"})] {
		let mut value = serde_json::to_value(&params).unwrap();
		value["training"] = invalid;
		assert!(serde_json::from_value::<PatchParams>(value).is_err());
	}
	let mut inference = params;
	inference.training = TrainingContract::InferenceOnly;
	let result = apply(&temp, inference, Boundary::None).await.unwrap();
	assert_eq!(result["training_contract"]["policy"], "inference_only");
	assert_eq!(result["training_owner_verification_required"], true);
}

#[tokio::test]
async fn every_durable_boundary_recovers_by_reading_the_original_owner() {
	for point in [Boundary::Intent, Boundary::Staged, Boundary::Published, Boundary::Completed] {
		let (temp, params) = fixture().await;
		assert!(apply(&temp, params.clone(), point).await.is_err());
		let should_exist = matches!(point, Boundary::Published | Boundary::Completed);
		assert_eq!(published_count(&temp).await, usize::from(should_exist));
		let resumed = apply(&temp, params.clone(), Boundary::None).await.unwrap();
		assert_eq!(resumed["reused"], should_exist);
		assert_eq!(resumed["recovered_publication"], point == Boundary::Published);
		assert_eq!(published_count(&temp).await, 1);
		assert_eq!(tokio::fs::read(&params.path).await.unwrap(), encoded());
		let root = temp.path().join("state/weight-artifacts-v1");
		let mut entries = tokio::fs::read_dir(root).await.unwrap();
		while let Some(entry) = entries.next_entry().await.unwrap() { assert!(!entry.file_name().to_string_lossy().starts_with(".pending-")); }
	}
}

#[tokio::test]
async fn changed_source_or_changed_request_cannot_resume_an_admitted_intent() {
	let (temp, params) = fixture().await;
	assert!(apply(&temp, params.clone(), Boundary::Intent).await.is_err());
	let mut changed = params.clone();
	changed.identity.objective_sha256 = key(88);
	assert!(apply(&temp, changed, Boundary::None).await.unwrap_err().to_string().contains("conflicts"));
	let mut bytes = encoded();
	let last = bytes.len()-1;
	bytes[last] ^= 1;
	tokio::fs::write(&params.path, bytes).await.unwrap();
	assert!(apply(&temp, params, Boundary::None).await.is_err());
	assert_eq!(published_count(&temp).await, 0);
}

#[tokio::test]
async fn missing_or_corrupted_published_outputs_are_never_silently_recreated() {
	for remove in [false, true] {
		let (temp, params) = fixture().await;
		let result = apply(&temp, params.clone(), Boundary::None).await.unwrap();
		let path = Path::new(result["artifact_path"].as_str().unwrap());
		if remove { tokio::fs::remove_dir_all(path.parent().unwrap()).await.unwrap(); }
		else { tokio::fs::write(path, b"corrupted").await.unwrap(); }
		assert!(apply(&temp, params, Boundary::None).await.is_err());
		if remove { assert!(!path.exists()); }
		else { assert_eq!(tokio::fs::read(path).await.unwrap(), b"corrupted"); }
	}
}

#[tokio::test]
async fn interrupted_stage_symlink_is_rejected_without_touching_target() {
	let (temp, params) = fixture().await;
	assert!(apply(&temp, params.clone(), Boundary::Staged).await.is_err());
	let root = temp.path().join("state/weight-artifacts-v1");
	let mut entries = tokio::fs::read_dir(&root).await.unwrap();
	let stage = entries.next_entry().await.unwrap().unwrap().path();
	let model = stage.join("model.safetensors");
	tokio::fs::remove_file(&model).await.unwrap();
	let outside = temp.path().join("unrelated");
	tokio::fs::write(&outside, b"keep").await.unwrap();
	std::os::unix::fs::symlink(&outside, &model).unwrap();
	assert!(apply(&temp, params, Boundary::None).await.is_err());
	assert_eq!(tokio::fs::read(outside).await.unwrap(), b"keep");
	assert_eq!(published_count(&temp).await, 0);
}

#[tokio::test]
async fn simultaneous_identical_requests_publish_once_under_the_original_lock() {
	let (temp, params) = fixture().await;
	let (left,right) = tokio::join!(apply(&temp, params.clone(), Boundary::None), apply(&temp, params, Boundary::None));
	let left=left.unwrap(); let right=right.unwrap();
	assert_eq!(left["artifact_id"], right["artifact_id"]);
	assert_ne!(left["reused"], right["reused"]);
	assert_eq!(published_count(&temp).await, 1);
}

#[tokio::test]
async fn original_single_tensor_api_and_cohorts_share_one_store_without_lookup_confusion() {
	let (temp, params) = fixture().await;
	let cohort = apply(&temp, params.clone(), Boundary::None).await.unwrap();
	let old = PatchTensorParams {path:params.path, expected_sha256:params.expected_sha256, tensor_name:"weight".into(), edits:params.members[0].edits.clone()};
	let state=temp.path().join("state");
	let single=super::super::apply_with_roots(old.clone(), &[temp.path().to_owned()], &state,None,None).await.unwrap();
	let retry=super::super::apply_with_roots(old, &[temp.path().to_owned()], &state,None,None).await.unwrap();
	assert_eq!(single["artifact_id"],retry["artifact_id"]);
	assert_eq!(retry["reused"],true);
	assert_ne!(single["sha256"],cohort["sha256"]);
}

#[test]
fn all_supported_half_values_are_exactly_represented_and_nonfinite_rejected() {
	assert_eq!(represented_value("F16","0100").unwrap(),2_f32.powi(-24));
	assert_eq!(represented_value("F16","ff7b").unwrap(),65504.);
	assert_eq!(represented_value("F16","003c").unwrap(),1.);
	assert_eq!(represented_value("BF16","803f").unwrap(),1.);
	assert_eq!(represented_value("F16","0080").unwrap().to_bits(),(-0_f32).to_bits());
	assert!(represented_value("F16","007c").is_err());
	assert!(represented_value("BF16","807f").is_err());
}
