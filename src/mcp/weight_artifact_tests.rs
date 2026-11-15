// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Real safetensors bytes: exact publication, reverse patch and held-out linear outputs.

use super::*;

fn encoded(dtype: &str, payload: &[u8], elements: usize) -> Vec<u8> {
	let mut header = serde_json::to_vec(
		&json!({"weight":{"dtype":dtype,"shape":[1,elements],"data_offsets":[0,payload.len()]}}),
	)
	.unwrap();
	while !header.len().is_multiple_of(8) {
		header.push(b' ');
	}
	let mut bytes = (header.len() as u64).to_le_bytes().to_vec();
	bytes.extend(header);
	bytes.extend(payload);
	bytes
}

fn parameters(path: &Path, bytes: &[u8], before: &[u8], after: &[u8]) -> PatchTensorParams {
	PatchTensorParams {
		path: path.to_string_lossy().into_owned(),
		expected_sha256: hex(&Sha256::digest(bytes)),
		tensor_name: "weight".into(),
		edits: vec![ExactElementEdit {
			index: 0,
			expected_hex: hex(before),
			replacement_hex: hex(after),
		}],
	}
}

async fn bytes_from(receipt: &Value) -> Vec<u8> {
	tokio::fs::read(receipt["artifact_path"].as_str().unwrap())
		.await
		.unwrap()
}

fn f32_weights(bytes: &[u8]) -> Vec<f32> {
	let header = u64::from_le_bytes(bytes[..8].try_into().unwrap()) as usize;
	bytes[8 + header..]
		.chunks_exact(4)
		.map(|part| f32::from_le_bytes(part.try_into().unwrap()))
		.collect()
}

#[tokio::test]
async fn exact_patch_improves_a_separate_linear_fixture_and_restores_every_parent_byte() {
	let temp = tempfile::tempdir().unwrap();
	let state = temp.path().join("state");
	let path = temp.path().join("parent.safetensors");
	let mut payload = 1_f32.to_le_bytes().to_vec();
	payload.extend((-3_f32).to_le_bytes());
	let original = encoded("F32", &payload, 2);
	tokio::fs::write(&path, &original).await.unwrap();
	let params = parameters(&path, &original, &1_f32.to_le_bytes(), &2_f32.to_le_bytes());
	let patched = apply_with_roots(
		params.clone(),
		&[temp.path().to_owned()],
		&state,
		None,
		None,
	)
	.await
	.unwrap();
	let actual = bytes_from(&patched).await;
	let weights = f32_weights(&actual);
	assert_eq!(weights, vec![2., -3.]);
	// The identified defect is coefficient one on the independent x=[1,0] probe.
	// These held-out inputs and targets are fixed separately from that probe.
	let held_out = [([-2_f32, 1_f32], -7_f32), ([0.5, 2.], -5.), ([3., -1.], 9.)];
	let mse = |w: &[f32]| {
		held_out
			.iter()
			.map(|(x, y)| (w[0] * x[0] + w[1] * x[1] - y).powi(2))
			.sum::<f32>()
			/ held_out.len() as f32
	};
	assert!(mse(&f32_weights(&original)) > 4.0);
	assert_eq!(mse(&weights), 0.);
	assert_eq!(
		weights[1] * 2.,
		-6.,
		"unmodified coefficient behavior remains exact"
	);
	assert_eq!(tokio::fs::read(&path).await.unwrap(), original);
	let retry = apply_with_roots(params, &[temp.path().to_owned()], &state, None, None)
		.await
		.unwrap();
	assert_eq!(retry["artifact_id"], patched["artifact_id"]);
	assert_eq!(retry["reused"], true);
	let restored = restore_with_state(patched["artifact_id"].as_str().unwrap(), &state)
		.await
		.unwrap();
	assert_eq!(bytes_from(&restored).await, original);
	assert_eq!(restored["sha256"], patched["source_sha256"]);
	assert_eq!(patched["production_eligible"], false);
	assert_eq!(
		patched["behavior_evaluated"], false,
		"artifact creation itself makes no quality claim"
	);
	assert!(
		restore_with_state(restored["artifact_id"].as_str().unwrap(), &state)
			.await
			.is_err()
	);
	println!(
		"WEIGHT_NATIVE_LINEAR_QUALIFICATION {}",
		json!({"held_out_mse_before":mse(&f32_weights(&original)),"held_out_mse_after":mse(&weights),"artifact_id":patched["artifact_id"],"parent_sha256":patched["source_sha256"],"restored_sha256":restored["sha256"],"scope":"fixed two-coefficient Rust linear fixture; no general model backend"})
	);
}

#[tokio::test]
async fn no_op_and_f16_bf16_edits_roundtrip_exactly() {
	for (dtype, before, after) in [
		("F16", vec![0, 0x3c], vec![0, 0x40]),
		("BF16", vec![0x80, 0x3f], vec![0, 0x40]),
		("F32", vec![0, 0, 0x80, 0x3f], vec![0, 0, 0, 0x40]),
	] {
		let temp = tempfile::tempdir().unwrap();
		let state = temp.path().join("state");
		let path = temp.path().join("model.safetensors");
		let original = encoded(dtype, &before, 1);
		tokio::fs::write(&path, &original).await.unwrap();
		let noop = apply_with_roots(
			parameters(&path, &original, &before, &before),
			&[temp.path().to_owned()],
			&state,
			None,
			None,
		)
		.await
		.unwrap();
		assert_eq!(noop["exact_no_op"], true);
		assert_eq!(noop["changed_bytes"], 0);
		assert_eq!(bytes_from(&noop).await, original);
		let patched = apply_with_roots(
			parameters(&path, &original, &before, &after),
			&[temp.path().to_owned()],
			&state,
			None,
			None,
		)
		.await
		.unwrap();
		assert!(bytes_from(&patched).await.ends_with(&after));
		let restored = restore_with_state(patched["artifact_id"].as_str().unwrap(), &state)
			.await
			.unwrap();
		assert_eq!(bytes_from(&restored).await, original);
	}
}

#[tokio::test]
async fn bad_source_identity_or_element_never_publishes_a_partial_artifact() {
	let temp = tempfile::tempdir().unwrap();
	let path = temp.path().join("parent.safetensors");
	let state = temp.path().join("state");
	let original = encoded("F32", &1_f32.to_le_bytes(), 1);
	tokio::fs::write(&path, &original).await.unwrap();
	for wrong_hash in [false, true] {
		let mut params = parameters(&path, &original, &1_f32.to_le_bytes(), &2_f32.to_le_bytes());
		if wrong_hash {
			params.expected_sha256 = "0".repeat(64);
		} else {
			params.edits[0].expected_hex = hex(&7_f32.to_le_bytes());
		}
		assert!(
			apply_with_roots(params, &[temp.path().to_owned()], &state, None, None)
				.await
				.is_err()
		);
		let mut entries = tokio::fs::read_dir(store_root(&state).await.unwrap())
			.await
			.unwrap();
		assert!(
			entries.next_entry().await.unwrap().is_none(),
			"failed stage must not become visible"
		);
		assert_eq!(tokio::fs::read(&path).await.unwrap(), original);
	}
	let outside = tempfile::tempdir().unwrap();
	assert!(apply_with_roots(
		parameters(&path, &original, &1_f32.to_le_bytes(), &2_f32.to_le_bytes()),
		&[outside.path().to_owned()],
		&state,
		None,
		None
	)
	.await
	.is_err());
	let alias = temp.path().join("alias");
	tokio::fs::symlink(&path, &alias).await.unwrap();
	assert!(apply_with_roots(
		parameters(
			&alias,
			&original,
			&1_f32.to_le_bytes(),
			&2_f32.to_le_bytes()
		),
		&[temp.path().to_owned()],
		&state,
		None,
		None
	)
	.await
	.is_err());
}

#[tokio::test]
async fn corruption_is_detected_before_restore_and_source_size_is_bounded() {
	let temp = tempfile::tempdir().unwrap();
	let path = temp.path().join("parent.safetensors");
	let state = temp.path().join("state");
	let original = encoded("F32", &1_f32.to_le_bytes(), 1);
	tokio::fs::write(&path, &original).await.unwrap();
	let patched = apply_with_roots(
		parameters(&path, &original, &1_f32.to_le_bytes(), &2_f32.to_le_bytes()),
		&[temp.path().to_owned()],
		&state,
		None,
		None,
	)
	.await
	.unwrap();
	let mut bytes = bytes_from(&patched).await;
	*bytes.last_mut().unwrap() ^= 1;
	tokio::fs::write(patched["artifact_path"].as_str().unwrap(), bytes)
		.await
		.unwrap();
	assert!(
		restore_with_state(patched["artifact_id"].as_str().unwrap(), &state)
			.await
			.is_err()
	);
	assert!(restore_with_state("../escape", &state).await.is_err());
	let oversized = temp.path().join("large.safetensors");
	let file = tokio::fs::File::create(&oversized).await.unwrap();
	file.set_len(MAX_MODEL_BYTES + 1).await.unwrap();
	assert!(apply_with_roots(
		parameters(
			&oversized,
			&original,
			&1_f32.to_le_bytes(),
			&2_f32.to_le_bytes()
		),
		&[temp.path().to_owned()],
		&state,
		None,
		None
	)
	.await
	.is_err());
}
