// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Native linear math, exact source identity and explicit scope/budget refusals.

use super::*;

fn encoded(dtype: &str, shape: &[usize], payload: &[u8]) -> Vec<u8> {
	let mut header = serde_json::to_vec(
		&json!({"weight":{"dtype":dtype,"shape":shape,"data_offsets":[0,payload.len()]}}),
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

fn fixture() -> Vec<u8> {
	let payload: Vec<u8> = [1_f32, -3., 0., 4.]
		.into_iter()
		.flat_map(f32::to_le_bytes)
		.collect();
	encoded("F32", &[2, 2], &payload)
}

fn params(path: &Path, bytes: &[u8]) -> ForwardLinearParams {
	ForwardLinearParams {
		source: LinearSource::Path {
			path: path.to_string_lossy().into_owned(),
			expected_sha256: hex(&Sha256::digest(bytes)),
			tensor_name: "weight".into(),
		},
		inputs: vec![vec![-2., 1.], vec![0.5, 2.], vec![3., -1.]],
		bias: None,
	}
}

#[tokio::test]
async fn real_safetensors_linear_reads_exact_pinned_bytes_and_optional_bias() {
	let temp = tempfile::tempdir().unwrap();
	let path = temp.path().join("linear.safetensors");
	let bytes = fixture();
	tokio::fs::write(&path, &bytes).await.unwrap();
	let mut request = params(&path, &bytes);
	let result = forward_with_roots(
		request.clone(),
		&[temp.path().to_owned()],
		&temp.path().join("state"),
	)
	.await
	.unwrap();
	assert_eq!(result["outputs"], json!([[-5., 4.], [-5.5, 8.], [6., -4.]]));
	assert_eq!(result["multiply_adds"], 12);
	assert_eq!(result["source_sha256"], hex(&Sha256::digest(&bytes)));
	assert_eq!(result["weight_shape"], json!([2, 2]));
	assert_eq!(result["implementation"], "rust_sequential_f32_linear");
	assert_eq!(result["training"], false);
	request.bias = Some(vec![0.25, -0.5]);
	let biased = forward_with_roots(
		request,
		&[temp.path().to_owned()],
		&temp.path().join("state"),
	)
	.await
	.unwrap();
	assert_eq!(
		biased["outputs"],
		json!([[-4.75, 3.5], [-5.25, 7.5], [6.25, -4.5]])
	);
	assert_ne!(biased["input_sha256"], result["input_sha256"]);
	assert_eq!(tokio::fs::read(&path).await.unwrap(), bytes);
}

#[tokio::test]
async fn changed_full_hash_outside_root_symlink_and_large_file_are_refused() {
	let temp = tempfile::tempdir().unwrap();
	let other = tempfile::tempdir().unwrap();
	let path = temp.path().join("linear.safetensors");
	let bytes = fixture();
	tokio::fs::write(&path, &bytes).await.unwrap();
	let request = params(&path, &bytes);
	assert!(forward_with_roots(
		request.clone(),
		&[other.path().to_owned()],
		&temp.path().join("state")
	)
	.await
	.is_err());
	let mut changed = bytes.clone();
	let last = changed.len() - 1;
	changed[last] ^= 1;
	tokio::fs::write(&path, &changed).await.unwrap();
	let error = forward_with_roots(
		request,
		&[temp.path().to_owned()],
		&temp.path().join("state"),
	)
	.await
	.unwrap_err();
	assert!(error.to_string().contains("complete source SHA-256"));
	let alias = temp.path().join("alias");
	tokio::fs::symlink(&path, &alias).await.unwrap();
	assert!(forward_with_roots(
		params(&alias, &changed),
		&[temp.path().to_owned()],
		&temp.path().join("state")
	)
	.await
	.is_err());
	let large = temp.path().join("large.safetensors");
	let file = tokio::fs::File::create(&large).await.unwrap();
	file.set_len(MAX_FILE_BYTES + 1).await.unwrap();
	let error = forward_with_roots(
		params(&large, &[]),
		&[temp.path().to_owned()],
		&temp.path().join("state"),
	)
	.await
	.unwrap_err();
	assert!(error.to_string().contains("2 GiB"));
}

#[tokio::test]
async fn tensor_scope_and_non_finite_weights_are_rejected() {
	let temp = tempfile::tempdir().unwrap();
	let path = temp.path().join("linear.safetensors");
	for bytes in [
		encoded("F16", &[1, 1], &0x3c00_u16.to_le_bytes()),
		encoded("BF16", &[1, 1], &0x3f80_u16.to_le_bytes()),
		encoded("F32", &[4], &[0; 16]),
		encoded("F32", &[1, 1], &f32::NAN.to_le_bytes()),
	] {
		tokio::fs::write(&path, &bytes).await.unwrap();
		let mut request = params(&path, &bytes);
		request.inputs = vec![vec![1.]];
		assert!(forward_with_roots(
			request,
			&[temp.path().to_owned()],
			&temp.path().join("state")
		)
		.await
		.is_err());
	}
}

#[tokio::test]
async fn source_kind_cannot_reopen_an_arbitrary_state_path() {
	let temp = tempfile::tempdir().unwrap();
	let state = temp.path().join("state");
	tokio::fs::create_dir(&state).await.unwrap();
	let path = state.join("linear.safetensors");
	let bytes = fixture();
	tokio::fs::write(&path, &bytes).await.unwrap();
	let request = params(&path, &bytes);
	assert!(
		forward_with_roots(request, &[temp.path().to_owned()], &state)
			.await
			.unwrap_err()
			.to_string()
			.contains("artifact ID")
	);
	let request = ForwardLinearParams {
		source: LinearSource::Artifact {
			artifact_id: "../linear.safetensors".into(),
			tensor_name: "weight".into(),
		},
		inputs: vec![vec![1., 2.]],
		bias: None,
	};
	assert!(
		forward_with_roots(request, &[temp.path().to_owned()], &state)
			.await
			.is_err()
	);
}

#[test]
fn shape_request_and_arithmetic_budgets_are_explicit() {
	let deadline = Instant::now() + Duration::from_secs(1);
	assert!(calculate(&[1.], &[vec![f32::NAN]], None, 1, 1, deadline).is_err());
	assert!(calculate(&[1.], &[vec![1.]], Some(&[f32::INFINITY]), 1, 1, deadline).is_err());
	assert!(calculate(&[f32::MAX], &[vec![2.]], None, 1, 1, deadline).is_err());
	assert!(calculate(&[1.], &[vec![]], None, 1, 1, deadline).is_err());
	assert!(calculate(
		&[1.],
		&[vec![1.]],
		None,
		1,
		1,
		Instant::now() - Duration::from_secs(1)
	)
	.is_err());
	assert!(check_inputs(&vec![vec![1.]; 65], None, 1, 1).is_err());
	assert!(check_inputs(&vec![vec![1.; 1024]; 17], None, 1024, 1024).is_err());
	assert!(check_inputs(&vec![vec![1.]; 5], None, 4096, 1).is_err());
	assert!(check_inputs(&[vec![1.; 257]], None, 4096, 257).is_err());
	let report = json!({"format":"safetensors","source":{"size_bytes":100},"result":{"tensor":{"name":"weight","dtype":"F32","storage_length_verified":true,"shape":["2","2"],"file_offset":84,"byte_length":16}}});
	assert_eq!(matrix_extent(&report, "weight").unwrap(), (2, 2, 84, 16));
	let mut bad_extent = report.clone();
	bad_extent["result"]["tensor"]["byte_length"] = json!(12);
	assert!(matrix_extent(&bad_extent, "weight").is_err());
	let mut oversized_shape = report;
	oversized_shape["result"]["tensor"]["shape"] = json!(["4096", "257"]);
	assert!(matrix_extent(&oversized_shape, "weight").is_err());
	assert!(serde_json::from_value::<ForwardLinearParams>(json!({"source":{"kind":"artifact","artifact_id":"wa1_x","tensor_name":"weight","path":"/unapproved"},"inputs":[[1]],"bias":null})).is_err());
}

#[tokio::test]
async fn hash_and_tensor_capture_share_one_stream_across_buffer_boundaries() {
	let temp = tempfile::tempdir().unwrap();
	let path = temp.path().join("capture.bin");
	let bytes: Vec<u8> = (0..1024 * 1024 + 64)
		.map(|index| (index % 251) as u8)
		.collect();
	tokio::fs::write(&path, &bytes).await.unwrap();
	let mut file = tokio::fs::File::open(&path).await.unwrap();
	let offset = 1024 * 1024 - 32;
	let (actual, tensor) = capture(&mut file, bytes.len() as u64, offset as u64, 96)
		.await
		.unwrap();
	assert_eq!(actual, hex(&Sha256::digest(&bytes)));
	assert_eq!(tensor, bytes[offset..offset + 96]);
	assert!(
		capture(&mut file, bytes.len() as u64 + 1, offset as u64, 96)
			.await
			.is_err()
	);
}
