// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Adversarial source, descriptor, precision, lineage and task boundary tests.

use crate::descriptor::*;
use crate::semantics::*;
use crate::{digest, unique_json, SourcePin};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::Write;

fn pin(bytes: &[u8]) -> SourcePin {
	SourcePin {
		source_id: "synthetic-reviewed-test-only".into(),
		sha256: digest(bytes),
		size_bytes: bytes.len() as u64,
	}
}

fn raw_file(header: &[u8], payload: &[u8]) -> Vec<u8> {
	let mut result = (header.len() as u64).to_le_bytes().to_vec();
	result.extend_from_slice(header);
	result.extend_from_slice(payload);
	result
}

fn file(tensors: &[(&str, &[u64], &str, Vec<u8>)]) -> Vec<u8> {
	let mut header = serde_json::Map::new();
	let mut payload = Vec::new();
	for (name, shape, dtype, bytes) in tensors {
		let start = payload.len();
		payload.extend_from_slice(bytes);
		header.insert(
			(*name).into(),
			json!({"dtype":dtype,"shape":shape,"data_offsets":[start,payload.len()]}),
		);
	}
	raw_file(&serde_json::to_vec(&header).unwrap(), &payload)
}

fn single(shape: &[u64]) -> Vec<u8> {
	let count: usize = shape.iter().map(|x| *x as usize).product();
	file(&[("weight", shape, "F32", vec![0; count * 4])])
}

fn claim(model: &AuthenticatedSafetensors<'_>, name: &str) -> DescriptorClaim {
	let row = model.tensor(name).unwrap();
	DescriptorClaim {
		source_file_sha256: model.receipt().source.sha256.clone(),
		tensor_name: name.into(),
		dtype: row.dtype,
		shape: row.shape.clone(),
		file_offset: row.file_offset,
		byte_length: row.byte_length,
		source_tensor_sha256: row.payload_sha256.clone().unwrap(),
	}
}

#[test]
fn actual_shape_cannot_be_replaced_by_same_element_count() {
	let bytes = single(&[49, 3]);
	let authenticated = authenticate_safetensors(&bytes, &pin(&bytes)).unwrap();
	let mut stated = claim(&authenticated, "weight");
	authenticate_claims(&authenticated, &[stated.clone()]).unwrap();
	stated.shape = vec![147];
	assert!(authenticate_claims(&authenticated, &[stated]).is_err());
}

#[test]
fn descriptor_claim_binds_dtype_offset_length_payload_and_file() {
	let bytes = single(&[49, 3]);
	let authenticated = authenticate_safetensors(&bytes, &pin(&bytes)).unwrap();
	for field in 0..6 {
		let mut stated = claim(&authenticated, "weight");
		match field {
			0 => stated.dtype = Dtype::F16,
			1 => stated.file_offset += 4,
			2 => stated.byte_length -= 4,
			3 => stated.source_tensor_sha256 = "1".repeat(64),
			4 => stated.source_file_sha256 = "2".repeat(64),
			_ => stated.tensor_name = "absent".into(),
		}
		assert!(
			authenticate_claims(&authenticated, &[stated]).is_err(),
			"field {field}"
		);
	}
	let c = claim(&authenticated, "weight");
	assert!(authenticate_claims(&authenticated, &[c.clone(), c]).is_err());
}

#[test]
fn stale_source_pin_detects_payload_and_header_mutation() {
	let bytes = single(&[2, 2]);
	let original = pin(&bytes);
	let mut modified = bytes.clone();
	*modified.last_mut().unwrap() = 1;
	assert!(authenticate_safetensors(&modified, &original).is_err());
	let mut modified = bytes.clone();
	modified[10] ^= 1;
	assert!(authenticate_safetensors(&modified, &original).is_err());
	let mut bad_size = original.clone();
	bad_size.size_bytes += 1;
	assert!(authenticate_safetensors(&bytes, &bad_size).is_err());
}

#[test]
fn duplicate_and_trailing_json_are_rejected() {
	for input in [
		br#"{"a":1,"a":2}"#.as_slice(),
		br#"{"a":{"dtype":"F32","dtype":"F16"}}"#.as_slice(),
		br#"{"a":1} {"b":2}"#.as_slice(),
	] {
		assert!(unique_json(input).is_err());
	}
	let bytes = raw_file(br#"{"w":{"dtype":"F32","shape":[1],"data_offsets":[0,4]},"w":{"dtype":"F32","shape":[1],"data_offsets":[0,4]}}"#,&[0;4]);
	assert!(authenticate_safetensors(&bytes, &pin(&bytes)).is_err());
}

#[test]
fn unsupported_rank_dtype_dimensions_and_fields_fail_closed() {
	for entry in [
		json!({"dtype":"U8","shape":[4],"data_offsets":[0,4]}),
		json!({"dtype":"F32","shape":[],"data_offsets":[0,4]}),
		json!({"dtype":"F32","shape":[0],"data_offsets":[0,4]}),
		json!({"dtype":"F32","shape":[1,1,1,1,1,1,1,1,1],"data_offsets":[0,4]}),
		json!({"dtype":"F32","shape":[1.0],"data_offsets":[0,4]}),
		json!({"dtype":"F32","shape":[1],"data_offsets":[0,4],"strides":[1]}),
	] {
		let bytes = raw_file(&serde_json::to_vec(&json!({"w":entry})).unwrap(), &[0; 4]);
		assert!(authenticate_safetensors(&bytes, &pin(&bytes)).is_err());
	}
}

#[test]
fn shape_product_and_storage_multiplication_overflow_are_rejected() {
	for shape in [vec![2, u64::MAX], vec![u64::MAX / 2]] {
		let bytes = raw_file(
			&serde_json::to_vec(&json!({"w":{"dtype":"F64","shape":shape,"data_offsets":[0,8]}}))
				.unwrap(),
			&[0; 8],
		);
		let error = authenticate_safetensors(&bytes, &pin(&bytes))
			.err()
			.unwrap()
			.to_string();
		assert!(error.contains("overflows"), "{error}");
	}
}

#[test]
fn gaps_overlaps_truncation_and_unindexed_tail_are_rejected() {
	for ranges in [
		[[0, 4], [3, 7]],
		[[0, 4], [5, 9]],
		[[1, 5], [5, 9]],
		[[0, 4], [4, 8]],
	] {
		let head = json!({"a":{"dtype":"F32","shape":[1],"data_offsets":ranges[0]},"b":{"dtype":"F32","shape":[1],"data_offsets":ranges[1]}});
		let bytes = raw_file(&serde_json::to_vec(&head).unwrap(), &[0; 9]);
		assert!(authenticate_safetensors(&bytes, &pin(&bytes)).is_err());
	}
	let bytes = single(&[2]);
	for cut in [0, 4, 8, bytes.len() - 1] {
		assert!(authenticate_safetensors(&bytes[..cut], &pin(&bytes[..cut])).is_err());
	}
}

#[test]
fn nonfinite_is_rejected_in_each_supported_float_storage() {
	for (dtype, value) in [
		("F16", 0x7c00_u16.to_le_bytes().to_vec()),
		("BF16", 0x7fc0_u16.to_le_bytes().to_vec()),
		("F32", f32::INFINITY.to_le_bytes().to_vec()),
		("F64", f64::NAN.to_le_bytes().to_vec()),
	] {
		let bytes = file(&[("w", &[1], dtype, value)]);
		assert!(authenticate_safetensors(&bytes, &pin(&bytes)).is_err());
	}
}

#[test]
fn signed_zero_and_finite_subnormal_are_preserved_in_payload_identity() {
	let negative = file(&[(
		"w",
		&[2],
		"F32",
		[(-0.0_f32).to_le_bytes(), 1_u32.to_le_bytes()].concat(),
	)]);
	let positive = file(&[(
		"w",
		&[2],
		"F32",
		[(0.0_f32).to_le_bytes(), 1_u32.to_le_bytes()].concat(),
	)]);
	let a = authenticate_safetensors(&negative, &pin(&negative)).unwrap();
	let b = authenticate_safetensors(&positive, &pin(&positive)).unwrap();
	assert_ne!(
		a.tensor("w").unwrap().payload_sha256,
		b.tensor("w").unwrap().payload_sha256
	);
	assert_eq!(
		a.payload("w").unwrap(),
		[(-0.0_f32).to_le_bytes(), 1_u32.to_le_bytes()].concat()
	);
}

struct SubsetFixture {
	prefix: Vec<u8>,
	parts: BTreeMap<String, Vec<u8>>,
	pin: SubsetPin,
	receipt: Vec<u8>,
	header_receipt: Vec<u8>,
}

fn subset_fixture(tensors: &[(&str, &[u64], &str, Vec<u8>)]) -> SubsetFixture {
	let full = file(tensors);
	let header = inspect_header(&full, full.len() as u64).unwrap();
	let prefix = full[..header.header_bytes as usize].to_vec();
	let mut parts = BTreeMap::new();
	let mut chunks = Vec::new();
	for row in header.tensors.values() {
		let bytes =
			full[row.file_offset as usize..(row.file_offset + row.byte_length) as usize].to_vec();
		for (i, chunk) in bytes.chunks(65_536).enumerate() {
			chunks.push(ChunkPin {
				name: row.name.clone(),
				local: (i * 65_536) as u64,
				offset: row.file_offset + (i * 65_536) as u64,
				limit: chunk.len() as u64,
				total: row.byte_length,
				sha256: digest(chunk),
				version: "observed-v1".into(),
			});
		}
		parts.insert(row.name.clone(), bytes);
	}
	let receipt = serde_json::to_vec(&chunks).unwrap();
	let header_receipt = serde_json::to_vec(&json!({"header":{
		"path":"/synthetic/base.safetensors","size":full.len(),"version":"observed-v1",
		"chunk_sha256":digest(&prefix),"offset":0,"next_offset":prefix.len(),"eof":false}}))
	.unwrap();
	let pin = SubsetPin {
		source_path: "/synthetic/base.safetensors".into(),
		observed_version: "observed-v1".into(),
		reported_full_sha256: digest(&full),
		source_size_bytes: full.len() as u64,
		prefix: pin(&prefix),
		header_receipt_sha256: digest(&header_receipt),
		receipt_sha256: digest(&receipt),
		chunks,
	};
	SubsetFixture {
		prefix,
		parts,
		pin,
		receipt,
		header_receipt,
	}
}

fn authenticate_fixture(f: &SubsetFixture) -> anyhow::Result<AuthenticatedSubset> {
	authenticate_subset(&f.prefix, &f.parts, &f.pin, &f.receipt, &f.header_receipt)
}

fn small_subset() -> SubsetFixture {
	subset_fixture(&[("w", &[2, 2], "F16", vec![0; 8])])
}

#[test]
fn partial_source_never_upgrades_to_whole_checkpoint() {
	let f = small_subset();
	let source = authenticate_fixture(&f).unwrap();
	assert!(!source.receipt().full_source_sha256_verified);
	assert!(!source.receipt().payload_membership_in_full_digest_proven);
	assert!(!source.receipt().remote_owner_attested);
	assert!(source.require_complete_source().is_err());
}

#[test]
fn partial_source_binds_header_path_version_and_digest() {
	for target in 0..4 {
		let mut f = small_subset();
		match target {
			0 => f.pin.source_path = "/different/file".into(),
			1 => f.pin.observed_version = "different-version".into(),
			2 => f.pin.prefix.sha256 = "1".repeat(64),
			_ => f.pin.source_size_bytes += 2,
		}
		assert!(authenticate_fixture(&f).is_err(), "mutation {target}");
	}
}

#[test]
fn incomplete_changed_or_falsely_located_chunks_are_rejected() {
	for target in 0..6 {
		let mut f = small_subset();
		match target {
			0 => f.parts.get_mut("w").unwrap()[0] = 1,
			1 => {
				f.parts.get_mut("w").unwrap().pop();
			}
			2 => f.pin.chunks[0].offset += 2,
			3 => f.pin.chunks[0].version = "other".into(),
			4 => f.pin.chunks[0].limit -= 2,
			_ => f.pin.chunks.push(f.pin.chunks[0].clone()),
		}
		f.receipt = serde_json::to_vec(&f.pin.chunks).unwrap();
		f.pin.receipt_sha256 = digest(&f.receipt);
		assert!(authenticate_fixture(&f).is_err(), "mutation {target}");
	}
}

fn required_roles(profile: Profile) -> Vec<&'static str> {
	match profile {
		Profile::NeuronJointRenewalEndpointF64V1 => vec![
			"forward_code",
			"task_code",
			"arithmetic_code",
			"planning_code",
			"target_contract",
			"checkpoint_fetch_receipt",
		],
		Profile::LayaMaskedBaFp32ActEscalateV1 => vec![
			"row_adapter_code",
			"action_adapter_code",
			"training_code",
			"runtime_config",
			"encoder_config",
			"base_manifest",
			"candidate_manifest",
			"origin_receipts",
			"adapter_origin_receipts",
			"head_chunk_receipts",
			"header_transfer_receipts",
		],
	}
}

fn profile_fixture(
	profile: Profile,
	overrides: BTreeMap<String, Vec<u8>>,
) -> (ProfilePin, BTreeMap<String, Vec<u8>>) {
	let evidence: BTreeMap<String, Vec<u8>> = required_roles(profile)
		.iter()
		.map(|role| {
			(
				(*role).into(),
				overrides
					.get(*role)
					.cloned()
					.unwrap_or_else(|| format!("SYNTHETIC TEST ONLY: {role}").into_bytes()),
			)
		})
		.collect::<BTreeMap<_, _>>();
	let sources = evidence
		.iter()
		.map(|(role, bytes)| EvidencePin {
			role: role.clone(),
			source: pin(bytes),
		})
		.collect();
	(ProfilePin { profile, sources }, evidence)
}

#[test]
fn semantic_profile_rejects_missing_changed_duplicate_and_extra_sources() {
	let (p, e) = profile_fixture(Profile::NeuronJointRenewalEndpointF64V1, BTreeMap::new());
	verify_profile(&p, &e).unwrap();
	let mut incomplete = e.clone();
	incomplete.remove("task_code");
	assert!(verify_profile(&p, &incomplete).is_err());
	let mut changed = e.clone();
	changed.get_mut("forward_code").unwrap().push(b'!');
	assert!(verify_profile(&p, &changed).is_err());
	let mut duplicate = p.clone();
	duplicate.sources[1] = duplicate.sources[0].clone();
	assert!(verify_profile(&duplicate, &e).is_err());
	let mut extra = e.clone();
	extra.insert("unreviewed".into(), vec![]);
	assert!(verify_profile(&p, &extra).is_err());
}

fn neuron() -> Value {
	json!({"schema":"joint-policy-v1","family":"renewal","head_dimensions":[85,48,4],
		"public_dimensions":43,"n_grid":31,"parameter_count":4332,
		"target":"sign(X_deadline6)>0, including early submit; learned belief is not privileged posterior",
		"coordinates":(0..31).map(|i|-0.9375+f64::from(i)/16.0).chain([-1.0,1.0]).collect::<Vec<_>>(),
		"confusion":[[1.,0.],[0.,1.]],
		"core":{"kind":"full_distribution_ctmc","raw":vec![0.;8],"tables":[{"dt":0.25,"drive":0,"matrix":vec![vec![0.;33];33]}]},
		"network":{"w1":vec![vec![0.;85];48],"b1":vec![0.;48],"w2":vec![vec![0.;48];4],"b2":vec![0.;4]}})
}

fn neuron_profile() -> VerifiedProfile {
	let (p, e) = profile_fixture(Profile::NeuronJointRenewalEndpointF64V1, BTreeMap::new());
	verify_profile(&p, &e).unwrap()
}

#[test]
fn neuron_binds_all_four_f64_tensors_and_keeps_dangerous_qualifications_false() {
	let bytes = serde_json::to_vec(&neuron()).unwrap();
	let p = neuron_profile();
	let result = authenticate_neuron_json(
		&bytes,
		&pin(&bytes),
		&p,
		TaskClass::EndpointBinarySubmission,
	)
	.unwrap();
	let r = serde_json::to_value(result.receipt()).unwrap();
	assert!(r["scope"].as_object().unwrap().values().all(|v| v == false));
	assert_eq!(
		r["facts"]["network_tensors"]
			.as_object()
			.unwrap()
			.values()
			.map(|v| v["elements"].as_u64().unwrap())
			.sum::<u64>(),
		4324
	);
	assert_eq!(r["facts"]["network_tensors"]["network.w2"]["dtype"], "F64");
	assert_eq!(r["facts"]["native_safetensors_cohort_compatible"], false);
}

#[test]
fn neuron_refuses_task_reinterpretation_and_wrong_network_shape() {
	let p = neuron_profile();
	let bytes = serde_json::to_vec(&neuron()).unwrap();
	for task in [TaskClass::CallPut, TaskClass::ActOrEscalate] {
		assert!(authenticate_neuron_json(&bytes, &pin(&bytes), &p, task).is_err());
	}
	let mut model = neuron();
	model["network"]["w2"] = json!(vec![vec![0.; 4]; 48]);
	let bytes = serde_json::to_vec(&model).unwrap();
	assert!(authenticate_neuron_json(
		&bytes,
		&pin(&bytes),
		&p,
		TaskClass::EndpointBinarySubmission
	)
	.is_err());
}

#[test]
fn neuron_protected_physics_and_semantics_are_bound_across_candidate() {
	let p = neuron_profile();
	let base = neuron();
	let b = serde_json::to_vec(&base).unwrap();
	let original =
		authenticate_neuron_json(&b, &pin(&b), &p, TaskClass::EndpointBinarySubmission).unwrap();
	let mut network = base.clone();
	network["network"]["b2"][0] = json!(0.25);
	let n = serde_json::to_vec(&network).unwrap();
	let edited =
		authenticate_neuron_json(&n, &pin(&n), &p, TaskClass::EndpointBinarySubmission).unwrap();
	validate_neuron_network_only(&original, &edited).unwrap();
	let mut physics = base;
	physics["core"]["raw"][0] = json!(0.25);
	let d = serde_json::to_vec(&physics).unwrap();
	let altered =
		authenticate_neuron_json(&d, &pin(&d), &p, TaskClass::EndpointBinarySubmission).unwrap();
	assert!(validate_neuron_network_only(&original, &altered).is_err());
}

#[test]
fn neuron_json_rejects_unknown_mlp_tensor_duplicate_tables_and_wrong_target() {
	let p = neuron_profile();
	for mode in 0..4 {
		let mut model = neuron();
		match mode {
			0 => model["network"]["extra"] = json!([0.]),
			1 => {
				let t = model["core"]["tables"][0].clone();
				model["core"]["tables"].as_array_mut().unwrap().push(t);
			}
			2 => model["target"] = json!("first passage"),
			_ => model["coordinates"][0] = json!(-1.),
		}
		let b = serde_json::to_vec(&model).unwrap();
		assert!(
			authenticate_neuron_json(&b, &pin(&b), &p, TaskClass::EndpointBinarySubmission)
				.is_err()
		);
	}
}

fn gzip(bytes: &[u8]) -> Vec<u8> {
	let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
	encoder.write_all(bytes).unwrap();
	encoder.finish().unwrap()
}

fn gzip_profile(zipped: &[u8]) -> VerifiedProfile {
	let origin = json!({"files":[{"sha256":digest(zipped),"bytes":zipped.len(),"url":pin(zipped).source_id,"git_blob_sha":"a".repeat(40)}]});
	let (pp, ee) = profile_fixture(
		Profile::NeuronJointRenewalEndpointF64V1,
		BTreeMap::from([(
			"checkpoint_fetch_receipt".into(),
			serde_json::to_vec(&origin).unwrap(),
		)]),
	);
	verify_profile(&pp, &ee).unwrap()
}

#[test]
fn original_gzip_is_authenticated_and_decoded_in_rust() {
	let raw = serde_json::to_vec(&neuron()).unwrap();
	let zipped = gzip(&raw);
	let p = gzip_profile(&zipped);
	let result = authenticate_neuron_gzip(
		&zipped,
		&pin(&zipped),
		&pin(&raw),
		&p,
		TaskClass::EndpointBinarySubmission,
	)
	.unwrap();
	assert_eq!(
		result.receipt().facts()["original_gzip_identity_and_derivation_verified"],
		true
	);
	let mut concatenated = zipped.clone();
	concatenated.extend(&zipped);
	assert!(authenticate_neuron_gzip(
		&concatenated,
		&pin(&concatenated),
		&pin(&raw),
		&gzip_profile(&concatenated),
		TaskClass::EndpointBinarySubmission
	)
	.is_err());
	let mut crc = zipped.clone();
	let at = crc.len() - 8;
	crc[at] ^= 1;
	assert!(authenticate_neuron_gzip(
		&crc,
		&pin(&crc),
		&pin(&raw),
		&gzip_profile(&crc),
		TaskClass::EndpointBinarySubmission
	)
	.is_err());
	assert!(authenticate_neuron_gzip(
		&zipped,
		&pin(&zipped),
		&pin(b"false derived JSON"),
		&p,
		TaskClass::EndpointBinarySubmission
	)
	.is_err());
}

fn laya_factors(child: bool, transpose: bool) -> Vec<u8> {
	let mut tensors = vec![
		(
			"model.scorer.1.A",
			if transpose {
				&[768, 2][..]
			} else {
				&[2, 768][..]
			},
			"F32",
			vec![0; 2 * 768 * 4],
		),
		("model.scorer.1.B", &[4, 2][..], "F32", vec![0; 4 * 2 * 4]),
		("model.scorer.3.A", &[1, 768][..], "F32", vec![0; 768 * 4]),
		("model.scorer.3.B", &[1, 1][..], "F32", vec![0; 4]),
	];
	if child {
		tensors.extend([
			("model.act_head.2.A", &[1, 64][..], "F32", vec![0; 64 * 4]),
			("model.act_head.2.B", &[2, 1][..], "F32", vec![0; 2 * 4]),
		]);
	}
	file(&tensors)
}

fn laya_base(parent: &[u8]) -> SubsetFixture {
	let mut f = subset_fixture(&[
		(
			"scorer.1.weight",
			&[768, 768],
			"F16",
			vec![0; 768 * 768 * 2],
		),
		("scorer.3.weight", &[1, 768], "F16", vec![0; 768 * 2]),
		("act_head.2.weight", &[2, 256], "F16", vec![0; 2 * 256 * 2]),
	]);
	let mut header: Value = serde_json::from_slice(&f.header_receipt).unwrap();
	header["parent"] = transfer_for(parent);
	f.header_receipt = serde_json::to_vec(&header).unwrap();
	f.pin.header_receipt_sha256 = digest(&f.header_receipt);
	f
}

fn transfer_for(bytes: &[u8]) -> Value {
	json!({"path":pin(bytes).source_id,"chunk_sha256":digest(bytes),"size":bytes.len(),"offset":0,"next_offset":bytes.len(),"eof":true})
}

fn laya_manifests(base: &SubsetFixture, child: &[u8], parent: &[u8]) -> (Value, Value) {
	let revision = "a".repeat(40);
	let candidate = json!({"schema":"heptatrader.laya-resident-candidate.v1","base_revision":revision,
		"adapter_sha256":digest(child),"action_adapter_validation":{"parent_adapter_sha256":digest(parent),"parent_action_adapter_present":false},
		"profile":{"dtype":"float32","precision_policy":"EXPLICIT_FP32_RUNTIME_PROFILE","organ_adapter":"FROZEN_IDENTITY",
		"action_target":"FROZEN_PARENT_ANSWER_CORRECTNESS_ACT_VS_ESCALATE","action_target_is_trade_permission":false,
		"targets":{"scorer.1":{"rows":[0,1,2,3],"rank":2},"scorer.3":{"rows":[0],"rank":1}},
		"action_targets":{"act_head.2":{"rows":[0,1],"cols":(0..64).collect::<Vec<_>>(),"rank":1}}}});
	let manifest = json!({"schema":"heptatrader.laya-base.v1","repository":"convaiinnovations/laya-multilingual","revision":revision,
		"files":{"model.safetensors":{"sha256":base.pin.reported_full_sha256,"size":base.pin.source_size_bytes}}});
	(candidate, manifest)
}

fn laya_profile(candidate: &[u8], base: &[u8], f: &SubsetFixture, child: &[u8]) -> VerifiedProfile {
	let tool_record =
		|v: Value| json!({"isError":false,"content":[{"text":serde_json::to_string(&v).unwrap()}]});
	let origin = json!({
		"candidate":tool_record(json!({"sha256":digest(candidate),"size":candidate.len()})),
		"base":tool_record(json!({"sha256":f.pin.reported_full_sha256,"size":f.pin.source_size_bytes,"path":f.pin.source_path,"version":f.pin.observed_version}))
	});
	let (p, e) = profile_fixture(
		Profile::LayaMaskedBaFp32ActEscalateV1,
		BTreeMap::from([
			("candidate_manifest".into(), candidate.to_vec()),
			("base_manifest".into(), base.to_vec()),
			(
				"origin_receipts".into(),
				serde_json::to_vec(&origin).unwrap(),
			),
			(
				"adapter_origin_receipts".into(),
				serde_json::to_vec(&json!({"adapter":transfer_for(child)})).unwrap(),
			),
			("head_chunk_receipts".into(), f.receipt.clone()),
			("header_transfer_receipts".into(), f.header_receipt.clone()),
		]),
	);
	verify_profile(&p, &e).unwrap()
}

#[test]
fn laya_binds_real_layout_f16_source_f32_factors_and_split_rounding_boundary() {
	let child = laya_factors(true, false);
	let parent = laya_factors(false, false);
	let f = laya_base(&parent);
	let base = authenticate_fixture(&f).unwrap();
	let (m, b) = laya_manifests(&f, &child, &parent);
	let m = serde_json::to_vec(&m).unwrap();
	let b = serde_json::to_vec(&b).unwrap();
	let profile = laya_profile(&m, &b, &f, &child);
	for (bytes, variant) in [
		(&child, LayaVariant::ChildPriceAndAct),
		(&parent, LayaVariant::ParentPriceOnly),
	] {
		let adapter = authenticate_safetensors(bytes, &pin(bytes)).unwrap();
		let result = authenticate_laya(
			&adapter,
			&base,
			&m,
			&b,
			&profile,
			variant,
			TaskClass::ActOrEscalate,
		)
		.unwrap();
		assert_eq!(
			result.facts()["merged_and_split_bitwise_equivalence_proven"],
			false
		);
		assert_eq!(result.facts()["full_base_checkpoint_authenticated"], false);
		assert_eq!(
			result.facts()["native_factor_norm_is_effective_weight_norm"],
			false
		);
		let r = serde_json::to_value(&result).unwrap();
		assert!(r["scope"].as_object().unwrap().values().all(|v| v == false));
		assert!(authenticate_laya(
			&adapter,
			&base,
			&m,
			&b,
			&profile,
			variant,
			TaskClass::CallPut
		)
		.is_err());
	}
}

#[test]
fn laya_rejects_factor_transposition_missing_revision_and_altered_mask() {
	let child = laya_factors(true, false);
	let parent = laya_factors(false, false);
	let f = laya_base(&parent);
	let base = authenticate_fixture(&f).unwrap();
	for failure in 0..4 {
		let altered = if failure == 0 {
			laya_factors(true, true)
		} else {
			child.clone()
		};
		let (mut m, mut b) = laya_manifests(&f, &altered, &parent);
		match failure {
			1 => {
				m.as_object_mut().unwrap().remove("base_revision");
				b.as_object_mut().unwrap().remove("revision");
			}
			2 => m["profile"]["action_targets"]["act_head.2"]["cols"][0] = json!(64),
			3 => m["profile"]["action_target"] = json!("CALL_PUT"),
			_ => {}
		}
		let m = serde_json::to_vec(&m).unwrap();
		let b = serde_json::to_vec(&b).unwrap();
		let profile = laya_profile(&m, &b, &f, &altered);
		let adapter = authenticate_safetensors(&altered, &pin(&altered)).unwrap();
		assert!(
			authenticate_laya(
				&adapter,
				&base,
				&m,
				&b,
				&profile,
				LayaVariant::ChildPriceAndAct,
				TaskClass::ActOrEscalate
			)
			.is_err(),
			"failure {failure}"
		);
	}
}

#[test]
fn semantic_profiles_cannot_cross_neuron_and_laya() {
	let (p, e) = profile_fixture(Profile::LayaMaskedBaFp32ActEscalateV1, BTreeMap::new());
	let p = verify_profile(&p, &e).unwrap();
	let bytes = serde_json::to_vec(&neuron()).unwrap();
	assert!(authenticate_neuron_json(
		&bytes,
		&pin(&bytes),
		&p,
		TaskClass::EndpointBinarySubmission
	)
	.is_err());
}
