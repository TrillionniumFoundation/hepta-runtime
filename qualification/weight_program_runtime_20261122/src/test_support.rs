// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Structurally valid synthetic profile fixtures; never evidence of owner review.

use crate::snapshot::{AuthenticatedSnapshot, EditDomain, SemanticSnapshot, PARAMS, ROWS, WIDTH};
use hepta_semantic_source_adapter_study::{
	digest,
	semantics::{verify_profile, EvidencePin, Profile, ProfilePin},
	SourcePin,
};
use serde_json::json;
use std::collections::BTreeMap;

/// Construct an isolated, structurally valid endpoint-law model and matching
/// profile evidence. All source text is explicitly synthetic. Only w1[0][0] is
/// one; other frontend weights and biases are zero. A custom head preserves all
/// supplied finite F64 bits, including negative zero.
pub(crate) fn fixture(
	domain: EditDomain,
	head: Option<&[f64]>,
) -> (AuthenticatedSnapshot, Vec<u8>, Vec<u8>) {
	let head = head.map_or_else(|| vec![0_f64; PARAMS], <[f64]>::to_vec);
	assert_eq!(head.len(), PARAMS, "fixture requires 196 readout values");
	assert!(head.iter().all(|value| value.is_finite()));
	let mut w1 = vec![vec![0_f64; 85]; WIDTH];
	w1[0][0] = 1.;
	let mut transition = vec![vec![0_f64; 33]; 33];
	for (index, row) in transition.iter_mut().enumerate() {
		row[index] = 1.;
	}
	let model = json!({
		"schema":"joint-policy-v1",
		"family":"renewal",
		"head_dimensions":[85,48,4],
		"public_dimensions":43,
		"n_grid":31,
		"parameter_count":4332,
		"target":"sign(X_deadline6)>0, including early submit; learned belief is not privileged posterior",
		"coordinates":(0..31).map(|i|-0.9375+f64::from(i)/16.0)
			.chain([-1.0,1.0]).collect::<Vec<_>>(),
		"bank_semantics":{"scope":"SYNTHETIC STRUCTURAL TEST FIXTURE ONLY"},
		"confusion":[[1.,0.],[0.,1.]],
		"core":{
			"kind":"full_distribution_ctmc",
			"raw":vec![0_f64;8],
			"tables":[{"dt":0.25,"drive":0,"matrix":transition}]
		},
		"network":{
			"w1":w1,
			"b1":vec![0_f64;WIDTH],
			"w2":head[..ROWS*WIDTH].chunks(WIDTH).map(|row|row.to_vec()).collect::<Vec<_>>(),
			"b2":head[ROWS*WIDTH..].to_vec()
		}
	});
	let original = serde_json::to_vec(&model).expect("encode fixture model");
	let mut protected = model.clone();
	let network = protected["network"].as_object_mut().unwrap();
	network.remove("w2");
	network.remove("b2");
	let mut header = serde_json::to_vec(&json!({
		"__metadata__":{
			"hepta_bridge":"hepta.json-f64-readout196-bridge.v1",
			"original_json_sha256":digest(&original),
			"protected_fields_sha256":digest(&serde_json::to_vec(&protected).unwrap()),
			"arithmetic":"JSON-decimal-roundtrip-to-binary64-no-cast"
		},
		"readout196":{"dtype":"F64","shape":[196],"data_offsets":[0,1568]},
		"original_json":{"dtype":"U8","shape":[original.len()],"data_offsets":[1568,1568+original.len()]}
	}))
	.unwrap();
	while !header.len().is_multiple_of(8) {
		header.push(b' ');
	}
	let mut bridge = (header.len() as u64).to_le_bytes().to_vec();
	bridge.extend(header);
	bridge.extend(head.iter().flat_map(|value| value.to_le_bytes()));
	bridge.extend(original);

	let evidence: BTreeMap<String, String> = [
		"forward_code",
		"task_code",
		"arithmetic_code",
		"planning_code",
		"target_contract",
		"checkpoint_fetch_receipt",
	]
	.into_iter()
	.map(|role| {
		(
			role.to_string(),
			format!("SYNTHETIC STRUCTURAL TEST ONLY: {role}\n"),
		)
	})
	.collect();
	let profile_pin = ProfilePin {
		profile: Profile::NeuronJointRenewalEndpointF64V1,
		sources: evidence
			.iter()
			.map(|(role, text)| EvidencePin {
				role: role.clone(),
				source: SourcePin {
					source_id: format!("synthetic-test-only:{role}"),
					sha256: digest(text.as_bytes()),
					size_bytes: text.len() as u64,
				},
			})
			.collect(),
	};
	let evidence_bytes = evidence
		.iter()
		.map(|(role, text)| (role.clone(), text.as_bytes().to_vec()))
		.collect();
	let profile = verify_profile(&profile_pin, &evidence_bytes).unwrap();
	let contract = serde_json::to_vec(&json!({
		"schema":"hepta.weight-program-evaluation-contract.v1",
		"task_class":"endpoint_binary_submission",
		"task":{
			"scope":"synthetic structural algebra test; no owner review or market qualification",
			"fixture_frontend":"w1[0][0]=1; other frontend weights and biases are zero"
		},
		"profile_pin":profile_pin,
		"profile_evidence":evidence,
		"profile_sources_binding_sha256":profile.binding_sha256()
	}))
	.unwrap();
	let claimed = SemanticSnapshot::capture(&bridge, &digest(&bridge), &contract, domain)
		.expect("synthetic fixture passes structural profile authentication");
	let authenticated = AuthenticatedSnapshot::authenticate(&claimed, &bridge, &contract)
		.expect("synthetic fixture binds actual bridge and contract bytes");
	(authenticated, bridge, contract)
}
