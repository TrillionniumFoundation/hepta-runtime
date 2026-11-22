// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Independent algebra, semantic rejection, numerical bounds and stopping controls.

use super::{
	edit::{self, EditProgram, ReadoutEquation},
	planner::{self, *},
	snapshot::*,
	test_support::fixture,
};
use hepta_semantic_source_adapter_study::digest;
use serde_json::{json, Value};
use std::collections::BTreeSet;

fn input(value: f64) -> Vec<f64> {
	let mut x = vec![0.; 85];
	x[0] = value;
	x
}
fn program(s: &AuthenticatedSnapshot, equations: Vec<ReadoutEquation>) -> EditProgram {
	EditProgram {
		schema: "hepta.readout-edit-program.v1".into(),
		role: "exposed_development".into(),
		snapshot_sha256: s.snapshot().identity().unwrap(),
		feature_evidence_sha256: "1".repeat(64),
		teacher_evidence_sha256: "2".repeat(64),
		ridge: 1e-9,
		radius_l2: 2.,
		max_equation_error: 1e-7,
		equations,
	}
}
fn rewritten_bridge(bytes: &[u8], mutate: impl FnOnce(&mut Value)) -> Vec<u8> {
	let offset = 8 + u64::from_le_bytes(bytes[..8].try_into().unwrap()) as usize;
	let mut model: Value = serde_json::from_slice(&bytes[offset + 1568..]).unwrap();
	mutate(&mut model);
	let original = serde_json::to_vec(&model).unwrap();
	let mut protected = model.clone();
	let net = protected["network"].as_object_mut().unwrap();
	net.remove("w2");
	net.remove("b2");
	let mut h=serde_json::to_vec(&json!({"__metadata__":{"hepta_bridge":"hepta.json-f64-readout196-bridge.v1",
        "original_json_sha256":digest(&original),"protected_fields_sha256":digest(&serde_json::to_vec(&protected).unwrap()),
        "arithmetic":"JSON-decimal-roundtrip-to-binary64-no-cast"},"readout196":{"dtype":"F64","shape":[196],"data_offsets":[0,1568]},
        "original_json":{"dtype":"U8","shape":[original.len()],"data_offsets":[1568,1568+original.len()]}})).unwrap();
	while !h.len().is_multiple_of(8) {
		h.push(b' ');
	}
	let mut out = (h.len() as u64).to_le_bytes().to_vec();
	out.extend(h);
	out.extend(&bytes[offset..offset + 1568]);
	out.extend(original);
	out
}
#[test]
fn forged_snapshot_and_profile_evidence_cannot_authorize_compilation() {
	let (auth, bytes, contract) = fixture(EditDomain::JointReadout, None);
	assert_eq!(auth.snapshot().validate().unwrap().len(), 196);
	let mut claim = auth.snapshot().clone();
	claim.law_sha256 = "0".repeat(64);
	assert!(claim.identity().is_ok());
	assert!(AuthenticatedSnapshot::authenticate(&claim, &bytes, &contract).is_err());
	let mut tampered: Value = serde_json::from_slice(&contract).unwrap();
	tampered["profile_evidence"]["forward_code"] = json!("altered source");
	assert!(SemanticSnapshot::capture(
		&bytes,
		&digest(&bytes),
		&serde_json::to_vec(&tampered).unwrap(),
		EditDomain::JointReadout
	)
	.is_err());
	let mut bad_binding: Value = serde_json::from_slice(&contract).unwrap();
	bad_binding["profile_sources_binding_sha256"] = json!("0".repeat(64));
	assert!(SemanticSnapshot::capture(
		&bytes,
		&digest(&bytes),
		&serde_json::to_vec(&bad_binding).unwrap(),
		EditDomain::JointReadout
	)
	.is_err());
	assert!(SemanticSnapshot::capture(
		&bytes,
		&"0".repeat(64),
		&contract,
		EditDomain::JointReadout
	)
	.is_err());
	assert!(
		SemanticSnapshot::capture(&bytes, &digest(&bytes), b"{}", EditDomain::JointReadout)
			.is_err()
	);
}
#[test]
fn freshly_rehashed_invalid_law_target_grid_and_parameter_semantics_are_rejected() {
	let (_, bytes, contract) = fixture(EditDomain::JointReadout, None);
	for case in 0..5 {
		let mutated = rewritten_bridge(&bytes, |model| match case {
			0 => model["core"] = Value::Null,
			1 => model["core"]["kind"] = json!("different_law"),
			2 => model["target"] = json!("first passage instead of endpoint"),
			3 => model["coordinates"][0] = json!(99.),
			_ => model["parameter_count"] = json!(4324),
		});
		assert!(
			SemanticSnapshot::capture(
				&mutated,
				&digest(&mutated),
				&contract,
				EditDomain::JointReadout
			)
			.is_err(),
			"case {case}"
		);
	}
}
#[test]
fn effective_head_receipt_and_actual_frontend_are_source_bound() {
	let (auth, mut bytes, contract) = fixture(EditDomain::JointReadout, None);
	let h = auth.hidden(&input(0.5_f64.atanh())).unwrap();
	assert!((h[0] - 0.5).abs() < 1e-15);
	assert!(h[1..].iter().all(|x| *x == 0.));
	assert!(auth.hidden(&[0.; 84]).is_err());
	assert!(auth.hidden(&input(f64::NAN)).is_err());
	let offset = 8 + u64::from_le_bytes(bytes[..8].try_into().unwrap()) as usize;
	bytes[offset..offset + 8].copy_from_slice(&0.25_f64.to_le_bytes());
	let next =
		SemanticSnapshot::capture(&bytes, &digest(&bytes), &contract, EditDomain::JointReadout)
			.unwrap();
	assert_eq!(
		next.protected_fields_sha256,
		auth.snapshot().protected_fields_sha256
	);
	assert_ne!(
		next.semantic_receipt_binding_sha256,
		auth.snapshot().semantic_receipt_binding_sha256
	);
	assert_eq!(decode_f64(&next.head_le_hex[0]).unwrap(), 0.25);
	bytes[offset..offset + 8].copy_from_slice(&f64::NAN.to_le_bytes());
	assert!(SemanticSnapshot::capture(
		&bytes,
		&digest(&bytes),
		&contract,
		EditDomain::JointReadout
	)
	.is_err());
}
#[test]
fn direct_gap_solution_uses_actual_bias_layout_and_has_exact_inverse() {
	let mut head = vec![0_f64; 196];
	head[195] = -0_f64;
	let (state, _, _) = fixture(EditDomain::ContinuationOnly, Some(&head));
	let p = program(
		&state,
		vec![ReadoutEquation::ContinuationGap {
			left: 0,
			right: 2,
			input: input(0.),
			target: 1.,
		}],
	);
	let result = edit::compile(&state, &p).unwrap();
	assert_eq!(
		result.edits.iter().map(|x| x.index).collect::<Vec<_>>(),
		[192, 194]
	);
	assert!((decode_f64(&result.candidate_head_le_hex[192]).unwrap() - 0.5).abs() < 1e-8);
	assert!((decode_f64(&result.candidate_head_le_hex[194]).unwrap() + 0.5).abs() < 1e-8);
	assert_eq!(
		result.candidate_head_le_hex[195],
		hex(&(-0_f64).to_le_bytes())
	);
	let mut restored = result.candidate_head_le_hex.clone();
	for e in &result.inverse_edits {
		assert_eq!(restored[e.index], e.expected_hex);
		restored[e.index] = e.replacement_hex.clone();
	}
	assert_eq!(restored, state.snapshot().head_le_hex);
}
#[test]
fn ridge_two_equations_matches_independent_hand_solution() {
	let (s, _, _) = fixture(EditDomain::JointReadout, None);
	let mut p = program(
		&s,
		vec![
			ReadoutEquation::ContinuationScore {
				row: 0,
				input: input(0.5_f64.atanh()),
				target: 2.,
			},
			ReadoutEquation::BeliefLogit {
				input: input(0.),
				target: -1.,
			},
		],
	);
	p.ridge = 1.;
	p.max_equation_error = 1.;
	let r = edit::compile(&s, &p).unwrap();
	assert!((decode_f64(&r.candidate_head_le_hex[0]).unwrap() - 4. / 9.).abs() < 1e-14);
	assert!((decode_f64(&r.candidate_head_le_hex[192]).unwrap() - 8. / 9.).abs() < 1e-14);
	assert!((decode_f64(&r.candidate_head_le_hex[195]).unwrap() + 0.5).abs() < 1e-14);
}
#[test]
fn semantic_alias_stale_identity_and_infeasible_equations_are_rejected() {
	let (s, _, _) = fixture(EditDomain::JointReadout, None);
	let invalid = program(
		&s,
		vec![ReadoutEquation::ContinuationScore {
			row: 3,
			input: input(0.),
			target: 1.,
		}],
	);
	assert!(edit::compile(&s, &invalid).is_err());
	let mut p = program(
		&s,
		vec![ReadoutEquation::BeliefLogit {
			input: input(0.),
			target: 1.,
		}],
	);
	p.snapshot_sha256 = "0".repeat(64);
	assert!(edit::compile(&s, &p).is_err());
	p.snapshot_sha256 = s.snapshot().identity().unwrap();
	p.role = "independent_confirmation".into();
	assert!(edit::compile(&s, &p).is_err());
	p.role = "exposed_development".into();
	p.radius_l2 = 0.01;
	assert!(edit::compile(&s, &p).is_err());
	p.radius_l2 = 2.;
	p.max_equation_error = 0.;
	assert!(edit::compile(&s, &p).is_err());
	let (q, _, _) = fixture(EditDomain::ContinuationOnly, None);
	p.snapshot_sha256 = q.snapshot().identity().unwrap();
	p.max_equation_error = 1e-7;
	assert!(edit::compile(&q, &p).is_err());
}
#[test]
fn tiny_nonzero_edit_cannot_hide_outside_radius_by_squared_norm_underflow() {
	let (s, _, _) = fixture(EditDomain::BeliefOnly, None);
	let mut p = program(
		&s,
		vec![ReadoutEquation::BeliefLogit {
			input: input(0.),
			target: 2e-200,
		}],
	);
	p.ridge = 1.;
	p.radius_l2 = 1e-250;
	p.max_equation_error = 1.;
	assert!(edit::compile(&s, &p).is_err());
	assert!(stable_l2([1e-200_f64].into_iter()) > 1e-250);
}
#[test]
fn causal_controls_preserve_actual_encoded_mask_and_norm() {
	let head: Vec<_> = (0..196).map(|i| ((i % 11) as f64 - 5.) * 0.001).collect();
	let (s, _, _) = fixture(EditDomain::ContinuationOnly, Some(&head));
	let p = program(
		&s,
		vec![ReadoutEquation::ContinuationScore {
			row: 0,
			input: input(0.5),
			target: 1.,
		}],
	);
	let c = edit::compile(&s, &p).unwrap();
	let controls = super::causal::controls(&s, &p, &[11, 23, 37, 53]).unwrap();
	assert_eq!(controls.arms.len(), 8);
	assert!(controls.arms[0].edits.is_empty());
	assert_eq!(
		controls.arms[1].candidate_head_le_hex,
		c.candidate_head_le_hex
	);
	for random in &controls.arms[4..] {
		assert!((random.delta_l2 / c.delta_l2 - 1.).abs() < 1e-12);
		assert!(random
			.edits
			.iter()
			.all(|e| s.snapshot().domain.permits(e.index)));
	}
	let permutation: Vec<_> = (0..48).rev().collect();
	let probe = super::causal::equivalent_coordinate_probe(&s, &input(0.5), &permutation).unwrap();
	assert!(probe.max_logit_error < 1e-12);
	assert_eq!(probe.max_hidden_error, 0.);
	assert!(probe.broken_wiring_logit_difference > 1e-4);
	assert!(super::causal::controls(&s, &p, &[11, 11, 37, 53]).is_err());
}
#[test]
fn unrepresentable_matched_norm_control_is_rejected_instead_of_mislabeled() {
	let mut head = vec![1e20; 196];
	head[192..].fill(0.);
	let (s, _, _) = fixture(EditDomain::ContinuationOnly, Some(&head));
	let p = program(
		&s,
		vec![ReadoutEquation::ContinuationScore {
			row: 0,
			input: input(0.),
			target: 1.,
		}],
	);
	assert!(edit::compile(&s, &p).is_ok());
	assert!(super::causal::controls(&s, &p, &[11, 23, 37, 53]).is_err());
}

#[test]
fn matched_norm_tolerance_cannot_relax_the_hard_radius() {
	let (s, _, _) = fixture(EditDomain::JointReadout, None);
	let mut p = program(
		&s,
		vec![ReadoutEquation::BeliefLogit {
			input: input(0.),
			target: 2.,
		}],
	);
	p.ridge = 3.;
	p.max_equation_error = 2.;
	p.radius_l2 = 0.5;
	assert_eq!(edit::compile(&s, &p).unwrap().delta_l2(), 0.5);
	assert!(super::causal::controls(&s, &p, &[11, 23, 37, 53]).is_err());
}

#[test]
fn prepared_handoff_commits_whole_candidate_and_rejects_source_changes() {
	use super::coordinator::{self, Preparation};
	let (s, bytes, _) = fixture(EditDomain::ContinuationOnly, None);
	let mut p = program(
		&s,
		vec![ReadoutEquation::ContinuationScore {
			row: 0,
			input: input(0.),
			target: 4.,
		}],
	);
	p.ridge = 3.;
	p.max_equation_error = 3.;
	let source_path = std::path::Path::new("/isolated/source.safetensors");
	let evaluator_source = b"separate evaluator implementation";
	let prepared = coordinator::prepare(Preparation {
		authenticated: &s,
		program: &p,
		source_bytes: &bytes,
		source_path,
		evaluator_source,
	})
	.unwrap();
	let mut expected = bytes.clone();
	let offset = 8 + u64::from_le_bytes(bytes[..8].try_into().unwrap()) as usize + 192 * 8;
	expected[offset..offset + 8].copy_from_slice(&1_f64.to_le_bytes());
	assert_eq!(prepared.intent().candidate_sha256, digest(&expected));
	assert_eq!(prepared.intent().source_sha256, digest(&bytes));
	assert_eq!(
		prepared.intent().task_sha256,
		s.snapshot().evaluation_contract_sha256
	);
	assert_eq!(prepared.intent().owner_request["edits"][0]["index"], 192);
	let mut changed = bytes.clone();
	changed[offset] ^= 1;
	assert!(coordinator::prepare(Preparation {
		authenticated: &s,
		program: &p,
		source_bytes: &changed,
		source_path,
		evaluator_source
	})
	.is_err());
}

#[test]
fn planner_handoff_cannot_publish_when_probe_or_stop_wins() {
	use super::coordinator::{self, Preparation};
	let (s, bytes, _) = fixture(EditDomain::ContinuationOnly, None);
	let p = program(
		&s,
		vec![ReadoutEquation::ContinuationScore {
			row: 0,
			input: input(0.),
			target: 1.,
		}],
	);
	let request = || Preparation {
		authenticated: &s,
		program: &p,
		source_bytes: &bytes,
		source_path: std::path::Path::new("/isolated/source.safetensors"),
		evaluator_source: b"independent evaluator",
	};
	let law = information_law();
	assert!(coordinator::prepare_selected_analytic(
		request(),
		&law,
		Budget {
			compute: 5,
			feedback: 2
		},
		"edit"
	)
	.is_err());
	assert!(coordinator::prepare_selected_analytic(
		request(),
		&law,
		Budget {
			compute: 0,
			feedback: 0
		},
		"edit"
	)
	.is_err());
	assert!(coordinator::prepare_selected_analytic(
		request(),
		&law,
		Budget {
			compute: 3,
			feedback: 2
		},
		"wrong-action"
	)
	.is_err());
	let prepared = coordinator::prepare_selected_analytic(
		request(),
		&law,
		Budget {
			compute: 3,
			feedback: 2,
		},
		"edit",
	)
	.unwrap();
	assert!(matches!(prepared.plan.first_choice, Choice::Execute { id, .. } if id == "edit"));
	assert!(prepared
		.prepared
		.transaction_id()
		.unwrap()
		.starts_with("wtx1_"));
}

fn outcome(p: f64, next: usize, id: &str) -> Outcome {
	Outcome {
		probability: p,
		next_state: next,
		observation: id.into(),
	}
}
fn action(
	id: &str,
	kind: ActionKind,
	compute: u32,
	feedback: u32,
	cost: f64,
	outcomes: Vec<Outcome>,
) -> Action {
	Action {
		id: id.into(),
		kind,
		resource_cost: Budget { compute, feedback },
		utility_cost: cost,
		outcomes,
	}
}

fn information_law() -> FiniteLaw {
	let mut states = Vec::new();
	for (i, phase, gain) in [
		(0, Phase::Unmodified, 0.),
		(1, Phase::Unmodified, 0.),
		(2, Phase::Unmodified, 0.),
		(3, Phase::UnverifiedCandidate, 0.),
		(4, Phase::UnverifiedCandidate, 0.),
		(5, Phase::UnverifiedCandidate, 0.),
		(6, Phase::VerifiedCandidate, 0.4),
		(7, Phase::VerifiedCandidate, -0.2),
		(8, Phase::VerifiedCandidate, 0.2),
	] {
		states.push(DecisionState {
			id: format!("s{i}"),
			phase,
			verified_use_gain: gain,
			actions: vec![],
		});
	}
	states[0].actions = vec![
		action(
			"probe",
			ActionKind::Probe,
			1,
			1,
			0.02,
			vec![outcome(0.5, 1, "A"), outcome(0.5, 2, "B")],
		),
		action(
			"edit",
			ActionKind::AnalyticEdit,
			2,
			0,
			0.03,
			vec![outcome(1., 3, "edited")],
		),
		action(
			"train",
			ActionKind::LocalTrain,
			3,
			0,
			0.06,
			vec![outcome(1., 5, "trained")],
		),
	];
	states[1].actions = vec![action(
		"edit",
		ActionKind::AnalyticEdit,
		2,
		0,
		0.03,
		vec![outcome(1., 4, "edited")],
	)];
	states[2].actions = vec![action(
		"train",
		ActionKind::LocalTrain,
		3,
		0,
		0.06,
		vec![outcome(1., 5, "trained")],
	)];
	states[3].actions = vec![action(
		"verify",
		ActionKind::Verify,
		1,
		1,
		0.02,
		vec![outcome(0.5, 6, "good"), outcome(0.5, 7, "bad")],
	)];
	states[4].actions = vec![action(
		"verify",
		ActionKind::Verify,
		1,
		1,
		0.02,
		vec![outcome(1., 6, "good")],
	)];
	states[5].actions = vec![action(
		"verify",
		ActionKind::Verify,
		1,
		1,
		0.02,
		vec![outcome(1., 8, "gain")],
	)];
	FiniteLaw {
		schema: "hepta.finite-edit-law.v1".into(),
		cost_unit: "synthetic_task_utility".into(),
		information_scope: "known two-type process, not market data".into(),
		initial_state: 0,
		states,
	}
}

#[test]
fn bellman_values_information_and_switches_with_resource_budget() {
	let law = information_law();
	let p = planner::solve(
		&law,
		Budget {
			compute: 5,
			feedback: 2,
		},
		None,
	)
	.unwrap();
	assert!((p.expected_net_gain - 0.215).abs() < 1e-12);
	assert!(matches!(p.first_choice,Choice::Execute{id,..} if id=="probe"));
	let short = planner::solve(
		&law,
		Budget {
			compute: 3,
			feedback: 2,
		},
		None,
	)
	.unwrap();
	assert!((short.expected_net_gain - 0.15).abs() < 1e-12);
	assert!(matches!(short.first_choice,Choice::Execute{id,..} if id=="edit"));
	let one_feedback = planner::solve(
		&law,
		Budget {
			compute: 5,
			feedback: 1,
		},
		None,
	)
	.unwrap();
	assert!((one_feedback.expected_net_gain - 0.15).abs() < 1e-12);
	let zero = planner::solve(
		&law,
		Budget {
			compute: 0,
			feedback: 0,
		},
		None,
	)
	.unwrap();
	assert_eq!(zero.first_choice, Choice::Stop);
	assert_eq!(zero.expected_net_gain, 0.);
	let allowed = BTreeSet::from([
		ActionKind::AnalyticEdit,
		ActionKind::LocalTrain,
		ActionKind::Verify,
	]);
	let greedy = planner::solve(
		&law,
		Budget {
			compute: 5,
			feedback: 2,
		},
		Some(&allowed),
	)
	.unwrap();
	assert!((greedy.expected_net_gain - 0.15).abs() < 1e-12);
}

#[test]
fn high_information_price_and_verification_price_can_stop_exploration() {
	let mut law = information_law();
	law.states[0].actions[0].utility_cost = 0.2;
	let plan = planner::solve(
		&law,
		Budget {
			compute: 5,
			feedback: 2,
		},
		None,
	)
	.unwrap();
	assert!((plan.expected_net_gain - 0.15).abs() < 1e-12);
	for state in &mut law.states {
		for action in &mut state.actions {
			if action.kind == ActionKind::Verify {
				action.utility_cost = 1.;
			}
		}
	}
	let plan = planner::solve(
		&law,
		Budget {
			compute: 5,
			feedback: 2,
		},
		None,
	)
	.unwrap();
	assert_eq!(plan.first_choice, Choice::Stop);
}

#[test]
fn invalid_probabilities_free_cycles_and_unverified_adoption_are_rejected() {
	let mut law = information_law();
	law.states[0].actions[0].outcomes[0].probability = 0.1;
	assert!(law.validate().is_err());
	let mut law = information_law();
	law.states[0].actions[0].resource_cost.compute = 0;
	assert!(law.validate().is_err());
	let mut law = information_law();
	law.states[3].verified_use_gain = 0.1;
	assert!(law.validate().is_err());
	let mut law = information_law();
	law.states[0].actions[1].outcomes[0].next_state = 6;
	assert!(law.validate().is_err());
	let mut law = information_law();
	law.states[0].actions[0].utility_cost = f64::NAN;
	assert!(law.validate().is_err());
}
