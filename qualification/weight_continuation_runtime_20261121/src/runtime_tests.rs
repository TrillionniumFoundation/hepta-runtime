// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Synthetic adversarial contracts plus native execution and restoration cases.

use crate::gate::*;
use crate::policy::*;
use crate::session::*;
use crate::source::*;
use crate::task::*;
use hepta_semantic_source_adapter_study::{digest, SourcePin};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

fn pin(bytes: &[u8]) -> SourcePin {
	SourcePin {
		source_id: "explicit-synthetic-test-fixture".into(),
		sha256: digest(bytes),
		size_bytes: bytes.len() as u64,
	}
}

fn synthetic() -> VerifiedSource {
	let mut matrix = vec![vec![0.0; 33]; 33];
	for (i, row) in matrix.iter_mut().enumerate() {
		row[i] = 1.0;
	}
	synthetic_source(StoredLaw {
		coordinates: (0..31)
			.map(|i| -0.9375 + f64::from(i) / 16.0)
			.chain([-1.0, 1.0])
			.collect(),
		confusion: [[0.98, 0.02], [0.02, 0.98]],
		tables: vec![Table {
			duration: 1.0,
			drive: 0,
			matrix,
		}],
	})
}

fn make_capsule(failure_probability: f64) -> Capsule {
	let source = synthetic();
	let public = Public {
		schema: "joint-current-at-due-fixed-deadline-v1".into(),
		id: "synthetic-policy-contract".into(),
		deadline: 6,
		target_tick: 6,
		initial_budget: 3,
		duration: [1.0; 6],
		drive: [0; 6],
		reliability: [0.9; 6],
		read_price: [0.02; 6],
		read_delay: [1, 2, 1, 2, 1, 1],
		packets: std::array::from_fn(|i| format!("unused_{i}.json")),
		packet_sha256: std::array::from_fn(|_| "0".repeat(64)),
		latency_price: 0.001,
		repair_price: 0.015,
		failure_probability,
		prior_distance: 0.375,
	};
	let mut states = Vec::new();
	let mut indices = BTreeMap::new();
	let mut pending = vec![initial(&public).unwrap()];
	while let Some(state) = pending.pop() {
		let key = state_identity(&state).unwrap();
		if indices.contains_key(&key) {
			continue;
		}
		indices.insert(key, states.len());
		states.push(state.clone());
		for action in 1..4 {
			if legal(&public, &state)[action] {
				for completion in completions(&public, &state, action).unwrap() {
					pending.push(successor(&public, &state, action, completion).unwrap());
				}
			}
		}
	}
	let n = states.len();
	let mut edges = Vec::new();
	let posterior: Vec<_> = states
		.iter()
		.map(|s| source.law.posterior(&public, s).unwrap())
		.collect();
	let masks: Vec<_> = states.iter().map(|s| legal(&public, s)).collect();
	for (i, state) in states.iter().enumerate() {
		let mut row: [Vec<Edge>; 6] = std::array::from_fn(|_| Vec::new());
		for action in 1..4 {
			if masks[i][action] {
				for completion in completions(&public, state, action).unwrap() {
					let after = successor(&public, state, action, completion).unwrap();
					row[action].push(Edge {
						probability: source.law.probability(&public, state, completion).unwrap(),
						target: indices[&state_identity(&after).unwrap()],
						fee: after.charges - state.charges,
						completion,
					});
				}
			}
		}
		edges.push(row);
	}
	let mut order: Vec<_> = (0..n).collect();
	order.sort_by_key(|i| states[*i].tick);
	let mut values = vec![0.0; n];
	let mut q_values = vec![[0.0; 6]; n];
	let mut actions = vec![0; n];
	for &i in order.iter().rev() {
		q_values[i][4] = 1.0 - 2.0 * posterior[i];
		q_values[i][5] = 2.0 * posterior[i] - 1.0;
		for action in 1..4 {
			for edge in &edges[i][action] {
				if edge.probability != 0.0 {
					q_values[i][action] += edge.probability * (values[edge.target] - edge.fee);
				}
			}
		}
		let mut best = 0;
		for a in 1..6 {
			if masks[i][a] && q_values[i][a] > q_values[i][best] {
				best = a;
			}
		}
		actions[i] = best;
		values[i] = q_values[i][best];
	}
	let mut reached = BTreeSet::new();
	let mut pending = vec![0];
	while let Some(i) = pending.pop() {
		if reached.insert(i) {
			for edge in &edges[i][actions[i]] {
				pending.push(edge.target);
			}
		}
	}
	let public_key = serde_json::to_string(&public).unwrap();
	Capsule {
		schema: "hepta-own-law-policy-capsule-v1".into(),
		bindings: Bindings {
			compressed_sha256: source.receipt.compressed_sha256,
			decoded_sha256: source.receipt.decoded_sha256,
			task_code_sha256: TASK_SHA256.into(),
			planning_code_sha256: PLANNING_SHA256.into(),
			compiler_code_sha256: digest(b"synthetic compiler"),
			public_sha256: digest(public_key.as_bytes()),
		},
		state_keys: states
			.iter()
			.map(|s| serde_json::to_string(s).unwrap())
			.collect(),
		public,
		public_key,
		initial: 0,
		states,
		legal_masks: masks,
		posterior,
		edges,
		q_values,
		actions,
		order,
		policy_reachable: reached.into_iter().collect(),
	}
}

fn capsule() -> Capsule {
	static FIXTURE: OnceLock<Capsule> = OnceLock::new();
	FIXTURE.get_or_init(|| make_capsule(0.2)).clone()
}
fn verify(capsule: &Capsule) -> anyhow::Result<VerifiedPolicy> {
	let bytes = serde_json::to_vec(capsule)?;
	verify_policy(
		&synthetic(),
		&bytes,
		&pin(&bytes),
		b"synthetic compiler",
		&pin(b"synthetic compiler"),
		Limits::default(),
	)
}
fn program() -> NativeProgram {
	verify(&capsule()).unwrap().compile_sparse().unwrap()
}

#[test]
fn lawful_capsule_executes_every_selected_observation_and_restores() {
	let policy = verify(&capsule()).unwrap();
	assert_eq!(policy.receipt().posterior_max_abs_error, 0.0);
	let program = policy.compile_sparse().unwrap();
	assert_eq!(
		program
			.selected_action(&initial(program.public()).unwrap())
			.unwrap(),
		2
	);
	assert!(program.state_count() < policy.receipt().states);
	let replay = exercise_every_selected_step(&program).unwrap();
	assert!(
		replay.executed_edges > 0 && replay.terminal_states > 0 && replay.snapshots_restored > 0
	);
	assert_eq!(
		policy.restore_sparse(program.bytes()).unwrap().sha256(),
		program.sha256()
	);
}

#[test]
fn caller_q_values_cannot_authenticate_themselves() {
	let mut c = capsule();
	c.q_values[0][2] += 1e-12;
	assert!(verify(&c).unwrap_err_text().contains("Q witness"));
}

#[test]
fn false_probability_is_rejected_even_if_normalized() {
	let mut c = capsule();
	c.edges[0][2][1].probability += 0.01;
	c.edges[0][2][2].probability -= 0.01;
	assert!(verify(&c)
		.unwrap_err_text()
		.contains("probability not derived"));
}

#[test]
fn false_posterior_cannot_define_its_own_bellman_targets() {
	let mut c = capsule();
	c.posterior[0] += 0.01;
	assert!(verify(&c)
		.unwrap_err_text()
		.contains("posterior not derived"));
}

#[test]
fn altered_complete_state_and_unknown_state_are_rejected() {
	let mut c = capsule();
	c.states[1].charges += 0.001;
	c.state_keys[1] = serde_json::to_string(&c.states[1]).unwrap();
	assert!(verify(&c).is_err());
	let p = program();
	let mut s = initial(p.public()).unwrap();
	s.charges = 0.00001;
	assert!(p.selected_action(&s).is_err());
}

#[test]
fn initial_negative_zero_charges_do_not_equal_original_state_bytes() {
	let mut c = capsule();
	c.states[c.initial].charges = -0.0;
	c.state_keys[c.initial] = serde_json::to_string(&c.states[c.initial]).unwrap();
	assert!(verify(&c).unwrap_err_text().contains("initial state"));
}

#[test]
fn changed_masks_order_and_policy_closure_are_rejected() {
	let mut c = capsule();
	c.legal_masks[0][3] = true;
	assert!(verify(&c).is_err());
	let mut c = capsule();
	c.order.swap(0, 1);
	assert!(verify(&c).is_err());
	let mut c = capsule();
	c.policy_reachable.pop();
	assert!(verify(&c).is_err());
}

#[test]
fn wrong_checkpoint_compiler_and_task_bindings_are_rejected() {
	for field in [0, 1, 2] {
		let mut c = capsule();
		match field {
			0 => c.bindings.compressed_sha256 = "a".repeat(64),
			1 => c.bindings.compiler_code_sha256 = "a".repeat(64),
			_ => c.bindings.task_code_sha256 = "a".repeat(64),
		}
		assert!(verify(&c).is_err());
	}
}

#[test]
fn bounds_reject_before_any_execution() {
	let c = capsule();
	let bytes = serde_json::to_vec(&c).unwrap();
	for limits in [
		Limits {
			max_states: c.states.len() - 1,
			..Limits::default()
		},
		Limits {
			max_edges: 1,
			..Limits::default()
		},
		Limits {
			max_matrix_products: 1,
			..Limits::default()
		},
		Limits {
			max_artifact_bytes: bytes.len() - 1,
			..Limits::default()
		},
	] {
		assert!(verify_policy(
			&synthetic(),
			&bytes,
			&pin(&bytes),
			b"synthetic compiler",
			&pin(b"synthetic compiler"),
			limits
		)
		.is_err());
	}
}

#[test]
fn unknown_schema_and_duplicate_json_keys_are_rejected() {
	let mut c = capsule();
	c.schema = "trust-me".into();
	assert!(verify(&c).is_err());
	let bytes = br#"{"schema":"first","schema":"second"}"#;
	assert!(verify_policy(
		&synthetic(),
		bytes,
		&pin(bytes),
		b"synthetic compiler",
		&pin(b"synthetic compiler"),
		Limits::default()
	)
	.is_err());
}

#[test]
fn zero_probability_branches_cannot_be_silently_removed() {
	let mut c = make_capsule(0.0);
	assert!(verify(&c).is_ok());
	let removed = c.edges[0][2].remove(0);
	assert_eq!(removed.probability, 0.0);
	assert_eq!(removed.completion.kind, CompletionKind::Failure);
	assert!(verify(&c).is_err());
}

#[test]
fn equal_terminal_scores_require_lowest_action_index() {
	let mut c = capsule();
	let index = c
		.states
		.iter()
		.position(|s| s.tick == 6 && s.history.is_empty())
		.unwrap();
	assert_eq!(c.q_values[index][0], c.q_values[index][4]);
	assert_eq!(c.actions[index], 0);
	c.actions[index] = 4;
	assert!(verify(&c).unwrap_err_text().contains("lowest-index"));
}

#[test]
fn repair_does_not_reset_latent_history_or_budget() {
	let public = capsule().public;
	let s = successor(
		&public,
		&initial(&public).unwrap(),
		2,
		Completion::failure(1),
	)
	.unwrap();
	assert!(s.broken);
	assert_eq!(s.budget, 2);
	let after = successor(&public, &s, 3, Completion::none()).unwrap();
	assert!(!after.broken);
	assert_eq!(after.budget, 2);
	assert_eq!(after.history, s.history);
	assert_eq!(after.tick, 2);
	assert_eq!(
		after.charges,
		s.charges + public.repair_price + public.latency_price
	);
}

#[test]
fn delayed_read_observes_completion_boundary_only() {
	let public = capsule().public;
	let s = successor(&public, &initial(&public).unwrap(), 1, Completion::none()).unwrap();
	let waiting = successor(&public, &s, 2, Completion::none()).unwrap();
	assert_eq!(waiting.pending.as_ref().unwrap().due_tick, 3);
	assert!(successor(&public, &waiting, 1, Completion::observation(2, 1)).is_err());
	let after = successor(&public, &waiting, 1, Completion::observation(3, 1)).unwrap();
	assert_eq!(after.history[0].source_tick, 1);
	assert_eq!(after.history[0].observation_tick, 3);
}

#[test]
fn failed_step_and_exhausted_budget_preserve_exact_snapshot_bytes() {
	let p = program();
	let mut session = Session::start(&p, 7).unwrap();
	let before = session.snapshot_bytes().unwrap();
	assert!(session
		.step(&p, p.public(), Completion::observation(2, 0))
		.is_err());
	assert_eq!(session.snapshot_bytes().unwrap(), before);
	let mut session = Session::start(&p, 0).unwrap();
	let before = session.snapshot_bytes().unwrap();
	assert!(session
		.step(&p, p.public(), Completion::failure(1))
		.is_err());
	assert_eq!(session.snapshot_bytes().unwrap(), before);
}

#[test]
fn altered_schedule_snapshot_and_saved_program_are_rejected() {
	let policy = verify(&capsule()).unwrap();
	let p = policy.compile_sparse().unwrap();
	let mut session = Session::start(&p, 7).unwrap();
	let mut schedule = p.public().clone();
	schedule.id.push('x');
	assert!(session.step(&p, &schedule, Completion::failure(1)).is_err());
	let mut saved: serde_json::Value =
		serde_json::from_slice(&session.snapshot_bytes().unwrap()).unwrap();
	saved["state"]["charges"] = 9.0.into();
	let bytes = serde_json::to_vec(&saved).unwrap();
	assert!(Session::restore(&p, &bytes, &pin(&bytes)).is_err());
	let mut bytes = p.bytes().to_vec();
	bytes[10] ^= 1;
	assert!(policy.restore_sparse(&bytes).is_err());
}

fn evaluation(p: &NativeProgram) -> EvaluationContract {
	EvaluationContract {
		schema: "hepta.finite-continuation-evaluation.v1".into(),
		program_sha256: p.sha256().into(),
		checkpoint_sha256: p.checkpoint_sha256().into(),
		workload_sha256: digest(b"synthetic workload"),
		freeze_receipt_sha256: digest(b"synthetic freeze"),
		confirmation_receipt_sha256: digest(b"synthetic confirmation"),
		freeze_sequence: 1,
		confirmation_sequence: 2,
		bound_kind: "owner_pinned_future".into(),
		quality_mode: QualityMode::StrictImprovement,
		quality_threshold: 0.0,
		quality_delta_lower: Some(0.1),
		calibration_delta_upper: Some(0.0),
		calibration_budget: 0.0001,
		horizon_calls: Some(100),
		resources: vec![ResourceBound {
			resource: "cpu".into(),
			unit: "seconds".into(),
			lambda_utility_per_unit: Some(0.1),
			baseline_future_lower: Some(2.0),
			candidate_future_upper: Some(1.0),
		}],
	}
}

fn decide(p: &NativeProgram, e: &EvaluationContract) -> GateDecision {
	let bytes = serde_json::to_vec(e).unwrap();
	evaluate_contract(p, &bytes, &pin(&bytes)).unwrap()
}

#[test]
fn native_ndu_can_keep_and_can_save_only_isolated_candidate() {
	let source = synthetic();
	let p = program();
	let d = decide(&p, &evaluation(&p));
	assert!(d.save_isolated_candidate());
	let mut slot = ResearchByteSlot::new(&source);
	slot.stage(&p).unwrap();
	assert_ne!(slot.active_bytes(), source.checkpoint_bytes());
	let (saved, restored) = slot.finish(&p, &d, true).unwrap();
	assert_eq!(saved.unwrap(), p.bytes());
	assert!(restored.original_bytes_exact);
	assert_eq!(slot.active_bytes(), source.checkpoint_bytes());
	let keep = keep_unknown(&p, "no owner future bound");
	slot.stage(&p).unwrap();
	assert!(slot.finish(&p, &keep, true).unwrap().0.is_none());
	assert_eq!(slot.active_bytes(), source.checkpoint_bytes());
}

#[test]
fn native_ndu_stops_for_unknown_cost_negative_value_or_unqualified_empirical_bounds() {
	let p = program();
	let mut e = evaluation(&p);
	e.resources[0].lambda_utility_per_unit = None;
	assert!(!decide(&p, &e).save_isolated_candidate());
	let mut e = evaluation(&p);
	e.resources[0].candidate_future_upper = Some(1000.0);
	assert!(!decide(&p, &e).save_isolated_candidate());
	let mut e = evaluation(&p);
	e.bound_kind = "empirical_finite_workload".into();
	assert!(!decide(&p, &e).save_isolated_candidate());
	let mut e = evaluation(&p);
	e.horizon_calls = None;
	assert!(!decide(&p, &e).save_isolated_candidate());
	let mut e = evaluation(&p);
	e.calibration_delta_upper = Some(0.01);
	assert!(!decide(&p, &e).save_isolated_candidate());
}

#[test]
fn execution_failure_rolls_back_even_when_quality_gate_passes() {
	let source = synthetic();
	let p = program();
	let decision = decide(&p, &evaluation(&p));
	let mut slot = ResearchByteSlot::new(&source);
	slot.stage(&p).unwrap();
	let (candidate, receipt) = slot.finish(&p, &decision, false).unwrap();
	assert!(candidate.is_none());
	assert!(receipt.original_bytes_exact);
	source.verify_unchanged(slot.active_bytes()).unwrap();
}

#[test]
fn staged_old_bytes_cannot_be_overwritten_twice() {
	let source = synthetic();
	let p = program();
	let mut slot = ResearchByteSlot::new(&source);
	slot.stage(&p).unwrap();
	assert!(slot.stage(&p).is_err());
	let (_, receipt) = slot.finish(&p, &keep_unknown(&p, "stop"), false).unwrap();
	assert!(receipt.original_bytes_exact);
}

#[test]
fn callback_error_automatically_restores_anchor_without_manual_finish() {
	let source = synthetic();
	let p = program();
	let decision = decide(&p, &evaluation(&p));
	let mut slot = ResearchByteSlot::new(&source);
	let run = slot
		.run(&p, &decision, || {
			let mut session = Session::start(&p, 0)?;
			session.step(&p, p.public(), Completion::failure(1))
		})
		.unwrap();
	assert!(run.execution.is_err());
	assert!(run.candidate.is_none());
	assert!(run.restoration.original_bytes_exact);
	assert_eq!(slot.active_bytes(), source.checkpoint_bytes());
}

#[test]
fn unwinding_callback_also_restores_owned_research_bytes() {
	let source = synthetic();
	let p = program();
	let mut slot = ResearchByteSlot::new(&source);
	let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
		let _ = slot.run(&p, &keep_unknown(&p, "stop"), || -> anyhow::Result<()> {
			panic!("synthetic evaluator panic")
		});
	}));
	assert!(result.is_err());
	assert_eq!(slot.active_bytes(), source.checkpoint_bytes());
}

trait ErrorText {
	fn unwrap_err_text(self) -> String;
}
impl<T> ErrorText for anyhow::Result<T> {
	fn unwrap_err_text(self) -> String {
		match self {
			Ok(_) => panic!("expected rejection"),
			Err(error) => error.to_string(),
		}
	}
}
