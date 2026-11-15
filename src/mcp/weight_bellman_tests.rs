// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Finite-DAG recurrence, ordered arithmetic, malformed graph and admission tests.

use super::*;

fn terminal(value: f64) -> Option<BellmanAction> {
	Some(BellmanAction::Terminal { value })
}

fn state(value: f64) -> BellmanState {
	BellmanState {
		actions: [terminal(value), None, None, None, None, None],
	}
}

fn branch(probability: f64, successor: u32, reward: f64, fee: f64) -> BellmanBranch {
	BellmanBranch {
		probability,
		successor,
		reward,
		fee,
	}
}

fn continuation(branches: Vec<BellmanBranch>) -> Option<BellmanAction> {
	Some(BellmanAction::Continue { branches })
}

fn known() -> BellmanPlanParams {
	BellmanPlanParams {
		states: vec![
			state(2.0),
			BellmanState {
				actions: [terminal(0.0), None, None, None, None, terminal(4.0)],
			},
			BellmanState {
				actions: [
					terminal(0.0),
					continuation(vec![branch(0.25, 0, 0.0, 0.5), branch(0.75, 1, 0.0, 0.5)]),
					None,
					None,
					None,
					None,
				],
			},
			BellmanState {
				actions: [
					terminal(3.0),
					None,
					terminal(3.0),
					continuation(vec![branch(1.0, 2, 1.0, 0.25)]),
					None,
					None,
				],
			},
		],
	}
}

#[test]
fn known_dag_selects_finite_global_continuations_in_fixed_action_order() {
	let result = solve(&known()).unwrap();
	assert_eq!(result["action_names"], json!(ACTION_NAMES));
	assert_eq!(result["states"][0]["value"], 2.0);
	assert_eq!(result["states"][1]["action"], 5);
	assert_eq!(result["states"][2]["q"][1], 3.0);
	assert_eq!(result["states"][2]["value"], 3.0);
	assert_eq!(result["states"][2]["action"], 1);
	assert_eq!(result["states"][3]["value"], 3.75);
	assert_eq!(result["states"][3]["action"], 3);
	assert!(result["states"][3]["q"][1].is_null());
	assert_eq!(result["maximum_self_consistency_residual_f64"], 0.0);
	assert_eq!(result["maximum_probability_sum_error_f64"], 0.0);
	assert_eq!(result["state_count"], 4);
	assert_eq!(result["branch_count"], 3);
	assert_eq!(result["gradient_steps"], 0);
	for flag in [
		"training_targets_used",
		"checkpoint_verified",
		"environment_law_verified",
		"real_arithmetic_optimality_certified",
		"independent_holdout_verified",
		"production_eligible",
		"self_consistency_is_numerical_error_bound",
	] {
		assert_eq!(result[flag], false, "{flag}");
	}
}

#[test]
fn exact_ties_choose_first_legal_and_near_ties_never_override_strict_maximum() {
	let params = BellmanPlanParams {
		states: vec![
			BellmanState {
				actions: [
					None,
					terminal(-2.0),
					terminal(-2.0),
					None,
					terminal(-3.0),
					None,
				],
			},
			BellmanState {
				actions: [
					terminal(1.0),
					terminal(1.0_f64.next_up()),
					None,
					None,
					None,
					None,
				],
			},
			BellmanState {
				actions: [terminal(-0.0), terminal(0.0), None, None, None, None],
			},
		],
	};
	let result = solve(&params).unwrap();
	assert_eq!(result["states"][0]["action"], 1);
	assert_eq!(result["states"][0]["value"], -2.0);
	assert_eq!(result["states"][1]["action"], 1);
	assert_eq!(result["states"][2]["action"], 0);
	assert_eq!(result["exact_tie_state_count"], 2);
	assert_eq!(result["near_tie_state_count"], 3);
	assert_eq!(result["minimum_relative_action_gap_f64"], 0.0);
}

#[test]
fn fees_remain_inside_each_multiplication_and_probabilities_are_not_normalized() {
	let p = 0.7500000000001;
	let params = BellmanPlanParams {
		states: vec![
			state(1.0),
			state(5.0),
			BellmanState {
				actions: [
					None,
					continuation(vec![branch(0.25, 0, 0.0, 3.0), branch(p, 1, 0.0, 3.0)]),
					None,
					None,
					None,
					None,
				],
			},
		],
	};
	let result = solve(&params).unwrap();
	let q = result["states"][2]["q"][1].as_f64().unwrap();
	let ordered = 0.25 * (1.0 - 3.0) + p * (5.0 - 3.0);
	assert_eq!(q.to_bits(), ordered.to_bits());
	assert_ne!(q.to_bits(), (0.25 * 1.0 + p * 5.0 - 3.0).to_bits());
	assert_ne!(q.to_bits(), (ordered / (0.25 + p)).to_bits());
	assert!(
		result["maximum_probability_sum_error_f64"]
			.as_f64()
			.unwrap() > 0.0
	);
}

#[test]
fn branch_order_and_separate_f64_operations_are_observable() {
	let mut params = BellmanPlanParams {
		states: vec![
			state(0.0),
			BellmanState {
				actions: [
					None,
					continuation(vec![
						branch(0.25, 0, 4e16, 0.0),
						branch(0.25, 0, -4e16, 0.0),
						branch(0.5, 0, 2.0, 0.0),
					]),
					None,
					None,
					None,
					None,
				],
			},
		],
	};
	assert_eq!(solve(&params).unwrap()["states"][1]["value"], 1.0);
	if let Some(BellmanAction::Continue { branches }) = &mut params.states[1].actions[1] {
		branches.swap(1, 2);
	}
	assert_eq!(solve(&params).unwrap()["states"][1]["value"], 0.0);
}

#[test]
fn zero_probability_is_skipped_after_validation_but_still_charged() {
	let params = BellmanPlanParams {
		states: vec![
			state(f64::MAX),
			BellmanState {
				actions: [
					None,
					continuation(vec![
						branch(0.0, 0, f64::MAX, 0.0),
						branch(1.0, 0, 0.0, f64::MAX),
					]),
					None,
					None,
					None,
					None,
				],
			},
		],
	};
	let result = solve(&params).unwrap();
	assert_eq!(result["states"][1]["value"], 0.0);
	assert_eq!(result["zero_probability_branch_count"], 1);
	assert_eq!(result["branch_count"], 2);
	let mut invalid = params;
	if let Some(BellmanAction::Continue { branches }) = &mut invalid.states[1].actions[1] {
		branches[0].successor = 1;
	}
	assert!(solve(&invalid)
		.unwrap_err()
		.to_string()
		.contains("strictly precede"));
}

fn with_branch(value: BellmanBranch) -> BellmanPlanParams {
	BellmanPlanParams {
		states: vec![
			state(0.0),
			BellmanState {
				actions: [None, continuation(vec![value]), None, None, None, None],
			},
		],
	}
}

#[test]
fn malformed_graphs_values_and_probabilities_are_refused_before_results() {
	for params in [
		BellmanPlanParams { states: vec![] },
		BellmanPlanParams {
			states: vec![state(0.0); MAX_STATES + 1],
		},
		BellmanPlanParams {
			states: vec![BellmanState {
				actions: [None, None, None, None, None, None],
			}],
		},
		BellmanPlanParams {
			states: vec![state(f64::NAN)],
		},
		BellmanPlanParams {
			states: vec![state(f64::INFINITY)],
		},
		with_branch(branch(-1.0, 0, 0.0, 0.0)),
		with_branch(branch(0.0, 0, 0.0, 0.0)),
		with_branch(branch(1.0 + 2e-12, 0, 0.0, 0.0)),
		with_branch(branch(f64::NAN, 0, 0.0, 0.0)),
		with_branch(branch(f64::INFINITY, 0, 0.0, 0.0)),
		with_branch(branch(1.0, 0, f64::NAN, 0.0)),
		with_branch(branch(1.0, 0, 0.0, -0.1)),
		with_branch(branch(1.0, 0, 0.0, f64::INFINITY)),
		with_branch(branch(1.0, 1, 0.0, 0.0)),
		with_branch(branch(1.0, u32::MAX, 0.0, 0.0)),
	] {
		assert!(solve(&params).is_err(), "{params:?}");
	}
	for branches in [vec![], vec![branch(0.25, 0, 0.0, 0.0); 4]] {
		let params = BellmanPlanParams {
			states: vec![
				state(0.0),
				BellmanState {
					actions: [None, continuation(branches), None, None, None, None],
				},
			],
		};
		assert!(solve(&params)
			.unwrap_err()
			.to_string()
			.contains("1..3 branches"));
	}
	let action = continuation(vec![branch(1.0, 0, 0.0, 0.0)]);
	let params = BellmanPlanParams {
		states: vec![
			state(0.0),
			BellmanState {
				actions: [action.clone(), action.clone(), action, None, None, None],
			},
		],
	};
	assert!(solve(&params)
		.unwrap_err()
		.to_string()
		.contains("at most two"));
}

#[test]
fn overflow_is_refused_instead_of_serializing_nonfinite_q() {
	let params = BellmanPlanParams {
		states: vec![
			state(f64::MAX),
			BellmanState {
				actions: [
					None,
					continuation(vec![branch(1.0, 0, f64::MAX, 0.0)]),
					None,
					None,
					None,
					None,
				],
			},
		],
	};
	assert!(solve(&params)
		.unwrap_err()
		.to_string()
		.contains("finite arithmetic"));
	let mut params = with_branch(branch(1.0, 0, -f64::MAX, f64::MAX));
	assert!(solve(&params)
		.unwrap_err()
		.to_string()
		.contains("finite arithmetic"));
	if let Some(BellmanAction::Continue { branches }) = &mut params.states[1].actions[1] {
		*branches = vec![branch(f64::MAX, 0, 0.0, 0.0), branch(f64::MAX, 0, 0.0, 0.0)];
	}
	assert!(solve(&params)
		.unwrap_err()
		.to_string()
		.contains("probability sum"));
}

#[test]
fn canonical_identity_binds_graph_order_floats_and_implementation() {
	let params = known();
	let first = solve(&params).unwrap();
	let again = solve(&params).unwrap();
	assert_eq!(first["request_sha256"], again["request_sha256"]);
	assert_eq!(first["plan_id"], again["plan_id"]);
	assert_eq!(
		first["request_sha256"],
		hex(Sha256::digest(serde_json::to_vec(&params).unwrap()))
	);
	assert_eq!(
		first["implementation_source_sha256"],
		hex(Sha256::digest(include_bytes!("weight_bellman.rs")))
	);
	let mut changed = params;
	changed.states[0].actions[0] = terminal(2.0_f64.next_up());
	let different = solve(&changed).unwrap();
	assert_ne!(first["request_sha256"], different["request_sha256"]);
	assert_ne!(first["plan_id"], different["plan_id"]);
}

#[test]
fn schema_refuses_unknown_reference_fields_and_wrong_action_shapes() {
	let valid = serde_json::to_value(known()).unwrap();
	let mut extra = valid.clone();
	extra["truth"] = json!(1);
	assert!(serde_json::from_value::<BellmanPlanParams>(extra).is_err());
	let mut extra = valid.clone();
	extra["states"][0]["reference_q"] = json!([1, 2]);
	assert!(serde_json::from_value::<BellmanPlanParams>(extra).is_err());
	let mut extra = valid.clone();
	extra["states"][0]["actions"][0]["unexpected"] = json!(true);
	assert!(serde_json::from_value::<BellmanPlanParams>(extra).is_err());
	let mut wrong = valid;
	wrong["states"][0]["actions"] = json!([null]);
	assert!(serde_json::from_value::<BellmanPlanParams>(wrong).is_err());
	let params: BellmanPlanParams = serde_json::from_str("{\"states\":[{\"actions\":[{\"kind\":\"terminal\",\"value\":1.0000000000000002},null,null,null,null,null]}]}").unwrap();
	assert_eq!(
		solve(&params).unwrap()["states"][0]["value"]
			.as_f64()
			.unwrap()
			.to_bits(),
		1.0_f64.next_up().to_bits()
	);
}

#[test]
fn maximum_dimensions_and_canonical_byte_budget_are_explicit() {
	let mut states = vec![BellmanState {
		actions: std::array::from_fn(|_| terminal(0.0)),
	}];
	let action = continuation(vec![
		branch(0.0, 0, 0.0, 0.0),
		branch(0.0, 0, 0.0, 0.0),
		branch(1.0, 0, 0.0, 0.0),
	]);
	for _ in 1..MAX_STATES {
		states.push(BellmanState {
			actions: [
				terminal(0.0),
				action.clone(),
				action.clone(),
				terminal(0.0),
				terminal(0.0),
				terminal(0.0),
			],
		});
	}
	let params = BellmanPlanParams { states };
	let result = solve(&params).unwrap();
	assert_eq!(result["state_count"], MAX_STATES);
	assert_eq!(result["branch_count"], (MAX_STATES - 1) * 6);
	assert!(result["operation_charged_units"].as_u64().unwrap() <= MAX_WORK);
	assert!(result["request_bytes"].as_u64().unwrap() <= MAX_REQUEST_BYTES as u64);
	let mut commitment = Commitment {
		hash: Sha256::new(),
		bytes: MAX_REQUEST_BYTES - 1,
		end: Instant::now() + Duration::from_secs(1),
	};
	assert_eq!(commitment.write(b"a").unwrap(), 1);
	assert!(commitment
		.write(b"b")
		.unwrap_err()
		.to_string()
		.contains("8 MiB"));
}

#[test]
fn expired_deadline_is_refused_in_validation_and_serialization() {
	let end = Instant::now() - Duration::from_secs(1);
	assert!(validate(&known(), end)
		.unwrap_err()
		.to_string()
		.contains("deadline"));
	let mut commitment = Commitment {
		hash: Sha256::new(),
		bytes: 0,
		end,
	};
	assert_eq!(
		commitment.write(b"{}").unwrap_err().kind(),
		std::io::ErrorKind::TimedOut
	);
}

#[tokio::test]
#[serial_test::serial]
async fn async_public_api_returns_the_same_candidate_and_refuses_exhausted_capacity() {
	let params = known();
	let expected = solve(&params).unwrap();
	let actual: Value = serde_json::from_str(&plan(params.clone()).await.unwrap()).unwrap();
	assert_eq!(actual["states"], expected["states"]);
	assert_eq!(actual["plan_id"], expected["plan_id"]);
	let permits = PLANNERS.get_or_init(|| Arc::new(Semaphore::new(2))).clone();
	let held = permits.acquire_many_owned(2).await.unwrap();
	assert!(plan(params)
		.await
		.unwrap_err()
		.to_string()
		.contains("capacity exhausted"));
	drop(held);
}
