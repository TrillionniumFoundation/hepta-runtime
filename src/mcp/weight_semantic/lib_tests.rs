// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
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
//! Preserved standalone r2 causal, numeric and rejection controls.

use super::core::{replay, Completion, ReplayParams, Step, Trace, PROFILE};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

fn sha(data: &[u8]) -> String {
	Sha256::digest(data)
		.iter()
		.map(|b| format!("{b:02x}"))
		.collect()
}

pub(super) fn base() -> ReplayParams {
	let coords: Vec<f64> = (1..32)
		.map(|i| -1. + i as f64 / 16.)
		.chain([-1., 1.])
		.collect();
	let identity: Vec<Vec<f64>> = (0..33)
		.map(|i| (0..33).map(|j| if i == j { 1. } else { 0. }).collect())
		.collect();
	let model = json!({"schema":"joint-policy-v1","family":"renewal","fit":11,"public_dimensions":43,
		"head_dimensions":[85,48,4],"n_grid":31,"coordinates":coords,"confusion":[[0.75,0.25],[0.25,0.75]],
		"network":{"w1":vec![vec![0.;85];48],"b1":vec![0.;48],"w2":vec![vec![0.;48];4],"b2":vec![0.;4]},
		"core":{"kind":"full_distribution_ctmc","tables":[{"dt":1.,"drive":0,"matrix":identity}],
			"generators":null,"raw":null,"physical":null,"optimizer_constraint":null},"nominal_raw":null,"parameter_count":0,
		"target":"sign(X_deadline6)>0, including early submit; learned belief is not privileged posterior",
		"bank_semantics":"no-new-observation predictive state probability at next boundary, two boundaries and deadline6; thresholds normalized(-.5,0,.5), strict>; actual scheduled future drives and durations"});
	let public = json!({"schema":"joint-current-at-due-fixed-deadline-v1","id":"analytic-fixture","deadline":6,
		"target_tick":6,"initial_budget":3,"duration":vec![1.;6],"drive":vec![0;6],"reliability":vec![1.;6],
		"read_price":vec![0.;6],"read_delay":vec![1;6],"latency_price":0.,"repair_price":0.,
		"failure_probability":0.1,"prior_distance":0.375,"packets":vec!["unused";6],"packet_sha256":vec!["0".repeat(64);6]});
	let checkpoint_json = serde_json::to_string(&model).unwrap();
	let public_json = serde_json::to_string(&public).unwrap();
	ReplayParams {
		profile: PROFILE.into(),
		expected_checkpoint_sha256: sha(checkpoint_json.as_bytes()),
		expected_public_sha256: sha(public_json.as_bytes()),
		checkpoint_json,
		public_json,
		traces: vec![Trace {
			source_row: 0,
			steps: vec![],
		}],
	}
}

fn change_model(p: &mut ReplayParams, f: impl FnOnce(&mut Value)) {
	let mut v: Value = serde_json::from_str(&p.checkpoint_json).unwrap();
	f(&mut v);
	p.checkpoint_json = serde_json::to_string(&v).unwrap();
	p.expected_checkpoint_sha256 = sha(p.checkpoint_json.as_bytes());
}

fn read(y: Option<u8>, tick: usize) -> Step {
	Step {
		action: 2,
		completion: Some(Completion {
			observation_tick: tick,
			failure: y.is_none(),
			observation: y,
		}),
	}
}

fn wait() -> Step {
	Step {
		action: 1,
		completion: None,
	}
}

#[test]
fn known_bayes_posterior_and_terminal_values() {
	let mut p = base();
	p.traces[0].steps = vec![read(Some(1), 1), wait(), wait(), wait(), wait(), wait()];
	let r = replay(&p).unwrap();
	let row = &r.rows[0];
	assert_eq!(row.analytic_endpoint_belief, 0.75);
	assert_eq!(row.teacher_q, [0., 0., 0., 0., -0.5, 0.5]);
	assert_eq!(row.legal, [true, false, false, false, true, true]);
	assert_eq!(row.target_action, 5);
	assert_eq!(row.learned_belief, 0.5);
	assert!(
		r.hidden_program_reexecuted
			&& r.teacher_program_reexecuted
			&& !r.external_source_authenticated
	);
}

#[test]
fn repair_changes_sensor_not_identity_latent_law() {
	let mut p = base();
	p.traces = vec![
		Trace {
			source_row: 0,
			steps: vec![read(Some(1), 1), read(None, 2)],
		},
		Trace {
			source_row: 1,
			steps: vec![
				read(Some(1), 1),
				read(None, 2),
				Step {
					action: 3,
					completion: None,
				},
			],
		},
		Trace {
			source_row: 2,
			steps: vec![read(Some(1), 1), read(None, 2), wait()],
		},
	];
	let r = replay(&p).unwrap();
	assert!(r.rows[0].state.broken && !r.rows[1].state.broken && r.rows[2].state.broken);
	assert_eq!(r.rows[1].mass, r.rows[2].mass);
	assert_eq!(r.rows[1].bank, r.rows[2].bank);
	assert!(r.rows[1].legal[2] && !r.rows[2].legal[2]);
}

#[test]
fn delayed_read_is_current_at_due() {
	let mut p = base();
	let mut public: Value = serde_json::from_str(&p.public_json).unwrap();
	public["read_delay"][0] = json!(2);
	p.public_json = serde_json::to_string(&public).unwrap();
	p.expected_public_sha256 = sha(p.public_json.as_bytes());
	p.traces[0].steps = vec![
		Step {
			action: 2,
			completion: None,
		},
		Step {
			action: 1,
			completion: Some(Completion {
				observation_tick: 2,
				failure: false,
				observation: Some(1),
			}),
		},
	];
	let r = replay(&p).unwrap();
	let history = &r.rows[0].state.history;
	assert_eq!(history[0].source_tick, 0);
	assert_eq!(history[0].observation_tick, 2);
	p.traces[0].steps[1]
		.completion
		.as_mut()
		.unwrap()
		.observation_tick = 1;
	assert!(replay(&p)
		.unwrap_err()
		.to_string()
		.contains("current-at-due"));
}

#[test]
fn unauthorized_or_contradictory_inputs_rejected() {
	let mut p = base();
	p.expected_checkpoint_sha256 = "0".repeat(64);
	assert!(replay(&p).is_err());
	let mut p = base();
	p.profile = "first-passage".into();
	assert!(replay(&p).is_err());
	let mut p = base();
	p.traces[0].steps = vec![read(None, 1), read(Some(1), 2)];
	assert!(replay(&p).is_err());
	let mut p = base();
	p.traces[0].steps = vec![Step {
		action: 0,
		completion: None,
	}];
	assert!(replay(&p).is_err());
	let mut p = base();
	p.traces.push(p.traces[0].clone());
	assert!(replay(&p).is_err());
	let mut p = base();
	p.traces[0].steps = vec![wait(); 7];
	assert!(replay(&p).is_err());
	let mut p = base();
	p.traces[0].steps = vec![Step {
		action: 1,
		completion: Some(Completion {
			observation_tick: 1,
			failure: false,
			observation: Some(1),
		}),
	}];
	assert!(replay(&p).is_err());
	let mut v = serde_json::to_value(base()).unwrap();
	v["teacher_q"] = json!(vec![0.; 6]);
	assert!(serde_json::from_value::<ReplayParams>(v).is_err());
}

#[test]
fn invalid_checkpoint_law_and_dimensions_rejected() {
	let mut p = base();
	change_model(&mut p, |v| {
		v["core"]["tables"][0]["matrix"][0][0] = json!(0.9)
	});
	assert!(replay(&p).is_err());
	let mut p = base();
	change_model(&mut p, |v| v["coordinates"][15] = json!(0.01));
	assert!(replay(&p).is_err());
	let mut p = base();
	change_model(&mut p, |v| v["head_dimensions"] = json!([86, 48, 4]));
	assert!(replay(&p).is_err());
	let mut p = base();
	change_model(&mut p, |v| v["target"] = json!("first-hit"));
	assert!(replay(&p).is_err());
	let mut p = base();
	change_model(&mut p, |v| {
		let t = v["core"]["tables"][0].clone();
		v["core"]["tables"].as_array_mut().unwrap().push(t);
	});
	assert!(replay(&p).is_err());
}

#[test]
fn no_information_zero_cost_uses_first_legal_maximum() {
	let mut p = base();
	let mut public: Value = serde_json::from_str(&p.public_json).unwrap();
	public["reliability"] = json!(vec![0.5; 6]);
	p.public_json = serde_json::to_string(&public).unwrap();
	p.expected_public_sha256 = sha(p.public_json.as_bytes());
	let r = replay(&p).unwrap();
	assert_eq!(r.rows[0].teacher_q, [0.; 6]);
	assert_eq!(r.rows[0].target_action, 0);
}

#[test]
fn zero_probability_trace_outcomes_are_rejected() {
	for (failure_probability, observation) in [(0., None), (1., Some(1))] {
		let mut p = base();
		let mut public: Value = serde_json::from_str(&p.public_json).unwrap();
		public["failure_probability"] = json!(failure_probability);
		p.public_json = serde_json::to_string(&public).unwrap();
		p.expected_public_sha256 = sha(p.public_json.as_bytes());
		p.traces[0].steps = vec![read(observation, 1)];
		assert!(replay(&p)
			.unwrap_err()
			.to_string()
			.contains("zero probability"));
	}
}
