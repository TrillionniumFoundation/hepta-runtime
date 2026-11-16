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
use serde::Serialize;
use serde_json::{Value,json};
use std::io::{Read,Write};
const ACTION_NAMES: [&str; 6] = ["STOP", "WAIT", "READ", "REPAIR", "SUBMIT_0", "SUBMIT_1"];
const SEMANTICS_VERSION: &str = "finite_dag_ordered_f64_v1";
const MAX_REQUEST_BYTES: usize = 8 * 1024 * 1024;
const MAX_WORK: u64 = 8_000_000;
const PROBABILITY_SUM_TOLERANCE: f64 = 1e-12;
const NEAR_TIE_TOLERANCE: f64 = 2e-12;
#[derive(Clone, Debug, Serialize)]
struct StatePlan {
	q: [Option<f64>; 6],
	value: f64,
	action: usize,
}

#[derive(Clone, Copy, Debug)]
struct Dimensions {
	states: usize,
	legal_actions: usize,
	continuing_actions: usize,
	branches: usize,
	zero_probability_branches: usize,
	probability_sum_error: f64,
	work: u64,
}

// An explicit observation fixture, never an implementation of a clock.
// This reference qualifies serialization of the supplied elapsed bits only.
#[derive(Clone, Copy)]
struct ObservedElapsed(u64);
impl ObservedElapsed {
    fn elapsed(self) -> Self { self }
    fn as_secs_f64(self) -> f64 { f64::from_bits(self.0) }
}
fn get(s: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(s[at..at+8].try_into().unwrap())
}
fn hex(s: &[u8]) -> String {
    s.iter().map(|value| format!("{value:02x}")).collect()
}
fn render_observation(s: &[u8]) -> Result<Value, Box<dyn std::error::Error>> {
    assert!(s.len() >= 64 && &s[..8] == b"HBLMRQ01");
    assert_eq!(get(s, 8), 1);
    assert_eq!(&s[40..64], &[0u8;24]);
    let core_len = usize::try_from(get(s, 16)).unwrap();
    let commitment_len = usize::try_from(get(s, 24)).unwrap();
    assert_eq!(s.len(), 64 + core_len + commitment_len);
    let c = &s[64..64+core_len];
    let h = &s[64+core_len..];
    assert_eq!(&c[..8], b"HIABPLN1");
    assert_eq!(&h[..8], b"HBCMTRES");
    let dims = Dimensions {
        states: usize::try_from(get(c, 8)).unwrap(),
        legal_actions: usize::try_from(get(c, 16)).unwrap(),
        continuing_actions: usize::try_from(get(c, 24)).unwrap(),
        branches: usize::try_from(get(c, 32)).unwrap(),
        zero_probability_branches: usize::try_from(get(c, 40)).unwrap(),
        probability_sum_error: f64::from_bits(get(c, 48)),
        work: get(c, 56),
    };
    assert_eq!(c.len(), 128 + 72 * dims.states);
    let plans: Vec<StatePlan> = (0..dims.states).map(|i| {
        let at = 128 + i * 72;
        let mask = get(c, at);
        StatePlan {
            q: std::array::from_fn(|j| {
                if mask & (1 << j) == 0 { None }
                else { Some(f64::from_bits(get(c, at + 24 + j * 8))) }
            }),
            value: f64::from_bits(get(c, at + 16)),
            action: usize::try_from(get(c, at + 8)).unwrap(),
        }
    }).collect();
    let exact_tie_states = get(c, 64);
    let near_tie_states = get(c, 72);
    let minimum_relative_action_gap = if get(c, 80) == 0 { None }
        else { Some(f64::from_bits(get(c, 88))) };
    let maximum_consistency_residual = f64::from_bits(get(c, 96));
    let request_bytes = usize::try_from(get(h, 8)).unwrap();
    assert_eq!(h.len(), 128 + request_bytes);
    let request_sha256 = hex(&h[16..48]);
    let implementation_source_sha256 = hex(&h[48..80]);
    let plan_id = format!("wb1_{}", hex(&h[80..112]));
    let started = ObservedElapsed(get(s, 32));
	Ok(json!({
		"schema":"hepta.weight.bellman-plan.v1", "semantics_version":SEMANTICS_VERSION,
		"method":"finite_dag_ordered_dynamic_programming_f64", "action_names":ACTION_NAMES,
		"recurrence":"in supplied branch order: total += probability * ((child_value + reward) - fee); zero probabilities skipped; first legal strict maximum",
		"plan_id":plan_id, "request_sha256":request_sha256, "request_bytes":request_bytes,
		"request_commitment_encoding":"typed canonical serde_json; not raw JSON-RPC transport bytes",
		"implementation_source_sha256":implementation_source_sha256,
		"state_count":dims.states, "legal_action_count":dims.legal_actions,
		"continuing_action_count":dims.continuing_actions, "branch_count":dims.branches,
		"zero_probability_branch_count":dims.zero_probability_branches, "states":plans,
		"probability_sum_tolerance":PROBABILITY_SUM_TOLERANCE,
		"maximum_probability_sum_error_f64":dims.probability_sum_error,
		"maximum_self_consistency_residual_f64":maximum_consistency_residual,
		"self_consistency_is_numerical_error_bound":false,
		"exact_tie_state_count":exact_tie_states, "near_tie_state_count":near_tie_states,
		"near_tie_relative_threshold":NEAR_TIE_TOLERANCE,
		"minimum_relative_action_gap_f64":minimum_relative_action_gap,
		"operation_charged_units":dims.work, "operation_budget_units":MAX_WORK,
		"canonical_request_byte_budget":MAX_REQUEST_BYTES,
		"native_operation_wall_seconds":started.elapsed().as_secs_f64(),
		"gradient_steps":0, "training_targets_used":false,
		"checkpoint_verified":false, "environment_law_verified":false,
		"real_arithmetic_optimality_certified":false, "independent_holdout_verified":false,
		"production_eligible":false,
		"scope":"bounded planning over the caller-declared finite DAG; no file access, checkpoint mutation, circuit identification, authentication of true dynamics, or end-to-end efficacy claim"
	}))
}

fn main() {
    let mut input = Vec::new();
    std::io::stdin().read_to_end(&mut input).unwrap();
    let mut at = 0;
    let mut output = std::io::BufWriter::new(std::io::stdout().lock());
    while at < input.len() {
        let size = usize::try_from(get(&input, at)).unwrap();
        at += 8;
        let value = render_observation(&input[at..at+size]).unwrap();
        at += size;
        let body = serde_json::to_vec(&value).unwrap();
        output.write_all(&(body.len() as u64).to_le_bytes()).unwrap();
        output.write_all(&body).unwrap();
    }
    assert_eq!(at, input.len());
    output.flush().unwrap();
}
