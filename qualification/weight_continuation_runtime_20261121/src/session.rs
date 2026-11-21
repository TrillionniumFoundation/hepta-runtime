// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Native sparse policy execution with complete-state checks and replayed snapshots.

use crate::policy::{state_identity, Edge, VerifiedPolicy};
use crate::task::{self, Completion, Public, State};
use anyhow::{anyhow, bail, Result};
use hepta_semantic_source_adapter_study::{digest, unique_json, SourcePin, MAX_JSON_BYTES};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Serialize)]
struct Node {
    state: State,
    action: usize,
    outcomes: Vec<Edge>,
}

#[derive(Clone, Debug, Serialize)]
struct ProgramDocument {
    schema: String,
    capsule_sha256: String,
    checkpoint_sha256: String,
    public: Public,
    initial: usize,
    nodes: BTreeMap<usize, Node>,
}

pub struct NativeProgram {
    document: ProgramDocument,
    index: BTreeMap<Vec<u8>, usize>,
    bytes: Vec<u8>,
    sha256: String,
}

impl VerifiedPolicy {
    pub fn compile_sparse(&self) -> Result<NativeProgram> {
        let mut nodes = BTreeMap::new();
        let mut index = BTreeMap::new();
        for &id in &self.reachable {
            let state = self.capsule.states[id].clone();
            let action = self.capsule.actions[id];
            index.insert(state_identity(&state)?, id);
            nodes.insert(
                id,
                Node {
                    state,
                    action,
                    outcomes: self.capsule.edges[id][action].clone(),
                },
            );
        }
        let document = ProgramDocument {
            schema: "hepta.native-sparse-continuation.v1".into(),
            capsule_sha256: self.receipt().capsule_sha256.clone(),
            checkpoint_sha256: self.receipt().source.compressed_sha256.clone(),
            public: self.capsule.public.clone(),
            initial: self.capsule.initial,
            nodes,
        };
        let bytes = serde_json::to_vec(&document)?;
        Ok(NativeProgram {
            document,
            index,
            sha256: digest(&bytes),
            bytes,
        })
    }

    pub fn restore_sparse(&self, stored: &[u8]) -> Result<NativeProgram> {
        let program = self.compile_sparse()?;
        if program.bytes != stored {
            bail!("saved native program differs from verified full-DAG compilation");
        }
        Ok(program)
    }
}

impl NativeProgram {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
    pub fn state_count(&self) -> usize {
        self.document.nodes.len()
    }
    pub fn public(&self) -> &Public {
        &self.document.public
    }
    pub fn checkpoint_sha256(&self) -> &str {
        &self.document.checkpoint_sha256
    }
    fn node(&self, state: &State) -> Result<&Node> {
        let id = self
            .index
            .get(&state_identity(state)?)
            .ok_or_else(|| anyhow!("unknown complete runtime state"))?;
        self.document
            .nodes
            .get(id)
            .ok_or_else(|| anyhow!("unavailable native policy node"))
    }
    pub fn selected_action(&self, state: &State) -> Result<usize> {
        Ok(self.node(state)?.action)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    schema: String,
    program_sha256: String,
    capsule_sha256: String,
    checkpoint_sha256: String,
    max_steps: usize,
    trace: Vec<Completion>,
    state: State,
}

pub struct Session {
    snapshot: Snapshot,
}

#[derive(Clone, Debug, Serialize)]
pub struct StepReceipt {
    pub before: State,
    pub action: usize,
    pub completion: Completion,
    pub after: State,
    pub step: usize,
    pub external_packet_opened: bool,
}

impl Session {
    pub fn start(program: &NativeProgram, max_steps: usize) -> Result<Self> {
        if max_steps > 7 {
            bail!("cannot expand deadline-six execution step budget");
        }
        let state = program
            .document
            .nodes
            .get(&program.document.initial)
            .ok_or_else(|| anyhow!("missing native initial state"))?
            .state
            .clone();
        Ok(Self {
            snapshot: Snapshot {
                schema: "hepta.continuation-session.v1".into(),
                program_sha256: program.sha256.clone(),
                capsule_sha256: program.document.capsule_sha256.clone(),
                checkpoint_sha256: program.document.checkpoint_sha256.clone(),
                max_steps,
                trace: Vec::new(),
                state,
            },
        })
    }
    pub fn state(&self) -> &State {
        &self.snapshot.state
    }
    pub fn steps(&self) -> usize {
        self.snapshot.trace.len()
    }
    pub fn snapshot_bytes(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(&self.snapshot)?)
    }
    pub fn step(
        &mut self,
        program: &NativeProgram,
        public: &Public,
        completion: Completion,
    ) -> Result<StepReceipt> {
        if program.sha256 != self.snapshot.program_sha256 || public != program.public() {
            bail!("program or full public schedule differs from session binding");
        }
        if self.snapshot.trace.len() >= self.snapshot.max_steps {
            bail!("execution budget exhausted; no state mutation");
        }
        let before = self.snapshot.state.clone();
        let node = program.node(&before)?;
        let after = task::successor(public, &before, node.action, completion)?;
        if !after.terminal {
            let edge = node
                .outcomes
                .iter()
                .find(|edge| edge.completion == completion)
                .ok_or_else(|| anyhow!("unknown observation path"))?;
            let target = program
                .document
                .nodes
                .get(&edge.target)
                .ok_or_else(|| anyhow!("selected policy outcome was pruned"))?;
            if state_identity(&after)? != state_identity(&target.state)? {
                bail!("native program transition disagrees with full task state");
            }
        }
        let receipt = StepReceipt {
            before,
            action: node.action,
            completion,
            after: after.clone(),
            step: self.steps() + 1,
            external_packet_opened: false,
        };
        // Every fallible operation precedes the sole mutation boundary.
        self.snapshot.state = after;
        self.snapshot.trace.push(completion);
        Ok(receipt)
    }
    pub fn restore(
        program: &NativeProgram,
        bytes: &[u8],
        reviewed_snapshot_pin: &SourcePin,
    ) -> Result<Self> {
        reviewed_snapshot_pin.verify(bytes, MAX_JSON_BYTES)?;
        let saved: Snapshot = serde_json::from_value(unique_json(bytes)?)?;
        if saved.schema != "hepta.continuation-session.v1"
            || saved.trace.len() > 7
            || saved.program_sha256 != program.sha256
            || saved.checkpoint_sha256 != program.document.checkpoint_sha256
            || saved.capsule_sha256 != program.document.capsule_sha256
        {
            bail!("saved session does not bind the original source and native program");
        }
        let mut restored = Self::start(program, saved.max_steps)?;
        for completion in &saved.trace {
            restored.step(program, program.public(), *completion)?;
        }
        if state_identity(&restored.snapshot.state)? != state_identity(&saved.state)? {
            bail!("saved state differs from native replay of the complete trace");
        }
        Ok(restored)
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ExhaustiveExecutionReceipt {
    pub selected_states: usize,
    pub executed_edges: usize,
    pub terminal_states: usize,
    pub snapshots_restored: usize,
    pub complete_terminal_states_exact: bool,
    pub actual_external_observations: usize,
}

pub fn exercise_every_selected_step(program: &NativeProgram) -> Result<ExhaustiveExecutionReceipt> {
    let mut traces = BTreeMap::new();
    traces.insert(program.document.initial, Vec::new());
    let mut order: Vec<_> = program.document.nodes.keys().copied().collect();
    order.sort_by_key(|index| program.document.nodes[index].state.tick);
    let mut result = ExhaustiveExecutionReceipt {
        selected_states: order.len(),
        executed_edges: 0,
        terminal_states: 0,
        snapshots_restored: 0,
        complete_terminal_states_exact: true,
        actual_external_observations: 0,
    };
    for index in order {
        let trace = traces
            .get(&index)
            .ok_or_else(|| anyhow!("native policy state has no executable trace"))?
            .clone();
        let mut session = Session::start(program, 7)?;
        for completion in &trace {
            session.step(program, program.public(), *completion)?;
        }
        let bytes = session.snapshot_bytes()?;
        let pin = SourcePin {
            source_id: "independent-research-session-snapshot".into(),
            sha256: digest(&bytes),
            size_bytes: bytes.len() as u64,
        };
        let node = program
            .document
            .nodes
            .get(&index)
            .ok_or_else(|| anyhow!("missing selected node"))?;
        let completions = task::completions(program.public(), &node.state, node.action)?;
        for completion in completions {
            let mut restored = Session::restore(program, &bytes, &pin)?;
            result.snapshots_restored += 1;
            let step = restored.step(program, program.public(), completion)?;
            let expected = task::successor(program.public(), &node.state, node.action, completion)?;
            if state_identity(&step.after)? != state_identity(&expected)? {
                bail!("saved/loaded executor changes terminal or complete state");
            }
            if step.after.terminal {
                result.terminal_states += 1;
            } else {
                let id = *program
                    .index
                    .get(&state_identity(&step.after)?)
                    .ok_or_else(|| anyhow!("outcome absent from sparse graph"))?;
                let mut next_trace = trace.clone();
                next_trace.push(completion);
                traces.entry(id).or_insert(next_trace);
                result.executed_edges += 1;
            }
        }
    }
    Ok(result)
}
