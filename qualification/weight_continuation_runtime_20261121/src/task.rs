// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Exact reviewed current-at-due sensor task, including complete owner state.

use anyhow::{bail, Result};
use hepta_semantic_source_adapter_study::validate_sha256;
use serde::{Deserialize, Serialize};

pub const ACTIONS: usize = 6;
pub const DEADLINE: usize = 6;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Public {
    pub schema: String,
    pub id: String,
    pub deadline: usize,
    pub target_tick: usize,
    pub initial_budget: usize,
    pub duration: [f64; DEADLINE],
    pub drive: [i8; DEADLINE],
    pub reliability: [f64; DEADLINE],
    pub read_price: [f64; DEADLINE],
    pub read_delay: [usize; DEADLINE],
    pub packets: [String; DEADLINE],
    pub packet_sha256: [String; DEADLINE],
    pub latency_price: f64,
    pub repair_price: f64,
    pub failure_probability: f64,
    pub prior_distance: f64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Pending {
    pub source_tick: usize,
    pub due_tick: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub source_tick: usize,
    pub observation_tick: usize,
    pub observation: u8,
    pub reliability: f64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct State {
    pub tick: usize,
    pub budget: usize,
    pub pending: Option<Pending>,
    pub broken: bool,
    pub last_symbol: i8,
    pub last_reliability: f64,
    pub history: Vec<Observation>,
    pub elapsed: f64,
    pub charges: f64,
    pub terminal: bool,
    pub submitted: Option<u8>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CompletionKind {
    None,
    Failure,
    Observation,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Completion {
    pub kind: CompletionKind,
    pub observation_tick: Option<usize>,
    pub observation: Option<u8>,
}

impl Completion {
    pub fn none() -> Self {
        Self {
            kind: CompletionKind::None,
            observation_tick: None,
            observation: None,
        }
    }
    pub fn failure(tick: usize) -> Self {
        Self {
            kind: CompletionKind::Failure,
            observation_tick: Some(tick),
            observation: None,
        }
    }
    pub fn observation(tick: usize, value: u8) -> Self {
        Self {
            kind: CompletionKind::Observation,
            observation_tick: Some(tick),
            observation: Some(value),
        }
    }
}

impl Public {
    pub fn validate(&self) -> Result<()> {
        if self.schema != "joint-current-at-due-fixed-deadline-v1"
            || self.deadline != DEADLINE
            || self.target_tick != DEADLINE
            || self.initial_budget != 3
            || self.id.is_empty()
            || self.id.len() > 256
            || self
                .duration
                .iter()
                .any(|x| !x.is_finite() || *x <= 0.0 || *x > 2.0)
            || self.drive.iter().any(|x| !(-1..=1).contains(x))
            || self
                .reliability
                .iter()
                .any(|x| !x.is_finite() || !(0.5..=1.0).contains(x))
            || self.read_delay.iter().any(|x| !(1..=2).contains(x))
            || self
                .read_price
                .iter()
                .chain([&self.latency_price, &self.repair_price])
                .any(|x| !x.is_finite() || *x < 0.0)
            || !self.failure_probability.is_finite()
            || !(0.0..=1.0).contains(&self.failure_probability)
            || ![0.125, 0.375, 0.75].contains(&self.prior_distance)
            || self
                .packets
                .iter()
                .any(|s| s.is_empty() || s.len() > 256 || s == "." || s == ".." || s.contains('/'))
        {
            bail!("public schedule differs from bounded endpoint-six task");
        }
        for hash in &self.packet_sha256 {
            validate_sha256(hash)?;
        }
        Ok(())
    }
}

pub fn initial(public: &Public) -> Result<State> {
    public.validate()?;
    Ok(State {
        tick: 0,
        budget: 3,
        pending: None,
        broken: false,
        last_symbol: 0,
        last_reliability: 0.5,
        history: Vec::new(),
        elapsed: 0.0,
        charges: 0.0,
        terminal: false,
        submitted: None,
    })
}

pub fn validate_state(public: &Public, state: &State) -> Result<()> {
    if state.tick > DEADLINE
        || state.budget > 3
        || state.history.len() > 3
        || !state.elapsed.is_finite()
        || !state.charges.is_finite()
        || state.charges < 0.0
        || !state.last_reliability.is_finite()
        || !(0.5..=1.0).contains(&state.last_reliability)
        || state.submitted.is_some_and(|y| y > 1)
        || (!state.terminal && state.submitted.is_some())
    {
        bail!("invalid complete state domain");
    }
    let mut elapsed = 0.0;
    for duration in &public.duration[..state.tick] {
        elapsed += duration;
    }
    if elapsed.to_bits() != state.elapsed.to_bits() {
        bail!("elapsed time does not match ordered schedule");
    }
    let mut previous = 0;
    for record in &state.history {
        if record.source_tick >= record.observation_tick
            || record.observation_tick > state.tick
            || record.observation_tick <= previous
            || record.observation > 1
            || record.source_tick >= DEADLINE
            || record.observation_tick != record.source_tick + public.read_delay[record.source_tick]
            || record.reliability != public.reliability[record.observation_tick - 1]
        {
            bail!("invalid or noncausal observation history");
        }
        previous = record.observation_tick;
    }
    let (symbol, reliability) = state
        .history
        .last()
        .map_or((0, 0.5), |r| (2 * r.observation as i8 - 1, r.reliability));
    if state.last_symbol != symbol || state.last_reliability != reliability {
        bail!("last observation fields are inconsistent");
    }
    if state.history.len() + usize::from(state.pending.is_some()) > 3 - state.budget {
        bail!("observations exceed read budget");
    }
    if let Some(pending) = &state.pending {
        if state.terminal
            || state.broken
            || pending.source_tick >= state.tick
            || pending.source_tick >= DEADLINE
            || pending.due_tick <= state.tick
            || pending.due_tick > DEADLINE
            || pending.due_tick != pending.source_tick + public.read_delay[pending.source_tick]
        {
            bail!("pending request contradicts the complete state");
        }
    }
    Ok(())
}

pub fn legal(public: &Public, state: &State) -> [bool; ACTIONS] {
    if state.terminal {
        return [false; ACTIONS];
    }
    let before = state.tick < DEADLINE;
    let read = before
        && state.budget > 0
        && !state.broken
        && state.pending.is_none()
        && state.tick + public.read_delay[state.tick] <= DEADLINE;
    [true, before, read, before && state.broken, true, true]
}

pub fn due_request(public: &Public, state: &State, action: usize) -> Result<Option<usize>> {
    validate_state(public, state)?;
    if action >= ACTIONS || !legal(public, state)[action] {
        bail!("illegal action has no state effects");
    }
    if [0, 4, 5].contains(&action) {
        return Ok(None);
    }
    let due = if action == 2 {
        Some(state.tick + public.read_delay[state.tick])
    } else {
        state.pending.as_ref().map(|p| p.due_tick)
    };
    Ok(due.filter(|tick| *tick == state.tick + 1))
}

pub fn completions(public: &Public, state: &State, action: usize) -> Result<Vec<Completion>> {
    Ok(match due_request(public, state, action)? {
        None => vec![Completion::none()],
        Some(tick) => vec![
            Completion::failure(tick),
            Completion::observation(tick, 0),
            Completion::observation(tick, 1),
        ],
    })
}

pub fn successor(
    public: &Public,
    before: &State,
    action: usize,
    completion: Completion,
) -> Result<State> {
    let due = due_request(public, before, action)?;
    if !completions(public, before, action)?.contains(&completion) {
        bail!("unknown or mistimed completion");
    }
    let mut state = before.clone();
    if [0, 4, 5].contains(&action) {
        state.terminal = true;
        state.submitted = if action == 0 {
            None
        } else {
            Some((action - 4) as u8)
        };
        state.pending = None;
        return Ok(state);
    }
    let t = state.tick;
    if action == 2 {
        state.budget -= 1;
        state.charges += public.read_price[t];
        state.pending = Some(Pending {
            source_tick: t,
            due_tick: t + public.read_delay[t],
        });
    } else if action == 3 {
        state.broken = false;
        state.charges += public.repair_price;
    }
    state.tick += 1;
    state.elapsed += public.duration[t];
    state.charges += public.latency_price * public.duration[t];
    if let Some(tick) = due {
        let request = state
            .pending
            .take()
            .ok_or_else(|| anyhow::anyhow!("due request disappeared"))?;
        match completion.kind {
            CompletionKind::Failure => state.broken = true,
            CompletionKind::Observation => {
                let y = completion
                    .observation
                    .ok_or_else(|| anyhow::anyhow!("missing binary observation"))?;
                let reliability = public.reliability[tick - 1];
                state.history.push(Observation {
                    source_tick: request.source_tick,
                    observation_tick: tick,
                    observation: y,
                    reliability,
                });
                state.last_symbol = 2 * y as i8 - 1;
                state.last_reliability = reliability;
            }
            CompletionKind::None => bail!("missing due completion"),
        }
    }
    validate_state(public, &state)?;
    Ok(state)
}
