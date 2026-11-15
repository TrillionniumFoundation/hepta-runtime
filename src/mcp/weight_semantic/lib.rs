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
//! Bounded native re-execution of one declared 31-state renewal policy profile.
//!
//! The caller supplies checkpoint bytes, a public schedule and causal traces.
//! Hidden features, the legal mask and a complete finite-horizon Bellman target
//! are computed here. No caller-supplied hidden vector, target or teacher table
//! is accepted. Digests bind inputs; they do not authenticate an external source.
//! The endpoint task, supplied transition law and risk-neutral additive utility
//! are explicit. This is neither first-passage nor a general NDU optimizer.

use anyhow::{bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

pub const PROFILE: &str = "hepta.joint-renewal.endpoint-replay.v1";
pub const MAX_REQUEST_BYTES: usize = 2 * 1024 * 1024;
const MAX_CHECKPOINT_BYTES: usize = 1024 * 1024;
const MAX_TRACES: usize = 128;
const MAX_CACHE_STATES: usize = 8192;
const N: usize = 33;
const H: usize = 48;
const TASK: &str = "joint-current-at-due-fixed-deadline-v1";
const BANK: &str = "no-new-observation predictive state probability at next boundary, two boundaries and deadline6; thresholds normalized(-.5,0,.5), strict>; actual scheduled future drives and durations";
const TARGET: &str =
	"sign(X_deadline6)>0, including early submit; learned belief is not privileged posterior";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayParams {
	pub profile: String,
	pub checkpoint_json: String,
	pub expected_checkpoint_sha256: String,
	pub public_json: String,
	pub expected_public_sha256: String,
	pub traces: Vec<Trace>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Trace {
	pub source_row: u32,
	pub steps: Vec<Step>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Step {
	pub action: u8,
	pub completion: Option<Completion>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Completion {
	pub observation_tick: usize,
	pub failure: bool,
	pub observation: Option<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Public {
	pub schema: String,
	pub id: String,
	pub deadline: usize,
	pub target_tick: usize,
	pub initial_budget: u8,
	pub duration: [f64; 6],
	pub drive: [i8; 6],
	pub reliability: [f64; 6],
	pub read_price: [f64; 6],
	pub read_delay: [usize; 6],
	pub latency_price: f64,
	pub repair_price: f64,
	pub failure_probability: f64,
	pub prior_distance: f64,
	pub packets: [String; 6],
	pub packet_sha256: [String; 6],
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pending {
	pub source_tick: usize,
	pub due_tick: usize,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
	pub source_tick: usize,
	pub observation_tick: usize,
	pub observation: u8,
	pub reliability: f64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
	pub tick: usize,
	pub budget: u8,
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Checkpoint {
	schema: String,
	family: String,
	fit: u32,
	public_dimensions: usize,
	head_dimensions: [usize; 3],
	n_grid: usize,
	coordinates: Vec<f64>,
	confusion: Vec<Vec<f64>>,
	network: Network,
	core: Core,
	target: String,
	bank_semantics: String,
	#[serde(rename = "nominal_raw")]
	_nominal_raw: serde_json::Value,
	#[serde(rename = "parameter_count")]
	_parameter_count: serde_json::Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Core {
	kind: String,
	tables: Vec<Table>,
	#[serde(rename = "generators")]
	_generators: serde_json::Value,
	#[serde(rename = "raw")]
	_raw: serde_json::Value,
	#[serde(rename = "physical")]
	_physical: serde_json::Value,
	#[serde(rename = "optimizer_constraint")]
	_optimizer_constraint: serde_json::Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Table {
	dt: f64,
	drive: i8,
	matrix: Vec<Vec<f64>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Network {
	w1: Vec<Vec<f64>>,
	b1: Vec<f64>,
	w2: Vec<Vec<f64>>,
	b2: Vec<f64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReplayRow {
	pub source_row: u32,
	pub state: State,
	pub public_features: Vec<f64>,
	pub mass: Vec<f64>,
	pub bank: Vec<f64>,
	pub hidden: Vec<f64>,
	pub hidden_f64_le_hex: String,
	pub hidden_sha256: String,
	pub network_scores: [f64; 6],
	pub learned_belief: f64,
	pub analytic_endpoint_belief: f64,
	pub teacher_q: [f64; 6],
	pub legal: [bool; 6],
	pub target_action: usize,
	pub minimum_teacher_margin: f64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReplayResult {
	pub schema: String,
	pub profile: String,
	pub fit: u32,
	pub checkpoint_sha256: String,
	pub public_sha256: String,
	pub implementation_sha256: String,
	pub hidden_program_reexecuted: bool,
	pub teacher_program_reexecuted: bool,
	pub states_reconstructed_from_causal_traces: bool,
	pub external_source_authenticated: bool,
	pub supplied_checkpoint_law_only: bool,
	pub rounded_binary64_not_interval_proof: bool,
	pub wall_seconds: f64,
	pub bellman_cache_states: usize,
	pub maximum_outcome_probability_error: f64,
	pub rows: Vec<ReplayRow>,
}

fn hex(bytes: &[u8]) -> String {
	bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn sha(bytes: &[u8]) -> String {
	hex(&Sha256::digest(bytes))
}

fn digest_ok(value: &str) -> bool {
	value.len() == 64
		&& value
			.bytes()
			.all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn bounded(x: f64, low: f64, high: f64) -> bool {
	x.is_finite() && x >= low && x <= high
}

fn matrix_ok(value: &[Vec<f64>], rows: usize, cols: usize) -> bool {
	value.len() == rows
		&& value
			.iter()
			.all(|r| r.len() == cols && r.iter().all(|x| bounded(*x, -1e6, 1e6)))
}

// Explicit separate binary64 products and left-to-right sums. No mul_add,
// BLAS, GPU, Python, external process or caller-selectable expression is used.
fn dot(a: &[f64], b: &[f64]) -> f64 {
	a.iter().zip(b).fold(0., |sum, (a, b)| sum + a * b)
}

fn row_times_matrix(v: &[f64], matrix: &[Vec<f64>]) -> Vec<f64> {
	(0..matrix[0].len())
		.map(|j| {
			v.iter()
				.enumerate()
				.fold(0., |sum, (i, x)| sum + x * matrix[i][j])
		})
		.collect()
}

// NumPy 2.3.5 reduces contiguous masses and compressed teacher events with eight
// accumulators. These fixed arrays have at most 33 elements, so only its <8 and
// <=128 branches apply (numpy/_core/src/umath/loops_utils.h.src, v2.3.5).
// The encoder bank and matrix products have a different reduction order.
fn contiguous_probability_sum(values: &[f64]) -> f64 {
	debug_assert!(values.len() <= N);
	if values.len() < 8 {
		return values.iter().fold(-0., |sum, value| sum + value);
	}
	let mut lanes = [0.; 8];
	lanes.copy_from_slice(&values[..8]);
	let mut chunks = values[8..].chunks_exact(8);
	for chunk in &mut chunks {
		for (sum, value) in lanes.iter_mut().zip(chunk) {
			*sum += value;
		}
	}
	let sum = ((lanes[0] + lanes[1]) + (lanes[2] + lanes[3]))
		+ ((lanes[4] + lanes[5]) + (lanes[6] + lanes[7]));
	chunks
		.remainder()
		.iter()
		.fold(sum, |sum, value| sum + value)
}

fn sigmoid(x: f64) -> f64 {
	1. / (1. + (-x.clamp(-700., 700.)).exp())
}

fn initial() -> State {
	State {
		tick: 0,
		budget: 3,
		pending: None,
		broken: false,
		last_symbol: 0,
		last_reliability: 0.5,
		history: Vec::new(),
		elapsed: 0.,
		charges: 0.,
		terminal: false,
		submitted: None,
	}
}

fn legal(public: &Public, state: &State) -> [bool; 6] {
	if state.terminal {
		return [false; 6];
	}
	let before = state.tick < 6;
	let read = before
		&& state.budget > 0
		&& !state.broken
		&& state.pending.is_none()
		&& state.tick + public.read_delay[state.tick] <= 6;
	[true, before, read, before && state.broken, true, true]
}

fn due_request(public: &Public, state: &State, action: usize) -> Result<Option<usize>> {
	ensure!(action < 6 && legal(public, state)[action], "illegal action");
	if matches!(action, 0 | 4 | 5) {
		return Ok(None);
	}
	let pending = if action == 2 {
		Some(Pending {
			source_tick: state.tick,
			due_tick: state.tick + public.read_delay[state.tick],
		})
	} else {
		state.pending.clone()
	};
	Ok(pending
		.filter(|p| p.due_tick == state.tick + 1)
		.map(|p| p.due_tick))
}

fn successor(
	public: &Public,
	state: &State,
	action: usize,
	completion: &Option<Completion>,
) -> Result<State> {
	let due = due_request(public, state, action)?;
	ensure!(
		due.is_some() == completion.is_some(),
		"completion must occur exactly at due boundary"
	);
	if let Some(c) = completion {
		ensure!(
			Some(c.observation_tick) == due,
			"observation is not current-at-due"
		);
		ensure!(
			if c.failure {
				c.observation.is_none()
			} else {
				matches!(c.observation, Some(0 | 1))
			},
			"invalid completion outcome"
		);
	}
	let mut next = state.clone();
	if matches!(action, 0 | 4 | 5) {
		next.terminal = true;
		next.submitted = if action == 0 {
			None
		} else {
			Some((action - 4) as u8)
		};
		next.pending = None;
		return Ok(next);
	}
	let t = state.tick;
	if action == 2 {
		next.budget -= 1;
		next.charges += public.read_price[t];
		next.pending = Some(Pending {
			source_tick: t,
			due_tick: t + public.read_delay[t],
		});
	} else if action == 3 {
		next.broken = false;
		next.charges += public.repair_price;
	}
	next.tick += 1;
	next.elapsed += public.duration[t];
	next.charges += public.latency_price * public.duration[t];
	if let Some(c) = completion {
		let pending = next.pending.take().context("due request disappeared")?;
		if c.failure {
			next.broken = true;
		} else {
			let y = c.observation.context("missing successful observation")?;
			let r = public.reliability[c.observation_tick - 1];
			next.history.push(Observation {
				source_tick: pending.source_tick,
				observation_tick: c.observation_tick,
				observation: y,
				reliability: r,
			});
			next.last_symbol = 2 * y as i8 - 1;
			next.last_reliability = r;
		}
	}
	Ok(next)
}

fn public_features(p: &Public, s: &State) -> Vec<f64> {
	let mut v = vec![
		s.tick as f64 / 6.,
		s.budget as f64 / 3.,
		s.elapsed / 9.,
		s.charges,
		u8::from(s.broken) as f64,
		u8::from(s.pending.is_some()) as f64,
		s.pending
			.as_ref()
			.map_or(0., |x| (x.due_tick - s.tick) as f64 / 2.),
		s.last_symbol as f64,
		s.last_reliability,
		p.latency_price,
		p.repair_price,
		p.failure_probability,
	];
	for i in 0..6 {
		v.extend([
			p.duration[i] / 2.,
			p.reliability[i],
			p.read_price[i],
			p.read_delay[i] as f64 / 2.,
		]);
	}
	v.extend(p.drive.iter().map(|x| *x as f64));
	v.push(p.prior_distance);
	v
}

#[derive(Clone, Hash, PartialEq, Eq)]
struct Key {
	tick: usize,
	budget: u8,
	broken: bool,
	pending: Option<Pending>,
	history: Vec<(usize, usize, u8)>,
}

impl From<&State> for Key {
	fn from(s: &State) -> Self {
		Self {
			tick: s.tick,
			budget: s.budget,
			broken: s.broken,
			pending: s.pending.clone(),
			history: s
				.history
				.iter()
				.map(|r| (r.source_tick, r.observation_tick, r.observation))
				.collect(),
		}
	}
}

type MassCacheKey = (usize, Vec<(usize, u8)>);

struct Engine {
	model: Checkpoint,
	public: Public,
	transitions: Vec<usize>,
	emissions: Vec<Vec<Vec<f64>>>,
	mass_cache: HashMap<MassCacheKey, Vec<f64>>,
	values: HashMap<Key, f64>,
	teacher_representatives: HashMap<Key, State>,
	deadline: Instant,
	probability_error: f64,
}

impl Engine {
	fn check_deadline(&self) -> Result<()> {
		ensure!(
			Instant::now() < self.deadline,
			"semantic replay exceeded 30-second cooperative deadline"
		);
		Ok(())
	}

	fn new(model: Checkpoint, public: Public, deadline: Instant) -> Result<Self> {
		ensure!(
			model.schema == "joint-policy-v1"
				&& model.family == "renewal"
				&& model.n_grid == 31
				&& model.public_dimensions == 43
				&& model.head_dimensions == [85, 48, 4],
			"unsupported checkpoint profile"
		);
		ensure!(
			model.target == TARGET
				&& model.bank_semantics == BANK
				&& model.core.kind == "full_distribution_ctmc",
			"checkpoint target/bank contract mismatch"
		);
		let coords: Vec<f64> = (1..32)
			.map(|i| -1. + i as f64 / 16.)
			.chain([-1., 1.])
			.collect();
		ensure!(
			model.coordinates == coords,
			"coordinate order or strict endpoint partition differs"
		);
		let n = &model.network;
		ensure!(
			matrix_ok(&n.w1, 48, 85)
				&& matrix_ok(&n.w2, 4, 48)
				&& n.b1.len() == 48
				&& n.b2.len() == 4
				&& n.b1.iter().chain(&n.b2).all(|x| bounded(*x, -1e6, 1e6)),
			"network dimensions or finite bounds"
		);
		ensure!(
			matrix_ok(&model.confusion, 2, 2)
				&& model
					.confusion
					.iter()
					.all(|r| r.iter().all(|x| *x > 0.)
						&& (r.iter().sum::<f64>() - 1.).abs() <= 5e-11),
			"invalid decoder law"
		);
		ensure!(
			!model.core.tables.is_empty() && model.core.tables.len() <= 24,
			"transition table count"
		);
		let mut pairs = HashSet::new();
		for t in &model.core.tables {
			ensure!(
				bounded(t.dt, f64::MIN_POSITIVE, 2.)
					&& (-1..=1).contains(&t.drive)
					&& pairs.insert((t.dt.to_bits(), t.drive)),
				"invalid or duplicate transition key"
			);
			ensure!(
				matrix_ok(&t.matrix, N, N)
					&& t.matrix.iter().all(|r| r.iter().all(|x| *x >= 0.)
						&& (r.iter().sum::<f64>() - 1.).abs() <= 5e-11),
				"invalid transition stochastic matrix"
			);
		}
		ensure!(
			public.schema == TASK
				&& public.deadline == 6
				&& public.target_tick == 6
				&& public.initial_budget == 3
				&& !public.id.is_empty()
				&& public.id.len() <= 256,
			"unsupported public task contract"
		);
		ensure!(
			public
				.duration
				.iter()
				.all(|x| bounded(*x, f64::MIN_POSITIVE, 2.))
				&& public.drive.iter().all(|d| (-1..=1).contains(d))
				&& public.reliability.iter().all(|r| bounded(*r, 0.5, 1.))
				&& public.read_delay.iter().all(|d| matches!(*d, 1 | 2))
				&& public.read_price.iter().all(|p| bounded(*p, 0., 1e3))
				&& bounded(public.latency_price, 0., 1e3)
				&& bounded(public.repair_price, 0., 1e3)
				&& bounded(public.failure_probability, 0., 1.)
				&& [0.125, 0.375, 0.75].contains(&public.prior_distance),
			"invalid public schedule"
		);
		ensure!(
			public.packets.iter().all(|s| !s.is_empty()
				&& s.len() <= 256
				&& s != "." && s != ".."
				&& !s.contains('/')
				&& !s.contains('\\'))
				&& public.packet_sha256.iter().all(|x| digest_ok(x)),
			"invalid packet identity metadata"
		);
		let mut transitions = Vec::new();
		let mut emissions = Vec::new();
		for i in 0..6 {
			transitions.push(
				model
					.core
					.tables
					.iter()
					.position(|t| t.dt == public.duration[i] && t.drive == public.drive[i])
					.context("schedule table absent")?,
			);
			let r = public.reliability[i];
			let noise = [[r, 1. - r], [1. - r, r]];
			let pair: Vec<Vec<f64>> = noise
				.iter()
				.map(|a| {
					(0..2)
						.map(|j| a[0] * model.confusion[0][j] + a[1] * model.confusion[1][j])
						.collect()
				})
				.collect();
			emissions.push(
				model
					.coordinates
					.iter()
					.map(|x| pair[usize::from(*x > 0.)].clone())
					.collect(),
			);
		}
		Ok(Self {
			model,
			public,
			transitions,
			emissions,
			mass_cache: HashMap::new(),
			values: HashMap::new(),
			teacher_representatives: HashMap::new(),
			deadline,
			probability_error: 0.,
		})
	}

	fn collect_teacher_representatives(&mut self) -> Result<()> {
		// The pinned Python compiler keeps the first LIFO-DFS full state for
		// each Markov key. Its charge bits affect rounded fee subtraction even
		// though sunk charges do not affect the mathematical future utility.
		let mut pending = vec![initial()];
		while let Some(state) = pending.pop() {
			self.check_deadline()?;
			let key = Key::from(&state);
			if self.teacher_representatives.contains_key(&key) {
				continue;
			}
			ensure!(
				self.teacher_representatives.len() < MAX_CACHE_STATES,
				"teacher representative state budget exceeded"
			);
			self.teacher_representatives.insert(key, state.clone());
			let mask = legal(&self.public, &state);
			for (action, allowed) in mask.iter().enumerate().take(4).skip(1) {
				if !allowed {
					continue;
				}
				let due = due_request(&self.public, &state, action)?;
				let completions = if let Some(tick) = due {
					vec![
						Some(Completion {
							observation_tick: tick,
							failure: true,
							observation: None,
						}),
						Some(Completion {
							observation_tick: tick,
							failure: false,
							observation: Some(0),
						}),
						Some(Completion {
							observation_tick: tick,
							failure: false,
							observation: Some(1),
						}),
					]
				} else {
					vec![None]
				};
				for completion in completions {
					ensure!(
						pending.len() < MAX_CACHE_STATES,
						"teacher DFS stack budget exceeded"
					);
					pending.push(successor(&self.public, &state, action, &completion)?);
				}
			}
		}
		Ok(())
	}

	fn transition(&self, tick: usize, v: &[f64]) -> Vec<f64> {
		row_times_matrix(v, &self.model.core.tables[self.transitions[tick]].matrix)
	}

	fn mass(&mut self, state: &State) -> Result<Vec<f64>> {
		self.check_deadline()?;
		let history: Vec<_> = state
			.history
			.iter()
			.map(|r| (r.observation_tick, r.observation))
			.collect();
		let key = (state.tick, history.clone());
		if let Some(v) = self.mass_cache.get(&key) {
			return Ok(v.clone());
		}
		let mut mass = vec![0.; N];
		for sign in [-1., 1.] {
			let pos = (0..31)
				.min_by(|a, b| {
					(self.model.coordinates[*a] - sign * self.public.prior_distance)
						.abs()
						.total_cmp(
							&(self.model.coordinates[*b] - sign * self.public.prior_distance).abs(),
						)
				})
				.context("prior support is empty")?;
			mass[pos] += 0.5;
		}
		for t in 0..state.tick {
			mass = self.transition(t, &mass);
			if let Some((_, y)) = history.iter().find(|(tick, _)| *tick == t + 1) {
				for (i, x) in mass.iter_mut().enumerate() {
					*x *= self.emissions[t][i][*y as usize];
				}
				let sum = contiguous_probability_sum(&mass);
				ensure!(
					sum > 0. && sum.is_finite(),
					"impossible observation under checkpoint law"
				);
				for x in &mut mass {
					*x /= sum;
				}
			}
		}
		ensure!(
			mass.iter().all(|x| bounded(*x, 0., 1. + 1e-8))
				&& (mass.iter().sum::<f64>() - 1.).abs() < 1e-8,
			"invalid propagated probability mass"
		);
		ensure!(
			self.mass_cache.len() < MAX_CACHE_STATES,
			"mass cache state budget exceeded"
		);
		self.mass_cache.insert(key, mass.clone());
		Ok(mass)
	}

	fn future(&self, mass: &[f64], from: usize, to: usize) -> Vec<f64> {
		let mut next = mass.to_vec();
		for t in from..to {
			next = self.transition(t, &next);
		}
		next
	}

	fn probability(&self, mass: &[f64], threshold: f64) -> f64 {
		mass.iter()
			.zip(&self.model.coordinates)
			.filter(|(_, x)| **x > threshold)
			.map(|(p, _)| *p)
			.sum()
	}

	fn teacher_posterior(&mut self, state: &State) -> Result<f64> {
		let mass = self.mass(state)?;
		let future = self.future(&mass, state.tick, 6);
		let event: Vec<_> = future
			.iter()
			.zip(&self.model.coordinates)
			.filter(|(_, coordinate)| **coordinate > 0.)
			.map(|(probability, _)| *probability)
			.collect();
		Ok(contiguous_probability_sum(&event))
	}

	fn value(&mut self, state: &State) -> Result<f64> {
		self.check_deadline()?;
		let key = Key::from(state);
		if let Some(v) = self.values.get(&key) {
			return Ok(*v);
		}
		// The Bellman state excludes sunk charges, just as the pinned Oracle.
		// The encoder still receives actual path charges through its own State.
		let mut normalized = state.clone();
		normalized.charges = 0.;
		normalized.elapsed = self.public.duration[..state.tick].iter().sum();
		let q = self.q(&normalized)?;
		let mask = legal(&self.public, &normalized);
		let value = q
			.iter()
			.zip(mask)
			.filter(|(_, ok)| *ok)
			.map(|(q, _)| *q)
			.fold(f64::NEG_INFINITY, f64::max);
		ensure!(
			self.values.len() < MAX_CACHE_STATES,
			"Bellman cache state budget exceeded"
		);
		self.values.insert(key, value);
		Ok(value)
	}

	fn q(&mut self, state: &State) -> Result<[f64; 6]> {
		self.check_deadline()?;
		ensure!(!state.terminal, "cannot score terminal state");
		let p = self.teacher_posterior(state)?;
		let mask = legal(&self.public, state);
		let mut values = [0.; 6]; // Illegal actions have an explicit mask, not sentinels.
		values[4] = 1. - 2. * p;
		values[5] = 2. * p - 1.;
		for action in 1..4 {
			if !mask[action] {
				continue;
			}
			let due = due_request(&self.public, state, action)?;
			let mut outcomes = vec![(1., None)];
			if let Some(tick) = due {
				let mass = self.mass(state)?;
				let next = self.transition(state.tick, &mass);
				let predictive = row_times_matrix(&next, &self.emissions[tick - 1]);
				let f = self.public.failure_probability;
				outcomes = vec![
					(
						f,
						Some(Completion {
							observation_tick: tick,
							failure: true,
							observation: None,
						}),
					),
					(
						(1. - f) * predictive[0],
						Some(Completion {
							observation_tick: tick,
							failure: false,
							observation: Some(0),
						}),
					),
					(
						(1. - f) * predictive[1],
						Some(Completion {
							observation_tick: tick,
							failure: false,
							observation: Some(1),
						}),
					),
				];
			}
			let sum: f64 = outcomes.iter().map(|(p, _)| *p).sum();
			self.probability_error = self.probability_error.max((sum - 1.).abs());
			ensure!((sum - 1.).abs() <= 2e-11, "Bellman outcome mass invalid");
			for (probability, completion) in outcomes {
				if probability == 0. {
					continue;
				}
				let next = successor(&self.public, state, action, &completion)?;
				values[action] +=
					probability * (self.value(&next)? - (next.charges - state.charges));
			}
		}
		ensure!(
			values.iter().all(|x| x.is_finite()),
			"nonfinite Bellman result"
		);
		Ok(values)
	}

	fn score(&mut self, trace: &Trace) -> Result<ReplayRow> {
		ensure!(
			trace.steps.len() <= 6,
			"trace exceeds six action boundaries"
		);
		let mut state = initial();
		for step in &trace.steps {
			if let Some(completion) = &step.completion {
				ensure!(
					if completion.failure {
						self.public.failure_probability > 0.
					} else {
						self.public.failure_probability < 1.
					},
					"trace outcome has zero probability under declared failure law"
				);
			}
			state = successor(&self.public, &state, step.action as usize, &step.completion)?;
		}
		ensure!(
			!state.terminal,
			"replay requests must identify a decision state"
		);
		let mass = self.mass(&state)?;
		let mut bank = Vec::with_capacity(9);
		for horizon in [(state.tick + 1).min(6), (state.tick + 2).min(6), 6] {
			let future = self.future(&mass, state.tick, horizon);
			for threshold in [-0.5, 0., 0.5] {
				bank.push(self.probability(&future, threshold));
			}
		}
		let pubvec = public_features(&self.public, &state);
		let mut input = pubvec.clone();
		input.extend(&mass);
		input.extend(&bank);
		ensure!(input.len() == 85, "feature width mismatch");
		let n = &self.model.network;
		let mut hidden: Vec<_> =
			n.w1.iter()
				.zip(&n.b1)
				.map(|(w, b)| (dot(w, &input) + b).tanh())
				.collect();
		let out: Vec<_> =
			n.w2.iter()
				.zip(&n.b2)
				.map(|(w, b)| dot(w, &hidden) + b)
				.collect();
		ensure!(
			hidden.len() == H && hidden.iter().chain(&out).all(|x| x.is_finite()),
			"nonfinite network result"
		);
		let learned = sigmoid(out[3]);
		hidden.push(1.);
		let raw: Vec<u8> = hidden.iter().flat_map(|x| x.to_le_bytes()).collect();
		let representative = self
			.teacher_representatives
			.get(&Key::from(&state))
			.context("trace state is absent from the teacher Markov support")?
			.clone();
		let q = self.q(&representative)?;
		let mask = legal(&self.public, &state);
		let mut action = 0;
		for i in 1..6 {
			if mask[i] && q[i] > q[action] {
				action = i;
			}
		}
		let margin = (0..6)
			.filter(|i| mask[*i] && *i != action)
			.map(|i| q[action] - q[i])
			.fold(f64::INFINITY, f64::min);
		Ok(ReplayRow {
			source_row: trace.source_row,
			state,
			public_features: pubvec,
			mass,
			bank: bank.clone(),
			hidden,
			hidden_f64_le_hex: hex(&raw),
			hidden_sha256: sha(&raw),
			network_scores: [
				0.,
				out[0],
				out[1],
				out[2],
				1. - 2. * learned,
				2. * learned - 1.,
			],
			learned_belief: learned,
			analytic_endpoint_belief: bank[7],
			teacher_q: q,
			legal: mask,
			target_action: action,
			minimum_teacher_margin: margin,
		})
	}
}

pub fn replay(params: &ReplayParams) -> Result<ReplayResult> {
	replay_until(params, Instant::now() + Duration::from_secs(30))
}

/// The composite caller may have already spent part of its deadline in
/// admission. Never renew that allowance when entering this numerical core.
pub fn replay_until(params: &ReplayParams, outer_end: Instant) -> Result<ReplayResult> {
	let start = Instant::now();
	let end = outer_end.min(start + Duration::from_secs(30));
	ensure!(
		start < end,
		"semantic replay deadline expired before admission"
	);
	ensure!(params.profile == PROFILE, "unsupported semantic profile");
	ensure!(
		params.checkpoint_json.len() <= MAX_CHECKPOINT_BYTES
			&& params.public_json.len() <= 16 * 1024,
		"semantic input byte budget exceeded"
	);
	ensure!(
		serde_json::to_vec(params)?.len() <= MAX_REQUEST_BYTES,
		"request byte budget exceeded"
	);
	ensure!(
		digest_ok(&params.expected_checkpoint_sha256)
			&& digest_ok(&params.expected_public_sha256)
			&& sha(params.checkpoint_json.as_bytes()) == params.expected_checkpoint_sha256
			&& sha(params.public_json.as_bytes()) == params.expected_public_sha256,
		"input digest mismatch"
	);
	ensure!(
		!params.traces.is_empty() && params.traces.len() <= MAX_TRACES,
		"trace count outside 1..128"
	);
	let mut ids = HashSet::new();
	ensure!(
		params.traces.iter().all(|t| ids.insert(t.source_row)),
		"duplicate source row"
	);
	let model = serde_json::from_str(&params.checkpoint_json).context("checkpoint schema")?;
	let public = serde_json::from_str(&params.public_json).context("public task schema")?;
	ensure!(
		Instant::now() < end,
		"semantic replay deadline expired during admission"
	);
	let mut engine = Engine::new(model, public, end)?;
	engine.collect_teacher_representatives()?;
	let mut rows = Vec::with_capacity(params.traces.len());
	for trace in &params.traces {
		rows.push(engine.score(trace)?);
	}
	let result = ReplayResult {
		schema: "hepta.weight-semantic-replay.result.v1".into(),
		profile: PROFILE.into(),
		fit: engine.model.fit,
		checkpoint_sha256: params.expected_checkpoint_sha256.clone(),
		public_sha256: params.expected_public_sha256.clone(),
		implementation_sha256: sha(include_bytes!("lib.rs")),
		hidden_program_reexecuted: true,
		teacher_program_reexecuted: true,
		states_reconstructed_from_causal_traces: true,
		external_source_authenticated: false,
		supplied_checkpoint_law_only: true,
		rounded_binary64_not_interval_proof: true,
		wall_seconds: start.elapsed().as_secs_f64(),
		bellman_cache_states: engine.values.len(),
		maximum_outcome_probability_error: engine.probability_error,
		rows,
	};
	if serde_json::to_vec(&result)?.len() > 1024 * 1024 {
		bail!("semantic result exceeds byte budget");
	}
	Ok(result)
}
