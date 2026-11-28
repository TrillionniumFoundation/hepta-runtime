// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! A closed, label-free semantic weight program for an explicitly changed research graph.
//! It grants no session, artifact, routing or production authority. The mathematical sign
//! condition does not replace complete F32 forwards: cancellation and saturation can tie.

use super::{
	bound_io::{self, BoundModel, Inputs},
	trace::ResearchGraph,
};
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

const COORDINATES: [usize; 4] = [7, 16, 25, 34];

/// A checked view contains no target labels or model outputs. Input normalization,
/// including strictly positive price scale, is already checked by the raw-input binder.
pub struct LateQuoteMinV1<'a> {
	x: &'a [f32],
	baseline: &'a [f32],
	queries: usize,
	semantic_input_sha256: String,
}

impl<'a> LateQuoteMinV1<'a> {
	pub fn check(input: &'a Inputs) -> Result<Self> {
		ensure!(
			(1..=80).contains(&input.n)
				&& input.x.len() == input.n * 108
				&& input.baseline.len() == input.n * 2,
			"late-quote input dimensions"
		);
		ensure!(
			input.x.iter().chain(&input.baseline).all(|x| x.is_finite()),
			"late-quote finite inputs"
		);
		for query in 0..input.n {
			for tick in 0..6 {
				for column in 0..9 {
					let left = ((query * 6 + tick) * 2) * 9 + column;
					if tick == 5 && column == 7 {
						ensure!(
							input.x[left] != input.x[left + 9],
							"late quotes must differ"
						);
					} else {
						ensure!(
							input.x[left].to_bits() == input.x[left + 9].to_bits(),
							"late-quote choices require shared history and equal nonprice inputs"
						);
					}
				}
			}
			ensure!(
				input.baseline[query * 2].to_bits() == input.baseline[query * 2 + 1].to_bits(),
				"late-quote equal external baselines required"
			);
		}
		let mut bytes = b"hepta.late-quote-min.v1\0".to_vec();
		bytes.extend_from_slice(&(input.n as u64).to_le_bytes());
		for value in input.x.iter().chain(&input.baseline) {
			bytes.extend_from_slice(&value.to_le_bytes());
		}
		Ok(Self {
			x: &input.x,
			baseline: &input.baseline,
			queries: input.n,
			semantic_input_sha256: bound_io::sha(&bytes),
		})
	}

	pub fn evidence(&self) -> Value {
		json!({"schema":"hepta.late-quote-min.v1", "queries":self.queries,
			"semantic_input_sha256":self.semantic_input_sha256,"horizon":6,"price_column":7,
			"shared_prefix":true,"equal_final_nonprice":true,"equal_external_baseline":true,
			"labels_or_model_outputs_read":false,"normalized_value_count":self.x.len()+self.baseline.len()})
	}

	/// Validation happens after compilation. This does not provide labels to the compiler.
	pub fn validate_targets(&self, input: &Inputs) -> Result<()> {
		ensure!(
			LateQuoteMinV1::check(input)?.semantic_input_sha256 == self.semantic_input_sha256,
			"validation input differs from checked semantic task"
		);
		for query in 0..self.queries {
			let at = (query * 6 + 5) * 18 + 7;
			ensure!(
				input.labels[query] == u8::from(self.x[at + 9] < self.x[at]),
				"validation target differs from the declared lower-price task"
			);
		}
		Ok(())
	}
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FunctionIdentity {
	pub artifact_sha256: String,
	pub graph: ResearchGraph,
	pub evaluator_source_sha256: String,
	pub initial_state_contract: String,
	pub request_route: RequestRoute,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RequestRoute {
	OriginalFixedProfile,
	CheckedLateQuoteMinV1,
	ResearchUnconditionalNegativeControl,
}

impl FunctionIdentity {
	pub fn digest(&self) -> Result<String> {
		Ok(bound_io::sha(&serde_json::to_vec(self)?))
	}
}

/// An observation is bound to the full function, input and phase. A parent weight
/// digest alone is never a restoration witness for a graph-changing intervention.
/// Phase means this workflow's evaluation stage, not a captured live neuronal state.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct PhaseBinding {
	pub function: FunctionIdentity,
	pub input_sha256: String,
	pub phase: Phase,
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
	Parent,
	BridgeKeep,
	EditedCandidate,
	Retention,
	WeightsOnlyRestore,
	CompleteRestore,
}

pub struct ResearchState {
	bytes: Vec<u8>,
	identity: FunctionIdentity,
}

impl ResearchState {
	pub fn bytes(&self) -> &[u8] {
		&self.bytes
	}
	pub fn identity(&self) -> &FunctionIdentity {
		&self.identity
	}
	pub fn phase(&self, raw: &[u8], phase: Phase) -> PhaseBinding {
		PhaseBinding {
			function: self.identity.clone(),
			input_sha256: bound_io::sha(raw),
			phase,
		}
	}
}

#[derive(Clone, Debug, Serialize)]
pub struct WordEdit {
	pub tensor_index: usize,
	pub file_offset: usize,
	pub before_bits: u32,
	pub after_bits: u32,
	pub signed_head_contrast: f64,
}

/// Re-execute this compiler for every checkpoint; do not transplant a prior delta.
pub struct PreparedLateQuote {
	parent: FunctionIdentity,
	candidate: FunctionIdentity,
	semantic_input_sha256: String,
	edits: Vec<WordEdit>,
	active_signed_channels: usize,
	mark_offset: usize,
}

fn mark_extent(model: &BoundModel, bytes: &[u8]) -> Result<(usize, usize)> {
	let fact = model
		.tensor_facts
		.iter()
		.find(|fact| fact["name"] == "body.input_mark.weight")
		.context("bound mark tensor missing")?;
	let offset = usize::try_from(fact["file_offset"].as_u64().context("mark offset")?)?;
	let length = usize::try_from(fact["byte_length"].as_u64().context("mark extent")?)?;
	ensure!(
		length == 36 * 4
			&& offset
				.checked_add(length)
				.is_some_and(|end| end <= bytes.len()),
		"bound mark tensor extent"
	);
	Ok((offset, length))
}

pub fn compile(
	model: &BoundModel,
	parent: &[u8],
	task: &LateQuoteMinV1<'_>,
	evaluator_source_sha256: &str,
) -> Result<Option<PreparedLateQuote>> {
	ensure!(
		model.artifact_sha256 == bound_io::sha(parent)
			&& model.canonical_sha256 == model.artifact_sha256,
		"exact original canonical parent required"
	);
	ensure!(
		evaluator_source_sha256.len() == 64
			&& evaluator_source_sha256
				.bytes()
				.all(|x| x.is_ascii_hexdigit() && !x.is_ascii_uppercase()),
		"evaluator source SHA256 required"
	);
	let (offset, _) = mark_extent(model, parent)?;
	let head = model
		.tensors
		.get("body.readout.weight")
		.context("signed head missing")?;
	ensure!(head.len() == 40, "two by twenty head required");
	let mut candidate = parent.to_vec();
	let mut edits = Vec::new();
	let mut active_signed_channels = 0;
	for (channel, index) in COORDINATES.iter().copied().enumerate() {
		let v = head[20 + channel * 5 + 2] - head[channel * 5 + 2];
		ensure!(v.is_finite(), "finite signed head contrast required");
		if v == 0.0 {
			continue;
		}
		active_signed_channels += 1;
		let begin = offset + index * 4;
		let old = f32::from_le_bytes(parent[begin..begin + 4].try_into()?);
		ensure!(old.is_finite(), "finite parent mark word required");
		let magnitude = if old == 0.0 { 1.0 / 16.0 } else { old.abs() };
		let new = if v > 0.0 { -magnitude } else { magnitude };
		if old.to_bits() != new.to_bits() {
			candidate[begin..begin + 4].copy_from_slice(&new.to_le_bytes());
			edits.push(WordEdit {
				tensor_index: index,
				file_offset: begin,
				before_bits: old.to_bits(),
				after_bits: new.to_bits(),
				signed_head_contrast: v,
			});
		}
	}
	if active_signed_channels == 0 {
		return Ok(None);
	}
	let original = FunctionIdentity {
		artifact_sha256: bound_io::sha(parent),
		graph: ResearchGraph::Original,
		evaluator_source_sha256: evaluator_source_sha256.into(),
		initial_state_contract: "fixed_reset_step0_six_tick_v1".into(),
		request_route: RequestRoute::OriginalFixedProfile,
	};
	let next = FunctionIdentity {
		artifact_sha256: bound_io::sha(&candidate),
		graph: ResearchGraph::FinalTickTiedReceiverMark,
		evaluator_source_sha256: evaluator_source_sha256.into(),
		initial_state_contract: "fixed_reset_step0_six_tick_v1".into(),
		request_route: RequestRoute::CheckedLateQuoteMinV1,
	};
	Ok(Some(PreparedLateQuote {
		parent: original,
		candidate: next,
		semantic_input_sha256: task.semantic_input_sha256.clone(),
		edits,
		active_signed_channels,
		mark_offset: offset,
	}))
}

impl PreparedLateQuote {
	/// All four exact words, including unchanged words, bind graph-only candidates
	/// to the original nonempty cohort transaction without widening that owner.
	pub fn scope_words(
		&self,
		parent: &[u8],
		change_weights: bool,
	) -> Result<Vec<(usize, u32, u32)>> {
		ensure!(
			bound_io::sha(parent) == self.parent.artifact_sha256,
			"scope parent differs"
		);
		COORDINATES
			.iter()
			.map(|index| {
				let at = self.mark_offset + index * 4;
				let before = u32::from_le_bytes(parent[at..at + 4].try_into()?);
				let after = if change_weights {
					self.edits
						.iter()
						.find(|edit| edit.tensor_index == *index)
						.map_or(before, |edit| edit.after_bits)
				} else {
					before
				};
				Ok((*index, before, after))
			})
			.collect()
	}
	pub fn evidence(&self) -> Value {
		json!({"schema":"hepta.late-quote-program.v1","parent":self.parent,"candidate":self.candidate,
			"semantic_input_sha256":self.semantic_input_sha256,"edits":self.edits,
			"changed_f32_words":self.edits.len(),"active_signed_channels":self.active_signed_channels,
			"program_source_sha256":bound_io::sha(include_bytes!("late_quote.rs")),
			"labels_read":false,"gradient_steps":0,"full_forward_calls":0,
			"modified_graph":true,"maximum_changed_words":4,
			"requires_complete_f32_validation":true,"production_authority_granted":false})
	}
	pub fn parent(&self, bytes: &[u8]) -> Result<ResearchState> {
		ensure!(
			bound_io::sha(bytes) == self.parent.artifact_sha256,
			"parent bytes changed"
		);
		Ok(ResearchState {
			bytes: bytes.to_vec(),
			identity: self.parent.clone(),
		})
	}
	pub fn apply(
		&self,
		current: &ResearchState,
		task: &LateQuoteMinV1<'_>,
		change_weights: bool,
	) -> Result<ResearchState> {
		ensure!(
			task.semantic_input_sha256 == self.semantic_input_sha256,
			"checked task differs from the prepared semantic input binding"
		);
		ensure!(
			current.identity == self.parent
				&& bound_io::sha(&current.bytes) == self.parent.artifact_sha256,
			"prepared parent graph, evaluator or artifact changed"
		);
		let mut bytes = current.bytes.clone();
		if change_weights {
			for edit in &self.edits {
				let word = &mut bytes[edit.file_offset..edit.file_offset + 4];
				ensure!(
					word == edit.before_bits.to_le_bytes(),
					"prepared prior F32 word changed"
				);
				word.copy_from_slice(&edit.after_bits.to_le_bytes());
			}
			ensure!(
				bound_io::sha(&bytes) == self.candidate.artifact_sha256,
				"compiled candidate bytes differ"
			);
		}
		Ok(ResearchState {
			identity: FunctionIdentity {
				artifact_sha256: bound_io::sha(&bytes),
				..self.candidate.clone()
			},
			bytes,
		})
	}
	pub fn restore(&self, current: &ResearchState, changed_weights: bool) -> Result<ResearchState> {
		let expected = if changed_weights {
			self.candidate.clone()
		} else {
			FunctionIdentity {
				artifact_sha256: self.parent.artifact_sha256.clone(),
				..self.candidate.clone()
			}
		};
		ensure!(
			current.identity == expected
				&& bound_io::sha(&current.bytes) == expected.artifact_sha256,
			"inverse requires exact candidate function identity"
		);
		let mut bytes = current.bytes.clone();
		if changed_weights {
			for edit in &self.edits {
				let word = &mut bytes[edit.file_offset..edit.file_offset + 4];
				ensure!(
					word == edit.after_bits.to_le_bytes(),
					"inverse F32 word changed"
				);
				word.copy_from_slice(&edit.before_bits.to_le_bytes());
			}
		}
		ensure!(
			bound_io::sha(&bytes) == self.parent.artifact_sha256,
			"inverse did not restore all parent bytes"
		);
		Ok(ResearchState {
			bytes,
			identity: self.parent.clone(),
		})
	}
}

/// Separate scientific binding; does not expand the original hidden-artifact scope.
pub fn bind_candidate(
	mut model: BoundModel,
	parent: &[u8],
	candidate: &[u8],
) -> Result<BoundModel> {
	ensure!(
		model.artifact_sha256 == bound_io::sha(parent)
			&& model.canonical_sha256 == model.artifact_sha256,
		"research candidate requires canonical parent"
	);
	ensure!(
		parent.len() == candidate.len(),
		"research candidate length changed"
	);
	let (offset, length) = mark_extent(&model, parent)?;
	for (index, (old, new)) in parent.iter().zip(candidate).enumerate() {
		ensure!(
			old == new
				|| COORDINATES
					.iter()
					.any(|word| (offset + word * 4..offset + word * 4 + 4).contains(&index)),
			"research candidate changed a protected byte"
		);
	}
	let values = model
		.tensors
		.get_mut("body.input_mark.weight")
		.context("mark values")?;
	for index in COORDINATES {
		let begin = offset + index * 4;
		let value = f32::from_le_bytes(candidate[begin..begin + 4].try_into()?);
		ensure!(value.is_finite(), "nonfinite research mark word");
		values[index] = f64::from(value);
	}
	let fact = model
		.tensor_facts
		.iter_mut()
		.find(|fact| fact["name"] == "body.input_mark.weight")
		.context("mark fact missing")?;
	fact["payload_sha256"] = json!(bound_io::sha(&candidate[offset..offset + length]));
	model.artifact_sha256 = bound_io::sha(candidate);
	Ok(model)
}

/// A goal gate over measured observations. The complete owner still must verify
/// retention and rollback. This gate is not a prediction, a global optimizer or permission.
pub fn goal_met(correct: usize, queries: usize, minimum_percent: u32) -> Result<bool> {
	ensure!(
		(1..=80).contains(&queries) && correct <= queries && (1..=100).contains(&minimum_percent),
		"bounded measured goal required"
	);
	Ok(correct * 100 >= queries * minimum_percent as usize)
}
