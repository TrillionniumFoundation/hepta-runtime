// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Pure composition of a bounded F32 edit program around one immutable anchor.
//!
//! Intermediate steps are plans, never published models. All touched coordinates,
//! including cancelled changes and exact no-ops, remain in the output. The final
//! represented-number radius is checked by the existing native weight_norm core.
//! Supplied hashes bind a program; the existing artifact owner must authenticate
//! actual source bytes before publication. This module owns no files, workers,
//! evaluation partitions, production pointer, or cross-request authority.

use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Write};

use super::weight_norm;
use super::weight_tensor::{unhex, ExactElementEdit};

const SCHEMA: &str = "hepta.weight.program-composition.v1";
const MAX_TENSORS: usize = 32;
const MAX_STEPS: usize = 64;
const MAX_UNION_ELEMENTS: usize = 1024;
const MAX_PROGRAM_EDITS: usize = 4096;
const MAX_TENSOR_ELEMENTS: u64 = 1_048_576;
const MAX_REQUEST_BYTES: usize = 1024 * 1024;
const MAX_RESULT_BYTES: usize = 2 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Binding {
	/// Complete original checkpoint identity, never only a header commitment.
	pub base_checkpoint_sha256: String,
	pub model_graph_sha256: String,
	pub tensor_map_sha256: String,
	pub semantics_sha256: String,
	/// Binds the declared rows, split rules, time, units and evaluation protocol.
	/// This is a caller commitment, not independent holdout custody.
	pub row_protocol_sha256: String,
	pub objective_sha256: String,
	pub dependency_manifest_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TensorContract {
	pub name: String,
	pub dtype: String,
	pub layout: String,
	pub shape: Vec<u64>,
	pub source_tensor_sha256: String,
	pub protected: bool,
	pub maximum_update_l2_norm: f64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TensorStep {
	pub tensor_name: String,
	pub edits: Vec<ExactElementEdit>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Step {
	pub step_id: String,
	/// Every step repeats the same frozen anchor and semantic contract.
	pub binding: Binding,
	pub members: Vec<TensorStep>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Request {
	pub schema: String,
	pub binding: Binding,
	pub tensors: Vec<TensorContract>,
	pub maximum_update_l2_norm: f64,
	pub steps: Vec<Step>,
}

#[derive(Debug, Serialize)]
pub(super) struct HistoryEntry {
	pub step_index: usize,
	pub expected_hex: String,
	pub replacement_hex: String,
}

#[derive(Debug, Serialize)]
pub(super) struct CoordinateHistory {
	pub index: u64,
	/// Complete edit history, including a final restoration to the anchor.
	pub changes: Vec<HistoryEntry>,
}

#[derive(Debug, Serialize)]
pub(super) struct MemberPlan {
	pub tensor_name: String,
	pub dtype: String,
	pub layout: String,
	pub shape: Vec<u64>,
	pub source_tensor_sha256: String,
	pub maximum_update_l2_norm: f64,
	/// One original-anchor to final-value edit for every touched coordinate.
	/// Final no-ops remain present so the artifact owner can authenticate them.
	pub edits: Vec<ExactElementEdit>,
	pub history: Vec<CoordinateHistory>,
	pub net_update_budget: Value,
}

#[derive(Debug, Serialize)]
pub(super) struct StepReceipt {
	pub step_index: usize,
	pub step_id: String,
	pub step_sha256: String,
	pub edit_count: usize,
}

#[derive(Debug, Serialize)]
pub(super) struct Plan {
	pub schema: &'static str,
	pub program_sha256: String,
	pub binding: Binding,
	pub members: Vec<MemberPlan>,
	pub steps: Vec<StepReceipt>,
	pub total_step_edits: usize,
	pub union_elements: usize,
	pub changed_elements: usize,
	/// Coordinates with an intermediate byte change and final original bytes.
	pub cancelled_elements: usize,
	pub net_update_budget: Value,
	pub source_authenticated: bool,
	pub independent_holdout_verified: bool,
	pub cross_request_budget_enforced: bool,
	pub intermediate_models_executed: bool,
	pub weights_modified: bool,
	pub production_eligible: bool,
}

struct BoundedBytes {
	bytes: Vec<u8>,
	limit: usize,
}

impl Write for BoundedBytes {
	fn write(&mut self, data: &[u8]) -> io::Result<usize> {
		if data.len() > self.limit.saturating_sub(self.bytes.len()) {
			return Err(io::Error::other(
				"composition serialization budget exceeded",
			));
		}
		self.bytes.extend_from_slice(data);
		Ok(data.len())
	}

	fn flush(&mut self) -> io::Result<()> {
		Ok(())
	}
}

fn encode<T: Serialize>(value: &T, limit: usize) -> Result<Vec<u8>> {
	let mut writer = BoundedBytes {
		bytes: Vec::new(),
		limit,
	};
	serde_json::to_writer(&mut writer, value)?;
	Ok(writer.bytes)
}

pub(super) fn sha256(bytes: &[u8]) -> String {
	Sha256::digest(bytes)
		.iter()
		.map(|byte| format!("{byte:02x}"))
		.collect()
}

fn valid_sha256(value: &str) -> bool {
	value.len() == 64
		&& value
			.bytes()
			.all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_binding(binding: &Binding) -> Result<()> {
	for value in [
		&binding.base_checkpoint_sha256,
		&binding.model_graph_sha256,
		&binding.tensor_map_sha256,
		&binding.semantics_sha256,
		&binding.row_protocol_sha256,
		&binding.objective_sha256,
		&binding.dependency_manifest_sha256,
	] {
		if !valid_sha256(value) {
			bail!("composition binding requires complete lowercase SHA-256 values");
		}
	}
	Ok(())
}

fn tensor_elements(tensor: &TensorContract) -> Result<u64> {
	if tensor.name.is_empty()
		|| tensor.name.len() > 4096
		|| tensor.name.contains('\0')
		|| tensor.dtype != "F32"
		|| tensor.layout != "row_major_le"
		|| tensor.shape.is_empty()
		|| tensor.shape.len() > 8
		|| !valid_sha256(&tensor.source_tensor_sha256)
	{
		bail!("invalid F32 tensor name, dtype, layout, shape or source identity");
	}
	let mut count = 1_u64;
	for dimension in &tensor.shape {
		count = count
			.checked_mul(*dimension)
			.ok_or_else(|| anyhow!("composition tensor dimension product overflow"))?;
		if *dimension == 0 || count > MAX_TENSOR_ELEMENTS {
			bail!("composition tensor exceeds the bounded positive shape contract");
		}
	}
	weight_norm::validate_radius(tensor.maximum_update_l2_norm)?;
	Ok(count)
}

/// Canonical descriptor commitment, independent of tensor array order.
/// Shape/dtype/source identity are included; policy flags and radii are separately
/// bound by the complete program SHA. This helper does not inspect a checkpoint.
pub(super) fn tensor_map_sha256(tensors: &[TensorContract]) -> Result<String> {
	if !(1..=MAX_TENSORS).contains(&tensors.len()) {
		bail!("composition requires 1 to 32 tensor contracts");
	}
	let mut descriptors = BTreeMap::new();
	for tensor in tensors {
		tensor_elements(tensor)?;
		if descriptors
			.insert(
				&tensor.name,
				(
					&tensor.dtype,
					&tensor.layout,
					&tensor.shape,
					&tensor.source_tensor_sha256,
				),
			)
			.is_some()
		{
			bail!("duplicate tensor contract name");
		}
	}
	Ok(sha256(&encode(
		&("hepta.weight.f32-tensor-map.v1", descriptors),
		MAX_REQUEST_BYTES,
	)?))
}

fn element(value: &str) -> Result<f32> {
	if value.len() != 8 {
		bail!("composition requires exactly four F32 little-endian bytes");
	}
	let bytes = unhex(value)?;
	let result = f32::from_le_bytes(bytes.try_into().map_err(|_| anyhow!("invalid F32 bytes"))?);
	if !result.is_finite() {
		bail!("composition requires finite intermediate and final F32 values");
	}
	Ok(result)
}

struct Coordinate {
	original: String,
	current: String,
	ever_changed: bool,
	history: Vec<HistoryEntry>,
}

/// Compose only the declared program. Passing this pure function grants no
/// authority to consume a holdout, publish an artifact, or select a live model.
pub(super) fn compose(request: &Request) -> Result<Plan> {
	if request.schema != SCHEMA || !(1..=MAX_STEPS).contains(&request.steps.len()) {
		bail!("composition requires its exact schema and 1 to 64 steps");
	}
	validate_binding(&request.binding)?;
	weight_norm::validate_radius(request.maximum_update_l2_norm)?;
	if tensor_map_sha256(&request.tensors)? != request.binding.tensor_map_sha256 {
		bail!("tensor descriptor map differs from the frozen composition binding");
	}
	let program_sha256 = sha256(&encode(request, MAX_REQUEST_BYTES)?);
	let contracts: BTreeMap<_, _> = request
		.tensors
		.iter()
		.map(|tensor| (tensor.name.as_str(), tensor))
		.collect();
	let mut coordinates: BTreeMap<(String, u64), Coordinate> = BTreeMap::new();
	let mut step_ids = BTreeSet::new();
	let mut steps = Vec::with_capacity(request.steps.len());
	let mut total_step_edits = 0usize;

	for (step_index, step) in request.steps.iter().enumerate() {
		if step.binding != request.binding {
			bail!("step binding differs from the frozen original model or protocol");
		}
		if !valid_sha256(&step.step_id) || !step_ids.insert(&step.step_id) {
			bail!("step identity must be unique and a complete lowercase SHA-256");
		}
		if !(1..=MAX_TENSORS).contains(&step.members.len()) {
			bail!("each composition step requires 1 to 32 tensor members");
		}
		let mut names = BTreeSet::new();
		let mut step_edits = 0usize;
		for member in &step.members {
			if !names.insert(&member.tensor_name) {
				bail!("duplicate tensor member in one composition step");
			}
			let contract = contracts
				.get(member.tensor_name.as_str())
				.ok_or_else(|| anyhow!("step references an undeclared tensor"))?;
			if contract.protected {
				bail!("composition may not touch a protected tensor, including no-ops");
			}
			let extent = tensor_elements(contract)?;
			if !(1..=MAX_UNION_ELEMENTS).contains(&member.edits.len()) {
				bail!("composition member requires 1 to 1024 exact edits");
			}
			step_edits = step_edits
				.checked_add(member.edits.len())
				.ok_or_else(|| anyhow!("composition step edit count overflow"))?;
			if step_edits > MAX_UNION_ELEMENTS {
				bail!("one composition step exceeds the existing 1024-element cap");
			}
			total_step_edits = total_step_edits
				.checked_add(member.edits.len())
				.ok_or_else(|| anyhow!("composition program edit count overflow"))?;
			if total_step_edits > MAX_PROGRAM_EDITS {
				bail!("composition exceeds the 4096-operation program budget");
			}
			let mut indices = BTreeSet::new();
			for edit in &member.edits {
				if edit.index >= extent || !indices.insert(edit.index) {
					bail!("duplicate or out-of-range coordinate within one step");
				}
				element(&edit.expected_hex)?;
				element(&edit.replacement_hex)?;
				let key = (member.tensor_name.clone(), edit.index);
				if !coordinates.contains_key(&key) && coordinates.len() >= MAX_UNION_ELEMENTS {
					bail!("composition touched-coordinate union exceeds 1024 elements");
				}
				let coordinate = coordinates.entry(key).or_insert_with(|| Coordinate {
					original: edit.expected_hex.clone(),
					current: edit.expected_hex.clone(),
					ever_changed: false,
					history: Vec::new(),
				});
				if coordinate.current != edit.expected_hex {
					bail!("discontinuous old/new bytes in composition at step {step_index}");
				}
				coordinate.ever_changed |= edit.replacement_hex != coordinate.original;
				coordinate.current.clone_from(&edit.replacement_hex);
				coordinate.history.push(HistoryEntry {
					step_index,
					expected_hex: edit.expected_hex.clone(),
					replacement_hex: edit.replacement_hex.clone(),
				});
			}
		}
		steps.push(StepReceipt {
			step_index,
			step_id: step.step_id.clone(),
			step_sha256: sha256(&encode(step, MAX_REQUEST_BYTES)?),
			edit_count: step_edits,
		});
	}

	let union_elements = coordinates.len();
	let mut grouped: BTreeMap<String, Vec<(u64, Coordinate)>> = BTreeMap::new();
	for ((name, index), coordinate) in coordinates {
		grouped.entry(name).or_default().push((index, coordinate));
	}
	let mut members = Vec::with_capacity(grouped.len());
	let mut pairs = Vec::with_capacity(union_elements);
	let mut changed_elements = 0usize;
	let mut cancelled_elements = 0usize;
	for (name, group) in grouped {
		let contract = contracts
			.get(name.as_str())
			.ok_or_else(|| anyhow!("composition lost a validated tensor contract"))?;
		let mut member_pairs = Vec::with_capacity(group.len());
		let mut edits = Vec::with_capacity(group.len());
		let mut history = Vec::with_capacity(group.len());
		for (index, coordinate) in group {
			let pair = (
				element(&coordinate.original)?,
				element(&coordinate.current)?,
			);
			member_pairs.push(pair);
			pairs.push(pair);
			if coordinate.original != coordinate.current {
				changed_elements += 1;
			} else if coordinate.ever_changed {
				cancelled_elements += 1;
			}
			edits.push(ExactElementEdit {
				index,
				expected_hex: coordinate.original,
				replacement_hex: coordinate.current,
			});
			history.push(CoordinateHistory {
				index,
				changes: coordinate.history,
			});
		}
		let budget = weight_norm::check_pairs(member_pairs, contract.maximum_update_l2_norm)?;
		if !budget.within_budget {
			bail!("composed member exceeds its exact radius from the original anchor");
		}
		members.push(MemberPlan {
			tensor_name: name,
			dtype: contract.dtype.clone(),
			layout: contract.layout.clone(),
			shape: contract.shape.clone(),
			source_tensor_sha256: contract.source_tensor_sha256.clone(),
			maximum_update_l2_norm: contract.maximum_update_l2_norm,
			edits,
			history,
			net_update_budget: serde_json::to_value(budget)?,
		});
	}
	let net_update_budget = weight_norm::check_pairs(pairs, request.maximum_update_l2_norm)?;
	if !net_update_budget.within_budget {
		bail!("composed program exceeds its exact global radius from the original anchor");
	}
	let plan = Plan {
		schema: SCHEMA,
		program_sha256,
		binding: request.binding.clone(),
		members,
		steps,
		total_step_edits,
		union_elements,
		changed_elements,
		cancelled_elements,
		net_update_budget: serde_json::to_value(net_update_budget)?,
		source_authenticated: false,
		independent_holdout_verified: false,
		cross_request_budget_enforced: false,
		intermediate_models_executed: false,
		weights_modified: false,
		production_eligible: false,
	};
	let _ = encode(&plan, MAX_RESULT_BYTES)?;
	Ok(plan)
}

#[cfg(test)]
#[path = "composition_tests.rs"]
mod tests;
