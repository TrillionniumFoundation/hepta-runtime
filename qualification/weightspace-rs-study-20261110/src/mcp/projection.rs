// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Candidate-only F32 sparse projection planner. No autograd, optimizer, file writes or activation.
//! It emits existing ExactElementEdit bytes for an already verified tensor snapshot.
//! Source-file authentication and durable publication remain with the existing runtime owner.
use super::{weight_norm, weight_tensor::ExactElementEdit};
use anyhow::{bail, Result};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub fn digest(data: &[u8]) -> String {
	Sha256::digest(data).iter().map(|b| format!("{b:02x}")).collect()
}
fn valid_hash(s: &str) -> bool {
	s.len() == 64 && s.bytes().all(|x| x.is_ascii_digit() || (b'a'..=b'f').contains(&x))
}
fn hex32(x: f32) -> String {
	x.to_le_bytes().iter().map(|b| format!("{b:02x}")).collect()
}
fn tensor_hash(schema: &str, values: &[f32]) -> String {
	let mut h = Sha256::new();
	h.update(b"hepta.research.f32-snapshot.v1\0");
	h.update(schema.as_bytes());
	for x in values { h.update(x.to_le_bytes()); }
	h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(Clone, Debug)]
pub struct FrozenTensor {
	name: String,
	rows: usize,
	cols: usize,
	values: Vec<f32>,
	source_file_sha256: String,
	schema_sha256: String,
	tensor_sha256: String,
}
impl FrozenTensor {
	pub fn new(name: &str, rows: usize, cols: usize, values: Vec<f32>, source: &str) -> Result<Self> {
		let count = rows.checked_mul(cols);
		if name.is_empty() || name.len() > 4096 || rows == 0 || cols == 0 || rows > 4096 || cols > 4096
			|| count.is_none_or(|n| n > 1_048_576 || n != values.len()) || !valid_hash(source)
			|| values.iter().any(|x| !x.is_finite()) {
			bail!("invalid tensor name, dimensions, finite F32 storage or source commitment");
		}
		let schema_sha256 = digest(&serde_json::to_vec(&json!({"schema":"f32_row_major_v1","name":name,"rows":rows,"cols":cols}))?);
		let tensor_sha256 = tensor_hash(&schema_sha256, &values);
		Ok(Self { name: name.into(), rows, cols, values, source_file_sha256: source.into(), schema_sha256, tensor_sha256 })
	}
	pub fn values(&self) -> &[f32] { &self.values }
	pub fn sha256(&self) -> &str { &self.tensor_sha256 }
	pub fn schema_sha256(&self) -> &str { &self.schema_sha256 }
	pub fn binding(&self, protocol: &str) -> Binding {
		Binding { source_file_sha256:self.source_file_sha256.clone(), tensor_sha256:self.tensor_sha256.clone(), schema_sha256:self.schema_sha256.clone(), protocol_sha256:protocol.into() }
	}
}

#[derive(Clone, Debug, Serialize)]
pub struct Binding {
	pub source_file_sha256: String,
	pub tensor_sha256: String,
	pub schema_sha256: String,
	pub protocol_sha256: String,
}
#[derive(Clone, Debug, Serialize)]
pub struct Policy {
	pub max_touched_elements: usize,
	pub max_abs_delta: f64,
	pub max_update_l2: f64,
	pub max_alpha: f64,
	pub protected_tensors: BTreeSet<String>,
}
impl Default for Policy {
	fn default() -> Self {
		Self { max_touched_elements:1024, max_abs_delta:1.0, max_update_l2:1.0, max_alpha:8.0, protected_tensors:BTreeSet::new() }
	}
}
#[derive(Clone, Debug, Serialize)]
#[serde(tag="kind",rename_all="snake_case")]
pub enum Program {
	SparseColumnProjection { columns:Vec<usize>, unit_direction:Vec<f64>, alpha:f64 },
	Coordinates { edits:Vec<Coordinate> },
}
#[derive(Clone, Debug, Serialize)]
pub struct Coordinate {
	pub index:usize,
	pub expected_f32_bits:u32,
	pub replacement:f32,
}
#[derive(Debug)]
pub struct Candidate {
	source_file_sha256:String,
	base_sha256:String,
	schema_sha256:String,
	protocol_sha256:String,
	values:Vec<f32>,
	sha256:String,
	exact_edits:Vec<ExactElementEdit>,
	receipt:Value,
}
impl Candidate {
	pub fn values(&self) -> &[f32] { &self.values }
	pub fn sha256(&self) -> &str { &self.sha256 }
	pub fn base_sha256(&self) -> &str { &self.base_sha256 }
	pub fn protocol_sha256(&self) -> &str { &self.protocol_sha256 }
	pub fn receipt(&self) -> &Value { &self.receipt }
	pub fn edits(&self) -> &[ExactElementEdit] { &self.exact_edits }
	pub fn revalidate(&self, base:&FrozenTensor, protocol:&str) -> Result<()> {
		if self.source_file_sha256 != base.source_file_sha256 || self.base_sha256 != base.tensor_sha256 || self.schema_sha256 != base.schema_sha256 || self.protocol_sha256 != protocol
			|| self.sha256 != tensor_hash(&self.schema_sha256,&self.values) {
			bail!("candidate is stale, cross-protocol or corrupt");
		}
		Ok(())
	}
}

pub fn plan(base:&FrozenTensor, binding:&Binding, program:&Program, policy:&Policy) -> Result<Candidate> {
	if binding.source_file_sha256 != base.source_file_sha256 || binding.tensor_sha256 != base.tensor_sha256
		|| binding.schema_sha256 != base.schema_sha256 || !valid_hash(&binding.protocol_sha256) {
		bail!("base/source/schema mismatch or invalid frozen protocol");
	}
	if policy.protected_tensors.contains(&base.name) { bail!("protected tensor"); }
	if !(1..=1024).contains(&policy.max_touched_elements) || !policy.max_alpha.is_finite() || policy.max_alpha < 0.0 {
		bail!("invalid planner policy");
	}
	weight_norm::validate_radius(policy.max_update_l2)?;
	weight_norm::validate_radius(policy.max_abs_delta)?;
	let mut values = base.values.clone();
	let touched;
	match program {
		Program::SparseColumnProjection { columns, unit_direction:u, alpha } => {
			if columns.is_empty() || columns.len() > base.cols || u.len()!=base.rows
				|| !alpha.is_finite() || *alpha < 0.0 || *alpha > policy.max_alpha || u.iter().any(|x| !x.is_finite()) {
				bail!("invalid sparse projection dimensions or finite direction/dose");
			}
			touched = base.rows.checked_mul(columns.len()).ok_or_else(||anyhow::anyhow!("projection size overflow"))?;
			if touched > policy.max_touched_elements { bail!("projection exceeds existing atomic exact-edit capacity"); }
			let unique:BTreeSet<_> = columns.iter().copied().collect();
			if unique.len()!=columns.len() || unique.iter().any(|j| *j>=base.cols) { bail!("duplicate or out-of-range column"); }
			let norm=u.iter().fold(0.0_f64,|n,x|n.hypot(*x));
			if (norm-1.0).abs()>1e-10 { bail!("direction must be unit length; no implicit normalization"); }
			// Every projected column uses only the immutable base, never an earlier mutation.
			for &j in columns {
				let mut component=0.0_f64;
				for (i,ui) in u.iter().enumerate() { component += ui*f64::from(base.values[i*base.cols+j]); }
				if !component.is_finite() { bail!("projection accumulation overflow"); }
				for (i,ui) in u.iter().enumerate() {
					let index=i*base.cols+j;
					let x=f64::from(base.values[index])-alpha*ui*component;
					let lowered=x as f32;
					if !x.is_finite() || !lowered.is_finite() { bail!("projection F64/F32 overflow"); }
					values[index]=lowered;
				}
			}
		}
		Program::Coordinates { edits } => {
			touched=edits.len();
			if touched==0 || touched>policy.max_touched_elements { bail!("coordinate count exceeds existing atomic capacity"); }
			let mut seen=BTreeSet::new();
			for edit in edits {
				if edit.index>=values.len() || !seen.insert(edit.index) || !edit.replacement.is_finite() { bail!("duplicate, nonfinite or out-of-range coordinate"); }
				if base.values[edit.index].to_bits()!=edit.expected_f32_bits { bail!("coordinate expected bytes mismatch"); }
				values[edit.index]=edit.replacement;
			}
		}
	}
	let mut edits=Vec::new();
	let mut delta_l2=0.0_f64;
	for (index,(&before,&after)) in base.values.iter().zip(&values).enumerate() {
		if before.to_bits()!=after.to_bits() {
			if !weight_norm::check_pairs([(before,after)],policy.max_abs_delta)?.within_budget { bail!("exact per-coordinate budget exceeded"); }
			delta_l2=delta_l2.hypot(f64::from(after)-f64::from(before));
			edits.push(ExactElementEdit { index:index as u64, expected_hex:hex32(before), replacement_hex:hex32(after) });
		}
	}
	if edits.is_empty() { bail!("no realized stored-F32 change"); }
	let exact_budget=weight_norm::check_edits(&edits,policy.max_update_l2)?;
	if !exact_budget.within_budget { bail!("exact stored-F32 joint L2 budget exceeded"); }
	let candidate_sha256=tensor_hash(&base.schema_sha256,&values);
	let plan_sha256=digest(&serde_json::to_vec(&(binding,program,policy,&edits))?);
	let base_l2=base.values.iter().fold(0.0_f64,|n,x|n.hypot(f64::from(*x)));
	let receipt=json!({
		"schema":"hepta.research.sparse-projection.v1","plan_sha256":plan_sha256,"binding":binding,
		"tensor_name":base.name,"rows":base.rows,"columns":base.cols,"dtype":"F32",
		"program":program,"policy":policy,"candidate_tensor_sha256":candidate_sha256,
		"selected_elements":touched,"actual_changed_elements":edits.len(),"edits":edits,
		"exact_joint_budget":exact_budget,"diagnostic_delta_l2":delta_l2,
		"diagnostic_relative_delta_l2":if base_l2>0.0 {Some(delta_l2/base_l2)} else {None},
		"gradient_steps":0,"source_modified":false,"production_eligible":false,
		"source_file_authenticated_here":false,"required_owner":"existing weight_artifact / weight_guard_journal",
		"meaning":"bounded compilation of a supplied direction; no discovery, general circuit understanding, global optimality or task-value claim"
	});
	Ok(Candidate { source_file_sha256:base.source_file_sha256.clone(),base_sha256:base.tensor_sha256.clone(),schema_sha256:base.schema_sha256.clone(),protocol_sha256:binding.protocol_sha256.clone(),values,sha256:candidate_sha256,exact_edits:edits,receipt })
}
#[cfg(test)]
#[path="projection_tests.rs"]
mod tests;
