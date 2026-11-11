// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! In-memory research contract for a candidate-only confirmation broker.
//! This does not replace weight_guard_journal or prove unseen/independent data.
//! It shows source/protocol binding, exact-row anti-reuse, finite quality/preservation
//! gates, a rollback of a research preview pointer, and a tamper-evident event chain.
use super::projection::{digest, Candidate, FrozenTensor};
use anyhow::{bail, Result};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::BTreeSet;

#[derive(Clone,Copy,Debug,Serialize,PartialEq,Eq)]
#[serde(rename_all="snake_case")]
pub enum Role { Calibration, Confirmation }
#[derive(Clone,Debug,Serialize)]
pub struct Example {
	pub id:String,
	pub input:Vec<f32>,
	pub target:Vec<f32>,
	pub regression:bool,
}
#[derive(Clone,Debug)]
pub struct Partition {
	role:Role,
	examples:Vec<Example>,
	sha256:String,
	input_fingerprints:BTreeSet<String>,
	row_ids:BTreeSet<String>,
}
impl Partition {
	pub fn new(role:Role, examples:Vec<Example>) -> Result<Self> {
		if examples.is_empty() || examples.len()>64 { bail!("confirmation partition supports 1..64 rows"); }
		let mut fingerprints=BTreeSet::new();let mut row_ids=BTreeSet::new();
		for row in &examples {
			if row.id.is_empty() || row.id.len()>256 || row.input.is_empty() || row.input.len()>4096 || row.target.is_empty() || row.target.len()>4096
				|| row.input.iter().chain(&row.target).any(|x|!x.is_finite()) || !row_ids.insert(row.id.clone()) {
				bail!("invalid finite example or duplicate row identity");
			}
			// Ignore supplied labels and row aliases when detecting exact input reuse.
			let bits:Vec<u32>=row.input.iter().map(|x|x.to_bits()).collect();
			if !fingerprints.insert(digest(&serde_json::to_vec(&bits)?)) { bail!("duplicate input content within partition"); }
		}
		if !examples.iter().any(|r|!r.regression) || !examples.iter().any(|r|r.regression) {
			bail!("both primary and regression rows are mandatory");
		}
		let sha256=digest(&serde_json::to_vec(&(role,&examples))?);
		Ok(Self { role,examples,sha256,input_fingerprints:fingerprints,row_ids })
	}
}
#[derive(Clone,Debug,Serialize)]
pub struct Protocol {
	base_sha256:String,
	calibration_sha256:String,
	confirmation_sha256:String,
	minimum_each_primary_gain:f64,
	maximum_regression_output_change:f64,
	sha256:String,
}
impl Protocol {
	pub fn freeze(base:&FrozenTensor, calibration:&Partition, confirmation:&Partition, min_gain:f64, regression:f64) -> Result<Self> {
		if calibration.role!=Role::Calibration || confirmation.role!=Role::Confirmation || !min_gain.is_finite() || min_gain<0.0 || !regression.is_finite() || regression<0.0 {
			bail!("invalid partition roles or declared gate");
		}
		if !calibration.input_fingerprints.is_disjoint(&confirmation.input_fingerprints) || !calibration.row_ids.is_disjoint(&confirmation.row_ids) {
			bail!("calibration and confirmation share exact input content or row identities");
		}
		let sha256=digest(&serde_json::to_vec(&("hepta.research.confirmation-protocol.v1",base.sha256(),&calibration.sha256,&confirmation.sha256,min_gain,regression))?);
		Ok(Self {base_sha256:base.sha256().into(),calibration_sha256:calibration.sha256.clone(),confirmation_sha256:confirmation.sha256.clone(),minimum_each_primary_gain:min_gain,maximum_regression_output_change:regression,sha256})
	}
	pub fn sha256(&self) -> &str { &self.sha256 }
}
#[derive(Clone,Debug,Serialize)]
struct Metrics {
	primary_rows:usize,
	mean_primary_gain:f64,
	minimum_primary_gain:f64,
	regression_rows:usize,
	maximum_regression_output_change:f64,
}
fn score(base:&FrozenTensor,candidate:&Candidate,partition:&Partition) -> Result<Metrics> {
	let receipt=candidate.receipt();
	let rows=receipt["rows"].as_u64().ok_or_else(||anyhow::anyhow!("missing rows"))? as usize;
	let cols=receipt["columns"].as_u64().ok_or_else(||anyhow::anyhow!("missing columns"))? as usize;
	let mut gains=Vec::new();let mut regressions=0;let mut maximum=0.0_f64;
	for example in &partition.examples {
		if example.input.len()!=cols || example.target.len()!=rows { bail!("example is not complete for the declared tensor schema"); }
		let mut before_error=0.0;let mut after_error=0.0;
		for output in 0..rows {
			let mut before=0.0_f32;let mut after=0.0_f32;
			for input in 0..cols {
				// Scope: the same explicit separate F32 multiply/add order in each arm.
				before += base.values()[output*cols+input]*example.input[input];
				after += candidate.values()[output*cols+input]*example.input[input];
			}
			if !before.is_finite() || !after.is_finite() { bail!("nonfinite native F32 evaluation"); }
			before_error+=(f64::from(before)-f64::from(example.target[output])).powi(2);
			after_error+=(f64::from(after)-f64::from(example.target[output])).powi(2);
			if example.regression { maximum=maximum.max((f64::from(after)-f64::from(before)).abs()); }
		}
		if example.regression { regressions+=1; } else { gains.push((before_error-after_error)/rows as f64); }
	}
	Ok(Metrics {primary_rows:gains.len(),mean_primary_gain:gains.iter().sum::<f64>()/gains.len() as f64,minimum_primary_gain:gains.into_iter().fold(f64::INFINITY,f64::min),regression_rows:regressions,maximum_regression_output_change:maximum})
}
fn passes(metrics:&Metrics,protocol:&Protocol) -> bool {
	metrics.minimum_primary_gain>protocol.minimum_each_primary_gain && metrics.maximum_regression_output_change<=protocol.maximum_regression_output_change
}
#[derive(Clone,Debug,Serialize)]
pub struct Event {
	previous_sha256:String,
	payload:Value,
	sha256:String,
}
#[derive(Debug,Serialize)]
pub struct PreviewResult {
	pub accepted:bool,
	pub outcome:String,
	pub pointer_before:String,
	pub pointer_after:String,
	pub rollback_verified:bool,
	pub report:Value,
}
pub struct SplitUseBroker {
	consumed_inputs:BTreeSet<String>,
	consumed_ids:BTreeSet<String>,
	preview_pointer:String,
	events:Vec<Event>,
}
impl SplitUseBroker {
	pub fn new(base:&FrozenTensor) -> Self {
		Self {consumed_inputs:BTreeSet::new(),consumed_ids:BTreeSet::new(),preview_pointer:base.sha256().into(),events:Vec::new()}
	}
	pub fn preview_pointer(&self) -> &str { &self.preview_pointer }
	pub fn events(&self) -> &[Event] { &self.events }
	fn append(&mut self,payload:Value) -> Result<()> {
		let previous=self.events.last().map(|e|e.sha256.clone()).unwrap_or_else(||digest(b"hepta.research.confirmation-ledger.v1"));
		let sha256=digest(&serde_json::to_vec(&(&previous,&payload))?);
		self.events.push(Event {previous_sha256:previous,payload,sha256});Ok(())
	}
	pub fn verify_chain(&self) -> Result<()> {
		let mut previous=digest(b"hepta.research.confirmation-ledger.v1");
		for e in &self.events {
			if e.previous_sha256!=previous || e.sha256!=digest(&serde_json::to_vec(&(&previous,&e.payload))?) { bail!("event chain mismatch"); }
			previous=e.sha256.clone();
		}Ok(())
	}
	pub fn confirm(&mut self,base:&FrozenTensor,candidate:&Candidate,protocol:&Protocol,calibration:&Partition,confirmation:&Partition) -> Result<PreviewResult> {
		candidate.revalidate(base,protocol.sha256())?;
		if protocol.base_sha256!=base.sha256() || self.preview_pointer!=base.sha256() || protocol.calibration_sha256!=calibration.sha256 || protocol.confirmation_sha256!=confirmation.sha256 {
			bail!("stale incumbent, changed partition or mismatched protocol");
		}
		if !self.consumed_inputs.is_disjoint(&confirmation.input_fingerprints) || !self.consumed_ids.is_disjoint(&confirmation.row_ids) { bail!("confirmation rows already consumed; adaptive reuse refused"); }
		let before=self.preview_pointer.clone();
		let calibration_metrics=score(base,candidate,calibration)?;
		if !passes(&calibration_metrics,protocol) {
			let report=json!({"calibration":calibration_metrics,"confirmation_evaluated":false,"gradient_steps":0,"production_eligible":false});
			self.append(json!({"phase":"calibration_rejected","candidate":candidate.sha256(),"protocol":protocol.sha256(),"report":report}))?;
			return Ok(PreviewResult {accepted:false,outcome:"calibration_rejected".into(),pointer_before:before.clone(),pointer_after:before,rollback_verified:true,report});
		}
		// Consume rows BEFORE any confirmation computation; failure does not free them.
		self.consumed_inputs.extend(confirmation.input_fingerprints.iter().cloned());
		self.consumed_ids.extend(confirmation.row_ids.iter().cloned());
		self.append(json!({"phase":"confirmation_started","candidate":candidate.sha256(),"protocol":protocol.sha256(),"pointer_before":before}))?;
		self.preview_pointer=candidate.sha256().into();
		let evaluated=score(base,candidate,confirmation);
		let accepted=evaluated.as_ref().is_ok_and(|m|passes(m,protocol));
		if !accepted { self.preview_pointer=before.clone(); }
		let report=match evaluated {
			Ok(metrics)=>json!({"calibration":calibration_metrics,"confirmation":metrics}),
			Err(error)=>json!({"calibration":calibration_metrics,"confirmation_error":error.to_string()}),
		};
		let report=json!({"scores":report,"confirmation_evaluated":true,"gradient_steps":0,"production_eligible":false,"live_pointer_modified":false,"independent_holdout_verified":false,"durable_ledger":false,"anti_reuse_scope":"exact input fingerprints and row IDs within this retained in-memory broker","meaning":"finite supplied-row software demonstration, no population-value claim"});
		let outcome=if accepted {"accepted_for_research_preview"} else {"rejected_preview_restored"};
		self.append(json!({"phase":outcome,"candidate":candidate.sha256(),"protocol":protocol.sha256(),"pointer_after":self.preview_pointer,"report":report}))?;
		Ok(PreviewResult {accepted,outcome:outcome.into(),pointer_before:before.clone(),pointer_after:self.preview_pointer.clone(),rollback_verified:!accepted && self.preview_pointer==before,report})
	}
}
#[cfg(test)]
#[path="confirmation_tests.rs"]
mod tests;
