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

//! Read-only F16 byte proposals from an already-admitted descriptor.
//! No replacement encoding, model execution, owner call or activation occurs.

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::{Component, Path};

use super::weight_artifact::cohort;
use super::weight_norm::{self, F32UpdateBudget};
use super::weight_tensor::{self, ExactElementEdit};

#[path = "weight_f16_source.rs"]
mod source;

const MAX_MEMBERS: usize = 32;
const MAX_EDITS: usize = 1024;
const MAX_REQUEST_BYTES: usize = 256 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TensorBinding {
	pub name: String,
	pub dtype: String,
	pub shape: Vec<u64>,
	/// Complete exact tensor payload, not a header or a selected-element hash.
	pub payload_sha256: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReadSetRole {
	EditTarget,
	/// Observed in full during the same stream, even though no edit is requested.
	Dependency,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Member {
	pub binding: TensorBinding,
	pub role: ReadSetRole,
	/// Exact little-endian F16 bytes; identity edits still count toward admission.
	pub edits: Vec<ExactElementEdit>,
	pub maximum_update_l2_norm: f64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct F16ProposalParams {
	pub request_id: String,
	/// Future owner label, not path admission. This function never opens it.
	pub path: String,
	pub source_sha256: String,
	pub members: Vec<Member>,
	pub maximum_update_l2_norm: f64,
	/// Commitments bind caller claims; they do not establish their semantic truth.
	pub data_manifest_sha256: String,
	pub objective_sha256: String,
	pub dependency_manifest_sha256: String,
}

#[derive(Serialize)]
struct ReadSetIdentity {
	binding: TensorBinding,
	role: ReadSetRole,
	file_offset: u64,
	byte_length: u64,
	checked_elements: usize,
}

/// Serialize-only evidence and an optional request for the unchanged cohort owner.
/// Possessing this value does not authorize invoking that owner or final use.
#[derive(Serialize)]
pub struct F16Proposal {
	schema: &'static str,
	source_sha256: String,
	candidate_sha256: String,
	source_size_bytes: u64,
	observed_version: String,
	raw_prefix_sha256: String,
	json_header_sha256: String,
	request_sha256: String,
	compiler_selected_source_sha256: String,
	read_set_sha256: String,
	read_set: Vec<ReadSetIdentity>,
	requested_elements: usize,
	changed_elements: usize,
	member_budgets: Vec<F32UpdateBudget>,
	global_budget: F32UpdateBudget,
	cohort: Option<cohort::PatchParams>,
	replacement_encoding_performed: bool,
	all_checkpoint_values_verified_finite: bool,
	behavior_evaluated: bool,
	production_eligible: bool,
}

impl F16Proposal {
	/// Complete candidate commitment computed from the authenticated byte stream.
	pub(crate) fn candidate_sha256(&self) -> &str {
		&self.candidate_sha256
	}

	pub fn is_keep(&self) -> bool {
		self.cohort.is_none()
	}

	/// A separate owner call must still validate roots, bytes, budgets and effects.
	pub fn cohort_proposal(&self) -> Option<&cohort::PatchParams> {
		self.cohort.as_ref()
	}
}

fn hex(bytes: &[u8]) -> String {
	super::rea_model::digest_hex(bytes)
}

fn sha(bytes: &[u8]) -> String {
	hex(&Sha256::digest(bytes))
}

// Decoding all finite binary16 values into binary32 is exact. No encoder exists
// here: replacements are the caller's original two bytes, never these F32 bits.
fn represented_value(text: &str) -> Result<f32> {
	let bytes = weight_tensor::unhex(text)?;
	let bits = u16::from_le_bytes(bytes.as_slice().try_into()?);
	let sign = u32::from(bits & 0x8000) << 16;
	let exponent = u32::from((bits >> 10) & 31);
	let mantissa = u32::from(bits & 1023);
	let magnitude = match exponent {
		31 => bail!("F16 proposal requires finite expected and replacement values"),
		0 if mantissa == 0 => 0,
		0 => {
			let leading = 31 - mantissa.leading_zeros();
			((leading + 103) << 23) | ((mantissa ^ (1 << leading)) << (23 - leading))
		}
		_ => ((exponent + 112) << 23) | (mantissa << 13),
	};
	Ok(f32::from_bits(sign | magnitude))
}

fn validate(params: &F16ProposalParams) -> Result<()> {
	let valid = super::weight_config::valid_sha256;
	if [
		&params.request_id,
		&params.source_sha256,
		&params.data_manifest_sha256,
		&params.objective_sha256,
		&params.dependency_manifest_sha256,
	]
	.into_iter()
	.any(|value| !valid(value))
		|| params.path.len() > 4096
		|| params.path.as_bytes().contains(&0)
		|| !Path::new(&params.path).is_absolute()
		|| Path::new(&params.path)
			.components()
			.any(|part| matches!(part, Component::ParentDir | Component::CurDir))
		|| !(1..=MAX_MEMBERS).contains(&params.members.len())
	{
		bail!("F16 proposal requires explicit digests, an owner path and 1..32 read-set members");
	}
	weight_norm::validate_radius(params.maximum_update_l2_norm)?;
	let mut names = BTreeSet::new();
	let mut count = 0usize;
	for member in &params.members {
		let binding = &member.binding;
		if binding.name.is_empty()
			|| binding.name.len() > 1024
			|| binding.name == "__metadata__"
			|| !names.insert(binding.name.as_str())
			|| binding.dtype != "F16"
			|| binding.shape.len() > 32
			|| !valid(&binding.payload_sha256)
			|| member.edits.len() > MAX_EDITS
			|| (member.role == ReadSetRole::Dependency) != member.edits.is_empty()
		{
			bail!("F16 proposal has an invalid or repeated tensor/read-set role");
		}
		weight_norm::validate_radius(member.maximum_update_l2_norm)?;
		count += member.edits.len();
		if count > MAX_EDITS {
			bail!("F16 proposal exceeds the existing 1024-element total cap");
		}
		for edit in &member.edits {
			if edit.expected_hex.len() != 4 || edit.replacement_hex.len() != 4 {
				bail!("F16 exact edits require two complete little-endian bytes");
			}
			represented_value(&edit.expected_hex)?;
			represented_value(&edit.replacement_hex)?;
		}
	}
	if count == 0 || serde_json::to_vec(params)?.len() > MAX_REQUEST_BYTES {
		bail!("F16 proposal requires a nonempty bounded exact-byte request");
	}
	Ok(())
}

fn implementation_sha256() -> String {
	let mut hash = Sha256::new();
	hash.update(b"hepta.weight.f16-exact-selected-source.v1\0");
	for (name, bytes) in [
		(
			"compiler",
			include_bytes!("weight_f16_proposal.rs").as_slice(),
		),
		("capture", include_bytes!("weight_f16_source.rs").as_slice()),
		("model", include_bytes!("rea_model.rs").as_slice()),
		("parser", include_bytes!("rea_model_parser.rs").as_slice()),
		("tensor", include_bytes!("weight_tensor.rs").as_slice()),
		("norm", include_bytes!("weight_norm.rs").as_slice()),
		(
			"cohort",
			include_bytes!("weight_artifact_cohort.rs").as_slice(),
		),
		("config", include_bytes!("weight_config.rs").as_slice()),
		("manifest", include_bytes!("../../Cargo.toml").as_slice()),
	] {
		hash.update((name.len() as u64).to_le_bytes());
		hash.update(name.as_bytes());
		hash.update((bytes.len() as u64).to_le_bytes());
		hash.update(bytes);
	}
	hex(&hash.finalize())
}

/// Borrow one already-admitted regular-file descriptor; never open `params.path`.
/// Directory inspection uses the existing inherited-fd worker outside tests.
/// Reads/seek are sequential; descriptor observation is not a hostile-writer lease.
/// Bounds apply to this typed request, not an unprovided wire decoder or scheduler.
pub async fn compile_from_admitted(
	params: &F16ProposalParams,
	file: &mut tokio::fs::File,
) -> Result<F16Proposal> {
	validate(params)?;
	let mut member_budgets = Vec::with_capacity(params.members.len());
	let mut all_pairs = Vec::new();
	for member in &params.members {
		let pairs = member
			.edits
			.iter()
			.map(|edit| {
				Ok((
					represented_value(&edit.expected_hex)?,
					represented_value(&edit.replacement_hex)?,
				))
			})
			.collect::<Result<Vec<_>>>()?;
		member_budgets.push(weight_norm::check_pairs(
			pairs.iter().copied(),
			member.maximum_update_l2_norm,
		)?);
		all_pairs.extend(pairs);
	}
	let global_budget =
		weight_norm::check_pairs(all_pairs.iter().copied(), params.maximum_update_l2_norm)?;
	if member_budgets.iter().any(|budget| !budget.within_budget) || !global_budget.within_budget {
		bail!("F16 exact-byte update exceeds a declared member or global norm budget");
	}
	let captured = source::capture(params, file).await?;
	let mut members = Vec::new();
	for member in &params.members {
		let edits: Vec<_> = member
			.edits
			.iter()
			.filter(|edit| edit.expected_hex != edit.replacement_hex)
			.cloned()
			.collect();
		if !edits.is_empty() {
			members.push(cohort::Member {
				tensor_name: member.binding.name.clone(),
				edits,
				maximum_update_l2_norm: member.maximum_update_l2_norm,
			});
		}
	}
	let changed_elements = members.iter().map(|member| member.edits.len()).sum();
	let request_sha256 = sha(&serde_json::to_vec(params)?);
	let compiler_selected_source_sha256 = implementation_sha256();
	let read_set_sha256 = sha(&serde_json::to_vec(&serde_json::json!({
		"schema": "hepta.weight.f16-read-set.v1",
		"source_sha256": params.source_sha256,
		"raw_prefix_sha256": captured.raw_prefix_sha256,
		"json_header_sha256": captured.json_header_sha256,
		"read_set": captured.read_set
	}))?);
	let dependency = sha(&serde_json::to_vec(&serde_json::json!({
		"caller_dependency_manifest_sha256": params.dependency_manifest_sha256,
		"request_sha256": request_sha256,
		"read_set_sha256": read_set_sha256,
		"compiler_selected_source_sha256": compiler_selected_source_sha256
	}))?);
	let cohort = (!members.is_empty()).then(|| cohort::PatchParams {
		request_id: params.request_id.clone(),
		path: params.path.clone(),
		expected_sha256: params.source_sha256.clone(),
		identity: cohort::Identity {
			code_sha256: compiler_selected_source_sha256.clone(),
			tensor_map_sha256: read_set_sha256.clone(),
			data_manifest_sha256: params.data_manifest_sha256.clone(),
			objective_sha256: params.objective_sha256.clone(),
			dependency_manifest_sha256: dependency,
		},
		members,
		maximum_update_l2_norm: params.maximum_update_l2_norm,
		training: cohort::TrainingContract::InferenceOnly,
	});
	if let Some(request) = &cohort {
		if serde_json::to_vec(request)?.len() > MAX_REQUEST_BYTES {
			bail!("F16 cohort handoff exceeds the existing serialized request budget");
		}
	}
	Ok(F16Proposal {
		schema: "hepta.weight.f16-exact-proposal.v1",
		source_sha256: params.source_sha256.clone(),
		candidate_sha256: captured.candidate_sha256,
		source_size_bytes: captured.source_size_bytes,
		observed_version: captured.observed_version,
		raw_prefix_sha256: captured.raw_prefix_sha256,
		json_header_sha256: captured.json_header_sha256,
		request_sha256,
		compiler_selected_source_sha256,
		read_set_sha256,
		read_set: captured.read_set,
		requested_elements: all_pairs.len(),
		changed_elements,
		member_budgets,
		global_budget,
		cohort,
		replacement_encoding_performed: false,
		all_checkpoint_values_verified_finite: false,
		behavior_evaluated: false,
		production_eligible: false,
	})
}

#[cfg(all(test, unix))]
#[path = "weight_f16_proposal_tests.rs"]
mod tests;
