// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! One fixed SmallHCSN pure-byte profile, shared by explicit-file examples and session owners.
//! This module grants no file, artifact, session or deployment authority. Its declarations
//! bind caller-provided bytes; upstream provenance and target truth remain separate claims.

use anyhow::{ensure, Result};
use serde_json::Value;

#[path = "weight_smallhcsn/bound_io.rs"]
mod bound_io;
#[path = "weight_smallhcsn/deadline.rs"]
mod deadline;
#[path = "weight_smallhcsn/matrix.rs"]
mod matrix;
#[path = "weight_smallhcsn/model.rs"]
mod model;
#[path = "weight_smallhcsn/physics.rs"]
mod physics;
#[path = "weight_smallhcsn/semantic.rs"]
mod semantic;

pub use bound_io::{BoundModel, Inputs};
pub use deadline::Deadline;
pub use model::Output;
pub use semantic::sender_semantic_map;

pub fn sha(bytes: &[u8]) -> String {
	bound_io::sha(bytes)
}

/// Actual source bytes of this fixed evaluator and its byte admission, not a provider qualification.
pub fn evaluator_identity() -> String {
	sha(&[
		include_bytes!("weight_smallhcsn.rs").as_slice(),
		include_bytes!("weight_smallhcsn/bound_io.rs").as_slice(),
		include_bytes!("weight_smallhcsn/deadline.rs").as_slice(),
		include_bytes!("weight_smallhcsn/model.rs").as_slice(),
		include_bytes!("weight_smallhcsn/physics.rs").as_slice(),
		include_bytes!("weight_smallhcsn/matrix.rs").as_slice(),
		include_bytes!("weight_smallhcsn/semantic.rs").as_slice(),
	]
	.concat())
}

/// The original single-readout binding used by the existing explicit-file example.
pub fn bind(manifest: &[u8], artifact: &[u8], input: &[u8]) -> Result<BoundModel> {
	bound_io::bind(manifest, artifact, input)
}

pub fn inputs(raw: &[u8]) -> Result<Inputs> {
	bound_io::inputs(raw)
}

pub fn evaluate(model: &BoundModel, inputs: &Inputs, deadline: &Deadline) -> Result<Output> {
	model::evaluate(model, inputs, deadline)
}

/// Rebuild every model tensor from the actual admitted candidate bytes. The existing
/// opaque hidden plan first proves all non-selected bytes equal the complete parent.
/// The selected sender scope keeps the readout, header, aliases and physical buffers fixed.
pub fn bind_hidden_candidate(
	manifest: &[u8],
	parent: &[u8],
	candidate: &[u8],
	input: &[u8],
	plan: &super::weight_hidden_scope::PreparedPlan,
) -> Result<(BoundModel, Value)> {
	let parent_sha256 = sha(parent);
	let parent_model = bound_io::bind(manifest, parent, input)?;
	ensure!(
		parent_model.canonical_sha256() == parent_sha256
			&& plan.evidence()["parent_sha256"] == parent_sha256,
		"hidden full-model profile differs from the exact canonical parent"
	);
	let admitted = plan.admit(candidate)?;
	let model = bound_io::bind_sender_candidate(manifest, candidate, input)?;
	ensure!(
		model.canonical_sha256() == parent_sha256,
		"hidden candidate profile changed its canonical parent declaration"
	);
	Ok((model, admitted.evidence))
}

#[cfg(test)]
#[path = "weight_smallhcsn/native_tests.rs"]
mod native_tests;

#[cfg(test)]
#[path = "weight_smallhcsn/semantic_tests.rs"]
pub(in crate::mcp) mod semantic_tests;
