// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Predeclared direction, dose and norm controls; no automatic causal claim or adoption.

use crate::{
	edit::{self, EditProgram, ElementEdit},
	snapshot::{
		decode_f64, hex, stable_l2, AuthenticatedSnapshot, SemanticSnapshot, PARAMS, ROWS, WIDTH,
	},
};
use anyhow::{bail, Result};
use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
pub struct Intervention {
	pub id: String,
	pub edits: Vec<ElementEdit>,
	pub delta_l2: f64,
	pub candidate_head_le_hex: Vec<String>,
}
#[derive(Clone, Debug, Serialize)]
pub struct InterventionSet {
	pub schema: String,
	pub source_sha256: String,
	pub snapshot_sha256: String,
	pub program_sha256: String,
	pub evaluation_contract_sha256: String,
	pub random_seeds: Vec<u64>,
	pub arms: Vec<Intervention>,
	pub interpretation: String,
}
fn arm(snapshot: &SemanticSnapshot, id: &str, delta: &[f64]) -> Result<Intervention> {
	let old = snapshot.validate()?;
	if delta.len() != PARAMS {
		bail!("control dimension mismatch");
	}
	let mut new = old.clone();
	for (i, d) in delta.iter().enumerate() {
		if !d.is_finite() || (!snapshot.domain.permits(i) && *d != 0.) {
			bail!("control exceeds edit domain");
		}
		if *d != 0. {
			new[i] += d;
		}
		if !new[i].is_finite() {
			bail!("nonfinite control");
		}
	}
	let norm = stable_l2(new.iter().zip(&old).map(|(a, b)| a - b));
	let edits = old
		.iter()
		.zip(&new)
		.enumerate()
		.filter(|(_, (a, b))| a.to_bits() != b.to_bits())
		.map(|(i, (a, b))| ElementEdit {
			index: i,
			expected_hex: hex(&a.to_le_bytes()),
			replacement_hex: hex(&b.to_le_bytes()),
		})
		.collect();
	Ok(Intervention {
		id: id.into(),
		edits,
		delta_l2: norm,
		candidate_head_le_hex: new.iter().map(|v| hex(&v.to_le_bytes())).collect(),
	})
}
fn require_norm(actual: f64, expected: f64) -> Result<()> {
	if !actual.is_finite()
		|| !expected.is_finite()
		|| expected <= 0.
		|| (actual / expected - 1.).abs() > 1e-10
	{
		bail!("encoded control cannot preserve its declared dose or matched norm");
	}
	Ok(())
}
/// Compile from authenticated source again. Serialized caller-provided patches
/// never establish the legality or identity of the primary intervention.
pub fn controls(
	authenticated: &AuthenticatedSnapshot,
	program: &EditProgram,
	seeds: &[u64],
) -> Result<InterventionSet> {
	let snapshot = authenticated.snapshot();
	let old = snapshot.validate()?;
	let compiled = edit::compile(authenticated, program)?;
	if seeds.len() != 4
		|| seeds.contains(&0)
		|| seeds
			.iter()
			.collect::<std::collections::BTreeSet<_>>()
			.len() != 4
	{
		bail!("four distinct nonzero predeclared seeds required");
	}
	let new = compiled
		.candidate_head_le_hex
		.iter()
		.map(|s| decode_f64(s))
		.collect::<Result<Vec<_>>>()?;
	let delta: Vec<_> = new.iter().zip(&old).map(|(a, b)| a - b).collect();
	let norm = stable_l2(delta.iter().copied());
	if !norm.is_finite() || norm == 0. {
		bail!("nonzero finite intervention required");
	}
	let mut arms = vec![
		arm(snapshot, "keep", &vec![0.; PARAMS])?,
		arm(snapshot, "primary", &delta)?,
		arm(
			snapshot,
			"half_dose",
			&delta.iter().map(|d| d * 0.5).collect::<Vec<_>>(),
		)?,
		arm(
			snapshot,
			"opposite",
			&delta.iter().map(|d| -d).collect::<Vec<_>>(),
		)?,
	];
	if arms[1].candidate_head_le_hex != compiled.candidate_head_le_hex {
		bail!("primary control does not reproduce exact compiled bytes");
	}
	require_norm(arms[1].delta_l2, norm)?;
	require_norm(arms[2].delta_l2, 0.5 * norm)?;
	require_norm(arms[3].delta_l2, norm)?;
	for (n, seed) in seeds.iter().enumerate() {
		let mut state = *seed;
		let mut random = vec![0.; PARAMS];
		for (i, value) in random.iter_mut().enumerate() {
			if snapshot.domain.permits(i) {
				state ^= state << 13;
				state ^= state >> 7;
				state ^= state << 17;
				*value = ((state >> 11) as f64) * (1.0 / 9_007_199_254_740_992.0) * 2. - 1.;
			}
		}
		let scale = norm / stable_l2(random.iter().copied());
		if !scale.is_finite() || scale == 0. {
			bail!("random direction degenerate");
		}
		for value in &mut random {
			*value *= scale;
		}
		let random_arm = arm(snapshot, &format!("matched_norm_random_{n}"), &random)?;
		require_norm(random_arm.delta_l2, norm)?;
		arms.push(random_arm);
	}
	if arms.iter().any(|a| a.delta_l2 > program.radius_l2) {
		bail!("encoded control exceeds the hard edit radius; norm-matching tolerance cannot relax the domain");
	}
	Ok(InterventionSet { schema:"hepta.predeclared-weight-interventions.v1".into(),
		source_sha256:compiled.source_sha256, snapshot_sha256:compiled.snapshot_sha256,
		program_sha256:compiled.program_sha256, evaluation_contract_sha256:compiled.evaluation_contract_sha256,
		random_seeds:seeds.to_vec(), arms,
		interpretation:"fixed causal controls require independent full-task evaluation; equation fitting alone does not establish a causal model-quality repair".into() })
}
#[derive(Clone, Debug, Serialize)]
pub struct EquivalenceProbe {
	pub max_logit_error: f64,
	pub max_hidden_error: f64,
	pub broken_wiring_logit_difference: f64,
	pub scope: String,
}
/// Recompute the full 85 -> 48 -> 4 network after simultaneously permuting
/// frontend rows, biases and readout columns. Source bytes remain unchanged.
pub fn equivalent_coordinate_probe(
	authenticated: &AuthenticatedSnapshot,
	input: &[f64],
	permutation: &[usize],
) -> Result<EquivalenceProbe> {
	let weights = authenticated.snapshot().validate()?;
	let hidden = authenticated.hidden(input)?;
	if permutation.len() != WIDTH
		|| permutation
			.iter()
			.copied()
			.collect::<std::collections::BTreeSet<_>>()
			!= (0..WIDTH).collect()
	{
		bail!("complete hidden permutation required");
	}
	let frontend: Vec<_> = permutation
		.iter()
		.map(|i| authenticated.frontend[*i].clone())
		.collect();
	let bias: Vec<_> = permutation
		.iter()
		.map(|i| authenticated.frontend_bias[*i])
		.collect();
	let permuted_hidden: Vec<_> = frontend
		.iter()
		.zip(&bias)
		.map(|(row, b)| (row.iter().zip(input).map(|(w, x)| w * x).sum::<f64>() + b).tanh())
		.collect();
	let mut hidden_error = 0_f64;
	for (i, j) in permutation.iter().enumerate() {
		hidden_error = hidden_error.max((permuted_hidden[i] - hidden[*j]).abs());
	}
	let mut maximum = 0_f64;
	let mut broken = 0_f64;
	for row in 0..ROWS {
		let original = weights[row * WIDTH..(row + 1) * WIDTH]
			.iter()
			.zip(&hidden)
			.map(|(w, h)| w * h)
			.sum::<f64>()
			+ weights[ROWS * WIDTH + row];
		let permuted = permutation
			.iter()
			.zip(&permuted_hidden)
			.map(|(j, h)| weights[row * WIDTH + j] * h)
			.sum::<f64>()
			+ weights[ROWS * WIDTH + row];
		let incorrect = weights[row * WIDTH..(row + 1) * WIDTH]
			.iter()
			.zip(&permuted_hidden)
			.map(|(w, h)| w * h)
			.sum::<f64>()
			+ weights[ROWS * WIDTH + row];
		if !original.is_finite() || !permuted.is_finite() || !incorrect.is_finite() {
			bail!("coordinate probe overflow");
		}
		maximum = maximum.max((original - permuted).abs());
		broken = broken.max((original - incorrect).abs());
	}
	Ok(EquivalenceProbe { max_logit_error:maximum, max_hidden_error:hidden_error, broken_wiring_logit_difference:broken,
		scope:"full-network simultaneous neuron permutation; algebraic consistency, not a causal task-value claim".into() })
}
