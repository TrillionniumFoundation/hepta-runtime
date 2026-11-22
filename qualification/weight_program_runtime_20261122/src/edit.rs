// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Closed-form ridge correction of declared exposed-development readout equations.

use crate::snapshot::{hex, stable_l2, valid_digest, AuthenticatedSnapshot, PARAMS, ROWS, WIDTH};
use anyhow::{bail, Result};
use hepta_semantic_source_adapter_study::digest;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ReadoutEquation {
	ContinuationScore {
		row: usize,
		input: Vec<f64>,
		target: f64,
	},
	ContinuationGap {
		left: usize,
		right: usize,
		input: Vec<f64>,
		target: f64,
	},
	BeliefLogit {
		input: Vec<f64>,
		target: f64,
	},
}

impl ReadoutEquation {
	fn linear_row(&self, authenticated: &AuthenticatedSnapshot) -> Result<(Vec<f64>, f64)> {
		let (terms, input, target): (Vec<(usize, f64)>, &Vec<f64>, f64) = match self {
			Self::ContinuationScore { row, input, target } if *row < 3 => {
				(vec![(*row, 1.)], input, *target)
			}
			Self::ContinuationGap {
				left,
				right,
				input,
				target,
			} if *left < 3 && *right < 3 && left != right => {
				(vec![(*left, 1.), (*right, -1.)], input, *target)
			}
			Self::BeliefLogit { input, target } => (vec![(3, 1.)], input, *target),
			_ => bail!("continuation and belief channels must retain their declared meanings"),
		};
		if !target.is_finite() || target.abs() > 1e6 {
			bail!("bounded finite readout target required");
		}
		let hidden = authenticated.hidden(input)?;
		let mut row = vec![0.; PARAMS];
		for (output, sign) in terms {
			for (i, value) in hidden.iter().enumerate() {
				row[output * WIDTH + i] = sign * value;
			}
			row[ROWS * WIDTH + output] = sign;
		}
		Ok((row, target))
	}
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EditProgram {
	pub schema: String,
	pub role: String,
	pub snapshot_sha256: String,
	pub feature_evidence_sha256: String,
	pub teacher_evidence_sha256: String,
	pub ridge: f64,
	pub radius_l2: f64,
	pub max_equation_error: f64,
	pub equations: Vec<ReadoutEquation>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ElementEdit {
	pub index: usize,
	pub expected_hex: String,
	pub replacement_hex: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct CompiledEdit {
	pub(crate) schema: String,
	pub(crate) source_sha256: String,
	pub(crate) snapshot_sha256: String,
	pub(crate) program_sha256: String,
	pub(crate) evaluation_contract_sha256: String,
	pub(crate) tensor_name: String,
	pub(crate) edits: Vec<ElementEdit>,
	pub(crate) inverse_edits: Vec<ElementEdit>,
	pub(crate) delta_l2: f64,
	pub(crate) equation_errors: Vec<f64>,
	pub(crate) candidate_head_le_hex: Vec<String>,
	pub(crate) method: String,
	pub(crate) independent_evaluation_required: bool,
	pub(crate) feature_computation: String,
	pub(crate) evidence_scope: String,
}

fn dot(a: &[f64], b: &[f64]) -> f64 {
	a.iter().zip(b).map(|(a, b)| a * b).sum()
}

fn cholesky_solve(a: &[Vec<f64>], b: &[f64]) -> Result<Vec<f64>> {
	let n = b.len();
	let mut l = vec![vec![0.; n]; n];
	for i in 0..n {
		for j in 0..=i {
			let value = a[i][j] - (0..j).map(|k| l[i][k] * l[j][k]).sum::<f64>();
			if i == j {
				if !value.is_finite() || value <= 0. {
					bail!("non-positive numerical Cholesky pivot");
				}
				l[i][j] = value.sqrt();
			} else {
				l[i][j] = value / l[j][j];
			}
		}
	}
	let mut y = vec![0.; n];
	for i in 0..n {
		y[i] = (b[i] - dot(&l[i][..i], &y[..i])) / l[i][i];
	}
	let mut x = vec![0.; n];
	for i in (0..n).rev() {
		x[i] = (y[i] - (i + 1..n).map(|j| l[j][i] * x[j]).sum::<f64>()) / l[i][i];
	}
	if x.iter().any(|v| !v.is_finite()) {
		bail!("nonfinite direct solve");
	}
	Ok(x)
}

pub fn compile(
	authenticated: &AuthenticatedSnapshot,
	program: &EditProgram,
) -> Result<CompiledEdit> {
	let snapshot = authenticated.snapshot();
	let original = snapshot.validate()?;
	let snapshot_id = snapshot.identity()?;
	if program.schema != "hepta.readout-edit-program.v1"
		|| program.role != "exposed_development"
		|| program.snapshot_sha256 != snapshot_id
		|| !valid_digest(&program.feature_evidence_sha256)
		|| !valid_digest(&program.teacher_evidence_sha256)
	{
		bail!("program provenance or source binding mismatch");
	}
	if program.equations.is_empty()
		|| program.equations.len() > 128
		|| !program.ridge.is_finite()
		|| program.ridge <= 0.
		|| program.ridge > 1e6
		|| !program.radius_l2.is_finite()
		|| program.radius_l2 <= 0.
		|| program.radius_l2 > 1e6
		|| !program.max_equation_error.is_finite()
		|| program.max_equation_error < 0.
	{
		bail!("bounded equations, positive ridge and edit radius required");
	}
	let mut rows = Vec::new();
	let mut residuals = Vec::new();
	for equation in &program.equations {
		let (mut row, target) = equation.linear_row(authenticated)?;
		let residual = target - dot(&row, &original);
		for (i, value) in row.iter_mut().enumerate() {
			if !snapshot.domain.permits(i) {
				*value = 0.;
			}
		}
		if dot(&row, &row) == 0. {
			bail!("equation has no coordinates in declared edit domain");
		}
		rows.push(row);
		residuals.push(residual);
	}
	let n = rows.len();
	let mut gram = vec![vec![0.; n]; n];
	for i in 0..n {
		for j in 0..n {
			gram[i][j] = dot(&rows[i], &rows[j]);
		}
		gram[i][i] += program.ridge;
	}
	let multipliers = cholesky_solve(&gram, &residuals)?;
	let mut candidate = original.clone();
	for i in 0..PARAMS {
		if snapshot.domain.permits(i) {
			let delta: f64 = rows
				.iter()
				.zip(&multipliers)
				.map(|(row, m)| row[i] * m)
				.sum();
			if delta != 0. {
				candidate[i] += delta;
			}
		}
	}
	let delta_l2 = stable_l2(candidate.iter().zip(&original).map(|(a, b)| a - b));
	if candidate.iter().any(|v| !v.is_finite())
		|| !delta_l2.is_finite()
		|| delta_l2 > program.radius_l2
	{
		bail!("compiled edit exceeds declared radius or finite arithmetic");
	}
	let mut errors = Vec::new();
	for equation in &program.equations {
		let (row, target) = equation.linear_row(authenticated)?;
		let error = (dot(&row, &candidate) - target).abs();
		if !error.is_finite() || error > program.max_equation_error {
			bail!("compiled edit misses declared equation tolerance");
		}
		errors.push(error);
	}
	let mut edits = Vec::new();
	for (i, (old, new)) in original.iter().zip(&candidate).enumerate() {
		if old.to_bits() != new.to_bits() {
			if !snapshot.domain.permits(i) {
				bail!("protected coordinate changed");
			}
			edits.push(ElementEdit {
				index: i,
				expected_hex: hex(&old.to_le_bytes()),
				replacement_hex: hex(&new.to_le_bytes()),
			});
		}
	}
	let inverse_edits = edits
		.iter()
		.map(|e| ElementEdit {
			index: e.index,
			expected_hex: e.replacement_hex.clone(),
			replacement_hex: e.expected_hex.clone(),
		})
		.collect();
	Ok(CompiledEdit {
		schema: "hepta.compiled-readout-edit.v1".into(),
		source_sha256: snapshot.source_sha256.clone(),
		snapshot_sha256: snapshot_id,
		program_sha256: digest(&serde_json::to_vec(program)?),
		evaluation_contract_sha256: snapshot.evaluation_contract_sha256.clone(),
		tensor_name: snapshot.tensor_name.clone(),
		edits,
		inverse_edits,
		delta_l2,
		equation_errors: errors,
		candidate_head_le_hex: candidate.iter().map(|v| hex(&v.to_le_bytes())).collect(),
		method: "direct_cholesky_ridge_equations_no_gradient_updates".into(),
		independent_evaluation_required: true,
		feature_computation: "recomputed_from_authenticated_protected_85_to_48_tanh_frontend".into(),
		evidence_scope: "feature_and_teacher_digests_are_declared_references; teacher_truth_and_input_origin_require_independent_review".into(),
	})
}

impl CompiledEdit {
	pub fn edits(&self) -> &[ElementEdit] {
		&self.edits
	}
	pub fn inverse_edits(&self) -> &[ElementEdit] {
		&self.inverse_edits
	}
	pub fn candidate_head_hex(&self) -> &[String] {
		&self.candidate_head_le_hex
	}
	pub fn delta_l2(&self) -> f64 {
		self.delta_l2
	}
	pub fn program_sha256(&self) -> &str {
		&self.program_sha256
	}
}
