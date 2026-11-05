// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! One-candidate native evaluation and exact recovery for isolated linear heads.
//! Labels are consumed only by the evaluator. This is a finite-data research gate,
//! not proof of independent holdout, causal value, global optimality or deployment.

use anyhow::{anyhow, bail, Context, Result};
use rmcp::schemars;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::weight_forward::{ForwardLinearParams, LinearSource};
use super::weight_tensor::PatchTensorParams;

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Objective {
	/// Score is negative mean squared error across all supplied rows and outputs.
	SquaredError { targets: Vec<Vec<f32>> },
	/// Argmax of the listed output columns selects a supplied realized action value.
	/// Ties select the first listed action. Values must already include task costs.
	ActionValue {
		action_columns: Vec<usize>,
		values: Vec<Vec<f32>>,
	},
}

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Constraint {
	Range {
		column: usize,
		lower: f64,
		upper: f64,
	},
	/// Two exhaustive, disjoint probabilities, checked per row. This is not
	/// monetary put-call parity or first-exit probabilities with surviving mass.
	Complement {
		call: usize,
		put: usize,
		tolerance: f64,
	},
	/// STOP=0, SUBMIT_1=2*belief-1, SUBMIT_0=1-2*belief; belief is in [0,1].
	TerminalQ {
		belief: usize,
		stop: usize,
		submit_zero: usize,
		submit_one: usize,
		tolerance: f64,
	},
	/// Preserve an output on these exact inputs, independently of the primary score.
	Preserve {
		column: usize,
		max_absolute_change: f64,
	},
}

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GuardedPatchParams {
	pub patch: PatchTensorParams,
	/// Fixed evaluation inputs only. No parameter fitting or candidate search occurs here.
	pub inputs: Vec<Vec<f32>>,
	pub bias: Option<Vec<f32>>,
	pub objective: Objective,
	/// Required strict improvement in negative MSE or mean realized action value.
	pub minimum_gain: f64,
	pub constraints: Vec<Constraint>,
	/// Optional exact L2 budget on this patch's authenticated F32 differences.
	/// Excludes supplied bias, environment changes and cumulative drift across patches.
	/// Signed zeros have zero numeric difference. An excess fails before publication.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub max_update_l2_norm: Option<f64>,
}

/// Bound the extra canonical-request copy before allocation grows beyond the cap.
/// Transport deserialization has already occurred; this does not claim a transport limit.
struct BoundedRequest(Vec<u8>);

impl Write for BoundedRequest {
	fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
		if bytes.len() > (1024 * 1024usize).saturating_sub(self.0.len()) {
			return Err(io::Error::other("guarded patch request exceeds 1 MiB"));
		}
		self.0.extend_from_slice(bytes);
		Ok(bytes.len())
	}
	fn flush(&mut self) -> io::Result<()> {
		Ok(())
	}
}

fn digest(bytes: &[u8]) -> String {
	Sha256::digest(bytes)
		.iter()
		.map(|byte| format!("{byte:02x}"))
		.collect()
}

fn predictions(report: &Value) -> Result<Vec<Vec<f64>>> {
	let rows: Vec<Vec<f64>> = serde_json::from_value(report["outputs"].clone())?;
	if rows.is_empty()
		|| rows[0].is_empty()
		|| rows
			.iter()
			.any(|row| row.len() != rows[0].len() || row.iter().any(|x| !x.is_finite()))
	{
		bail!("native evaluator received invalid predictions");
	}
	Ok(rows)
}

fn score(objective: &Objective, rows: &[Vec<f64>]) -> Result<f64> {
	let (labels, columns) = match objective {
		Objective::SquaredError { targets } => (targets, rows[0].len()),
		Objective::ActionValue {
			action_columns,
			values,
		} => {
			let mut sorted = action_columns.clone();
			sorted.sort_unstable();
			if sorted.is_empty()
				|| sorted.len() > 256
				|| sorted.windows(2).any(|p| p[0] == p[1])
				|| sorted.last().is_some_and(|i| *i >= rows[0].len())
			{
				bail!("action columns must be distinct valid output indices");
			}
			(values, action_columns.len())
		}
	};
	if labels.len() != rows.len()
		|| labels
			.iter()
			.any(|row| row.len() != columns || row.iter().any(|x| !x.is_finite()))
	{
		bail!("evaluation labels must be finite and exactly match rows and objective columns");
	}
	let total: f64 = rows
		.iter()
		.zip(labels)
		.map(|(row, labels)| match objective {
			Objective::SquaredError { .. } => {
				-row.iter()
					.zip(labels)
					.map(|(prediction, target)| (prediction - f64::from(*target)).powi(2))
					.sum::<f64>() / columns as f64
			}
			Objective::ActionValue { action_columns, .. } => {
				let mut selected = 0;
				for index in 1..action_columns.len() {
					if row[action_columns[index]] > row[action_columns[selected]] {
						selected = index;
					}
				}
				f64::from(labels[selected])
			}
		})
		.sum();
	let result = total / rows.len() as f64;
	if !result.is_finite() {
		bail!("evaluation score is not finite");
	}
	Ok(result)
}

fn check_constraints(
	constraints: &[Constraint],
	rows: &[Vec<f64>],
	parent: &[Vec<f64>],
) -> Result<Vec<usize>> {
	let width = rows[0].len();
	let mut failures = Vec::new();
	for (index, constraint) in constraints.iter().enumerate() {
		let (columns, valid) = match constraint {
			Constraint::Range {
				column,
				lower,
				upper,
			} => (
				vec![*column],
				lower.is_finite() && upper.is_finite() && lower <= upper,
			),
			Constraint::Complement {
				call,
				put,
				tolerance,
			} => (
				vec![*call, *put],
				call != put && tolerance.is_finite() && (0.0..=1.0).contains(tolerance),
			),
			Constraint::TerminalQ {
				belief,
				stop,
				submit_zero,
				submit_one,
				tolerance,
			} => {
				let mut columns = vec![*belief, *stop, *submit_zero, *submit_one];
				columns.sort_unstable();
				let distinct = columns.windows(2).all(|p| p[0] != p[1]);
				(
					columns,
					distinct && tolerance.is_finite() && (0.0..=1.0).contains(tolerance),
				)
			}
			Constraint::Preserve {
				column,
				max_absolute_change,
			} => (
				vec![*column],
				max_absolute_change.is_finite() && *max_absolute_change >= 0.0,
			),
		};
		if !valid || columns.iter().any(|column| *column >= width) {
			bail!("invalid constraint bounds or output indices at index {index}");
		}
		let passed = rows
			.iter()
			.zip(parent)
			.all(|(row, before)| match constraint {
				Constraint::Range {
					column,
					lower,
					upper,
				} => (*lower..=*upper).contains(&row[*column]),
				Constraint::Complement {
					call,
					put,
					tolerance,
				} => {
					(0.0..=1.0).contains(&row[*call])
						&& (0.0..=1.0).contains(&row[*put])
						&& (row[*call] + row[*put] - 1.0).abs() <= *tolerance
				}
				Constraint::TerminalQ {
					belief,
					stop,
					submit_zero,
					submit_one,
					tolerance,
				} => {
					(0.0..=1.0).contains(&row[*belief])
						&& row[*stop].abs() <= *tolerance
						&& (row[*submit_one] - (2.0 * row[*belief] - 1.0)).abs() <= *tolerance
						&& (row[*submit_zero] - (1.0 - 2.0 * row[*belief])).abs() <= *tolerance
				}
				Constraint::Preserve {
					column,
					max_absolute_change,
				} => (row[*column] - before[*column]).abs() <= *max_absolute_change,
			});
		if !passed {
			failures.push(index);
		}
	}
	Ok(failures)
}

async fn run_forward(
	params: &GuardedPatchParams,
	source: LinearSource,
	roots: &[PathBuf],
	state: &Path,
) -> Result<Value> {
	tokio::time::timeout(
		Duration::from_secs(60),
		super::weight_forward::forward_with_roots(
			ForwardLinearParams {
				source,
				inputs: params.inputs.clone(),
				bias: params.bias.clone(),
			},
			roots,
			state,
		),
	)
	.await
	.context("guarded forward deadline expired")?
}

pub(super) async fn evaluate_with_roots(
	params: GuardedPatchParams,
	roots: &[PathBuf],
	state: &Path,
) -> Result<Value> {
	let started = Instant::now();
	if !params.minimum_gain.is_finite()
		|| params.minimum_gain < 0.0
		|| params.constraints.len() > 32
	{
		bail!("minimum gain must be finite and nonnegative; at most 32 constraints");
	}
	let mut buffer = BoundedRequest(Vec::new());
	serde_json::to_writer(&mut buffer, &params)?;
	let encoded = buffer.0;
	let evaluation_id = format!("wg1_{}", digest(&encoded));
	let update_budget = params
		.max_update_l2_norm
		.map(|radius| super::weight_norm::check_edits(&params.patch.edits, radius))
		.transpose()?;
	if update_budget
		.as_ref()
		.is_some_and(|budget| !budget.within_budget)
	{
		bail!(
			"declared F32 patch exceeds its exact joint L2 update budget; no candidate published"
		);
	}
	let before = run_forward(
		&params,
		LinearSource::Path {
			path: params.patch.path.clone(),
			expected_sha256: params.patch.expected_sha256.clone(),
			tensor_name: params.patch.tensor_name.clone(),
		},
		roots,
		state,
	)
	.await?;
	let original = predictions(&before)?;
	let primary_before = score(&params.objective, &original)?;
	// Validate labels and every constraint before publishing any candidate.
	let original_violations = check_constraints(&params.constraints, &original, &original)?;
	let candidate = tokio::time::timeout(
		Duration::from_secs(300),
		super::weight_artifact::apply_with_roots(params.patch.clone(), roots, state, None, None),
	)
	.await
	.context("candidate publication uncertain; reconcile the identical exact patch")??;
	let candidate_id = candidate["artifact_id"]
		.as_str()
		.ok_or_else(|| anyhow!("candidate artifact identity missing"))?;
	let checked = async {
		let report = run_forward(
			&params,
			LinearSource::Artifact {
				artifact_id: candidate_id.into(),
				tensor_name: params.patch.tensor_name.clone(),
			},
			roots,
			state,
		)
		.await?;
		let rows = predictions(&report)?;
		let primary_after = score(&params.objective, &rows)?;
		let violations = check_constraints(&params.constraints, &rows, &original)?;
		Ok::<_, anyhow::Error>((primary_after, violations))
	}
	.await;
	let (primary_after, violations, error) = match checked {
		Ok((value, violations)) => (Some(value), violations, None),
		Err(error) => (
			None,
			Vec::new(),
			Some(error.to_string().chars().take(1024).collect::<String>()),
		),
	};
	let gain = primary_after.map(|value| value - primary_before);
	let accepted = error.is_none()
		&& violations.is_empty()
		&& gain.is_some_and(|gain| gain > params.minimum_gain);
	let mut restoration = Value::Null;
	let mut restoration_error = None;
	if !accepted {
		// A failed check always attempts exact reverse publication. No live pointer was changed.
		let recovered = tokio::time::timeout(Duration::from_secs(360), async {
			let receipt = super::weight_artifact::restore_with_state(candidate_id, state).await?;
			let restored_id = receipt["artifact_id"]
				.as_str()
				.ok_or_else(|| anyhow!("restore artifact identity missing"))?;
			let report = run_forward(
				&params,
				LinearSource::Artifact {
					artifact_id: restored_id.into(),
					tensor_name: params.patch.tensor_name.clone(),
				},
				roots,
				state,
			)
			.await?;
			if report["source_sha256"] != params.patch.expected_sha256
				|| predictions(&report)? != original
			{
				bail!("restored hash or predictions differ from the evaluated parent");
			}
			Ok::<_, anyhow::Error>(receipt)
		})
		.await;
		match recovered {
			Ok(Ok(receipt)) => restoration = receipt,
			Ok(Err(error)) => restoration_error = Some(error.to_string()),
			Err(_) => {
				restoration_error =
					Some("restoration deadline expired; recovery is unverified".into())
			}
		}
	}
	let outcome = if accepted {
		"accepted_on_supplied_rows"
	} else if restoration_error.is_none() {
		"rejected_and_restored"
	} else {
		"rejected_recovery_unverified"
	};
	Ok(json!({
		"schema":"hepta.weight.guarded-linear-patch.v1", "evaluation_id":evaluation_id,
		"outcome":outcome, "accepted":accepted, "candidate":candidate, "restoration":restoration,
		"primary_before":primary_before, "primary_after":primary_after, "gain":gain,
		"minimum_gain":params.minimum_gain, "score_direction":"higher_is_better",
		"f32_update_budget":update_budget,
		"f32_update_budget_source_bytes_authenticated":update_budget.is_some(),
		"f32_update_budget_scope":"numeric F32 differences in this patch only; excludes supplied bias, environment changes and cumulative drift across patches",
		"parent_constraint_violations":original_violations,"candidate_constraint_violations":violations,
		"evaluation_error":error,"restoration_error":restoration_error,
		"evaluation_examples":params.inputs.len(),"request_sha256":digest(&encoded),
		"native_operation_wall_seconds":started.elapsed().as_secs_f64(),"gradient_steps":0,
		"independent_holdout_verified":false,"end_to_end_cost_known":false,"production_eligible":false,
		"interruption_recovery_verified":false,"durable_evaluation_receipt":false,
		"source_modified":false,"scope":"one fixed F32 linear head and caller-supplied evaluation rows; no live activation"
	}))
}

pub async fn evaluate(params: GuardedPatchParams) -> Result<String> {
	let config = super::runtime::runtime_config()?;
	let result = evaluate_with_roots(
		params,
		&config.controller_workspace_roots,
		&config.state_dir,
	)
	.await?;
	Ok(serde_json::to_string(&result)?)
}

#[cfg(all(test, target_os = "linux"))]
#[path = "weight_guard_tests.rs"]
mod tests;
