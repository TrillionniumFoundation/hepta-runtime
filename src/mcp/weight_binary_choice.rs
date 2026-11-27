// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Source-bound binary-choice readout evaluation over frozen F32 features.
//! Shares the existing linear kernel and its total budgets; never publishes a weight artifact.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::{rea_files, rea_model, runtime, weight_artifact, weight_config, weight_forward};

#[path = "weight_binary_choice_source.rs"]
mod source;

const MAX_REQUEST_BYTES: usize = 1024 * 1024;
const MAX_ROWS: usize = 4096;
const BATCH_ROWS: usize = 64;
const SECONDS: u64 = 60;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CheckpointInput {
	Path { path: String },
	Artifact { artifact_id: String },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointBinding {
	pub input: CheckpointInput,
	pub complete_sha256: String,
	pub weight_payload_sha256: String,
	pub bias_payload_sha256: String,
}

/// These producer identities are committed declarations, not proof that features were recomputed.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProducerBinding {
	pub parent_checkpoint_sha256: String,
	pub producer_code_sha256: String,
	pub producer_cache_sha256: String,
	pub physical_source_sha256: String,
	pub evaluation_protocol_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QueryPair {
	pub query_id: String,
	pub choice0_row: usize,
	pub choice1_row: usize,
	pub margin_target: i8,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ChoiceData {
	pub producer: ProducerBinding,
	/// Query-major order: choice 0, choice 1, then the next query.
	pub rows: Vec<Vec<f32>>,
	pub row_ids: Vec<String>,
	/// One physical baseline per row, in exactly the same order as the feature rows.
	pub baseline: Vec<f32>,
	pub pairs: Vec<QueryPair>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BinaryChoiceParams {
	pub parent: CheckpointBinding,
	pub candidate: CheckpointBinding,
	pub weight_tensor: String,
	pub bias_tensor: String,
	pub data: ChoiceData,
	pub expected_data_sha256: String,
}

#[derive(Debug, Serialize)]
pub struct SourceEvidence {
	complete_sha256: String,
	source_size_bytes: u64,
	observed_version: String,
	header_sha256: String,
	protected_bytes_sha256: String,
	weight_payload_sha256: String,
	bias_payload_sha256: String,
	weight_offset: u64,
	weight_length: usize,
	bias_offset: u64,
	complete_source_hash_passes: u8,
}

#[derive(Debug, Serialize)]
struct BatchEvidence {
	start_row: usize,
	row_count: usize,
	source_sha256: String,
	captured_weight_payload_sha256: String,
	macs: u64,
	output_values: u64,
	raw_output_bits_sha256: String,
}

#[derive(Debug, Serialize)]
struct Evaluation {
	source: SourceEvidence,
	batches: Vec<BatchEvidence>,
	/// These are the actual existing-kernel output bits, before task aggregation.
	raw_head_bits: Vec<[u32; 2]>,
	query_margin_bits: Vec<u32>,
	mean_squared_margin_error: f64,
	accuracy: f64,
	correct_queries: usize,
}

#[derive(Clone, Copy, Debug, Serialize)]
struct Work {
	rows: usize,
	queries: usize,
	columns: usize,
	combined_linear_macs: u64,
	combined_linear_output_values: u64,
	combined_aggregate_values: u64,
	combined_output_and_aggregate_values: u64,
}

/// Serialize-only diagnostic evidence. It does not grant adoption or owner permission.
#[derive(Debug, Serialize)]
pub struct BinaryChoiceReport {
	schema: &'static str,
	request_sha256: String,
	data_sha256: String,
	producer: ProducerBinding,
	work: Work,
	parent: Evaluation,
	candidate: Evaluation,
	mean_squared_error_reduction: f64,
	accuracy_change: f64,
	seconds_elapsed: f64,
	operation_deadline_seconds: u64,
	batch_row_limit: usize,
	physical_and_bias_bytes_unchanged: bool,
	complete_sources_authenticated: bool,
	feature_provenance_verified: bool,
	full_model_executed: bool,
	production_eligible: bool,
	metric: &'static str,
	operation_order: &'static str,
}

fn sha(bytes: &[u8]) -> String {
	rea_model::digest_hex(&Sha256::digest(bytes))
}

fn check_deadline(deadline: Instant) -> Result<()> {
	if Instant::now() >= deadline {
		bail!("binary-choice evaluation exceeded its shared 60 second deadline");
	}
	Ok(())
}

fn work(rows: usize, columns: usize) -> Result<Work> {
	if !(2..=MAX_ROWS).contains(&rows) || !rows.is_multiple_of(2) || !(1..=4096).contains(&columns)
	{
		bail!("binary-choice evaluation requires complete pairs and 1..=4096 columns");
	}
	// Both models count against one original operator budget. The additional scores and
	// margins also count against that same output-value ceiling, never a fresh batch budget.
	let macs = (rows as u64) * (columns as u64) * 2 * 2;
	let outputs = (rows as u64) * 2 * 2;
	let aggregates = (rows as u64) * 3;
	if macs > weight_forward::MAX_MACS || outputs + aggregates > weight_forward::MAX_OUTPUT_VALUES {
		bail!("binary-choice combined models exceed the original MAC or output-value budget");
	}
	Ok(Work {
		rows,
		queries: rows / 2,
		columns,
		combined_linear_macs: macs,
		combined_linear_output_values: outputs,
		combined_aggregate_values: aggregates,
		combined_output_and_aggregate_values: outputs + aggregates,
	})
}

fn validate_data(data: &ChoiceData) -> Result<Work> {
	let columns = data.rows.first().map_or(0, Vec::len);
	let work = work(data.rows.len(), columns)?;
	let producer = &data.producer;
	if [
		&producer.parent_checkpoint_sha256,
		&producer.producer_code_sha256,
		&producer.producer_cache_sha256,
		&producer.physical_source_sha256,
		&producer.evaluation_protocol_sha256,
	]
	.iter()
	.any(|value| !weight_config::valid_sha256(value))
		|| data
			.rows
			.iter()
			.any(|row| row.len() != columns || row.iter().any(|value| !value.is_finite()))
		|| data.baseline.len() != work.rows
		|| data.baseline.iter().any(|value| !value.is_finite())
		|| data.row_ids.len() != work.rows
		|| data.pairs.len() != work.queries
	{
		bail!("binary-choice data requires finite, complete and hash-bound rows and baselines");
	}
	let mut row_ids = HashSet::new();
	if data
		.row_ids
		.iter()
		.any(|id| !weight_config::valid_sha256(id) || !row_ids.insert(id.as_str()))
	{
		bail!("binary-choice row identities must be unique SHA-256 values");
	}
	let mut query_ids = HashSet::new();
	for (index, pair) in data.pairs.iter().enumerate() {
		if !weight_config::valid_sha256(&pair.query_id)
			|| !query_ids.insert(pair.query_id.as_str())
			|| pair.choice0_row != 2 * index
			|| pair.choice1_row != 2 * index + 1
			|| !matches!(pair.margin_target, -1 | 1)
		{
			bail!(
				"binary-choice pairing must cover query-major rows exactly once with +/-1 targets"
			);
		}
	}
	Ok(work)
}

/// Canonical data commitment covers actual F32 bits, all source declarations, row identities,
/// ordered pairing and targets. JSON float spelling cannot change the underlying commitment.
pub fn data_sha256(data: &ChoiceData) -> Result<String> {
	let work = validate_data(data)?;
	let mut hash = Sha256::new();
	hash.update(b"hepta.weight.binary-choice-data.v1\0");
	for value in [
		&data.producer.parent_checkpoint_sha256,
		&data.producer.producer_code_sha256,
		&data.producer.producer_cache_sha256,
		&data.producer.physical_source_sha256,
		&data.producer.evaluation_protocol_sha256,
	] {
		hash.update(value.as_bytes());
	}
	hash.update((work.rows as u64).to_le_bytes());
	hash.update((work.columns as u64).to_le_bytes());
	for ((row, id), baseline) in data.rows.iter().zip(&data.row_ids).zip(&data.baseline) {
		hash.update(id.as_bytes());
		for value in row {
			hash.update(value.to_le_bytes());
		}
		hash.update(baseline.to_le_bytes());
	}
	hash.update((work.queries as u64).to_le_bytes());
	for pair in &data.pairs {
		hash.update(pair.query_id.as_bytes());
		hash.update((pair.choice0_row as u64).to_le_bytes());
		hash.update((pair.choice1_row as u64).to_le_bytes());
		hash.update(pair.margin_target.to_le_bytes());
	}
	Ok(rea_model::digest_hex(&hash.finalize()))
}

struct BoundedHash {
	count: usize,
	hash: Sha256,
}

impl Write for BoundedHash {
	fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
		if bytes.len() > MAX_REQUEST_BYTES.saturating_sub(self.count) {
			return Err(std::io::Error::other("binary-choice request exceeds 1 MiB"));
		}
		self.count += bytes.len();
		self.hash.update(bytes);
		Ok(bytes.len())
	}

	fn flush(&mut self) -> std::io::Result<()> {
		Ok(())
	}
}

fn request_sha256(params: &BinaryChoiceParams) -> Result<String> {
	let mut writer = BoundedHash {
		count: 0,
		hash: Sha256::new(),
	};
	writer
		.hash
		.update(b"hepta.weight.binary-choice-request.v1\0");
	serde_json::to_writer(&mut writer, params)?;
	Ok(rea_model::digest_hex(&writer.hash.finalize()))
}

fn validate(params: &BinaryChoiceParams) -> Result<Work> {
	let work = validate_data(&params.data)?;
	if params.weight_tensor.is_empty()
		|| params.weight_tensor.len() > 1024
		|| params.bias_tensor.is_empty()
		|| params.bias_tensor.len() > 1024
		|| params.weight_tensor == params.bias_tensor
		|| !weight_config::valid_sha256(&params.expected_data_sha256)
		|| params.data.producer.parent_checkpoint_sha256 != params.parent.complete_sha256
	{
		bail!("binary-choice selection or parent feature-source binding is invalid");
	}
	for source in [&params.parent, &params.candidate] {
		if [
			&source.complete_sha256,
			&source.weight_payload_sha256,
			&source.bias_payload_sha256,
		]
		.iter()
		.any(|value| !weight_config::valid_sha256(value))
		{
			bail!("binary-choice sources require complete file and parameter hashes");
		}
	}
	if data_sha256(&params.data)? != params.expected_data_sha256 {
		bail!("binary-choice data, pairing, target or baseline differs from its commitment");
	}
	Ok(work)
}

async fn open(
	binding: &CheckpointBinding,
	roots: &[PathBuf],
	state: &Path,
) -> Result<tokio::fs::File> {
	match &binding.input {
		CheckpointInput::Path { path } => {
			if !Path::new(path).is_absolute() || Path::new(path).starts_with(state) {
				bail!(
					"binary-choice workspace source requires an absolute admitted non-state path"
				);
			}
			Ok(rea_files::open_confined(Path::new(path), roots).await?.0)
		}
		CheckpointInput::Artifact { artifact_id } => {
			let (file, _, expected) =
				weight_artifact::open_pinned_artifact(artifact_id, state).await?;
			if expected != binding.complete_sha256 {
				bail!("binary-choice artifact identity differs from the canonical owner manifest");
			}
			Ok(file)
		}
	}
}

fn aggregate(outputs: &[Vec<f32>], data: &ChoiceData) -> Result<(Vec<u32>, f64, usize)> {
	if outputs.len() != data.rows.len() || outputs.iter().any(|row| row.len() != 2) {
		bail!("binary-choice raw head output shape differs from complete paired rows");
	}
	let mut scores = Vec::with_capacity(outputs.len());
	for (output, baseline) in outputs.iter().zip(&data.baseline) {
		// Three distinct F32 producer operations must not be replaced with F64 arithmetic
		// or the algebraically equivalent subtraction of two combined head rows.
		let contrast: f32 = output[1] - output[0];
		let score: f32 = *baseline + contrast;
		if !contrast.is_finite() || !score.is_finite() {
			bail!("binary-choice F32 contrast or physical score overflowed");
		}
		scores.push(score);
	}
	let mut margins = Vec::with_capacity(data.pairs.len());
	let mut squared_error = 0_f64;
	let mut correct = 0;
	for pair in &data.pairs {
		let margin: f32 = scores[pair.choice1_row] - scores[pair.choice0_row];
		if !margin.is_finite() {
			bail!("binary-choice final F32 margin overflowed");
		}
		let error = f64::from(margin) - f64::from(pair.margin_target);
		squared_error += error * error;
		correct += usize::from((margin > 0.0) == (pair.margin_target == 1));
		margins.push(margin.to_bits());
	}
	let mse = squared_error / (data.pairs.len() as f64);
	if !mse.is_finite() {
		bail!("binary-choice F64 mean squared error is nonfinite");
	}
	Ok((margins, mse, correct))
}

fn calculate(
	captured: source::Captured,
	data: &ChoiceData,
	work: Work,
	deadline: Instant,
) -> Result<Evaluation> {
	let mut raw = Vec::with_capacity(work.rows);
	let mut batches = Vec::new();
	for (index, rows) in data.rows.chunks(BATCH_ROWS).enumerate() {
		check_deadline(deadline)?;
		let output = weight_forward::calculate(
			&captured.weights,
			rows,
			Some(&captured.bias),
			2,
			work.columns,
			deadline,
		)?;
		let bits: Vec<_> = output
			.iter()
			.flat_map(|row| row.iter().flat_map(|value| value.to_le_bytes()))
			.collect();
		batches.push(BatchEvidence {
			start_row: index * BATCH_ROWS,
			row_count: rows.len(),
			source_sha256: captured.evidence.complete_sha256.clone(),
			captured_weight_payload_sha256: captured.evidence.weight_payload_sha256.clone(),
			macs: (rows.len() as u64) * (work.columns as u64) * 2,
			output_values: (rows.len() as u64) * 2,
			raw_output_bits_sha256: sha(&bits),
		});
		raw.extend(output);
	}
	check_deadline(deadline)?;
	let (query_margin_bits, mean_squared_margin_error, correct_queries) = aggregate(&raw, data)?;
	check_deadline(deadline)?;
	Ok(Evaluation {
		source: captured.evidence,
		batches,
		raw_head_bits: raw
			.iter()
			.map(|row| [row[0].to_bits(), row[1].to_bits()])
			.collect(),
		query_margin_bits,
		mean_squared_margin_error,
		accuracy: (correct_queries as f64) / (work.queries as f64),
		correct_queries,
	})
}

async fn evaluate_inner(
	params: &BinaryChoiceParams,
	roots: &[PathBuf],
	state: &Path,
	started: Instant,
	deadline: Instant,
) -> Result<BinaryChoiceReport> {
	let request_sha256 = request_sha256(params)?;
	let work = validate(params)?;
	check_deadline(deadline)?;
	let mut parent_file = open(&params.parent, roots, state).await?;
	let parent = source::capture(
		params,
		&params.parent,
		&mut parent_file,
		work.columns,
		deadline,
	)
	.await?;
	drop(parent_file);
	let mut candidate_file = open(&params.candidate, roots, state).await?;
	let candidate = source::capture(
		params,
		&params.candidate,
		&mut candidate_file,
		work.columns,
		deadline,
	)
	.await?;
	drop(candidate_file);
	if parent.evidence.source_size_bytes != candidate.evidence.source_size_bytes
		|| parent.evidence.weight_offset != candidate.evidence.weight_offset
		|| parent.evidence.weight_length != candidate.evidence.weight_length
		|| parent.evidence.protected_bytes_sha256 != candidate.evidence.protected_bytes_sha256
		|| parent.evidence.bias_payload_sha256 != candidate.evidence.bias_payload_sha256
	{
		bail!(
			"binary-choice frozen features require every byte outside the selected weight to remain unchanged"
		);
	}
	let parent = calculate(parent, &params.data, work, deadline)?;
	let candidate = calculate(candidate, &params.data, work, deadline)?;
	check_deadline(deadline)?;
	Ok(BinaryChoiceReport {
		schema: "hepta.weight.binary-choice-contrast.v1",
		request_sha256,
		data_sha256: params.expected_data_sha256.clone(),
		producer: params.data.producer.clone(),
		work,
		mean_squared_error_reduction: parent.mean_squared_margin_error
			- candidate.mean_squared_margin_error,
		accuracy_change: candidate.accuracy - parent.accuracy,
		parent,
		candidate,
		seconds_elapsed: started.elapsed().as_secs_f64(),
		operation_deadline_seconds: SECONDS,
		batch_row_limit: BATCH_ROWS,
		physical_and_bias_bytes_unchanged: true,
		complete_sources_authenticated: true,
		feature_provenance_verified: false,
		full_model_executed: false,
		production_eligible: false,
		metric: "mean squared error of final F32 query margins against +/-1 targets, accumulated in F64",
		operation_order: "F32(z1-z0); F32(baseline+contrast); F32(score_choice1-score_choice0); F64 squared error; choice1 iff margin>0",
	})
}

async fn evaluate_with_roots(
	params: &BinaryChoiceParams,
	roots: &[PathBuf],
	state: &Path,
) -> Result<BinaryChoiceReport> {
	let started = Instant::now();
	let deadline = started + Duration::from_secs(SECONDS);
	tokio::time::timeout(
		Duration::from_secs(SECONDS),
		evaluate_inner(params, roots, state, started, deadline),
	)
	.await
	.context("binary-choice capture and evaluation exceeded its shared 60 second deadline")?
}

/// Reopen both actual sources using existing workspace/artifact admission. This read-only
/// operation authenticates bytes and evaluates a frozen readout; it performs no model-body replay.
pub async fn evaluate(params: &BinaryChoiceParams) -> Result<BinaryChoiceReport> {
	let config = runtime::runtime_config()?;
	evaluate_with_roots(
		params,
		&config.controller_workspace_roots,
		&config.state_dir,
	)
	.await
}

#[cfg(all(test, target_os = "linux"))]
#[path = "weight_binary_choice_tests.rs"]
mod tests;
