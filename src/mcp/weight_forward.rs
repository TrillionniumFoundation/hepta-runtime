// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Bounded native F32 linear inference on an explicitly pinned safetensors tensor.
//! This fixed operator is not a general neural-network or PyTorch replacement.

use anyhow::{anyhow, bail, Context, Result};
use rmcp::schemars;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncSeekExt};

const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_WEIGHTS: u64 = 1_048_576;
const MAX_MACS: u64 = 16_777_216;
const MAX_OUTPUT_VALUES: u64 = 16_384;

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum LinearSource {
	Path {
		/// Absolute file within existing controller workspace roots.
		path: String,
		/// Complete source SHA-256, never a header-only identity.
		expected_sha256: String,
		tensor_name: String,
	},
	Artifact {
		/// Internal wa1_ artifact ID, verified against the native manifest.
		artifact_id: String,
		tensor_name: String,
	},
}

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ForwardLinearParams {
	pub source: LinearSource,
	/// 1..=64 finite F32 rows. Columns must match the tensor's input dimension.
	pub inputs: Vec<Vec<f32>>,
	/// Optional explicit finite F32 bias, one value per output. Omitted means zero.
	pub bias: Option<Vec<f32>>,
}

fn hex(bytes: &[u8]) -> String {
	bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn matrix_extent(report: &Value, name: &str) -> Result<(usize, usize, u64, usize)> {
	let tensor = &report["result"]["tensor"];
	if report["format"] != "safetensors"
		|| tensor["name"] != name
		|| tensor["dtype"] != "F32"
		|| tensor["storage_length_verified"] != true
	{
		bail!("native linear forward requires one verified F32 safetensors tensor");
	}
	let shape = tensor["shape"]
		.as_array()
		.filter(|shape| shape.len() == 2)
		.ok_or_else(|| anyhow!("linear weight must have [out_features,in_features] rank two"))?;
	let dimension = |index: usize| -> Result<u64> {
		Ok(shape[index]
			.as_str()
			.ok_or_else(|| anyhow!("model dimensions must retain exact decimal strings"))?
			.parse::<u64>()?)
	};
	let (outputs, inputs) = (dimension(0)?, dimension(1)?);
	if !(1..=4096).contains(&outputs) || !(1..=4096).contains(&inputs) {
		bail!("native linear dimensions must each be 1..=4096");
	}
	let count = outputs
		.checked_mul(inputs)
		.filter(|count| *count <= MAX_WEIGHTS)
		.ok_or_else(|| anyhow!("linear weight exceeds 1048576 elements"))?;
	let length = count * 4;
	let offset = tensor["file_offset"]
		.as_u64()
		.ok_or_else(|| anyhow!("tensor offset missing"))?;
	let source_size = report["source"]["size_bytes"]
		.as_u64()
		.ok_or_else(|| anyhow!("source size missing"))?;
	if tensor["byte_length"].as_u64() != Some(length)
		|| offset > source_size
		|| length > source_size - offset
	{
		bail!("linear weight extent differs from its declared shape");
	}
	Ok((outputs as usize, inputs as usize, offset, length as usize))
}

/// Tensor bytes are captured during the complete-file hash pass, so the
/// computation cannot silently use a later independent read of different data.
async fn capture(
	file: &mut tokio::fs::File,
	size: u64,
	offset: u64,
	length: usize,
) -> Result<(String, Vec<u8>)> {
	file.seek(std::io::SeekFrom::Start(0)).await?;
	let mut tensor = vec![0u8; length];
	let mut buffer = vec![0u8; 1024 * 1024];
	let mut hash = Sha256::new();
	let mut position = 0u64;
	let end = offset
		.checked_add(length as u64)
		.ok_or_else(|| anyhow!("tensor range overflow"))?;
	while position < size {
		let count = (size - position).min(buffer.len() as u64) as usize;
		file.read_exact(&mut buffer[..count]).await?;
		hash.update(&buffer[..count]);
		let left = position.max(offset);
		let right = (position + count as u64).min(end);
		if left < right {
			tensor[(left - offset) as usize..(right - offset) as usize]
				.copy_from_slice(&buffer[(left - position) as usize..(right - position) as usize]);
		}
		position += count as u64;
	}
	Ok((hex(&hash.finalize()), tensor))
}

fn check_inputs(
	inputs: &[Vec<f32>],
	bias: Option<&[f32]>,
	outputs: usize,
	columns: usize,
) -> Result<u64> {
	if !(1..=4096).contains(&outputs)
		|| !(1..=4096).contains(&columns)
		|| !(1..=64).contains(&inputs.len())
		|| inputs
			.iter()
			.any(|row| row.len() != columns || row.iter().any(|value| !value.is_finite()))
		|| bias.is_some_and(|bias| {
			bias.len() != outputs || bias.iter().any(|value| !value.is_finite())
		}) {
		bail!("native linear inputs and bias must be finite and match the selected dimensions");
	}
	let count = (outputs as u64) * (columns as u64);
	let macs = (inputs.len() as u64) * count;
	if count > MAX_WEIGHTS
		|| macs > MAX_MACS
		|| (inputs.len() as u64) * (outputs as u64) > MAX_OUTPUT_VALUES
	{
		bail!("native linear batch exceeds the weight, 16777216 multiply-add or 16384 output-value budget");
	}
	Ok(macs)
}

fn calculate(
	weights: &[f32],
	inputs: &[Vec<f32>],
	bias: Option<&[f32]>,
	outputs: usize,
	columns: usize,
	deadline: Instant,
) -> Result<Vec<Vec<f32>>> {
	check_inputs(inputs, bias, outputs, columns)?;
	if weights.len() != outputs * columns || weights.iter().any(|value| !value.is_finite()) {
		bail!("native linear weights must be finite and match the selected dimensions");
	}
	let mut result = Vec::with_capacity(inputs.len());
	for input in inputs {
		let mut row = Vec::with_capacity(outputs);
		for (output, output_weights) in weights.chunks_exact(columns).enumerate() {
			if Instant::now() >= deadline {
				bail!("native linear computation exceeded its operation deadline");
			}
			let mut sum = 0_f32;
			for (weight, value) in output_weights.iter().zip(input) {
				sum += weight * value;
			}
			if let Some(bias) = bias {
				sum += bias[output];
			}
			if !sum.is_finite() {
				bail!("native linear result overflowed F32");
			}
			row.push(sum);
		}
		result.push(row);
	}
	Ok(result)
}

async fn forward_with_roots(
	params: ForwardLinearParams,
	roots: &[PathBuf],
	state: &Path,
) -> Result<Value> {
	let deadline = Instant::now() + Duration::from_secs(60);
	if !(1..=64).contains(&params.inputs.len())
		|| params.inputs.iter().any(|row| {
			row.is_empty() || row.len() > 4096 || row.iter().any(|value| !value.is_finite())
		}) || params
		.bias
		.as_ref()
		.is_some_and(|bias| bias.len() > 4096 || bias.iter().any(|value| !value.is_finite()))
	{
		bail!("native linear request exceeds its row or dimension budget");
	}
	let (mut file, before, expected, name) = match &params.source {
		LinearSource::Path {
			path,
			expected_sha256,
			tensor_name,
		} => {
			if !super::weight_config::valid_sha256(expected_sha256) {
				bail!("linear source requires a complete SHA-256");
			}
			if Path::new(path).starts_with(state) {
				bail!("runtime state artifacts require an artifact ID, not a caller-supplied path");
			}
			let (file, metadata) = super::rea_files::open_confined(Path::new(path), roots).await?;
			(
				file,
				metadata,
				expected_sha256.clone(),
				tensor_name.as_str(),
			)
		}
		LinearSource::Artifact {
			artifact_id,
			tensor_name,
		} => {
			let (file, metadata, expected) =
				super::weight_artifact::open_pinned_artifact(artifact_id, state).await?;
			(file, metadata, expected, tensor_name.as_str())
		}
	};
	if name.is_empty() || name.len() > 4096 || before.len() > MAX_FILE_BYTES {
		bail!("native linear file exceeds 2 GiB or tensor name is invalid");
	}
	let report = super::rea_model::inspect_tensor_descriptor(&mut file, name).await?;
	let (outputs, columns, offset, length) = matrix_extent(&report, name)?;
	let macs = check_inputs(&params.inputs, params.bias.as_deref(), outputs, columns)?;
	let (full_sha, bytes) = capture(&mut file, before.len(), offset, length).await?;
	#[cfg(unix)]
	super::rea_files::ensure_unchanged(&before, &file.metadata().await?)?;
	if full_sha != expected {
		bail!("native linear complete source SHA-256 differs");
	}
	let weights = bytes
		.as_chunks::<4>()
		.0
		.iter()
		.map(|chunk| f32::from_le_bytes(*chunk))
		.collect::<Vec<_>>();
	let input_sha = hex(&Sha256::digest(serde_json::to_vec(
		&json!({"inputs":params.inputs,"bias":params.bias}),
	)?));
	let started = Instant::now();
	let result = calculate(
		&weights,
		&params.inputs,
		params.bias.as_deref(),
		outputs,
		columns,
		deadline,
	)?;
	Ok(
		json!({"schema":"hepta.weight.linear-forward.v1","implementation":"rust_sequential_f32_linear","source":params.source,"source_sha256":full_sha,"header_sha256":report["source"]["header_sha256"],"observed_version":report["source"]["observed_version"],"tensor_sha256":hex(&Sha256::digest(&bytes)),"input_sha256":input_sha,"weight_shape":[outputs,columns],"outputs":result,"multiply_adds":macs,"compute_seconds":started.elapsed().as_secs_f64(),"training":false,"production_eligible":false,"scope":"one F32 rank-two linear tensor with optional explicit bias"}),
	)
}

pub async fn forward(params: ForwardLinearParams) -> Result<String> {
	let config = super::runtime::runtime_config()?;
	let result = tokio::time::timeout(
		Duration::from_secs(60),
		forward_with_roots(
			params,
			&config.controller_workspace_roots,
			&config.state_dir,
		),
	)
	.await
	.context("native linear forward exceeded its 60-second deadline")??;
	let text = serde_json::to_string(&result)?;
	if text.len() > 1024 * 1024 {
		bail!("native linear response exceeds 1 MiB");
	}
	Ok(text)
}

#[cfg(all(test, target_os = "linux"))]
#[path = "weight_forward_tests.rs"]
mod tests;
