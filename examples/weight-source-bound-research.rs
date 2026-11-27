// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Explicit-config research driver for isolated native weight artifacts.
//! Uses the existing Runtime owner in this process; starts no service and changes no live pointer.

use anyhow::{anyhow, bail, Context, Result};
use hepta_runtime::mcp::{
	runtime,
	weight_artifact::{
		self,
		cohort::{f16_research, f32_recovery},
	},
	weight_binary_choice, weight_exact_rank,
	weight_guard::{f16::CoupledF16EvaluationParams, source_bound_f32},
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::path::Path;
use tokio::io::AsyncReadExt;

const MAX_INPUT_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum ResearchOperation {
	ExactF32ProtectionRank {
		params: Box<weight_exact_rank::ExactRankParams>,
	},
	F32RecoverOriginalIntent {
		params: Box<f32_recovery::RecoveryParams>,
	},
	BinaryChoiceContrast {
		params: Box<weight_binary_choice::BinaryChoiceParams>,
	},
	F16Research {
		params: Box<CoupledF16EvaluationParams>,
	},
	F16NextRequest {
		params: Box<CoupledF16EvaluationParams>,
		artifact_id: String,
	},
	F32Roundtrip {
		params: Box<source_bound_f32::SourceBoundParams>,
	},
	F32NextRequest {
		params: Box<source_bound_f32::SourceBoundParams>,
		artifact_id: String,
	},
	/// Explicit canonical recovery of an already known artifact after a prior process ended.
	F32Restore {
		params: Box<source_bound_f32::SourceBoundParams>,
		artifact_id: String,
	},
}

async fn read_input(path: &str) -> Result<Vec<u8>> {
	if !Path::new(path).is_absolute() {
		bail!("research driver requires explicit absolute input paths");
	}
	let file = tokio::fs::File::open(path).await?;
	let before = file.metadata().await?;
	if !before.is_file() || before.len() > MAX_INPUT_BYTES {
		bail!("research driver input must be a regular JSON file within 2 MiB");
	}
	let mut bytes = Vec::new();
	file.take(MAX_INPUT_BYTES + 1)
		.read_to_end(&mut bytes)
		.await?;
	if bytes.len() as u64 != before.len() || bytes.len() as u64 > MAX_INPUT_BYTES {
		bail!("research driver input changed size or exceeded its byte limit");
	}
	Ok(bytes)
}

async fn restored_f32(
	params: &source_bound_f32::SourceBoundParams,
	restoration: Value,
) -> Result<Value> {
	if restoration["sha256"] != params.guard.patch.expected_sha256
		|| restoration["source_modified"] != false
		|| restoration["production_eligible"] != false
	{
		bail!("canonical restoration does not bind the original isolated checkpoint");
	}
	let id = restoration["artifact_id"]
		.as_str()
		.ok_or_else(|| anyhow!("canonical restoration has no artifact identity"))?;
	let next = source_bound_f32::next_request(params, id).await?;
	Ok(json!({
		"restoration":restoration,
		"new_request":next,
		"restored_complete_bytes_and_stored_bias_reauthenticated":true,
		"full_model_executed":false,
		"production_eligible":false
	}))
}

async fn f32_roundtrip(params: source_bound_f32::SourceBoundParams) -> Result<Value> {
	let evaluation = source_bound_f32::evaluate(params.clone()).await?;
	let guard = &evaluation["guard"];
	let restoration = if guard["restoration"].is_object() {
		guard["restoration"].clone()
	} else {
		let candidate = guard["candidate"]["artifact_id"].as_str().ok_or_else(|| {
			anyhow!("no completed F32 publication; reconcile the original request")
		})?;
		serde_json::from_str(
			&weight_artifact::restore(weight_artifact::RestoreParams {
				artifact_id: candidate.into(),
			})
			.await?,
		)?
	};
	let restored = restored_f32(&params, restoration).await?;
	Ok(json!({
		"schema":"hepta.weight.source-bound-f32-research-roundtrip.v1",
		"evaluation":evaluation,
		"restored":restored,
		"source_dtype":"F32",
		"full_model_executed":false,
		"crash_recovery_verified":false,
		"live_activation":false,
		"production_eligible":false
	}))
}

async fn run(args: &[String]) -> Result<()> {
	if args.len() != 3 {
		bail!(
			"usage: weight-source-bound-research ABSOLUTE_RUNTIME_CONFIG_JSON ABSOLUTE_REQUEST_JSON"
		);
	}
	let config: runtime::RuntimeConfig = serde_json::from_slice(&read_input(&args[1]).await?)
		.context("invalid explicit Runtime configuration")?;
	config.validate()?;
	let request: ResearchOperation = serde_json::from_slice(&read_input(&args[2]).await?)
		.context("invalid bounded research request")?;
	runtime::init_runtime(config)?;
	let result = match request {
		ResearchOperation::ExactF32ProtectionRank { params } => {
			weight_exact_rank::evaluate(*params)?
		}
		ResearchOperation::F32RecoverOriginalIntent { params } => {
			f32_recovery::run(*params).await?
		}
		ResearchOperation::BinaryChoiceContrast { params } => {
			serde_json::to_value(weight_binary_choice::evaluate(&params).await?)?
		}
		ResearchOperation::F16Research { params } => {
			serde_json::to_value(f16_research::run(*params).await?)?
		}
		ResearchOperation::F16NextRequest {
			params,
			artifact_id,
		} => serde_json::to_value(f16_research::next_request(&params, &artifact_id).await?)?,
		ResearchOperation::F32Roundtrip { params } => f32_roundtrip(*params).await?,
		ResearchOperation::F32NextRequest {
			params,
			artifact_id,
		} => source_bound_f32::next_request(&params, &artifact_id).await?,
		ResearchOperation::F32Restore {
			params,
			artifact_id,
		} => {
			let restoration = serde_json::from_str(
				&weight_artifact::restore(weight_artifact::RestoreParams { artifact_id }).await?,
			)?;
			restored_f32(&params, restoration).await?
		}
	};
	println!("{}", serde_json::to_string(&result)?);
	Ok(())
}

fn main() -> Result<()> {
	let args: Vec<_> = std::env::args().collect();
	// The library's non-test parser re-executes this binary with a read-only inherited
	// descriptor. Delegate its exact private entry before creating runtime threads.
	if args.len() == 4 && args[1] == "rea-model-worker" && args[2] == "--request" {
		return hepta_runtime::mcp::rea_model::serve_once(&args[3]);
	}
	tokio::runtime::Builder::new_multi_thread()
		.worker_threads(2)
		.enable_all()
		.build()?
		.block_on(run(&args))
}
