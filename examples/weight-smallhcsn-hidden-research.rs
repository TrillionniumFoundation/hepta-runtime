// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Explicit-file hidden-scope admission and full raw-input candidate evaluation.
//! This driver prepares the existing cohort request; it creates no model artifact or live pointer.

#[path = "native_smallhcsn_profile/bound_io.rs"]
mod bound_io;

use anyhow::{ensure, Context, Result};
use hepta_runtime::mcp::weight_hidden_scope::{self, drift};
use hepta_runtime::mcp::weight_smallhcsn as profile_core;
use hepta_runtime::mcp::weight_smallhcsn::Deadline;
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
	path::Path,
	time::{Duration, Instant},
};
use tokio::{fs::OpenOptions, io::AsyncWriteExt};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BoundInputs {
	profile_path: String,
	profile_sha256: String,
	parent_path: String,
	raw_input_path: String,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum HiddenOperation {
	CompileDrift {
		params: Box<drift::CompileParams>,
	},
	PrepareCohort {
		params: Box<weight_hidden_scope::PlanParams>,
		sources: BoundInputs,
		request_id: String,
	},
	EvaluateCandidate {
		params: Box<weight_hidden_scope::PlanParams>,
		sources: BoundInputs,
		candidate_path: String,
		output_path: String,
	},
}

async fn capture_inputs(
	sources: &BoundInputs,
	params: &weight_hidden_scope::PlanParams,
	deadline: &Deadline,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
	let profile = bound_io::capture(
		Path::new(&sources.profile_path),
		&sources.profile_sha256,
		262144,
		deadline,
	)
	.await?;
	let parent = bound_io::capture(
		Path::new(&sources.parent_path),
		&params.parent_sha256,
		131072,
		deadline,
	)
	.await?;
	let input = bound_io::capture(
		Path::new(&sources.raw_input_path),
		&params.input_sha256,
		65536,
		deadline,
	)
	.await?;
	Ok((profile, parent, input))
}

async fn write_output(path: &str, raw: &[u8], deadline: &Deadline) -> Result<()> {
	ensure!(
		Path::new(path).is_absolute(),
		"explicit absolute new output path required"
	);
	deadline.check()?;
	let mut file = tokio::time::timeout(
		deadline.remaining()?,
		OpenOptions::new().write(true).create_new(true).open(path),
	)
	.await
	.context("hidden output open deadline")?
	.context("create new hidden output")?;
	let written: Result<()> = async {
		tokio::time::timeout(deadline.remaining()?, file.write_all(raw))
			.await
			.context("hidden output write deadline")?
			.context("write hidden output")?;
		tokio::time::timeout(deadline.remaining()?, file.flush())
			.await
			.context("hidden output flush deadline")?
			.context("flush hidden output")
	}
	.await;
	if let Err(error) = written {
		drop(file);
		tokio::fs::remove_file(path)
			.await
			.context("remove incomplete owned hidden output")?;
		return Err(error);
	}
	Ok(())
}

fn bind_parent(
	profile: &[u8],
	parent: &[u8],
	input: &[u8],
	expected: &str,
) -> Result<profile_core::BoundModel> {
	let model = bound_io::bind(profile, parent, input)?;
	ensure!(
		model.canonical_sha256() == expected,
		"hidden scope requires the exact canonical parent commitment"
	);
	Ok(model)
}

async fn perform(operation: HiddenOperation, deadline: &Deadline) -> Result<Value> {
	match operation {
		HiddenOperation::CompileDrift { params } => drift::compile_with_deadline(
			&params,
			Instant::now() + deadline.remaining()?.min(Duration::from_secs(5)),
		),
		HiddenOperation::PrepareCohort {
			params,
			sources,
			request_id,
		} => {
			let (profile, parent, input) = capture_inputs(&sources, &params, deadline).await?;
			let bound = bind_parent(&profile, &parent, &input, &params.parent_sha256)?;
			// Parse raw inputs now, so this plan cannot silently bind a cached-feature file.
			let inputs = bound_io::inputs(&input)?;
			let plan = weight_hidden_scope::prepare_with_deadline(
				&params,
				&parent,
				Instant::now() + deadline.remaining()?.min(Duration::from_secs(5)),
			)?;
			let request = plan.cohort_request(sources.parent_path.clone(), request_id)?;
			capture_inputs(&sources, &params, deadline).await?;
			deadline.check()?;
			Ok(
				json!({"schema":"hepta.native-smallhcsn-hidden-cohort-plan.v1",
                "admission":plan.evidence(),"cohort_request":request,"queries":inputs.queries(),
                "profile_sha256":sources.profile_sha256,"profile_identifier":bound.profile_identifier(),
                "source_declarations":bound.source_declarations(),"target_truth_verified":false,
                "full_model_executed":false,"model_artifact_published":false,
                "existing_cohort_owner_required":true,"production_eligible":false}),
			)
		}
		HiddenOperation::EvaluateCandidate {
			params,
			sources,
			candidate_path,
			output_path,
		} => {
			let (profile, parent, input) = capture_inputs(&sources, &params, deadline).await?;
			let inputs = bound_io::inputs(&input)?;
			let plan = weight_hidden_scope::prepare_with_deadline(
				&params,
				&parent,
				Instant::now() + deadline.remaining()?.min(Duration::from_secs(5)),
			)?;
			let candidate = bound_io::capture(
				Path::new(&candidate_path),
				&params.candidate_sha256,
				131072,
				deadline,
			)
			.await?;
			let (bound, admission) =
				profile_core::bind_hidden_candidate(&profile, &parent, &candidate, &input, &plan)?;
			let result = profile_core::evaluate(&bound, &inputs, deadline)?;
			let output = result.bytes();
			capture_inputs(&sources, &params, deadline).await?;
			bound_io::capture(
				Path::new(&candidate_path),
				&params.candidate_sha256,
				131072,
				deadline,
			)
			.await?;
			deadline.check()?;
			write_output(&output_path, &output, deadline).await?;
			Ok(json!({"schema":"hepta.native-smallhcsn-hidden-result.v1",
                "admission":admission,"profile_sha256":sources.profile_sha256,
                "parent_before_sha256":params.parent_sha256,"parent_after_sha256":params.parent_sha256,
                "candidate_before_sha256":params.candidate_sha256,"candidate_after_sha256":params.candidate_sha256,
                "input_sha256":params.input_sha256,"output_sha256":bound_io::sha(&output),
                "output_path":output_path,"output_bytes":output.len(),"queries":result.n,"ticks":6,
                "profile_identifier":bound.profile_identifier(),"source_declarations":bound.source_declarations(),
                "source_checkpoint_sha256_declared":bound.source_checkpoint_sha256(),
                "source_declarations_independently_proved_by_this_call":false,
                "full_model_executed":true,"cached_features_used_as_input":false,
                "max_physical_violations":result.diagnostics,"margin_mse_f64":result.mse,"correct":result.correct,
                "diagnostic_order":["mass_error","negative_probability","mark_excess","negative_risk","risk_above_one","risk_above_event_count"],
                "owner_artifact_identity_independently_verified":false,"target_truth_verified":false,
                "candidate_selected":false,"restoration_performed_by_this_call":false,
                "production_eligible":false}))
		}
	}
}

async fn run(args: &[String]) -> Result<()> {
	ensure!(
		args.len() == 3,
		"usage: weight-smallhcsn-hidden-research ABS_REQUEST_JSON REQUEST_SHA256"
	);
	let started = Instant::now();
	let deadline = Deadline::new(Duration::from_secs(60));
	let raw = bound_io::capture(Path::new(&args[1]), &args[2], 1048576, &deadline).await?;
	let request: HiddenOperation =
		serde_json::from_slice(&raw).context("bounded hidden request")?;
	let mut result = perform(request, &deadline).await?;
	result["request_file_sha256"] = json!(args[2]);
	result["active_wall_seconds"] = json!(started.elapsed().as_secs_f64());
	println!("{result}");
	Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
	if let Err(error) = run(&std::env::args().collect::<Vec<_>>()).await {
		eprintln!("{error:#}");
		std::process::exit(1);
	}
}
