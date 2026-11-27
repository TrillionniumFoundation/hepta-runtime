// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Isolated complete-model research evaluator. This example publishes no model.
#[path = "native_smallhcsn_profile/bound_io.rs"]
mod bound_io;
#[path = "native_smallhcsn_profile/deadline.rs"]
mod deadline;
#[path = "native_smallhcsn_profile/matrix.rs"]
mod matrix;
#[path = "native_smallhcsn_profile/model.rs"]
mod model;
#[cfg(test)]
#[path = "native_smallhcsn_profile/native_tests.rs"]
mod native_tests;
#[path = "native_smallhcsn_profile/physics.rs"]
mod physics;

use anyhow::{ensure, Context, Result};
use serde_json::json;
use std::{
	path::Path,
	time::{Duration, Instant},
};
use tokio::{fs::OpenOptions, io::AsyncWriteExt};

async fn run(args: &[String]) -> Result<()> {
	ensure!(args.len()==8, "usage: weight-smallhcsn-research ABS_PROFILE_JSON PROFILE_SHA ABS_ARTIFACT ARTIFACT_SHA ABS_RAW_INPUT INPUT_SHA ABS_NEW_OUTPUT");
	let started = Instant::now();
	let deadline = deadline::Deadline::new(Duration::from_secs(60));
	let profile = bound_io::capture(Path::new(&args[1]), &args[2], 262144, &deadline).await?;
	let artifact = bound_io::capture(Path::new(&args[3]), &args[4], 131072, &deadline).await?;
	let input = bound_io::capture(Path::new(&args[5]), &args[6], 65536, &deadline).await?;
	ensure!(
		Path::new(&args[7]).is_absolute(),
		"explicit absolute output path required"
	);
	let bound = bound_io::bind(&profile, &artifact, &input)?;
	let inputs = bound_io::inputs(&input)?;
	let output = model::evaluate(&bound, &inputs, &deadline)?;
	let raw = output.bytes();
	// A second open verifies that the named source artifacts still have their admitted identities.
	bound_io::capture(Path::new(&args[1]), &args[2], 262144, &deadline).await?;
	bound_io::capture(Path::new(&args[3]), &args[4], 131072, &deadline).await?;
	bound_io::capture(Path::new(&args[5]), &args[6], 65536, &deadline).await?;
	deadline.check()?;
	let mut file = tokio::time::timeout(
		deadline.remaining()?,
		OpenOptions::new()
			.write(true)
			.create_new(true)
			.open(&args[7]),
	)
	.await
	.context("output open deadline")?
	.context("create new result file")?;
	let write: Result<()> = async {
		tokio::time::timeout(deadline.remaining()?, file.write_all(&raw))
			.await
			.context("output write deadline")?
			.context("write result file")?;
		tokio::time::timeout(deadline.remaining()?, file.flush())
			.await
			.context("output flush deadline")?
			.context("flush result file")
	}
	.await;
	if let Err(error) = write {
		drop(file);
		tokio::fs::remove_file(&args[7])
			.await
			.context("remove incomplete owned result")?;
		return Err(error);
	}
	println!(
		"{}",
		json!({"schema":"hepta.native-smallhcsn-research-result.v1",
        "profile_sha256":args[2],"source_before_sha256":args[4],"source_after_sha256":args[4],
        "input_sha256":args[6],"output_sha256":bound_io::sha(&raw),"output_bytes":raw.len(),
        "canonical_sha256_declared":bound.canonical_sha256,
        "source_checkpoint_sha256_declared":bound.source_checkpoint_sha256,
        "profile_identifier":bound.profile_identifier,"source_declarations":bound.source_declarations,
        "source_declarations_independently_proved_by_this_call":false,
        "full_model_executed":true,"cached_features_used_as_input":false,"queries":output.n,
        "ticks":6,"neurons":8,"max_physical_violations":output.diagnostics,
        "diagnostic_order":["mass_error","negative_probability","mark_excess","negative_risk","risk_above_one","risk_above_event_count"],
        "margin_mse_f64":output.mse,"correct":output.correct,"active_wall_seconds":started.elapsed().as_secs_f64(),
        "output_path":args[7],"production_eligible":false})
	);
	Ok(())
}
#[tokio::main(flavor = "current_thread")]
async fn main() {
	if let Err(error) = run(&std::env::args().collect::<Vec<_>>()).await {
		eprintln!("{error:#}");
		std::process::exit(1);
	}
}
