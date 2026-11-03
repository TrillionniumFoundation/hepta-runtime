// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Observe one original terminal job through the public native API, without launch.
//! The same source works on the sequential baseline and the bounded-window build.

use anyhow::{bail, Result};
use hepta_runtime::{
	mcp::runtime::{init_runtime, jobs::ProcessStartParams, RuntimeConfig},
	native,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::time::Instant;

fn digest(bytes: &[u8]) -> String {
	Sha256::digest(bytes)
		.iter()
		.map(|byte| format!("{byte:02x}"))
		.collect()
}

#[tokio::main]
async fn main() -> Result<()> {
	let args: Vec<String> = std::env::args().collect();
	if args.len() != 4 {
		bail!("usage: native_output_probe CONFIG ORIGINAL_REQUEST_JSON MAX_OUTPUT_BYTES");
	}
	let config: RuntimeConfig = serde_json::from_slice(&tokio::fs::read(&args[1]).await?)?;
	let original: ProcessStartParams = serde_json::from_slice(&tokio::fs::read(&args[2]).await?)?;
	let max_output_bytes = args[3].parse::<usize>()?;
	init_runtime(config)?;
	let started = Instant::now();
	let Some(output) = native::observe_terminal_output(&original, max_output_bytes).await? else {
		println!(
			"{}",
			json!({"status":"pending", "wall_micros":started.elapsed().as_micros()})
		);
		return Ok(());
	};
	let observation_micros = started.elapsed().as_micros();
	let measured = output.observation_timing();
	let observation_timing = json!({
		"initial_observation_micros": measured.initial_observation.as_micros(),
		"page_reads": measured.page_reads,
		"read_windows": measured.read_windows,
		"output_read_micros": measured.output_read.as_micros(),
		"final_observation_micros": measured.final_observation.as_micros(),
	});
	if !output.matches_request(&original)? {
		bail!("terminal output changed the original request binding");
	}
	let job_id = output.job_id().to_owned();
	let exit_code = output.exit_code();
	let outcome = format!("{:?}", output.outcome());
	let (stdout, stderr) = output.into_streams();
	println!(
		"{}",
		json!({
			"status":"terminal", "job_id":job_id, "exit_code":exit_code,
			"outcome":outcome, "observation_micros":observation_micros,
			"stdout_bytes":stdout.len(), "stderr_bytes":stderr.len(),
			"stdout_sha256":digest(&stdout), "stderr_sha256":digest(&stderr),
			"original_host":original.host, "original_key":original.idempotency_key,
			"new_execution_submitted":false, "observation_timing":observation_timing
		})
	);
	Ok(())
}
