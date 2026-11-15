// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Qualification driver for an explicitly configured, trusted native embedding.
//! This example grants no Hepta FinalUse and never turns shadow intents executable.
use anyhow::{bail, ensure, Context, Result};
use hepta_runtime::{
	mcp::runtime::{init_runtime, jobs::ProcessStartParams, RuntimeConfig},
	native,
};
use std::io::Write;

#[tokio::main]
async fn main() -> Result<()> {
	let args: Vec<String> = std::env::args().collect();
	if args.len() != 4 {
		bail!("usage: native_process_driver CONFIG start|start-hold|start-checked|start-checked-hold|observe|status|read|cancel REQUEST_JSON_FILE");
	}
	let config = tokio::fs::read(&args[1])
		.await
		.context("read explicit runtime configuration")?;
	let request = tokio::fs::read(&args[3])
		.await
		.context("read original operation request")?;
	init_runtime(serde_json::from_slice::<RuntimeConfig>(&config)?)?;
	let response = match args[2].as_str() {
		"start" | "start-hold" => {
			native::execute_or_observe(serde_json::from_slice(&request)?).await?
		}
		"start-checked" | "start-checked-hold" => {
			let original: ProcessStartParams = serde_json::from_slice(&request)?;
			let expected = serde_json::to_vec(&original)?;
			// This owned fixture checks the runtime handoff, not a production Hepta
			// issuer. Actual FinalUse qualification belongs to the Agentd owner.
			native::execute_or_observe_with_entry(original, move |actual| {
				ensure!(
					serde_json::to_vec(actual)? == expected,
					"checked entry changed original request"
				);
				eprintln!("HEPTA_NATIVE_CHECKED_FIXTURE_ENTRY");
				Ok(())
			})
			.await?
		}
		"observe" => native::observe_request(serde_json::from_slice(&request)?)
			.await?
			.unwrap_or_else(|| "null".to_owned()),
		"status" => native::status(serde_json::from_slice(&request)?).await?,
		"read" => native::read(serde_json::from_slice(&request)?).await?,
		"cancel" => native::cancel(serde_json::from_slice(&request)?).await?,
		_ => bail!("unsupported native process operation"),
	};
	println!("{response}");
	std::io::stdout().flush()?;
	if matches!(args[2].as_str(), "start-hold" | "start-checked-hold") {
		std::future::pending::<()>().await;
	}
	Ok(())
}
