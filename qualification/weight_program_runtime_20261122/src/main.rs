// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Create-only offline study interface; publication remains with the canonical owner.

use anyhow::{bail, Context, Result};
use hepta_semantic_source_adapter_study::unique_json;
use hepta_weight_program_study::{causal, coordinator, edit, planner, snapshot};
use serde::Deserialize;
use std::{
	collections::BTreeSet,
	io::{Read, Write},
	path::Path,
};

fn read(path: &str) -> Result<Vec<u8>> {
	let file = std::fs::File::open(path).context("open explicit input")?;
	if !file.metadata()?.is_file() || file.metadata()?.len() > snapshot::MAX_INPUT_BYTES as u64 {
		bail!("bounded regular input required");
	}
	let mut bytes = Vec::new();
	file.take(snapshot::MAX_INPUT_BYTES as u64 + 1)
		.read_to_end(&mut bytes)?;
	if bytes.len() > snapshot::MAX_INPUT_BYTES {
		bail!("input grew beyond bound");
	}
	Ok(bytes)
}

fn write(path: &str, value: &impl serde::Serialize) -> Result<()> {
	let p = Path::new(path);
	let parent = p
		.parent()
		.filter(|p| !p.as_os_str().is_empty())
		.unwrap_or(Path::new("."));
	let mut file = std::fs::OpenOptions::new()
		.create_new(true)
		.write(true)
		.open(p)?;
	file.write_all(&serde_json::to_vec_pretty(value)?)?;
	file.write_all(b"\n")?;
	file.sync_all()?;
	std::fs::File::open(parent)?.sync_all()?;
	Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PlanRequest {
	law: planner::FiniteLaw,
	budget: planner::Budget,
	allowed_actions: Option<BTreeSet<planner::ActionKind>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EquivalenceRequest {
	inputs: Vec<Vec<f64>>,
	permutation: Vec<usize>,
}

fn main() -> Result<()> {
	let args: Vec<_> = std::env::args().skip(1).collect();
	match args.first().map(String::as_str) {
		Some("snapshot") if args.len() == 6 => {
			let domain = match args[4].as_str() {
				"q" => snapshot::EditDomain::ContinuationOnly,
				"b" => snapshot::EditDomain::BeliefOnly,
				"joint" => snapshot::EditDomain::JointReadout,
				_ => bail!("domain must be q, b or joint"),
			};
			let state = snapshot::SemanticSnapshot::capture(
				&read(&args[1])?, &args[2], &read(&args[3])?, domain,
			)?;
			let identity = state.identity()?;
			write(&args[5], &serde_json::json!({"snapshot":state,"snapshot_sha256":identity}))?;
		}
		Some("compile") if args.len() == 6 => {
			let state = load_snapshot(&args[1], &args[3], &args[4])?;
			let program: edit::EditProgram = serde_json::from_value(unique_json(&read(&args[2])?)?)?;
			write(&args[5], &edit::compile(&state, &program)?)?;
		}
		Some("controls") if args.len() == 7 => {
			let state = load_snapshot(&args[1], &args[3], &args[4])?;
			let program: edit::EditProgram = serde_json::from_value(unique_json(&read(&args[2])?)?)?;
			let seeds: Vec<u64> = serde_json::from_value(unique_json(&read(&args[5])?)?)?;
			write(&args[6], &causal::controls(&state, &program, &seeds)?)?;
		}
		Some("prepare") if args.len() == 7 => {
			let state = load_snapshot(&args[1], &args[3], &args[4])?;
			let program: edit::EditProgram = serde_json::from_value(unique_json(&read(&args[2])?)?)?;
			let source = read(&args[3])?;
			let evaluator = read(&args[5])?;
			let prepared = coordinator::prepare(coordinator::Preparation {
				authenticated: &state, program: &program, source_bytes: &source,
				source_path: Path::new(&args[3]), evaluator_source: &evaluator,
			})?;
			write(&args[6], &prepared)?;
		}
		Some("equivalence") if args.len() == 6 => {
			let state = load_snapshot(&args[1], &args[3], &args[4])?;
			let request: EquivalenceRequest = serde_json::from_value(unique_json(&read(&args[2])?)?)?;
			if request.inputs.is_empty() || request.inputs.len() > 4096 {
				bail!("one to 4096 explicit probe inputs required");
			}
			let probes = request.inputs.iter().map(|input| causal::equivalent_coordinate_probe(&state, input, &request.permutation))
				.collect::<Result<Vec<_>>>()?;
			write(&args[5], &serde_json::json!({"schema":"hepta.full-network-equivalence-probes.v1", "source_sha256":state.snapshot().source_sha256,
				"snapshot_sha256":state.snapshot().identity()?,"request_sha256":hepta_semantic_source_adapter_study::digest(&read(&args[2])?),"probes":probes}))?;
		}
		Some("plan") if args.len() == 3 => {
			let request: PlanRequest = serde_json::from_value(unique_json(&read(&args[1])?)?)?;
			write(&args[2], &planner::solve(&request.law, request.budget, request.allowed_actions.as_ref())?)?;
		}
		Some("batch-plan") if args.len() == 3 => {
			let requests: Vec<PlanRequest> = hepta_weight_program_study::batch::parse(&read(&args[1])?)?;
			let plans = requests.iter().map(|r| planner::solve(&r.law, r.budget, r.allowed_actions.as_ref()))
				.collect::<Result<Vec<_>>>()?;
			write(&args[2], &plans)?;
		}
		_ => bail!("usage: snapshot BRIDGE SHA CONTRACT q|b|joint NEW_OUTPUT; compile SNAPSHOT PROGRAM BRIDGE CONTRACT NEW_OUTPUT; controls SNAPSHOT PROGRAM BRIDGE CONTRACT SEEDS NEW_OUTPUT; prepare SNAPSHOT PROGRAM BRIDGE CONTRACT EVALUATOR_SOURCE NEW_OUTPUT; equivalence SNAPSHOT REQUEST BRIDGE CONTRACT NEW_OUTPUT; plan REQUEST NEW_OUTPUT; batch-plan REQUESTS NEW_OUTPUT"),
	}
	Ok(())
}

fn load_snapshot(
	path: &str,
	bridge: &str,
	contract: &str,
) -> Result<snapshot::AuthenticatedSnapshot> {
	let value = unique_json(&read(path)?)?;
	let state: snapshot::SemanticSnapshot = serde_json::from_value(value["snapshot"].clone())?;
	if value["snapshot_sha256"] != state.identity()? {
		bail!("snapshot identity mismatch");
	}
	snapshot::AuthenticatedSnapshot::authenticate(&state, &read(bridge)?, &read(contract)?)
}
