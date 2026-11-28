// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Explicit-file read-only diagnostic built from the production full-model source files.

#[path = "../../../src/mcp/weight_smallhcsn/bound_io.rs"]
pub mod bound_io;
#[path = "../../../src/mcp/weight_smallhcsn/deadline.rs"]
pub mod deadline;
#[path = "../../../src/mcp/weight_smallhcsn/late_quote.rs"]
pub mod late_quote;
#[path = "../../../src/mcp/weight_smallhcsn/matrix.rs"]
pub mod matrix;
#[path = "../../../src/mcp/weight_smallhcsn/model.rs"]
pub mod model;
#[path = "../../../src/mcp/weight_smallhcsn/physics.rs"]
pub mod physics;
#[path = "../../../src/mcp/weight_smallhcsn/trace.rs"]
pub mod trace;

#[cfg(test)]
#[path = "../../../src/mcp/weight_smallhcsn/trace_tests.rs"]
mod trace_tests;

#[cfg(test)]
#[path = "../../../src/mcp/weight_smallhcsn/late_quote_tests.rs"]
mod late_quote_tests;

use anyhow::{ensure, Context, Result};
use serde_json::json;
use std::{
	fs::{File, OpenOptions},
	io::{Read, Write},
	path::Path,
	time::{Duration, Instant},
};

fn capture(path: &str, expected: &str, limit: u64) -> Result<Vec<u8>> {
	ensure!(
		Path::new(path).is_absolute(),
		"absolute input path required"
	);
	let mut options = OpenOptions::new();
	options.read(true);
	#[cfg(unix)]
	{
		use std::os::unix::fs::OpenOptionsExt;
		options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
	}
	let file = options.open(path).context("open pinned input")?;
	ensure!(file.metadata()?.is_file(), "regular input required");
	let mut bytes = Vec::new();
	file.take(limit + 1).read_to_end(&mut bytes)?;
	ensure!(bytes.len() as u64 <= limit, "input byte cap");
	ensure!(bound_io::sha(&bytes) == expected, "input digest mismatch");
	Ok(bytes)
}

/// Scientific control only. Every byte outside four declared F32 words must match
/// the canonical parent. This does not use or expand production artifact authority.
fn mark_control(
	parent_model: bound_io::BoundModel,
	parent: &[u8],
	candidate: &[u8],
) -> Result<bound_io::BoundModel> {
	late_quote::bind_candidate(parent_model, parent, candidate)
}

fn run(args: &[String]) -> Result<()> {
	ensure!(args.len() == 11, "usage: hepta-smallhcsn-trace-research trace|check|mark-control|mark-control-check|late-bridge ABS_PROFILE PROFILE_SHA ABS_PARENT PARENT_SHA ABS_CANDIDATE CANDIDATE_SHA ABS_INPUT INPUT_SHA ABS_NEW_OUTPUT");
	ensure!(
		matches!(
			args[1].as_str(),
			"trace" | "check" | "late-bridge" | "mark-control" | "mark-control-check"
		),
		"unknown operation"
	);
	let started = Instant::now();
	let deadline = deadline::Deadline::new(Duration::from_secs(60));
	let profile = capture(&args[2], &args[3], 262144)?;
	let parent = capture(&args[4], &args[5], 131072)?;
	let candidate = capture(&args[6], &args[7], 131072)?;
	let raw = capture(&args[8], &args[9], 65536)?;
	let parent_model = bound_io::bind(&profile, &parent, &raw)?;
	ensure!(
		parent_model.canonical_sha256() == args[5],
		"exact canonical parent required"
	);
	let mark_scope = args[1] == "late-bridge" || args[1].starts_with("mark-control");
	let graph = if args[1] == "late-bridge" {
		trace::ResearchGraph::FinalTickTiedReceiverMark
	} else {
		trace::ResearchGraph::Original
	};
	let selected = if mark_scope {
		mark_control(parent_model, &parent, &candidate)?
	} else {
		bound_io::bind_sender_candidate(&profile, &candidate, &raw)?
	};
	ensure!(
		selected.canonical_sha256() == args[5],
		"candidate parent differs"
	);
	let inputs = bound_io::inputs(&raw)?;
	let (output, records) = if graph == trace::ResearchGraph::Original {
		model::evaluate_traced(&selected, &inputs, &deadline)?
	} else {
		model::evaluate_research_traced(&selected, &inputs, &deadline, graph)?
	};
	let output_bytes = output.bytes();
	let mut passes = 1;
	let checked = args[1] == "check" || args[1] == "mark-control-check";
	if checked {
		let untraced = model::evaluate(&selected, &inputs, &deadline)?;
		passes += 1;
		ensure!(
			untraced.bytes() == output_bytes,
			"trace changed native model output"
		);
	}
	for record in records.iter().filter(|r| r.tick == 5) {
		let row = record.query * 2 + record.choice;
		ensure!(
			record.choice_score.to_bits() == output.scores[row].to_bits(),
			"final traced score differs"
		);
		for head in 0..2 {
			ensure!(
				record.receiver_heads[head].to_bits() == output.heads[row * 2 + head].to_bits(),
				"final traced head differs"
			);
		}
	}
	for (path, digest, limit) in [
		(&args[2], &args[3], 262144),
		(&args[4], &args[5], 131072),
		(&args[6], &args[7], 131072),
		(&args[8], &args[9], 65536),
	] {
		capture(path, digest, limit)?;
	}
	deadline.check()?;
	let result = json!({
		"schema":"hepta.smallhcsn.native-readonly-trace.v1",
		"profile_sha256":args[3],"parent_sha256":args[5],"selected_artifact_sha256":args[7],"input_sha256":args[9],
		"bound_profile_sha256":selected.profile_sha256,"header_sha256":selected.header_sha256,"tensor_facts":selected.tensor_facts,
		"input_paths_reopened_with_same_digests":true,
		"research_graph":graph,"modified_graph":graph != trace::ResearchGraph::Original,
		"effective_connectivity_changed":graph != trace::ResearchGraph::Original,
		"declared_profile_is_parameter_source_only_for_modified_graph":graph != trace::ResearchGraph::Original,
		"research_coordinate_scope":if mark_scope { "four_input_mark_price_column_words_7_16_25_34" } else { "original_sender40_scope" },
		"production_model_binding_or_edit_authority_granted":false,
		"source_checkpoint_sha256_declared":selected.source_checkpoint_sha256(),
		"source_provenance_independently_verified":false,
		"queries":output.n,"full_model_forward_calls":passes,"parameter_fits":0,"weight_writes":0,
		"parameter_or_graph_intervention_selected":candidate != parent || graph != trace::ResearchGraph::Original,
		"causal_effect_identified_by_this_single_observation":false,"production_eligible":false,
		"untraced_output_byte_equality_checked":checked,"original_output_sha256":bound_io::sha(&output_bytes),
		"features":output.features,"heads":output.heads,"scores":output.scores,
		"correct":output.correct,"margin_mse":output.mse,"physical_residuals":output.diagnostics,
		"trace_order":"query, choice, tick; neurons 0..3 senders, 4..7 receivers",
		"feature_order":["analytic_continuation_value","first_passage_risk","signed_event_rate","event_rate","normalized_margin"],
		"intermediate_heads_are_diagnostics_only":true,"trace":records,
		"active_wall_seconds_before_output_write":started.elapsed().as_secs_f64()
	});
	ensure!(
		Path::new(&args[10]).is_absolute(),
		"absolute output path required"
	);
	let bytes = serde_json::to_vec(&result)?;
	ensure!(
		bytes.len() <= 8 * 1024 * 1024,
		"bounded trace output exceeded"
	);
	let mut file: File = OpenOptions::new()
		.write(true)
		.create_new(true)
		.open(&args[10])?;
	file.write_all(&bytes)?;
	file.sync_all()?;
	println!(
		"{}",
		json!({"schema":"hepta.smallhcsn.native-readonly-trace-receipt.v1","output_sha256":bound_io::sha(&bytes),"output_bytes":bytes.len(),"model_output_sha256":bound_io::sha(&output_bytes),"full_model_forward_calls":passes,"correct":output.correct,"mse":output.mse,"wall_seconds":started.elapsed().as_secs_f64()})
	);
	Ok(())
}

fn main() {
	if let Err(error) = run(&std::env::args().collect::<Vec<_>>()) {
		eprintln!("{error:#}");
		std::process::exit(1);
	}
}
