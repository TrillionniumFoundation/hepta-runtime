// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Isolated, opt-in semantic-program qualification. No deployed model is modified.

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

use anyhow::{ensure, Result};
use late_quote::{
	FunctionIdentity, LateQuoteMinV1, Phase, PhaseBinding, RequestRoute, ResearchState,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
	fs::{File, OpenOptions},
	io::{Read, Write},
	path::Path,
	time::{Duration, Instant},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Pin {
	path: String,
	sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
	schema: String,
	parent: Pin,
	late_profile: Pin,
	late_input: Pin,
	retention_profile: Pin,
	retention_input: Pin,
	minimum_accuracy_percent: u32,
}

fn read(pin: &Pin, maximum: u64) -> Result<Vec<u8>> {
	ensure!(
		Path::new(&pin.path).is_absolute(),
		"absolute pinned input required"
	);
	let mut options = OpenOptions::new();
	options.read(true);
	#[cfg(unix)]
	{
		use std::os::unix::fs::OpenOptionsExt;
		options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
	}
	let file = options.open(&pin.path)?;
	ensure!(file.metadata()?.is_file(), "regular input required");
	let mut bytes = Vec::new();
	file.take(maximum + 1).read_to_end(&mut bytes)?;
	ensure!(
		bytes.len() as u64 <= maximum && bound_io::sha(&bytes) == pin.sha256,
		"input byte cap or SHA256 changed"
	);
	Ok(bytes)
}

fn write_new(directory: &Path, name: &str, bytes: &[u8]) -> Result<()> {
	let mut options = OpenOptions::new();
	options.write(true).create_new(true);
	#[cfg(unix)]
	{
		use std::os::unix::fs::OpenOptionsExt;
		options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
	}
	let mut file = options.open(directory.join(name))?;
	file.write_all(bytes)?;
	file.sync_all()?;
	Ok(())
}

fn engine_identity() -> String {
	bound_io::sha(
		&[
			include_bytes!("../../../src/mcp/weight_smallhcsn/model.rs").as_slice(),
			include_bytes!("../../../src/mcp/weight_smallhcsn/physics.rs").as_slice(),
			include_bytes!("../../../src/mcp/weight_smallhcsn/matrix.rs").as_slice(),
			include_bytes!("../../../src/mcp/weight_smallhcsn/trace.rs").as_slice(),
			include_bytes!("../../../src/mcp/weight_smallhcsn/bound_io.rs").as_slice(),
			include_bytes!("../../../src/mcp/weight_smallhcsn/deadline.rs").as_slice(),
		]
		.concat(),
	)
}

fn running_executable_sha256() -> Result<String> {
	#[cfg(target_os = "linux")]
	let file = File::open("/proc/self/exe")?;
	#[cfg(not(target_os = "linux"))]
	let file = File::open(std::env::current_exe()?)?;
	ensure!(
		file.metadata()?.is_file(),
		"running executable must be a regular file"
	);
	let mut bytes = Vec::new();
	file.take(64 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
	ensure!(
		bytes.len() <= 64 * 1024 * 1024,
		"running executable byte cap"
	);
	Ok(bound_io::sha(&bytes))
}

struct EvaluationInput<'a> {
	profile: &'a [u8],
	parent: &'a [u8],
	raw: &'a [u8],
}

fn evaluate(
	state: &ResearchState,
	graph: trace::ResearchGraph,
	phase: Phase,
	dataset: &EvaluationInput<'_>,
	deadline: &deadline::Deadline,
	records: &mut Vec<Value>,
) -> Result<model::Output> {
	let EvaluationInput {
		profile,
		parent,
		raw,
	} = *dataset;
	// This second original binding also pins the readout payload before the separate
	// research scope admits four mark words. No sender candidate bytes are accepted here.
	let model = bound_io::bind_sender_candidate(profile, parent, raw)?;
	let model = late_quote::bind_candidate(model, parent, state.bytes())?;
	let input = bound_io::inputs(raw)?;
	let request_route = match (graph, phase) {
		(trace::ResearchGraph::Original, _) => RequestRoute::OriginalFixedProfile,
		(_, Phase::BridgeKeep | Phase::EditedCandidate) => {
			LateQuoteMinV1::check(&input)?;
			RequestRoute::CheckedLateQuoteMinV1
		}
		_ => RequestRoute::ResearchUnconditionalNegativeControl,
	};
	let started = Instant::now();
	let output = if graph == trace::ResearchGraph::Original && phase == Phase::Parent {
		model::evaluate_traced(&model, &input, deadline)?.0
	} else if graph == trace::ResearchGraph::Original {
		model::evaluate(&model, &input, deadline)?
	} else {
		model::evaluate_research_traced(&model, &input, deadline, graph)?.0
	};
	let binding = PhaseBinding {
		function: FunctionIdentity {
			graph,
			request_route,
			..state.identity().clone()
		},
		input_sha256: bound_io::sha(raw),
		phase,
	};
	records.push(json!({"binding":binding,"profile_sha256":bound_io::sha(profile),
		"bound_profile_sha256":model.profile_sha256,"bound_header_sha256":model.header_sha256,
		"model_output_sha256":bound_io::sha(&output.bytes()),"correct":output.correct,"queries":output.n,
		"cross_entropy":cross_entropy(&output,&input),"margin_mse":output.mse,
		"physical_residuals":output.diagnostics,"full_model_forward_calls":1,"wall_seconds":started.elapsed().as_secs_f64()}));
	Ok(output)
}

fn cross_entropy(output: &model::Output, inputs: &bound_io::Inputs) -> f64 {
	(0..inputs.n)
		.map(|q| {
			let margin = f64::from(output.scores[q * 2 + 1]) - f64::from(output.scores[q * 2]);
			margin.max(0.0) + (-margin.abs()).exp().ln_1p() - f64::from(inputs.labels[q]) * margin
		})
		.sum::<f64>()
		/ inputs.n as f64
}

fn retained(parent: &model::Output, candidate: &model::Output, input: &bound_io::Inputs) -> bool {
	let no_lost = (0..input.n).all(|q| {
		let a = u8::from(parent.scores[q * 2 + 1] > parent.scores[q * 2]);
		let b = u8::from(candidate.scores[q * 2 + 1] > candidate.scores[q * 2]);
		a != input.labels[q] || b == a
	});
	no_lost && cross_entropy(candidate, input) <= cross_entropy(parent, input) + 1e-6
}

fn run(args: &[String]) -> Result<()> {
	ensure!(
		args.len() == 4,
		"usage: hepta-smallhcsn-late-program ABS_REQUEST REQUEST_SHA ABS_NEW_OUTPUT_DIRECTORY"
	);
	let start = Instant::now();
	let executable_sha256 = running_executable_sha256()?;
	let deadline = deadline::Deadline::new(Duration::from_secs(60));
	let request_bytes = read(
		&Pin {
			path: args[1].clone(),
			sha256: args[2].clone(),
		},
		65536,
	)?;
	let request: Request = serde_json::from_slice(&request_bytes)?;
	ensure!(
		request.schema == "hepta.late-quote-qualification.v1"
			&& (1..=100).contains(&request.minimum_accuracy_percent),
		"explicit fixed research request and goal required"
	);
	let parent = read(&request.parent, 131072)?;
	let late_profile = read(&request.late_profile, 262144)?;
	let late_raw = read(&request.late_input, 65536)?;
	let retention_profile = read(&request.retention_profile, 262144)?;
	let retention_raw = read(&request.retention_input, 65536)?;
	let model = bound_io::bind(&late_profile, &parent, &late_raw)?;
	let inputs = bound_io::inputs(&late_raw)?;
	let task = LateQuoteMinV1::check(&inputs)?;
	let prepared = late_quote::compile(&model, &parent, &task, &engine_identity())?;
	let output_dir = Path::new(&args[3]);
	ensure!(
		output_dir.is_absolute(),
		"absolute new output directory required"
	);
	std::fs::create_dir(output_dir)?;
	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt;
		std::fs::set_permissions(output_dir, std::fs::Permissions::from_mode(0o700))?;
	}
	write_new(output_dir, "request.json", &request_bytes)?;
	let Some(program) = prepared else {
		write_new(
			output_dir,
			"result.json",
			&serde_json::to_vec_pretty(
				&json!({"status":"ABSTAIN","reason":"all signed head contrasts are zero",
			"full_model_forward_calls":0,"weight_writes":0,"production_authority_granted":false}),
			)?,
		)?;
		return Ok(());
	};
	write_new(
		output_dir,
		"compiled_program.json",
		&serde_json::to_vec_pretty(
			&json!({"program":program.evidence(),"semantic_preconditions":task.evidence()}),
		)?,
	)?;
	// Targets are checked only after the label-free candidate has been compiled and sealed.
	for q in 0..inputs.n {
		let at = (q * 6 + 5) * 18 + 7;
		ensure!(
			inputs.labels[q] == u8::from(inputs.x[at + 9] < inputs.x[at]),
			"validation target differs from declared lower-price task"
		);
	}
	let parent_state = program.parent(&parent)?;
	write_new(
		output_dir,
		"parent.function.json",
		&serde_json::to_vec(parent_state.identity())?,
	)?;
	let mut observations = Vec::new();
	let late_data = EvaluationInput {
		profile: &late_profile,
		parent: &parent,
		raw: &late_raw,
	};
	let retention_data = EvaluationInput {
		profile: &retention_profile,
		parent: &parent,
		raw: &retention_raw,
	};
	let parent_late = evaluate(
		&parent_state,
		trace::ResearchGraph::Original,
		Phase::Parent,
		&late_data,
		&deadline,
		&mut observations,
	)?;
	let parent_retention = evaluate(
		&parent_state,
		trace::ResearchGraph::Original,
		Phase::Retention,
		&retention_data,
		&deadline,
		&mut observations,
	)?;
	let bridge = program.apply(&parent_state, &task, false)?;
	let keep = evaluate(
		&bridge,
		trace::ResearchGraph::FinalTickTiedReceiverMark,
		Phase::BridgeKeep,
		&late_data,
		&deadline,
		&mut observations,
	)?;
	let keep_goal = late_quote::goal_met(
		keep.correct as usize,
		keep.n,
		request.minimum_accuracy_percent,
	)?;
	let change_weights = !keep_goal;
	let selected = if change_weights {
		program.apply(&parent_state, &task, true)?
	} else {
		bridge
	};
	let selected_late = if change_weights {
		evaluate(
			&selected,
			trace::ResearchGraph::FinalTickTiedReceiverMark,
			Phase::EditedCandidate,
			&late_data,
			&deadline,
			&mut observations,
		)?
	} else {
		keep
	};
	write_new(output_dir, "candidate.safetensors", selected.bytes())?;
	write_new(
		output_dir,
		"candidate.function.json",
		&serde_json::to_vec(selected.identity())?,
	)?;
	// Retain the inverse capsule before subsequent validation can fail. Both are
	// isolated artifacts: no active shared model points at the research candidate.
	// The inverse always restores bytes AND graph, even if no weight word changed.
	let restored = program.restore(&selected, change_weights)?;
	write_new(output_dir, "restored.safetensors", restored.bytes())?;
	write_new(
		output_dir,
		"restored.function.json",
		&serde_json::to_vec(restored.identity())?,
	)?;
	let unconditional = evaluate(
		&selected,
		trace::ResearchGraph::FinalTickTiedReceiverMark,
		Phase::Retention,
		&retention_data,
		&deadline,
		&mut observations,
	)?;
	let scoped = evaluate(
		&selected,
		trace::ResearchGraph::Original,
		Phase::Retention,
		&retention_data,
		&deadline,
		&mut observations,
	)?;
	let retained_input = bound_io::inputs(&retention_raw)?;
	let unconditional_retained = retained(&parent_retention, &unconditional, &retained_input);
	let scoped_equal = parent_retention.bytes() == scoped.bytes();
	let weight_only = evaluate(
		&restored,
		trace::ResearchGraph::FinalTickTiedReceiverMark,
		Phase::WeightsOnlyRestore,
		&retention_data,
		&deadline,
		&mut observations,
	)?;
	let restored_retention = evaluate(
		&restored,
		restored.identity().graph,
		Phase::CompleteRestore,
		&retention_data,
		&deadline,
		&mut observations,
	)?;
	let restored_late = evaluate(
		&restored,
		restored.identity().graph,
		Phase::CompleteRestore,
		&late_data,
		&deadline,
		&mut observations,
	)?;
	let complete_restore = restored.identity() == parent_state.identity()
		&& restored.bytes() == parent
		&& restored_retention.bytes() == parent_retention.bytes()
		&& restored_late.bytes() == parent_late.bytes();
	ensure!(
		complete_restore,
		"graph plus weight rollback did not restore complete outputs"
	);
	for (pin, limit) in [
		(&request.parent, 131072),
		(&request.late_profile, 262144),
		(&request.late_input, 65536),
		(&request.retention_profile, 262144),
		(&request.retention_input, 65536),
	] {
		read(pin, limit)?;
	}
	let goal = late_quote::goal_met(
		selected_late.correct as usize,
		selected_late.n,
		request.minimum_accuracy_percent,
	)?;
	let accepted = goal && scoped_equal && complete_restore;
	let result = json!({"schema":"hepta.late-quote-program-qualification.v1","request_sha256":args[2],
		"running_executable_sha256":executable_sha256,"dependency_lockfile_sha256":bound_io::sha(include_bytes!("../Cargo.lock")),"target_arch":std::env::consts::ARCH,"target_os":std::env::consts::OS,"workflow_source_sha256":bound_io::sha(include_bytes!("late_program.rs")),
		"status":if accepted {"RESEARCH_TASK_SCOPED_VERIFIED"} else {"REJECTED_AND_RESTORED"},
		"selected_action":if change_weights {"EDIT_FOUR_PRICE_WORDS_IF_NEEDED"} else {"KEEP_WEIGHTS_WITH_EXPLICIT_TASK_GRAPH"},
		"selection_scope":"measured finite bridge-keep then fixed sign program; no global weight optimum or calibrated utility claim",
		"minimum_accuracy_percent":request.minimum_accuracy_percent,"goal_met":goal,
		"bridge_only_already_met_goal":keep_goal,"program_selected_after_keep_goal_failure":change_weights,"weight_edit_applied":selected.bytes()!=parent,
		"scoped_original_graph_retention_byte_equal":scoped_equal,"unconditional_graph_retention_passed":unconditional_retained,
		"scoped_retention_uses_same_selected_weights":true,"scoped_retention_requires_conditional_graph_routing":true,
		"source_provenance_independently_verified":false,
		"unconditional_graph_accepted":goal && unconditional_retained,"unconditional_rejected_and_restored":!unconditional_retained && complete_restore,
		"weight_only_rollback_output_equal":weight_only.bytes()==parent_retention.bytes(),
		"graph_and_weights_rollback_output_equal":complete_restore,"observations":observations,
		"full_model_forward_calls":observations.len(),"compilation_label_reads":0,"optimizer_steps":0,
		"actual_artifact_files_written":2,"source_parent_modified":false,"shared_model_activated":false,
		"durable_production_transaction_or_crash_recovery_qualified":false,
		"artifacts_are_isolated_create_only_research_files":true,"production_authority_granted":false,
		"wall_seconds_before_final_write":start.elapsed().as_secs_f64()});
	write_new(
		output_dir,
		"result.json",
		&serde_json::to_vec_pretty(&result)?,
	)?;
	File::open(output_dir)?.sync_all()?;
	println!(
		"{}",
		json!({"status":result["status"],"selected_action":result["selected_action"],"full_model_forward_calls":observations.len(),
		"goal_met":goal,"unconditional_retention_passed":unconditional_retained,"complete_restore":complete_restore,
		"wall_seconds":start.elapsed().as_secs_f64()})
	);
	Ok(())
}

fn main() {
	if let Err(error) = run(&std::env::args().collect::<Vec<_>>()) {
		eprintln!("{error:#}");
		std::process::exit(1);
	}
}
