// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Persistent native research execution; canonical artifacts never become a live model.

mod evaluation;
mod inputs;
#[cfg(test)]
#[path = "lifecycle_tests.rs"]
mod lifecycle_tests;
mod meter;
mod owner;

use anyhow::{bail, Result};
use evaluation::{Context, NativeEvaluator};
use hepta_semantic_source_adapter_study::{digest, unique_json};
use hepta_weight_program_study::coordinator::{self, Preparation};
use hepta_weight_recovery_study::{self as recovery, ArtifactOwner, Checkpoint};
use inputs::Request;
use serde_json::json;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const CUTS: &[&str] = &[
	"capture_complete",
	"prepared",
	"publish_intent",
	"publish_effect",
	"published",
	"verify_intent",
	"evaluation_started",
	"baseline_complete",
	"verify_effect",
	"verified",
	"accepted",
	"restore_intent",
	"restore_effect",
	"restored",
	"complete",
];

pub(crate) fn cut(root: &Path, selected: &str, reached: &str) -> Result<()> {
	if !selected.is_empty() && selected == reached {
		inputs::save_json(
			&root.join("CUT_REACHED.json"),
			&json!({"phase":reached,"pid":std::process::id()}),
		)?;
		loop {
			std::thread::park_timeout(Duration::from_secs(1));
		}
	}
	Ok(())
}

struct StopAt {
	root: PathBuf,
	selected: String,
}

struct KeepBeforePublication;
impl Checkpoint for KeepBeforePublication {
	fn reached(&mut self, name: &str) -> Result<()> {
		if name == "prepared" {
			bail!("captured request had not started; retain original without publication");
		}
		Ok(())
	}
}

fn has_durable_record(root: &Path, transaction: &str) -> Result<bool> {
	let directory = root.join("journal").join(transaction);
	if !directory.try_exists()? {
		return Ok(false);
	}
	inputs::private_dir(&directory)?;
	let mut found = false;
	for (count, entry) in std::fs::read_dir(directory)?.enumerate() {
		if count >= 48 {
			bail!("bounded journal inventory exceeded");
		}
		if entry?.file_name().to_string_lossy().starts_with("record-") {
			found = true;
		}
	}
	Ok(found)
}
impl Checkpoint for StopAt {
	fn reached(&mut self, name: &str) -> Result<()> {
		cut(&self.root, &self.selected, name)
	}
}

fn read_inputs(request: &Request, root: &Path, fresh: bool) -> Result<[Vec<u8>; 4]> {
	let pins = [
		&request.source_bridge,
		&request.source_gzip,
		&request.semantic_contract,
		&request.program,
	];
	let names = [
		"source.safetensors",
		"source.json.gz",
		"contract.json",
		"program.json",
	];
	let mut results = Vec::new();
	for (pin, name) in pins.into_iter().zip(names) {
		let bytes = if fresh {
			pin.read()?
		} else {
			inputs::read(&root.join(name), inputs::MAX_INPUT)?
		};
		pin.verify(&bytes)?;
		results.push(bytes);
	}
	results
		.try_into()
		.map_err(|_| anyhow::anyhow!("four explicit input capabilities required"))
}

fn run(args: &[String]) -> Result<()> {
	if !(args.len() == 5 || args.len() == 6)
		|| !matches!(args[0].as_str(), "run" | "recover" | "next-task")
	{
		bail!("usage: hepta-weight-lifecycle-study run|recover|next-task REQUEST SHA256 ROOT RESULT.json [CUT]");
	}
	let begin = Instant::now();
	let total_cpu_start = meter::cpu_seconds()?;
	let auth_stamp = meter::Stamp::start()?;
	let fresh = args[0] == "run";
	let selected = args.get(5).cloned().unwrap_or_default();
	if !selected.is_empty() && (!fresh || !CUTS.contains(&selected.as_str())) {
		bail!("fault injection requires a fresh isolated run and a declared boundary");
	}
	let path = Path::new(&args[1]);
	inputs::absolute(path)?;
	let raw = inputs::read(path, inputs::MAX_INPUT)?;
	if digest(&raw) != args[2] {
		bail!("request byte identity mismatch");
	}
	let request = Request::parse(&raw)?;
	let root = PathBuf::from(&args[3]);
	inputs::absolute(&root)?;
	inputs::result_name(&args[4])?;
	if !fresh {
		inputs::private_dir(&root)?;
		if inputs::read(&root.join("REQUEST.json"), inputs::MAX_INPUT)? != raw {
			bail!("recovery request differs from retained request");
		}
	}
	let files = read_inputs(&request, &root, fresh)?;
	let binary = inputs::read(&std::env::current_exe()?, 256 * 1024 * 1024)?;
	let binary_sha = digest(&binary);
	let [bridge, gzip, contract, program] = files;
	let context = Context::load(
		request,
		bridge,
		gzip.clone(),
		contract,
		program.clone(),
		&binary_sha,
	)?;
	let evaluator_binding = serde_json::to_vec(
		&json!({"schema":"hepta.lifecycle-evaluator-binding.v1",
		"worker_binary_sha256":binary_sha,"request_sha256":args[2],"native_arithmetic":hepta_full_native_study::forward::ARITHMETIC,
		"source_components":{"worker":digest(include_bytes!("main.rs")),"evaluation":digest(include_bytes!("evaluation.rs")),
			"owner":digest(include_bytes!("owner.rs")),"inputs":digest(include_bytes!("inputs.rs"))}}),
	)?;
	let source_path = root.join("source.safetensors");
	let prepared = coordinator::prepare(Preparation {
		authenticated: &context.authenticated,
		program: &context.program,
		source_bytes: &context.original,
		source_path: &source_path,
		evaluator_source: &evaluator_binding,
	})?;
	let auth_measurement = auth_stamp.finish("authenticate_and_compile")?;
	if fresh {
		let capture_stamp = meter::Stamp::start()?;
		inputs::new_dir(&root)?;
		inputs::save(&root.join("REQUEST.json"), &raw)?;
		for (name, bytes) in [
			("source.safetensors", &context.original),
			("source.json.gz", &gzip),
			("contract.json", &context.contract),
			("program.json", &program),
			("EVALUATOR_BINDING.json", &evaluator_binding),
		] {
			inputs::save(&root.join(name), bytes)?;
		}
		inputs::save_json(
			&root.join("PREPARED.json"),
			&serde_json::to_value(&prepared)?,
		)?;
		inputs::save_json(
			&root.join("CAPTURE_METRICS.json"),
			&capture_stamp.finish("durable_input_capture")?,
		)?;
		cut(&root, &selected, "capture_complete")?;
	} else if inputs::read(&root.join("EVALUATOR_BINDING.json"), inputs::MAX_INPUT)?
		!= evaluator_binding
		|| unique_json(&inputs::read(
			&root.join("PREPARED.json"),
			inputs::MAX_INPUT,
		)?)? != serde_json::to_value(&prepared)?
	{
		bail!("fresh authentication or compiled execution identity differs from durable request");
	}
	let mut owner = owner::NativeOwner::new(&root)?;
	let mut evaluator = NativeEvaluator {
		context: &context,
		state: owner.state.clone(),
		output: root.join("EVALUATION.json"),
		calls: 0,
		full_policy_dps: 0,
		cut: selected.clone(),
		measurement: None,
	};
	let mut checkpoint = StopAt {
		root: root.clone(),
		selected,
	};
	let record =
		if fresh {
			coordinator::execute_research(
				&prepared,
				&root.join("journal"),
				&mut owner,
				&mut evaluator,
				&mut checkpoint,
			)?
		} else if has_durable_record(&root, &prepared.transaction_id()?)? {
			coordinator::recover_research(
				&prepared,
				&root.join("journal"),
				&mut owner,
				&mut checkpoint,
			)?
		} else {
			let store = owner.state.join("weight-artifacts-v1");
			if store.try_exists()? && std::fs::read_dir(store)?.next().is_some() {
				bail!("owner artifacts exist without a durable journal; refuse unstarted classification");
			}
			coordinator::execute_research(
				&prepared,
				&root.join("journal"),
				&mut owner,
				&mut evaluator,
				&mut KeepBeforePublication,
			)?
		};
	evaluation::verify_retained_evaluation(&root, &record)?;
	let restored_path = if let Some(receipt) = &record.restoration {
		owner.inspect(receipt)?;
		owner.artifact_path(receipt)?
	} else {
		source_path.clone()
	};
	let restored = inputs::read(&restored_path, inputs::MAX_INPUT)?;
	if restored != context.original {
		bail!("restoration is not byte-identical to the original checkpoint");
	}
	let mut next_measurement = None;
	let next = if args[0] == "next-task" {
		let next_stamp = meter::Stamp::start()?;
		if record.stage != recovery::Stage::Complete {
			bail!("next task requires completed prior recovery");
		}
		let snapshot = hepta_weight_program_study::snapshot::SemanticSnapshot::capture(
			&restored,
			&context.request.source_bridge.sha256,
			&context.contract,
			context.request.domain,
		)?;
		if snapshot.identity()? != context.authenticated.snapshot().identity()? {
			bail!("next-task semantic identity changed");
		}
		let result = context.policy_traced(
			&restored,
			&context.request.policy.next_task,
			Some(&root.join(format!("NEXT_{}", std::process::id()))),
		)?;
		next_measurement = Some(next_stamp.finish("next_task")?);
		Some(
			json!({"actual_model_path":restored_path,"model_sha256":digest(&restored),"snapshot_sha256":snapshot.identity()?,
			"actual_next_task_full_policy":result,"full_policy_dps":1,"live_model_pointer_changed":false}),
		)
	} else {
		None
	};
	let result = json!({"schema":"hepta.weight-lifecycle-process-result.v1","mode":args[0],"pid":std::process::id(),
		"request_sha256":args[2],"worker_binary_sha256":binary_sha,"transaction_id":prepared.transaction_id()?,
		"record":record,"evaluator_calls_this_process":evaluator.calls,"full_policy_dps_this_process":evaluator.full_policy_dps+usize::from(next.is_some()),
		"owner_calls_this_process":owner.calls,"source_bytes":context.original.len(),
		"owner_invocations_this_process":owner.operations,"phase_measurements":{"authenticate_and_compile":auth_measurement,
			"evaluation":evaluator.measurement,"next_task":next_measurement},
		"candidate_bytes":context.original.len(),"restored_bytes":restored.len(),"owner_inspected_model_bytes":owner.inspected_model_bytes,
		"source_unchanged":inputs::read(&source_path,inputs::MAX_INPUT)?==context.original,"restoration_exact":true,
		"next_task":next,"wall_seconds":begin.elapsed().as_secs_f64(),"process_cpu_seconds_before_final_result_write":meter::cpu_seconds()?-total_cpu_start,"production_adoption":false,
		"complete_native_evaluator":true,"external_evaluator_processes":0});
	inputs::save_json(&root.join(&args[4]), &result)?;
	println!(
		"{}",
		serde_json::to_string(
			&json!({"mode":args[0],"decision":result["record"]["decision"],"result":root.join(&args[4])})
		)?
	);
	Ok(())
}

fn main() -> Result<()> {
	run(&std::env::args().skip(1).collect::<Vec<_>>())
}
