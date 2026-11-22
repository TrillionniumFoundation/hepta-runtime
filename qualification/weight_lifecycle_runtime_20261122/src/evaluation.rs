// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Independent full native policy evaluation, including each policy's occupancy.

use crate::inputs::{self, Request};
use anyhow::{anyhow, bail, Result};
use hepta_continuation_runtime_study::{
	source::{authenticate_source, VerifiedSource},
	task::Public,
};
use hepta_full_native_study::{codec, dag, forward};
use hepta_semantic_source_adapter_study::{
	digest,
	semantics::{verify_profile, ProfilePin},
	unique_json, SourcePin,
};
use hepta_weight_program_study::{
	edit::EditProgram,
	snapshot::{AuthenticatedSnapshot, SemanticSnapshot},
};
use hepta_weight_recovery_study as recovery;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub struct Context {
	pub request: Request,
	pub source: VerifiedSource,
	pub original: Vec<u8>,
	pub contract: Vec<u8>,
	pub program: EditProgram,
	pub authenticated: AuthenticatedSnapshot,
	pub model: Value,
	pub hardware_key: String,
}

/// A local file capability is not its repository provenance. The receipt pin
/// below comes from the already verified profile, not from the proposed edit.
pub(crate) fn original_compressed_pin(
	file: &inputs::Pin,
	receipt_pin: &SourcePin,
	receipt: &[u8],
) -> Result<SourcePin> {
	receipt_pin.verify(receipt, hepta_semantic_source_adapter_study::MAX_JSON_BYTES)?;
	let origin = unique_json(receipt)?;
	let files = origin["files"]
		.as_array()
		.ok_or_else(|| anyhow!("authenticated repository receipt has no files"))?;
	let matching: Vec<_> = files
		.iter()
		.filter(|row| {
			row["sha256"] == file.sha256 && row["bytes"].as_u64() == Some(file.bytes as u64)
		})
		.collect();
	if matching.len() != 1 {
		bail!("compressed checkpoint bytes have no unique authenticated repository origin");
	}
	let original_source_id = matching[0]["url"]
		.as_str()
		.filter(|value| !value.is_empty())
		.ok_or_else(|| anyhow!("authenticated checkpoint origin has no source identity"))?;
	Ok(file.source_pin(original_source_id))
}

impl Context {
	pub fn load(
		request: Request,
		bridge: Vec<u8>,
		gzip: Vec<u8>,
		contract: Vec<u8>,
		program: Vec<u8>,
		binary_sha: &str,
	) -> Result<Self> {
		request.source_bridge.verify(&bridge)?;
		request.source_gzip.verify(&gzip)?;
		request.semantic_contract.verify(&contract)?;
		request.program.verify(&program)?;
		let snapshot = SemanticSnapshot::capture(
			&bridge,
			&request.source_bridge.sha256,
			&contract,
			request.domain,
		)?;
		let authenticated = AuthenticatedSnapshot::authenticate(&snapshot, &bridge, &contract)?;
		let cv = unique_json(&contract)?;
		if cv["task"]["existing_exposed_public_world"]
			!= serde_json::to_value(&request.policy.primary)?
		{
			bail!("primary task differs from the authenticated semantic contract");
		}
		let pin: ProfilePin = serde_json::from_value(cv["profile_pin"].clone())?;
		let texts: BTreeMap<String, String> =
			serde_json::from_value(cv["profile_evidence"].clone())?;
		let evidence = texts
			.into_iter()
			.map(|(k, v)| (k, v.into_bytes()))
			.collect();
		let profile = verify_profile(&pin, &evidence)?;
		let compressed_pin = original_compressed_pin(
			&request.source_gzip,
			profile
				.sources()
				.get("checkpoint_fetch_receipt")
				.ok_or_else(|| anyhow!("verified checkpoint receipt pin missing"))?,
			evidence
				.get("checkpoint_fetch_receipt")
				.ok_or_else(|| anyhow!("verified checkpoint receipt bytes missing"))?,
		)?;
		let source =
			authenticate_source(&gzip, &compressed_pin, &request.decoded_source, &profile)?;
		let decoded = codec::decode(&bridge)?;
		request.decoded_source.verify(&decoded, inputs::MAX_INPUT)?;
		let model = unique_json(&decoded)?;
		// Source authentication protects all non-network fields. The edit snapshot
		// additionally protects w1/b1, so these are deliberately distinct hash domains.
		let mut physics_and_task = model.clone();
		physics_and_task
			.as_object_mut()
			.ok_or_else(|| anyhow!("checkpoint must be a JSON object"))?
			.remove("network");
		if digest(&serde_json::to_vec(&physics_and_task)?)
			!= source.receipt().protected_fields_sha256
		{
			bail!("checkpoint and bridge non-network semantics differ");
		}
		if codec::protected_hash(&model)? != snapshot.protected_fields_sha256 {
			bail!("bridge law and protected frontend differ from edit snapshot");
		}
		let program: EditProgram = serde_json::from_value(unique_json(&program)?)?;
		let hardware_key = digest(&serde_json::to_vec(
			&json!({"architecture":std::env::consts::ARCH,
			"os":std::env::consts::OS,"worker_binary_sha256":binary_sha,"arithmetic":forward::ARITHMETIC}),
		)?);
		Ok(Self {
			request,
			source,
			original: bridge,
			contract,
			program,
			authenticated,
			model,
			hardware_key,
		})
	}

	pub fn policy_traced(
		&self,
		bytes: &[u8],
		task: &Public,
		trace: Option<&Path>,
	) -> Result<Value> {
		let model = unique_json(&codec::decode(bytes)?)?;
		if codec::protected_hash(&model)? != codec::protected_hash(&self.model)? {
			bail!("full policy model changed the protected law or frontend");
		}
		if let Some(path) = trace {
			inputs::save_json(
				&path.with_extension("DAG_STARTED.json"),
				&json!({"model_sha256":digest(bytes),
				"attempted_full_native_graphs":1,"attempted_policy_dps":0,"actual_completed_policy_dps":null}),
			)?;
		}
		let graph = dag::build(&self.source, &model, task, &self.hardware_key)?;
		if let Some(path) = trace {
			inputs::save_json(
				&path.with_extension("DP_STARTED.json"),
				&json!({"model_sha256":digest(bytes),
				"completed_full_native_graphs":1,"attempted_policy_dps":1,"actual_completed_policy_dps":null}),
			)?;
		}
		let result = dag::evaluate(&graph, &codec::readout(&model)?)?;
		if let Some(path) = trace {
			inputs::save_json(
				&path.with_extension("DP_COMPLETED.json"),
				&json!({"model_sha256":digest(bytes),
				"attempted_policy_dps":1,"actual_completed_policy_dps":1}),
			)?;
		}
		if !result.utility.is_finite()
			|| !result.pdi_residual.is_finite()
			|| result.pdi_residual.abs() > 2e-10
			|| (result.terminal_mass - 1.0).abs() > 2e-10
		{
			bail!("full native task value conservation failed");
		}
		Ok(
			json!({"model_sha256":digest(bytes),"weights_sha256":codec::weights_hash(&model)?,
			"states":graph.states.len(),"graph_key":graph.key,"public":task,"policy":result,
			"full_native_graphs":1,"full_policy_dps":1,"arithmetic":forward::ARITHMETIC}),
		)
	}
}

pub struct NativeEvaluator<'a> {
	pub context: &'a Context,
	pub state: PathBuf,
	pub output: PathBuf,
	pub calls: usize,
	pub full_policy_dps: usize,
	pub cut: String,
	pub measurement: Option<Value>,
}

fn utility(record: &Value) -> Result<f64> {
	record["policy"]["utility"]
		.as_f64()
		.filter(|v| v.is_finite())
		.ok_or_else(|| anyhow!("finite utility missing"))
}

pub fn verdict(gain: f64, minimum_gain: f64, preservation: &[f64], max_loss: f64) -> bool {
	gain.is_finite()
		&& minimum_gain.is_finite()
		&& max_loss.is_finite()
		&& gain > minimum_gain
		&& preservation
			.iter()
			.all(|difference| difference.is_finite() && *difference >= -max_loss)
}

impl recovery::Evaluator for NativeEvaluator<'_> {
	fn evaluate(
		&mut self,
		intent: &recovery::Intent,
		candidate: &recovery::OwnerReceipt,
	) -> Result<recovery::Evaluation> {
		let measurement = crate::meter::Stamp::start()?;
		self.calls += 1;
		if self.calls != 1 {
			bail!("one evaluation per fresh research transaction");
		}
		let bytes = inputs::read(
			&self
				.state
				.join("weight-artifacts-v1")
				.join(&candidate.artifact_id)
				.join("model.safetensors"),
			inputs::MAX_INPUT,
		)?;
		if digest(&bytes) != intent.candidate_sha256 {
			bail!("evaluator candidate differs from immutable intent");
		}
		inputs::save_json(
			&self.output.with_extension("STARTED.json"),
			&json!({
			"candidate_sha256":candidate.content_sha256,"reserved_policy_dps":2*(1+self.context.request.policy.preservation.len()),
			"attempted_policy_dps":0,"completed_policy_dps":0}),
		)?;
		crate::cut(
			self.output
				.parent()
				.ok_or_else(|| anyhow!("evaluator root missing"))?,
			&self.cut,
			"evaluation_started",
		)?;
		let mut records = Vec::new();
		let tasks = std::iter::once(&self.context.request.policy.primary)
			.chain(&self.context.request.policy.preservation);
		let root = self
			.output
			.parent()
			.ok_or_else(|| anyhow!("evaluator root missing"))?;
		for (index, task) in tasks.enumerate() {
			let baseline = self.context.policy_traced(
				&self.context.original,
				task,
				Some(&root.join(format!("TASK_{index:02}_BASELINE"))),
			)?;
			self.full_policy_dps += 1;
			crate::cut(
				self.output
					.parent()
					.ok_or_else(|| anyhow!("evaluator root missing"))?,
				&self.cut,
				"baseline_complete",
			)?;
			let edited = self.context.policy_traced(
				&bytes,
				task,
				Some(&root.join(format!("TASK_{index:02}_CANDIDATE"))),
			)?;
			self.full_policy_dps += 1;
			let gain = utility(&edited)? - utility(&baseline)?;
			let detailed =
				serde_json::to_vec(&json!({"baseline":baseline,"candidate":edited,"gain":gain}))?;
			if detailed.len() > hepta_semantic_source_adapter_study::MAX_JSON_BYTES {
				bail!("bounded per-task evaluation record exceeded");
			}
			let filename = format!("TASK_{index:02}.json");
			inputs::save(&root.join(&filename), &detailed)?;
			records.push(
				json!({"filename":filename,"sha256":digest(&detailed),"bytes":detailed.len(),"gain":gain}),
			);
		}
		let gain = records[0]["gain"]
			.as_f64()
			.ok_or_else(|| anyhow!("primary gain missing"))?;
		let preservation = records[1..]
			.iter()
			.map(|v| {
				v["gain"]
					.as_f64()
					.ok_or_else(|| anyhow!("preservation gain missing"))
			})
			.collect::<Result<Vec<_>>>()?;
		let passed = verdict(
			gain,
			self.context.request.policy.minimum_gain,
			&preservation,
			self.context.request.policy.maximum_preservation_loss,
		);
		let result = json!({"schema":"hepta.weight-lifecycle-evaluation.v1","candidate_sha256":intent.candidate_sha256,
			"source_sha256":intent.source_sha256,"law_sha256":intent.law_sha256,"task_sha256":intent.task_sha256,
			"evaluator_sha256":intent.evaluator_sha256,"passed":passed,"primary_gain":gain,
			"policy":self.context.request.policy,"tasks":records,"full_native_graphs":self.full_policy_dps,
			"full_policy_dps":self.full_policy_dps,"eligible_for_production_adoption":false,
			"scope":"complete native evaluation of predeclared exposed research tasks"});
		let bytes = serde_json::to_vec(&result)?;
		inputs::save(&self.output, &bytes)?;
		self.measurement = Some(measurement.finish("complete_native_evaluation")?);
		inputs::save_json(
			&self.output.with_extension("METRICS.json"),
			self.measurement
				.as_ref()
				.ok_or_else(|| anyhow!("evaluation measurement missing"))?,
		)?;
		Ok(recovery::Evaluation {
			candidate_sha256: intent.candidate_sha256.clone(),
			task_sha256: intent.task_sha256.clone(),
			law_sha256: intent.law_sha256.clone(),
			evaluator_sha256: intent.evaluator_sha256.clone(),
			passed,
			result_sha256: digest(&bytes),
		})
	}
}

pub fn verify_retained_evaluation(root: &Path, record: &recovery::Record) -> Result<()> {
	if let Some(evaluation) = &record.evaluation {
		let bytes = inputs::read(&root.join("EVALUATION.json"), inputs::MAX_INPUT)?;
		if digest(&bytes) != evaluation.result_sha256 {
			bail!("retained evaluator result is missing or changed");
		}
		let result = unique_json(&bytes)?;
		if result["candidate_sha256"] != evaluation.candidate_sha256
			|| result["passed"] != evaluation.passed
			|| result["task_sha256"] != evaluation.task_sha256
			|| result["law_sha256"] != evaluation.law_sha256
			|| result["evaluator_sha256"] != evaluation.evaluator_sha256
		{
			bail!("retained evaluation does not match journal binding");
		}
		let tasks = result["tasks"]
			.as_array()
			.ok_or_else(|| anyhow!("task evidence missing"))?;
		if tasks.is_empty() || tasks.len() > 9 {
			bail!("task evidence count differs");
		}
		for (index, task) in tasks.iter().enumerate() {
			let name = format!("TASK_{index:02}.json");
			if task["filename"] != name {
				bail!("task evidence filename differs");
			}
			let bytes = inputs::read(
				&root.join(name),
				hepta_semantic_source_adapter_study::MAX_JSON_BYTES,
			)?;
			if task["sha256"] != digest(&bytes) || task["bytes"] != bytes.len() as u64 {
				bail!("retained full task evidence is missing or changed");
			}
		}
	}
	Ok(())
}

/// The canonical journal still validates its own entire chain. This extra read
/// prevents a complete decision when its separately retained evaluation vanished.
pub fn verify_latest_evidence(root: &Path, intent: &recovery::Intent) -> Result<()> {
	let directory = root.join("journal").join(intent.id()?);
	if !directory.try_exists()? {
		return Ok(());
	}
	inputs::private_dir(&directory)?;
	let mut paths = Vec::new();
	for (count, entry) in std::fs::read_dir(directory)?.enumerate() {
		if count >= 48 {
			bail!("bounded journal evidence inventory exceeded");
		}
		let entry = entry?;
		if entry.file_name().to_string_lossy().starts_with("record-") {
			paths.push(entry.path());
		}
	}
	paths.sort();
	if let Some(path) = paths.last() {
		let record: recovery::Record =
			serde_json::from_value(unique_json(&inputs::read(path, 1024 * 1024)?)?)?;
		if record.intent != *intent {
			bail!("journal evidence intent differs");
		}
		verify_retained_evaluation(root, &record)?;
	}
	Ok(())
}
