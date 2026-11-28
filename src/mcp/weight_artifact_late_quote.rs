// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! A closed semantic task-graph program inside the existing retained cohort owner.
//! Its artifacts contain weights and function capsules atomically. No production route,
//! new lifecycle registry, source-path authority or generic graph-edit permission is added.

use super::*;
use crate::mcp::{
	rea_files,
	rea_model::session::weight::late_quote::{Authority, Input},
	runtime, weight_smallhcsn as model,
};
use anyhow::ensure;

#[path = "weight_artifact_smallhcsn_clock.rs"]
mod clock;
#[path = "weight_artifact_late_quote_compile.rs"]
mod compiler;
#[path = "weight_artifact_late_quote_evaluation.rs"]
mod evaluation;
#[path = "weight_artifact_late_quote_execution.rs"]
mod execution;
#[path = "weight_artifact_late_quote_inverse.rs"]
mod inverse;
#[path = "weight_artifact_late_quote_journal.rs"]
mod journal;

#[cfg(all(test, target_os = "linux"))]
#[path = "weight_artifact_late_quote_crash_tests.rs"]
mod crash_tests;
#[cfg(all(test, target_os = "linux"))]
#[path = "weight_artifact_late_quote_tests.rs"]
mod tests;

const ATTEMPT_SECONDS: u64 = 60;
const PHASE_SECONDS: u64 = 20;
const MAX_FIXED_ARTIFACT_BYTES: u64 = 131072;
const MAX_RAW_BYTES: usize = 65536;
const RECORD_BYTES: u64 = 16 * 1024;
const RESULT_BYTES: u64 = 48 * 1024;
const SCOPE: &str = "smallhcsn_late_quote_min_mark4_task_route_v1";

fn budget() -> Value {
	json!({"schema":"hepta.late-quote.attempt-budget.v1",
		"normal_attempt_seconds":ATTEMPT_SECONDS,"phase_seconds":PHASE_SECONDS,
		"phase_forward_caps":{"parent":3,"candidate":3,"restored":2},
		"maximum_full_model_forward_calls":8,"maximum_phase_reservations":3,
		"partial_phase_replay":false,"crash_refunds":false,"recovery_restarts_window":false,
		"recovery_parent_or_candidate_forwards":0,"artifact_bytes":MAX_FIXED_ARTIFACT_BYTES,
		"profiles":2,"profile_bytes_each":49152,"raw_input_bytes_each":MAX_RAW_BYTES,
		"queries_per_batch":80,"choices":2,"ticks":6,"maximum_changed_words":4,
		"maximum_original_intent_bytes":MAX_MANIFEST_BYTES,"maximum_phase_record_bytes":RECORD_BYTES,
		"maximum_result_bytes":RESULT_BYTES,"response_bytes":60*1024,
		"same_boot_clock_required_for_new_forward":true,
		"phase_deadline_is_cooperative":true,"os_hard_realtime_guarantee":false})
}

fn implementation() -> String {
	digest(
		&[
			include_bytes!("weight_artifact_late_quote.rs").as_slice(),
			include_bytes!("weight_artifact_late_quote_compile.rs").as_slice(),
			include_bytes!("weight_artifact_late_quote_journal.rs").as_slice(),
			include_bytes!("weight_artifact_late_quote_evaluation.rs").as_slice(),
			include_bytes!("weight_artifact_late_quote_execution.rs").as_slice(),
			include_bytes!("weight_artifact_late_quote_inverse.rs").as_slice(),
			include_bytes!("weight_artifact_smallhcsn_clock.rs").as_slice(),
			include_bytes!("rea_model_session_late_quote.rs").as_slice(),
			include_bytes!("weight_artifact_cohort.rs").as_slice(),
			include_bytes!("weight_artifact.rs").as_slice(),
			include_bytes!("weight_tensor.rs").as_slice(),
			include_bytes!("weight_norm.rs").as_slice(),
		]
		.concat(),
	)
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Action {
	Keep,
	Sign,
	Abstain,
}

impl Action {
	fn name(self) -> &'static str {
		match self {
			Self::Keep => "keep",
			Self::Sign => "sign",
			Self::Abstain => "abstain",
		}
	}
}

/// Evidence is deserializable; authority is not. Its digest binds both alternatives
/// before any forward or decision, and is the caller's recovery commitment.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Plan {
	schema: String,
	input: Input,
	authority: Value,
	roots: Vec<PathBuf>,
	state: PathBuf,
	transaction_implementation: String,
	cohort_implementation: String,
	evaluator_source: String,
	running_executable_sha256: String,
	budget: Value,
	semantic_task: Value,
	program: Value,
	parent_function: model::FunctionIdentity,
	keep_function: model::FunctionIdentity,
	sign_function: model::FunctionIdentity,
	keep_words: Vec<ExactElementEdit>,
	sign_words: Vec<ExactElementEdit>,
	sign_admissible: bool,
}

impl Plan {
	fn sha(&self) -> Result<String> {
		Ok(digest(&serde_json::to_vec(self)?))
	}
	fn id(&self) -> Result<String> {
		Ok(digest(&serde_json::to_vec(
			&json!({"schema":"hepta.late-quote.original-id.v1","plan_sha256":self.sha()?}),
		)?))
	}
	fn function(&self, action: Action) -> &model::FunctionIdentity {
		match action {
			Action::Keep => &self.keep_function,
			Action::Sign => &self.sign_function,
			Action::Abstain => &self.parent_function,
		}
	}
	fn words(&self, action: Action) -> &[ExactElementEdit] {
		match action {
			Action::Keep | Action::Abstain => &self.keep_words,
			Action::Sign => &self.sign_words,
		}
	}
	fn child_id(&self, action: Action) -> Result<String> {
		Ok(digest(&serde_json::to_vec(
			&json!({"schema":"hepta.late-quote.candidate-key.v1","original_id":self.id()?,"action":action}),
		)?))
	}
	fn function_binding(&self, action: Action, restored: bool) -> Result<Value> {
		let function = if restored {
			&self.parent_function
		} else {
			self.function(action)
		};
		let normal = model::FunctionIdentity {
			graph: model::ResearchGraph::Original,
			request_route: model::RequestRoute::OriginalFixedProfile,
			..function.clone()
		};
		Ok(
			json!({"schema":"hepta.late-quote.function-capsule.v1","fixed_scope":SCOPE,
			"original_journal_id":self.id()?,"original_plan_sha256":self.sha()?,"action":action,
			"role":if restored {"restored"} else {"candidate"},"function":function,
			"normal_route_function":normal,"parent_function":self.parent_function,
			"semantic_task":self.semantic_task,
			"running_executable_sha256":self.running_executable_sha256,
			"route_contract":{"late_request_graph":function.graph,"normal_request_graph":model::ResearchGraph::Original,
				"late_request_requires_checked_task":!restored,"same_weight_bytes_for_both_routes":true},
			"live_neuronal_state_captured":false,"shared_model_activated":false}),
		)
	}
	fn request(&self, action: Action) -> Result<PatchParams> {
		ensure!(
			action == Action::Keep || (action == Action::Sign && self.sign_admissible),
			"no cohort authority for an inadmissible or abstained action"
		);
		let data = json!({"late_profile":digest(self.input.profile_json.as_bytes()),
			"late_raw":digest(&decode_raw(&self.input.raw_input_hex)?),
			"normal_profile":digest(self.input.retention_profile_json.as_bytes()),
			"normal_raw":digest(&decode_raw(&self.input.retention_raw_input_hex)?),
			"semantic_task":self.semantic_task});
		Ok(PatchParams {
			request_id: self.child_id(action)?,
			path: self.authority["source_path"]
				.as_str()
				.context("saved source path")?
				.into(),
			expected_sha256: self.parent_function.artifact_sha256.clone(),
			identity: Identity {
				code_sha256: self.transaction_implementation.clone(),
				tensor_map_sha256: digest(&serde_json::to_vec(
					&json!({"tensor":"body.input_mark.weight","dtype":"F32","shape":[4,9],"indices":[7,16,25,34]}),
				)?),
				data_manifest_sha256: digest(&serde_json::to_vec(&data)?),
				objective_sha256: digest(&serde_json::to_vec(
					&json!({"goal":"late_quote_min_v1","minimum_accuracy_percent":self.input.minimum_accuracy_percent,"retention":"same_selected_weights_original_graph_all_output_bytes_equal"}),
				)?),
				dependency_manifest_sha256: digest(&serde_json::to_vec(
					&json!({"evaluator_source":self.evaluator_source,"program":self.program,"function":self.function(action)}),
				)?),
			},
			members: vec![Member {
				tensor_name: "body.input_mark.weight".into(),
				edits: self.words(action).to_vec(),
				maximum_update_l2_norm: self.input.maximum_update_l2_norm,
			}],
			maximum_update_l2_norm: self.input.maximum_update_l2_norm,
			training: TrainingContract::InferenceOnly,
		})
	}
}

struct Prepared {
	plan: Plan,
	parent: Vec<u8>,
	keep: PreparedCohort,
	sign: Option<PreparedCohort>,
	preparation_wall_seconds: f64,
}

fn decode_raw(text: &str) -> Result<Vec<u8>> {
	ensure!(
		text.len() <= MAX_RAW_BYTES * 2 && text.len().is_multiple_of(2) && text.is_ascii(),
		"bounded late-quote raw hex required"
	);
	let mut bytes = Vec::with_capacity(text.len() / 2);
	for word in text.as_bytes().chunks(16) {
		bytes.extend(weight_tensor::unhex(std::str::from_utf8(word)?)?);
	}
	Ok(bytes)
}

async fn capture(
	file: &mut tokio::fs::File,
	before: &std::fs::Metadata,
	expected: &str,
) -> Result<Vec<u8>> {
	ensure!(
		(10..=MAX_FIXED_ARTIFACT_BYTES).contains(&before.len()),
		"late-quote complete artifact byte cap"
	);
	file.seek(std::io::SeekFrom::Start(0)).await?;
	let mut bytes = vec![0; before.len() as usize];
	file.read_exact(&mut bytes).await?;
	unchanged(before, &file.metadata().await?)?;
	ensure!(
		digest(&bytes) == expected,
		"complete late-quote artifact bytes differ"
	);
	Ok(bytes)
}

async fn running_executable_sha256() -> Result<String> {
	#[cfg(target_os = "linux")]
	let mut file = tokio::fs::File::open("/proc/self/exe").await?;
	#[cfg(not(target_os = "linux"))]
	let mut file = tokio::fs::File::open(std::env::current_exe()?).await?;
	let before = file.metadata().await?;
	ensure!(
		before.is_file() && before.len() <= 512 * 1024 * 1024,
		"bounded current executable identity required"
	);
	let sha = file_hash(&mut file, before.len()).await?;
	unchanged(&before, &file.metadata().await?)?;
	Ok(sha)
}

pub(in crate::mcp) async fn compile(input: Input, authority: Authority) -> Result<Value> {
	prepare(input, authority).await
}

pub(in crate::mcp) async fn prepare(input: Input, authority: Authority) -> Result<Value> {
	let config = runtime::runtime_config()?;
	let prepared = tokio::time::timeout(
		Duration::from_secs(ATTEMPT_SECONDS),
		compiler::preflight(
			input,
			&authority,
			&config.controller_workspace_roots,
			&config.state_dir,
		),
	)
	.await
	.context("late-quote preparation deadline")??;
	let Some(p) = prepared else {
		return Ok(
			json!({"status":"ABSTAIN","reason":"all signed head contrasts are zero","compiler_forward_calls":0,"weight_writes":0}),
		);
	};
	Ok(
		json!({"schema":"hepta.late-quote.preparation.v1","journal_id":p.plan.id()?,"plan_sha256":p.plan.sha()?,
		"program":p.plan.program,"semantic_task":p.plan.semantic_task,"budget":p.plan.budget,
		"parent_function":p.plan.parent_function,"keep_function":p.plan.keep_function,"sign_function":p.plan.sign_function,
		"keep_artifact_id":p.keep.manifest.artifact_id,"sign_artifact_id":p.sign.as_ref().map(|c|&c.manifest.artifact_id),"sign_admissible":p.plan.sign_admissible,
		"model_forward_calls":0,"optimizer_steps":0,"journal_written":false,"candidate_published":false,
		"source_admission_and_preparation_wall_seconds":p.preparation_wall_seconds,
		"compilation_label_reads":0,"production_eligible":false,"global_ndu_optimality_verified":false}),
	)
}

pub(in crate::mcp) async fn roundtrip(
	input: Input,
	id: String,
	authority: Authority,
	admission: runtime::effect_owner_fence::AdmissionPermit,
) -> Result<Value> {
	authority.authorize(&input)?;
	ensure!(
		crate::mcp::weight_config::valid_sha256(&id),
		"original late-quote journal digest required"
	);
	let config = runtime::runtime_config()?;
	let guards = owner_guards_from_admission(admission).await?;
	retained_transaction(
		guards,
		execution::roundtrip(
			input,
			id,
			authority,
			config.controller_workspace_roots.clone(),
			config.state_dir.clone(),
		),
	)
	.await
}

pub(in crate::mcp) async fn recover(
	id: String,
	expected_plan: String,
	authority: Authority,
	admission: runtime::effect_owner_fence::AdmissionPermit,
) -> Result<Value> {
	ensure!(
		crate::mcp::weight_config::valid_sha256(&id)
			&& crate::mcp::weight_config::valid_sha256(&expected_plan),
		"original journal and plan digests required"
	);
	let config = runtime::runtime_config()?;
	let guards = owner_guards_from_admission(admission).await?;
	retained_transaction(
		guards,
		execution::recover(
			id,
			expected_plan,
			authority,
			config.controller_workspace_roots.clone(),
			config.state_dir.clone(),
		),
	)
	.await
}
