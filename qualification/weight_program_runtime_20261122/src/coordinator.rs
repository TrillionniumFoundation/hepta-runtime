// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Typed handoff from authenticated compilation to the existing recovery owner.
//! This module never writes model files or maintains an active model pointer.

use crate::{
	edit::{self, EditProgram},
	planner,
	snapshot::{decode_f64, AuthenticatedSnapshot, MAX_INPUT_BYTES},
};
use anyhow::{bail, Result};
use hepta_semantic_source_adapter_study::digest;
use hepta_weight_recovery_study as recovery;
use serde::Serialize;
use serde_json::json;
use std::path::{Component, Path};

pub struct Preparation<'a> {
	pub authenticated: &'a AuthenticatedSnapshot,
	pub program: &'a EditProgram,
	pub source_bytes: &'a [u8],
	pub source_path: &'a Path,
	pub evaluator_source: &'a [u8],
}

/// Private fields and no Deserialize: serialized evidence is not an executable
/// authorization token. A new caller must authenticate and compile again.
#[derive(Serialize)]
pub struct PreparedEdit {
	schema: String,
	snapshot_sha256: String,
	program_sha256: String,
	semantic_receipt_binding_sha256: String,
	intent: recovery::Intent,
	scope: String,
}
impl PreparedEdit {
	pub fn intent(&self) -> &recovery::Intent {
		&self.intent
	}
	pub fn transaction_id(&self) -> Result<String> {
		self.intent.id()
	}
}

pub fn prepare(request: Preparation<'_>) -> Result<PreparedEdit> {
	let snapshot = request.authenticated.snapshot();
	if request.source_bytes.len() > MAX_INPUT_BYTES
		|| digest(request.source_bytes) != snapshot.source_sha256
		|| request.evaluator_source.is_empty()
		|| request.evaluator_source.len() > MAX_INPUT_BYTES
		|| !request.source_path.is_absolute()
		|| request
			.source_path
			.components()
			.any(|c| matches!(c, Component::ParentDir | Component::CurDir))
	{
		bail!("exact source bytes, explicit absolute owner path and bounded evaluator source required");
	}
	let source_path = request
		.source_path
		.to_str()
		.ok_or_else(|| anyhow::anyhow!("UTF-8 owner path required"))?;
	let compiled = edit::compile(request.authenticated, request.program)?;
	if compiled.edits().is_empty() {
		bail!("empty edit must remain KEEP without artifact publication");
	}
	// Authentication has already checked the complete bridge layout. Recheck all
	// actual old bytes while deriving the entire candidate commitment in memory.
	let offset = 8 + usize::try_from(u64::from_le_bytes(request.source_bytes[..8].try_into()?))?;
	let mut candidate = request.source_bytes.to_vec();
	for e in compiled.edits() {
		let at = offset + 8 * e.index;
		let old = decode_f64(&e.expected_hex)?.to_le_bytes();
		if candidate.get(at..at + 8) != Some(old.as_slice()) {
			bail!("compiled expected bytes differ from actual source");
		}
		candidate[at..at + 8].copy_from_slice(&decode_f64(&e.replacement_hex)?.to_le_bytes());
	}
	let owner_request = json!({"path":source_path,"expected_sha256":snapshot.source_sha256,
		"tensor_name":snapshot.tensor_name,"edits":compiled.edits()});
	let intent = recovery::Intent {
		schema: "hepta.weight.recovery-intent.v1".into(),
		source_sha256: snapshot.source_sha256.clone(),
		candidate_sha256: digest(&candidate),
		law_sha256: snapshot.law_sha256.clone(),
		task_sha256: snapshot.evaluation_contract_sha256.clone(),
		evaluator_sha256: digest(request.evaluator_source),
		owner_request_sha256: digest(&serde_json::to_vec(&owner_request)?),
		owner_request,
	};
	intent.validate()?;
	Ok(PreparedEdit { schema:"hepta.prepared-research-edit.v1".into(),
		snapshot_sha256:snapshot.identity()?,program_sha256:compiled.program_sha256().into(),
		semantic_receipt_binding_sha256:snapshot.semantic_receipt_binding_sha256.clone(),intent,
		scope:"research-only typed handoff; owner enforces filesystem permissions and exact bytes; evaluator independently establishes task value; no production pointer adoption".into() })
}

#[derive(Serialize)]
pub struct PlannedEdit {
	pub plan: planner::Plan,
	pub prepared: PreparedEdit,
}

/// A plan is recomputed, not accepted as a caller-supplied self-hashed result.
/// Probe/train/stop choices must return to the agent instead of publishing an edit.
pub fn prepare_selected_analytic(
	request: Preparation<'_>,
	law: &planner::FiniteLaw,
	budget: planner::Budget,
	action_id: &str,
) -> Result<PlannedEdit> {
	let plan = planner::solve(law, budget, None)?;
	match &plan.first_choice {
		planner::Choice::Execute { action, id } if id == action_id
			&& law.states[law.initial_state].actions[*action].kind == planner::ActionKind::AnalyticEdit => {},
		_ => bail!("NDU did not choose the bound analytic action; return to probe/train/KEEP/stop controller"),
	}
	Ok(PlannedEdit {
		plan,
		prepared: prepare(request)?,
	})
}

pub fn execute_research<
	O: recovery::ArtifactOwner,
	E: recovery::Evaluator,
	C: recovery::Checkpoint,
>(
	prepared: &PreparedEdit,
	journal: &Path,
	owner: &mut O,
	evaluator: &mut E,
	checkpoint: &mut C,
) -> Result<recovery::Record> {
	recovery::execute(
		journal,
		prepared.intent.clone(),
		owner,
		evaluator,
		checkpoint,
	)
}

pub fn recover_research<O: recovery::ArtifactOwner, C: recovery::Checkpoint>(
	prepared: &PreparedEdit,
	journal: &Path,
	owner: &mut O,
	checkpoint: &mut C,
) -> Result<recovery::Record> {
	recovery::recover(journal, &prepared.intent, owner, checkpoint)
}
