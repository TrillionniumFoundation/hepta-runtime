// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! One-worker composition of causal semantic replay and exact witness checking.
//!
//! The caller selects comparisons and nonnegative multipliers, never features,
//! states, scores, legal masks or teacher targets. This single-schedule profile
//! binds locally executed semantics without authenticating external sources.

use anyhow::{ensure, Context, Result};
use rmcp::schemars;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::time::{Duration, Instant};

use super::weight_certificate::{self, CertificateParams, CertificateRow, CertificateSource};
use super::weight_semantic::{self, core, SemanticReplayParams};

const PROFILE: &str = "hepta.weight-semantic-certificate.single-schedule.v1";
const MAX_WITNESSES: usize = 256;
const MAX_REQUEST_BYTES: usize = 3 * 1024 * 1024;
const SEMANTICS: &str = "binary64_rne_gradual_separate_products_sum49_v1";

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SemanticCertificateParams {
	/// The existing exact-byte envelope for one checkpoint, public schedule and
	/// 1..128 causal traces. No hidden features or teacher scores are accepted.
	pub replay: SemanticReplayParams,
	/// SHA256 of this compiled weight_semantic_certificate.rs, not a caller program.
	pub expected_join_source_sha256: String,
	/// SHA256 of the compiled weight_semantic.rs admission, worker and result adapter.
	pub expected_semantic_adapter_source_sha256: String,
	/// SHA256 of the compiled weight_certificate.rs exact-checker boundary.
	pub expected_certificate_source_sha256: String,
	/// SHA256 of the compiled weight_certificate_exact.rs arithmetic implementation.
	pub expected_arithmetic_source_sha256: String,
	/// 1..256 distinct (source_row, competitor_action) pairs. Every replay trace
	/// must occur. The native first-maximum target is derived, never supplied.
	pub witnesses: Vec<SemanticWitness>,
}

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SemanticWitness {
	pub source_row: u32,
	/// WAIT=1, READ=2 or REPAIR=3; must be legal and differ from the native target.
	pub competitor_action: u8,
	/// One finite nonnegative binary64 value as exactly 16 lowercase hex digits,
	/// in little-endian storage order. Zero is permitted but proves no separation.
	pub multiplier_f64_le_hex: String,
}

fn hex(bytes: impl AsRef<[u8]>) -> String {
	bytes.as_ref().iter().map(|x| format!("{x:02x}")).collect()
}

fn sha(bytes: impl AsRef<[u8]>) -> String {
	hex(Sha256::digest(bytes.as_ref()))
}

fn deadline(end: Instant) -> Result<()> {
	ensure!(
		Instant::now() < end,
		"semantic certificate exceeded its 30-second outer result deadline"
	);
	Ok(())
}

struct Commitment {
	hash: Sha256,
	bytes: usize,
	end: Instant,
}

impl Write for Commitment {
	fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
		if data.len() > MAX_REQUEST_BYTES.saturating_sub(self.bytes) || Instant::now() >= self.end {
			return Err(std::io::Error::other(
				"semantic certificate canonical request byte/deadline budget exceeded",
			));
		}
		self.hash.update(data);
		self.bytes += data.len();
		Ok(data.len())
	}

	fn flush(&mut self) -> std::io::Result<()> {
		Ok(())
	}
}

fn admit(
	params: &SemanticCertificateParams,
	end: Instant,
) -> Result<(core::ReplayParams, String, usize)> {
	deadline(end)?;
	ensure!(
		(1..=MAX_WITNESSES).contains(&params.witnesses.len()),
		"semantic certificate requires 1..256 witness comparisons"
	);
	for (supplied, compiled, name) in [
		(
			&params.expected_join_source_sha256,
			include_bytes!("weight_semantic_certificate.rs").as_slice(),
			"join",
		),
		(
			&params.expected_semantic_adapter_source_sha256,
			include_bytes!("weight_semantic.rs").as_slice(),
			"semantic adapter",
		),
		(
			&params.expected_certificate_source_sha256,
			include_bytes!("weight_certificate.rs").as_slice(),
			"certificate",
		),
		(
			&params.expected_arithmetic_source_sha256,
			include_bytes!("weight_certificate_exact.rs").as_slice(),
			"arithmetic",
		),
	] {
		weight_certificate::bytes(supplied, 32)?;
		ensure!(
			*supplied == sha(compiled),
			"semantic certificate {name} source SHA256 mismatch"
		);
	}
	let request = weight_semantic::admit_request(&params.replay)?;
	ensure!(
		(1..=128).contains(&request.traces.len()),
		"semantic certificate requires 1..128 traces"
	);
	let traces: HashSet<_> = request
		.traces
		.iter()
		.map(|trace| trace.source_row)
		.collect();
	ensure!(
		traces.len() == request.traces.len(),
		"duplicate replay source row"
	);
	let mut pairs = HashSet::new();
	let mut covered = HashSet::new();
	for witness in &params.witnesses {
		ensure!(
			traces.contains(&witness.source_row),
			"witness source row is absent from replay traces"
		);
		ensure!(
			pairs.insert((witness.source_row, witness.competitor_action)),
			"duplicate source-row/competitor witness"
		);
		ensure!(
			(1..=3).contains(&witness.competitor_action),
			"witness competitor must be a continuation"
		);
		let bytes = weight_certificate::bytes(&witness.multiplier_f64_le_hex, 8)?;
		let multiplier = f64::from_le_bytes(bytes.as_slice().try_into()?);
		ensure!(
			multiplier.is_finite() && multiplier >= 0.,
			"witness multiplier must be finite and nonnegative"
		);
		covered.insert(witness.source_row);
	}
	ensure!(
		covered == traces,
		"witnesses must cover every replay source row"
	);
	let mut commitment = Commitment {
		hash: Sha256::new(),
		bytes: 0,
		end,
	};
	serde_json::to_writer(&mut commitment, params)
		.context("committing semantic certificate request")?;
	deadline(end)?;
	Ok((request, hex(commitment.hash.finalize()), commitment.bytes))
}

fn witness_digest(rows: &[CertificateRow]) -> Result<String> {
	let mut hash = Sha256::new();
	hash.update(b"hepta.weight.continuation-witness.v1\0");
	hash.update((rows.len() as u64).to_le_bytes());
	for row in rows {
		hash.update(row.source_row.to_le_bytes());
		hash.update(weight_certificate::bytes(&row.state_sha256, 32)?);
		hash.update(weight_certificate::bytes(&row.teacher_table_sha256, 32)?);
		hash.update(row.legal.map(u8::from));
		hash.update([row.target_action, row.competitor_action]);
		hash.update(weight_certificate::bytes(&row.multiplier_f64_le_hex, 8)?);
		hash.update(weight_certificate::bytes(&row.hidden_f64_le_hex, 49 * 8)?);
		hash.update(weight_certificate::bytes(&row.teacher_q_f64_le_hex, 6 * 8)?);
	}
	Ok(hex(hash.finalize()))
}

fn join(
	params: &SemanticCertificateParams,
	request: &core::ReplayParams,
	replay: &core::ReplayResult,
	request_sha256: &str,
	end: Instant,
) -> Result<CertificateParams> {
	ensure!(
		replay.checkpoint_sha256 == request.expected_checkpoint_sha256
			&& replay.public_sha256 == request.expected_public_sha256
			&& replay.implementation_sha256 == params.replay.expected_core_source_sha256
			&& replay.rows.len() == request.traces.len(),
		"native replay result identity differs from admitted request"
	);
	let mut rows = HashMap::new();
	let mut selected_teacher_rows = Vec::with_capacity(replay.rows.len());
	for row in &replay.rows {
		deadline(end)?;
		ensure!(
			rows.insert(row.source_row, row).is_none(),
			"native replay repeats source row"
		);
		let state_sha256 = sha(serde_json::to_vec(&(
			"hepta.native-replayed-state.v1",
			&replay.checkpoint_sha256,
			&replay.public_sha256,
			&replay.implementation_sha256,
			&params.replay.expected_target_contract_sha256,
			&row.state,
		))?);
		let teacher_q = hex(row
			.teacher_q
			.iter()
			.flat_map(|x| x.to_le_bytes())
			.collect::<Vec<_>>());
		selected_teacher_rows.push((
			row.source_row,
			state_sha256,
			teacher_q,
			row.legal,
			row.target_action,
		));
	}
	// This digest commits to selected reconstructed teacher rows, not a claim
	// that the entire cached Bellman table or an external table was captured.
	let teacher_table_sha256 = sha(serde_json::to_vec(&(
		"hepta.native-selected-teacher-rows.v1",
		&replay.checkpoint_sha256,
		&replay.public_sha256,
		&replay.implementation_sha256,
		&params.replay.expected_target_contract_sha256,
		&selected_teacher_rows,
	))?);
	let table: HashMap<_, _> = selected_teacher_rows
		.iter()
		.map(|row| (row.0, row))
		.collect();
	let mut generated = Vec::with_capacity(params.witnesses.len());
	for witness in &params.witnesses {
		deadline(end)?;
		let row = rows
			.get(&witness.source_row)
			.context("native replay omitted witness source row")?;
		let binding = table
			.get(&witness.source_row)
			.context("teacher row binding is absent")?;
		ensure!(
			(1..=3).contains(&row.target_action)
				&& (1..=3).contains(&witness.competitor_action)
				&& witness.competitor_action as usize != row.target_action
				&& row.legal[witness.competitor_action as usize],
			"native target and competitor must be distinct legal continuations"
		);
		generated.push(CertificateRow {
			source_row: row.source_row,
			state_sha256: binding.1.clone(),
			teacher_table_sha256: teacher_table_sha256.clone(),
			hidden_f64_le_hex: row.hidden_f64_le_hex.clone(),
			hidden_sha256: row.hidden_sha256.clone(),
			multiplier_f64_le_hex: witness.multiplier_f64_le_hex.clone(),
			teacher_q_f64_le_hex: binding.2.clone(),
			legal: row.legal,
			target_action: row.target_action as u8,
			competitor_action: witness.competitor_action,
		});
	}
	Ok(CertificateParams {
		semantics: SEMANTICS.into(),
		checkpoint_json: request.checkpoint_json.clone(),
		expected_checkpoint_sha256: request.expected_checkpoint_sha256.clone(),
		expected_witness_sha256: witness_digest(&generated)?,
		source: CertificateSource {
			fit_id: replay.fit,
			protocol_sha256: sha(PROFILE.as_bytes()),
			feature_source_sha256: replay.implementation_sha256.clone(),
			teacher_source_sha256: replay.implementation_sha256.clone(),
			original_witness_record_sha256: request_sha256.into(),
		},
		rows: generated,
	})
}

fn execute_until(params: &SemanticCertificateParams, end: Instant) -> Result<String> {
	let started = Instant::now();
	let (request, request_sha256, request_bytes) = admit(params, end)?;
	let replay =
		core::replay_until(&request, end).context("native semantic certificate replay failed")?;
	deadline(end)?;
	let certificate_params = join(params, &request, &replay, &request_sha256, end)?;
	let certificate = weight_certificate::solve_until(&certificate_params, end)?;
	ensure!(
		certificate["implementation_source_sha256"] == params.expected_certificate_source_sha256
			&& certificate["arithmetic_source_sha256"] == params.expected_arithmetic_source_sha256
			&& certificate["checkpoint_sha256"] == replay.checkpoint_sha256
			&& certificate["witness_sha256"] == certificate_params.expected_witness_sha256,
		"native certificate result identity differs from generated witness"
	);
	deadline(end)?;
	let result = weight_semantic::encode_result(&json!({
		"schema": "hepta.weight-semantic-certificate.result.v1", "profile": PROFILE,
		"request_sha256": request_sha256, "canonical_request_bytes": request_bytes,
		"replay_request_sha256": params.replay.expected_request_sha256,
		"join_source_sha256": params.expected_join_source_sha256,
		"semantic_adapter_source_sha256": params.expected_semantic_adapter_source_sha256,
		"core_source_sha256": replay.implementation_sha256,
		"target_contract_sha256": params.replay.expected_target_contract_sha256,
		"checkpoint_sha256": replay.checkpoint_sha256, "public_sha256": replay.public_sha256,
		"fit": replay.fit, "replayed_traces": replay.rows.len(),
		"generated_witness_rows": certificate_params.rows, "certificate": certificate,
		"witness_semantics_reexecuted_and_joined": true,
		"caller_hidden_q_state_mask_or_target_accepted": false,
		"maximum_concurrent_workers": 1, "worker_shared_with_semantic_replay": true,
		"outer_result_deadline_seconds": 30,
		"semantic_core_relative_cooperative_deadline_seconds": 30,
		"semantic_core_receives_outer_deadline": true,
		"whole_operation_deadline_is_hard_limit": false,
		"compiled_source_pins_identify_executable": false,
		"deadline_policy": "admission, semantic replay and exact checking retain the same outer cutoff; inner operations take the earlier outer/local cap; late serialized results are refused; this cooperative cutoff is not a hard process kill",
		"canonical_request_byte_budget": MAX_REQUEST_BYTES,
		"trace_budget": 128, "witness_row_budget": MAX_WITNESSES,
		"wall_seconds_before_serialization": started.elapsed().as_secs_f64(),
		"external_source_authenticated": false, "hardware_arithmetic_semantics_verified": false,
		"independent_holdout_verified": false, "task_value_improvement_qualified": false,
		"whole_network_impossibility_qualified": false, "production_eligible": false,
		"weights_modified": false, "gradient_steps": 0,
		"scope": "one supplied checkpoint and public schedule; selected causal traces; native first-maximum continuation ordering and the original coefficient ball; the nested checker reports its own supplied-row scope, while this enclosing operation executes and joins those rows; no external-source, interval, efficacy or deployment claim"
	}))?;
	deadline(end)?;
	Ok(result)
}

pub async fn verify(params: SemanticCertificateParams) -> Result<String> {
	weight_semantic::run_shared_worker(move || {
		execute_until(&params, Instant::now() + Duration::from_secs(30))
	})
	.await
}

#[cfg(test)]
#[path = "weight_semantic_certificate_tests.rs"]
pub(crate) mod tests;
