// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Admission of byte-bound evaluator records; no evaluator or independence proof.

use crate::{Binding, Intent};
use anyhow::{bail, Result};
use hepta_continuation_runtime_study::source::{ARITHMETIC_SHA256, TASK_SHA256};
use hepta_semantic_source_adapter_study::{validate_sha256, SourcePin};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Role {
	ExposedTrainGeneration,
	ExposedTrainSelection,
	ExposedTrainAudit,
	SealedOwnLawConfirmation,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Dataset {
	pub role: Role,
	pub full_state_manifest_sha256: String,
	pub finalist_seal_sha256: Option<String>,
	pub postfreeze_sample_seal_sha256: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Contract {
	pub candidate_id: String,
	pub row_mask: u8,
	pub binding: Binding,
	pub protocol_sha256: String,
	pub producer_sha256: String,
	pub evaluator_sha256: String,
	pub evidence_pin: SourcePin,
	pub dataset: Dataset,
	pub maximum_work_units: u64,
	pub maximum_cpu_seconds: f64,
	pub owner_revision: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
	pub schema: String,
	pub candidate_id: String,
	pub readout_sha256: String,
	pub binding: Binding,
	pub protocol_sha256: String,
	pub evaluator_sha256: String,
	pub task_sha256: String,
	pub arithmetic_sha256: String,
	pub target: String,
	pub metric: String,
	pub role: Role,
	pub dataset: Dataset,
	pub resource_receipt_sha256: String,
	pub work_units: u64,
	pub cpu_seconds: f64,
	pub complete: bool,
	pub original_value: f64,
	pub candidate_value: f64,
}

impl Contract {
	pub fn check_intent(&self, intent: &Intent) -> Result<()> {
		for hash in [
			&self.protocol_sha256,
			&self.producer_sha256,
			&self.evaluator_sha256,
			&self.dataset.full_state_manifest_sha256,
		] {
			validate_sha256(hash)?;
		}
		if self.candidate_id.is_empty()
			|| self.candidate_id.len() > 128
			|| intent.candidate_id != self.candidate_id
			|| intent.binding != self.binding
			|| intent.row_mask != self.row_mask
			|| intent.protocol_sha256 != self.protocol_sha256
			|| intent.producer_sha256 != self.producer_sha256
		{
			bail!("intent differs from external reviewed contract");
		}
		match (
			&self.dataset.finalist_seal_sha256,
			&self.dataset.postfreeze_sample_seal_sha256,
		) {
			(Some(a), Some(b)) if self.dataset.role == Role::SealedOwnLawConfirmation && a != b => {
				validate_sha256(a)?;
				validate_sha256(b)?;
			}
			(None, None) if self.dataset.role != Role::SealedOwnLawConfirmation => {}
			_ => {
				bail!("role requires distinct finalist/sample seals; exposed TRAIN is not holdout")
			}
		}
		Ok(())
	}
	pub fn check_evidence(&self, intent: &Intent, evidence: &Evidence) -> Result<()> {
		validate_sha256(&evidence.resource_receipt_sha256)?;
		if evidence.schema != "hepta.own-law-evaluator-record.v1"
			|| evidence.candidate_id != self.candidate_id
			|| evidence.binding != self.binding
			|| evidence.readout_sha256 != intent.expected_readout_sha256
			|| evidence.protocol_sha256 != self.protocol_sha256
			|| evidence.evaluator_sha256 != self.evaluator_sha256
			|| evidence.task_sha256 != TASK_SHA256
			|| evidence.arithmetic_sha256 != ARITHMETIC_SHA256
			|| evidence.target != "fixed_deadline6_binary_endpoint"
			|| evidence.metric != "full_state_own_law_dag_expected_task_utility"
			|| evidence.role != self.dataset.role
			|| evidence.dataset != self.dataset
			|| !evidence.complete
		{
			bail!("typed evaluator identity, complete-state role or fixed target mismatch");
		}
		if self.maximum_work_units == 0
			|| evidence.work_units == 0
			|| evidence.work_units > self.maximum_work_units
			|| !self.maximum_cpu_seconds.is_finite()
			|| self.maximum_cpu_seconds <= 0.0
			|| !evidence.cpu_seconds.is_finite()
			|| evidence.cpu_seconds < 0.0
			|| evidence.cpu_seconds > self.maximum_cpu_seconds
			|| !evidence.original_value.is_finite()
			|| !evidence.candidate_value.is_finite()
			|| !(evidence.candidate_value - evidence.original_value).is_finite()
		{
			bail!("evaluation is incomplete, nonfinite or over the reviewed resource budget");
		}
		Ok(())
	}
}
