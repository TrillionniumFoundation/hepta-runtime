// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Finite research gate and disposable byte-slot restoration, never production adoption.

use crate::session::NativeProgram;
use crate::source::VerifiedSource;
use anyhow::{bail, Result};
use hepta_semantic_source_adapter_study::{
    digest, unique_json, validate_sha256, SourcePin, MAX_JSON_BYTES,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceBound {
    pub resource: String,
    pub unit: String,
    pub lambda_utility_per_unit: Option<f64>,
    pub baseline_future_lower: Option<f64>,
    pub candidate_future_upper: Option<f64>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QualityMode {
    StrictImprovement,
    NonInferiority,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationContract {
    pub schema: String,
    pub program_sha256: String,
    pub checkpoint_sha256: String,
    pub workload_sha256: String,
    pub freeze_receipt_sha256: String,
    pub confirmation_receipt_sha256: String,
    pub freeze_sequence: u64,
    pub confirmation_sequence: u64,
    pub bound_kind: String,
    pub quality_mode: QualityMode,
    pub quality_threshold: f64,
    pub quality_delta_lower: Option<f64>,
    pub calibration_delta_upper: Option<f64>,
    pub calibration_budget: f64,
    pub horizon_calls: Option<u64>,
    pub resources: Vec<ResourceBound>,
}

#[derive(Clone, Debug, Serialize)]
pub struct GateDecision {
    action: String,
    reason: String,
    program_sha256: String,
    net_value_lower: Option<f64>,
    external_evidence_attested: bool,
    production_eligible: bool,
}

impl GateDecision {
    pub fn save_isolated_candidate(&self) -> bool {
        self.action == "SAVE_ISOLATED_CANDIDATE"
    }
    pub fn action(&self) -> &str {
        &self.action
    }
}

pub fn keep_unknown(program: &NativeProgram, reason: &str) -> GateDecision {
    GateDecision {
        action: "KEEP_ORIGINAL_AND_STOP".into(),
        reason: reason.into(),
        program_sha256: program.sha256().into(),
        net_value_lower: None,
        external_evidence_attested: false,
        production_eligible: false,
    }
}

/// The supplied pin must come from the reviewing evaluation owner, separately
/// from the candidate. This function checks its arithmetic and bindings; it does
/// not itself prove label independence, host attestation or chronological custody.
pub fn evaluate_contract(
    program: &NativeProgram,
    bytes: &[u8],
    reviewed_pin: &SourcePin,
) -> Result<GateDecision> {
    reviewed_pin.verify(bytes, MAX_JSON_BYTES)?;
    let contract: EvaluationContract = serde_json::from_value(unique_json(bytes)?)?;
    if contract.schema != "hepta.finite-continuation-evaluation.v1"
        || contract.program_sha256 != program.sha256()
        || contract.checkpoint_sha256 != program.checkpoint_sha256()
    {
        bail!("evaluation contract refers to a different candidate or source");
    }
    for hash in [
        &contract.workload_sha256,
        &contract.freeze_receipt_sha256,
        &contract.confirmation_receipt_sha256,
    ] {
        validate_sha256(hash)?;
    }
    if contract.confirmation_sequence <= contract.freeze_sequence
        || contract.freeze_receipt_sha256 == contract.confirmation_receipt_sha256
    {
        bail!("confirmation is not ordered after a distinct candidate freeze");
    }
    if !contract.quality_threshold.is_finite()
        || contract.quality_threshold < 0.0
        || !contract.calibration_budget.is_finite()
        || contract.calibration_budget < 0.0
        || contract.resources.len() > 16
    {
        bail!("invalid finite quality/resource contract");
    }
    if contract.bound_kind != "owner_pinned_future" {
        return Ok(keep_unknown(
            program,
            "empirical or unknown cost bounds do not establish future NDU value",
        ));
    }
    let (Some(quality), Some(calibration), Some(horizon)) = (
        contract.quality_delta_lower,
        contract.calibration_delta_upper,
        contract.horizon_calls,
    ) else {
        return Ok(keep_unknown(
            program,
            "quality, calibration or future horizon is unknown",
        ));
    };
    if !quality.is_finite() || !calibration.is_finite() || horizon > 1_000_000_000_000 {
        bail!("nonfinite or unbounded quality contract");
    }
    let quality_pass = match contract.quality_mode {
        QualityMode::StrictImprovement => quality > contract.quality_threshold,
        QualityMode::NonInferiority => quality >= -contract.quality_threshold,
    };
    if !quality_pass || calibration > contract.calibration_budget || horizon == 0 {
        return Ok(keep_unknown(
            program,
            "quality/calibration gate failed or remaining horizon is zero",
        ));
    }
    if contract.resources.is_empty() {
        return Ok(keep_unknown(
            program,
            "future resource valuation is unknown",
        ));
    }
    let mut resources = BTreeSet::new();
    let mut net = horizon as f64 * quality;
    for resource in &contract.resources {
        if resource.resource.is_empty()
            || resource.resource.len() > 64
            || resource.unit.is_empty()
            || resource.unit.len() > 64
            || !resources.insert(&resource.resource)
        {
            bail!("missing or duplicate resource coordinate");
        }
        let (Some(lambda), Some(baseline), Some(candidate)) = (
            resource.lambda_utility_per_unit,
            resource.baseline_future_lower,
            resource.candidate_future_upper,
        ) else {
            return Ok(keep_unknown(
                program,
                "future resource bounds or conversion rate is unknown",
            ));
        };
        if [lambda, baseline, candidate]
            .iter()
            .any(|value| !value.is_finite() || *value < 0.0)
        {
            bail!("invalid future resource bound");
        }
        net -= lambda * (candidate - baseline);
    }
    if !net.is_finite() {
        bail!("NDU arithmetic overflow");
    }
    if net <= 0.0 {
        return Ok(keep_unknown(
            program,
            "no strictly positive lower bound on net value",
        ));
    }
    Ok(GateDecision {
        action: "SAVE_ISOLATED_CANDIDATE".into(),
        reason: "bounded reviewed quality/cost contract passed for this finite candidate only"
            .into(),
        program_sha256: program.sha256().into(),
        net_value_lower: Some(net),
        external_evidence_attested: false,
        production_eligible: false,
    })
}

pub struct ResearchByteSlot {
    anchor: Vec<u8>,
    active: Vec<u8>,
    checkpoint_sha256: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct RestorationReceipt {
    pub anchor_sha256: String,
    pub staged_sha256: String,
    pub restored_sha256: String,
    pub original_bytes_exact: bool,
    pub isolated_candidate_saved: bool,
    pub checkpoint_file_written: bool,
    pub production_owner_invoked: bool,
}

pub struct ResearchRun<T> {
    pub execution: std::result::Result<T, String>,
    pub candidate: Option<Vec<u8>>,
    pub restoration: RestorationReceipt,
}

struct RollbackGuard<'a> {
    slot: &'a mut ResearchByteSlot,
}

impl Drop for RollbackGuard<'_> {
    fn drop(&mut self) {
        self.slot.active.clone_from(&self.slot.anchor);
    }
}

impl ResearchByteSlot {
    pub fn new(source: &VerifiedSource) -> Self {
        let bytes = source.checkpoint_bytes().to_vec();
        Self {
            anchor: bytes.clone(),
            active: bytes,
            checkpoint_sha256: source.receipt().compressed_sha256.clone(),
        }
    }
    pub fn active_bytes(&self) -> &[u8] {
        &self.active
    }
    pub fn run<T>(
        &mut self,
        program: &NativeProgram,
        decision: &GateDecision,
        execute: impl FnOnce() -> Result<T>,
    ) -> Result<ResearchRun<T>> {
        self.stage(program)?;
        let guard = RollbackGuard { slot: self };
        let execution = execute().map_err(|error| error.to_string());
        let (candidate, restoration) = guard.slot.finish(program, decision, execution.is_ok())?;
        Ok(ResearchRun {
            execution,
            candidate,
            restoration,
        })
    }
    /// Low-level manual staging. Use `run` for automatic restoration when an
    /// execution callback returns an error or unwinds. This method alone does
    /// not establish a rollback guard across a caller's subsequent operations.
    pub fn stage(&mut self, program: &NativeProgram) -> Result<()> {
        if self.active != self.anchor || digest(&self.anchor) != self.checkpoint_sha256 {
            bail!("old bytes differ from immutable research anchor");
        }
        if program.checkpoint_sha256() != self.checkpoint_sha256 {
            bail!("candidate uses another checkpoint");
        }
        self.active = program.bytes().to_vec();
        Ok(())
    }
    /// Finish a manually staged operation and restore its independent bytes.
    /// Automatic callback-error/panic-unwind recovery belongs to `run`, not to
    /// a caller's unguarded interval between `stage` and `finish`.
    pub fn finish(
        &mut self,
        program: &NativeProgram,
        decision: &GateDecision,
        execution_ok: bool,
    ) -> Result<(Option<Vec<u8>>, RestorationReceipt)> {
        let staged_sha256 = digest(&self.active);
        let valid_stage =
            self.active == program.bytes() && program.checkpoint_sha256() == self.checkpoint_sha256;
        let decision_matches = decision.program_sha256 == program.sha256();
        let save =
            valid_stage && decision_matches && execution_ok && decision.save_isolated_candidate();
        let candidate = if save {
            Some(self.active.clone())
        } else {
            None
        };
        // The independent byte slot is restored on success, rejection and failure.
        // No file containing the original checkpoint is ever opened for writing.
        self.active.clone_from(&self.anchor);
        if !valid_stage || !decision_matches {
            bail!("invalid staged program or evaluation binding; original bytes restored");
        }
        Ok((
            candidate,
            RestorationReceipt {
                anchor_sha256: self.checkpoint_sha256.clone(),
                staged_sha256,
                restored_sha256: digest(&self.active),
                original_bytes_exact: self.active == self.anchor,
                isolated_candidate_saved: save,
                checkpoint_file_written: false,
                production_owner_invoked: false,
            },
        ))
    }
}
