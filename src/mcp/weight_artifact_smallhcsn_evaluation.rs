// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Durably charged fixed-kernel phases. Interrupted reservations are never replayed.

use super::*;

pub(super) fn bounded_error(error: &anyhow::Error) -> String {
	error.to_string().chars().take(512).collect()
}

pub(super) async fn run(
	directory: &Path,
	saved: &journal::Saved,
	phase: journal::Phase,
	bound: model::BoundModel,
	raw: &[u8],
	whole_deadline: &model::Deadline,
) -> Result<Value> {
	ensure!(
		saved.evaluator == model::evaluator_identity(),
		"saved evaluator differs; exact inverse is allowed but a new model evaluation is not"
	);
	let inputs = model::inputs(raw)?;
	let phase_deadline = whole_deadline.capped(
		saved
			.remaining_window()
			.await?
			.min(Duration::from_secs(PHASE_SECONDS)),
	);
	phase_deadline.check()?;
	journal::charge(directory, saved, phase).await?;
	let started = std::time::Instant::now();
	let before_worker = async {
		phase_deadline.check()?;
		saved.remaining_window().await?;
		Ok::<_, anyhow::Error>(())
	}
	.await;
	let measured = if let Err(error) = before_worker {
		Err(error)
	} else {
		tokio::task::spawn_blocking(move || {
			let output = model::evaluate(&bound, &inputs, &phase_deadline)?;
			let bytes = output.bytes();
			ensure!(bytes.len() <= 14800, "fixed model output byte budget");
			ensure!(
				output.diagnostics.iter().all(|value| value.is_finite()),
				"nonfinite physical diagnostic"
			);
			Ok::<_, anyhow::Error>(json!({
				"queries":output.n,"correct":output.correct,"mse":output.mse,
				"physical_diagnostics":output.diagnostics,
				"physical_valid":output.diagnostics.iter().all(|value| *value <= 2e-9),
				"physical_tolerance":2e-9,"output_sha256":digest(&bytes),"output_bytes":bytes.len()
			}))
		})
		.await
		.context("fixed model worker failed after its nonrefundable charge")
		.and_then(|value| value)
	};
	let report = match measured {
		Ok(metrics) => json!({
			"schema":"hepta.smallhcsn.model-result.v1","original_request_id":saved.id(),
			"phase":phase.name(),"artifact_sha256":phase.source(saved),
			"raw_input_sha256":saved.input.plan.input_sha256,"evaluator_sha256":saved.evaluator,
			"model_completed":true,"metrics":metrics,"error":null,
			"observed_wall_milliseconds":started.elapsed().as_millis().min(u64::MAX as u128) as u64
		}),
		Err(error) => json!({
			"schema":"hepta.smallhcsn.model-result.v1","original_request_id":saved.id(),
			"phase":phase.name(),"artifact_sha256":phase.source(saved),
			"raw_input_sha256":saved.input.plan.input_sha256,"evaluator_sha256":saved.evaluator,
			"model_completed":false,"metrics":null,"error":bounded_error(&error),
			"observed_wall_milliseconds":started.elapsed().as_millis().min(u64::MAX as u128) as u64
		}),
	};
	journal::phase_result(directory, phase, &report).await?;
	Ok(report)
}

pub(super) async fn recorded(directory: &Path, phase: journal::Phase) -> Result<Value> {
	let name = format!("model-{}-result.json", phase.name());
	if journal::exists(directory, &name).await? {
		journal::read(directory, &name, 4096).await
	} else {
		Ok(Value::Null)
	}
}

pub(super) fn valid(value: &Value) -> bool {
	value["model_completed"] == true && value["metrics"]["physical_valid"] == true
}

pub(super) fn observed_gain(parent: &Value, candidate: &Value) -> Value {
	let values = (|| {
		if parent["model_completed"] != true
			|| candidate["model_completed"] != true
			|| parent["metrics"]["queries"] != candidate["metrics"]["queries"]
		{
			return None;
		}
		let before = parent["metrics"]["mse"].as_f64()?;
		let after = candidate["metrics"]["mse"].as_f64()?;
		let delta = candidate["metrics"]["correct"]
			.as_i64()?
			.checked_sub(parent["metrics"]["correct"].as_i64()?)?;
		let gain = before - after;
		if !gain.is_finite() {
			return None;
		}
		Some((gain, delta))
	})();
	match values {
		Some((gain, delta)) => json!({
			"observed_mse_gain":gain,"delta_correct":delta,
			"strict_improvement":gain > 0.0 && delta >= 0,
			"scope":"this_fixed_raw_input_batch_only_not_declared_future_utility",
			"declared_ndu_use_gain_verified":false
		}),
		None => json!({"observed_mse_gain":null,"delta_correct":null,"strict_improvement":false,
			"scope":"incomplete_or_invalid_comparable_model_results","declared_ndu_use_gain_verified":false}),
	}
}

pub(super) fn quality(parent: &Value, candidate: &Value, minimum_gain: f64) -> Result<bool> {
	if !valid(parent) || !valid(candidate) {
		return Ok(false);
	}
	let p = &parent["metrics"];
	let c = &candidate["metrics"];
	let parent_mse = p["mse"].as_f64().context("recorded parent MSE")?;
	let candidate_mse = c["mse"].as_f64().context("recorded candidate MSE")?;
	let parent_correct = p["correct"].as_u64().context("recorded parent count")?;
	let candidate_correct = c["correct"].as_u64().context("recorded candidate count")?;
	Ok(parent_mse.is_finite()
		&& candidate_mse.is_finite()
		&& p["queries"] == c["queries"]
		&& parent_mse - candidate_mse >= minimum_gain
		&& candidate_correct >= parent_correct)
}
