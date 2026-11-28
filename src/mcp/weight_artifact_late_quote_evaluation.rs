// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Full F32 forwards with explicit graph and route identities. One durable phase
//! charge covers a bounded group; a crash never permits replay of a missing suffix.

use super::*;
use journal::{Decision, Phase, Saved};

pub(super) fn bounded_error(error: &anyhow::Error) -> String {
	error.to_string().chars().take(512).collect()
}

#[derive(Clone)]
struct Job {
	name: &'static str,
	function: model::FunctionIdentity,
	profile: String,
	raw: Vec<u8>,
}

fn jobs(saved: &Saved, phase: Phase, decision: Option<&Decision>) -> Result<Vec<Job>> {
	let plan = &saved.plan;
	let late = decode_raw(&plan.input.raw_input_hex)?;
	let normal = decode_raw(&plan.input.retention_raw_input_hex)?;
	let job = |name, function, late_data| Job {
		name,
		function,
		profile: if late_data {
			plan.input.profile_json.clone()
		} else {
			plan.input.retention_profile_json.clone()
		},
		raw: if late_data {
			late.clone()
		} else {
			normal.clone()
		},
	};
	Ok(match phase {
		Phase::Parent => vec![
			job("original_late", plan.parent_function.clone(), true),
			job("original_normal", plan.parent_function.clone(), false),
			job("bridge_keep", plan.keep_function.clone(), true),
		],
		Phase::Candidate => {
			let decision =
				decision.context("candidate group requires its original one-shot decision")?;
			ensure!(
				decision.action != Action::Abstain,
				"ABSTAIN has no candidate forwards or publication"
			);
			let selected = plan.function(decision.action).clone();
			let mut jobs = Vec::new();
			if decision.action == Action::Sign {
				jobs.push(job("selected_late", selected.clone(), true));
			}
			jobs.push(job(
				"scoped_normal",
				model::FunctionIdentity {
					graph: model::ResearchGraph::Original,
					request_route: model::RequestRoute::OriginalFixedProfile,
					..selected.clone()
				},
				false,
			));
			jobs.push(job(
				"unconditional_normal",
				model::FunctionIdentity {
					request_route: model::RequestRoute::ResearchUnconditionalNegativeControl,
					..selected
				},
				false,
			));
			jobs
		}
		Phase::Restored => vec![
			job("restored_late", plan.parent_function.clone(), true),
			job("restored_normal", plan.parent_function.clone(), false),
		],
	})
}

fn metrics(output: &model::Output, input: &model::Inputs) -> Result<Value> {
	ensure!(
		output
			.features
			.iter()
			.chain(&output.heads)
			.chain(&output.scores)
			.all(|v| v.is_finite())
			&& output
				.diagnostics
				.iter()
				.all(|v| v.is_finite() && *v >= 0.0),
		"nonfinite or negative full-model result"
	);
	let bytes = output.bytes();
	ensure!(bytes.len() <= 14800, "fixed model output byte cap");
	let mut cross_entropy = 0.0;
	let mut correct_mask = Vec::with_capacity(input.queries());
	for (q, label) in input.labels().iter().enumerate() {
		let margin = f64::from(output.scores[q * 2 + 1]) - f64::from(output.scores[q * 2]);
		cross_entropy +=
			margin.max(0.0) + (-margin.abs()).exp().ln_1p() - f64::from(*label) * margin;
		correct_mask.push(u8::from(output.scores[q * 2 + 1] > output.scores[q * 2]) == *label);
	}
	cross_entropy /= input.queries() as f64;
	ensure!(
		cross_entropy.is_finite() && output.mse.is_finite(),
		"finite model objective required"
	);
	Ok(
		json!({"queries":output.n,"correct":output.correct,"correct_mask":correct_mask,"cross_entropy":cross_entropy,"mse":output.mse,
		"physical_diagnostics":output.diagnostics,"physical_valid":output.diagnostics.iter().all(|v|*v<=2e-9),"physical_tolerance":2e-9,
		"output_sha256":digest(&bytes),"output_bytes":bytes.len()}),
	)
}

pub(super) async fn run(
	directory: &Path,
	saved: &Saved,
	phase: Phase,
	decision: Option<&Decision>,
	parent: Vec<u8>,
	actual: Vec<u8>,
	whole_deadline: &model::Deadline,
) -> Result<Value> {
	ensure!(
		saved.plan.evaluator_source == model::evaluator_identity()
			&& saved.plan.transaction_implementation == implementation()
			&& saved.plan.running_executable_sha256 == running_executable_sha256().await?,
		"saved source or executable differs; inverse only, no new model work"
	);
	let jobs = jobs(saved, phase, decision)?;
	ensure!(jobs.len() <= phase.cap(), "fixed phase call cap");
	let raw = decode_raw(&saved.plan.input.raw_input_hex)?;
	let input = model::inputs(&raw)?;
	let task = model::LateQuoteMinV1::check(&input)?;
	task.validate_targets(&input)?;
	let phase_deadline = whole_deadline.capped(
		saved
			.remaining()
			.await?
			.min(Duration::from_secs(PHASE_SECONDS)),
	);
	phase_deadline.check()?;
	journal::charge(directory, saved, phase).await?;
	let started = std::time::Instant::now();
	let before_worker = async {
		phase_deadline.check()?;
		saved.remaining().await?;
		Ok::<_, anyhow::Error>(())
	}
	.await;
	let measured = if let Err(error) = before_worker {
		Err(error)
	} else {
		tokio::task::spawn_blocking(move || {
			let mut observations=Vec::new(); let mut error=None;
			for job in jobs {
				let observed=(||->Result<Value>{
					phase_deadline.check()?;
					let bytes=if phase==Phase::Parent {&parent}else{&actual};
					ensure!(digest(bytes)==job.function.artifact_sha256,"actual artifact differs from function capsule");
					let bound=model::bind(job.profile.as_bytes(),&parent,&job.raw)?;
					let bound=model::bind_research_mark_candidate(bound,&parent,bytes)?;
					let input=model::inputs(&job.raw)?;
					if job.function.request_route==model::RequestRoute::CheckedLateQuoteMinV1 {model::LateQuoteMinV1::check(&input)?;}
					let output=if job.function.graph==model::ResearchGraph::Original {model::evaluate(&bound,&input,&phase_deadline)?}
						else {model::evaluate_research_traced(&bound,&input,&phase_deadline,job.function.graph)?.0};
					Ok(json!({"name":job.name,"function":job.function,"profile_sha256":digest(job.profile.as_bytes()),"raw_input_sha256":digest(&job.raw),"metrics":metrics(&output,&input)?}))
				})();
				match observed {Ok(value)=>observations.push(value),Err(e)=>{error=Some(bounded_error(&e));break;}}
			}
			Ok::<_,anyhow::Error>((observations,error))
		}).await.context("charged full-model group worker failed").and_then(|x|x)
	};
	let (observations, error) = match measured {
		Ok(v) => v,
		Err(e) => (Vec::new(), Some(bounded_error(&e))),
	};
	let result = json!({"schema":"hepta.late-quote.phase-result.v1","journal_id":saved.journal_id,"plan_sha256":saved.plan_sha256,"attempt_sha256":saved.sha()?,"phase":phase,
		"completed":error.is_none(),"observations":observations,"error":error,"observed_wall_milliseconds":started.elapsed().as_millis().min(u64::MAX as u128) as u64,
		"optimizer_steps":0,"partial_group_replay_allowed":false});
	journal::result(directory, saved, phase, decision, &result).await?;
	Ok(result)
}

pub(super) fn validate(
	saved: &Saved,
	phase: Phase,
	decision: Option<&Decision>,
	value: &Value,
) -> Result<()> {
	let expected = jobs(saved, phase, decision)?;
	let observations = value["observations"]
		.as_array()
		.context("fixed phase observation array")?;
	ensure!(
		value["schema"] == "hepta.late-quote.phase-result.v1"
			&& value["journal_id"] == saved.journal_id
			&& value["plan_sha256"] == saved.plan_sha256
			&& value["attempt_sha256"] == saved.sha()?
			&& value["phase"] == serde_json::to_value(phase)?
			&& value["observed_wall_milliseconds"].as_u64().is_some()
			&& value["optimizer_steps"] == 0
			&& value["partial_group_replay_allowed"] == false
			&& observations.len() <= expected.len(),
		"saved grouped phase identity or cap differs"
	);
	if value["completed"] == true {
		ensure!(
			observations.len() == expected.len() && value["error"].is_null(),
			"completed group lacks exact forwards"
		);
	} else {
		ensure!(
			value["completed"] == false
				&& value["error"]
					.as_str()
					.is_some_and(|s| s.chars().count() <= 512),
			"failed group error contract"
		);
	}
	for (record, job) in observations.iter().zip(expected) {
		ensure!(
			record["name"] == job.name
				&& record["function"] == serde_json::to_value(&job.function)?
				&& record["profile_sha256"] == digest(job.profile.as_bytes())
				&& record["raw_input_sha256"] == digest(&job.raw),
			"saved observation graph, route, task or stage differs"
		);
		let metrics = &record["metrics"];
		let n = metrics["queries"].as_u64().context("queries")?;
		let correct = metrics["correct"].as_u64().context("correct")?;
		let mask = metrics["correct_mask"].as_array().context("correct mask")?;
		let diagnostics = metrics["physical_diagnostics"]
			.as_array()
			.context("physical diagnostics")?;
		ensure!(
			(1..=80).contains(&n)
				&& n as usize == model::inputs(&job.raw)?.queries()
				&& correct <= n
				&& mask.len() == n as usize
				&& mask.iter().all(Value::is_boolean)
				&& mask.iter().filter(|v| v.as_bool() == Some(true)).count() as u64 == correct
				&& metrics["cross_entropy"]
					.as_f64()
					.is_some_and(|v| v.is_finite() && v >= 0.0)
				&& metrics["mse"]
					.as_f64()
					.is_some_and(|v| v.is_finite() && v >= 0.0)
				&& diagnostics.len() == 6
				&& diagnostics
					.iter()
					.all(|v| v.as_f64().is_some_and(|v| v.is_finite() && v >= 0.0))
				&& metrics["physical_tolerance"] == json!(2e-9)
				&& metrics["physical_valid"]
					== json!(diagnostics
						.iter()
						.all(|v| v.as_f64().is_some_and(|v| v <= 2e-9)))
				&& metrics["output_bytes"] == json!(76 + n * 184)
				&& metrics["output_sha256"]
					.as_str()
					.is_some_and(crate::mcp::weight_config::valid_sha256),
			"saved model metrics exceed fixed numerical contract"
		);
	}
	Ok(())
}

pub(super) fn valid(value: &Value) -> bool {
	value["completed"] == true
		&& value["observations"].as_array().is_some_and(|rows| {
			!rows.is_empty()
				&& rows
					.iter()
					.all(|row| row["metrics"]["physical_valid"] == true)
		})
}

pub(super) fn no_lost_correct_or_ce(parent: &Value, candidate: &Value) -> bool {
	let p = &parent["metrics"];
	let c = &candidate["metrics"];
	match (
		p["correct_mask"].as_array(),
		c["correct_mask"].as_array(),
		p["cross_entropy"].as_f64(),
		c["cross_entropy"].as_f64(),
	) {
		(Some(pm), Some(cm), Some(pc), Some(cc)) => {
			pm.len() == cm.len()
				&& pm
					.iter()
					.zip(cm)
					.all(|(a, b)| a.as_bool() != Some(true) || b.as_bool() == Some(true))
				&& cc <= pc + 1e-6
		}
		_ => false,
	}
}
