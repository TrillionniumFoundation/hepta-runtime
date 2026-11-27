// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Immutable fixed-profile records inside the original cohort journal.
//! Historical identity is checked using its saved implementation, never a new-source replay.

use super::*;

pub(super) fn wall_clock_milliseconds() -> Result<u64> {
	let millis = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.context("native attempt clock precedes UNIX epoch")?
		.as_millis();
	u64::try_from(millis).context("native attempt clock overflow")
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Saved {
	pub schema: String,
	pub input: Input,
	pub authority: Value,
	pub roots: Vec<PathBuf>,
	pub state: PathBuf,
	pub cohort_implementation: String,
	pub transaction_implementation: String,
	pub evaluator: String,
	pub budget: Value,
	pub created_unix_milliseconds: u64,
	pub expires_unix_milliseconds: u64,
	#[serde(default, skip_serializing_if = "Value::is_null")]
	pub proposal_evidence: Value,
	#[serde(default, skip_serializing_if = "Value::is_null")]
	pub preparation_computation: Value,
	#[serde(default, skip_serializing_if = "Value::is_null")]
	pub ndu_evidence: Value,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub native_boot_clock: Option<clock::Stamp>,
	pub manifest: CohortManifest,
}

impl Saved {
	pub(super) fn new(
		prepared: &Prepared,
		authority: &Authority,
		roots: &[PathBuf],
		state: &Path,
		created_unix_milliseconds: u64,
		native_boot_clock: clock::Stamp,
	) -> Result<Self> {
		Ok(Self {
			schema: "hepta.smallhcsn.original-attempt.v1".into(),
			input: prepared.input.clone(),
			authority: authority.binding()?,
			roots: roots.to_vec(),
			state: state.to_owned(),
			cohort_implementation: cohort_implementation(),
			transaction_implementation: implementation(),
			evaluator: model::evaluator_identity(),
			budget: budget(),
			created_unix_milliseconds,
			expires_unix_milliseconds: created_unix_milliseconds
				.checked_add(ATTEMPT_SECONDS * 1000)
				.context("original attempt clock overflow")?,
			manifest: prepared.cohort.manifest.clone(),
			proposal_evidence: prepared.proposal_evidence.clone(),
			preparation_computation: prepared.preparation_computation.clone(),
			ndu_evidence: ndu::seal(&prepared.ndu_evidence, &prepared.id)?,
			native_boot_clock: Some(native_boot_clock),
		})
	}

	pub(super) fn id(&self) -> &str {
		&self.manifest.request.request_id
	}

	pub(super) async fn remaining_window(&self) -> Result<Duration> {
		let original = self.native_boot_clock.as_ref()
			.context("legacy attempt has no original same-boot clock; inverse remains allowed without new model work")?;
		let observed = clock::sample().await?;
		let monotonic = original.remaining_at(&observed, ATTEMPT_SECONDS)?;
		let now = wall_clock_milliseconds()?;
		ensure!(now >= self.created_unix_milliseconds && now < self.expires_unix_milliseconds,
			"original model-attempt wall window is expired or moved backward; inverse remains allowed");
		Ok(monotonic.min(Duration::from_millis(self.expires_unix_milliseconds - now)))
	}

	pub(super) fn validate(
		&self,
		authority: &Authority,
		roots: &[PathBuf],
		state: &Path,
	) -> Result<()> {
		authority.authorize(&self.input)?;
		if let Some(stamp) = &self.native_boot_clock {
			stamp.validate()?;
		}
		ensure!(
			self.schema == "hepta.smallhcsn.original-attempt.v1"
				&& self.authority == authority.binding()?
				&& self.roots == roots
				&& self.state == state
				&& self.budget == budget()
				&& self.created_unix_milliseconds > 0
				&& self
					.created_unix_milliseconds
					.checked_add(ATTEMPT_SECONDS * 1000)
					== Some(self.expires_unix_milliseconds)
				&& self.manifest.parent_artifact_id.is_none()
				&& self.manifest.restored_source_sha256.is_none()
				&& self.manifest.request.expected_sha256 == authority.parent_sha256()
				&& self.manifest.request.path == authority.source_path()
				&& self.manifest.target_sha256 == self.input.plan.candidate_sha256
				&& self.manifest.source_size_bytes <= MAX_FIXED_ARTIFACT_BYTES
				&& self.manifest.artifact_id == manifest_id(&self.manifest)?,
			"saved SmallHCSN attempt is outside its original session, policy or source scope"
		);
		for sha in [
			&self.cohort_implementation,
			&self.transaction_implementation,
			&self.evaluator,
		] {
			ensure!(
				crate::mcp::weight_config::valid_sha256(sha),
				"saved implementation digest"
			);
		}
		let raw = decode_raw(&self.input.raw_input_hex)?;
		ensure!(
			raw.len() <= MAX_RAW_BYTES && digest(&raw) == self.input.plan.input_sha256,
			"saved raw input commitment differs"
		);
		let _ = model::inputs(&raw)?;
		let expected_id = digest(&serde_json::to_vec(&json!({
			"schema":"hepta.smallhcsn.original-request.v1",
			"authority":self.authority,"request":self.input,"roots":roots,"state":state,
			"evaluator":self.evaluator,"implementation":self.transaction_implementation,"budget":self.budget
		}))?);
		ensure!(
			self.id() == expected_id,
			"saved request is not its original bound identity"
		);
		let mut expected_binding = json!({
			"schema":"hepta.smallhcsn.cohort-binding.v1","original_request_id":self.id(),
			"authority":self.authority,"parent_sha256":authority.parent_sha256(),
			"profile_sha256":digest(self.input.profile_json.as_bytes()),
			"raw_input_sha256":self.input.plan.input_sha256,
			"plan_sha256":digest(&serde_json::to_vec(&self.input.plan)?),
			"candidate_sha256":self.input.plan.candidate_sha256,
			"evaluator_sha256":self.evaluator,"implementation_sha256":self.transaction_implementation,
			"budget_sha256":digest(&serde_json::to_vec(&self.budget)?),
			"fixed_scope":"smallhcsn_centered_sender_drive_and_bias40_v1"
		});
		if let Some(proposal) = &self.input.proposal {
			let compiler_source = self.proposal_evidence["program"]["compiler_source_sha256"]
				.as_str()
				.context("saved native proposal compiler identity")?;
			ensure!(
				crate::mcp::weight_config::valid_sha256(compiler_source),
				"saved compiler source digest"
			);
			let program = compiler::program(
				proposal,
				&digest(self.input.profile_json.as_bytes()),
				compiler_source,
				&self.evaluator,
			)?;
			ensure!(
				self.proposal_evidence["program"] == program
					&& self.proposal_evidence["plan_sha256"]
						== digest(&serde_json::to_vec(&self.input.plan)?)
					&& self.proposal_evidence["candidate_sha256"] == self.manifest.target_sha256
					&& self.proposal_evidence["compiler_invocations"] == 1
					&& self.proposal_evidence["compiler_model_forward_calls"] == 0,
				"original native compilation evidence is missing or differs"
			);
			expected_binding["native_proposal_program_sha256"] = program["program_sha256"].clone();
		} else {
			ensure!(
				self.proposal_evidence.is_null(),
				"manual plan cannot impersonate a native compilation"
			);
		}

		if let Some(program) = ndu::validate_saved(
			&self.input,
			&self.proposal_evidence,
			&self.ndu_evidence,
			&self.evaluator,
			&self.budget,
			self.id(),
		)? {
			expected_binding["finite_policy_program_sha256"] = program["program_sha256"].clone();
		}

		ensure!(
			self.manifest.research_binding.as_ref() == Some(&expected_binding),
			"saved artifact is missing or changes the fixed native authority binding"
		);
		let mut request = self.manifest.request.clone();
		validate(&mut request)?;
		ensure!(
			serde_json::to_vec(&request)? == serde_json::to_vec(&self.manifest.request)?
				&& request.members.len() == 2
				&& request.members[0].tensor_name == hidden::BIAS_NAME
				&& request.members[1].tensor_name == hidden::WEIGHT_NAME
				&& matches!(request.training, TrainingContract::InferenceOnly),
			"saved canonical request is not the fixed two-tensor normalized cohort"
		);
		Ok(())
	}
}

pub(super) async fn exists(directory: &Path, name: &str) -> Result<bool> {
	match tokio::fs::symlink_metadata(directory.join(name)).await {
		Ok(_) => Ok(true),
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
		Err(error) => Err(error.into()),
	}
}

pub(super) async fn read(directory: &Path, name: &str, cap: u64) -> Result<Value> {
	let bytes =
		rea_files::read_private_bounded(&directory.join(name), &[directory.to_owned()], cap)
			.await?;
	crate::mcp::rea_evidence::parse_unique_json(&bytes)
}

pub(super) async fn write(directory: &Path, name: &str, value: &Value, cap: u64) -> Result<()> {
	let bytes = serde_json::to_vec(value)?;
	ensure!(
		bytes.len() as u64 <= cap,
		"fixed SmallHCSN record byte budget exceeded"
	);
	write_record(directory, name, &bytes).await
}

pub(super) fn identity(
	manifest: &CohortManifest,
	research: &Value,
	implementation: &str,
	roots: &[PathBuf],
	state: &Path,
) -> Result<String> {
	Ok(digest(&serde_json::to_vec(&json!({
		"request":manifest.request,"roots":roots,"state":state,"implementation":implementation,
		"parent":manifest.parent_artifact_id,"restored_sha":manifest.restored_source_sha256,"research":research
	}))?))
}

pub(super) async fn load(
	state: &Path,
	roots: &[PathBuf],
	id: &str,
	authority: &Authority,
) -> Result<(PathBuf, Intent, Saved)> {
	ensure!(
		crate::mcp::weight_config::valid_sha256(id),
		"original journal ID required"
	);
	let root = state.join("weight-cohort-journal-v1");
	verify_private_directory(&root).await?;
	let directory = root.join(id);
	verify_private_directory(&directory).await?;
	let intent: Intent =
		serde_json::from_value(read(&directory, "intent.json", MAX_MANIFEST_BYTES).await?)?;
	let research = intent
		.research
		.as_ref()
		.context("legacy unbound intent is not a SmallHCSN authority")?;
	let saved: Saved = serde_json::from_value(research.clone())?;
	saved.validate(authority, roots, state)?;
	let manifest_bytes = serde_json::to_vec(&saved.manifest)?;
	ensure!(
		saved.id() == id
			&& intent.schema == "hepta.weight.cohort-intent.v1"
			&& intent.artifact_id == saved.manifest.artifact_id
			&& intent.manifest_sha256 == digest(&manifest_bytes)
			&& intent.request_digest
				== identity(
					&saved.manifest,
					research,
					&saved.cohort_implementation,
					roots,
					state
				)?,
		"original SmallHCSN intent integrity mismatch"
	);
	Ok((directory, intent, saved))
}

#[derive(Clone, Copy, Debug)]
pub(super) enum Phase {
	Parent,
	Candidate,
	Restored,
}
impl Phase {
	pub(super) fn name(self) -> &'static str {
		match self {
			Self::Parent => "parent",
			Self::Candidate => "candidate",
			Self::Restored => "restored",
		}
	}
	pub(super) fn source(self, saved: &Saved) -> &str {
		match self {
			Self::Candidate => &saved.manifest.target_sha256,
			_ => &saved.manifest.request.expected_sha256,
		}
	}
	fn charge(self, saved: &Saved) -> Result<Value> {
		Ok(
			json!({"schema":"hepta.smallhcsn.model-charge.v1","original_request_id":saved.id(),
			"phase":self.name(),"reserved_seconds":PHASE_SECONDS,"nonrefundable":true,
			"source_sha256":self.source(saved),"raw_input_sha256":saved.input.plan.input_sha256,
			"evaluator_sha256":saved.evaluator,"binding_sha256":digest(&serde_json::to_vec(&saved.manifest.research_binding)?) }),
		)
	}
}

pub(super) async fn charged(directory: &Path, phase: Phase) -> Result<bool> {
	exists(directory, &format!("model-{}-charge.json", phase.name())).await
}

pub(super) async fn charge(directory: &Path, saved: &Saved, phase: Phase) -> Result<()> {
	ensure!(
		!charged(directory, phase).await?,
		"model phase was already durably charged; replay is forbidden"
	);
	write(
		directory,
		&format!("model-{}-charge.json", phase.name()),
		&phase.charge(saved)?,
		4096,
	)
	.await
}

pub(super) async fn phase_result(directory: &Path, phase: Phase, value: &Value) -> Result<()> {
	ensure!(
		charged(directory, phase).await?,
		"model result has no original durable charge"
	);
	write(
		directory,
		&format!("model-{}-result.json", phase.name()),
		value,
		4096,
	)
	.await
}

fn validate_result(saved: &Saved, phase: Phase, value: &Value) -> Result<()> {
	ensure!(
		value["schema"] == "hepta.smallhcsn.model-result.v1"
			&& value["original_request_id"] == saved.id()
			&& value["phase"] == phase.name()
			&& value["artifact_sha256"] == phase.source(saved)
			&& value["raw_input_sha256"] == saved.input.plan.input_sha256
			&& value["evaluator_sha256"] == saved.evaluator
			&& value["observed_wall_milliseconds"].as_u64().is_some(),
		"model result identity differs from its durable phase charge"
	);
	match value["model_completed"].as_bool() {
		Some(true) => {
			let metrics = &value["metrics"];
			let n = metrics["queries"].as_u64().context("model query count")?;
			let correct = metrics["correct"].as_u64().context("model correct count")?;
			let mse = metrics["mse"].as_f64().context("model finite MSE")?;
			let diagnostics = metrics["physical_diagnostics"]
				.as_array()
				.context("model diagnostics")?;
			ensure!(
				(1..=80).contains(&n)
					&& correct <= n && mse.is_finite()
					&& mse >= 0.0 && diagnostics.len() == 6
					&& diagnostics
						.iter()
						.all(|v| v.as_f64().is_some_and(|x| x.is_finite() && x >= 0.0))
					&& metrics["physical_tolerance"] == json!(2e-9)
					&& metrics["physical_valid"]
						== json!(diagnostics
							.iter()
							.all(|v| v.as_f64().is_some_and(|x| x <= 2e-9)))
					&& metrics["output_sha256"]
						.as_str()
						.is_some_and(crate::mcp::weight_config::valid_sha256)
					&& metrics["output_bytes"].as_u64() == Some(76 + n * 184)
					&& value["error"].is_null(),
				"model result exceeds the fixed numerical output contract"
			);
		}
		Some(false) => ensure!(
			value["metrics"].is_null()
				&& value["error"]
					.as_str()
					.is_some_and(|x| x.chars().count() <= 512),
			"failed model phase result contract"
		),
		None => bail!("model result requires an explicit completion state"),
	}
	Ok(())
}

pub(super) async fn ledger(directory: &Path, saved: &Saved) -> Result<Value> {
	let mut rows = Vec::new();
	let mut count = 0;
	let mut completed = 0;
	for phase in [Phase::Parent, Phase::Candidate, Phase::Restored] {
		let present = charged(directory, phase).await?;
		let result_name = format!("model-{}-result.json", phase.name());
		let result = if exists(directory, &result_name).await? {
			ensure!(
				present,
				"model result exists without its nonrefundable phase charge"
			);
			read(directory, &result_name, 4096).await?
		} else {
			Value::Null
		};
		if present {
			ensure!(
				read(
					directory,
					&format!("model-{}-charge.json", phase.name()),
					4096
				)
				.await? == phase.charge(saved)?,
				"saved model charge differs from the fixed original budget"
			);
			count += 1;
		}
		if !result.is_null() {
			validate_result(saved, phase, &result)?;
		}
		if result["model_completed"] == true {
			completed += 1;
		}
		rows.push(
			json!({"phase":phase.name(),"charged":present,"result":result,
			"interrupted_cost_unknown":present && result.is_null()}),
		);
	}
	Ok(
		json!({"schema":"hepta.smallhcsn.attempt-ledger.v1","phases":rows,
		"reserved_phase_count":count,"reserved_seconds":count*PHASE_SECONDS,
		"completed_model_evaluations":completed,"maximum_reserved_seconds":ATTEMPT_SECONDS,
		"interrupted_reservations_refunded":false,"charged_phase_replayed":false}),
	)
}
