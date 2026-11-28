// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Closed immutable plan, one-shot selection and nonrefundable grouped phase records.

use super::*;

pub(super) fn now_ms() -> Result<u64> {
	u64::try_from(
		std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)?
			.as_millis(),
	)
	.context("attempt wall clock overflow")
}

pub(super) async fn exists(directory: &Path, name: &str) -> Result<bool> {
	match tokio::fs::symlink_metadata(directory.join(name)).await {
		Ok(_) => Ok(true),
		Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
		Err(e) => Err(e.into()),
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
		"late-quote durable record byte cap"
	);
	write_record(directory, name, &bytes).await
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Saved {
	pub schema: String,
	pub journal_id: String,
	pub plan_sha256: String,
	pub plan: Plan,
	pub keep_manifest: CohortManifest,
	pub sign_manifest: Option<CohortManifest>,
	pub created_unix_ms: u64,
	pub expires_unix_ms: u64,
	pub native_boot_clock: clock::Stamp,
	pub preparation_wall_seconds: f64,
}

impl Saved {
	pub fn sha(&self) -> Result<String> {
		Ok(digest(&serde_json::to_vec(self)?))
	}
	pub fn seal(&self) -> Result<Value> {
		Ok(
			json!({"schema":"hepta.late-quote.original-attempt-seal.v1","journal_id":self.journal_id,"plan_sha256":self.plan_sha256,"attempt_sha256":self.sha()?}),
		)
	}
	pub fn new(p: &Prepared, created: u64, stamp: clock::Stamp) -> Result<Self> {
		Ok(Self {
			schema: "hepta.late-quote.original-attempt.v1".into(),
			journal_id: p.plan.id()?,
			plan_sha256: p.plan.sha()?,
			plan: p.plan.clone(),
			keep_manifest: p.keep.manifest.clone(),
			sign_manifest: p.sign.as_ref().map(|c| c.manifest.clone()),
			created_unix_ms: created,
			expires_unix_ms: created
				.checked_add(ATTEMPT_SECONDS * 1000)
				.context("attempt expiry overflow")?,
			native_boot_clock: stamp,
			preparation_wall_seconds: p.preparation_wall_seconds,
		})
	}
	pub fn manifest(&self, action: Action) -> Result<&CohortManifest> {
		match action {
			Action::Keep => Ok(&self.keep_manifest),
			Action::Sign => self
				.sign_manifest
				.as_ref()
				.context("SIGN candidate was not admitted"),
			Action::Abstain => bail!("ABSTAIN cannot publish an artifact"),
		}
	}
	pub async fn remaining(&self) -> Result<Duration> {
		let remaining = self
			.native_boot_clock
			.remaining_at(&clock::sample().await?, ATTEMPT_SECONDS)?;
		let now = now_ms()?;
		ensure!(
			now >= self.created_unix_ms && now < self.expires_unix_ms,
			"original wall window expired or moved backward; inverse only"
		);
		Ok(remaining.min(Duration::from_millis(self.expires_unix_ms - now)))
	}
	pub fn validate(
		&self,
		id: &str,
		authority: &Authority,
		roots: &[PathBuf],
		state: &Path,
	) -> Result<()> {
		let p = &self.plan;
		authority.authorize(&p.input)?;
		self.native_boot_clock.validate()?;
		ensure!(
			self.schema == "hepta.late-quote.original-attempt.v1"
				&& p.schema == "hepta.late-quote.sealed-plan.v1"
				&& self.journal_id == id
				&& p.id()? == id
				&& p.sha()? == self.plan_sha256
				&& p.authority == authority.binding()?
				&& p.roots == roots
				&& p.state == state
				&& p.budget == budget()
				&& self.created_unix_ms > 0
				&& self.preparation_wall_seconds.is_finite()
				&& self.preparation_wall_seconds >= 0.0
				&& self.created_unix_ms.checked_add(ATTEMPT_SECONDS * 1000)
					== Some(self.expires_unix_ms),
			"saved late-quote intent differs from original plan, authority, state or fixed budget"
		);
		for sha in [
			&p.transaction_implementation,
			&p.cohort_implementation,
			&p.evaluator_source,
			&p.running_executable_sha256,
		] {
			ensure!(
				crate::mcp::weight_config::valid_sha256(sha),
				"saved implementation digest"
			);
		}
		let raw = decode_raw(&p.input.raw_input_hex)?;
		let normalized = model::inputs(&raw)?;
		let task = model::LateQuoteMinV1::check(&normalized)?;
		let normal = decode_raw(&p.input.retention_raw_input_hex)?;
		let _ = model::inputs(&normal)?;
		ensure!(
			p.semantic_task == task.evidence()
				&& p.program["semantic_input_sha256"] == p.semantic_task["semantic_input_sha256"]
				&& p.program["schema"] == "hepta.late-quote-program.v1"
				&& p.program["labels_read"] == false
				&& p.program["gradient_steps"] == 0
				&& p.program["full_forward_calls"] == 0
				&& p.program["maximum_changed_words"] == 4,
			"saved semantic task or label-free program evidence differs"
		);
		for function in [&p.parent_function, &p.keep_function, &p.sign_function] {
			ensure!(
				crate::mcp::weight_config::valid_sha256(&function.artifact_sha256)
					&& function.evaluator_source_sha256 == p.evaluator_source
					&& function.initial_state_contract == "fixed_reset_step0_six_tick_v1",
				"saved function source or fixed initial state differs"
			);
		}
		ensure!(
			p.parent_function.artifact_sha256 == authority.parent_sha256()
				&& p.parent_function.graph == model::ResearchGraph::Original
				&& p.parent_function.request_route == model::RequestRoute::OriginalFixedProfile
				&& p.keep_function.artifact_sha256 == authority.parent_sha256()
				&& p.keep_function.graph == model::ResearchGraph::FinalTickTiedReceiverMark
				&& p.sign_function.graph == p.keep_function.graph
				&& p.keep_function.request_route == model::RequestRoute::CheckedLateQuoteMinV1
				&& p.sign_function.request_route == p.keep_function.request_route
				&& p.program["parent"] == serde_json::to_value(&p.parent_function)?
				&& p.program["candidate"] == serde_json::to_value(&p.sign_function)?,
			"saved graph, route or candidate function is outside this closed profile"
		);
		let sign_pairs = p
			.sign_words
			.iter()
			.map(|word| {
				Ok((
					represented_value("F32", &word.expected_hex)?,
					represented_value("F32", &word.replacement_hex)?,
				))
			})
			.collect::<Result<Vec<_>>>()?;
		ensure!(
			p.sign_words.len() == 4
				&& p.sign_words.iter().map(|w| w.index).eq([7, 16, 25, 34])
				&& p.sign_words
					.iter()
					.all(|w| w.expected_hex.len() == 8 && w.replacement_hex.len() == 8)
				&& p.sign_admissible
					== crate::mcp::weight_norm::check_pairs(
						sign_pairs,
						p.input.maximum_update_l2_norm
					)?
					.within_budget
				&& self.sign_manifest.is_some() == p.sign_admissible,
			"saved SIGN feasibility differs from the prebound exact radius"
		);
		self.validate_manifest(Action::Keep)?;
		if p.sign_admissible {
			self.validate_manifest(Action::Sign)?;
		}
		ensure!(
			p.keep_words
				.iter()
				.zip(&p.sign_words)
				.all(|(a, b)| a.index == b.index
					&& a.expected_hex == b.expected_hex
					&& a.expected_hex == a.replacement_hex),
			"KEEP and SIGN must share the same four exact original words"
		);
		Ok(())
	}
	fn validate_manifest(&self, action: Action) -> Result<()> {
		let p = &self.plan;
		let m = self.manifest(action)?;
		let mut request = p.request(action)?;
		validate(&mut request)?;
		let words = p.words(action);
		ensure!(
			words.len() == 4
				&& words.iter().map(|e| e.index).eq([7, 16, 25, 34])
				&& serde_json::to_vec(&m.request)? == serde_json::to_vec(&request)?
				&& m.research_binding.as_ref() == Some(&p.function_binding(action, false)?)
				&& m.schema == "hepta.weight.native-cohort.v1"
				&& m.artifact_id == manifest_id(m)?
				&& m.parent_artifact_id.is_none()
				&& m.restored_source_sha256.is_none()
				&& m.target_sha256 == p.function(action).artifact_sha256
				&& m.patches.len() == 1,
			"saved cohort differs from its prebound four-word function capsule"
		);
		let profile: Value =
			crate::mcp::rea_evidence::parse_unique_json(p.input.profile_json.as_bytes())?;
		let pin = &profile["profiles"][0];
		ensure!(
			pin["canonical_sha256"] == p.parent_function.artifact_sha256
				&& pin["file_bytes"].as_u64() == Some(m.source_size_bytes)
				&& (10..=MAX_FIXED_ARTIFACT_BYTES).contains(&m.source_size_bytes),
			"saved original complete extent differs"
		);
		let tensor = pin["tensors"]
			.as_array()
			.context("saved tensor pins")?
			.iter()
			.find(|v| v["name"] == "body.input_mark.weight")
			.context("saved mark tensor pin")?;
		let offset = 8u64
			.checked_add(
				pin["header_length"]
					.as_u64()
					.context("saved header length")?,
			)
			.and_then(|n| n.checked_add(tensor["data_offsets"][0].as_u64()?))
			.context("saved mark offset overflow")?;
		let patch = &m.patches[0];
		ensure!(
			patch.tensor_name == "body.input_mark.weight"
				&& patch.dtype == "F32"
				&& patch.tensor_file_offset == offset
				&& patch.tensor_byte_length == 144
				&& patch.source_size_bytes == m.source_size_bytes
				&& patch.changes.len() == 4,
			"saved mark patch extent differs"
		);
		let mut pairs = Vec::new();
		let mut changed = 0u64;
		for (change, word) in patch.changes.iter().zip(words) {
			ensure!(
				change.index == word.index
					&& change.file_offset == offset + word.index * 4
					&& change.expected_hex == word.expected_hex
					&& change.replacement_hex == word.replacement_hex
					&& word.expected_hex.len() == 8
					&& word.replacement_hex.len() == 8,
				"saved exact protected-word scope differs"
			);
			let a = weight_tensor::unhex(&word.expected_hex)?;
			let b = weight_tensor::unhex(&word.replacement_hex)?;
			changed += a.iter().zip(&b).filter(|(a, b)| a != b).count() as u64;
			pairs.push((
				represented_value("F32", &word.expected_hex)?,
				represented_value("F32", &word.replacement_hex)?,
			));
		}
		let radius = crate::mcp::weight_norm::check_pairs(pairs, p.input.maximum_update_l2_norm)?;
		let radius_value = serde_json::to_value(&radius)?;
		ensure!(
			radius.within_budget
				&& m.changed_bytes == changed
				&& m.global_budget == radius_value
				&& m.member_budgets == vec![radius_value],
			"saved exact radius or changed-byte count differs"
		);
		Ok(())
	}
}

pub(super) async fn load(
	state: &Path,
	roots: &[PathBuf],
	id: &str,
	authority: &Authority,
) -> Result<(PathBuf, Saved)> {
	ensure!(
		crate::mcp::weight_config::valid_sha256(id),
		"original late-quote journal digest required"
	);
	let root = state.join("weight-cohort-journal-v1");
	verify_private_directory(&root).await?;
	let directory = root.join(id);
	verify_private_directory(&directory).await?;
	let saved: Saved =
		serde_json::from_value(read(&directory, "late-intent.json", MAX_MANIFEST_BYTES).await?)?;
	saved.validate(id, authority, roots, state)?;
	ensure!(
		read(&directory, "late-intent-seal.json", 4096).await? == saved.seal()?,
		"saved original clock, plan or function differs from its immutable attempt seal"
	);
	Ok((directory, saved))
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum Phase {
	Parent,
	Candidate,
	Restored,
}
impl Phase {
	pub fn name(self) -> &'static str {
		match self {
			Self::Parent => "parent",
			Self::Candidate => "candidate",
			Self::Restored => "restored",
		}
	}
	pub fn cap(self) -> usize {
		match self {
			Self::Parent | Self::Candidate => 3,
			Self::Restored => 2,
		}
	}
	fn charge(self, saved: &Saved) -> Result<Value> {
		Ok(
			json!({"schema":"hepta.late-quote.phase-charge.v1","journal_id":saved.journal_id,"plan_sha256":saved.plan_sha256,
		"attempt_sha256":saved.sha()?,"phase":self,"reserved_seconds":PHASE_SECONDS,"maximum_forward_calls":self.cap(),"nonrefundable":true,"partial_replay_allowed":false}),
		)
	}
}
pub(super) async fn charged(directory: &Path, phase: Phase) -> Result<bool> {
	exists(directory, &format!("late-{}-charge.json", phase.name())).await
}
pub(super) async fn charge(directory: &Path, saved: &Saved, phase: Phase) -> Result<()> {
	ensure!(
		!charged(directory, phase).await?,
		"grouped model phase already charged; partial replay is forbidden"
	);
	write(
		directory,
		&format!("late-{}-charge.json", phase.name()),
		&phase.charge(saved)?,
		4096,
	)
	.await?;
	execution::test_boundary(&format!("{}-charged", phase.name())).await
}
pub(super) async fn recorded(directory: &Path, phase: Phase) -> Result<Value> {
	let name = format!("late-{}-result.json", phase.name());
	if exists(directory, &name).await? {
		read(directory, &name, RECORD_BYTES).await
	} else {
		Ok(Value::Null)
	}
}
pub(super) async fn result(
	directory: &Path,
	saved: &Saved,
	phase: Phase,
	decision: Option<&Decision>,
	value: &Value,
) -> Result<()> {
	ensure!(
		charged(directory, phase).await?,
		"phase result has no original charge"
	);
	evaluation::validate(saved, phase, decision, value)?;
	write(
		directory,
		&format!("late-{}-result.json", phase.name()),
		value,
		RECORD_BYTES,
	)
	.await
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(super) struct Decision {
	pub schema: String,
	pub journal_id: String,
	pub plan_sha256: String,
	pub attempt_sha256: String,
	pub parent_phase_sha256: String,
	pub action: Action,
	pub selected_artifact_id: Option<String>,
	pub selected_function: model::FunctionIdentity,
	pub bridge_keep_met_goal: bool,
}
impl Decision {
	pub fn from_original_observation(saved: &Saved, parent: &Value) -> Result<Self> {
		evaluation::validate(saved, Phase::Parent, None, parent)?;
		ensure!(
			evaluation::valid(parent),
			"finite selection requires all original parent-phase forwards to complete"
		);
		let metrics = &parent["observations"][2]["metrics"];
		let keep = model::late_quote_goal_met(
			metrics["correct"].as_u64().context("KEEP correct")? as usize,
			metrics["queries"].as_u64().context("KEEP queries")? as usize,
			saved.plan.input.minimum_accuracy_percent,
		)?;
		let action = if keep {
			Action::Keep
		} else if saved.plan.sign_admissible {
			Action::Sign
		} else {
			Action::Abstain
		};
		Ok(Self {
			schema: "hepta.late-quote.one-shot-decision.v1".into(),
			journal_id: saved.journal_id.clone(),
			plan_sha256: saved.plan_sha256.clone(),
			attempt_sha256: saved.sha()?,
			parent_phase_sha256: digest(&serde_json::to_vec(parent)?),
			action,
			selected_artifact_id: if action == Action::Abstain {
				None
			} else {
				Some(saved.manifest(action)?.artifact_id.clone())
			},
			selected_function: saved.plan.function(action).clone(),
			bridge_keep_met_goal: keep,
		})
	}
	pub fn sha(&self) -> Result<String> {
		Ok(digest(&serde_json::to_vec(self)?))
	}
}
pub(super) async fn decision(directory: &Path, saved: &Saved) -> Result<Option<Decision>> {
	if !exists(directory, "late-decision.json").await? {
		return Ok(None);
	}
	let decision: Decision =
		serde_json::from_value(read(directory, "late-decision.json", 4096).await?)?;
	let parent = recorded(directory, Phase::Parent).await?;
	ensure!(
		decision == Decision::from_original_observation(saved, &parent)?,
		"saved one-shot decision differs; recovery cannot reselect a candidate"
	);
	Ok(Some(decision))
}

pub(super) async fn ledger(
	directory: &Path,
	saved: &Saved,
	decision: Option<&Decision>,
) -> Result<Value> {
	let mut rows = Vec::new();
	let mut reservations = 0usize;
	let mut completed = 0usize;
	let mut uncertain = false;
	for phase in [Phase::Parent, Phase::Candidate, Phase::Restored] {
		let charged = charged(directory, phase).await?;
		let result = recorded(directory, phase).await?;
		if charged {
			ensure!(
				read(
					directory,
					&format!("late-{}-charge.json", phase.name()),
					4096
				)
				.await? == phase.charge(saved)?,
				"saved grouped charge changed"
			);
			reservations += 1;
		}
		if !result.is_null() {
			ensure!(charged, "result without nonrefundable charge");
			evaluation::validate(saved, phase, decision, &result)?;
			completed += result["observations"]
				.as_array()
				.context("phase observations")?
				.len();
		}
		uncertain |= charged && result["completed"] != true;
		rows.push(json!({"phase":phase,"charged":charged,"reserved_forward_cap":if charged {phase.cap()} else {0},"result":result,
			"interrupted_cost_unknown":charged && result["completed"]!=true}));
	}
	Ok(
		json!({"schema":"hepta.late-quote.attempt-ledger.v1","phases":rows,"reserved_phase_count":reservations,"reserved_seconds":reservations*PHASE_SECONDS as usize,
		"completed_forward_calls_with_durable_results":completed,"unobserved_partial_work_possible":uncertain,"maximum_forward_calls":8,"phase_refunds":false,"charged_phase_replayed":false}),
	)
}
