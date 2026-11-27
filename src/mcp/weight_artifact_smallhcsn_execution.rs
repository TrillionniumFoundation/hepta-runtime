// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Retained SmallHCSN execution and source-independent explicit compensation.
//! Once publication is possible, every normal failure flows through the original inverse.

use super::*;

fn note(errors: &mut Vec<Value>, stage: &str, error: anyhow::Error) {
	errors.push(json!({"stage":stage,"error":evaluation::bounded_error(&error)}));
}

async fn actual_bytes(
	saved: &journal::Saved,
	id: &str,
	expected: &str,
	deadline: &model::Deadline,
) -> Result<Vec<u8>> {
	let (mut file, before, sha) = open_pinned(id, &saved.state).await?;
	ensure!(
		sha == expected,
		"reopened fixed-model artifact identity differs"
	);
	capture(&mut file, &before, expected, deadline).await
}

async fn candidate_phase(
	saved: &journal::Saved,
	directory: &Path,
	parent: &[u8],
	plan: &hidden::PreparedPlan,
	authority: &Authority,
	deadline: &model::Deadline,
) -> Result<Value> {
	authority.revalidate().await?;
	deadline.check()?;
	let phase_deadline = deadline.capped(Duration::from_secs(PHASE_SECONDS));
	let bytes = actual_bytes(
		saved,
		&saved.manifest.artifact_id,
		&saved.manifest.target_sha256,
		&phase_deadline,
	)
	.await?;
	let raw = decode_raw(&saved.input.raw_input_hex)?;
	let (bound, evidence) = model::bind_hidden_candidate(
		saved.input.profile_json.as_bytes(),
		parent,
		&bytes,
		&raw,
		plan,
	)?;
	ensure!(
		evidence["actual_candidate_verified"] == true
			&& evidence["all_other_bytes_preserved"] == true,
		"candidate full-model binding lacks exact protected-byte evidence"
	);
	evaluation::run(
		directory,
		saved,
		journal::Phase::Candidate,
		bound,
		&raw,
		&phase_deadline,
	)
	.await
}

struct Restoration {
	receipt: Value,
	fresh_readback: bool,
}

async fn compensate(
	saved: &journal::Saved,
	directory: &Path,
	root: &Path,
	authority: &Authority,
	deadline: &model::Deadline,
	errors: &mut Vec<Value>,
) -> Restoration {
	// This inverse intentionally does not revalidate a credential that may have been revoked
	// after its effect was admitted. It can only reverse this saved exact two-tensor candidate.
	let receipt = match inverse::restore(saved, root).await {
		Ok(value) => value,
		Err(error) => {
			note(errors, "canonical_inverse", error);
			return Restoration {
				receipt: Value::Null,
				fresh_readback: false,
			};
		}
	};
	let fresh = async {
		let id = receipt["artifact_id"]
			.as_str()
			.context("canonical inverse artifact ID")?;
		// Readback is allowed even after the model budget is expired. It proves exact bytes,
		// not a new model evaluation; the original artifact reader retains its native bounds.
		let read_deadline = model::Deadline::new(Duration::from_secs(PHASE_SECONDS));
		let bytes = actual_bytes(
			saved,
			id,
			&saved.manifest.request.expected_sha256,
			&read_deadline,
		)
		.await?;
		let raw = decode_raw(&saved.input.raw_input_hex)?;
		let bound = model::bind(saved.input.profile_json.as_bytes(), &bytes, &raw)?;
		ensure!(
			bound.artifact_sha256() == bound.canonical_sha256()
				&& bound.artifact_sha256() == saved.manifest.request.expected_sha256,
			"fresh restored model is not its canonical complete parent"
		);
		Ok::<_, anyhow::Error>((bound, raw))
	}
	.await;
	let (bound, raw) = match fresh {
		Ok(value) => value,
		Err(error) => {
			note(errors, "fresh_restored_byte_binding", error);
			return Restoration {
				receipt,
				fresh_readback: false,
			};
		}
	};
	let fresh_evaluation = async {
		if journal::charged(directory, journal::Phase::Restored).await? {
			// A previous crash may have destroyed the result. Its charge still forbids replay.
			return Ok(());
		}
		authority.revalidate().await?;
		saved.remaining_window().await?;
		deadline.check()?;
		evaluation::run(
			directory,
			saved,
			journal::Phase::Restored,
			bound,
			&raw,
			deadline,
		)
		.await?;
		Ok::<_, anyhow::Error>(())
	}
	.await;
	if let Err(error) = fresh_evaluation {
		note(errors, "fresh_restored_evaluation", error);
	}
	Restoration {
		receipt,
		fresh_readback: true,
	}
}

struct Completion {
	candidate: Value,
	restoration: Restoration,
	errors: Vec<Value>,
	recovery: bool,
	no_publication: bool,
}

async fn result(
	saved: &journal::Saved,
	directory: &Path,
	authority: &Authority,
	completion: Completion,
) -> Result<Value> {
	let Completion {
		candidate,
		restoration,
		mut errors,
		recovery,
		no_publication,
	} = completion;
	let parent = evaluation::recorded(directory, journal::Phase::Parent).await?;
	let candidate_model = evaluation::recorded(directory, journal::Phase::Candidate).await?;
	let restored = evaluation::recorded(directory, journal::Phase::Restored).await?;
	let ledger = journal::ledger(directory, saved).await?;
	let authority_valid = match authority.revalidate().await {
		Ok(()) => true,
		Err(error) => {
			note(&mut errors, "authority_after_inverse", error);
			false
		}
	};
	let quality = evaluation::quality(&parent, &candidate_model, saved.input.minimum_mse_gain)?;
	let model_restored = evaluation::valid(&parent)
		&& evaluation::valid(&restored)
		&& parent["metrics"]["output_sha256"] == restored["metrics"]["output_sha256"];
	let bytes_restored = restoration.receipt.is_object()
		&& restoration.receipt["sha256"] == saved.manifest.request.expected_sha256
		&& restoration.receipt["source_sha256"] == saved.manifest.target_sha256;
	let qualified = bytes_restored
		&& restoration.fresh_readback
		&& model_restored
		&& quality
		&& authority_valid
		&& errors.is_empty();
	let observations = evaluation::observed_gain(&parent, &candidate_model);
	let complete = evaluation::valid(&parent)
		&& evaluation::valid(&candidate_model)
		&& evaluation::valid(&restored);
	let mut report = json!({
		"schema":"hepta.rea.smallhcsn-roundtrip.v1","journal_id":saved.id(),
		"parent_sha256":saved.manifest.request.expected_sha256,
		"bound_identity":saved.manifest.research_binding,
		"candidate":candidate,"restoration":restoration.receipt,
		"restoration_verified":bytes_restored,"restored_bytes_verified":bytes_restored,
		"fresh_restored_readback_verified":restoration.fresh_readback,
		"fresh_restored_model_matches_parent":model_restored,
		"parent_evaluation":parent,"candidate_evaluation":candidate_model,"restored_evaluation":restored,
		"candidate_quality_passed":quality,"research_roundtrip_verified":qualified,
		"observed_fixed_data_change":observations,
		"strict_fixed_data_improvement_verified":qualified && observations["strict_improvement"] == true,
		"original_finite_policy":saved.ndu_evidence,
		"finite_policy_observation":ndu::observed(&saved.ndu_evidence,qualified,complete),
		"finite_planner_invocations_this_request":if recovery {json!(0)} else {saved.preparation_computation["finite_planner_invocations"].clone()},
		"fixed_data_quality_qualified":qualified,"session_authority_valid_after_effect":authority_valid,
		"candidate_publication_absent_verified":no_publication,
	});
	let report_tail = json!({
		"full_model_executed":ledger["completed_model_evaluations"].as_u64().is_some_and(|n|n>0),
		"fixed_six_tick_model":true,"cached_features_used":false,
		"attempt_ledger":ledger,"budget":saved.budget,"errors":errors,
		"original_proposal_compilation":saved.proposal_evidence,
		"original_preparation_computation":saved.preparation_computation,
		"pure_compiler_invocations_this_request":if recovery {json!(0)} else {saved.preparation_computation["pure_compiler_invocations"].clone()},
		"original_window":{"start_unix_milliseconds":saved.created_unix_milliseconds,
			"end_unix_milliseconds":saved.expires_unix_milliseconds,"restarted_on_recovery":false,
			"native_boot_clock":saved.native_boot_clock,
			"same_boot_boottime_required_for_new_forward":true,
			"legacy_missing_boot_clock_allows_inverse_only":true,
			"wall_clock_record_only_not_sufficient_for_forward":true,
			"observed_backward_clock_forbids_forward":true},
		"explicit_recovery":recovery,"original_owner_task_retained":true,
		"original_source_path_opened":!recovery,"parent_forward_replayed":false,"candidate_forward_replayed":false,
		"source_modified":false,"accepted_for_activation":false,"live_activation":false,
		"production_eligible":false,"automatic_retry":false,"background_crash_recovery":false,
		"upstream_provenance_verified":false,"target_truth_verified":false,
		"global_ndu_optimality_verified":false
	});
	report
		.as_object_mut()
		.context("fixed SmallHCSN result object")?
		.extend(
			report_tail
				.as_object()
				.context("fixed SmallHCSN result tail")?
				.clone(),
		);
	ensure!(
		serde_json::to_vec(&report)?.len() <= 48 * 1024,
		"fixed result byte budget"
	);
	Ok(report)
}

async fn candidate_receipt(
	saved: &journal::Saved,
	intent: &Intent,
	directory: &Path,
	root: &Path,
) -> Result<Option<Value>> {
	if !inverse::available(root, &saved.manifest).await? {
		ensure!(
			!journal::exists(directory, "outcome.json").await?,
			"completed candidate is missing; publication may not be replayed"
		);
		return Ok(None);
	}
	let completed = journal::exists(directory, "outcome.json").await?;
	// The original intent and complete immutable model suffice to finish a lost publication
	// response without reopening a deleted workspace source or executing another forward.
	journal::write(
		directory,
		"outcome.json",
		&json!({
			"schema":"hepta.weight.cohort-outcome.v1","intent":intent,
			"target_sha256":saved.manifest.target_sha256,"all_members_verified":true
		}),
		MAX_MANIFEST_BYTES,
	)
	.await?;
	Ok(Some(cohort_receipt(
		&saved.manifest,
		root,
		directory,
		true,
		completed,
	)))
}

async fn reuse_result(
	directory: &Path,
	name: &str,
	saved: &journal::Saved,
	root: &Path,
) -> Result<Value> {
	let mut report = journal::read(directory, name, 48 * 1024).await?;
	ensure!(
		report["schema"] == "hepta.rea.smallhcsn-roundtrip.v1"
			&& report["journal_id"] == saved.id()
			&& report["parent_sha256"] == saved.manifest.request.expected_sha256
			&& report["bound_identity"] == serde_json::to_value(&saved.manifest.research_binding)?
			&& report["attempt_ledger"] == journal::ledger(directory, saved).await?
			&& report["parent_evaluation"]
				== evaluation::recorded(directory, journal::Phase::Parent).await?
			&& report["candidate_evaluation"]
				== evaluation::recorded(directory, journal::Phase::Candidate).await?
			&& report["restored_evaluation"]
				== evaluation::recorded(directory, journal::Phase::Restored).await?,
		"saved result differs from its original intent"
	);
	if report["restored_bytes_verified"] == true {
		let receipt = inverse::already_restored(saved, root)
			.await?
			.context("original verified inverse disappeared")?;
		ensure!(
			report["restoration"]["artifact_id"] == receipt["artifact_id"],
			"saved result names a different inverse"
		);
	}
	report["reused_original_result"] = json!(true);
	report["new_model_evaluations"] = json!(0);
	report["pure_compiler_invocations_this_request"] = json!(0);
	report["finite_planner_invocations_this_request"] = json!(0);
	Ok(report)
}

pub(super) async fn roundtrip(
	input: Input,
	id: String,
	authority: Authority,
	roots: Vec<PathBuf>,
	state: PathBuf,
) -> Result<Value> {
	let deadline = model::Deadline::new(Duration::from_secs(ATTEMPT_SECONDS));
	let native_boot_clock = clock::begin().await?;
	let created = journal::wall_clock_milliseconds()?;
	authority.revalidate().await?;
	let root = store_root(&state).await?;
	let _lock = lock_store(&root).await?;
	let journal_root = state.join("weight-cohort-journal-v1");
	let existing = journal_root.join(&id);
	if journal::exists(&journal_root, &id).await? {
		verify_private_directory(&existing).await?;
		ensure!(journal::exists(&existing,"intent.json").await?,
			"existing original journal lacks its durable intent; a fresh time window or forward is forbidden");
		let (directory, _, saved) = journal::load(&state, &roots, &id, &authority).await?;
		ensure!(
			serde_json::to_vec(&input)? == serde_json::to_vec(&saved.input)?,
			"same original ID cannot substitute a different request"
		);
		for name in ["smallhcsn-recovery.json", "smallhcsn-result.json"] {
			if journal::exists(&directory, name).await? {
				return reuse_result(&directory, name, &saved, &root).await;
			}
		}
		bail!(
			"original model attempt is uncertain; recover its same journal ID, never relaunch it"
		);
	}
	let prepared = tokio::time::timeout(
		deadline.remaining()?,
		preflight(input, &authority, &roots, &state, &deadline),
	)
	.await
	.context("fixed prepublication admission exceeded the original model window")??;
	ensure!(prepared.id == id, "preflight original request ID changed");
	let saved = journal::Saved::new(
		&prepared,
		&authority,
		&roots,
		&state,
		created,
		native_boot_clock,
	)?;
	let research = serde_json::to_value(&saved)?;
	let intent = original_intent(
		&saved.manifest,
		&prepared.cohort.manifest_bytes,
		&roots,
		&state,
		Some(research),
	)?;
	let directory = journal_directory(&state, &id).await?;
	journal::write(
		&directory,
		"intent.json",
		&serde_json::to_value(&intent)?,
		MAX_MANIFEST_BYTES,
	)
	.await?;
	let mut errors = Vec::new();
	let parent = async {
		authority.revalidate().await?;
		let bound = model::bind(
			saved.input.profile_json.as_bytes(),
			&prepared.parent,
			&prepared.raw,
		)?;
		evaluation::run(
			&directory,
			&saved,
			journal::Phase::Parent,
			bound,
			&prepared.raw,
			&deadline,
		)
		.await
	}
	.await;
	let parent_valid = match parent {
		Ok(report) => evaluation::valid(&report),
		Err(error) => {
			note(&mut errors, "parent_evaluation", error);
			false
		}
	};
	let mut published = Value::Null;
	if parent_valid {
		let publication = async {
			authority.revalidate().await?;
			saved.remaining_window().await?;
			deadline.check()?;
			publish_prepared(
				prepared.cohort,
				&root,
				&directory,
				intent.clone(),
				Boundary::None,
			)
			.await
		}
		.await;
		match publication {
			Ok(receipt) => published = receipt,
			Err(error) => note(&mut errors, "candidate_publication", error),
		}
	}
	#[cfg(all(test, target_os = "linux"))]
	if published.is_object() {
		tests::after_publication(&directory, &published).await;
	}
	// A failed or lost publication response does not bypass the inverse: reconcile its exact ID.
	let mut no_publication = false;
	match candidate_receipt(&saved, &intent, &directory, &root).await {
		Ok(Some(receipt)) => published = receipt,
		Ok(None) => no_publication = true,
		Err(error) => note(&mut errors, "candidate_reopen", error),
	}
	let restoration = if !no_publication {
		if published.is_object() {
			if let Err(error) = candidate_phase(
				&saved,
				&directory,
				&prepared.parent,
				&prepared.plan,
				&authority,
				&deadline,
			)
			.await
			{
				note(&mut errors, "candidate_evaluation", error);
			}
		}
		compensate(
			&saved,
			&directory,
			&root,
			&authority,
			&deadline,
			&mut errors,
		)
		.await
	} else {
		Restoration {
			receipt: Value::Null,
			fresh_readback: false,
		}
	};
	let report = result(
		&saved,
		&directory,
		&authority,
		Completion {
			candidate: published,
			restoration,
			errors,
			recovery: false,
			no_publication,
		},
	)
	.await?;
	journal::write(&directory, "smallhcsn-result.json", &report, 48 * 1024).await?;
	#[cfg(all(test, target_os = "linux"))]
	tests::completed(&report);
	Ok(report)
}

pub(super) async fn recover(
	id: String,
	expected_candidate: String,
	authority: Authority,
	roots: Vec<PathBuf>,
	state: PathBuf,
) -> Result<Value> {
	authority.revalidate().await?;
	let root = state.join("weight-artifacts-v1");
	verify_private_directory(&root).await?;
	let _lock = lock_store(&root).await?;
	let (directory, intent, saved) = journal::load(&state, &roots, &id, &authority).await?;
	ensure!(
		saved.manifest.target_sha256 == expected_candidate,
		"recovery candidate differs from the original source-bound intent"
	);
	if journal::exists(&directory, "smallhcsn-recovery.json").await? {
		return reuse_result(&directory, "smallhcsn-recovery.json", &saved, &root).await;
	}
	if journal::exists(&directory, "smallhcsn-result.json").await? {
		let report = journal::read(&directory, "smallhcsn-result.json", 48 * 1024).await?;
		if report["restored_bytes_verified"] == true {
			return reuse_result(&directory, "smallhcsn-result.json", &saved, &root).await;
		}
	}
	let mut errors = Vec::new();
	let mut candidate = Value::Null;
	let mut no_publication = false;
	match candidate_receipt(&saved, &intent, &directory, &root).await {
		Ok(Some(receipt)) => candidate = receipt,
		Ok(None) => no_publication = true,
		Err(error) => note(&mut errors, "candidate_reconciliation", error),
	}
	// This local cap can only reduce the persisted original window inside evaluation::run.
	// It cannot reopen sixty seconds or refund a phase charged by the interrupted process.
	let deadline = model::Deadline::new(Duration::from_secs(PHASE_SECONDS));
	let restored_before = inverse::already_restored(&saved, &root).await;
	let restoration = if no_publication && matches!(&restored_before, Ok(None)) {
		Restoration {
			receipt: Value::Null,
			fresh_readback: false,
		}
	} else {
		if let Err(error) = restored_before {
			note(&mut errors, "inverse_reconciliation", error);
		}
		compensate(
			&saved,
			&directory,
			&root,
			&authority,
			&deadline,
			&mut errors,
		)
		.await
	};
	let verified = restoration.receipt.is_object();
	let report = result(
		&saved,
		&directory,
		&authority,
		Completion {
			candidate,
			restoration,
			errors,
			recovery: true,
			no_publication,
		},
	)
	.await?;
	// Failed inverse attempts retain their original unresolved intent for explicit reconciliation;
	// there is no automatic retry and no replacement model phase or mutable success record.
	if verified || no_publication {
		journal::write(&directory, "smallhcsn-recovery.json", &report, 48 * 1024).await?;
	}
	Ok(report)
}
