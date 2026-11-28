// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! One retained owner controls finite selection, publication and compensation.
//! Recovery never opens the original workspace source, recompiles, or reselects.

use super::*;
use journal::{Decision, Phase, Saved};

fn note(errors: &mut Vec<Value>, stage: &str, error: anyhow::Error) {
	errors.push(json!({"stage":stage,"error":evaluation::bounded_error(&error)}));
}

pub(super) async fn test_boundary(name: &str) -> Result<()> {
	#[cfg(test)]
	if std::env::var("HEPTA_TEST_LATE_QUOTE_PHASE").as_deref() == Ok(name) {
		let marker = std::env::var("HEPTA_TEST_LATE_QUOTE_MARKER")?;
		tokio::fs::write(marker, name).await?;
		loop {
			tokio::time::sleep(Duration::from_millis(20)).await;
		}
	}
	let _ = name;
	Ok(())
}

async fn actual_bytes(saved: &Saved, artifact: &str, expected: &str) -> Result<Vec<u8>> {
	let (mut file, before, sha) = open_pinned(artifact, &saved.plan.state).await?;
	ensure!(
		sha == expected,
		"reopened artifact differs from saved function identity"
	);
	capture(&mut file, &before, expected).await
}

struct Restoration {
	receipt: Value,
	fresh_bytes_and_capsule: bool,
}

struct ForwardWindow<'a> {
	deadline: &'a model::Deadline,
	allow_new_phase: bool,
}

async fn compensate(
	saved: &Saved,
	decision: &Decision,
	directory: &Path,
	root: &Path,
	authority: &Authority,
	window: ForwardWindow<'_>,
	errors: &mut Vec<Value>,
) -> Restoration {
	// The already admitted owner may compensate after caller cancellation or revocation.
	// It cannot grant a new forward or restore a different task/function.
	let receipt = match inverse::restore(root, saved, decision).await {
		Ok(value) => value,
		Err(error) => {
			note(errors, "graph_and_weight_inverse", error);
			return Restoration {
				receipt: Value::Null,
				fresh_bytes_and_capsule: false,
			};
		}
	};
	let fresh = async {
		let artifact = receipt["artifact_id"]
			.as_str()
			.context("inverse artifact identity")?;
		ensure!(
			receipt["function_capsule"] == saved.plan.function_binding(decision.action, true)?,
			"inverse receipt lacks the complete original route, initial state and evaluator capsule"
		);
		let bytes =
			actual_bytes(saved, artifact, &saved.plan.parent_function.artifact_sha256).await?;
		let raw = decode_raw(&saved.plan.input.raw_input_hex)?;
		let bound = model::bind(saved.plan.input.profile_json.as_bytes(), &bytes, &raw)?;
		ensure!(
			bound.artifact_sha256() == saved.plan.parent_function.artifact_sha256
				&& bound.canonical_sha256() == bound.artifact_sha256(),
			"restored complete checkpoint differs from canonical original"
		);
		Ok::<_, anyhow::Error>(bytes)
	}
	.await;
	let bytes = match fresh {
		Ok(bytes) => bytes,
		Err(error) => {
			note(errors, "restored_bytes_and_capsule_readback", error);
			return Restoration {
				receipt,
				fresh_bytes_and_capsule: false,
			};
		}
	};
	let readback = async {
		if !window.allow_new_phase || journal::charged(directory, Phase::Restored).await? {
			return Ok(());
		}
		authority.revalidate().await?;
		saved.remaining().await?;
		window.deadline.check()?;
		evaluation::run(
			directory,
			saved,
			Phase::Restored,
			Some(decision),
			bytes.clone(),
			bytes,
			window.deadline,
		)
		.await?;
		Ok::<_, anyhow::Error>(())
	}
	.await;
	if let Err(error) = readback {
		note(errors, "original_window_restored_forward", error);
	}
	Restoration {
		receipt,
		fresh_bytes_and_capsule: true,
	}
}

struct Completion {
	candidate: Value,
	restoration: Restoration,
	errors: Vec<Value>,
	recovery: bool,
	no_publication: bool,
	reused: bool,
	prior_forward_results: u64,
}

fn observation<'a>(phase: &'a Value, name: &str) -> &'a Value {
	phase["observations"]
		.as_array()
		.and_then(|rows| rows.iter().find(|row| row["name"] == name))
		.unwrap_or(&Value::Null)
}

async fn report(
	saved: &Saved,
	decision: Option<&Decision>,
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
		reused,
		prior_forward_results,
	} = completion;
	let parent = journal::recorded(directory, Phase::Parent).await?;
	let candidate_model = journal::recorded(directory, Phase::Candidate).await?;
	let restored = journal::recorded(directory, Phase::Restored).await?;
	let ledger = journal::ledger(directory, saved, decision).await?;
	let authority_valid = match authority.revalidate().await {
		Ok(()) => true,
		Err(error) => {
			note(&mut errors, "authority_after_compensation", error);
			false
		}
	};
	let action = decision.map(|d| d.action);
	let selected_late = match action {
		Some(Action::Keep) => observation(&parent, "bridge_keep"),
		Some(Action::Sign) => observation(&candidate_model, "selected_late"),
		_ => &Value::Null,
	};
	let goal = if selected_late.is_null() {
		false
	} else {
		model::late_quote_goal_met(
			selected_late["metrics"]["correct"]
				.as_u64()
				.context("selected correct count")? as usize,
			selected_late["metrics"]["queries"]
				.as_u64()
				.context("selected query count")? as usize,
			saved.plan.input.minimum_accuracy_percent,
		)?
	};
	let original_late = observation(&parent, "original_late");
	let original_normal = observation(&parent, "original_normal");
	let scoped = observation(&candidate_model, "scoped_normal");
	let unconditional = observation(&candidate_model, "unconditional_normal");
	let scoped_retention = !scoped.is_null()
		&& scoped["metrics"]["output_sha256"] == original_normal["metrics"]["output_sha256"];
	let unconditional_retention = evaluation::no_lost_correct_or_ce(original_normal, unconditional);
	let outputs_restored = evaluation::valid(&parent)
		&& evaluation::valid(&restored)
		&& observation(&restored, "restored_late")["metrics"]["output_sha256"]
			== original_late["metrics"]["output_sha256"]
		&& observation(&restored, "restored_normal")["metrics"]["output_sha256"]
			== original_normal["metrics"]["output_sha256"];
	let inverse_verified = restoration.fresh_bytes_and_capsule
		&& restoration.receipt["sha256"] == saved.plan.parent_function.artifact_sha256
		&& decision.is_some_and(|d| {
			restoration.receipt["source_sha256"] == saved.plan.function(d.action).artifact_sha256
		});
	let qualified = goal
		&& scoped_retention
		&& outputs_restored
		&& inverse_verified
		&& evaluation::valid(&parent)
		&& evaluation::valid(&candidate_model)
		&& authority_valid
		&& errors.is_empty();
	let status = if qualified {
		"RESEARCH_TASK_SCOPED_VERIFIED"
	} else if action == Some(Action::Abstain) {
		"ABSTAIN_NO_ADMISSIBLE_EDIT"
	} else if inverse_verified {
		"REJECTED_AND_FUNCTION_RESTORED"
	} else if no_publication {
		"NO_CANDIDATE_PUBLICATION"
	} else {
		"RECOVERY_REQUIRED"
	};
	let report = json!({"schema":"hepta.late-quote.roundtrip.v1","journal_id":saved.journal_id,"plan_sha256":saved.plan_sha256,"attempt_sha256":saved.sha()?,
		"status":status,"fixed_scope":SCOPE,"selected_action":action.map(Action::name),"decision":decision,"candidate":candidate,"restoration":restoration.receipt,
		"parent_evaluation":parent,"candidate_evaluation":candidate_model,"restored_evaluation":restored,
		"candidate_goal_met":goal,"scoped_original_graph_retention_byte_equal":scoped_retention,
		"scoped_retention_uses_same_selected_weights":true,"scoped_retention_requires_conditional_graph_routing":true,
		"unconditional_graph_retention_passed":unconditional_retention,
		"unconditional_graph_accepted":goal && unconditional_retention && inverse_verified && outputs_restored && evaluation::valid(&parent) && evaluation::valid(&candidate_model) && authority_valid && errors.is_empty(),
		"weights_graph_route_initial_state_and_evaluator_restored":inverse_verified,"fresh_restored_complete_outputs_equal":outputs_restored,
		"research_roundtrip_verified":qualified,"candidate_publication_absent_verified":no_publication,"session_authority_valid_after_effect":authority_valid,
		"attempt_ledger":ledger,"budget":saved.plan.budget,"errors":errors,
		"original_preparation_wall_seconds":saved.preparation_wall_seconds,
		"original_window":{"created_unix_ms":saved.created_unix_ms,"expires_unix_ms":saved.expires_unix_ms,"native_boot_clock":saved.native_boot_clock,"restarted_on_recovery":false},
		"new_complete_forward_results_this_request":ledger["completed_forward_calls_with_durable_results"].as_u64().context("ledger forward count")?.checked_sub(prior_forward_results).context("ledger count moved backward")?,
		"original_running_executable_sha256":saved.plan.running_executable_sha256,"original_evaluator_source_sha256":saved.plan.evaluator_source,
		"explicit_recovery":recovery,"reused_original_result":reused,"parent_or_candidate_forward_replayed":false,
		"original_source_path_opened":!recovery && !reused,"pure_compiler_invocations_this_request":if recovery||reused {0}else{1},
		"selection_replayed_on_recovery":false,"source_modified":false,"shared_model_activated":false,"production_eligible":false,
		"optimizer_steps":0,"global_ndu_optimality_verified":false,"upstream_provenance_verified":false,
		"scope_limit":"fixed lower-quote task, six-tick reset graph, source-bound F32 kernel and measured batches; no arbitrary-network or trading-profit claim"});
	ensure!(
		serde_json::to_vec(&report)?.len() as u64 <= RESULT_BYTES,
		"late-quote final result cap"
	);
	Ok(report)
}

async fn no_unselected_publication(
	saved: &Saved,
	decision: Option<&Decision>,
	root: &Path,
) -> Result<()> {
	for action in [Action::Keep, Action::Sign] {
		if action == Action::Sign && !saved.plan.sign_admissible {
			continue;
		}
		if decision.is_some_and(|d| d.action == action) {
			continue;
		}
		ensure!(
			!inverse::available(root, saved.manifest(action)?).await?,
			"an unselected semantic candidate was published outside the one-shot decision"
		);
	}
	Ok(())
}

async fn final_record(directory: &Path, report: &Value, recovery: bool) -> Result<()> {
	if report["weights_graph_route_initial_state_and_evaluator_restored"] == true
		|| report["candidate_publication_absent_verified"] == true
	{
		journal::write(
			directory,
			if recovery {
				"late-recovery.json"
			} else {
				"late-result.json"
			},
			report,
			RESULT_BYTES,
		)
		.await?;
	}
	Ok(())
}

pub(super) async fn roundtrip(
	input: Input,
	id: String,
	authority: Authority,
	roots: Vec<PathBuf>,
	state: PathBuf,
) -> Result<Value> {
	let deadline = model::Deadline::new(Duration::from_secs(ATTEMPT_SECONDS));
	let stamp = clock::begin().await?;
	let created = journal::now_ms()?;
	authority.revalidate().await?;
	let root = store_root(&state).await?;
	let _lock = lock_store(&root).await?;
	let directory = state.join("weight-cohort-journal-v1").join(&id);
	if journal::exists(&state.join("weight-cohort-journal-v1"), &id).await? {
		let (_, saved) = journal::load(&state, &roots, &id, &authority).await?;
		ensure!(
			serde_json::to_vec(&saved.plan.input)? == serde_json::to_vec(&input)?,
			"original attempt cannot substitute another input or goal"
		);
		ensure!(
			journal::exists(&directory, "late-result.json").await?
				|| journal::exists(&directory, "late-recovery.json").await?,
			"original attempt is uncertain; explicitly recover its same journal and plan"
		);
		return reconcile(saved, directory, &root, &authority, true).await;
	}
	let prepared = tokio::time::timeout(
		deadline.remaining()?,
		compiler::preflight(input, &authority, &roots, &state),
	)
	.await
	.context("original late-quote preparation window")??
	.context("semantic compiler abstained; no attempt admitted")?;
	ensure!(
		prepared.plan.id()? == id,
		"source, task, executable or original prepared plan changed"
	);
	let saved = Saved::new(&prepared, created, stamp)?;
	saved.validate(&id, &authority, &roots, &state)?;
	let directory = journal_directory(&state, &id).await?;
	journal::write(
		&directory,
		"late-intent.json",
		&serde_json::to_value(&saved)?,
		MAX_MANIFEST_BYTES,
	)
	.await?;
	journal::write(&directory, "late-intent-seal.json", &saved.seal()?, 4096).await?;
	let mut errors = Vec::new();
	let mut decision = None;
	let mut candidate = Value::Null;
	let parent = async {
		authority.revalidate().await?;
		evaluation::run(
			&directory,
			&saved,
			Phase::Parent,
			None,
			prepared.parent.clone(),
			prepared.parent.clone(),
			&deadline,
		)
		.await
	}
	.await;
	match parent {
		Ok(value) if evaluation::valid(&value) => {
			let selected = Decision::from_original_observation(&saved, &value)?;
			journal::write(
				&directory,
				"late-decision.json",
				&serde_json::to_value(&selected)?,
				4096,
			)
			.await?;
			test_boundary("decision-sealed").await?;
			decision = Some(selected);
		}
		Ok(_) => note(
			&mut errors,
			"parent_phase",
			anyhow!("parent phase failed its complete physical gate"),
		),
		Err(error) => note(&mut errors, "parent_phase", error),
	}
	if let Some(selected) = decision.as_ref().filter(|d| d.action != Action::Abstain) {
		let publication = async {
			authority.revalidate().await?;
			saved.remaining().await?;
			deadline.check()?;
			let cohort = match selected.action {
				Action::Keep => prepared.keep,
				Action::Sign => prepared.sign.context("SIGN was not admitted")?,
				Action::Abstain => bail!("ABSTAIN publication forbidden"),
			};
			let child = journal_directory(&state, &cohort.manifest.request.request_id).await?;
			publish_prepared(
				cohort,
				&root,
				&child,
				inverse::candidate_intent(&saved, selected)?,
				Boundary::None,
			)
			.await
		}
		.await;
		if let Err(error) = publication {
			note(&mut errors, "candidate_publication", error);
		}
		match inverse::candidate_receipt(&root, &saved, selected).await {
			Ok(Some(value)) => candidate = value,
			Ok(None) => {}
			Err(error) => note(&mut errors, "candidate_reconciliation", error),
		}
		if candidate.is_object() {
			test_boundary("candidate-published").await?;
			#[cfg(all(test, target_os = "linux"))]
			tests::after_publication(&directory, &candidate).await;
			let evaluated = async {
				authority.revalidate().await?;
				let bytes = actual_bytes(
					&saved,
					&saved.manifest(selected.action)?.artifact_id,
					&selected.selected_function.artifact_sha256,
				)
				.await?;
				evaluation::run(
					&directory,
					&saved,
					Phase::Candidate,
					Some(selected),
					prepared.parent,
					bytes,
					&deadline,
				)
				.await
			}
			.await;
			if let Err(error) = evaluated {
				note(&mut errors, "candidate_phase", error);
			}
		}
	}
	let mut no_publication = match no_unselected_publication(&saved, decision.as_ref(), &root).await
	{
		Ok(()) => true,
		Err(error) => {
			note(&mut errors, "unselected_candidate_scope", error);
			false
		}
	};
	let restoration =
		if let Some(selected) = decision.as_ref().filter(|d| d.action != Action::Abstain) {
			match inverse::available(&root, saved.manifest(selected.action)?).await {
				Ok(false) => Restoration {
					receipt: Value::Null,
					fresh_bytes_and_capsule: false,
				},
				present => {
					no_publication = false;
					if let Err(error) = present {
						note(&mut errors, "candidate_presence", error);
					}
					compensate(
						&saved,
						selected,
						&directory,
						&root,
						&authority,
						ForwardWindow {
							deadline: &deadline,
							allow_new_phase: true,
						},
						&mut errors,
					)
					.await
				}
			}
		} else {
			Restoration {
				receipt: Value::Null,
				fresh_bytes_and_capsule: false,
			}
		};
	let result = report(
		&saved,
		decision.as_ref(),
		&directory,
		&authority,
		Completion {
			candidate,
			restoration,
			errors,
			recovery: false,
			no_publication,
			reused: false,
			prior_forward_results: 0,
		},
	)
	.await?;
	final_record(&directory, &result, false).await?;
	#[cfg(all(test, target_os = "linux"))]
	tests::completed(&result);
	Ok(result)
}

async fn reconcile(
	saved: Saved,
	directory: PathBuf,
	root: &Path,
	authority: &Authority,
	reused: bool,
) -> Result<Value> {
	let decision = journal::decision(&directory, &saved).await?;
	// Verify all original charges and observations before consulting the original time window.
	let prior_forward_results = journal::ledger(&directory, &saved, decision.as_ref()).await?
		["completed_forward_calls_with_durable_results"]
		.as_u64()
		.context("original forward count")?;
	no_unselected_publication(&saved, decision.as_ref(), root).await?;
	let mut candidate = Value::Null;
	let mut no_publication = true;
	let mut errors = Vec::new();
	let deadline = model::Deadline::new(Duration::from_secs(PHASE_SECONDS));
	let restoration =
		if let Some(selected) = decision.as_ref().filter(|d| d.action != Action::Abstain) {
			match inverse::candidate_receipt(root, &saved, selected).await {
				Ok(Some(value)) => {
					candidate = value;
					no_publication = false;
				}
				Ok(None) => {}
				Err(error) => {
					no_publication = false;
					note(&mut errors, "candidate_reconciliation", error);
				}
			}
			let previous = inverse::already_restored(root, &saved, selected).await;
			if no_publication && matches!(&previous, Ok(None)) {
				Restoration {
					receipt: Value::Null,
					fresh_bytes_and_capsule: false,
				}
			} else {
				if let Err(error) = previous {
					note(&mut errors, "inverse_reconciliation", error);
				}
				compensate(
					&saved,
					selected,
					&directory,
					root,
					authority,
					ForwardWindow {
						deadline: &deadline,
						allow_new_phase: !reused,
					},
					&mut errors,
				)
				.await
			}
		} else {
			Restoration {
				receipt: Value::Null,
				fresh_bytes_and_capsule: false,
			}
		};
	let result = report(
		&saved,
		decision.as_ref(),
		&directory,
		authority,
		Completion {
			candidate,
			restoration,
			errors,
			recovery: true,
			no_publication,
			reused,
			prior_forward_results,
		},
	)
	.await?;
	if !reused {
		final_record(&directory, &result, true).await?;
	}
	Ok(result)
}

pub(super) async fn recover(
	id: String,
	expected_plan: String,
	authority: Authority,
	roots: Vec<PathBuf>,
	state: PathBuf,
) -> Result<Value> {
	authority.revalidate().await?;
	let root = state.join("weight-artifacts-v1");
	verify_private_directory(&root).await?;
	let _lock = lock_store(&root).await?;
	let (directory, saved) = journal::load(&state, &roots, &id, &authority).await?;
	ensure!(
		saved.plan_sha256 == expected_plan,
		"recovery cannot substitute a different prebound finite plan"
	);
	let reused = journal::exists(&directory, "late-recovery.json").await?
		|| journal::exists(&directory, "late-result.json").await?;
	reconcile(saved, directory, &root, &authority, reused).await
}
