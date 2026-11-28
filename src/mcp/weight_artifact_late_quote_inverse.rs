// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Canonical graph-and-weight inverse through the existing cohort store and journal.
//! Same checkpoint SHA is not a restoration shortcut: the function capsule must change.

use super::*;
use journal::{Decision, Saved};

fn identity(
	manifest: &CohortManifest,
	research: &Value,
	implementation: &str,
	roots: &[PathBuf],
	state: &Path,
) -> Result<String> {
	Ok(digest(&serde_json::to_vec(
		&json!({"request":manifest.request,"roots":roots,"state":state,"implementation":implementation,
		"parent":manifest.parent_artifact_id,"restored_sha":manifest.restored_source_sha256,"research":research}),
	)?))
}

fn research(
	saved: &Saved,
	decision: &Decision,
	inverse: bool,
	implementation: &str,
) -> Result<Value> {
	Ok(
		json!({"schema":"hepta.late-quote.cohort-intent.v1","original_journal_id":saved.journal_id,"original_plan_sha256":saved.plan_sha256,
		"original_decision_sha256":decision.sha()?,"inverse":inverse,"cohort_implementation":implementation,
		"function_capsule":saved.plan.function_binding(decision.action,inverse)?}),
	)
}

pub(super) fn candidate_intent(saved: &Saved, decision: &Decision) -> Result<Intent> {
	let manifest = saved.manifest(decision.action)?;
	original_intent(
		manifest,
		&serde_json::to_vec(manifest)?,
		&saved.plan.roots,
		&saved.plan.state,
		Some(research(
			saved,
			decision,
			false,
			&saved.plan.cohort_implementation,
		)?),
	)
}

async fn retained_intent(
	directory: &Path,
	manifest: &CohortManifest,
	saved: &Saved,
	decision: &Decision,
	inverse: bool,
	roots: &[PathBuf],
) -> Result<Option<Intent>> {
	if !journal::exists(directory, "intent.json").await? {
		return Ok(None);
	}
	let intent: Intent =
		serde_json::from_value(journal::read(directory, "intent.json", MAX_MANIFEST_BYTES).await?)?;
	let actual = intent
		.research
		.as_ref()
		.context("semantic cohort requires original research binding")?;
	let implementation = actual["cohort_implementation"]
		.as_str()
		.context("saved cohort implementation")?;
	ensure!(
		crate::mcp::weight_config::valid_sha256(implementation)
			&& (inverse || implementation == saved.plan.cohort_implementation)
			&& actual == &research(saved, decision, inverse, implementation)?
			&& intent.schema == "hepta.weight.cohort-intent.v1"
			&& intent.artifact_id == manifest.artifact_id
			&& intent.manifest_sha256 == digest(&serde_json::to_vec(manifest)?)
			&& intent.request_digest
				== identity(manifest, actual, implementation, roots, &saved.plan.state)?,
		"original semantic cohort intent differs"
	);
	Ok(Some(intent))
}

pub(super) async fn available(root: &Path, expected: &CohortManifest) -> Result<bool> {
	if !journal::exists(root, &expected.artifact_id).await? {
		return Ok(false);
	}
	let actual = read_cohort(root, &expected.artifact_id).await?;
	ensure!(
		serde_json::to_vec(&actual)? == serde_json::to_vec(expected)?,
		"retained artifact changed its exact weights or semantic capsule"
	);
	Ok(true)
}

async fn receipt(
	root: &Path,
	directory: &Path,
	manifest: &CohortManifest,
	intent: &Intent,
) -> Result<Value> {
	ensure!(
		available(root, manifest).await?,
		"published semantic artifact is missing"
	);
	let completed = journal::exists(directory, "outcome.json").await?;
	journal::write(directory,"outcome.json",&json!({"schema":"hepta.weight.cohort-outcome.v1","intent":intent,"target_sha256":manifest.target_sha256,"all_members_verified":true}),MAX_MANIFEST_BYTES).await?;
	let mut value = cohort_receipt(manifest, root, directory, true, completed);
	value["function_capsule"] = serde_json::to_value(&manifest.research_binding)?;
	Ok(value)
}

pub(super) async fn candidate_receipt(
	root: &Path,
	saved: &Saved,
	decision: &Decision,
) -> Result<Option<Value>> {
	let manifest = saved.manifest(decision.action)?;
	let directory = saved
		.plan
		.state
		.join("weight-cohort-journal-v1")
		.join(&manifest.request.request_id);
	if !available(root, manifest).await? {
		ensure!(
			!journal::exists(&directory, "outcome.json").await?,
			"completed candidate disappeared; republication is forbidden"
		);
		return Ok(None);
	}
	verify_private_directory(&directory).await?;
	let intent = retained_intent(
		&directory,
		manifest,
		saved,
		decision,
		false,
		&saved.plan.roots,
	)
	.await?
	.context("candidate publication lacks original intent")?;
	Ok(Some(receipt(root, &directory, manifest, &intent).await?))
}

pub(super) fn inverse_manifest(
	saved: &Saved,
	decision: &Decision,
	root: &Path,
) -> Result<CohortManifest> {
	let candidate = saved.manifest(decision.action)?;
	let mut inverse = candidate.clone();
	inverse.request.request_id = digest(&serde_json::to_vec(
		&json!({"schema":"hepta.late-quote.inverse-key.v1","original_id":saved.journal_id,"decision_sha256":decision.sha()?,"candidate_artifact_id":candidate.artifact_id}),
	)?);
	inverse.request.path = root
		.join(&candidate.artifact_id)
		.join("model.safetensors")
		.to_string_lossy()
		.into_owned();
	inverse.request.expected_sha256 = candidate.target_sha256.clone();
	for member in &mut inverse.request.members {
		for word in &mut member.edits {
			std::mem::swap(&mut word.expected_hex, &mut word.replacement_hex);
		}
	}
	for patch in &mut inverse.patches {
		for change in &mut patch.changes {
			std::mem::swap(&mut change.expected_hex, &mut change.replacement_hex);
		}
	}
	inverse.target_sha256 = candidate.request.expected_sha256.clone();
	inverse.parent_artifact_id = Some(candidate.artifact_id.clone());
	inverse.restored_source_sha256 = Some(candidate.request.expected_sha256.clone());
	inverse.research_binding = Some(saved.plan.function_binding(decision.action, true)?);
	inverse.artifact_id = manifest_id(&inverse)?;
	ensure!(
		inverse.artifact_id != candidate.artifact_id
			&& inverse.research_binding != candidate.research_binding,
		"graph inverse must have its own original-function capsule, including zero changed bytes"
	);
	Ok(inverse)
}

pub(super) async fn already_restored(
	root: &Path,
	saved: &Saved,
	decision: &Decision,
) -> Result<Option<Value>> {
	let expected = inverse_manifest(saved, decision, root)?;
	if !available(root, &expected).await? {
		return Ok(None);
	}
	let directory = saved
		.plan
		.state
		.join("weight-cohort-journal-v1")
		.join(&expected.request.request_id);
	verify_private_directory(&directory).await?;
	let intent = retained_intent(
		&directory,
		&expected,
		saved,
		decision,
		true,
		&[root.to_owned()],
	)
	.await?
	.context("published inverse lacks original durable intent")?;
	Ok(Some(receipt(root, &directory, &expected, &intent).await?))
}

pub(super) async fn restore(root: &Path, saved: &Saved, decision: &Decision) -> Result<Value> {
	if let Some(receipt) = already_restored(root, saved, decision).await? {
		return Ok(receipt);
	}
	ensure!(
		available(root, saved.manifest(decision.action)?).await?,
		"candidate missing; inverse cannot recreate or replay it"
	);
	let expected = inverse_manifest(saved, decision, root)?;
	let prepared = prepare_with_roots(
		expected.request.clone(),
		&[root.to_owned()],
		expected.parent_artifact_id.clone(),
		expected.restored_source_sha256.clone(),
		expected.research_binding.clone(),
	)
	.await?;
	ensure!(
		prepared.manifest_bytes == serde_json::to_vec(&expected)?,
		"canonical inverse differs from the saved exact graph-and-weight reverse"
	);
	let directory = journal_directory(&saved.plan.state, &expected.request.request_id).await?;
	let intent = match retained_intent(
		&directory,
		&expected,
		saved,
		decision,
		true,
		&[root.to_owned()],
	)
	.await?
	{
		Some(intent) => intent,
		None => original_intent(
			&expected,
			&prepared.manifest_bytes,
			&[root.to_owned()],
			&saved.plan.state,
			Some(research(saved, decision, true, &cohort_implementation())?),
		)?,
	};
	publish_prepared(prepared, root, &directory, intent, Boundary::None).await?;
	already_restored(root, saved, decision)
		.await?
		.context("inverse publication did not retain the original function capsule")
}
