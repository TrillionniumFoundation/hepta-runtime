// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Exact inverse under the held original cohort lock, independent of the workspace source.
//! Previously published inverses are reconciled using their saved original intent identity.

use super::*;

fn inverse_manifest(saved: &journal::Saved, root: &Path) -> Result<CohortManifest> {
	let mut inverse = saved.manifest.clone();
	inverse.request.request_id = digest(&serde_json::to_vec(&json!({
		"schema":"hepta.smallhcsn.inverse-key.v1","original_request_id":saved.id(),
		"original_artifact_id":saved.manifest.artifact_id
	}))?);
	inverse.request.path = root
		.join(&saved.manifest.artifact_id)
		.join("model.safetensors")
		.to_string_lossy()
		.into_owned();
	inverse.request.expected_sha256 = saved.manifest.target_sha256.clone();
	inverse.request.training = TrainingContract::InferenceOnly;
	for member in &mut inverse.request.members {
		for edit in &mut member.edits {
			std::mem::swap(&mut edit.expected_hex, &mut edit.replacement_hex);
		}
	}
	for patch in &mut inverse.patches {
		for change in &mut patch.changes {
			std::mem::swap(&mut change.expected_hex, &mut change.replacement_hex);
		}
	}
	inverse.target_sha256 = saved.manifest.request.expected_sha256.clone();
	inverse.parent_artifact_id = Some(saved.manifest.artifact_id.clone());
	inverse.restored_source_sha256 = Some(saved.manifest.request.expected_sha256.clone());
	inverse.artifact_id = manifest_id(&inverse)?;
	Ok(inverse)
}

fn inverse_research(saved: &journal::Saved, cohort_implementation: &str) -> Value {
	json!({"schema":"hepta.smallhcsn.inverse-intent.v1",
		"original_request_id":saved.id(),"original_artifact_id":saved.manifest.artifact_id,
		"authority":saved.authority,"cohort_implementation":cohort_implementation,
		"research_binding":saved.manifest.research_binding})
}

async fn retained_intent(
	directory: &Path,
	expected: &CohortManifest,
	saved: &journal::Saved,
	root: &Path,
) -> Result<Option<Intent>> {
	if !journal::exists(directory, "intent.json").await? {
		return Ok(None);
	}
	let intent: Intent =
		serde_json::from_value(journal::read(directory, "intent.json", MAX_MANIFEST_BYTES).await?)?;
	let research = intent
		.research
		.as_ref()
		.context("bound inverse requires its original research intent")?;
	let implementation = research["cohort_implementation"]
		.as_str()
		.context("saved inverse implementation")?;
	ensure!(
		crate::mcp::weight_config::valid_sha256(implementation)
			&& research == &inverse_research(saved, implementation)
			&& intent.schema == "hepta.weight.cohort-intent.v1"
			&& intent.artifact_id == expected.artifact_id
			&& intent.manifest_sha256 == digest(&serde_json::to_vec(expected)?)
			&& intent.request_digest
				== journal::identity(
					expected,
					research,
					implementation,
					&[root.to_owned()],
					&saved.state
				)?,
		"saved inverse differs from its original authority, artifact or request"
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
		"actual retained artifact differs from its original complete bound manifest"
	);
	Ok(true)
}

async fn finish_receipt(
	root: &Path,
	directory: &Path,
	manifest: &CohortManifest,
	intent: &Intent,
) -> Result<Value> {
	ensure!(
		available(root, manifest).await?,
		"original inverse artifact is missing"
	);
	let completed = journal::exists(directory, "outcome.json").await?;
	let outcome = json!({"schema":"hepta.weight.cohort-outcome.v1","intent":intent,
		"target_sha256":manifest.target_sha256,"all_members_verified":true});
	journal::write(directory, "outcome.json", &outcome, MAX_MANIFEST_BYTES).await?;
	Ok(cohort_receipt(manifest, root, directory, true, completed))
}

pub(super) async fn already_restored(saved: &journal::Saved, root: &Path) -> Result<Option<Value>> {
	let expected = inverse_manifest(saved, root)?;
	let directory = saved
		.state
		.join("weight-cohort-journal-v1")
		.join(&expected.request.request_id);
	if !journal::exists(root, &expected.artifact_id).await? {
		return Ok(None);
	}
	verify_private_directory(&directory).await?;
	let intent = retained_intent(&directory, &expected, saved, root)
		.await?
		.context("published inverse has no original durable intent")?;
	Ok(Some(
		finish_receipt(root, &directory, &expected, &intent).await?,
	))
}

pub(super) async fn restore(saved: &journal::Saved, root: &Path) -> Result<Value> {
	if let Some(receipt) = already_restored(saved, root).await? {
		return Ok(receipt);
	}
	ensure!(
		available(root, &saved.manifest).await?,
		"candidate missing; inverse cannot recreate it or replay a model"
	);
	let expected = inverse_manifest(saved, root)?;
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
		"canonical inverse compiler differs from the exact original reverse"
	);
	let directory = journal_directory(&saved.state, &expected.request.request_id).await?;
	let intent = if let Some(intent) = retained_intent(&directory, &expected, saved, root).await? {
		intent
	} else {
		original_intent(
			&expected,
			&prepared.manifest_bytes,
			&[root.to_owned()],
			&saved.state,
			Some(inverse_research(saved, &cohort_implementation())),
		)?
	};
	let receipt = publish_prepared(prepared, root, &directory, intent, Boundary::None).await?;
	ensure!(
		receipt["source_sha256"] == saved.manifest.target_sha256
			&& receipt["sha256"] == saved.manifest.request.expected_sha256
			&& receipt["source_modified"] == false
			&& receipt["production_eligible"] == false,
		"inverse receipt failed its complete original parent identity"
	);
	Ok(receipt)
}
