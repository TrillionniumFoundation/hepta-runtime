// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Read an already durable guard intent while retaining its original cross-process owner lock.
//! No parent model is opened, no guard is replayed and no journal record is changed.

use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::super::{rea_evidence, weight_config, weight_guard::GuardedPatchParams};
use super::linux::{self, Journal, MAX_CANDIDATE_BYTES, MAX_RECORD_BYTES, MAX_REQUEST_BYTES};
use crate::mcp::rea_model::session::weight::SessionAuthority;

struct HeldIntent {
	journal: Journal,
	entry: File,
	id: String,
	intent: Vec<u8>,
	candidate: Option<Vec<u8>>,
	completion: Option<Vec<u8>>,
}

/// This handle cannot be deserialized or constructed without the original journal admission.
pub(in crate::mcp) struct LockedIntent {
	pub request: GuardedPatchParams,
	pub intent_sha256: String,
	pub candidate_artifact_id: Option<String>,
	pub recorded_candidate_sha256: Option<String>,
	pub original_completion_present: bool,
	held: Arc<HeldIntent>,
}

impl LockedIntent {
	/// Recheck pinned entry bytes and namespace identity before and after inverse publication.
	pub async fn revalidate(&self) -> Result<()> {
		let held = Arc::clone(&self.held);
		tokio::task::spawn_blocking(move || {
			held.journal
				.check_entry(&held.id, &held.entry, &held.intent)?;
			if linux::read_optional(&held.entry, "candidate.json", MAX_CANDIDATE_BYTES)?
				!= held.candidate
				|| linux::read_optional(&held.entry, "completion.json", MAX_RECORD_BYTES)?
					!= held.completion
			{
				bail!("original guard records changed during source-bound recovery");
			}
			Ok::<_, anyhow::Error>(())
		})
		.await
		.context("guard recovery intent revalidation task failed")?
	}
}

fn check_record(record: &Value, schema: &str, id: &str, intent_sha: &str) -> Result<()> {
	if record["schema"] != schema
		|| record["journal_id"] != id
		|| record["intent_sha256"] != intent_sha
		|| record["guard_semantics"] != linux::VERSION
	{
		bail!("original guard recovery record differs from its exact intent identity");
	}
	Ok(())
}

/// Lock only an existing original guard journal. An absent or busy owner is an error, never a
/// reason to create a new intent, replay a parent forward or publish a replacement candidate.
pub(in crate::mcp) async fn lock_existing(
	id: &str,
	roots: &[PathBuf],
	state: &Path,
) -> Result<LockedIntent> {
	lock_existing_scoped(id, roots, state, None).await
}

pub(in crate::mcp) async fn lock_existing_for_session(
	id: &str,
	roots: &[PathBuf],
	state: &Path,
	authority: &SessionAuthority,
) -> Result<LockedIntent> {
	authority.revalidate().await?;
	lock_existing_scoped(id, roots, state, Some(authority.clone())).await
}

async fn lock_existing_scoped(
	id: &str,
	roots: &[PathBuf],
	state: &Path,
	authority: Option<SessionAuthority>,
) -> Result<LockedIntent> {
	let intent_sha = id
		.strip_prefix("wgj1_")
		.filter(|sha| weight_config::valid_sha256(sha))
		.ok_or_else(|| anyhow!("source-bound recovery requires an existing wgj1 journal identity"))?
		.to_owned();
	if roots.is_empty() || roots.len() > 64 {
		bail!("guard recovery requires the original bounded workspace roots");
	}
	let journal = Journal::open_existing(state).await?;
	let id = id.to_owned();
	let roots = roots.to_vec();
	let state = state.to_owned();
	tokio::task::spawn_blocking(move || {
		let entry = linux::open_at(
			journal.root_descriptor(),
			&id,
			libc::O_RDONLY | libc::O_DIRECTORY,
			0,
		)?;
		linux::owned_directory(&entry)?;
		let intent = linux::read_optional(&entry, "intent.json", MAX_REQUEST_BYTES)?
			.ok_or_else(|| anyhow!("original guard intent is missing"))?;
		let saved = rea_evidence::parse_unique_json(&intent)?;
		let expected_authority = authority.as_ref().map(serde_json::to_value).transpose()?;
		if linux::digest(&intent) != intent_sha
			|| saved["schema"] != "hepta.weight.guard-intent.v1"
			|| saved["guard_semantics"] != linux::VERSION
			|| saved["state_dir"] != json!(state)
			|| saved["workspace_roots"] != json!(roots)
			|| saved["source_fingerprint_is_complete_execution_closure"] != false
			|| saved.get("session_authority") != expected_authority.as_ref()
		{
			bail!("original guard intent, canonical roots or state binding differs");
		}
		let request: GuardedPatchParams = serde_json::from_value(saved["request"].clone())?;
		if let Some(authority) = &authority {
			authority.authorize_guard(&request)?;
		}
		journal.check_entry(&id, &entry, &intent)?;
		let candidate = linux::read_optional(&entry, "candidate.json", MAX_CANDIDATE_BYTES)?;
		let (candidate_artifact_id, recorded_candidate_sha256) = if let Some(bytes) = &candidate {
			let record = rea_evidence::parse_unique_json(bytes)?;
			check_record(&record, "hepta.weight.guard-candidate.v1", &id, &intent_sha)?;
			let receipt = &record["candidate"];
			if receipt["schema"] != "hepta.weight.native-artifact-receipt.v1"
				|| receipt["kind"] != "patch"
				|| receipt["source_sha256"] != request.patch.expected_sha256
				|| receipt["source_modified"] != false
				|| receipt["production_eligible"] != false
			{
				bail!("original guard candidate receipt source or scope differs from its intent");
			}
			let id = receipt["artifact_id"]
				.as_str()
				.ok_or_else(|| anyhow!("original guard candidate record has no artifact ID"))?;
			let target = receipt["sha256"]
				.as_str()
				.filter(|sha| weight_config::valid_sha256(sha))
				.ok_or_else(|| {
					anyhow!("original guard candidate record has no complete target hash")
				})?;
			(Some(id.to_owned()), Some(target.to_owned()))
		} else {
			(None, None)
		};
		let completion = linux::read_optional(&entry, "completion.json", MAX_RECORD_BYTES)?;
		if let Some(bytes) = &completion {
			let record = rea_evidence::parse_unique_json(bytes)?;
			check_record(
				&record,
				"hepta.weight.guard-completion.v1",
				&id,
				&intent_sha,
			)?;
			if !matches!(
				record["mode"].as_str(),
				Some("evaluation" | "interrupted_recovery")
			) {
				bail!("original guard completion has unknown semantics");
			}
		}
		Ok(LockedIntent {
			request,
			intent_sha256: intent_sha,
			candidate_artifact_id,
			recorded_candidate_sha256,
			original_completion_present: completion.is_some(),
			held: Arc::new(HeldIntent {
				journal,
				entry,
				id,
				intent,
				candidate,
				completion,
			}),
		})
	})
	.await
	.context("existing guard intent read task failed")?
}
