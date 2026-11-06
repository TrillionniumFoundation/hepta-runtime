// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0

//! Bounded immutable checkpoint transactions under verified credential scope.
//! Content identity includes payload, private retention metadata and authority.

use super::{ListParams, ResumeParams, Scope};
use crate::mcp::rea_evidence_session::{CheckpointCandidate, EvidenceSession};
use crate::mcp::runtime::effect_owner_fence::AdmissionPermit;
use crate::mcp::{rea_evidence, rea_evidence_file};
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::{self, Write};
use std::sync::{Arc, OnceLock};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

#[path = "rea_evidence_checkpoint_store.rs"]
mod store;

const SCHEMA: &str = "hepta.rea.evidence-checkpoint.v1";
const RETENTION_SCHEMA: &str = "hepta.rea.evidence-retention.v1";
const JSON_PROFILE: &str = "hepta.rea.native-json-128m-16m-depth120.v1";
const ROOT_NAME: &str = "rea-evidence-checkpoints-v1";
const ID_PREFIX: &str = "ecp1_";
const MAX_CHECKPOINTS: usize = 32;
const MAX_RECORDS: usize = 2048;
const MAX_UNKNOWN_REVISIONS: usize = 8192;
const MAX_BUNDLE_BYTES: usize = 128 * 1024 * 1024;
const MAX_SIDECAR_BYTES: usize = 16 * 1024 * 1024;
const MAX_MANIFEST_BYTES: usize = 4096;
const MAX_STORE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_CONCURRENT_OWNERS: usize = 2;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
	schema: String,
	retention_schema: String,
	json_profile: String,
	owner_sha256: String,
	policy_sha256: String,
	bundle_sha256: String,
	bundle_bytes: usize,
	retention_sha256: String,
	retention_bytes: usize,
	records: usize,
	unknown_revisions: usize,
}

fn hash(bytes: &[u8]) -> String {
	Sha256::digest(bytes)
		.iter()
		.map(|byte| format!("{byte:02x}"))
		.collect()
}

fn valid_sha(value: &str) -> bool {
	value.len() == 64
		&& value
			.bytes()
			.all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_id(value: &str) -> bool {
	value.strip_prefix(ID_PREFIX).is_some_and(valid_sha)
}

fn owner_binding(scope: &Scope) -> Result<String> {
	ensure!(
		valid_sha(&scope.owner) && valid_sha(&scope.policy),
		"trusted checkpoint owner or current policy is unavailable"
	);
	Ok(hash(format!("{SCHEMA}\0owner\0{}", scope.owner).as_bytes()))
}

fn active(cancellation: &CancellationToken) -> Result<()> {
	ensure!(
		!cancellation.is_cancelled(),
		"Evidence checkpoint operation cancelled before publication"
	);
	Ok(())
}

struct BoundedWriter<'a> {
	bytes: Vec<u8>,
	maximum: usize,
	cancellation: &'a CancellationToken,
}

impl Write for BoundedWriter<'_> {
	fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
		if self.cancellation.is_cancelled() {
			return Err(io::Error::other(
				"Evidence checkpoint cancelled during serialization",
			));
		}
		if self
			.bytes
			.len()
			.checked_add(bytes.len())
			.is_none_or(|length| length > self.maximum)
		{
			return Err(io::Error::other(format!(
				"native checkpoint serialization byte budget exceeded ({})",
				self.maximum
			)));
		}
		self.bytes
			.try_reserve(bytes.len())
			.map_err(|_| io::Error::other("native checkpoint serialization allocation failed"))?;
		self.bytes.extend_from_slice(bytes);
		Ok(bytes.len())
	}
	fn flush(&mut self) -> io::Result<()> {
		Ok(())
	}
}

fn encode(value: &Value, maximum: usize, cancellation: &CancellationToken) -> Result<Vec<u8>> {
	let mut output = BoundedWriter {
		bytes: Vec::new(),
		maximum,
		cancellation,
	};
	rea_evidence::write_canonical(value, &mut output)?;
	Ok(output.bytes)
}

struct CompareWriter<'a> {
	expected: &'a [u8],
	offset: usize,
	cancellation: &'a CancellationToken,
}

impl Write for CompareWriter<'_> {
	fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
		if self.cancellation.is_cancelled() {
			return Err(io::Error::other("checkpoint authentication cancelled"));
		}
		let end = self
			.offset
			.checked_add(bytes.len())
			.ok_or_else(|| io::Error::other("checkpoint canonical size overflow"))?;
		if self.expected.get(self.offset..end) != Some(bytes) {
			return Err(io::Error::other(
				"checkpoint JSON is not exact canonical data",
			));
		}
		self.offset = end;
		Ok(bytes.len())
	}
	fn flush(&mut self) -> io::Result<()> {
		Ok(())
	}
}

fn parse_canonical(
	bytes: &[u8],
	cancellation: &CancellationToken,
) -> Result<(Value, rea_evidence_file::ObjectOrder)> {
	let (value, order) = rea_evidence_file::parse_checkpoint_json(bytes, cancellation)?;
	let mut comparison = CompareWriter {
		expected: bytes,
		offset: 0,
		cancellation,
	};
	rea_evidence::write_canonical(&value, &mut comparison)?;
	ensure!(
		comparison.offset == bytes.len(),
		"checkpoint canonical data has trailing bytes"
	);
	Ok((value, order))
}

impl Manifest {
	fn bytes(&self, cancellation: &CancellationToken) -> Result<Vec<u8>> {
		encode(
			&serde_json::to_value(self)?,
			MAX_MANIFEST_BYTES,
			cancellation,
		)
	}
	fn id(&self, cancellation: &CancellationToken) -> Result<String> {
		Ok(format!("{ID_PREFIX}{}", hash(&self.bytes(cancellation)?)))
	}
	fn validate(&self, id: &str, cancellation: &CancellationToken) -> Result<()> {
		ensure!(valid_id(id), "checkpoint ID is invalid");
		ensure!(
			self.schema == SCHEMA
				&& self.retention_schema == RETENTION_SCHEMA
				&& self.json_profile == JSON_PROFILE,
			"checkpoint schema or native JSON profile is unsupported"
		);
		ensure!(
			[
				&self.owner_sha256,
				&self.policy_sha256,
				&self.bundle_sha256,
				&self.retention_sha256
			]
			.iter()
			.all(|value| valid_sha(value)),
			"checkpoint manifest has an invalid digest"
		);
		ensure!(
			self.bundle_bytes > 0
				&& self.bundle_bytes <= MAX_BUNDLE_BYTES
				&& self.retention_bytes > 0
				&& self.retention_bytes <= MAX_SIDECAR_BYTES
				&& self.records <= MAX_RECORDS
				&& self.unknown_revisions <= MAX_UNKNOWN_REVISIONS,
			"checkpoint manifest exceeds the native byte, record or Unknown revision profile"
		);
		ensure!(
			self.id(cancellation)? == id,
			"checkpoint manifest identity does not match its immutable locator"
		);
		Ok(())
	}
	fn authorized(&self, scope: &Scope) -> Result<bool> {
		Ok(self.owner_sha256 == owner_binding(scope)? && self.policy_sha256 == scope.policy)
	}
	fn row(&self, id: &str) -> Value {
		json!({"checkpoint_id":id,"records":self.records,"unknown_revisions":self.unknown_revisions,
			"bundle_bytes":self.bundle_bytes,"retention_bytes":self.retention_bytes})
	}
}

fn authenticate_payloads(
	manifest: &Manifest,
	bundle: &[u8],
	retention: &[u8],
	cancellation: &CancellationToken,
) -> Result<CheckpointCandidate> {
	ensure!(
		bundle.len() == manifest.bundle_bytes
			&& retention.len() == manifest.retention_bytes
			&& hash(bundle) == manifest.bundle_sha256
			&& hash(retention) == manifest.retention_sha256,
		"checkpoint payload or retention sidecar length/digest differs"
	);
	let (bundle, order) = parse_canonical(bundle, cancellation)?;
	let (retention, _) = parse_canonical(retention, cancellation)?;
	ensure!(
		bundle
			.get("records")
			.and_then(Value::as_array)
			.is_some_and(
				|records| records.len() == manifest.records && records.len() <= MAX_RECORDS
			) && bundle
			.get("unknowns")
			.and_then(Value::as_array)
			.is_some_and(|unknowns| unknowns.len() == manifest.unknown_revisions
				&& unknowns.len() <= MAX_UNKNOWN_REVISIONS),
		"checkpoint complete payload counts exceed or differ from the native manifest profile"
	);
	let candidate = CheckpointCandidate::authenticate(
		bundle,
		&order,
		retention,
		MAX_BUNDLE_BYTES,
		cancellation,
	)?;
	ensure!(
		candidate.counts() == (manifest.records, manifest.unknown_revisions),
		"checkpoint manifest counts do not match its complete authenticated state"
	);
	Ok(candidate)
}

fn read_manifest(
	directory: &mut store::Directory,
	id: &str,
	cancellation: &CancellationToken,
) -> Result<Manifest> {
	directory.require_complete()?;
	let bytes = directory.read("manifest.json", MAX_MANIFEST_BYTES, cancellation)?;
	let (value, _) = parse_canonical(&bytes, cancellation)?;
	let manifest: Manifest =
		serde_json::from_value(value).context("checkpoint manifest schema is invalid")?;
	manifest.validate(id, cancellation)?;
	directory.check_binding()?;
	Ok(manifest)
}

fn read_payloads(
	directory: &mut store::Directory,
	manifest: &Manifest,
	cancellation: &CancellationToken,
) -> Result<CheckpointCandidate> {
	let bundle = directory.read("bundle.json", MAX_BUNDLE_BYTES, cancellation)?;
	let retention = directory.read("retention.json", MAX_SIDECAR_BYTES, cancellation)?;
	let candidate = authenticate_payloads(manifest, &bundle, &retention, cancellation)?;
	directory.confirm_read()?;
	Ok(candidate)
}

async fn owned<G, T, F>(cancellation: CancellationToken, admission: G, operation: F) -> Result<T>
where
	G: Send + 'static,
	T: Send + 'static,
	F: FnOnce(&CancellationToken) -> Result<T> + Send + 'static,
{
	active(&cancellation)?;
	static CAPACITY: OnceLock<Arc<Semaphore>> = OnceLock::new();
	let capacity = Arc::clone(
		CAPACITY.get_or_init(|| Arc::new(Semaphore::new(MAX_CONCURRENT_OWNERS))),
	)
	.try_acquire_owned()
	.context(
		"native checkpoint owner capacity is occupied; wait for the actual owners to complete",
	)?;
	let stop = cancellation.child_token();
	let cancel_on_drop = stop.clone().drop_guard();
	let result = tokio::task::spawn_blocking(move || {
		let (_admission, _capacity) = (admission, capacity);
		operation(&stop)
	})
	.await;
	let _ = cancel_on_drop.disarm();
	result.context(
		"checkpoint blocking owner failed; reconcile the same immutable content identity",
	)?
}

fn checkpoint_at(
	scope: &Scope,
	session: &EvidenceSession,
	cancellation: &CancellationToken,
	hook: &dyn Fn(store::CommitPhase) -> Result<()>,
) -> Result<String> {
	active(cancellation)?;
	let snapshot = session.checkpoint_snapshot(MAX_RECORDS, MAX_UNKNOWN_REVISIONS, cancellation)?;
	let (records, unknown_revisions) = snapshot.counts();
	let mut writer = BoundedWriter {
		bytes: Vec::new(),
		maximum: MAX_BUNDLE_BYTES,
		cancellation,
	};
	snapshot.write_bundle(&mut writer)?;
	let bundle = writer.bytes;
	let retention = encode(
		&snapshot.sidecar(MAX_SIDECAR_BYTES, cancellation)?,
		MAX_SIDECAR_BYTES,
		cancellation,
	)?;
	let manifest = Manifest {
		schema: SCHEMA.into(),
		retention_schema: RETENTION_SCHEMA.into(),
		json_profile: JSON_PROFILE.into(),
		owner_sha256: owner_binding(scope)?,
		policy_sha256: scope.policy.clone(),
		bundle_sha256: hash(&bundle),
		bundle_bytes: bundle.len(),
		retention_sha256: hash(&retention),
		retention_bytes: retention.len(),
		records,
		unknown_revisions,
	};
	let id = manifest.id(cancellation)?;
	// A successful checkpoint must already be recoverable within the same
	// parser/materialization/depth profile; no over-budget success is published.
	drop(authenticate_payloads(
		&manifest,
		&bundle,
		&retention,
		cancellation,
	)?);
	let manifest_bytes = manifest.bytes(cancellation)?;
	let store = store::Store::open(scope, true, true, cancellation)?
		.context("checkpoint store was not created")?;
	let reused = if let Some(mut directory) = store.checkpoint(&id)? {
		let existing = read_manifest(&mut directory, &id, cancellation)?;
		ensure!(
			existing.authorized(scope)?,
			"checkpoint is unavailable to the current authenticated owner or policy"
		);
		drop(read_payloads(&mut directory, &existing, cancellation)?);
		store.confirm_existing()?;
		directory.confirm_read()?;
		true
	} else {
		let incoming = bundle
			.len()
			.checked_add(retention.len())
			.and_then(|size| size.checked_add(manifest_bytes.len()))
			.context("checkpoint publication size overflow")?;
		store.admit_quota(incoming as u64)?;
		store.publish(
			&id,
			[
				("bundle.json", &bundle),
				("retention.json", &retention),
				("manifest.json", &manifest_bytes),
			],
			cancellation,
			hook,
		)?;
		false
	};
	let mut receipt = manifest.row(&id);
	receipt["reused"] = json!(reused);
	receipt["durability"] = json!("file_and_directory_sync_confirmed");
	receipt["ownership_scope"] = json!("authenticated_private_operator_credential");
	receipt["authenticated_chatgpt_caller_isolation"] = json!(false);
	receipt["automatic_checkpoint"] = json!(false);
	receipt["subsequent_records_require_another_checkpoint"] = json!(true);
	Ok(serde_json::to_string(&receipt)?)
}

pub(super) async fn checkpoint(
	scope: Scope,
	session: Arc<EvidenceSession>,
	cancellation: CancellationToken,
	admission: Arc<AdmissionPermit>,
) -> Result<String> {
	owned(cancellation, admission, move |stop| {
		checkpoint_at(&scope, &session, stop, &|_| Ok(()))
	})
	.await
}

fn resume_at(
	scope: &Scope,
	params: &ResumeParams,
	session: &EvidenceSession,
	cancellation: &CancellationToken,
) -> Result<String> {
	ensure!(valid_id(&params.checkpoint_id), "checkpoint ID is invalid");
	session.require_empty_for_resume()?;
	let store = store::Store::open(scope, false, false, cancellation)?
		.context("checkpoint is unavailable to the current authenticated owner or policy")?;
	let mut directory = store
		.checkpoint(&params.checkpoint_id)?
		.context("checkpoint is unavailable to the current authenticated owner or policy")?;
	let manifest = read_manifest(&mut directory, &params.checkpoint_id, cancellation)?;
	ensure!(
		manifest.authorized(scope)?,
		"checkpoint is unavailable to the current authenticated owner or policy"
	);
	let candidate = read_payloads(&mut directory, &manifest, cancellation)?;
	let mut receipt = manifest.row(&params.checkpoint_id);
	receipt["restored"] = json!(true);
	receipt["automatic_checkpoint"] = json!(false);
	receipt["ownership_scope"] = json!("authenticated_private_operator_credential");
	receipt["authenticated_chatgpt_caller_isolation"] = json!(false);
	let encoded = serde_json::to_string(&receipt)?;
	store.confirm_existing()?;
	directory.confirm_read()?;
	// The final empty-state and cancellation checks share the publication lock.
	session.resume_if_empty(candidate, cancellation)?;
	Ok(encoded)
}

pub(super) async fn resume(
	scope: Scope,
	params: ResumeParams,
	session: Arc<EvidenceSession>,
	cancellation: CancellationToken,
	admission: Arc<AdmissionPermit>,
) -> Result<String> {
	owned(cancellation, admission, move |stop| {
		resume_at(&scope, &params, &session, stop)
	})
	.await
}

fn list_at(scope: &Scope, params: &ListParams, cancellation: &CancellationToken) -> Result<String> {
	ensure!(
		(1..=MAX_CHECKPOINTS).contains(&params.limit),
		"checkpoint list limit must be between 1 and 32"
	);
	ensure!(
		params.offset == 0 || params.expected_catalog_sha256.is_some(),
		"checkpoint continuation requires expected_catalog_sha256 from its first page"
	);
	if let Some(expected) = &params.expected_catalog_sha256 {
		ensure!(
			valid_sha(expected),
			"checkpoint expected catalog SHA-256 is invalid"
		);
	}
	let owner = owner_binding(scope)?;
	let store = store::Store::open(scope, false, false, cancellation)?;
	let mut rows = Vec::new();
	let mut ids = Vec::new();
	let mut observed = Vec::new();
	let mut original_names = Vec::new();
	if let Some(store) = &store {
		original_names = store.names()?;
		for id in &original_names {
			active(cancellation)?;
			if id.starts_with(".stage-") {
				continue;
			}
			ensure!(
				valid_id(id),
				"checkpoint store contains an invalid committed entry"
			);
			let mut directory = store
				.checkpoint(id)?
				.context("checkpoint catalog changed while its store lock was held")?;
			let manifest = read_manifest(&mut directory, id, cancellation)?;
			if !manifest.authorized(scope)? {
				continue;
			}
			// A digest-only manifest listing would miss a damaged retention file.
			// This bounded catalog verifies every visible immutable checkpoint.
			drop(read_payloads(&mut directory, &manifest, cancellation)?);
			rows.push(manifest.row(id));
			ids.push(id.clone());
			observed.push(directory);
		}
	}
	let catalog = hash(&encode(
		&json!({"schema":"hepta.rea.evidence-checkpoint-catalog.v1","owner_sha256":owner,"policy_sha256":scope.policy,"checkpoint_ids":ids}),
		64 * 1024,
		cancellation,
	)?);
	if let Some(expected) = &params.expected_catalog_sha256 {
		ensure!(
			expected == &catalog,
			"checkpoint catalog or current owner/policy changed; restart listing at offset zero"
		);
	}
	ensure!(
		params.offset <= rows.len(),
		"checkpoint list offset exceeds the verified catalog"
	);
	let end = params.offset.saturating_add(params.limit).min(rows.len());
	let result = json!({"schema":"hepta.rea.evidence-checkpoint-list.v1","catalog_sha256":catalog,
		"offset":params.offset,"limit":params.limit,"total":rows.len(),"returned":end-params.offset,
		"next_offset":if end<rows.len() {Some(end)} else {None},"exhausted":end==rows.len(),
		"checkpoints":&rows[params.offset..end],"ownership_scope":"authenticated_private_operator_credential",
		"authenticated_chatgpt_caller_isolation":false,"automatic_checkpoint":false});
	let encoded = serde_json::to_string(&result)?;
	ensure!(
		encoded.len() <= 32 * 1024,
		"checkpoint catalog response exceeds its native wire budget"
	);
	active(cancellation)?;
	if let Some(store) = store {
		store.confirm_existing()?;
		for directory in &observed {
			directory.confirm_read()?;
		}
		ensure!(
			store.names()? == original_names,
			"checkpoint catalog changed during its complete observation"
		);
	}
	Ok(encoded)
}

pub(super) async fn list(
	scope: Scope,
	params: ListParams,
	cancellation: CancellationToken,
	admission: Arc<AdmissionPermit>,
) -> Result<String> {
	owned(cancellation, admission, move |stop| {
		list_at(&scope, &params, stop)
	})
	.await
}

#[cfg(test)]
#[path = "rea_evidence_checkpoint_tests.rs"]
mod tests;
