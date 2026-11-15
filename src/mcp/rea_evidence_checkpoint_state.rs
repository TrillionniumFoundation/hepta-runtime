// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0

//! Private retention-state snapshots and authenticated empty-session restore.
//! This is deliberately separate from the frozen public import merge contract.

use super::{
	CheckpointCandidate, CheckpointSnapshot, EvidenceSession, EvidenceSnapshot, SessionRecord,
	SessionState,
};
use crate::mcp::rea_evidence_file::{ObjectOrder, StoredObjectOrder};
use crate::mcp::rea_response_encoding::JsonView;
use crate::mcp::rea_response_order::{RecordOrder, RecordOrigin};
use crate::mcp::{rea_evidence, rea_evidence_source, rea_response_encoding};
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::io::{self, Write};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

const SIDECAR_SCHEMA: &str = "hepta.rea.evidence-retention.v1";
const ORDER_PROFILE: &str = "hepta.rea.response-order.v1";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Sidecar {
	schema: String,
	order_profile: String,
	records: Vec<RetainedMetadata>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RetainedMetadata {
	evidence_id: String,
	origin: RecordOrigin,
	has_imported_order: bool,
	imported_order: Vec<StoredObjectOrder>,
}

impl EvidenceSession {
	pub(in crate::mcp) fn checkpoint_snapshot(
		&self,
		maximum_records: usize,
		maximum_unknown_revisions: usize,
		cancellation: &CancellationToken,
	) -> Result<CheckpointSnapshot> {
		let state = self
			.state
			.lock()
			.map_err(|_| anyhow::anyhow!("Evidence session registry is unavailable"))?;
		ensure!(
			!cancellation.is_cancelled(),
			"Evidence checkpoint cancelled before snapshot"
		);
		ensure!(state.records.len() <= maximum_records, "native checkpoint retained-record budget exceeded ({maximum_records}); no checkpoint was committed");
		ensure!(state.unknowns.len() <= maximum_unknown_revisions, "native checkpoint Unknown revision budget exceeded ({maximum_unknown_revisions}); no checkpoint was committed");
		Ok(CheckpointSnapshot {
			state: state.clone(),
		})
	}

	pub(in crate::mcp) fn require_empty_for_resume(&self) -> Result<()> {
		let state = self
			.state
			.lock()
			.map_err(|_| anyhow::anyhow!("Evidence session registry is unavailable"))?;
		ensure!(
			state.records.is_empty() && state.unknowns.is_empty(),
			"Evidence checkpoint resume requires an empty session; create a new session"
		);
		Ok(())
	}

	pub(in crate::mcp) fn resume_if_empty(
		&self,
		candidate: CheckpointCandidate,
		cancellation: &CancellationToken,
	) -> Result<()> {
		let mut state = self
			.state
			.lock()
			.map_err(|_| anyhow::anyhow!("Evidence session registry is unavailable"))?;
		ensure!(state.records.is_empty() && state.unknowns.is_empty(), "Evidence checkpoint resume requires an empty session; concurrent work already populated this session");
		ensure!(
			!cancellation.is_cancelled(),
			"Evidence checkpoint resume cancelled before publication"
		);
		*state = candidate.state;
		Ok(())
	}
}

impl CheckpointSnapshot {
	pub(in crate::mcp) fn counts(&self) -> (usize, usize) {
		(self.state.records.len(), self.state.unknowns.len())
	}

	pub(in crate::mcp) fn write_bundle<W: Write>(&self, output: &mut W) -> Result<()> {
		EvidenceSnapshot {
			records: self
				.state
				.records
				.iter()
				.map(|(id, record)| (id.clone(), Arc::clone(&record.evidence)))
				.collect(),
			unknowns: self.state.unknowns.clone(),
		}
		.write_canonical(output)
	}

	pub(in crate::mcp) fn sidecar(
		&self,
		mut order_budget: usize,
		cancellation: &CancellationToken,
	) -> Result<Value> {
		let mut records = Vec::with_capacity(self.state.records.len());
		for (id, record) in &self.state.records {
			ensure!(
				!cancellation.is_cancelled(),
				"Evidence checkpoint cancelled while capturing retention metadata"
			);
			let imported_order = match &record.imported_order {
				Some(order) => order.checkpoint_order(&record.evidence, &mut order_budget)?,
				None => Vec::new(),
			};
			records.push(RetainedMetadata {
				evidence_id: id.clone(),
				origin: record.origin,
				has_imported_order: record.imported_order.is_some(),
				imported_order,
			});
		}
		Ok(serde_json::to_value(Sidecar {
			schema: SIDECAR_SCHEMA.into(),
			order_profile: ORDER_PROFILE.into(),
			records,
		})?)
	}
}

struct OrderValidationSink<'a> {
	bytes: usize,
	maximum: usize,
	cancellation: &'a CancellationToken,
}

impl Write for OrderValidationSink<'_> {
	fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
		if self.cancellation.is_cancelled() {
			return Err(io::Error::other(
				"checkpoint producer-order authentication cancelled",
			));
		}
		self.bytes = self
			.bytes
			.checked_add(bytes.len())
			.filter(|total| *total <= self.maximum)
			.ok_or_else(|| {
				io::Error::other("checkpoint native producer-order byte budget exceeded")
			})?;
		Ok(bytes.len())
	}
	fn flush(&mut self) -> io::Result<()> {
		Ok(())
	}
}

impl CheckpointCandidate {
	pub(in crate::mcp) fn authenticate(
		bundle: Value,
		bundle_order: &ObjectOrder,
		sidecar: Value,
		maximum_record_bytes: usize,
		cancellation: &CancellationToken,
	) -> Result<Self> {
		ensure!(
			!cancellation.is_cancelled(),
			"Evidence checkpoint resume cancelled"
		);
		let resolver = |path: &[Value]| bundle_order.keys(path);
		let candidate =
			rea_evidence_source::authenticate_import_with_order(bundle, Some(&resolver)).map_err(
				|_| anyhow::anyhow!("checkpoint complete Evidence bundle authentication failed"),
			)?;
		let sidecar: Sidecar = serde_json::from_value(sidecar)
			.context("checkpoint retention sidecar schema is invalid")?;
		ensure!(
			sidecar.schema == SIDECAR_SCHEMA && sidecar.order_profile == ORDER_PROFILE,
			"checkpoint retention schema or response-order profile is unsupported"
		);
		ensure!(
			candidate.records.len() == sidecar.records.len(),
			"checkpoint sidecar does not cover every retained record"
		);
		let mut metadata = BTreeMap::new();
		for entry in sidecar.records {
			ensure!(
				metadata.insert(entry.evidence_id.clone(), entry).is_none(),
				"checkpoint retention record ID is duplicated"
			);
		}
		let mut state = SessionState::default();
		for evidence in candidate.records {
			ensure!(
				!cancellation.is_cancelled(),
				"Evidence checkpoint resume cancelled during authentication"
			);
			let id = evidence["evidence_id"]
				.as_str()
				.context("authenticated checkpoint record lost its ID")?
				.to_owned();
			let entry = metadata
				.remove(&id)
				.context("checkpoint retention metadata is missing for a complete record")?;
			let imported_order = if entry.has_imported_order {
				ensure!(
					entry.origin == RecordOrigin::Unknown,
					"imported checkpoint order cannot claim a native producing entry point"
				);
				Some(Arc::new(ObjectOrder::from_checkpoint_order(
					&evidence,
					entry.imported_order,
				)?))
			} else {
				ensure!(
					entry.imported_order.is_empty(),
					"checkpoint has unselected imported-order data"
				);
				if entry.origin != RecordOrigin::Unknown {
					// Root shape alone does not establish producer order for nested
					// free JSON. Traverse the same encoder used by retained replies,
					// validating every object's complete key set without a wire copy.
					let mut sink = OrderValidationSink {
						bytes: 0,
						maximum: maximum_record_bytes,
						cancellation,
					};
					rea_response_encoding::write_json_view(
						JsonView::Value(&evidence),
						&RecordOrder::new(&evidence, entry.origin),
						rea_evidence::canonical_js_number,
						&mut sink,
					)
					.context("checkpoint native producer order is incomplete")?;
				}
				None
			};
			state.records.insert(
				id,
				SessionRecord {
					evidence: Arc::new(evidence),
					origin: entry.origin,
					imported_order,
				},
			);
		}
		ensure!(
			metadata.is_empty(),
			"checkpoint sidecar refers to absent records"
		);
		for unknown in candidate.unknowns {
			let id = unknown["unknown_id"]
				.as_str()
				.context("authenticated unknown lost its ID")?
				.to_owned();
			let revision = unknown["revision"]
				.as_u64()
				.context("authenticated unknown lost its revision")?;
			ensure!(
				state
					.unknowns
					.insert((id, revision), Arc::new(unknown))
					.is_none(),
				"checkpoint unknown revision is duplicated"
			);
		}
		ensure!(
			!cancellation.is_cancelled(),
			"Evidence checkpoint resume cancelled after authentication"
		);
		Ok(Self { state })
	}

	pub(in crate::mcp) fn counts(&self) -> (usize, usize) {
		(self.state.records.len(), self.state.unknowns.len())
	}
}
