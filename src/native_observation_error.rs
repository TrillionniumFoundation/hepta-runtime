// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Bounded observation diagnostics; arbitrary transport errors stay out of public text.

use std::fmt;
use std::time::Duration;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Stage {
	Admission,
	InitialLookup,
	InitialEnvelope,
	InitialBinding,
	InitialPublication,
	OutputBudget,
	PageTransport,
	PageDecode,
	PageBinding,
	PageIntegrity,
	FinalLookup,
	FinalEnvelope,
	FinalBinding,
	FinalPublication,
}

impl Stage {
	fn label(self) -> &'static str {
		match self {
			Self::Admission => "admission",
			Self::InitialLookup => "initial_lookup",
			Self::InitialEnvelope => "initial_envelope",
			Self::InitialBinding => "initial_binding",
			Self::InitialPublication => "initial_publication",
			Self::OutputBudget => "output_budget",
			Self::PageTransport => "page_transport",
			Self::PageDecode => "page_decode",
			Self::PageBinding => "page_binding",
			Self::PageIntegrity => "page_integrity",
			Self::FinalLookup => "final_lookup",
			Self::FinalEnvelope => "final_envelope",
			Self::FinalBinding => "final_binding",
			Self::FinalPublication => "final_publication",
		}
	}
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Cause {
	InvalidRequest,
	Unavailable,
	Deadline,
	InvalidJson,
	BindingMismatch,
	PublicationInvalid,
	PublicationChanged,
	RetentionBudget,
	Allocation,
	InvalidPage,
}

impl Cause {
	fn label(self) -> &'static str {
		match self {
			Self::InvalidRequest => "invalid_request",
			Self::Unavailable => "unavailable",
			Self::Deadline => "deadline",
			Self::InvalidJson => "invalid_json",
			Self::BindingMismatch => "binding_mismatch",
			Self::PublicationInvalid => "publication_invalid",
			Self::PublicationChanged => "publication_changed",
			Self::RetentionBudget => "retention_budget",
			Self::Allocation => "allocation",
			Self::InvalidPage => "invalid_page",
		}
	}

	pub(super) fn transport(error: &anyhow::Error) -> Self {
		// Never infer a timeout from remote-controlled stderr or an error string.
		if error.chain().any(|source| {
			source.is::<tokio::time::error::Elapsed>()
				|| source
					.downcast_ref::<std::io::Error>()
					.is_some_and(|error| error.kind() == std::io::ErrorKind::TimedOut)
		}) {
			Self::Deadline
		} else {
			Self::Unavailable
		}
	}
}

#[derive(Clone, Debug)]
pub(super) struct PageFailure {
	pub stage: Stage,
	pub cause: Cause,
	pub window: usize,
	pub index: usize,
	pub stdout_offset: u64,
	pub stderr_offset: u64,
	pub limit: u64,
	pub elapsed: Duration,
}

pub(super) struct Failure {
	pub stage: Stage,
	pub cause: Cause,
	pub elapsed: Duration,
	pub initial_observation: Duration,
	pub output_read: Duration,
	pub final_observation: Duration,
	pub page_reads_attempted: usize,
	pub validated_page_reads: usize,
	pub read_windows: usize,
	// Counts of the validated contiguous prefix before refusal; these fields
	// neither publish the bytes nor authorize a terminal output witness.
	pub retained_stdout_bytes: usize,
	pub retained_stderr_bytes: usize,
	// At most one fixed-size collector window, not an unbounded history.
	pub pages: Vec<PageFailure>,
	source: anyhow::Error,
}

impl Failure {
	pub(super) fn new(stage: Stage, cause: Cause, source: anyhow::Error) -> Self {
		Self {
			stage,
			cause,
			elapsed: Duration::ZERO,
			initial_observation: Duration::ZERO,
			output_read: Duration::ZERO,
			final_observation: Duration::ZERO,
			page_reads_attempted: 0,
			validated_page_reads: 0,
			read_windows: 0,
			retained_stdout_bytes: 0,
			retained_stderr_bytes: 0,
			pages: Vec::new(),
			source,
		}
	}
}

impl fmt::Display for Failure {
	fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(out,
			"stage={} cause={} elapsed_us={} initial_us={} read_us={} final_us={} page_reads={} validated_pages={} windows={} prefix_stdout={} prefix_stderr={}",
			self.stage.label(), self.cause.label(), self.elapsed.as_micros(),
			self.initial_observation.as_micros(), self.output_read.as_micros(),
			self.final_observation.as_micros(), self.page_reads_attempted,
			self.validated_page_reads, self.read_windows,
			self.retained_stdout_bytes, self.retained_stderr_bytes)?;
		for page in &self.pages {
			write!(out,
				" [stage={} cause={} window={} page={} stdout_offset={} stderr_offset={} limit={} elapsed_us={}]",
				page.stage.label(), page.cause.label(), page.window, page.index,
				page.stdout_offset, page.stderr_offset, page.limit, page.elapsed.as_micros())?;
		}
		Ok(())
	}
}

impl fmt::Debug for Failure {
	fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
		fmt::Display::fmt(self, out)
	}
}

impl std::error::Error for Failure {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		Some(self.source.as_ref())
	}
}

/// Only enum labels and bounded numeric observations cross the HIA boundary.
pub(super) fn public_diagnostic(error: &anyhow::Error) -> String {
	match error.downcast_ref::<Failure>() {
		Some(failure) => failure.to_string(),
		None => "stage=unclassified cause=unavailable".to_owned(),
	}
}
