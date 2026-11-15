// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! File barriers own and join every submitted worker before publishing a cohort.
use super::super::trace;
use anyhow::{anyhow, Result};
use std::fs::File;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Arc;
use std::thread::Builder;

pub(super) type Operation = Arc<dyn Fn(&File) -> Result<()> + Send + Sync + 'static>;

#[derive(Clone, Debug)]
struct SharedFailure(Arc<anyhow::Error>);

impl std::fmt::Display for SharedFailure {
	fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		formatter.write_str("audit file barrier worker unavailable; never replay")
	}
}

impl std::error::Error for SharedFailure {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		Some(self.0.as_ref().as_ref())
	}
}

#[derive(Debug)]
enum Outcome {
	Synced,
	Failed(anyhow::Error),
	Panicked,
}

fn execute(file: Arc<File>, operation: Operation, index: usize, cohort: usize) -> Outcome {
	let outcome = catch_unwind(AssertUnwindSafe(|| {
		match trace::measure("file_sync_worker", cohort, Some(index), || operation(&file)) {
			Ok(()) => Outcome::Synced,
			Err(error) => Outcome::Failed(error),
		}
	}));
	// A completed join must fence the worker's final writable reference and
	// its CLOSE_WRITE/namespace-version observation before publication starts.
	drop(file);
	drop(operation);
	match outcome {
		Ok(value) => value,
		Err(_) => {
			trace::Span::new("file_sync_worker_panic", cohort, Some(index)).record(Some(&anyhow!(
				"audit file barrier worker unavailable; never replay"
			)));
			Outcome::Panicked
		}
	}
}

fn synchronize_with_hooks(
	files: &[Arc<File>],
	operation: Operation,
	mut before_spawn: impl FnMut(usize) -> std::io::Result<()>,
	mut submitted: impl FnMut(usize),
) -> Vec<Result<()>> {
	if files.len() <= 1 {
		return inline(files, operation);
	}
	// Each cohort owns its workers. There is no shared admission queue or
	// fixed worker count. Scope also joins accepted work on caller unwind,
	// before the caller's Prepared guards may unlink or publish any file.
	std::thread::scope(|scope| {
		let mut workers = Vec::with_capacity(files.len());
		let mut spawn_failure = None;
		for (index, file) in files.iter().enumerate() {
			if let Err(error) = before_spawn(index) {
				spawn_failure = Some(error);
				break;
			}
			let file = file.clone();
			let operation = operation.clone();
			let cohort = files.len();
			match Builder::new()
				.name(format!("audit-file-sync-{index}"))
				.spawn_scoped(scope, move || execute(file, operation, index, cohort))
			{
				Ok(worker) => {
					workers.push(worker);
					// The handle is under scope custody before the caller can unwind.
					submitted(index + 1);
				}
				Err(error) => {
					spawn_failure = Some(error);
					break;
				}
			}
		}
		// Join every accepted worker even after a spawn failure or worker panic.
		// Handles retain input order; a reply cannot duplicate or replace a slot.
		let outcomes: Vec<_> = workers
			.into_iter()
			.map(|worker| worker.join().unwrap_or(Outcome::Panicked))
			.collect();
		if let Some(error) = spawn_failure {
			let failure = SharedFailure(Arc::new(error.into()));
			return (0..files.len())
				.map(|_| Err(anyhow::Error::new(failure.clone())))
				.collect();
		}
		if outcomes.len() != files.len()
			|| outcomes
				.iter()
				.any(|outcome| matches!(outcome, Outcome::Panicked))
		{
			return (0..files.len())
				.map(|_| {
					Err(anyhow!(
						"audit file barrier worker unavailable; never replay"
					))
				})
				.collect();
		}
		outcomes
			.into_iter()
			.map(|outcome| match outcome {
				Outcome::Synced => Ok(()),
				Outcome::Failed(error) => Err(error),
				Outcome::Panicked => Err(anyhow!(
					"audit file barrier worker unavailable; never replay"
				)),
			})
			.collect()
	})
}

fn inline(files: &[Arc<File>], operation: Operation) -> Vec<Result<()>> {
	// Preserve the existing caller path, including normal caller unwinding.
	// There are no submitted worker jobs to outlive that unwind.
	files
		.iter()
		.enumerate()
		.map(|(slot, file)| {
			trace::measure("file_sync_inline", files.len(), Some(slot), || {
				operation(file)
			})
		})
		.collect()
}

pub(super) fn synchronize(files: &[Arc<File>], operation: Operation) -> Vec<Result<()>> {
	synchronize_with_hooks(files, operation, |_| Ok(()), |_| {})
}

#[cfg(test)]
pub(super) fn synchronize_with_hook(
	files: &[Arc<File>],
	operation: Operation,
	submitted: impl FnMut(usize),
) -> Vec<Result<()>> {
	synchronize_with_hooks(files, operation, |_| Ok(()), submitted)
}

pub(super) fn is_ready() -> bool {
	// No process-wide pool needs initialization. Per-call OS spawn failures
	// are reported only after that call's original accepted workers are joined.
	true
}

#[cfg(test)]
#[path = "request_audit_sync_tests.rs"]
mod tests;
