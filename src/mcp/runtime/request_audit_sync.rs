// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! A fixed file-sync pool whose cohort lifetime includes every submitted file.
use super::super::trace;
use anyhow::{anyhow, Result};
use std::fs::File;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::{Builder, JoinHandle};

pub(super) const WORKERS: usize = 4;
const MAX_FILES: usize = 32;
pub(super) type Operation = Arc<dyn Fn(&File) -> Result<()> + Send + Sync + 'static>;
type Worker = Box<dyn FnOnce() + Send + 'static>;
type PoolCell = OnceLock<std::result::Result<Pool, SharedFailure>>;
static POOL: PoolCell = OnceLock::new();

#[derive(Clone, Debug)]
struct SharedFailure(Arc<anyhow::Error>);

impl std::fmt::Display for SharedFailure {
	fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		formatter.write_str("audit file barrier pool unavailable")
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

#[derive(Debug)]
struct Completion {
	index: usize,
	outcome: Outcome,
}

// Field order also fences unexpected worker unwinding: the file reference is
// released before the reply sender can disconnect its caller's drain channel.
struct Job {
	file: Option<Arc<File>>,
	operation: Option<Operation>,
	index: usize,
	cohort: usize,
	reply: SyncSender<Completion>,
}

fn execute(mut job: Job) {
	let outcome = catch_unwind(AssertUnwindSafe(|| {
		match (job.file.as_ref(), job.operation.as_ref()) {
			(Some(file), Some(operation)) => {
				match trace::measure("file_sync_worker", job.cohort, Some(job.index), || {
					operation(file)
				}) {
					Ok(()) => Outcome::Synced,
					Err(error) => Outcome::Failed(error),
				}
			}
			_ => Outcome::Panicked,
		}
	}));
	// A completion must never let publication race a worker's last writable
	// reference (and a later CLOSE_WRITE/namespace-version observation).
	drop(job.file.take());
	drop(job.operation.take());
	let outcome = match outcome {
		Ok(value) => value,
		Err(_) => {
			trace::Span::new("file_sync_worker_panic", job.cohort, Some(job.index)).record(Some(
				&anyhow!("audit file barrier worker unavailable; never replay"),
			));
			Outcome::Panicked
		}
	};
	let _ = job.reply.send(Completion {
		index: job.index,
		outcome,
	});
}

fn worker(queue: Arc<Mutex<Receiver<Job>>>) {
	loop {
		let job = {
			let queue = match queue.lock() {
				Ok(value) => value,
				Err(_) => break,
			};
			match queue.recv() {
				Ok(value) => value,
				Err(_) => break,
			}
		};
		execute(job);
	}
}

pub(super) struct Pool {
	sender: Option<SyncSender<Job>>,
	workers: Vec<JoinHandle<()>>,
}

impl Pool {
	fn is_ready(&self) -> bool {
		self.sender.is_some()
			&& self.workers.len() == WORKERS
			&& self.workers.iter().all(|worker| !worker.is_finished())
	}

	pub(super) fn new() -> Result<Self> {
		Self::start_with(|index, task| {
			Builder::new()
				.name(format!("audit-file-sync-{index}"))
				.spawn(task)
		})
	}

	fn start_with(
		mut spawn: impl FnMut(usize, Worker) -> std::io::Result<JoinHandle<()>>,
	) -> Result<Self> {
		let (sender, receive) = mpsc::sync_channel(MAX_FILES);
		let receive = Arc::new(Mutex::new(receive));
		let mut workers = Vec::with_capacity(WORKERS);
		for index in 0..WORKERS {
			let receive = receive.clone();
			match spawn(index, Box::new(move || worker(receive))) {
				Ok(handle) => workers.push(handle),
				Err(error) => {
					drop(sender);
					for handle in workers {
						let _ = handle.join();
					}
					return Err(error.into());
				}
			}
		}
		Ok(Self {
			sender: Some(sender),
			workers,
		})
	}

	pub(super) fn synchronize(&self, files: &[Arc<File>], operation: Operation) -> Vec<Result<()>> {
		self.synchronize_with_hook(files, operation, |_| {})
	}

	// The hook is a caller-unwind test seam; production instantiates an empty
	// closure. Its invocation follows the drain count update, never precedes it.
	pub(super) fn synchronize_with_hook(
		&self,
		files: &[Arc<File>],
		operation: Operation,
		mut submitted: impl FnMut(usize),
	) -> Vec<Result<()>> {
		if files.len() > MAX_FILES {
			return refused(files.len(), "audit file barrier cohort exceeded");
		}
		if files.len() <= 1 {
			return inline(files, operation);
		}
		let sender = match &self.sender {
			Some(value) => value,
			None => return refused(files.len(), "audit file barrier pool unavailable"),
		};
		let (reply, receive) = mpsc::sync_channel(MAX_FILES);
		let mut drain = CohortDrainGuard {
			reply: Some(reply),
			receive,
			remaining: 0,
			disconnected: false,
		};
		let mut outcomes: Vec<Option<Outcome>> = (0..files.len()).map(|_| None).collect();
		let mut failed = false;
		for (index, file) in files.iter().enumerate() {
			let reply = match &drain.reply {
				Some(value) => value.clone(),
				None => {
					failed = true;
					break;
				}
			};
			let job = Job {
				file: Some(file.clone()),
				operation: Some(operation.clone()),
				index,
				cohort: files.len(),
				reply,
			};
			match sender.send(job) {
				Ok(()) => {
					drain.remaining += 1;
					submitted(index + 1);
				}
				Err(error) => {
					// The rejected job was never counted. Release its references
					// before draining any previously accepted work.
					drop(error.0);
					failed = true;
					break;
				}
			}
		}
		drain.close_reply();
		while let Some(completion) = drain.next() {
			if completion.index >= outcomes.len() || outcomes[completion.index].is_some() {
				failed = true;
				continue;
			}
			if matches!(&completion.outcome, Outcome::Panicked) {
				failed = true;
			}
			outcomes[completion.index] = Some(completion.outcome);
		}
		if failed || drain.disconnected || outcomes.iter().any(Option::is_none) {
			return refused(
				files.len(),
				"audit file barrier worker unavailable; never replay",
			);
		}
		outcomes
			.into_iter()
			.map(|value| match value {
				Some(Outcome::Synced) => Ok(()),
				Some(Outcome::Failed(error)) => Err(error),
				_ => Err(anyhow!(
					"audit file barrier worker unavailable; never replay"
				)),
			})
			.collect()
	}
}

impl Drop for Pool {
	fn drop(&mut self) {
		drop(self.sender.take());
		for worker in self.workers.drain(..) {
			let _ = worker.join();
		}
	}
}

// This guard owns the original reply sender as well as its receiver. Closing
// that sender first permits a lost worker to disconnect after all remaining
// jobs release theirs; keeping it elsewhere would deadlock the unwind path.
struct CohortDrainGuard {
	reply: Option<SyncSender<Completion>>,
	receive: Receiver<Completion>,
	remaining: usize,
	disconnected: bool,
}

impl CohortDrainGuard {
	fn close_reply(&mut self) {
		drop(self.reply.take());
	}

	fn next(&mut self) -> Option<Completion> {
		// Drain to sender disconnection, not merely an expected message count.
		// Even a malformed/duplicate reply cannot release Prepared while some
		// other accepted job still owns its file and sender.
		match self.receive.recv() {
			Ok(value) => {
				if self.remaining == 0 {
					self.disconnected = true;
				} else {
					self.remaining -= 1;
				}
				Some(value)
			}
			Err(_) => {
				self.disconnected |= self.remaining != 0;
				self.remaining = 0;
				None
			}
		}
	}
}

impl Drop for CohortDrainGuard {
	fn drop(&mut self) {
		self.close_reply();
		while self.next().is_some() {}
	}
}

fn refused(count: usize, reason: &str) -> Vec<Result<()>> {
	(0..count).map(|_| Err(anyhow!("{reason}"))).collect()
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

fn with_cell(
	files: &[Arc<File>],
	operation: Operation,
	cell: &PoolCell,
	initialize: impl FnOnce() -> Result<Pool>,
) -> Vec<Result<()>> {
	if files.len() > MAX_FILES {
		return refused(files.len(), "audit file barrier cohort exceeded");
	}
	if files.len() <= 1 {
		return inline(files, operation);
	}
	match cell.get_or_init(|| {
		trace::measure("file_sync_pool_initialize", files.len(), None, initialize)
			.map_err(|error| SharedFailure(Arc::new(error)))
	}) {
		Ok(pool) => pool.synchronize(files, operation),
		Err(error) => (0..files.len())
			.map(|_| Err(anyhow::Error::new(error.clone())))
			.collect(),
	}
}

pub(super) fn synchronize(files: &[Arc<File>], operation: Operation) -> Vec<Result<()>> {
	with_cell(files, operation, &POOL, Pool::new)
}

fn cell_is_ready(cell: &PoolCell) -> bool {
	match cell.get() {
		None => true,
		Some(Ok(pool)) => pool.is_ready(),
		Some(Err(_)) => false,
	}
}

pub(super) fn is_ready() -> bool {
	cell_is_ready(&POOL)
}

#[cfg(test)]
#[path = "request_audit_sync_tests.rs"]
mod tests;
