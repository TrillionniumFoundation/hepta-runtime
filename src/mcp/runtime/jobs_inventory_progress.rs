// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Resumable original-byte validation; no inventory row escapes an unfinished scan.
use super::*;

pub(in super::super) struct Progress<T> {
	directories: Directories,
	names: Vec<String>,
	records: Vec<RecordProof>,
	rows: Vec<T>,
	watch: Option<namespace_version::Version>,
	read_next: usize,
	complete: bool,
	validating: bool,
	retained_bytes: usize,
	memory_limit: usize,
}

impl<T> Progress<T> {
	pub(in super::super) fn begin(
		root: &Path,
		limits: InventoryLimits,
		expected: Option<&SourceProof>,
		memory_limit: usize,
		mut reserve: impl FnMut(usize) -> Result<()>,
	) -> Result<Self> {
		let budget = Budget {
			started: Instant::now(),
			limits,
		};
		budget.check()?;
		let directories = Directories::open(root)?;
		if expected.is_some_and(|old| !directories.same_scope(&old.directories)) {
			bail!("durable inventory root or directory changed");
		}
		let watch = content_watch(&directories.jobs);
		let names = entries(&directories.jobs, &budget)?;
		if names.len() > limits.records {
			bail!("durable inventory source row bound exceeded");
		}
		if expected.is_some_and(|old| old.names != names) {
			bail!("durable inventory membership changed; restart from the first page");
		}
		let validating = expected.is_some();
		let count = if validating { 0 } else { names.len() };
		let retained_bytes = std::mem::size_of::<Self>()
			+ names.capacity() * std::mem::size_of::<String>()
			+ names.iter().map(String::capacity).sum::<usize>()
			+ count * std::mem::size_of::<RecordProof>()
			+ count * std::mem::size_of::<T>();
		if retained_bytes > memory_limit {
			bail!("durable inventory progress cache byte bound exceeded");
		}
		reserve(retained_bytes)?;
		let records = Vec::with_capacity(count);
		let rows = Vec::with_capacity(count);
		Ok(Self {
			directories,
			names,
			records,
			rows,
			watch,
			read_next: 0,
			complete: false,
			validating,
			retained_bytes,
			memory_limit,
		})
	}

	fn step(
		&mut self,
		root: &Path,
		limits: InventoryLimits,
		expected: Option<&SourceProof>,
		mut project: impl FnMut(&str, &[u8]) -> Result<T>,
		heap_bytes: impl Fn(&T) -> usize,
		mut reserve: impl FnMut(usize) -> Result<()>,
	) -> Result<bool> {
		let budget = Budget {
			started: Instant::now(),
			limits,
		};
		budget.check()?;
		if self.complete || self.validating != expected.is_some() {
			bail!("durable inventory progress state unavailable");
		}
		if self.names.len() > limits.records {
			bail!("durable inventory source row bound exceeded");
		}
		self.directories.finish(root)?;
		let mut consumed = 0u64;
		// The scratch buffer belongs to this admitted step and is dropped on
		// every pending response. No raw payload accumulates between requests.
		let mut raw = Vec::new();
		while self.read_next < self.names.len() {
			if budget.started.elapsed() >= limits.time {
				return Ok(false);
			}
			let index = self.read_next;
			let name = &self.names[index];
			let id = name
				.strip_suffix(".json")
				.context("invalid inventory identity")?;
			if !valid_name(id) {
				bail!("invalid durable inventory identity");
			}
			let mut file = open_at(Some(&self.directories.jobs), name, libc::O_RDONLY)?;
			let before = file.metadata()?;
			if !before.is_file()
				|| before.uid() != unsafe { libc::geteuid() }
				|| before.mode() & 0o7777 != 0o600
				|| before.nlink() != 1
				|| before.len() == 0
				|| before.len() > limits.record_bytes
			{
				bail!("durable inventory metadata inode or byte bound refused");
			}
			if before.len() > limits.bytes {
				bail!("durable inventory one record exceeds the source step byte bound");
			}
			if consumed > limits.bytes - before.len() {
				return Ok(false);
			}
			consumed += before.len();
			raw.clear();
			raw.try_reserve_exact(before.len() as usize + 1)
				.context("cannot allocate bounded durable inventory read buffer")?;
			Read::by_ref(&mut file)
				.take(before.len() + 1)
				.read_to_end(&mut raw)?;
			let before = stamp(&before);
			if raw.len() as u64 != before.5 || before != stamp(&file.metadata()?) {
				bail!("durable inventory metadata changed during observation");
			}
			let sha256: [u8; 32] = Sha256::digest(&raw).into();
			if let Some(old) = expected {
				if old.records[index].stamp != before || old.records[index].sha256 != sha256 {
					bail!(
						"durable inventory original content changed; restart from the first page"
					);
				}
			} else {
				let row = project(id, &raw)?;
				self.retained_bytes = self
					.retained_bytes
					.checked_add(heap_bytes(&row))
					.context("durable inventory progress byte overflow")?;
				if self.retained_bytes > self.memory_limit {
					bail!("durable inventory progress cache byte bound exceeded");
				}
				reserve(self.retained_bytes)?;
				self.rows.push(row);
				self.records.push(RecordProof {
					stamp: before,
					sha256,
				});
			}
			self.read_next += 1;
		}
		drop(raw);
		// Keep the final membership and named-inode fences in one bounded step,
		// just as the original observation did. Yield before this fence, never
		// remember a partial final fence across an unbounded caller pause.
		if budget.started.elapsed() >= limits.time / 2 {
			return Ok(false);
		}
		if entries(&self.directories.jobs, &budget)? != self.names {
			bail!("durable inventory membership changed");
		}
		let records = expected.map_or(self.records.as_slice(), |old| old.records.as_slice());
		for (index, name) in self.names.iter().enumerate() {
			budget.check()?;
			if named_stamp(&self.directories.jobs, name)? != records[index].stamp {
				bail!("durable inventory metadata changed");
			}
		}
		// Also catch membership changes during the final named-inode fence.
		if entries(&self.directories.jobs, &budget)? != self.names {
			bail!("durable inventory membership changed");
		}
		self.directories.finish(root)?;
		let after = content_watch(&self.directories.jobs);
		if self.watch.is_some() && !same_content_watch(self.watch, after) {
			bail!("durable inventory content watch changed during observation");
		}
		budget.check()?;
		self.complete = true;
		Ok(true)
	}

	pub(in super::super) fn observe_step(
		&mut self,
		root: &Path,
		limits: InventoryLimits,
		mut project: impl FnMut(JobRecordData<ValidatedJobString>) -> T,
		heap_bytes: impl Fn(&T) -> usize,
		reserve: impl FnMut(usize) -> Result<()>,
	) -> Result<bool> {
		self.step(
			root,
			limits,
			None,
			|id, raw| {
				let record: JobRecordData<ValidatedJobString> =
					serde_json::from_slice(raw).context("corrupt durable inventory metadata")?;
				if record.id != id || !valid_name(&record.host) {
					bail!("durable inventory record identity mismatch");
				}
				Ok(project(record))
			},
			heap_bytes,
			reserve,
		)
	}

	pub(in super::super) fn finish(self) -> Result<(Vec<T>, SourceProof)> {
		if !self.complete || self.validating {
			bail!("durable inventory observation is incomplete");
		}
		Ok((
			self.rows,
			SourceProof {
				directories: self.directories,
				names: self.names,
				records: self.records,
			},
		))
	}
}

impl Progress<()> {
	pub(in super::super) fn validate_step(
		&mut self,
		root: &Path,
		limits: InventoryLimits,
		proof: &SourceProof,
	) -> Result<bool> {
		// Byte-for-byte equality with the fully decoded original proves the
		// complete schema too; private and unselected-host fields remain covered.
		self.step(root, limits, Some(proof), |_, _| Ok(()), |_| 0, |_| Ok(()))
	}
}
