// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Advisory metadata reclamation only inside a dedicated, bounded own cgroup.
use super::*;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path};

const CONTROL_BYTES: u64 = 8192;
const MIB: u64 = 1024 * 1024;
const INTERVAL: Duration = Duration::from_secs(2);

fn group_path(text: &str) -> Option<String> {
	let mut paths = text.lines().filter_map(|line| line.strip_prefix("0::"));
	let path = paths.next()?;
	if paths.next().is_some() || !path.starts_with('/') || path == "/" {
		return None;
	}
	if path
		.split('/')
		.skip(1)
		.any(|part| part.is_empty() || part == "." || part == "..")
	{
		return None;
	}
	Some(path.to_owned())
}
fn dedicated(procs: &str, own: u32, parent: u32) -> bool {
	let mut present = false;
	for word in procs.split_whitespace() {
		let Ok(pid) = word.parse::<u32>() else {
			return false;
		};
		if pid == 0 || (pid != own && pid != parent) {
			return false;
		}
		present |= pid == own;
	}
	present
}
fn amount(limit: u64, current: u64, slab: u64, file: u64) -> Option<u64> {
	if limit < 256 * MIB
		|| current < limit.saturating_mul(7) / 8
		|| slab < limit.saturating_mul(5) / 8
		|| file >= limit / 4
	{
		return None;
	}
	Some((limit / 8).clamp(64 * MIB, 256 * MIB))
}
fn statistic(text: &str, key: &str) -> Option<u64> {
	text.lines().find_map(|line| {
		let mut fields = line.split_whitespace();
		if fields.next()? != key {
			return None;
		}
		let number = fields.next()?.parse().ok()?;
		if fields.next().is_some() {
			return None;
		}
		Some(number)
	})
}
fn bounded(mut file: File) -> Result<String> {
	let mut bytes = Vec::new();
	Read::by_ref(&mut file)
		.take(CONTROL_BYTES + 1)
		.read_to_end(&mut bytes)?;
	if bytes.len() as u64 > CONTROL_BYTES {
		bail!("archive cgroup control too large");
	}
	Ok(String::from_utf8(bytes)?)
}
fn control(directory: &File, filename: &str) -> Result<String> {
	bounded(open_at(
		directory,
		filename,
		libc::O_RDONLY | libc::O_NONBLOCK,
		0,
	)?)
}
fn current_group() -> Result<String> {
	let file = std::fs::OpenOptions::new()
		.read(true)
		.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
		.open("/proc/self/cgroup")?;
	group_path(&bounded(file)?).ok_or_else(|| anyhow!("archive has no dedicated unified cgroup"))
}
fn cgroup_filesystem(file: &File) -> Result<()> {
	let mut raw = std::mem::MaybeUninit::<libc::statfs>::uninit();
	if unsafe { libc::fstatfs(file.as_raw_fd(), raw.as_mut_ptr()) } != 0 {
		return Err(std::io::Error::last_os_error().into());
	}
	if unsafe { raw.assume_init() }.f_type != 0x6367_7270 {
		bail!("archive cgroup control is not cgroup2");
	}
	Ok(())
}
fn open_group(path: &str) -> Result<File> {
	if group_path(&format!("0::{path}")).as_deref() != Some(path) {
		bail!("invalid archive cgroup path");
	}
	let mut directory = std::fs::OpenOptions::new()
		.read(true)
		.custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW)
		.open("/sys/fs/cgroup")?;
	cgroup_filesystem(&directory)?;
	for component in Path::new(path.trim_start_matches('/')).components() {
		let Component::Normal(component) = component else {
			bail!("invalid cgroup component");
		};
		directory = open_at(
			&directory,
			component
				.to_str()
				.ok_or_else(|| anyhow!("invalid cgroup name"))?,
			libc::O_RDONLY | libc::O_DIRECTORY,
			0,
		)?;
	}
	cgroup_filesystem(&directory)?;
	let metadata = directory.metadata()?;
	if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o022 != 0 {
		bail!("archive cgroup is not owned privately");
	}
	Ok(directory)
}

#[derive(Default)]
struct TraceDuration {
	calls: u64,
	total: Duration,
	maximum: Duration,
}
impl TraceDuration {
	fn record(&mut self, elapsed: Duration) {
		self.calls = self.calls.saturating_add(1);
		self.total = self.total.saturating_add(elapsed);
		self.maximum = self.maximum.max(elapsed);
	}
}
struct BudgetTrace {
	started: Instant,
	probes: TraceDuration,
	maintains: TraceDuration,
	writes: TraceDuration,
}
impl BudgetTrace {
	fn new(started: Instant) -> Self {
		Self {
			started,
			probes: TraceDuration::default(),
			maintains: TraceDuration::default(),
			writes: TraceDuration::default(),
		}
	}
}
fn write_errno(result: &std::io::Result<()>) -> String {
	match result {
		Ok(()) => "none".to_owned(),
		Err(error) => error
			.raw_os_error()
			.map_or_else(|| "none".to_owned(), |number| number.to_string()),
	}
}

pub(super) struct Budget {
	directory: File,
	path: String,
	limit: u64,
	last_probe: Instant,
	attempts: u64,
	accepted: u64,
	requested: u64,
	trace: Option<BudgetTrace>,
}
impl Budget {
	pub(super) fn new(tracing: bool, started: Instant) -> Option<Self> {
		let path = current_group().ok()?;
		let directory = open_group(&path).ok()?;
		let limit = control(&directory, "memory.max")
			.ok()?
			.trim()
			.parse::<u64>()
			.ok()?;
		let value = Self {
			directory,
			path,
			limit,
			last_probe: Instant::now(),
			attempts: 0,
			accepted: 0,
			requested: 0,
			trace: tracing.then(|| BudgetTrace::new(started)),
		};
		if limit < 256 * MIB || !value.still_dedicated().ok()? {
			return None;
		}
		Some(value)
	}
	fn still_dedicated(&self) -> Result<bool> {
		if current_group()? != self.path
			|| control(&self.directory, "cgroup.type")?.trim() != "domain"
		{
			return Ok(false);
		}
		let fresh = open_group(&self.path)?;
		let pinned = self.directory.metadata()?;
		let named = fresh.metadata()?;
		if (pinned.dev(), pinned.ino()) != (named.dev(), named.ino())
			|| control(&fresh, "memory.max")?.trim().parse::<u64>()? != self.limit
		{
			return Ok(false);
		}
		Ok(dedicated(
			&control(&fresh, "cgroup.procs")?,
			std::process::id(),
			unsafe { libc::getppid() } as u32,
		))
	}
	fn probe(&mut self) -> Result<()> {
		let started = self.trace.as_ref().map(|_| Instant::now());
		let result = self.probe_once();
		if let (Some(trace), Some(started)) = (&mut self.trace, started) {
			trace.probes.record(started.elapsed());
		}
		result
	}
	fn probe_once(&mut self) -> Result<()> {
		let current = control(&self.directory, "memory.current")?
			.trim()
			.parse::<u64>()?;
		let stats = control(&self.directory, "memory.stat")?;
		let slab = statistic(&stats, "slab_reclaimable")
			.ok_or_else(|| anyhow!("missing cgroup slab statistic"))?;
		let file =
			statistic(&stats, "file").ok_or_else(|| anyhow!("missing cgroup file statistic"))?;
		let Some(bytes) = amount(self.limit, current, slab, file) else {
			return Ok(());
		};
		if !self.still_dedicated()? {
			return Ok(());
		}
		let mut reclaim = open_at(
			&self.directory,
			"memory.reclaim",
			libc::O_WRONLY | libc::O_NONBLOCK,
			0,
		)?;
		cgroup_filesystem(&reclaim)?;
		let metadata = reclaim.metadata()?;
		if !metadata.is_file()
			|| metadata.uid() != unsafe { libc::geteuid() }
			|| metadata.mode() & 0o022 != 0
		{
			return Ok(());
		}
		self.attempts += 1;
		self.requested = self.requested.saturating_add(bytes);
		// Reclaim is advisory: EAGAIN can mean partial progress. Failure never
		// publishes an unchecked row or changes either resource limit.
		let write_started = self.trace.as_ref().map(|trace| {
			eprintln!("archive_index cold_stage=private_cgroup_reclaim_write_start sequence={} relative_ms={} current_bytes={current} slab_reclaimable_bytes={slab} file_bytes={file} requested_bytes={bytes}", self.attempts, trace.started.elapsed().as_millis());
			Instant::now()
		});
		let result = reclaim.write_all(bytes.to_string().as_bytes());
		if let (Some(trace), Some(started)) = (&mut self.trace, write_started) {
			let elapsed = started.elapsed();
			trace.writes.record(elapsed);
			eprintln!("archive_index cold_stage=private_cgroup_reclaim_write_end sequence={} relative_ms={} write_elapsed_us={} ok={} errno={}", self.attempts, trace.started.elapsed().as_millis(), elapsed.as_micros(), result.is_ok(), write_errno(&result));
		}
		if result.is_ok() {
			self.accepted += 1;
		}
		Ok(())
	}
	pub(super) fn maintain(&mut self) {
		let started = self.trace.as_ref().map(|_| Instant::now());
		self.maintain_once();
		if let (Some(trace), Some(started)) = (&mut self.trace, started) {
			trace.maintains.record(started.elapsed());
		}
	}
	fn maintain_once(&mut self) {
		if self.last_probe.elapsed() < INTERVAL {
			return;
		}
		self.last_probe = Instant::now();
		let _ = self.probe();
	}
	pub(super) fn trace(&self) {
		if let Some(trace) = &self.trace {
			eprintln!("archive_index private_cgroup_reclaim_attempts={} accepted_requests={} requested_bytes={} limits_unchanged=true originals_rechecked=true", self.attempts, self.accepted, self.requested);
			eprintln!("archive_index cold_stage=private_cgroup_reclaim_timing relative_ms={} probe_calls={} probe_elapsed_us={} probe_max_us={} maintain_calls={} maintain_elapsed_us={} maintain_max_us={} write_calls={} write_elapsed_us={} write_max_us={}", trace.started.elapsed().as_millis(), trace.probes.calls, trace.probes.total.as_micros(), trace.probes.maximum.as_micros(), trace.maintains.calls, trace.maintains.total.as_micros(), trace.maintains.maximum.as_micros(), trace.writes.calls, trace.writes.total.as_micros(), trace.writes.maximum.as_micros());
		}
	}
}

#[cfg(test)]
#[path = "request_archive_memory_tests.rs"]
mod tests;
