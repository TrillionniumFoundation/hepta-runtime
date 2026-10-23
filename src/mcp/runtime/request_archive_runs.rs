// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Bounded private comparison streams retain every original identity and stamp.
use super::*;
use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::io::BufWriter;
use std::os::unix::fs::FileExt;

type Image = [u8; VALUE_BYTES];
const HEADER: usize = 40;
const SORT_ROWS: usize = 8192;
const FAN_IN: usize = 16;
const READ_ROWS: usize = 1024;
const TERMINAL_READERS: usize = COLD_ROW_WORKERS * FAN_IN;
#[cfg(test)]
const DIRECTORY_COHORT: usize = 4096;
// Keep metadata I/O overlapped without oversubscribing a bounded controller:
// excessive parallel lookups compete with inode reclamation for the same CPUs.
pub(super) const STAT_WORKERS: usize = 8;
const WRITEBACK_BYTES: u64 = 4 * 1024 * 1024;
const PAGE_BYTES: u64 = 4096;
#[cfg(target_os = "linux")]
#[path = "request_archive_memory.rs"]
mod memory;

#[path = "request_archive_directory.rs"]
mod directory;
pub(super) use directory::RowExpected;

/// Disk-backed observations can outlive the metadata workers without retaining names.
pub(super) struct Observed(directory::Observed);

pub(super) fn observe(slot: &Slot, deadline: Instant, cancelled: &AtomicBool) -> Result<Observed> {
	let pool = rayon::ThreadPoolBuilder::new()
		.num_threads(STAT_WORKERS)
		.build()?;
	directory::observe(slot, &pool, deadline, cancelled).map(Observed)
}

/// One budget spans the overlapping scans and the later identity join.
pub(super) struct OriginalBudget {
	#[cfg(target_os = "linux")]
	inner: Option<memory::Budget>,
}
impl OriginalBudget {
	pub(super) fn new(tracing: bool, started: Instant) -> Self {
		#[cfg(not(target_os = "linux"))]
		let _ = (tracing, started);
		Self {
			#[cfg(target_os = "linux")]
			inner: memory::Budget::new(tracing, started),
		}
	}
	pub(super) fn maintain(&mut self) {
		#[cfg(target_os = "linux")]
		if let Some(budget) = &mut self.inner {
			budget.maintain();
		}
	}
	pub(super) fn trace(&self) {
		#[cfg(target_os = "linux")]
		if let Some(budget) = &self.inner {
			budget.trace();
		}
	}
}

// Anonymous comparison streams are disposable, but buffered writes otherwise
// keep hundreds of MB dirty while millions of original dentries are needed.
// Reclaim only complete pages of these private descriptors, after writeback.
fn release_pages(file: &File, start: u64, end: u64) {
	let start = start.div_ceil(PAGE_BYTES) * PAGE_BYTES;
	let end = end / PAGE_BYTES * PAGE_BYTES;
	#[cfg(target_os = "linux")]
	if end > start {
		unsafe {
			let _ = libc::posix_fadvise(
				file.as_raw_fd(),
				start as libc::off_t,
				(end - start) as libc::off_t,
				libc::POSIX_FADV_DONTNEED,
			);
		}
	}
	let _ = (file, start, end);
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SortOrder {
	Identity,
	#[cfg(test)]
	Inode,
}
impl SortOrder {
	fn stream_role(self) -> &'static str {
		match self {
			Self::Identity => "observed_identity",
			#[cfg(test)]
			Self::Inode => "legacy_inode_fixture",
		}
	}
	fn compare(self, left: &Image, right: &Image) -> std::cmp::Ordering {
		match self {
			Self::Identity => left[..32].cmp(&right[..32]),
			#[cfg(test)]
			Self::Inode => left[32..48]
				.cmp(&right[32..48])
				.then_with(|| left[..32].cmp(&right[..32])),
		}
	}
}

fn digest(domain: &[u8]) -> ArchiveHash {
	let mut hash = ArchiveHash::new();
	hash.update(domain);
	hash
}
fn tracing_enabled() -> bool {
	std::env::var_os("HEPTA_ARCHIVE_INDEX_TRACE").as_deref() == Some(std::ffi::OsStr::new("1"))
}

struct WritebackTrace {
	started: Instant,
	build_elapsed: Duration,
	calls: u64,
	elapsed: Duration,
	maximum: Duration,
}
impl WritebackTrace {
	fn new() -> Self {
		Self {
			started: Instant::now(),
			build_elapsed: Duration::ZERO,
			calls: 0,
			elapsed: Duration::ZERO,
			maximum: Duration::ZERO,
		}
	}
}
fn temporary(root: &File) -> Result<File> {
	#[cfg(target_os = "linux")]
	if let Ok(file) = open_at(root, ".", libc::O_RDWR | libc::O_TMPFILE, 0o600) {
		return Ok(file);
	}
	// The fallback is confined to the already validated private state directory.
	// Unlink immediately, before writing data, so a process exit leaves no spool.
	use ring::rand::SecureRandom;
	let mut nonce = [0u8; 32];
	ring::rand::SystemRandom::new()
		.fill(&mut nonce)
		.map_err(|_| anyhow!("archive temporary entropy unavailable"))?;
	let mut filename = String::from(".archive-compare-");
	for byte in nonce {
		use std::fmt::Write;
		write!(&mut filename, "{byte:02x}")?;
	}
	let file = open_at(
		root,
		&filename,
		libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
		0o600,
	)?;
	let component = name(&filename)?;
	if unsafe { libc::unlinkat(root.as_raw_fd(), component.as_ptr(), 0) } < 0 {
		return Err(std::io::Error::last_os_error().into());
	}
	Ok(file)
}
fn private(file: &File, length: u64) -> Result<FileStamp> {
	let m = file.metadata()?;
	if !m.is_file()
		|| m.uid() != unsafe { libc::geteuid() }
		|| m.mode() & 0o7777 != 0o600
		|| m.nlink() != 0
		|| m.len() != length
	{
		bail!("archive comparison spool changed");
	}
	Ok(FileStamp {
		device: m.dev(),
		inode: m.ino(),
		mode: m.mode(),
		uid: m.uid(),
		links: m.nlink(),
		length: m.len(),
		modified: (m.mtime(), m.mtime_nsec()),
		changed: (m.ctime(), m.ctime_nsec()),
	})
}
pub(super) struct Spool {
	file: File,
	length: u64,
	rows: u64,
	runs: u64,
	headers: [u8; 32],
	stamp: FileStamp,
	order: SortOrder,
	writeback_trace: Option<WritebackTrace>,
}
pub(super) struct Writer {
	output: BufWriter<File>,
	length: u64,
	rows: u64,
	runs: u64,
	headers: ArchiveHash,
	current: Option<(u64, u64, ArchiveHash, Option<Image>)>,
	order: SortOrder,
	written_back: u64,
	writeback_trace: Option<WritebackTrace>,
}
impl Writer {
	pub(super) fn new(root: &File) -> Result<Self> {
		Self::with_order(root, SortOrder::Identity)
	}
	fn with_order(root: &File, order: SortOrder) -> Result<Self> {
		Ok(Self {
			output: BufWriter::with_capacity(64 * 1024, temporary(root)?),
			length: 0,
			rows: 0,
			runs: 0,
			headers: digest(b"archive-comparison-headers-v1"),
			current: None,
			order,
			written_back: 0,
			writeback_trace: tracing_enabled().then(WritebackTrace::new),
		})
	}
	pub(super) fn begin(&mut self) -> Result<()> {
		if self.current.is_some() {
			bail!("archive comparison run still open");
		}
		let offset = self.length;
		self.output.write_all(&[0; HEADER])?;
		self.length = self
			.length
			.checked_add(HEADER as u64)
			.ok_or_else(|| anyhow!("archive comparison offset overflow"))?;
		self.current = Some((offset, 0, digest(b"archive-comparison-records-v1"), None));
		Ok(())
	}
	pub(super) fn push(&mut self, image: Image) -> Result<()> {
		let (_, count, hash, last) = self
			.current
			.as_mut()
			.ok_or_else(|| anyhow!("archive comparison run missing"))?;
		if last
			.as_ref()
			.is_some_and(|old| !self.order.compare(old, &image).is_lt())
		{
			bail!("archive comparison duplicate or unordered identity");
		}
		*last = Some(image);
		hash.update(image);
		self.output.write_all(&image)?;
		*count = count
			.checked_add(1)
			.ok_or_else(|| anyhow!("archive comparison count overflow"))?;
		self.length = self
			.length
			.checked_add(VALUE_BYTES as u64)
			.ok_or_else(|| anyhow!("archive comparison offset overflow"))?;
		if self.length - self.written_back >= WRITEBACK_BYTES {
			self.writeback()?;
		}
		Ok(())
	}
	fn writeback(&mut self) -> Result<()> {
		let started = self.writeback_trace.as_ref().map(|_| Instant::now());
		let result = (|| -> Result<()> {
			self.output.flush()?;
			#[cfg(target_os = "linux")]
			{
				self.output.get_ref().sync_data()?;
				release_pages(self.output.get_ref(), self.written_back, self.length);
			}
			Ok(())
		})();
		if let (Some(stats), Some(started)) = (&mut self.writeback_trace, started) {
			let elapsed = started.elapsed();
			stats.calls += 1;
			stats.elapsed += elapsed;
			stats.maximum = stats.maximum.max(elapsed);
		}
		result?;
		self.written_back = self.length / PAGE_BYTES * PAGE_BYTES;
		Ok(())
	}
	pub(super) fn end(&mut self) -> Result<()> {
		let (offset, count, hash, _) = self
			.current
			.take()
			.ok_or_else(|| anyhow!("archive comparison run missing"))?;
		self.output.flush()?;
		let mut header = [0; HEADER];
		header[..8].copy_from_slice(&count.to_be_bytes());
		header[8..].copy_from_slice(&hash.finalize());
		self.output.get_ref().write_all_at(&header, offset)?;
		self.headers.update(header);
		self.rows = self
			.rows
			.checked_add(count)
			.ok_or_else(|| anyhow!("archive comparison count overflow"))?;
		self.runs += 1;
		Ok(())
	}
	pub(super) fn finish(mut self) -> Result<Spool> {
		if self.current.is_some() {
			self.end()?;
		}
		self.writeback()?;
		let stamp = private(self.output.get_ref(), self.length)?;
		if let Some(stats) = &mut self.writeback_trace {
			stats.build_elapsed = stats.started.elapsed();
		}
		let file = self.output.into_inner().map_err(|e| e.into_error())?;
		Ok(Spool {
			file,
			length: self.length,
			rows: self.rows,
			runs: self.runs,
			headers: self.headers.finalize(),
			stamp,
			order: self.order,
			writeback_trace: self.writeback_trace,
		})
	}
}
struct Run<'a> {
	file: &'a File,
	position: u64,
	end: u64,
	left: u64,
	expected: [u8; 32],
	hash: Option<ArchiveHash>,
	stamp: FileStamp,
	buffer: Box<[u8]>,
	used: usize,
	available: usize,
	last: Option<Image>,
	order: SortOrder,
	released: u64,
}
impl<'a> Run<'a> {
	fn open(spool: &'a Spool, offset: u64, headers: &mut ArchiveHash) -> Result<Self> {
		if private(&spool.file, spool.length)? != spool.stamp {
			bail!("archive comparison spool changed");
		}
		let mut header = [0; HEADER];
		spool.file.read_exact_at(&mut header, offset)?;
		headers.update(header);
		let count = u64::from_be_bytes(header[..8].try_into()?);
		let position = offset
			.checked_add(HEADER as u64)
			.ok_or_else(|| anyhow!("archive comparison offset overflow"))?;
		let end = count
			.checked_mul(VALUE_BYTES as u64)
			.and_then(|bytes| position.checked_add(bytes))
			.filter(|end| *end <= spool.length)
			.ok_or_else(|| anyhow!("archive comparison run exceeds file"))?;
		Ok(Self {
			file: &spool.file,
			position,
			end,
			left: count,
			expected: header[8..].try_into()?,
			hash: Some(digest(b"archive-comparison-records-v1")),
			stamp: spool.stamp,
			buffer: vec![0; VALUE_BYTES * READ_ROWS].into_boxed_slice(),
			used: 0,
			available: 0,
			last: None,
			order: spool.order,
			released: position,
		})
	}
	fn next(&mut self) -> Result<Option<Image>> {
		if self.left == 0 {
			release_pages(self.file, self.released, self.position);
			self.released = self.position / PAGE_BYTES * PAGE_BYTES;
			if private(self.file, self.stamp.length)? != self.stamp {
				bail!("archive comparison spool changed");
			}
			if let Some(hash) = self.hash.take() {
				if hash.finalize() != self.expected {
					bail!("archive comparison record digest changed");
				}
			}
			return Ok(None);
		}
		if self.used == self.available {
			release_pages(self.file, self.released, self.position);
			self.released = self.position / PAGE_BYTES * PAGE_BYTES;
			let records = self.left.min(READ_ROWS as u64) as usize;
			self.available = records * VALUE_BYTES;
			self.used = 0;
			self.file
				.read_exact_at(&mut self.buffer[..self.available], self.position)?;
			// Hash the exact contiguous payload already read into this fixed buffer.
			// Record order and consumption are still checked below, and only a
			// fully consumed EOF may finalize and accept the complete run digest.
			self.hash
				.as_mut()
				.ok_or_else(|| anyhow!("archive comparison digest unavailable"))?
				.update(&self.buffer[..self.available]);
			self.position += self.available as u64;
		}
		let image: Image = self.buffer[self.used..self.used + VALUE_BYTES].try_into()?;
		self.used += VALUE_BYTES;
		self.left -= 1;
		if self
			.last
			.as_ref()
			.is_some_and(|old| !self.order.compare(old, &image).is_lt())
		{
			bail!("archive comparison duplicate or unordered identity");
		}
		self.last = Some(image);
		Ok(Some(image))
	}
}
impl Spool {
	pub(super) fn byte_length(&self) -> u64 {
		self.length
	}
	pub(super) fn run_count(&self) -> u64 {
		self.runs
	}
	fn one(&self) -> Result<Run<'_>> {
		if private(&self.file, self.length)? != self.stamp {
			bail!("archive comparison spool changed");
		}
		if self.runs != 1 {
			bail!("archive comparison sort incomplete");
		}
		let mut headers = digest(b"archive-comparison-headers-v1");
		let run = Run::open(self, 0, &mut headers)?;
		if run.end != self.length || run.left != self.rows || headers.finalize() != self.headers {
			bail!("archive comparison header changed");
		}
		Ok(run)
	}
	#[cfg(test)]
	fn sorted(self, root: &File, deadline: Instant, cancelled: &AtomicBool) -> Result<Self> {
		self.merge_until(root, deadline, cancelled, 1, None)
	}
	fn reduced(
		self,
		root: &File,
		deadline: Instant,
		cancelled: &AtomicBool,
		partition: usize,
	) -> Result<Self> {
		self.merge_until(root, deadline, cancelled, FAN_IN as u64, Some(partition))
	}
	fn merge_until(
		mut self,
		root: &File,
		deadline: Instant,
		cancelled: &AtomicBool,
		maximum_runs: u64,
		partition: Option<usize>,
	) -> Result<Self> {
		live(cancelled, deadline)?;
		let started = tracing_enabled().then(Instant::now);
		let input_runs = self.runs;
		let stream_role = self.order.stream_role();
		if let (Some(partition), Some(stats)) = (partition, &self.writeback_trace) {
			eprintln!("archive_index cold_stage=physical_spool_ready partition={partition} rows={} runs={} bytes={} build_elapsed_ms={} writeback_calls={} writeback_elapsed_ms={} writeback_max_ms={} stream_role={stream_role}", self.rows, self.runs, self.length, stats.build_elapsed.as_millis(), stats.calls, stats.elapsed.as_millis(), stats.maximum.as_millis());
		}
		let mut generation = 0;
		while self.runs > maximum_runs {
			live(cancelled, deadline)?;
			if private(&self.file, self.length)? != self.stamp {
				bail!("archive comparison spool changed");
			}
			let generation_started = started.map(|_| Instant::now());
			let mut output = Writer::with_order(root, self.order)?;
			let mut offset = 0;
			let mut seen = 0;
			let mut headers = digest(b"archive-comparison-headers-v1");
			while offset < self.length {
				let mut readers = Vec::with_capacity(FAN_IN);
				let mut heap = BinaryHeap::new();
				for index in 0..FAN_IN {
					if offset == self.length {
						break;
					}
					let mut reader = Run::open(&self, offset, &mut headers)?;
					offset = reader.end;
					seen += 1;
					if let Some(image) = reader.next()? {
						heap.push(Reverse((merge_key(self.order, &image), image, index)));
					}
					readers.push(reader);
				}
				output.begin()?;
				while let Some(Reverse((_, image, index))) = heap.pop() {
					live(cancelled, deadline)?;
					output.push(image)?;
					if let Some(next) = readers[index].next()? {
						heap.push(Reverse((merge_key(self.order, &next), next, index)));
					}
				}
				output.end()?;
			}
			if seen != self.runs || headers.finalize() != self.headers {
				bail!("archive comparison header changed");
			}
			let next = output.finish()?;
			if next.rows != self.rows {
				bail!("archive comparison count changed");
			}
			generation += 1;
			if let (Some(partition), Some(generation_started), Some(stats)) =
				(partition, generation_started, &next.writeback_trace)
			{
				eprintln!("archive_index cold_stage=physical_merge_generation partition={partition} generation={generation} input_runs={} output_runs={} rows={} input_bytes={} output_bytes={} elapsed_ms={} writeback_calls={} writeback_elapsed_ms={} writeback_max_ms={} stream_role={stream_role}", self.runs, next.runs, next.rows, self.length, next.length, generation_started.elapsed().as_millis(), stats.calls, stats.elapsed.as_millis(), stats.maximum.as_millis());
			}
			self = next;
		}
		if let (Some(partition), Some(started)) = (partition, started) {
			eprintln!("archive_index cold_stage=physical_sort_partition_complete partition={partition} rows={} input_runs={input_runs} output_runs={} generations={generation} elapsed_ms={} stream_role={stream_role}", self.rows, self.runs, started.elapsed().as_millis());
		}
		Ok(self)
	}
}
fn merge_key(order: SortOrder, image: &Image) -> [u8; 48] {
	let mut key = [0u8; 48];
	match order {
		SortOrder::Identity => key[..32].copy_from_slice(&image[..32]),
		#[cfg(test)]
		SortOrder::Inode => {
			key[..16].copy_from_slice(&image[32..48]);
			key[16..].copy_from_slice(&image[..32]);
		}
	}
	key
}

/// The last merge is a read-only stream: every input run is still fully hashed
/// and checked, without writing and rereading a final disposable generation.
/// Sorting has joined before this is created, so at most four times FAN_IN
/// readers exist, matching the old four simultaneous materialized merges.
struct TerminalMerge<'a> {
	sources: &'a [Spool],
	readers: Vec<Run<'a>>,
	heap: BinaryHeap<Reverse<([u8; 48], Image, usize)>>,
	last: Option<Image>,
	rows: u64,
	emitted: u64,
	complete: bool,
	order: SortOrder,
}
impl<'a> TerminalMerge<'a> {
	#[cfg(test)]
	fn new(sources: &'a [Spool], deadline: Instant, cancelled: &AtomicBool) -> Result<Self> {
		Self::with_order(sources, deadline, cancelled, SortOrder::Inode)
	}
	fn with_order(
		sources: &'a [Spool],
		deadline: Instant,
		cancelled: &AtomicBool,
		order: SortOrder,
	) -> Result<Self> {
		live(cancelled, deadline)?;
		if sources.is_empty() || sources.len() > COLD_ROW_WORKERS {
			bail!("archive terminal partition coverage changed");
		}
		let mut readers = Vec::with_capacity(TERMINAL_READERS);
		let mut heap = BinaryHeap::new();
		let mut rows = 0u64;
		for source in sources {
			if source.order != order || source.runs == 0 || source.runs > FAN_IN as u64 {
				bail!("archive terminal sort incomplete");
			}
			if private(&source.file, source.length)? != source.stamp {
				bail!("archive comparison spool changed");
			}
			let mut offset = 0;
			let mut seen = 0;
			let mut source_rows = 0u64;
			let mut headers = digest(b"archive-comparison-headers-v1");
			while offset < source.length {
				live(cancelled, deadline)?;
				if seen >= source.runs || readers.len() >= TERMINAL_READERS {
					bail!("archive comparison run coverage changed");
				}
				let mut reader = Run::open(source, offset, &mut headers)?;
				offset = reader.end;
				seen += 1;
				source_rows = source_rows
					.checked_add(reader.left)
					.ok_or_else(|| anyhow!("archive comparison count overflow"))?;
				let index = readers.len();
				if let Some(image) = reader.next()? {
					heap.push(Reverse((merge_key(order, &image), image, index)));
				}
				readers.push(reader);
			}
			if seen != source.runs
				|| source_rows != source.rows
				|| offset != source.length
				|| headers.finalize() != source.headers
			{
				bail!("archive comparison header or count changed");
			}
			rows = rows
				.checked_add(source_rows)
				.ok_or_else(|| anyhow!("archive comparison count overflow"))?;
		}
		Ok(Self {
			sources,
			readers,
			heap,
			last: None,
			rows,
			emitted: 0,
			complete: false,
			order,
		})
	}
	fn next(&mut self, deadline: Instant, cancelled: &AtomicBool) -> Result<Option<Image>> {
		live(cancelled, deadline)?;
		if self.complete {
			return Ok(None);
		}
		let Some(Reverse((_, image, index))) = self.heap.pop() else {
			if self.emitted != self.rows
				|| self
					.readers
					.iter()
					.any(|run| run.left != 0 || run.position != run.end || run.hash.is_some())
			{
				bail!("archive terminal stream coverage changed");
			}
			for source in self.sources {
				if private(&source.file, source.length)? != source.stamp {
					bail!("archive comparison spool changed");
				}
			}
			self.complete = true;
			return Ok(None);
		};
		if self
			.last
			.as_ref()
			.is_some_and(|old| !self.order.compare(old, &image).is_lt())
		{
			bail!("archive terminal duplicate or unordered identity");
		}
		if let Some(next) = self.readers[index].next()? {
			self.heap
				.push(Reverse((merge_key(self.order, &next), next, index)));
		}
		self.emitted = self
			.emitted
			.checked_add(1)
			.filter(|count| *count <= self.rows)
			.ok_or_else(|| anyhow!("archive terminal count changed"))?;
		self.last = Some(image);
		Ok(Some(image))
	}
}

struct Sorter {
	writer: Writer,
	cohort: Vec<Image>,
}
impl Sorter {
	fn new(root: &File) -> Result<Self> {
		Self::with_order(root, SortOrder::Identity)
	}
	fn with_order(root: &File, order: SortOrder) -> Result<Self> {
		Ok(Self {
			writer: Writer::with_order(root, order)?,
			cohort: Vec::with_capacity(SORT_ROWS),
		})
	}
	fn push(&mut self, image: Image) -> Result<()> {
		self.cohort.push(image);
		if self.cohort.len() == SORT_ROWS {
			self.flush()?;
		}
		Ok(())
	}
	fn flush(&mut self) -> Result<()> {
		if self.cohort.is_empty() {
			return Ok(());
		}
		self.cohort
			.sort_unstable_by(|a, b| self.writer.order.compare(a, b));
		self.writer.begin()?;
		for image in self.cohort.drain(..) {
			self.writer.push(image)?;
		}
		self.writer.end()
	}
	fn finish(mut self) -> Result<Spool> {
		self.flush()?;
		if self.writer.runs == 0 {
			self.writer.begin()?;
			self.writer.end()?;
		}
		self.writer.finish()
	}
}

#[cfg(test)]
fn observe_legacy_test_sources(
	slot: &Slot,
	deadline: Instant,
	cancelled: &AtomicBool,
) -> Result<Vec<Spool>> {
	let pool = rayon::ThreadPoolBuilder::new()
		.num_threads(STAT_WORKERS)
		.build()?;
	let mut sorters = (0..COLD_ROW_WORKERS)
		.map(|_| Sorter::new(&slot.root))
		.collect::<Result<Vec<_>>>()?;
	let mut names = Vec::with_capacity(DIRECTORY_COHORT);
	let mut check = |names: &mut Vec<String>| -> Result<()> {
		let images = pool.install(|| {
			names
				.par_iter()
				.map(|filename| -> Result<Image> {
					live(cancelled, deadline)?;
					let identity = id(filename
						.strip_suffix(".json")
						.ok_or_else(|| anyhow!("invalid archive member"))?)?;
					Ok(order_image(&identity, stamp(&slot.archive, filename)?))
				})
				.collect::<Result<Vec<_>>>()
		})?;
		for image in images {
			sorters[image[0] as usize * COLD_ROW_WORKERS / 256].push(image)?;
		}
		names.clear();
		Ok(())
	};
	slot.archive.walk(|_, filename, _| {
		live(cancelled, deadline)?;
		if staging(filename)? {
			return Ok(());
		}
		if !filename.strip_suffix(".json").is_some_and(valid_id) {
			bail!("invalid archive member");
		}
		names.push(filename.to_owned());
		if names.len() == DIRECTORY_COHORT {
			check(&mut names)?;
		}
		Ok(())
	})?;
	check(&mut names)?;
	sorters.into_iter().map(Sorter::finish).collect()
}
fn filename(identity: &[u8]) -> Result<String> {
	if identity.len() != 32 {
		bail!("invalid archive comparison identity");
	}
	let mut key = [0; 80];
	key[48..].copy_from_slice(identity);
	let mut image = [0; VALUE_BYTES];
	image[..32].copy_from_slice(identity);
	Ok(decode(&key, &image)?.0)
}
#[cfg(test)]
fn join(
	slot: &Slot,
	expected: &Spool,
	actual: &Spool,
	deadline: Instant,
	cancelled: &AtomicBool,
	output: &Sender,
) -> Result<()> {
	let mut expected = expected.one()?;
	let mut actual = actual.one()?;
	let mut old = expected.next()?;
	let mut seen = actual.next()?;
	let mut changes = Vec::with_capacity(BUILD_CHUNK);
	let mut changed = Vec::with_capacity(BUILD_CHUNK);
	loop {
		live(cancelled, deadline)?;
		match (old.as_ref(), seen.as_ref()) {
			(None, None) => break,
			(Some(a), Some(b)) if a[..32] == b[..32] => {
				if a != b {
					changed.push((filename(&a[..32])?, decode_stamp(&a[32..])?));
				}
				old = expected.next()?;
				seen = actual.next()?;
			}
			(Some(a), Some(b)) if a[..32] < b[..32] => {
				bail!("archive original identity coverage changed")
			}
			(Some(_), None) => bail!("archive original identity coverage changed"),
			(_, Some(b)) => {
				changes.push(checked_original(slot, &filename(&b[..32])?)?);
				seen = actual.next()?;
			}
		}
		if changed.len() == BUILD_CHUNK {
			original_cohort(
				slot,
				&mut changed,
				&mut changes,
				deadline,
				cancelled,
				output,
			)?;
		}
		if changes.len() >= BUILD_CHUNK {
			output
				.send(Message::Changes(std::mem::take(&mut changes)))
				.map_err(|_| anyhow!("archive writer unavailable"))?;
		}
	}
	original_cohort(
		slot,
		&mut changed,
		&mut changes,
		deadline,
		cancelled,
		output,
	)?;
	if !changes.is_empty() {
		output
			.send(Message::Changes(changes))
			.map_err(|_| anyhow!("archive writer unavailable"))?;
	}
	Ok(())
}

/// Full ROW-derived images retain every ID and stamp; only their visit order
/// changes to group filesystem inode metadata reads. The spool is disposable.
#[cfg(test)]
pub(super) struct Expected(Sorter);
#[cfg(test)]
impl Expected {
	pub(super) fn new(root: &File) -> Result<Self> {
		Ok(Self(Sorter::with_order(root, SortOrder::Inode)?))
	}
	pub(super) fn push(&mut self, image: Image) -> Result<()> {
		self.0.push(image)
	}
	pub(super) fn finish(self) -> Result<Spool> {
		self.0.finish()
	}
}

#[cfg(test)]
fn check_expected(
	slot: &Slot,
	expected: &Spool,
	pool: &rayon::ThreadPool,
	deadline: Instant,
	cancelled: &AtomicBool,
	output: &Sender,
) -> Result<()> {
	check_sources(
		slot,
		std::slice::from_ref(expected),
		pool,
		deadline,
		cancelled,
		output,
	)
}

#[cfg(test)]
struct CheckTrace {
	started: Instant,
	last_report: Instant,
	stat_elapsed: Duration,
	checked: u64,
	changed: u64,
	cohorts: u64,
}
#[cfg(test)]
fn check_sources(
	slot: &Slot,
	sources: &[Spool],
	pool: &rayon::ThreadPool,
	deadline: Instant,
	cancelled: &AtomicBool,
	output: &Sender,
) -> Result<()> {
	let mut trace = tracing_enabled().then(|| CheckTrace {
		started: Instant::now(),
		last_report: Instant::now(),
		stat_elapsed: Duration::ZERO,
		checked: 0,
		changed: 0,
		cohorts: 0,
	});
	let result = (|| {
		let mut input = TerminalMerge::new(sources, deadline, cancelled)?;
		let mut cohort = Vec::with_capacity(BUILD_CHUNK);
		let mut flush = |cohort: &mut Vec<(String, FileStamp)>| -> Result<()> {
			if cohort.is_empty() {
				return Ok(());
			}
			let started = trace.as_ref().map(|_| Instant::now());
			let result = pool.install(|| {
				cohort
					.par_iter()
					.map(|(filename, old)| -> Result<Option<Entry>> {
						live(cancelled, deadline)?;
						let actual = stamp(&slot.archive, filename).map_err(|error| {
							if error
								.downcast_ref::<std::io::Error>()
								.is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound)
							{
								anyhow!("archive original identity coverage changed: {error}")
							} else {
								error
							}
						})?;
						if actual == *old {
							Ok(None)
						} else {
							checked_original(slot, filename).map(Some)
						}
					})
					.collect::<Result<Vec<_>>>()
			});
			if let (Some(stats), Some(started)) = (&mut trace, started) {
				stats.stat_elapsed += started.elapsed();
			}
			let changes: Vec<_> = result?.into_iter().flatten().collect();
			if let Some(stats) = &mut trace {
				stats.checked += cohort.len() as u64;
				stats.changed += changes.len() as u64;
				stats.cohorts += 1;
				if stats.last_report.elapsed() >= Duration::from_secs(5) {
					eprintln!("archive_index cold_stage=physical_stat_stream_progress checked_rows={} changed_rows={} cohorts={} stat_elapsed_ms={} elapsed_ms={}", stats.checked, stats.changed, stats.cohorts, stats.stat_elapsed.as_millis(), stats.started.elapsed().as_millis());
					stats.last_report = Instant::now();
				}
			}
			if !changes.is_empty() {
				output
					.send(Message::Changes(changes))
					.map_err(|_| anyhow!("archive writer unavailable"))?;
			}
			cohort.clear();
			Ok(())
		};
		while let Some(image) = input.next(deadline, cancelled)? {
			cohort.push((filename(&image[..32])?, decode_stamp(&image[32..])?));
			if cohort.len() == BUILD_CHUNK {
				flush(&mut cohort)?;
			}
		}
		flush(&mut cohort)
	})();
	if let Some(stats) = trace {
		let status = if result.is_ok() { "passed" } else { "failed" };
		eprintln!("archive_index cold_stage=physical_stat_stream_complete status={status} checked_rows={} changed_rows={} cohorts={} stat_elapsed_ms={} elapsed_ms={} maximum_readers={TERMINAL_READERS} global_inode_order=true", stats.checked, stats.changed, stats.cohorts, stats.stat_elapsed.as_millis(), stats.started.elapsed().as_millis());
	}
	result
}

fn reduce_sources(
	slot: &Slot,
	sources: Vec<(usize, Spool)>,
	deadline: Instant,
	cancelled: &AtomicBool,
) -> Result<Vec<Spool>> {
	std::thread::scope(|scope| {
		let handles: Vec<_> = sources
			.into_iter()
			.map(|(partition, source)| {
				scope.spawn(move || {
					let result = source.reduced(&slot.root, deadline, cancelled, partition);
					if result.is_err() {
						cancelled.store(true, Ordering::Relaxed);
					}
					result
				})
			})
			.collect();
		let mut reduced = Vec::with_capacity(COLD_ROW_WORKERS);
		let mut failure = None;
		for handle in handles {
			let result = match handle.join() {
				Ok(result) => result,
				Err(_) => Err(anyhow!("archive comparison sort worker panicked")),
			};
			match result {
				Ok(source) => reduced.push(source),
				Err(error) => {
					cancelled.store(true, Ordering::Relaxed);
					if failure.is_none() {
						failure = Some(error);
					}
				}
			}
		}
		match failure {
			Some(error) => Err(error),
			None => Ok(reduced),
		}
	})
}

#[derive(Default)]
struct CoordinatorTrace {
	receive_timeouts: u64,
	original_done: Option<Duration>,
}
impl CoordinatorTrace {
	fn timeout(&mut self) {
		self.receive_timeouts = self.receive_timeouts.saturating_add(1);
	}
	fn done(&mut self, elapsed: Duration) {
		self.original_done = Some(elapsed);
	}
	fn complete(&self, elapsed: Duration, passed: bool) -> String {
		let done = self
			.original_done
			.map_or_else(|| "none".to_owned(), |time| time.as_millis().to_string());
		let tail = self.original_done.map_or_else(
			|| "none".to_owned(),
			|time| elapsed.saturating_sub(time).as_micros().to_string(),
		);
		let status = if passed { "passed" } else { "failed" };
		format!("archive_index cold_stage=physical_coordinator_scope_complete status={status} receive_timeouts={} original_done_relative_ms={done} scope_complete_relative_ms={} post_original_done_elapsed_us={tail}", self.receive_timeouts, elapsed.as_millis())
	}
}

pub(super) fn verify(
	database: &Database,
	slot: &Slot,
	sources: Vec<(usize, Spool)>,
	deadline: Instant,
) -> Result<Option<OriginalCoverage>> {
	let mut budget = OriginalBudget::new(tracing_enabled(), Instant::now());
	let result = verify_observed(database, slot, sources, None, deadline, &mut budget);
	budget.trace();
	result
}

pub(super) fn verify_observed(
	database: &Database,
	slot: &Slot,
	sources: Vec<(usize, Spool)>,
	observed: Option<Observed>,
	deadline: Instant,
	budget: &mut OriginalBudget,
) -> Result<Option<OriginalCoverage>> {
	let started = Instant::now();
	let tracing = tracing_enabled();
	let mut coordinator_trace = tracing.then(CoordinatorTrace::default);
	let cancelled = AtomicBool::new(false);
	if sources.len() != COLD_ROW_WORKERS {
		bail!("archive comparison partition coverage changed");
	}
	let mut sources = sources;
	sources.sort_unstable_by_key(|(part, _)| *part);
	if sources
		.iter()
		.enumerate()
		.any(|(part, (found, _))| part != *found)
	{
		bail!("archive comparison partition coverage changed");
	}
	let pool = rayon::ThreadPoolBuilder::new()
		.num_threads(STAT_WORKERS)
		.build()?;
	let result = std::thread::scope(|scope| {
		let (send, receive) = std::sync::mpsc::sync_channel(1);
		let cancellation = &cancelled;
		let pool = &pool;
		let output = send.clone();
		scope.spawn(move || {
			let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
			let result = match observed {
				Some(Observed(observed)) => directory::join_observed(slot, sources, observed, deadline, cancellation, &output).map(Some),
				None => verify_original_sources(slot, sources, pool, deadline, cancellation, &output),
			};
			if tracing {
				let status = if result.is_ok() { "passed" } else { "failed" };
				eprintln!("archive_index cold_stage=physical_coordinator_worker_complete status={status} relative_ms={}", started.elapsed().as_millis());
			}
			result
			})).unwrap_or_else(|_| Err(anyhow!("archive comparison worker panicked")));
			let message = match result {
				Ok(coverage) => Message::OriginalDone(coverage),
				Err(error) => Message::Failed(error),
			};
			let _ = output.send(message);
		});
		drop(send);
		let result = (|| {
			let mut finished = false;
			let mut coverage = None;
			let mut changes = Vec::new();
			while !finished {
				match receive.recv_timeout(MAINTENANCE_INTERVAL) {
					Ok(Message::OriginalDone(observed)) => {
						coverage = observed;
						finished = true;
						if let Some(trace) = &mut coordinator_trace {
							let elapsed = started.elapsed();
							trace.done(elapsed);
							eprintln!("archive_index cold_stage=physical_coordinator_original_done relative_ms={} receive_timeouts={}", elapsed.as_millis(), trace.receive_timeouts);
						}
					}
					Ok(Message::Changes(entries)) => changes = entries,
					Ok(Message::Failed(error)) => return Err(error),
					Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
						if let Some(trace) = &mut coordinator_trace {
							trace.timeout();
						}
					}
					_ => bail!("archive comparison worker unavailable"),
				}
				fold_cache_changes(database, slot, &mut changes)?;
				budget.maintain();
			}
			// The original worker joins every partition worker before OriginalDone,
			// so every bounded Changes send has completed first. The final receive
			// iteration also folds before returning.
			Ok(coverage)
		})();
		cancelled.store(true, Ordering::Relaxed);
		drop(receive);
		result
	});
	if let Some(trace) = &coordinator_trace {
		eprintln!("{}", trace.complete(started.elapsed(), result.is_ok()));
	}
	if result.is_ok() && tracing {
		eprintln!(
			"archive_index cold_stage=original_physical_stream_checks_complete elapsed_ms={}",
			started.elapsed().as_millis()
		);
	}
	result
}

fn verify_original_sources(
	slot: &Slot,
	sources: Vec<(usize, Spool)>,
	pool: &rayon::ThreadPool,
	deadline: Instant,
	cancelled: &AtomicBool,
	output: &Sender,
) -> Result<Option<OriginalCoverage>> {
	// Retain the former inode-stream regression fixtures without making that
	// visitation strategy reachable from a production ROW partition.
	#[cfg(test)]
	if sources
		.first()
		.is_some_and(|(_, source)| source.order == SortOrder::Inode)
	{
		return reduce_sources(slot, sources, deadline, cancelled)
			.and_then(|sources| check_sources(slot, &sources, pool, deadline, cancelled, output))
			.map(|()| None);
	}
	directory::verify_sources(slot, sources, pool, deadline, cancelled, output).map(Some)
}

#[cfg(test)]
#[path = "request_archive_runs_tests.rs"]
mod tests;

pub(super) fn trace() {
	eprintln!("archive_index physical_original_workers={STAT_WORKERS} maximum_original_cohort={BUILD_CHUNK} disk_merge_fan_in={FAN_IN} disk_run_buffer_records={READ_ROWS} constant_RAM=true every_stamp_compared_directly=true full_id_preserved=true terminal_merge_streaming=true terminal_merge_maximum_readers={TERMINAL_READERS} global_inode_visit_order=false visit_order=directory_batch_inode maximum_directory_name_batch={} maximum_identity_join_readers={} identity_join_workers={} maximum_partition_join_readers={}", directory::NAME_BATCH, directory::JOIN_READER_BOUND, directory::JOIN_WORKERS, FAN_IN + 1);
}
