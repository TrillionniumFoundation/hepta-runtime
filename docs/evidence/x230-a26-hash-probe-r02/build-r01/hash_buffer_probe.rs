// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Standalone fixed-scale full-read/SHA256 experiment; never invokes SSH.
use std::fs::{File, Metadata};
use std::io::{self, BufWriter, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::MetadataExt;
use std::process::ExitCode;
use std::time::Instant;

const MAX_BYTES: usize = 16 * 1024 * 1024;
const BLOCKS: usize = 8;
const ITERATIONS: usize = 128;
const WARMUPS: usize = 8;

#[derive(Clone, Debug, Eq, PartialEq)]
struct Stamp {
	dev: u64,
	ino: u64,
	uid: u32,
	mode: u32,
	nlink: u64,
	len: u64,
	mtime: (i64, i64),
	ctime: (i64, i64),
}

impl Stamp {
	fn of(value: &Metadata) -> Self {
		Self {
			dev: value.dev(),
			ino: value.ino(),
			uid: value.uid(),
			mode: value.mode(),
			nlink: value.nlink(),
			len: value.len(),
			mtime: (value.mtime(), value.mtime_nsec()),
			ctime: (value.ctime(), value.ctime_nsec()),
		}
	}
	fn json(&self) -> String {
		format!("{{\"dev\":{},\"ino\":{},\"uid\":{},\"mode\":{},\"nlink\":{},\"len\":{},\"mtime\":[{},{}],\"ctime\":[{},{}]}}",
            self.dev, self.ino, self.uid, self.mode, self.nlink, self.len,
            self.mtime.0, self.mtime.1, self.ctime.0, self.ctime.1)
	}
}

#[derive(Debug)]
struct Failure {
	stage: &'static str,
	detail: String,
	errno: Option<i32>,
}

type ProbeResult<T> = Result<T, Failure>;

impl Failure {
	fn io(stage: &'static str, error: io::Error) -> Self {
		Self {
			stage,
			detail: error.to_string(),
			errno: error.raw_os_error(),
		}
	}
	fn check(stage: &'static str, detail: &str) -> Self {
		Self {
			stage,
			detail: detail.to_owned(),
			errno: None,
		}
	}
	fn json(&self) -> String {
		format!(
			"{{\"stage\":{},\"detail\":{},\"errno\":{}}}",
			quote(self.stage),
			quote(&self.detail),
			self.errno
				.map_or_else(|| "null".to_owned(), |v| v.to_string())
		)
	}
}

fn quote(value: &str) -> String {
	let mut out = String::from("\"");
	for value in value.chars() {
		match value {
			'"' => out.push_str("\\\""),
			'\\' => out.push_str("\\\\"),
			'\n' => out.push_str("\\n"),
			'\r' => out.push_str("\\r"),
			'\t' => out.push_str("\\t"),
			value if value < '\u{20}' => out.push_str(&format!("\\u{:04x}", value as u32)),
			value => out.push(value),
		}
	}
	out.push('"');
	out
}

fn hex(value: &[u8; 32]) -> String {
	value.iter().map(|v| format!("{v:02x}")).collect()
}

fn require(value: bool, stage: &'static str, detail: &str) -> ProbeResult<()> {
	if value {
		Ok(())
	} else {
		Err(Failure::check(stage, detail))
	}
}

fn open_target() -> ProbeResult<File> {
	let mut current = File::open("/").map_err(|e| Failure::io("open_root", e))?;
	for (index, name) in [c"usr", c"bin", c"ssh"].iter().enumerate() {
		let flags = libc::O_RDONLY
			| libc::O_NOFOLLOW
			| libc::O_NONBLOCK
			| libc::O_CLOEXEC
			| if index < 2 { libc::O_DIRECTORY } else { 0 };
		let fd = unsafe { libc::openat(current.as_raw_fd(), name.as_ptr(), flags) };
		if fd < 0 {
			return Err(Failure::io("open_target", io::Error::last_os_error()));
		}
		current = unsafe { File::from_raw_fd(fd) };
	}
	Ok(current)
}

fn checked_target() -> ProbeResult<(File, Stamp)> {
	let file = open_target()?;
	let meta = file
		.metadata()
		.map_err(|e| Failure::io("metadata_before", e))?;
	require(
		meta.is_file()
			&& meta.nlink() == 1
			&& meta.uid() == 0
			&& meta.mode() & 0o6022 == 0
			&& meta.mode() & 0o111 != 0
			&& meta.len() > 0
			&& meta.len() <= MAX_BYTES as u64,
		"target_check",
		"fixed executable inode, permissions, or byte bound differs",
	)?;
	let code = unsafe {
		libc::fgetxattr(
			file.as_raw_fd(),
			c"security.capability".as_ptr(),
			std::ptr::null_mut(),
			0,
		)
	};
	if code >= 0 || io::Error::last_os_error().raw_os_error() != Some(libc::ENODATA) {
		return Err(Failure::check(
			"target_capabilities",
			"unsupported executable capability state",
		));
	}
	Ok((file, Stamp::of(&meta)))
}

fn thread_cpu_ns() -> ProbeResult<u128> {
	let mut value = libc::timespec {
		tv_sec: 0,
		tv_nsec: 0,
	};
	let code = unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut value) };
	if code != 0 {
		return Err(Failure::io("thread_cpu_clock", io::Error::last_os_error()));
	}
	require(
		value.tv_sec >= 0 && (0..1_000_000_000).contains(&value.tv_nsec),
		"thread_cpu_clock",
		"invalid thread CPU clock fields",
	)?;
	Ok(value.tv_sec as u128 * 1_000_000_000 + value.tv_nsec as u128)
}

struct HashRun {
	bytes: usize,
	read_calls: usize,
	interrupted_reads: usize,
	digest: Option<[u8; 32]>,
	failure: Option<Failure>,
}

#[inline(never)]
fn read_hash<const N: usize>(file: &mut File) -> HashRun {
	let mut hash = ring::digest::Context::new(&ring::digest::SHA256);
	let mut buffer = [0; N];
	let mut out = HashRun {
		bytes: 0,
		read_calls: 0,
		interrupted_reads: 0,
		digest: None,
		failure: None,
	};
	let mut reader = Read::by_ref(file).take(MAX_BYTES as u64 + 1);
	loop {
		out.read_calls += 1;
		let count = match Read::read(&mut reader, &mut buffer) {
			Err(error) if error.kind() == io::ErrorKind::Interrupted => {
				out.interrupted_reads += 1;
				continue;
			}
			Err(error) => {
				out.failure = Some(Failure::io("read", error));
				return out;
			}
			Ok(count) => count,
		};
		if count == 0 {
			break;
		}
		out.bytes += count;
		hash.update(&buffer[..count]);
	}
	let mut digest = [0; 32];
	digest.copy_from_slice(hash.finish().as_ref());
	out.digest = Some(digest);
	out
}

struct Pin {
	stamp: Stamp,
	digest: [u8; 32],
}

struct Iteration {
	index: usize,
	before_fd: Option<Stamp>,
	after_fd: Option<Stamp>,
	after_path: Option<Stamp>,
	wall_ns: Option<u128>,
	cpu_ns: Option<u128>,
	read: Option<HashRun>,
	verified: bool,
	failure: Option<Failure>,
}

impl Iteration {
	fn json(&self) -> String {
		let stamp = |v: &Option<Stamp>| v.as_ref().map_or_else(|| "null".to_owned(), Stamp::json);
		let number = |v: Option<u128>| v.map_or_else(|| "null".to_owned(), |v| v.to_string());
		let read = self.read.as_ref().map_or_else(|| "null".to_owned(), |v| format!(
            "{{\"bytes\":{},\"read_calls\":{},\"interrupted_reads\":{},\"sha256\":{},\"failure\":{}}}",
            v.bytes, v.read_calls, v.interrupted_reads,
            v.digest.as_ref().map_or_else(|| "null".to_owned(), |v| quote(&hex(v))),
            v.failure.as_ref().map_or_else(|| "null".to_owned(), Failure::json)));
		format!("{{\"index\":{},\"before_fd\":{},\"after_fd\":{},\"after_path\":{},\"read_hash_wall_ns\":{},\"read_hash_thread_cpu_ns\":{},\"read\":{},\"verified\":{},\"failure\":{}}}",
            self.index, stamp(&self.before_fd), stamp(&self.after_fd), stamp(&self.after_path),
            number(self.wall_ns), number(self.cpu_ns), read, self.verified,
            self.failure.as_ref().map_or_else(|| "null".to_owned(), Failure::json))
	}
}

fn iteration<const N: usize>(pin: &Pin, index: usize) -> Iteration {
	let mut out = Iteration {
		index,
		before_fd: None,
		after_fd: None,
		after_path: None,
		wall_ns: None,
		cpu_ns: None,
		read: None,
		verified: false,
		failure: None,
	};
	let result = (|| -> ProbeResult<()> {
		let (mut file, before) = checked_target()?;
		out.before_fd = Some(before.clone());
		require(
			before == pin.stamp,
			"stamp_before",
			"fixed target changed before timed read",
		)?;
		let cpu_start = thread_cpu_ns()?;
		let wall_start = Instant::now();
		out.read = Some(read_hash::<N>(&mut file));
		out.wall_ns = Some(wall_start.elapsed().as_nanos());
		let cpu_end = thread_cpu_ns()?;
		require(
			cpu_end >= cpu_start,
			"thread_cpu_clock",
			"thread CPU clock moved backwards",
		)?;
		out.cpu_ns = Some(cpu_end - cpu_start);
		let read = out
			.read
			.as_mut()
			.expect("read result set before inspection");
		if let Some(error) = read.failure.take() {
			return Err(error);
		}
		out.after_fd = Some(Stamp::of(
			&file
				.metadata()
				.map_err(|e| Failure::io("metadata_after_fd", e))?,
		));
		out.after_path = Some(Stamp::of(
			&open_target()?
				.metadata()
				.map_err(|e| Failure::io("metadata_after_path", e))?,
		));
		require(
			out.after_fd.as_ref() == Some(&pin.stamp)
				&& out.after_path.as_ref() == Some(&pin.stamp),
			"stamp_after",
			"original descriptor or reopened path changed after timed read",
		)?;
		require(
			read.bytes as u64 == pin.stamp.len && read.bytes <= MAX_BYTES,
			"length",
			"complete-file byte count differs",
		)?;
		require(
			read.digest == Some(pin.digest),
			"digest",
			"complete-file SHA256 differs",
		)?;
		out.verified = true;
		Ok(())
	})();
	if let Err(error) = result {
		out.failure = Some(error);
	}
	out
}

fn emit(output: &mut impl Write, json: &str) -> ProbeResult<()> {
	writeln!(output, "{json}").map_err(|e| Failure::io("write_evidence", e))?;
	output.flush().map_err(|e| Failure::io("flush_evidence", e))
}

fn run_cell<const N: usize>(
	output: &mut impl Write,
	pin: &Pin,
	phase: &str,
	block: Option<usize>,
	slot: char,
	ordinal: usize,
	count: usize,
) -> ProbeResult<()> {
	let start = Instant::now();
	let mut values = Vec::with_capacity(count);
	for index in 0..count {
		let value = iteration::<N>(pin, index);
		let passed = value.verified;
		values.push(value);
		if !passed {
			break;
		}
	}
	let whole_wall = start.elapsed().as_nanos();
	let passed = values.len() == count && values.iter().all(|v| v.verified);
	let cpu: u128 = values.iter().filter_map(|v| v.cpu_ns).sum();
	let wall: u128 = values.iter().filter_map(|v| v.wall_ns).sum();
	emit(output, &format!("{{\"event\":\"cell\",\"phase\":{},\"block\":{},\"slot\":{},\"ordinal\":{},\"buffer_bytes\":{},\"requested_iterations\":{},\"completed_iterations\":{},\"passed\":{},\"read_hash_thread_cpu_ns\":{},\"read_hash_wall_ns\":{},\"whole_cell_wall_ns\":{},\"iterations\":[{}]}}",
        quote(phase), block.map_or_else(|| "null".to_owned(), |v| v.to_string()), quote(&slot.to_string()),
        ordinal, N, count, values.iter().filter(|v| v.verified).count(), passed, cpu, wall, whole_wall,
        values.iter().map(Iteration::json).collect::<Vec<_>>().join(",")))?;
	require(
		passed,
		"cell",
		"failed partial cell retained; later cells were not run",
	)
}

fn run(output: &mut impl Write) -> ProbeResult<()> {
	emit(output, "{\"event\":\"plan\",\"schema\":\"hepta-x230-full-file-hash-microprobe/v1\",\"target\":\"/usr/bin/ssh\",\"maximum_file_bytes\":16777216,\"variants\":{\"A\":16384,\"B\":65536},\"reference_reads\":1,\"warmup_order\":\"AB\",\"warmup_iterations_per_cell\":8,\"blocks\":8,\"order_per_block\":\"ABBA\",\"iterations_per_cell\":128,\"measured_cells\":32,\"measured_full_file_hashes\":4096}")?;
	let (mut file, stamp) = checked_target()?;
	let reference = read_hash::<16384>(&mut file);
	if let Some(error) = reference.failure {
		return Err(error);
	}
	let after_fd = Stamp::of(
		&file
			.metadata()
			.map_err(|e| Failure::io("reference_after_fd", e))?,
	);
	let after_path = Stamp::of(
		&open_target()?
			.metadata()
			.map_err(|e| Failure::io("reference_after_path", e))?,
	);
	require(
		stamp == after_fd && stamp == after_path && reference.bytes as u64 == stamp.len,
		"reference",
		"reference descriptor, path, or length changed across the read",
	)?;
	let pin = Pin {
		stamp,
		digest: reference
			.digest
			.ok_or_else(|| Failure::check("reference", "missing digest"))?,
	};
	emit(output, &format!("{{\"event\":\"reference\",\"stamp\":{},\"sha256\":{},\"bytes\":{},\"read_calls\":{},\"interrupted_reads\":{}}}",
        pin.stamp.json(), quote(&hex(&pin.digest)), reference.bytes, reference.read_calls, reference.interrupted_reads))?;
	run_cell::<16384>(output, &pin, "warmup", None, 'A', 0, WARMUPS)?;
	run_cell::<65536>(output, &pin, "warmup", None, 'B', 1, WARMUPS)?;
	for block in 0..BLOCKS {
		run_cell::<16384>(
			output,
			&pin,
			"measured",
			Some(block),
			'A',
			block * 4,
			ITERATIONS,
		)?;
		run_cell::<65536>(
			output,
			&pin,
			"measured",
			Some(block),
			'B',
			block * 4 + 1,
			ITERATIONS,
		)?;
		run_cell::<65536>(
			output,
			&pin,
			"measured",
			Some(block),
			'B',
			block * 4 + 2,
			ITERATIONS,
		)?;
		run_cell::<16384>(
			output,
			&pin,
			"measured",
			Some(block),
			'A',
			block * 4 + 3,
			ITERATIONS,
		)?;
	}
	let (_, final_stamp) = checked_target()?;
	require(
		final_stamp == pin.stamp,
		"final_stamp",
		"fixed target changed before completion",
	)?;
	emit(output, &format!("{{\"event\":\"complete\",\"passed\":true,\"measured_cells\":32,\"measured_full_file_hashes\":4096,\"warmup_cells\":2,\"warmup_full_file_hashes\":16,\"final_stamp\":{},\"reference_sha256\":{}}}",
        final_stamp.json(), quote(&hex(&pin.digest))))
}

fn main() -> ExitCode {
	let stdout = io::stdout();
	let mut output = BufWriter::new(stdout.lock());
	match run(&mut output) {
		Ok(()) => ExitCode::SUCCESS,
		Err(error) => {
			let _ = emit(
				&mut output,
				&format!(
					"{{\"event\":\"failure\",\"passed\":false,\"failure\":{}}}",
					error.json()
				),
			);
			eprintln!("hash microprobe failed; retain all output and do not retry cells");
			ExitCode::FAILURE
		}
	}
}
