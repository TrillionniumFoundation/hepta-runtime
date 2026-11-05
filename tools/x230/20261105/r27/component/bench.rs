// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Fixed-input mechanism benchmark of the original observation preparation code.
use serde_json::json;
use std::hint::black_box;
use std::time::Duration;
#[cfg(not(count_allocations))]
use std::time::Instant;

type Prepared = (String, Vec<u8>, Duration, bool);
type Prepare = fn(&Case) -> anyhow::Result<Prepared>;
const PYTHON_COMMAND_STUB: &str = "python3 -c 'r27 serializer mechanism stub'";
const ROUNDS: usize = 2;
const SMALL_ITERATIONS: u64 = 100_000;
const LARGE_ITERATIONS: u64 = 2_000;
const ALLOCATION_ITERATIONS: u64 = 1_000;

#[cfg(not(count_allocations))]
#[global_allocator]
static ALLOCATOR: std::alloc::System = std::alloc::System;

// BEGIN_EXTRACTED_SOURCE
const SOURCE_METADATA: &str = r#"{"kind":"source","sources":{"baseline":{"file":"/workspace/scratch/806ba5f52f94/r24-tested-source/src/mcp/runtime/ssh.rs","sha256":"4db25902c01d1a501f699ca26c9a70af49860127c625a9e0ff402572ad3e9829","items":[{"name":"limit","sha256":"fd1c020bec9797c019a59094340586bf2a0354f7278041832535c790b9348b7f","bytes":48,"first_line":31,"last_line":31},{"name":"validate","sha256":"c701ff688aaa21b5e44824954fd7334529d13da39a42a94e0cacc8d21122ac45","bytes":293,"first_line":36,"last_line":45},{"name":"script","sha256":"e63affe0edc9f69703c30852014617884bca28aca597e24188f47db0884c7219","bytes":54,"first_line":107,"last_line":110},{"name":"observation","sha256":"9fd17830d2e38ccbef8f8004e4227cebdced5f42e1403b35359b7f0920f07848","bytes":456,"first_line":139,"last_line":165},{"name":"prepare","sha256":"faa62b0f11d4542cfff1ce5a61cd2406ef9b18ba4631db9fe551cf912f7fccd2","bytes":2389,"first_line":260,"last_line":344}]},"candidate":{"file":"/workspace/scratch/b96be991ab90/r27-serializer/apply-check/r24/src/mcp/runtime/ssh.rs","sha256":"d0d3fcc1a6207e0f0b9f761b5e66d9ab82c62ad83a04085165295fa1f41b56f0","items":[{"name":"limit","sha256":"fd1c020bec9797c019a59094340586bf2a0354f7278041832535c790b9348b7f","bytes":48,"first_line":31,"last_line":31},{"name":"validate","sha256":"c701ff688aaa21b5e44824954fd7334529d13da39a42a94e0cacc8d21122ac45","bytes":293,"first_line":36,"last_line":45},{"name":"script","sha256":"e63affe0edc9f69703c30852014617884bca28aca597e24188f47db0884c7219","bytes":54,"first_line":107,"last_line":110},{"name":"observation","sha256":"9fd17830d2e38ccbef8f8004e4227cebdced5f42e1403b35359b7f0920f07848","bytes":456,"first_line":139,"last_line":165},{"name":"payload","sha256":"054c7eb6df1c305da731c320c815d4d2ba9bd9de7e38a4db55fe0982874232e5","bytes":532,"first_line":262,"last_line":292},{"name":"prepare","sha256":"1a594047348b95b1022fec0f4e54c3caf7350d83fee871864681efcb1906d2de","bytes":2409,"first_line":294,"last_line":400}]}}}"#;
mod baseline {
use anyhow::{bail, Result};
use std::time::Duration;
const MAX_OBSERVATION_BYTES: usize = 64 * 1024;

fn validate_observation_bytes(command: &str, input: &[u8]) -> Result<()> {
	if command
		.len()
		.checked_add(input.len())
		.is_none_or(|bytes| bytes > MAX_OBSERVATION_BYTES)
	{
		bail!("observation_pool_payload_unsupported: queued command and stdin exceed64KiB; no fallback");
	}
	Ok(())
}

pub(super) enum ObservationScript {
	Status,
	Read,
}

pub(super) enum JobObservation<'a> {
	PythonStatus {
		job_id: &'a str,
		job_dir: &'a str,
		unit: &'a str,
		request_digest: &'a str,
		wait_seconds: u64,
	},
	PythonRead {
		job_id: &'a str,
		job_dir: &'a str,
		unit: &'a str,
		request_digest: &'a str,
		stdout_offset: u64,
		stderr_offset: u64,
		limit: u64,
	},
	SystemStatus {
		job_id: &'a str,
	},
	SystemRead {
		job_id: &'a str,
		stdout_offset: u64,
		stderr_offset: u64,
		limit: u64,
	},
}

fn prepare_observation(value: JobObservation<'_>) -> Result<(String, Vec<u8>, Duration, bool)> {
	use serde_json::json;
	let fields: &[&str] = match &value {
		JobObservation::PythonStatus {
			job_id,
			job_dir,
			unit,
			request_digest,
			..
		} => &[job_id, job_dir, unit, request_digest],
		JobObservation::PythonRead {
			job_id,
			job_dir,
			unit,
			request_digest,
			..
		} => &[job_id, job_dir, unit, request_digest],
		JobObservation::SystemStatus { job_id } | JobObservation::SystemRead { job_id, .. } => {
			&[job_id]
		}
	};
	// Reject before json! clones or expands an oversized original string.
	if fields
		.iter()
		.try_fold(0usize, |total, field| total.checked_add(field.len()))
		.is_none_or(|bytes| bytes > MAX_OBSERVATION_BYTES)
	{
		bail!("observation_pool_payload_unsupported: original observation fields exceed64KiB; no fallback");
	}
	let (script, input, timeout, system) = match value {
		JobObservation::PythonStatus {
			job_id,
			job_dir,
			unit,
			request_digest,
			wait_seconds,
		} => (
			Some(ObservationScript::Status),
			json!({"job_id":job_id,"job_dir":job_dir,"request_digest":request_digest,"unit":unit,"wait_seconds":wait_seconds.min(30)}),
			Duration::from_secs(wait_seconds.min(30) + 10),
			false,
		),
		JobObservation::PythonRead {
			job_id,
			job_dir,
			unit,
			request_digest,
			stdout_offset,
			stderr_offset,
			limit,
		} => (
			Some(ObservationScript::Read),
			json!({"job_id":job_id,"job_dir":job_dir,"request_digest":request_digest,"unit":unit,"stdout_offset":stdout_offset,"stderr_offset":stderr_offset,"limit":limit}),
			Duration::from_secs(15),
			false,
		),
		JobObservation::SystemStatus { job_id } => (
			None,
			json!({"op":"status","job_id":job_id}),
			Duration::from_secs(20),
			true,
		),
		JobObservation::SystemRead {
			job_id,
			stdout_offset,
			stderr_offset,
			limit,
		} => (
			None,
			json!({"op":"read","job_id":job_id,"stdout_offset":stdout_offset,"stderr_offset":stderr_offset,"limit":limit}),
			Duration::from_secs(20),
			true,
		),
	};
	let command = match script {
		Some(script) => job_observation_command(script)?.to_owned(),
		None => "sudo -n /usr/local/libexec/hepta-runtime-jobctl".to_owned(),
	};
	let mut bytes = serde_json::to_vec(&input)?;
	if system {
		bytes.push(b'\n');
	}
	validate_observation_bytes(&command, &bytes)?;
	Ok((command, bytes, timeout, system))
}

// Both modules use the same fixed stub and the same fixture adapter.
fn job_observation_command(_script: ObservationScript) -> Result<&'static str> {
    Ok(super::PYTHON_COMMAND_STUB)
}

pub(super) const LIMIT: usize = MAX_OBSERVATION_BYTES;

#[inline(never)]
pub(super) fn prepare(case: &super::Case) -> Result<super::Prepared> {
    let value = match case.kind {
        super::Kind::PythonStatus => JobObservation::PythonStatus {
            job_id: &case.job_id,
            job_dir: &case.job_dir,
            unit: &case.unit,
            request_digest: &case.request_digest,
            wait_seconds: case.wait_seconds,
        },
        super::Kind::PythonRead => JobObservation::PythonRead {
            job_id: &case.job_id,
            job_dir: &case.job_dir,
            unit: &case.unit,
            request_digest: &case.request_digest,
            stdout_offset: case.stdout_offset,
            stderr_offset: case.stderr_offset,
            limit: case.limit,
        },
        super::Kind::SystemStatus => JobObservation::SystemStatus { job_id: &case.job_id },
        super::Kind::SystemRead => JobObservation::SystemRead {
            job_id: &case.job_id,
            stdout_offset: case.stdout_offset,
            stderr_offset: case.stderr_offset,
            limit: case.limit,
        },
    };
    prepare_observation(value)
}
}

mod candidate {
use anyhow::{bail, Result};
use std::time::Duration;
use serde::Serialize;
const MAX_OBSERVATION_BYTES: usize = 64 * 1024;

fn validate_observation_bytes(command: &str, input: &[u8]) -> Result<()> {
	if command
		.len()
		.checked_add(input.len())
		.is_none_or(|bytes| bytes > MAX_OBSERVATION_BYTES)
	{
		bail!("observation_pool_payload_unsupported: queued command and stdin exceed64KiB; no fallback");
	}
	Ok(())
}

pub(super) enum ObservationScript {
	Status,
	Read,
}

pub(super) enum JobObservation<'a> {
	PythonStatus {
		job_id: &'a str,
		job_dir: &'a str,
		unit: &'a str,
		request_digest: &'a str,
		wait_seconds: u64,
	},
	PythonRead {
		job_id: &'a str,
		job_dir: &'a str,
		unit: &'a str,
		request_digest: &'a str,
		stdout_offset: u64,
		stderr_offset: u64,
		limit: u64,
	},
	SystemStatus {
		job_id: &'a str,
	},
	SystemRead {
		job_id: &'a str,
		stdout_offset: u64,
		stderr_offset: u64,
		limit: u64,
	},
}

#[derive(Serialize)]
#[serde(untagged)]
enum JobObservationPayload<'a> {
	PythonStatus {
		job_dir: &'a str,
		job_id: &'a str,
		request_digest: &'a str,
		unit: &'a str,
		wait_seconds: u64,
	},
	PythonRead {
		job_dir: &'a str,
		job_id: &'a str,
		limit: u64,
		request_digest: &'a str,
		stderr_offset: u64,
		stdout_offset: u64,
		unit: &'a str,
	},
	SystemStatus {
		job_id: &'a str,
		op: &'static str,
	},
	SystemRead {
		job_id: &'a str,
		limit: u64,
		op: &'static str,
		stderr_offset: u64,
		stdout_offset: u64,
	},
}

fn prepare_observation(value: JobObservation<'_>) -> Result<(String, Vec<u8>, Duration, bool)> {
	let fields: &[&str] = match &value {
		JobObservation::PythonStatus {
			job_id,
			job_dir,
			unit,
			request_digest,
			..
		} => &[job_id, job_dir, unit, request_digest],
		JobObservation::PythonRead {
			job_id,
			job_dir,
			unit,
			request_digest,
			..
		} => &[job_id, job_dir, unit, request_digest],
		JobObservation::SystemStatus { job_id } | JobObservation::SystemRead { job_id, .. } => {
			&[job_id]
		}
	};
	// Reject oversized borrowed fields before serialization can expand them.
	if fields
		.iter()
		.try_fold(0usize, |total, field| total.checked_add(field.len()))
		.is_none_or(|bytes| bytes > MAX_OBSERVATION_BYTES)
	{
		bail!("observation_pool_payload_unsupported: original observation fields exceed64KiB; no fallback");
	}
	let (script, input, timeout, system) = match value {
		JobObservation::PythonStatus {
			job_id,
			job_dir,
			unit,
			request_digest,
			wait_seconds,
		} => (
			Some(ObservationScript::Status),
			JobObservationPayload::PythonStatus {
				job_dir,
				job_id,
				request_digest,
				unit,
				wait_seconds: wait_seconds.min(30),
			},
			Duration::from_secs(wait_seconds.min(30) + 10),
			false,
		),
		JobObservation::PythonRead {
			job_id,
			job_dir,
			unit,
			request_digest,
			stdout_offset,
			stderr_offset,
			limit,
		} => (
			Some(ObservationScript::Read),
			JobObservationPayload::PythonRead {
				job_dir,
				job_id,
				limit,
				request_digest,
				stderr_offset,
				stdout_offset,
				unit,
			},
			Duration::from_secs(15),
			false,
		),
		JobObservation::SystemStatus { job_id } => (
			None,
			JobObservationPayload::SystemStatus {
				job_id,
				op: "status",
			},
			Duration::from_secs(20),
			true,
		),
		JobObservation::SystemRead {
			job_id,
			stdout_offset,
			stderr_offset,
			limit,
		} => (
			None,
			JobObservationPayload::SystemRead {
				job_id,
				limit,
				op: "read",
				stderr_offset,
				stdout_offset,
			},
			Duration::from_secs(20),
			true,
		),
	};
	let command = match script {
		Some(script) => job_observation_command(script)?.to_owned(),
		None => "sudo -n /usr/local/libexec/hepta-runtime-jobctl".to_owned(),
	};
	let mut bytes = serde_json::to_vec(&input)?;
	if system {
		bytes.push(b'\n');
	}
	validate_observation_bytes(&command, &bytes)?;
	Ok((command, bytes, timeout, system))
}

// Both modules use the same fixed stub and the same fixture adapter.
fn job_observation_command(_script: ObservationScript) -> Result<&'static str> {
    Ok(super::PYTHON_COMMAND_STUB)
}

pub(super) const LIMIT: usize = MAX_OBSERVATION_BYTES;

#[inline(never)]
pub(super) fn prepare(case: &super::Case) -> Result<super::Prepared> {
    let value = match case.kind {
        super::Kind::PythonStatus => JobObservation::PythonStatus {
            job_id: &case.job_id,
            job_dir: &case.job_dir,
            unit: &case.unit,
            request_digest: &case.request_digest,
            wait_seconds: case.wait_seconds,
        },
        super::Kind::PythonRead => JobObservation::PythonRead {
            job_id: &case.job_id,
            job_dir: &case.job_dir,
            unit: &case.unit,
            request_digest: &case.request_digest,
            stdout_offset: case.stdout_offset,
            stderr_offset: case.stderr_offset,
            limit: case.limit,
        },
        super::Kind::SystemStatus => JobObservation::SystemStatus { job_id: &case.job_id },
        super::Kind::SystemRead => JobObservation::SystemRead {
            job_id: &case.job_id,
            stdout_offset: case.stdout_offset,
            stderr_offset: case.stderr_offset,
            limit: case.limit,
        },
    };
    prepare_observation(value)
}
}
// END_EXTRACTED_SOURCE

#[derive(Clone, Copy)]
enum Kind {
	PythonStatus,
	PythonRead,
	SystemStatus,
	SystemRead,
}

struct Case {
	name: &'static str,
	kind: Kind,
	job_id: String,
	job_dir: String,
	unit: String,
	request_digest: String,
	wait_seconds: u64,
	stdout_offset: u64,
	stderr_offset: u64,
	limit: u64,
	near_limit: bool,
}

impl Case {
	fn ordinary(name: &'static str, kind: Kind) -> Self {
		Self {
			name,
			kind,
			job_id: "original-123".to_owned(),
			job_dir: "/var/lib/hepta-runtime/jobs/original-123".to_owned(),
			unit: "hepta-runtime-job-original-123".to_owned(),
			request_digest: "a".repeat(64),
			wait_seconds: 31,
			stdout_offset: 17,
			stderr_offset: 29,
			limit: 16_384,
			near_limit: false,
		}
	}

	fn raw_field_bytes(&self) -> usize {
		match self.kind {
			Kind::PythonStatus | Kind::PythonRead => {
				self.job_id.len() + self.job_dir.len() + self.unit.len() + self.request_digest.len()
			}
			Kind::SystemStatus | Kind::SystemRead => self.job_id.len(),
		}
	}

	fn timing_iterations(&self) -> u64 {
		if self.near_limit { LARGE_ITERATIONS } else { SMALL_ITERATIONS }
	}
}

fn fixtures() -> Vec<Case> {
	let mut escaped = Case::ordinary("python_read_escaped_unicode", Kind::PythonRead);
	let special = "中文λ🦀e\u{301}\u{2028}\u{2029}\"\\\0\n\r\t\u{8}\u{c}";
	escaped.job_id = special.to_owned();
	escaped.job_dir = special.to_owned();
	escaped.unit = special.to_owned();
	escaped.request_digest = special.to_owned();
	escaped.stdout_offset = u64::MAX;
	escaped.stderr_offset = u64::MAX - 1;
	escaped.limit = u64::MAX;
	let mut near = Case::ordinary("python_read_64k_boundary", Kind::PythonRead);
	near.job_dir.clear();
	near.near_limit = true;
	let (command, bytes, _, _) = baseline::prepare(&near).unwrap();
	near.job_dir = "x".repeat(baseline::LIMIT - command.len() - bytes.len());
	vec![
		Case::ordinary("python_status", Kind::PythonStatus),
		Case::ordinary("python_read", Kind::PythonRead),
		Case::ordinary("system_status", Kind::SystemStatus),
		Case::ordinary("system_read", Kind::SystemRead),
		escaped,
		near,
	]
}

fn verify(cases: &[Case]) {
	let mut map = serde_json::Map::new();
	for (key, value) in [("z", 1), ("a", 2), ("m", 3)] {
		map.insert(key.to_owned(), json!(value));
	}
	assert_eq!(serde_json::to_vec(&map).unwrap(), br#"{"a":2,"m":3,"z":1}"#);
	assert_eq!(baseline::LIMIT, candidate::LIMIT);
	for case in cases {
		let a = baseline::prepare(case).unwrap();
		let b = candidate::prepare(case).unwrap();
		assert_eq!(a, b, "byte/command/timeout/system mismatch: {}", case.name);
		if case.near_limit {
			assert_eq!(a.0.len() + a.1.len(), baseline::LIMIT);
		}
		println!("{}", json!({
			"kind": "case", "case": case.name,
			"raw_field_bytes": case.raw_field_bytes(), "command_bytes": a.0.len(),
			"stdin_bytes": a.1.len(), "combined_bytes": a.0.len() + a.1.len(),
			"timeout_seconds": a.2.as_secs(), "system": a.3,
			"timing_iterations": case.timing_iterations(), "byte_equivalent": true,
		}));
	}
}

fn exercise(prepare: Prepare, case: &Case, iterations: u64) {
	for _ in 0..iterations {
		// Destruction belongs in the measured loop, as it does for every request.
		drop(black_box(prepare(black_box(case)).unwrap()));
	}
}

fn warm_up(cases: &[Case]) {
	for case in cases {
		let iterations = if case.near_limit { 32 } else { 1_000 };
		exercise(baseline::prepare, case, iterations);
		exercise(candidate::prepare, case, iterations);
	}
}

#[cfg(not(count_allocations))]
fn process_cpu_ns() -> u64 {
	let mut value = std::mem::MaybeUninit::<libc::timespec>::uninit();
	let result = unsafe { libc::clock_gettime(libc::CLOCK_PROCESS_CPUTIME_ID, value.as_mut_ptr()) };
	assert_eq!(result, 0, "clock_gettime: {}", std::io::Error::last_os_error());
	let value = unsafe { value.assume_init() };
	let seconds = u64::try_from(value.tv_sec).unwrap();
	let nanos = u64::try_from(value.tv_nsec).unwrap();
	seconds.checked_mul(1_000_000_000).unwrap().checked_add(nanos).unwrap()
}

#[cfg(not(count_allocations))]
struct Sample {
	case: &'static str,
	round: usize,
	slot: usize,
	version: &'static str,
	iterations: u64,
	cpu_ns: u64,
	wall_ns: u64,
}

#[cfg(not(count_allocations))]
fn measure(cases: &[Case]) {
	let order: [(&str, Prepare); 4] = [
		("baseline", baseline::prepare),
		("candidate", candidate::prepare),
		("candidate", candidate::prepare),
		("baseline", baseline::prepare),
	];
	let mut samples = Vec::with_capacity(cases.len() * ROUNDS * order.len());
	for case in cases {
		for round in 0..ROUNDS {
			for (slot, &(version, prepare)) in order.iter().enumerate() {
				let iterations = case.timing_iterations();
				let wall_start = Instant::now();
				let cpu_start = process_cpu_ns();
				exercise(prepare, case, iterations);
				let cpu_ns = process_cpu_ns().checked_sub(cpu_start).unwrap();
				let wall_ns = u64::try_from(wall_start.elapsed().as_nanos()).unwrap();
				assert!(cpu_ns > 0 && wall_ns > 0);
				samples.push(Sample { case: case.name, round, slot, version, iterations, cpu_ns, wall_ns });
			}
		}
	}
	// Retain every sample; no output allocation or I/O occurs between batches.
	for sample in &samples {
		println!("{}", json!({
			"kind": "timing", "case": sample.case, "round": sample.round,
			"slot": sample.slot, "version": sample.version, "iterations": sample.iterations,
			"cpu_ns": sample.cpu_ns, "wall_ns": sample.wall_ns,
			"cpu_ns_per_call": sample.cpu_ns as f64 / sample.iterations as f64,
			"wall_ns_per_call": sample.wall_ns as f64 / sample.iterations as f64,
		}));
	}
	for case in cases {
		let sum = |version| -> (u64, u64, u64) {
			samples.iter().filter(|s| s.case == case.name && s.version == version)
				.fold((0, 0, 0), |(calls, cpu, wall), s| {
					(calls + s.iterations, cpu + s.cpu_ns, wall + s.wall_ns)
				})
		};
		let (a_calls, a_cpu, a_wall) = sum("baseline");
		let (b_calls, b_cpu, b_wall) = sum("candidate");
		assert_eq!(a_calls, b_calls);
		println!("{}", json!({
			"kind": "summary", "case": case.name, "calls_per_version": a_calls,
			"baseline_cpu_ns_per_call": a_cpu as f64 / a_calls as f64,
			"candidate_cpu_ns_per_call": b_cpu as f64 / b_calls as f64,
			"baseline_wall_ns_per_call": a_wall as f64 / a_calls as f64,
			"candidate_wall_ns_per_call": b_wall as f64 / b_calls as f64,
			"candidate_cpu_over_baseline": b_cpu as f64 / a_cpu as f64,
			"candidate_wall_over_baseline": b_wall as f64 / a_wall as f64,
		}));
	}
}

#[cfg(count_allocations)]
mod allocation_probe {
	use std::alloc::{GlobalAlloc, Layout, System};
	use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
	pub struct CountingSystem;
	#[global_allocator]
	static ALLOCATOR: CountingSystem = CountingSystem;
	static ENABLED: AtomicBool = AtomicBool::new(false);
	static ALLOC: AtomicU64 = AtomicU64::new(0);
	static ZEROED: AtomicU64 = AtomicU64::new(0);
	static REALLOC: AtomicU64 = AtomicU64::new(0);
	static DEALLOC: AtomicU64 = AtomicU64::new(0);
	static REQUESTED_BYTES: AtomicU64 = AtomicU64::new(0);

	unsafe impl GlobalAlloc for CountingSystem {
		unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
			if ENABLED.load(Ordering::Relaxed) {
				ALLOC.fetch_add(1, Ordering::Relaxed);
				REQUESTED_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
			}
			unsafe { System.alloc(layout) }
		}
		unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
			if ENABLED.load(Ordering::Relaxed) {
				ZEROED.fetch_add(1, Ordering::Relaxed);
				REQUESTED_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
			}
			unsafe { System.alloc_zeroed(layout) }
		}
		unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
			if ENABLED.load(Ordering::Relaxed) {
				REALLOC.fetch_add(1, Ordering::Relaxed);
				REQUESTED_BYTES.fetch_add(size as u64, Ordering::Relaxed);
			}
			unsafe { System.realloc(pointer, layout, size) }
		}
		unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
			if ENABLED.load(Ordering::Relaxed) {
				DEALLOC.fetch_add(1, Ordering::Relaxed);
			}
			unsafe { System.dealloc(pointer, layout) }
		}
	}

	pub(super) fn begin() {
		assert!(!ENABLED.load(Ordering::SeqCst));
		for counter in [&ALLOC, &ZEROED, &REALLOC, &DEALLOC, &REQUESTED_BYTES] {
			counter.store(0, Ordering::Relaxed);
		}
		ENABLED.store(true, Ordering::SeqCst);
	}

	pub(super) fn end() -> [u64; 5] {
		ENABLED.store(false, Ordering::SeqCst);
		[&ALLOC, &ZEROED, &REALLOC, &DEALLOC, &REQUESTED_BYTES]
			.map(|counter| counter.load(Ordering::Relaxed))
	}
}

#[cfg(count_allocations)]
fn measure(cases: &[Case]) {
	let order: [(&str, Prepare); 2] = [
		("baseline", baseline::prepare),
		("candidate", candidate::prepare),
	];
	let mut samples = Vec::with_capacity(cases.len() * order.len());
	for case in cases {
		for &(version, prepare) in &order {
			allocation_probe::begin();
			exercise(prepare, case, ALLOCATION_ITERATIONS);
			let counts = allocation_probe::end();
			samples.push((case.name, version, counts));
		}
	}
	for (case, version, [alloc, zeroed, realloc, dealloc, requested_bytes]) in samples {
		println!("{}", json!({
			"kind": "allocation", "case": case, "version": version,
			"iterations": ALLOCATION_ITERATIONS,
			"alloc_calls": alloc, "alloc_zeroed_calls": zeroed,
			"realloc_calls": realloc, "dealloc_calls": dealloc,
			"requested_bytes": requested_bytes,
			"alloc_calls_per_call": alloc as f64 / ALLOCATION_ITERATIONS as f64,
			"realloc_calls_per_call": realloc as f64 / ALLOCATION_ITERATIONS as f64,
			"requested_bytes_per_call": requested_bytes as f64 / ALLOCATION_ITERATIONS as f64,
		}));
	}
}

fn main() {
	assert!(std::env::args_os().nth(1).is_none(), "this fixed benchmark takes no arguments");
	println!("{SOURCE_METADATA}");
	println!("{}", json!({
		"kind": "configuration", "mode": if cfg!(count_allocations) { "allocation" } else { "timing" },
		"allocator": "System", "allocation_probe": cfg!(count_allocations),
		"rounds": ROUNDS, "order": "ABBA", "small_iterations": SMALL_ITERATIONS,
		"near_limit_iterations": LARGE_ITERATIONS, "allocation_iterations": ALLOCATION_ITERATIONS,
		"python_command_stub": PYTHON_COMMAND_STUB,
		"cpu_clock": "CLOCK_PROCESS_CPUTIME_ID", "wall_clock": "Instant",
		"timed_scope": "prepare_observation plus identical fixture adapter and output drop",
	}));
	let cases = fixtures();
	verify(&cases);
	warm_up(&cases);
	measure(&cases);
}
