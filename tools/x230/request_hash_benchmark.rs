// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
// Standalone, synthetic request-binding CPU benchmark. Does not launch a job,
// open runtime state, touch SSH, or change A19 source. Link existing release
// rlibs using the same Rust 1.95.0 toolchain and -C panic=abort.
// Usage: request_hash_benchmark [cycles=6] [small=100000] [plain=64] [escaped=8]
// Every cycle measures each case in A/B/B/A order, where A is the exact A19
// writer below and B changes only its SHA256 backend to ring. Case order is
// reversed on alternate cycles. No timed cell includes setup or JSON output.

use anyhow::{bail, Context, Result};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::hint::black_box;
use std::io::Write;
use std::time::Instant;

const MIB: usize = 1024 * 1024;
const SCHEMA: &str = "hepta-request-hash-writer-abba/v1";

// Same owned fields and field types as jobs::ProcessStartParams. Derives and
// validation are outside the measured request_digest function in production.
#[derive(Clone)]
struct ProcessStartParams {
    host: String,
    executable: String,
    args: Vec<String>,
    cwd: Option<String>,
    env: BTreeMap<String, String>,
    stdin: Option<String>,
    timeout_seconds: Option<u64>,
    idempotency_key: Option<String>,
    nice: Option<u8>,
    cpu_quota_percent: Option<u16>,
    memory_max_bytes: Option<u64>,
}

// The following A19 binding and current writer are copied verbatim from
// src/mcp/runtime/jobs.rs, including ordering, serialization and hex encoding.
// Keep the alphabetical key order of the original serde_json::Value map.
// Borrow potentially large input while retaining exactly its original JSON bytes.
#[derive(Serialize)]
struct RequestBinding<'a> {
	args: &'a [String],
	cpu_quota_percent: Option<u16>,
	cwd: Option<&'a str>,
	env: &'a BTreeMap<String, String>,
	executable: &'a str,
	host: &'a str,
	memory_max_bytes: Option<u64>,
	nice: Option<u8>,
	stdin: Option<&'a str>,
	timeout_seconds: Option<u64>,
}
fn request_binding(params: &ProcessStartParams) -> RequestBinding<'_> {
	RequestBinding {
		args: &params.args,
		cpu_quota_percent: params.cpu_quota_percent,
		cwd: params.cwd.as_deref(),
		env: &params.env,
		executable: &params.executable,
		host: &params.host,
		memory_max_bytes: params.memory_max_bytes,
		nice: params.nice,
		stdin: params.stdin.as_deref(),
		timeout_seconds: params.timeout_seconds,
	}
}
struct RequestHashWriter(Sha256);
impl Write for RequestHashWriter {
	fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
		self.0.update(bytes);
		Ok(bytes.len())
	}
	fn flush(&mut self) -> std::io::Result<()> {
		Ok(())
	}
}
fn request_digest(params: &ProcessStartParams) -> Result<String> {
	let mut writer = RequestHashWriter(Sha256::new());
	serde_json::to_writer(&mut writer, &request_binding(params))?;
	let digest = writer.0.finalize();
	let mut hex = String::with_capacity(64);
	const HEX: &[u8; 16] = b"0123456789abcdef";
	for byte in digest {
		hex.push(HEX[(byte >> 4) as usize] as char);
		hex.push(HEX[(byte & 15) as usize] as char);
	}
	Ok(hex)
}

// Candidate: same writes, serialization call and hex representation. No extra
// buffering, input cloning, one-shot hash, or pre-serialized input is timed.
struct RingRequestHashWriter(ring::digest::Context);
impl Write for RingRequestHashWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn ring_request_digest(params: &ProcessStartParams) -> Result<String> {
    let mut writer = RingRequestHashWriter(ring::digest::Context::new(&ring::digest::SHA256));
    serde_json::to_writer(&mut writer, &request_binding(params))?;
    let digest = writer.0.finish();
    let mut hex = String::with_capacity(64);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for &byte in digest.as_ref() {
        hex.push(HEX[(byte >> 4) as usize] as char);
        hex.push(HEX[(byte & 15) as usize] as char);
    }
    Ok(hex)
}

// Independent legacy Value/Vec representation, used only outside measurement.
fn legacy_bytes(params: &ProcessStartParams) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(&json!({
        "host": params.host,
        "executable": params.executable,
        "args": params.args,
        "cwd": params.cwd,
        "env": params.env,
        "stdin": params.stdin,
        "timeout_seconds": params.timeout_seconds,
        "nice": params.nice,
        "cpu_quota_percent": params.cpu_quota_percent,
        "memory_max_bytes": params.memory_max_bytes,
    }))?)
}

#[derive(Default, Serialize)]
struct WriteShape {
    calls: usize,
    bytes: usize,
    nonempty_writes_at_most_16_bytes: usize,
    largest_write_bytes: usize,
}
impl Write for WriteShape {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.calls += 1;
        self.bytes += bytes.len();
        self.nonempty_writes_at_most_16_bytes += usize::from(!bytes.is_empty() && bytes.len() <= 16);
        self.largest_write_bytes = self.largest_write_bytes.max(bytes.len());
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct Case {
    name: &'static str,
    params: ProcessStartParams,
    iterations: usize,
    serialized_bytes: usize,
    expected: String,
}

fn verify_case(case: &mut Case) -> Result<()> {
    let legacy = legacy_bytes(&case.params)?;
    let borrowed = serde_json::to_vec(&request_binding(&case.params))?;
    assert_eq!(borrowed, legacy, "{}: original JSON bytes changed", case.name);
    let independent: [u8; 32] = Sha256::digest(&legacy).into();
    let expected: String = independent.iter().map(|byte| format!("{byte:02x}")).collect();
    assert_eq!(independent.as_slice(), ring::digest::digest(&ring::digest::SHA256, &legacy).as_ref());
    assert_eq!(request_digest(&case.params)?, expected, "{}: current full digest", case.name);
    assert_eq!(ring_request_digest(&case.params)?, expected, "{}: candidate full digest", case.name);
    assert_eq!(expected.len(), 64);
    if case.name == "small" {
        // The same frozen fixture already exists in jobs_tests.rs.
        assert_eq!(expected, "ca832d57a27411bc9e0a382fed917e42212140108bb0e7c94953dd8d30bc1411");
    }
    let mut other_key = case.params.clone();
    other_key.idempotency_key = Some("different-excluded-key".into());
    assert_eq!(request_digest(&other_key)?, expected);
    assert_eq!(ring_request_digest(&other_key)?, expected);
    let mut shape = WriteShape::default();
    serde_json::to_writer(&mut shape, &request_binding(&case.params))?;
    assert_eq!(shape.bytes, legacy.len());
    case.serialized_bytes = legacy.len();
    case.expected = expected;
    emit(json!({
        "schema": SCHEMA, "record": "preflight", "case": case.name,
        "stdin_bytes": case.params.stdin.as_ref().map_or(0, |value| value.len()),
        "serialized_bytes": case.serialized_bytes, "serialization_writes": shape,
        "original_json_bytes_equal": true, "full_sha256_equal": true,
        "idempotency_key_remains_excluded": true, "digest_bits": 256,
    }))?;
    Ok(())
}

fn process_cpu_ns() -> Result<u64> {
    let mut value = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    if unsafe { libc::clock_gettime(libc::CLOCK_PROCESS_CPUTIME_ID, &mut value) } != 0 {
        return Err(std::io::Error::last_os_error()).context("process CPU clock unavailable");
    }
    let seconds = u64::try_from(value.tv_sec).context("negative process CPU seconds")?;
    let nanos = u64::try_from(value.tv_nsec).context("negative process CPU nanoseconds")?;
    seconds.checked_mul(1_000_000_000).and_then(|v| v.checked_add(nanos))
        .context("process CPU clock overflow")
}

#[derive(Clone, Copy)]
struct Measurement { wall_seconds: f64, cpu_seconds: f64 }

fn measure(case: &Case, calculate: fn(&ProcessStartParams) -> Result<String>) -> Result<Measurement> {
    let cpu_start = process_cpu_ns()?;
    let started = Instant::now();
    for _ in 0..case.iterations {
        black_box(calculate(black_box(&case.params))?);
    }
    let wall_seconds = started.elapsed().as_secs_f64();
    let cpu_seconds = process_cpu_ns()?.checked_sub(cpu_start)
        .context("process CPU clock went backwards")? as f64 / 1_000_000_000.0;
    Ok(Measurement { wall_seconds, cpu_seconds })
}

#[derive(Default)]
struct Summary {
    baseline_wall_us: Vec<f64>,
    candidate_wall_us: Vec<f64>,
    baseline_cpu_us: Vec<f64>,
    candidate_cpu_us: Vec<f64>,
    wall_speedups: Vec<f64>,
    cpu_speedups: Vec<f64>,
}

fn distribution(values: &[f64]) -> Value {
    let mut ordered = values.to_vec();
    ordered.sort_by(f64::total_cmp);
    let count = ordered.len();
    let median = if count % 2 == 0 {
        (ordered[count / 2 - 1] + ordered[count / 2]) / 2.0
    } else { ordered[count / 2] };
    json!({"min": ordered[0], "median": median, "max": ordered[count - 1]})
}

fn emit(value: Value) -> Result<()> {
    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    serde_json::to_writer(&mut output, &value)?;
    output.write_all(b"\n")?;
    output.flush()?;
    Ok(())
}

fn parameter(arguments: &[String], index: usize, default: usize) -> Result<usize> {
    let value = match arguments.get(index) {
        Some(argument) => argument.parse::<usize>().context("arguments must be positive integers")?,
        None => default,
    };
    if value == 0 { bail!("arguments must be positive integers"); }
    Ok(value)
}

fn main() -> Result<()> {
    let arguments: Vec<String> = std::env::args().collect();
    if arguments.len() > 5 {
        bail!("usage: request_hash_benchmark [cycles=6] [small=100000] [plain=64] [escaped=8]");
    }
    let cycles = parameter(&arguments, 1, 6)?;
    let iterations = [parameter(&arguments, 2, 100_000)?, parameter(&arguments, 3, 64)?, parameter(&arguments, 4, 8)?];
    let small = ProcessStartParams {
        host: "rog".into(), executable: "/usr/bin/printf".into(), args: vec!["ok".into()],
        cwd: Some("/tmp".into()), env: BTreeMap::new(), stdin: None,
        timeout_seconds: Some(10), idempotency_key: Some("key".into()),
        nice: Some(1), cpu_quota_percent: Some(20), memory_max_bytes: Some(134_217_728),
    };
    let mut plain = small.clone();
    plain.stdin = Some("x".repeat(MIB));
    let mut escaped = small.clone();
    escaped.stdin = Some("\"\\\0\n".repeat(MIB / 4));
    let mut cases = [
        Case { name: "small", params: small, iterations: iterations[0], serialized_bytes: 0, expected: String::new() },
        Case { name: "one_mib_plain", params: plain, iterations: iterations[1], serialized_bytes: 0, expected: String::new() },
        Case { name: "one_mib_heavily_escaped", params: escaped, iterations: iterations[2], serialized_bytes: 0, expected: String::new() },
    ];
    emit(json!({
        "schema": SCHEMA, "record": "method", "cycles": cycles,
        "case_iterations_per_cell": iterations, "order": ["sha2", "ring", "ring", "sha2"],
        "wall_clock": "std::time::Instant", "cpu_clock": "CLOCK_PROCESS_CPUTIME_ID",
        "cpu_scope": "single benchmark process; clock/Instant boundary overhead included",
        "timed_scope": "borrowed JSON serialization + streamed SHA256 + same 64-char hex allocation/drop",
        "excluded": ["parameter construction", "equality checks", "reporting", "filesystem", "audit", "SSH", "job launch"],
        "case_order": "forward on even cycles, reverse on odd cycles",
        "warmup_calls_per_backend": [128, 4, 2],
        "target_os": std::env::consts::OS, "target_arch": std::env::consts::ARCH,
        "baseline": "A19 RequestHashWriter(sha2::Sha256)",
        "candidate": "same writer API and serde_json::to_writer with ring::digest::Context",
        "process_start_tps_measured": false, "overall_runtime_speedup_measured": false,
    }))?;
    // Check all complete digests before any timing begins.
    for case in &mut cases { verify_case(case)?; }
    let warmups = [128, 4, 2];
    for (case, count) in cases.iter().zip(warmups) {
        for _ in 0..count {
            black_box(request_digest(black_box(&case.params))?);
            black_box(ring_request_digest(black_box(&case.params))?);
        }
    }
    let mut summaries: [Summary; 3] = std::array::from_fn(|_| Summary::default());
    for cycle in 0..cycles {
        let order = if cycle % 2 == 0 { [0, 1, 2] } else { [2, 1, 0] };
        for index in order {
            let case = &cases[index];
            let backends: [(char, &str, fn(&ProcessStartParams) -> Result<String>); 4] = [
                ('A', "sha2", request_digest), ('B', "ring", ring_request_digest),
                ('B', "ring", ring_request_digest), ('A', "sha2", request_digest),
            ];
            let mut samples = Vec::with_capacity(4);
            for (_, _, calculate) in backends { samples.push(measure(case, calculate)?); }
            // Report only after all four cells; emitting cannot interrupt ABBA.
            for (position, ((label, backend, _), sample)) in backends.iter().zip(&samples).enumerate() {
                emit(json!({
                    "schema": SCHEMA, "record": "sample", "cycle": cycle + 1,
                    "case": case.name, "position": position + 1, "label": label.to_string(),
                    "backend": backend, "iterations": case.iterations,
                    "stdin_bytes": case.params.stdin.as_ref().map_or(0, |v| v.len()),
                    "serialized_bytes": case.serialized_bytes,
                    "wall_seconds": sample.wall_seconds, "cpu_seconds": sample.cpu_seconds,
                    "wall_us_per_call": sample.wall_seconds * 1_000_000.0 / case.iterations as f64,
                    "cpu_us_per_call": sample.cpu_seconds * 1_000_000.0 / case.iterations as f64,
                }))?;
            }
            let divisor = 2.0 * case.iterations as f64;
            let baseline_wall = (samples[0].wall_seconds + samples[3].wall_seconds) * 1_000_000.0 / divisor;
            let candidate_wall = (samples[1].wall_seconds + samples[2].wall_seconds) * 1_000_000.0 / divisor;
            let baseline_cpu = (samples[0].cpu_seconds + samples[3].cpu_seconds) * 1_000_000.0 / divisor;
            let candidate_cpu = (samples[1].cpu_seconds + samples[2].cpu_seconds) * 1_000_000.0 / divisor;
            let wall_speedup = baseline_wall / candidate_wall;
            let cpu_speedup = baseline_cpu / candidate_cpu;
            let summary = &mut summaries[index];
            summary.baseline_wall_us.push(baseline_wall);
            summary.candidate_wall_us.push(candidate_wall);
            summary.baseline_cpu_us.push(baseline_cpu);
            summary.candidate_cpu_us.push(candidate_cpu);
            summary.wall_speedups.push(wall_speedup);
            summary.cpu_speedups.push(cpu_speedup);
            emit(json!({
                "schema": SCHEMA, "record": "paired_cycle", "cycle": cycle + 1, "case": case.name,
                "sha2_wall_us_per_call": baseline_wall, "ring_wall_us_per_call": candidate_wall,
                "sha2_cpu_us_per_call": baseline_cpu, "ring_cpu_us_per_call": candidate_cpu,
                "wall_speedup_sha2_over_ring": wall_speedup,
                "cpu_speedup_sha2_over_ring": cpu_speedup,
                "wall_time_reduction_percent": 100.0 * (1.0 - candidate_wall / baseline_wall),
                "cpu_time_reduction_percent": 100.0 * (1.0 - candidate_cpu / baseline_cpu),
            }))?;
        }
    }
    for (case, summary) in cases.iter().zip(summaries) {
        // Detect any late result mismatch without charging correctness checks
        // to one backend's timed cells.
        assert_eq!(request_digest(&case.params)?, case.expected);
        assert_eq!(ring_request_digest(&case.params)?, case.expected);
        emit(json!({
            "schema": SCHEMA, "record": "summary", "case": case.name, "cycles": cycles,
            "all_full_digest_checks_passed": true,
            "sha2_wall_us_per_call": distribution(&summary.baseline_wall_us),
            "ring_wall_us_per_call": distribution(&summary.candidate_wall_us),
            "sha2_cpu_us_per_call": distribution(&summary.baseline_cpu_us),
            "ring_cpu_us_per_call": distribution(&summary.candidate_cpu_us),
            "paired_wall_speedup_sha2_over_ring": distribution(&summary.wall_speedups),
            "paired_cpu_speedup_sha2_over_ring": distribution(&summary.cpu_speedups),
            "speedup_interpretation": "greater than 1 favors ring; less than 1 favors sha2",
            "process_start_tps_measured": false, "overall_runtime_speedup_measured": false,
        }))?;
    }
    Ok(())
}
