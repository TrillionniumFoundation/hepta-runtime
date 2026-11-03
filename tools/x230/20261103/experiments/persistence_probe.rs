// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Isolated synthetic receipt writer probe; never operates a runtime state directory.
use serde_json::{json, Value};
use std::alloc::{GlobalAlloc, Layout, System};
use std::error::Error;
use std::fs::{self, File, OpenOptions};
use std::hint::black_box;
use std::io::{self, BufWriter, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const LIMIT: u64 = 4 * 1024 * 1024;
const BUFFER: usize = 16 * 1024;
static TRACK: AtomicBool = AtomicBool::new(false);
static LIVE: AtomicU64 = AtomicU64::new(0);
static PEAK: AtomicU64 = AtomicU64::new(0);
static TOTAL: AtomicU64 = AtomicU64::new(0);
static ALLOCATIONS: AtomicU64 = AtomicU64::new(0);

struct MeasuredAllocator;
#[global_allocator]
static ALLOCATOR: MeasuredAllocator = MeasuredAllocator;

unsafe impl GlobalAlloc for MeasuredAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = System.alloc(layout);
        if !pointer.is_null() && TRACK.load(Ordering::Relaxed) {
            let size = layout.size() as u64;
            TOTAL.fetch_add(size, Ordering::Relaxed);
            ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
            let now = LIVE.fetch_add(size, Ordering::Relaxed) + size;
            PEAK.fetch_max(now, Ordering::Relaxed);
        }
        pointer
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        if TRACK.load(Ordering::Relaxed) {
            LIVE.fetch_sub(layout.size() as u64, Ordering::Relaxed);
        }
        System.dealloc(pointer, layout);
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let result = System.realloc(pointer, layout, new_size);
        if !result.is_null() && TRACK.load(Ordering::Relaxed) {
            TOTAL.fetch_add(new_size as u64, Ordering::Relaxed);
            ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
            let before = LIVE.fetch_sub(layout.size() as u64, Ordering::Relaxed);
            let now = before - layout.size() as u64 + new_size as u64;
            LIVE.fetch_add(new_size as u64, Ordering::Relaxed);
            PEAK.fetch_max(now, Ordering::Relaxed);
        }
        result
    }
}

#[repr(C)]
struct Timespec {
    seconds: i64,
    nanoseconds: i64,
}
extern "C" {
    fn clock_gettime(clock: i32, value: *mut Timespec) -> i32;
}
fn cpu_seconds() -> f64 {
    let mut value = Timespec { seconds: 0, nanoseconds: 0 };
    assert_eq!(unsafe { clock_gettime(2, &mut value) }, 0);
    value.seconds as f64 + value.nanoseconds as f64 / 1_000_000_000.0
}

#[derive(Clone, Copy)]
enum Mode { Vec, Stream }
impl Mode {
    fn label(self) -> &'static str {
        match self { Self::Vec => "vec", Self::Stream => "count_stream_16k" }
    }
}

struct ByteCount(u64);
impl Write for ByteCount {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 = self.0.saturating_add(bytes.len() as u64);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}
fn encoded_len(value: &Value) -> Result<u64> {
    let mut counter = ByteCount(0);
    serde_json::to_writer_pretty(&mut counter, value)?;
    Ok(counter.0)
}
fn require_bound(bytes: u64) -> Result<()> {
    if bytes > LIMIT {
        return Err(io::Error::new(io::ErrorKind::InvalidInput,
            "durable job record exceeds 4194304 bytes").into());
    }
    Ok(())
}
fn buffered<W: Write>(destination: W, value: &Value, capacity: usize) -> Result<()> {
    let mut writer = BufWriter::with_capacity(capacity, destination);
    let result: Result<()> = match serde_json::to_writer_pretty(&mut writer, value) {
        Ok(()) => writer.flush().map_err(|error| error.into()),
        Err(error) if error.is_io() => Err(io::Error::from(error).into()),
        Err(error) => Err(error.into()),
    };
    let (_destination, _unwritten) = writer.into_parts();
    result
}

struct ProbeSink(u64);
impl Write for ProbeSink {
    #[inline(never)]
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let bytes = black_box(bytes);
        self.0 += bytes.len() as u64;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}
fn serialize(mode: Mode, value: &Value) -> Result<u64> {
    let mut sink = ProbeSink(0);
    match mode {
        Mode::Vec => {
            let bytes = serde_json::to_vec_pretty(value)?;
            require_bound(bytes.len() as u64)?;
            sink.write_all(black_box(&bytes))?;
        }
        Mode::Stream => {
            let length = encoded_len(value)?;
            require_bound(length)?;
            buffered(&mut sink, value, length.min(BUFFER as u64) as usize)?;
        }
    }
    Ok(black_box(sink.0))
}

fn fixture(size: usize, escaped: bool) -> Result<Value> {
    let mut value = json!({
        "execution_mode":"operator", "system_jobctl":false,
        "id":"isolated-writer-probe", "host":"fixture-never-connect",
        "ssh_target":"never-connect.invalid", "unit":"fixture-unit",
        "remote_job_dir":"/never-launch/isolated-writer-probe",
        "executable":"/usr/bin/true", "args":[""], "cwd":null,
        "env_keys":["EXAMPLE"], "created_unix_ms":1793700000000u64,
        "idempotency_key":"fixture-only", "request_fingerprint":7,
        "request_digest":"a".repeat(64), "launch_state":"pending",
        "launch_error":"UTF8 中文 and punctuation"
    });
    let overhead = encoded_len(&value)? as usize;
    assert!(size >= overhead);
    let spare = size - overhead;
    let payload = if escaped {
        let mut payload = "\n\\\"\t".repeat(spare / 8);
        payload.push_str(&"x".repeat(spare % 8));
        payload
    } else { "x".repeat(spare) };
    value["args"][0] = Value::String(payload);
    assert_eq!(encoded_len(&value)? as usize, size);
    Ok(value)
}

fn allocation_sample(mode: Mode, value: &Value) -> Result<Value> {
    LIVE.store(0, Ordering::Relaxed);
    PEAK.store(0, Ordering::Relaxed);
    TOTAL.store(0, Ordering::Relaxed);
    ALLOCATIONS.store(0, Ordering::Relaxed);
    TRACK.store(true, Ordering::SeqCst);
    let result = serialize(mode, value);
    TRACK.store(false, Ordering::SeqCst);
    let bytes = result?;
    assert_eq!(LIVE.load(Ordering::Relaxed), 0);
    Ok(json!({"bytes":bytes, "peak_live_requested_bytes":PEAK.load(Ordering::Relaxed),
        "requested_bytes_total":TOTAL.load(Ordering::Relaxed),
        "allocation_or_reallocation_calls":ALLOCATIONS.load(Ordering::Relaxed)}))
}

fn save(root: &Path, mode: Mode, value: &Value) -> Result<()> {
    let path = root.join("record.json");
    let temporary = root.join(format!("record.json.tmp.{}", std::process::id()));
    let bytes = match mode {
        Mode::Vec => Some(serde_json::to_vec_pretty(value)?),
        Mode::Stream => None,
    };
    let length = match &bytes { Some(bytes) => bytes.len() as u64, None => encoded_len(value)? };
    require_bound(length)?;
    let mut file = OpenOptions::new().create_new(true).write(true).mode(0o600).open(&temporary)?;
    match bytes {
        Some(bytes) => file.write_all(&bytes)?,
        None => buffered(&mut file, value, length.min(BUFFER as u64) as usize)?,
    }
    file.sync_all()?;
    drop(file);
    fs::rename(temporary, path)?;
    File::open(root)?.sync_all()?;
    Ok(())
}

#[derive(Clone, Copy)]
enum Fault { Write, Partial, Zero, Flush }
struct FaultSink { fault: Fault, calls: usize, failed: bool, after_failure: usize }
impl Write for FaultSink {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.failed {
            self.after_failure += 1;
            return Err(io::Error::from_raw_os_error(28));
        }
        self.calls += 1;
        match self.fault {
            Fault::Flush => Ok(bytes.len()),
            Fault::Partial if self.calls == 1 => Ok(bytes.len().min(2)),
            Fault::Zero => { self.failed = true; Ok(0) }
            _ => { self.failed = true; Err(io::Error::from_raw_os_error(28)) }
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        if self.failed { self.after_failure += 1; }
        if matches!(self.fault, Fault::Flush) {
            self.failed = true;
            return Err(io::Error::from_raw_os_error(28));
        }
        Ok(())
    }
}

fn verify(root: &Path) -> Result<Value> {
    let mut equality_cases = 0;
    for size in [1024, 65536, 786432, LIMIT as usize - 32, LIMIT as usize] {
        for escaped in [false, true] {
            let value = fixture(size, escaped)?;
            let expected = serde_json::to_vec_pretty(&value)?;
            let mut actual = Vec::new();
            buffered(&mut actual, &value, size.min(BUFFER))?;
            assert_eq!(actual, expected);
            equality_cases += 1;
        }
    }
    for mode in [Mode::Vec, Mode::Stream] {
        for escaped in [false, true] {
            let dir = root.join(format!("oversize-{}-{escaped}", mode.label()));
            fs::create_dir(&dir)?;
            let error = save(&dir, mode, &fixture(LIMIT as usize + 1, escaped)?).unwrap_err();
            assert!(error.to_string().contains("durable job record exceeds"));
            assert_eq!(fs::read_dir(dir)?.count(), 0);
        }
    }
    let mut failures = 0;
    for size in [1024, 65536] {
        let value = fixture(size, false)?;
        for fault in [Fault::Write, Fault::Partial, Fault::Zero, Fault::Flush] {
            let mut sink = FaultSink { fault, calls:0, failed:false, after_failure:0 };
            let error = buffered(&mut sink, &value, BUFFER).unwrap_err();
            let io = error.downcast_ref::<io::Error>().expect("original IO type retained");
            if matches!(fault, Fault::Zero) { assert_eq!(io.kind(), io::ErrorKind::WriteZero); }
            else { assert_eq!(io.raw_os_error(), Some(28)); }
            assert!(sink.failed);
            assert_eq!(sink.after_failure, 0, "Drop must not replay a failed write/flush");
            failures += 1;
        }
    }
    Ok(json!({"byte_equal_cases":equality_cases,"oversize_without_temp_cases":4,
        "write_or_flush_failure_without_drop_retry_cases":failures,"passed":true}))
}

fn main() -> Result<()> {
    let root = std::env::args().nth(1).expect("isolated output directory required");
    let root = Path::new(&root);
    let verification = verify(root)?;
    println!("VERIFIED {verification}");
    io::stdout().flush()?;
    let mut pure_rows = Vec::new();
    let mut allocations = Vec::new();
    for size in [1024, 65536, 786432, LIMIT as usize - 32] {
        for escaped in [false, true] {
            let value = fixture(size, escaped)?;
            let iterations = match size { 1024 => 128, 65536 => 24, 786432 => 4, _ => 1 };
            for mode in [Mode::Vec, Mode::Stream] {
                assert_eq!(serialize(mode, &value)?, size as u64);
                allocations.push(json!({"size":size,"escaped":escaped,"mode":mode.label(),
                    "allocation":allocation_sample(mode,&value)?}));
            }
            for cycle in 0..2 {
                for (position, mode) in [Mode::Vec,Mode::Stream,Mode::Stream,Mode::Vec].into_iter().enumerate() {
                    let cpu_before = cpu_seconds();
                    let started = Instant::now();
                    for _ in 0..iterations { assert_eq!(serialize(mode,&value)?,size as u64); }
                    let wall = started.elapsed().as_secs_f64();
                    let cpu = cpu_seconds()-cpu_before;
                    pure_rows.push(json!({"size":size,"escaped":escaped,"mode":mode.label(),
                        "cycle":cycle,"position":position,"iterations":iterations,
                        "wall_seconds":wall,"cpu_seconds":cpu,"cpu_seconds_per_call":cpu/iterations as f64}));
                }
            }
            println!("PURE_CASE size={size} escaped={escaped}");
            io::stdout().flush()?;
        }
    }
    let durable = root.join("durable");
    fs::create_dir(&durable)?;
    let mut durable_rows = Vec::new();
    for size in [1024, LIMIT as usize - 32] {
        let value = fixture(size,false)?;
        let expected = serde_json::to_vec_pretty(&value)?;
        for (position,mode) in [Mode::Vec,Mode::Stream,Mode::Stream,Mode::Vec].into_iter().enumerate() {
            let cpu_before = cpu_seconds();
            let started = Instant::now();
            save(&durable,mode,&value)?;
            let wall = started.elapsed().as_secs_f64();
            let cpu = cpu_seconds()-cpu_before;
            assert_eq!(fs::read(durable.join("record.json"))?,expected);
            durable_rows.push(json!({"size":size,"mode":mode.label(),"position":position,
                "wall_seconds":wall,"cpu_seconds":cpu,"barriers":"write/flush, file.sync_all, rename, directory.sync_all"}));
        }
    }
    let result = json!({"schema":"isolated-synthetic-receipt-writer-probe-v1",
        "verification":verification,"pure_rows":pure_rows,"allocation_rows":allocations,
        "durable_rows":durable_rows,
        "measurement_notes":{
            "fixture":"serde_json::Value with fixed JobRecord-like fields; sorted Value map, not production JobRecord struct",
            "timing":"single thread; two ABBA cycles per pure case; allocator sampling disabled during timing; one ABBA durable cycle per size",
            "allocation":"separate single-call sample after fixture construction; requested bytes in alloc/realloc/dealloc; excludes fixture and report; logical live peak, not RSS or allocator internal transient realloc peak",
            "limitations":"cached library build; CPU quota and other build load affect wall; synthetic sink adds one noinline black_box write; no production throughput or recovery qualification"}});
    fs::write(root.join("results.json"), serde_json::to_vec_pretty(&result)?)?;
    println!("COMPLETE results.json");
    Ok(())
}
