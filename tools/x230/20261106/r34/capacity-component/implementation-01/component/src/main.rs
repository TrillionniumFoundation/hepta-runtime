// Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
//! Linux-only native transport component. It is not an MCP server or authority issuer.
//! One original runtime owns every ordinary SSH gate and the existing-job cancellation.

#[cfg(not(target_os = "linux"))]
compile_error!("this owned-process capacity component runs only on the Linux controller");

use anyhow::{anyhow, bail, ensure, Context, Result};
use hepta_runtime::{
    mcp::runtime::{
        self,
        config::ExecutionMode,
        jobs::{ProcessCancelParams, ProcessReadParams, ProcessRefParams, ProcessStartParams},
        ssh, HostConfig, Platform, RuntimeConfig,
    },
    native,
};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::CString,
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::{fd::{AsRawFd, FromRawFd}, unix::{fs::{MetadataExt, OpenOptionsExt}, process::ExitStatusExt}},
    path::{Component, Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::task::JoinHandle;

const HOSTS: [&str; 6] = ["ai395", "mac", "main", "pocket4", "rog", "x230"];
const GATE_SOURCE: &str = concat!(include_str!("../fixtures/common.py"), "\n", include_str!("../fixtures/gate.py"));
const WORKLOAD_SOURCE: &str = concat!(include_str!("../fixtures/common.py"), "\n", include_str!("../fixtures/workload.py"));
const GATE_BUDGET: Duration = Duration::from_secs(40);
const BARRIER_BUDGET_NS: u64 = 10_000_000_000;
const CONTROL_BUDGET_NS: u64 = 45_000_000_000;
const MAX_INPUT: usize = 1024 * 1024;

fn monotonic_ns() -> Result<u64> {
    let mut stamp = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // CLOCK_MONOTONIC is shared with the local coordinator's time.monotonic_ns().
    ensure!(unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut stamp) } == 0,
        "read controller monotonic clock: {}", std::io::Error::last_os_error());
    ensure!(stamp.tv_sec >= 0 && (0..1_000_000_000).contains(&stamp.tv_nsec), "invalid monotonic clock");
    (stamp.tv_sec as u64).checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(stamp.tv_nsec as u64))
        .context("monotonic timestamp overflow")
}

fn exact_keys(value: &Value, keys: &[&str]) -> Result<()> {
    let actual: BTreeSet<&str> = value.as_object().context("JSON object required")?.keys().map(String::as_str).collect();
    ensure!(actual == keys.iter().copied().collect(), "unexpected JSON fields");
    Ok(())
}

fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value.get(key).and_then(Value::as_str).with_context(|| format!("string field {key} required"))
}

fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn job_id(value: &str) -> bool {
    let parts: Vec<&str> = value.split('-').collect();
    parts.len() == 3 && parts.iter().all(|part| !part.is_empty() && lower_hex(part, part.len()))
}

fn absolute_clean(value: &str) -> Result<PathBuf> {
    let path = PathBuf::from(value);
    ensure!(path.is_absolute() && path.components().all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
        && !value.contains(['\0', '\n', '\r']) && path != Path::new("/"), "canonical absolute path required");
    Ok(path)
}

fn metadata_identity(info: &std::fs::Metadata) -> (u64, u64, u32, u32) {
    (info.dev(), info.ino(), info.uid(), info.mode())
}

fn file_stamp(info: &std::fs::Metadata) -> (u64, u64, u32, u32, u64, u64, i64, i64, i64, i64) {
    (info.dev(), info.ino(), info.uid(), info.mode(), info.nlink(), info.len(),
     info.mtime(), info.mtime_nsec(), info.ctime(), info.ctime_nsec())
}

struct PrivateDir { path: PathBuf, file: File }

impl PrivateDir {
    fn open(path: PathBuf) -> Result<Self> {
        ensure!(std::fs::canonicalize(&path)? == path, "indirect private directory");
        let file = OpenOptions::new().read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK).open(&path)?;
        let info = file.metadata()?;
        ensure!(info.is_dir() && info.uid() == unsafe { libc::geteuid() } && info.mode() & 0o777 == 0o700,
            "private directory owner/mode differs");
        ensure!(metadata_identity(&info) == metadata_identity(&std::fs::symlink_metadata(&path)?), "private directory changed");
        Ok(Self { path, file })
    }

    fn create(path: PathBuf) -> Result<Self> {
        let parent = path.parent().context("private output parent missing")?;
        ensure!(std::fs::canonicalize(parent)? == parent, "indirect output parent");
        let mut builder = std::fs::DirBuilder::new();
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700).create(&path)?; // create-only, never reuse an old cell
        Self::open(path)
    }

    fn named(&self) -> Result<()> {
        ensure!(std::fs::canonicalize(&self.path)? == self.path
            && metadata_identity(&self.file.metadata()?) == metadata_identity(&std::fs::symlink_metadata(&self.path)?),
            "private directory no longer has its original path");
        Ok(())
    }

    fn open_at(&self, name: &str, flags: i32) -> Result<File> {
        ensure!(!name.is_empty() && name != "." && name != ".." && !name.contains('/'), "unsafe private filename");
        self.named()?;
        let name = CString::new(name)?;
        let fd = unsafe { libc::openat(self.file.as_raw_fd(), name.as_ptr(), flags | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK, 0o600) };
        if fd < 0 { return Err(std::io::Error::last_os_error().into()); }
        // This is the one owning File for the newly opened descriptor.
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    fn create_file(&self, name: &str) -> Result<File> {
        let file = self.open_at(name, libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL)?;
        let info = file.metadata()?;
        ensure!(info.is_file() && info.nlink() == 1 && info.uid() == unsafe { libc::geteuid() }
            && info.mode() & 0o777 == 0o600, "unsafe private output");
        Ok(file)
    }

    fn save(&self, name: &str, raw: &[u8]) -> Result<()> {
        let mut file = self.create_file(name)?;
        file.write_all(raw)?;
        file.sync_all()?;
        self.file.sync_all()?;
        self.named()
    }

    fn json(&self, name: &str, value: &Value) -> Result<()> {
        let mut raw = serde_json::to_vec_pretty(value)?;
        raw.push(b'\n');
        self.save(name, &raw)
    }

    fn read(&self, name: &str, limit: usize) -> Result<Option<Vec<u8>>> {
        let mut file = match self.open_at(name, libc::O_RDONLY) {
            Ok(file) => file,
            Err(error) if error.downcast_ref::<std::io::Error>().is_some_and(|value| value.kind() == std::io::ErrorKind::NotFound) => return Ok(None),
            Err(error) => return Err(error),
        };
        let before = file.metadata()?;
        ensure!(before.is_file() && before.uid() == unsafe { libc::geteuid() } && before.nlink() == 1
            && before.mode() & 0o777 == 0o600 && before.len() <= limit as u64, "unsafe private input");
        let mut raw = Vec::new();
        (&mut file).take(limit as u64 + 1).read_to_end(&mut raw)?;
        ensure!(raw.len() as u64 == before.len() && file_stamp(&before) == file_stamp(&file.metadata()?)
            && file_stamp(&before) == file_stamp(&std::fs::symlink_metadata(self.path.join(name))?), "private input changed");
        self.named()?;
        Ok(Some(raw))
    }
}

struct JournalState { file: File, sequence: u64 }
struct Journal { directory: Arc<PrivateDir>, state: Mutex<JournalState> }

impl Journal {
    fn new(directory: Arc<PrivateDir>) -> Result<Self> {
        let file = directory.create_file("events.jsonl")?;
        directory.file.sync_all()?;
        Ok(Self { directory, state: Mutex::new(JournalState { file, sequence: 0 }) })
    }

    fn emit(&self, event: &str, data: Value) -> Result<u64> {
        let mut state = self.state.lock().map_err(|_| anyhow!("component journal mutex poisoned"))?;
        let at = monotonic_ns()?;
        let row = json!({"schema":"hepta-r34-capacity-event/v1", "sequence":state.sequence,
            "monotonic_ns":at, "event":event, "data":data});
        let mut raw = serde_json::to_vec(&row)?;
        raw.push(b'\n');
        state.file.write_all(&raw)?;
        state.file.sync_all()?;
        state.sequence += 1;
        Ok(at)
    }
}

struct Cell {
    nonce: String,
    victim: String,
    arm: String,
    config: RuntimeConfig,
    profile: PathBuf,
    output: PathBuf,
    control: Arc<PrivateDir>,
    tickets: BTreeMap<String, Value>,
}

impl Cell {
    fn load(path: &Path) -> Result<Self> {
        let parent = PrivateDir::open(path.parent().context("cell parent missing")?.to_owned())?;
        let name = path.file_name().and_then(|value| value.to_str()).context("cell filename missing")?;
        let raw = parent.read(name, MAX_INPUT)?.context("cell input missing")?;
        let value: Value = serde_json::from_slice(&raw)?;
        exact_keys(&value, &["schema", "status", "arm", "nonce", "victim", "runtime_config", "observation_profile", "output_directory", "control_directory", "fixtures", "bindings"])?;
        ensure!(value["schema"] == "hepta-r34-capacity-cell/v1" && value["status"] == "sealed_actual_cell", "unsealed component cell");
        let nonce = text(&value, "nonce")?.to_owned();
        let victim = text(&value, "victim")?.to_owned();
        let arm = text(&value, "arm")?.to_owned();
        ensure!(lower_hex(&nonce, 24) && ["x230", "mac"].contains(&victim.as_str()) && ["A", "B"].contains(&arm.as_str()), "invalid frozen cell role");
        exact_keys(&value["bindings"], &["driver_binary_sha256", "runtime_source_map_sha256", "runtime_qualification_report_sha256", "component_build_report_sha256", "scenario_sources_sha256"])?;
        for hash in value["bindings"].as_object().context("missing actual build bindings")?.values() {
            ensure!(hash.as_str().is_some_and(|hash| lower_hex(hash, 64)), "future component build identity is unset");
        }
        let config_path = absolute_clean(text(&value, "runtime_config")?)?;
        let config = RuntimeConfig::load(&config_path)?;
        let profile = absolute_clean(text(&value, "observation_profile")?)?;
        let output = absolute_clean(text(&value, "output_directory")?)?;
        let control = Arc::new(PrivateDir::open(absolute_clean(text(&value, "control_directory")?)?)?);
        let cell_root = output.parent().context("private cell output parent missing")?;
        ensure!(output.file_name().is_some_and(|name| name == "driver")
            && control.path == cell_root.join("control") && config.state_dir == cell_root.join("runtime-state")
            && !config.state_dir.exists(), "component requires its fresh private controller namespace");
        ensure!(std::fs::read_dir(&control.path)?.next().is_none(), "control namespace was already used");
        exact_keys(&value["fixtures"], &HOSTS)?;
        ensure!(config.hosts.keys().map(String::as_str).collect::<BTreeSet<_>>() == HOSTS.into_iter().collect(), "runtime host set differs");
        let mut tickets = BTreeMap::new();
        let mut targets = BTreeSet::new();
        for host in HOSTS {
            let ticket = &value["fixtures"][host];
            exact_keys(ticket, &["nonce", "host", "victim", "base", "name", "fixture_identity", "source_job_id", "source_record_sha256", "expected_platform"])?;
            ensure!(ticket["nonce"] == nonce && ticket["host"] == host && ticket["victim"] == victim, "fixture role differs");
            let name = format!("r34-capacity-{nonce}-{host}");
            ensure!(ticket["name"] == name && job_id(text(ticket, "source_job_id")?)
                && lower_hex(text(ticket, "source_record_sha256")?, 64), "fixture provenance differs");
            let base = absolute_clean(text(ticket, "base")?)?;
            ensure!(ticket["fixture_identity"].as_array().is_some_and(|identity| identity.len() == 4 && identity.iter().all(|part| part.as_u64().is_some())), "fixture has not been prepared");
            let configured = config.host(host)?;
            ensure!(configured.execution_mode == ExecutionMode::Operator && configured.allow_execute
                && configured.allow_job_network && !configured.allow_pty && !configured.allow_write
                && configured.privileged_actions.is_empty(), "frozen operator fixture policy differs");
            ensure!(configured.remote_state_dir == base.join(name).to_str().context("non-UTF8 fixture")?, "remote state is outside fresh fixture");
            let platform = if configured.platform == Platform::Macos { "darwin" } else { "linux" };
            ensure!(ticket["expected_platform"] == platform, "configured remote platform differs");
            ensure!(targets.insert(configured.ssh_target.clone()), "duplicate aliases do not prove distinct target limits");
            tickets.insert(host.to_owned(), ticket.clone());
        }
        Ok(Self { nonce, victim, arm, config, profile, output, control, tickets })
    }

    fn gate_count(&self, host: &str) -> usize {
        let peer = if self.victim == "x230" { "ai395" } else { "main" };
        if host == self.victim || host == peer { 2 } else { 1 }
    }

    fn command(&self, action: &str) -> Result<Option<Value>> {
        if let Some(raw) = self.control.read("abort.json", 65536)? {
            let value: Value = serde_json::from_slice(&raw)?;
            ensure!(value["schema"] == "hepta-r34-capacity-control/v1" && value["nonce"] == self.nonce
                && value["action"] == "abort", "foreign abort control");
            bail!("coordinator stopped this cell: {}", value["reason"]);
        }
        let Some(raw) = self.control.read(&format!("{action}.json"), 65536)? else { return Ok(None); };
        let value: Value = serde_json::from_slice(&raw)?;
        exact_keys(&value, &["schema", "nonce", "action", "jobs"])?;
        ensure!(value["schema"] == "hepta-r34-capacity-control/v1" && value["nonce"] == self.nonce
            && value["action"] == action, "foreign component command");
        Ok(Some(value))
    }

    async fn wait_command(&self, action: &str, jobs: &Value, deadline: u64) -> Result<()> {
        loop {
            ensure!(monotonic_ns()? < deadline, "component {action} control deadline expired");
            if let Some(value) = self.command(action)? {
                ensure!(&value["jobs"] == jobs, "control refers to different original jobs");
                ensure!(monotonic_ns()? < deadline, "late component control does not renew deadline");
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }
}

#[derive(Clone)]
struct Job { host: String, id: String, request: ProcessStartParams }

fn start_request(cell: &Cell, host: &str) -> Result<ProcessStartParams> {
    let ticket = cell.tickets.get(host).context("missing fixed fixture")?;
    Ok(ProcessStartParams {
        host: host.to_owned(), executable: "/usr/bin/python3".to_owned(),
        args: vec!["-I".to_owned(), "-S".to_owned(), "-c".to_owned(), WORKLOAD_SOURCE.to_owned(), serde_json::to_string(ticket)?],
        cwd: Some(cell.config.host(host)?.remote_state_dir.clone()), env: BTreeMap::new(),
        stdin: Some(format!("HEPTA-R34-CAPACITY {} {host}\n", cell.nonce)),
        timeout_seconds: Some(120), idempotency_key: Some(format!("r34-capacity-{}-{host}", cell.nonce)),
        nice: None, cpu_quota_percent: None, memory_max_bytes: None,
    })
}

struct StartBatch { jobs: Vec<Job>, errors: Vec<String> }

async fn start_jobs(cell: &Cell, log: &Arc<Journal>) -> Result<StartBatch> {
    let mut requests = Vec::new();
    for host in HOSTS {
        let request = start_request(cell, host)?;
        log.directory.json(&format!("start-{host}.request.json"), &serde_json::to_value(&request)?)?;
        requests.push(request);
    }
    // No fallible caller operation is allowed to abandon the six original handles.
    let mut handles = Vec::new();
    for request in requests {
        let host = request.host.clone();
        let owned = request.clone();
        handles.push((host, request, tokio::spawn(async move { native::execute_or_observe(owned).await })));
    }
    let mut jobs = Vec::new();
    let mut errors = Vec::new();
    for (host, request, handle) in handles {
        match handle.await {
            Ok(Ok(raw)) => {
                // Recover the known original identity before a fallible evidence write.
                let parsed: Result<Job> = (|| {
                    let response: Value = serde_json::from_str(&raw)?;
                    ensure!(response["reused"] == false, "fresh fixture key unexpectedly reused an existing job");
                    let record = response.get("job").context("missing original job record")?;
                    let id = text(record, "id")?.to_owned();
                    ensure!(job_id(&id) && record["host"] == host
                        && record["remote_job_dir"] == format!("{}/jobs/{id}", cell.config.host(&host)?.remote_state_dir), "original job binding differs");
                    Ok(Job { host: host.clone(), id, request })
                })();
                match parsed {
                    Ok(job) => jobs.push(job),
                    Err(error) => errors.push(format!("{host}: original response identity: {error:#}")),
                }
                if let Err(error) = log.directory.save(&format!("start-{host}.response.json"), raw.as_bytes()) {
                    errors.push(format!("{host}: retain original response: {error:#}"));
                }
            }
            Ok(Err(error)) => errors.push(format!("{host}: original start error; retain original key: {error:#}")),
            Err(error) => errors.push(format!("{host}: original start task join: {error}")),
        }
    }
    if let Err(error) = log.emit("starts_joined", json!({"jobs":jobs.iter().map(|job| (job.host.clone(), job.id.clone())).collect::<BTreeMap<_, _>>(), "errors":errors,
        "unknown_effects_keep_original_request_files":true})) {
        errors.push(format!("retain completed start batch: {error:#}"));
    }
    // Native failures after admission may be unknown. They are never replaced or relaunched.
    // Known successes remain available for reconciliation even if a sibling or log write failed.
    Ok(StartBatch { jobs, errors })
}

struct GateTask { role: String, handle: JoinHandle<Result<Value>> }

fn pending_roles(gates: &[GateTask]) -> Vec<String> {
    gates.iter().filter(|gate| !gate.handle.is_finished()).map(|gate| gate.role.clone()).collect()
}

async fn one_gate(host: HostConfig, role: String, command: String, input: Vec<u8>, log: Arc<Journal>) -> Result<Value> {
    let before = monotonic_ns()?;
    let result = ssh::run_capture(&host, &command, &input, GATE_BUDGET).await;
    let after = monotonic_ns()?;
    let row = match result {
        Ok(output) => {
            log.directory.save(&format!("{role}.stdout"), &output.stdout)?;
            log.directory.save(&format!("{role}.stderr"), &output.stderr)?;
            json!({"role":role, "submitted_monotonic_ns":before, "finished_monotonic_ns":after,
                "transport_returned":true, "exit_code":output.status.code(), "signal":output.status.signal(),
                "success":output.status.success(), "stdout_bytes":output.stdout.len(), "stderr_bytes":output.stderr.len()})
        }
        Err(error) => json!({"role":role, "submitted_monotonic_ns":before, "finished_monotonic_ns":after,
            "transport_returned":false, "success":false, "error":format!("{error:#}"), "automatic_retry":false}),
    };
    log.directory.json(&format!("{role}.result.json"), &row)?;
    log.emit("gate_completed", row.clone())?;
    Ok(row)
}

async fn gate_phase(cell: &Cell, jobs: &[Job], log: &Arc<Journal>) -> Result<Value> {
    let job_map = json!(jobs.iter().map(|job| (job.host.clone(), job.id.clone())).collect::<BTreeMap<_, _>>());
    log.emit("jobs_started", json!({"jobs":job_map, "workload_ttl_seconds":90, "supervisor_timeout_seconds":120}))?;
    cell.wait_command("start-gates", &job_map, monotonic_ns()?.checked_add(CONTROL_BUDGET_NS).context("control deadline overflow")?).await?;
    let command = format!("{} -I -S -c {}", ssh::shell_quote("/usr/bin/python3"), ssh::shell_quote(GATE_SOURCE));
    let mut prepared = Vec::new();
    for host in HOSTS {
        for index in 0..cell.gate_count(host) {
            let role = format!("gate-{host}-{index}");
            let payload = json!({"ticket":cell.tickets[host], "index":index});
            let input = serde_json::to_vec(&payload)?;
            log.directory.json(&format!("{role}.request.json"), &json!({"host":host,"target":cell.config.host(host)?.ssh_target,
                "remote_command":command,"stdin":payload,"transport_budget_seconds":40}))?;
            prepared.push((cell.config.host(host)?.clone(), role, command.clone(), input));
        }
    }
    ensure!(prepared.len() == 8, "gate inventory is not eight");
    let submitted = monotonic_ns()?;
    let deadline = submitted.checked_add(BARRIER_BUDGET_NS).context("barrier deadline overflow")?;
    let mut gates = Vec::new();
    for (host, role, command, input) in prepared {
        gates.push(GateTask { role:role.clone(), handle:tokio::spawn(one_gate(host, role, command, input, Arc::clone(log))) });
    }
    // This inner scope can fail, but every created gate handle is always joined below.
    let measurement: Result<Value> = async {
        log.emit("gates_submitted", json!({"first_submit_monotonic_ns":submitted,"barrier_deadline_monotonic_ns":deadline,
            "pending":pending_roles(&gates),"jobs":job_map}))?;
        cell.wait_command("cancel", &job_map, deadline).await?;
        let pending = pending_roles(&gates);
        ensure!(pending.len() == 8, "a gate completed before cancellation; saturation not established");
        let victim = jobs.iter().find(|job| job.host == cell.victim).context("original victim job missing")?;
        let request = ProcessCancelParams { host:victim.host.clone(), job_id:victim.id.clone(), grace_seconds:Some(3) };
        log.directory.json("cancel.request.json", &serde_json::to_value(&request)?)?;
        ensure!(monotonic_ns()? < deadline && pending_roles(&gates).len() == 8, "saturation setup expired before dispatch");
        let dispatch = log.emit("cancel_dispatch", json!({"host":victim.host,"job_id":victim.id,"pending":pending_roles(&gates),
            "release_after_seconds":3,"ack_is_not_terminal":true}))?;
        let entry = monotonic_ns()?;
        // No timeout wrapper, abort, retry, alternate key, or copied cancellation code.
        let result = native::cancel(request).await;
        let finished = monotonic_ns()?;
        let row = match result {
            Ok(raw) => {
                log.directory.save("cancel.response.json", raw.as_bytes())?;
                let decoded: Value = serde_json::from_str(&raw).context("original cancel returned invalid JSON")?;
                json!({"library_returned":true,"dispatch_monotonic_ns":dispatch,"entry_monotonic_ns":entry,
                    "finished_monotonic_ns":finished,"response":decoded})
            }
            Err(error) => json!({"library_returned":false,"dispatch_monotonic_ns":dispatch,"entry_monotonic_ns":entry,
                "finished_monotonic_ns":finished,"error":format!("{error:#}"),"automatic_retry":false}),
        };
        log.directory.json("cancel.result.json", &row)?;
        log.emit("cancel_completed", row.clone())?;
        Ok(row)
    }.await;
    let mut joined = Vec::new();
    let mut join_errors = Vec::new();
    for gate in gates {
        match gate.handle.await {
            Ok(Ok(row)) => joined.push(row),
            Ok(Err(error)) => join_errors.push(format!("{}: {error:#}", gate.role)),
            Err(error) => join_errors.push(format!("{}: original gate task join: {error}", gate.role)),
        }
    }
    let measurement_error = measurement.as_ref().err().map(|error| format!("{error:#}"));
    let row = json!({"measurement":measurement.as_ref().ok(),"measurement_error":measurement_error,
        "gate_results":joined,"gate_join_errors":join_errors,"all_original_gate_tasks_awaited":true});
    log.directory.json("gate-phase.json", &row)?;
    log.emit("gates_joined", json!({"count":joined.len(),"errors":join_errors,"measurement_error":measurement_error}))?;
    // Result reporting happens only after actual completion of every task.
    Ok(row)
}

fn terminal(value: &Value) -> bool {
    value.get("state").and_then(Value::as_str).is_some_and(|state| ["succeeded", "failed", "cancelled", "timed_out"].contains(&state))
        && value["terminal_publication_confirmed"] == true
}

async fn reconcile_one(job: Job, log: Arc<Journal>, deadline: u64) -> Result<Value> {
    let mut index = 0;
    loop {
        ensure!(monotonic_ns()? < deadline, "original job reconciliation deadline expired");
        ensure!(index < 512, "bounded status observation count exceeded");
        let result = native::status(ProcessRefParams { host:job.host.clone(), job_id:job.id.clone() }).await;
        let raw = match result {
            Ok(raw) => raw,
            Err(error) => {
                log.directory.json(&format!("status-{}-{index:03}.error.json", job.host), &json!({"error":format!("{error:#}"),"job_id":job.id}))?;
                index += 1;
                tokio::time::sleep(Duration::from_millis(250)).await;
                continue;
            }
        };
        log.directory.save(&format!("status-{}-{index:03}.json", job.host), raw.as_bytes())?;
        let status: Value = serde_json::from_str(&raw)?;
        ensure!(status["job_id"] == job.id, "original status identity differs");
        if terminal(&status) {
            let read = native::read(ProcessReadParams { host:job.host.clone(),job_id:job.id.clone(),stdout_offset:Some(0),stderr_offset:Some(0),limit:Some(16384) }).await?;
            log.directory.save(&format!("read-{}.json", job.host), read.as_bytes())?;
            let observation = native::observe_request(job.request).await?;
            if let Some(raw) = &observation { log.directory.save(&format!("original-key-{}.json",job.host),raw.as_bytes())?; }
            return Ok(json!({"host":job.host,"job_id":job.id,"terminal_status":status,"read":serde_json::from_str::<Value>(&read)?,
                "original_key_still_bound":observation.is_some()}));
        }
        index += 1;
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

async fn run_cell(cell: &Cell, log: &Arc<Journal>) -> Result<Value> {
    let started = monotonic_ns()?;
    let batch = start_jobs(cell, log).await?;
    let known_jobs = batch.jobs.len();
    let gates = if batch.errors.is_empty() && known_jobs == 6 {
        gate_phase(cell, &batch.jobs, log).await
    } else {
        Err(anyhow!("gate phase withheld: the original six-job start batch did not complete without error"))
    };
    // Reconcile the known original identities even when gate/control measurement failed.
    let deadline = started.checked_add(150_000_000_000).context("reconciliation deadline overflow")?;
    let mut handles = Vec::new();
    for job in batch.jobs { handles.push((job.host.clone(), tokio::spawn(reconcile_one(job, Arc::clone(log), deadline)))); }
    let mut reconciliation = Vec::new();
    let mut errors = Vec::new();
    for (host, handle) in handles {
        match handle.await {
            Ok(Ok(row)) => reconciliation.push(row),
            Ok(Err(error)) => errors.push(format!("{host}: {error:#}")),
            Err(error) => errors.push(format!("{host}: original reconciliation task join: {error}")),
        }
    }
    let gate_error = gates.as_ref().err().map(|error| format!("{error:#}"));
    let gate_failed = match gates.as_ref() {
        Err(_) => true,
        Ok(row) => !row["measurement_error"].is_null()
            || row["gate_join_errors"].as_array().is_none_or(|rows| !rows.is_empty())
            || row["gate_results"].as_array().is_none_or(|rows| rows.len() != 8 || rows.iter().any(|row| row["success"] != true))
            || row["measurement"]["library_returned"] != true,
    };
    let phase_errors = !batch.errors.is_empty() || known_jobs != 6 || !errors.is_empty() || gate_failed;
    let result = json!({"start_errors":batch.errors,"known_original_jobs":known_jobs,
        "gate_phase":gates.as_ref().ok(),"gate_phase_error":gate_error,
        "job_reconciliation":reconciliation,"job_reconciliation_errors":errors,
        "all_original_reconciliation_tasks_awaited":true,"driver_phase_errors_present":phase_errors,
        "ttl_is_not_terminal_proof":true});
    log.directory.json("cell-operations.json", &result)?;
    Ok(result)
}

async fn run(cell: Cell) -> Result<()> {
    let output = Arc::new(PrivateDir::create(cell.output.clone())?);
    let log = Arc::new(Journal::new(Arc::clone(&output))?);
    log.emit("cell_initializing", json!({"arm":cell.arm,"nonce":cell.nonce,"victim":cell.victim,
        "controller_pid":std::process::id(),"scope":"native direct-transport component; not MCP end-to-end"}))?;
    runtime::search_jobs::init_search_interpreters(&cell.config)?;
    runtime::init_runtime(cell.config.clone())?;
    runtime::prepare_durable_stores().await?;
    runtime::request_audit::enable_group_commit()?;
    let direct = ssh::start_direct_transport()?;
    let pool = match ssh::start_observation_pool(Some(&cell.profile), false).await {
        Ok(Some(pool)) => pool,
        Ok(None) => {
            let direct_result = direct.shutdown().await;
            output.json("startup-failure.json", &json!({"error":"configured pool startup returned no guard",
                "direct_shutdown":direct_result.as_ref().err().map(|error|format!("{error:#}")),"direct_shutdown_awaited":true}))?;
            bail!("configured observation pool did not start");
        }
        Err(error) => {
            let direct_result = direct.shutdown().await;
            output.json("startup-failure.json", &json!({"error":format!("{error:#}"),
                "direct_shutdown":direct_result.as_ref().err().map(|error|format!("{error:#}")),"direct_shutdown_awaited":true}))?;
            return Err(error.context("observation pool startup; original direct owner shutdown was awaited"));
        }
    };
    let operation = run_cell(&cell, &log).await;
    // No error propagation can bypass either original owner join.
    runtime::shutdown_request_scoped().await;
    let (direct_cleanup, pool_cleanup) = tokio::join!(direct.shutdown(), pool.shutdown());
    let result = json!({"schema":"hepta-r34-capacity-driver-result/v1","arm":cell.arm,"nonce":cell.nonce,
        "victim":cell.victim,"operation":operation.as_ref().ok(),"operation_error":operation.as_ref().err().map(|error|format!("{error:#}")),
        "direct_shutdown_awaited":true,"direct_shutdown_error":direct_cleanup.as_ref().err().map(|error|format!("{error:#}")),
        "pool_shutdown_awaited":true,"pool_shutdown_error":pool_cleanup.as_ref().err().map(|error|format!("{error:#}")),
        "capacity_passed":null,"candidate_adopted":false,"automatic_retry":false,
        "scope":"driver completion is not an occupancy witness or full MCP performance result"});
    output.json("driver-result.json", &result)?;
    log.emit("driver_completed", json!({"operation_returned":operation.is_ok(),"direct_shutdown_ok":direct_cleanup.is_ok(),
        "pool_shutdown_ok":pool_cleanup.is_ok(),"capacity_passed":null}))?;
    // This exit is operational completion only; the independent evidence checker decides capacity.
    let operation = operation?;
    direct_cleanup?;
    pool_cleanup?;
    ensure!(operation["driver_phase_errors_present"] == false, "component retained primary operation or reconciliation errors; inspect driver-result.json");
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().collect();
    ensure!(args.len() == 2, "usage: hepta-direct-capacity-component SEALED_CELL_JSON");
    let path = PathBuf::from(&args[1]);
    ensure!(path.is_absolute(), "explicit absolute cell input required");
    let cell = Cell::load(&path)?;
    tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build()?.block_on(run(cell))
}
