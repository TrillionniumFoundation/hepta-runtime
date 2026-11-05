// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Fixed JADX bridge on the existing static worker/job owner.
//! Java uses its verified installed inode (its launcher needs the JRE layout).
//! Engine jar, bridge and input are sealed snapshots. Temp space is private,
//! monitored and removed on normal completion; this is not a namespace sandbox.

use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{
	atomic::{AtomicU64, Ordering},
	Arc,
};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::process::Command;
use tokio::time::Instant;

use super::linux::{
	hash_runtime, memfile, open_artifact, read_capped, snapshot, unchanged, Snapshot,
};
use crate::mcp::rea_provider::{sha256, JavaEngineProfile, StaticOperation, WorkerRequest};

pub(super) const BRIDGE: &str = include_str!("rea_jadx_bridge.java");
const MAX_JAR_BYTES: u64 = 128 * 1024 * 1024;
const MAX_RUNTIME_FILE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_DISK_BYTES: u64 = 64 * 1024 * 1024;
const MAX_DISK_ENTRIES: usize = 1024;

struct Pin {
	file: tokio::fs::File,
	before: std::fs::Metadata,
	canonical_path: PathBuf,
	roots: Vec<String>,
}

async fn pin(path: &str, expected: &str, roots: Vec<String>, deadline: Instant) -> Result<Pin> {
	let canonical_path = tokio::fs::canonicalize(path)
		.await
		.with_context(|| format!("canonicalize installed Java component {path}"))?;
	if canonical_path != Path::new(path) {
		bail!("Java runtime manifest paths must name their canonical installation files");
	}
	let selected = path.to_owned();
	let admitted_roots = roots.clone();
	let source =
		tokio::task::spawn_blocking(move || open_artifact(Path::new(&selected), &roots)).await??;
	let mut file = tokio::fs::File::from_std(source);
	let before = file.metadata().await?;
	if !before.is_file() || before.len() > MAX_RUNTIME_FILE_BYTES {
		bail!("Java runtime file is not a bounded regular file");
	}
	let mut hash = Sha256::new();
	let mut buffer = vec![0u8; 64 * 1024];
	let mut count = 0u64;
	loop {
		let n = tokio::time::timeout_at(deadline, file.read(&mut buffer))
			.await
			.context("Java identity deadline exceeded")??;
		if n == 0 {
			break;
		}
		count += n as u64;
		if count > MAX_RUNTIME_FILE_BYTES {
			bail!("Java runtime file grew beyond its limit");
		}
		hash.update(&buffer[..n]);
	}
	let actual: String = hash
		.finalize()
		.iter()
		.map(|byte| format!("{byte:02x}"))
		.collect();
	if actual != expected || count != before.len() || !unchanged(&before, &file.metadata().await?) {
		bail!("Java runtime file changed or its SHA-256 pin does not match");
	}
	let pinned = Pin {
		file,
		before,
		canonical_path,
		roots: admitted_roots,
	};
	verify_pin(&pinned).await?;
	Ok(pinned)
}

/// Java resolves runtime components through installation paths, so retaining
/// the old descriptor alone cannot detect a replacement of a named component.
/// Re-admit each path before and after launch; the installation still is not a
/// sealed execution closure and a privileged actor can race these observations.
async fn verify_pin(pinned: &Pin) -> Result<()> {
	let selected = pinned.canonical_path.clone();
	let roots = pinned.roots.clone();
	let current = tokio::task::spawn_blocking(move || {
		open_artifact(&selected, &roots)?
			.metadata()
			.map_err(anyhow::Error::from)
	})
	.await??;
	if !unchanged(&pinned.before, &current)
		|| !unchanged(&pinned.before, &pinned.file.metadata().await?)
	{
		bail!("Java runtime installation path or pinned inode changed");
	}
	Ok(())
}

async fn verify_runtime(java: &Pin, components: &[Pin]) -> Result<()> {
	verify_pin(java).await?;
	for component in components {
		verify_pin(component).await?;
	}
	Ok(())
}

async fn bridge_snapshot(deadline: Instant) -> Result<Snapshot> {
	let mut source = tokio::fs::File::from_std(memfile("hepta-jadx-bridge")?);
	source.write_all(BRIDGE.as_bytes()).await?;
	source.flush().await?;
	source.seek(std::io::SeekFrom::Start(0)).await?;
	snapshot(
		source,
		&sha256(BRIDGE.as_bytes()),
		64 * 1024,
		false,
		deadline,
	)
	.await
}

#[path = "rea_engine_directory.rs"]
mod engine_directory;

#[path = "rea_engine_scratch.rs"]
mod scratch_owner;
use scratch_owner::{scratch, Scratch};

async fn disk_usage(root: &Scratch) -> Result<u64> {
	root.sampled_bytes(MAX_DISK_BYTES, MAX_DISK_ENTRIES).await
}

fn network_filter() -> Result<Vec<libc::sock_filter>> {
	#[cfg(target_arch = "x86_64")]
	const ARCH: u32 = 0xc000003e;
	#[cfg(target_arch = "aarch64")]
	const ARCH: u32 = 0xc00000b7;
	#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
	{
		bail!("Java worker network filter is not qualified on this architecture");
	}
	#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
	{
		let stmt = |code, k| libc::sock_filter {
			code,
			jt: 0,
			jf: 0,
			k,
		};
		let jump = |k, jt, jf| libc::sock_filter {
			code: 0x15,
			jt,
			jf,
			k,
		};
		let mut rules = vec![
			stmt(0x20, 4),
			jump(ARCH, 1, 0),
			stmt(0x06, 0x80000000),
			stmt(0x20, 0),
		];
		#[cfg(target_arch = "x86_64")]
		rules.extend([
			libc::sock_filter {
				code: 0x45,
				jt: 0,
				jf: 1,
				k: 0x40000000,
			},
			stmt(0x06, 0x80000000),
		]);
		for number in [
			libc::SYS_socket,
			libc::SYS_socketpair,
			libc::SYS_connect,
			libc::SYS_bind,
			libc::SYS_listen,
			libc::SYS_accept,
			libc::SYS_accept4,
			libc::SYS_sendto,
			libc::SYS_recvfrom,
			libc::SYS_sendmsg,
			libc::SYS_recvmsg,
			libc::SYS_ptrace,
			libc::SYS_process_vm_readv,
			libc::SYS_process_vm_writev,
			libc::SYS_io_uring_setup,
			libc::SYS_io_uring_enter,
			libc::SYS_io_uring_register,
		] {
			rules.push(jump(number as u32, 0, 1));
			rules.push(stmt(0x06, 0x00050000 | libc::EPERM as u32));
		}
		rules.push(stmt(0x06, 0x7fff0000));
		Ok(rules)
	}
}

struct JavaLaunch<'a> {
	work: &'a Scratch,
	java_home: &'a str,
	max_output: usize,
	deadline: Instant,
	peak: Arc<AtomicU64>,
}

async fn run_java(
	java: &Pin,
	inherited: &[i32],
	arguments: &[String],
	launch: JavaLaunch<'_>,
) -> Result<(Vec<u8>, Vec<u8>, std::process::ExitStatus)> {
	let JavaLaunch {
		work,
		java_home,
		max_output,
		deadline,
		peak,
	} = launch;
	let java_fd = java.file.as_raw_fd();
	let fds: Vec<_> = std::iter::once(java_fd)
		.chain(inherited.iter().copied())
		.collect();
	let filter = network_filter()?;
	let mut command = Command::new(format!("/proc/self/fd/{java_fd}"));
	command
		.args(arguments)
		.env_clear()
		.env("LC_ALL", "C")
		.env("JAVA_HOME", java_home)
		.env("HOME", work.as_os_str())
		.env("XDG_CONFIG_HOME", work.as_os_str())
		.env("XDG_CACHE_HOME", work.as_os_str())
		.env("TMPDIR", work.as_os_str())
		.current_dir(&**work)
		.stdin(Stdio::null())
		.stdout(Stdio::piped())
		.stderr(Stdio::piped())
		.kill_on_drop(true);
	unsafe {
		command.pre_exec(move || {
			for fd in &fds {
				if libc::fcntl(*fd, libc::F_SETFD, 0) < 0 {
					return Err(std::io::Error::last_os_error());
				}
			}
			if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
				return Err(std::io::Error::last_os_error());
			}
			let rule = libc::sock_fprog {
				len: filter.len() as u16,
				filter: filter.as_ptr().cast_mut(),
			};
			if libc::syscall(libc::SYS_seccomp, 1, 0, &rule) != 0 {
				return Err(std::io::Error::last_os_error());
			}
			let size = libc::rlimit {
				rlim_cur: 16 * 1024 * 1024,
				rlim_max: 16 * 1024 * 1024,
			};
			if libc::setrlimit(libc::RLIMIT_FSIZE, &size) != 0 {
				return Err(std::io::Error::last_os_error());
			}
			Ok(())
		});
	}
	let mut child = command.spawn().context("cannot start fixed Java engine")?;
	let stdout = child.stdout.take().context("Java stdout absent")?;
	let stderr = child.stderr.take().context("Java stderr absent")?;
	let result=tokio::time::timeout_at(deadline,async {
		tokio::select! {
			result=async { tokio::try_join!(read_capped(stdout,max_output),read_capped(stderr,max_output),async {child.wait().await.map_err(Into::into)}) } => result,
			result=async {
				loop {
					let bytes=disk_usage(work).await?;
					peak.fetch_max(bytes,Ordering::Relaxed);
					tokio::time::sleep(Duration::from_millis(250)).await;
				}
				#[allow(unreachable_code)] Ok::<(),anyhow::Error>(())
			} => match result { Err(error)=>Err(error),Ok(())=>Err(anyhow!("unexpected scratch monitor completion")) }
		}
	}).await;
	match result {
		Ok(Ok(result)) => {
			let bytes = disk_usage(work).await?;
			peak.fetch_max(bytes, Ordering::Relaxed);
			Ok(result)
		}
		other => {
			let _ = child.start_kill();
			let _ = child.wait().await;
			match other {
				Ok(Err(error)) => Err(error),
				Err(_) => bail!("Java engine total deadline exceeded"),
				Ok(Ok(_)) => bail!("unreachable Java completion"),
			}
		}
	}
}

async fn analyze_inner(
	input: &WorkerRequest,
	engine: &JavaEngineProfile,
	work: &Scratch,
	started: Instant,
	deadline: Instant,
) -> Result<Value> {
	hash_runtime(&input.profile.runtime_sha256, deadline)
		.await
		.context("verify current runtime identity before JADX execution")?;
	let java = pin(
		&input.profile.backend_executable,
		&input.profile.backend_sha256,
		vec![engine.java_home.clone()],
		deadline,
	)
	.await?;
	let mut runtime_pins = Vec::new();
	for (relative, digest) in &engine.runtime_files {
		runtime_pins.push(
			pin(
				&format!("{}/{relative}", engine.java_home),
				digest,
				vec![engine.java_home.clone()],
				deadline,
			)
			.await?,
		);
	}
	let jar_source = tokio::fs::File::open(&engine.jar_path).await?;
	let jar = snapshot(
		jar_source,
		&engine.jar_sha256,
		MAX_JAR_BYTES,
		false,
		deadline,
	)
	.await?;
	let selected = input.request.artifact_path.clone();
	let roots = input.profile.input_roots.clone();
	let source =
		tokio::task::spawn_blocking(move || open_artifact(Path::new(&selected), &roots)).await??;
	let artifact = snapshot(
		tokio::fs::File::from_std(source),
		&input.request.artifact_sha256,
		input.profile.max_artifact_bytes,
		false,
		deadline,
	)
	.await?;
	let mut target = tokio::fs::File::from_std(artifact.file.try_clone()?);
	target.seek(std::io::SeekFrom::Start(0)).await?;
	let mut header = [0u8; 8];
	let count = target.read(&mut header).await?;
	if count < 4
		|| !(header.starts_with(b"\xca\xfe\xba\xbe")
			|| header.starts_with(b"PK\x03\x04")
			|| header.starts_with(b"dex\n"))
	{
		bail!("JADX accepts only captured class, ZIP/JAR/APK or DEX byte carriers; scripts and project files are refused");
	}
	target.seek(std::io::SeekFrom::Start(0)).await?;
	let bridge = bridge_snapshot(deadline).await?;
	let peak = Arc::new(AtomicU64::new(0));
	verify_runtime(&java, &runtime_pins).await?;
	let (version_out, version_err, version_status) = run_java(
		&java,
		&[],
		&["--version".into()],
		JavaLaunch {
			work,
			java_home: &engine.java_home,
			max_output: 8192,
			deadline,
			peak: peak.clone(),
		},
	)
	.await?;
	verify_runtime(&java, &runtime_pins).await?;
	let version = std::str::from_utf8(&version_out)?
		.lines()
		.next()
		.context("Java version absent")?;
	if !version_status.success()
		|| !version_err.is_empty()
		|| version != input.profile.backend_version
	{
		bail!("Java version differs from the admitted profile");
	}
	let operation = match input.request.operation {
		StaticOperation::Classes => "classes",
		StaticOperation::Sources => "sources",
		_ => bail!("unsupported JADX operation"),
	};
	let arguments = vec![
		"-Xmx256m".into(),
		"-XX:MaxMetaspaceSize=256m".into(),
		"-XX:ReservedCodeCacheSize=64m".into(),
		"-XX:CompressedClassSpaceSize=64m".into(),
		"-XX:+UseSerialGC".into(),
		"-XX:ActiveProcessorCount=1".into(),
		"-XX:-UsePerfData".into(),
		"-XX:+DisableAttachMechanism".into(),
		format!("-Duser.home={}", work.display()),
		format!("-Djava.io.tmpdir={}", work.display()),
		"--source".into(),
		"21".into(),
		format!("/proc/self/fd/{}", bridge.file.as_raw_fd()),
		format!("/proc/self/fd/{}", jar.file.as_raw_fd()),
		format!("/proc/self/fd/{}", artifact.file.as_raw_fd()),
		operation.into(),
		input.profile.max_output_bytes.to_string(),
	];
	verify_runtime(&java, &runtime_pins).await?;
	let (stdout, stderr, status) = run_java(
		&java,
		&[
			jar.file.as_raw_fd(),
			bridge.file.as_raw_fd(),
			artifact.file.as_raw_fd(),
		],
		&arguments,
		JavaLaunch {
			work,
			java_home: &engine.java_home,
			max_output: input.profile.max_output_bytes,
			deadline,
			peak: peak.clone(),
		},
	)
	.await?;
	verify_runtime(&java, &runtime_pins).await?;
	let stdout_text = std::str::from_utf8(&stdout).context("JADX stdout is not UTF-8")?;
	let stderr_text = std::str::from_utf8(&stderr).context("JADX stderr is not UTF-8")?;
	if status.success() {
		let observation: Value = serde_json::from_str(stdout_text)
			.context("JADX bridge omitted its JSON observation")?;
		if observation["schema"] != "hepta.rea.jadx-observation.v1"
			|| observation["engine_version"] != engine.engine_version
			|| observation["operation"] != operation
			|| observation["target_executed"] != false
			|| observation["external_plugins_loaded"] != false
			|| observation["source_semantics_validated"] != false
		{
			bail!("JADX observation does not match the fixed engine contract");
		}
	}
	let mut report = json!({
		"schema":"hepta.rea.static-report.v1","request_sha256":sha256(&serde_json::to_vec(input)?),
		"runtime_sha256":input.profile.runtime_sha256,"provider":input.profile.provider,"operation":input.request.operation,
		"backend":{"sha256":input.profile.backend_sha256,"version":version,"size_bytes":java.before.len(),"snapshot":"verified_installed_inode"},
		"java_engine":engine,"bridge_sha256":bridge.sha256,
		"subject":{"selected_path":input.request.artifact_path,"sha256":artifact.sha256,"size_bytes":artifact.size,"snapshot":"sealed_linux_memfd"},
		"backend_success":status.success(),"backend_exit_code":status.code(),"stdout":stdout_text,"stderr":stderr_text,
		"stdout_sha256":sha256(&stdout),"stderr_sha256":sha256(&stderr),"stdout_bytes":stdout.len(),"stderr_bytes":stderr.len(),"output_complete":true,
		"summary":crate::mcp::rea_provider::summary::selected_fields(input.profile.provider,input.request.operation,stdout_text,status.success()),
		"elapsed_ms":started.elapsed().as_millis(),"rea_evidence_compatible":false,
		"coverage":{"scope":"selected_static_backend_operation","status":"partial"},
		"scratch":{"monitored_peak_bytes":peak.load(Ordering::Relaxed),"monitored_limit_bytes":MAX_DISK_BYTES,"max_entries":MAX_DISK_ENTRIES,"single_file_limit_bytes":16*1024*1024,"poll_interval_ms":250},
		"network_syscalls_denied":true,
		"limitations":["Fixed JADX API observations do not establish reconstructed source correctness",
			"Selected JRE installation paths and held inodes are checked before and after Java runs; this is not a sealed execution closure and privileged concurrent replacement can race observations",
			"System shared libraries and the full JRE installation closure are not attested by the selected manifest",
			"Java executes a verified installed inode; jar, bridge and input are sealed, but this is not a full namespace sandbox",
			"Scratch bytes are sampled every 250 ms, so the aggregate byte limit is a monitored budget rather than a hard filesystem quota; individual files are limited to 16 MiB",
			"Durable jobs clean their adopted private scratch only after the original process group stops; unknown owner outcomes retain it. Standalone workers have no crash-recovery owner"]
	});
	report["native_report_id"] = json!(format!(
		"hepta_rea_static_v1_{}",
		sha256(&serde_json::to_vec(&report)?)
	));
	Ok(report)
}

pub(super) async fn analyze(input: WorkerRequest) -> Result<Value> {
	let engine = input
		.profile
		.java_engine
		.as_ref()
		.context("JADX profile lacks engine pins")?;
	let started = Instant::now();
	let deadline = started + Duration::from_secs(input.profile.timeout_seconds);
	let work = scratch(&input.profile.working_directory, "jadx").await?;
	let result = analyze_inner(&input, engine, &work, started, deadline).await;
	let cleanup_owner = work.cleanup_owner();
	let retained_path = work.display().to_string();
	let cleanup = work.finish().await;
	match (result, cleanup) {
		(Ok(mut report), Ok(removed)) => {
			report["scratch"]["removed_after_operation"] = json!(removed);
			report["scratch"]["cleanup_pending"] = json!(!removed);
			report["scratch"]["cleanup_owner"] = json!(cleanup_owner);
			report
				.as_object_mut()
				.context("engine report is not an object")?
				.remove("native_report_id");
			report["native_report_id"] = json!(format!(
				"hepta_rea_static_v1_{}",
				sha256(&serde_json::to_vec(&report)?)
			));
			Ok(report)
		}
		(Err(error), Ok(_)) => Err(error),
		(_, Err(error)) => {
			Err(error).with_context(|| format!("JADX scratch cleanup incomplete: {retained_path}"))
		}
	}
}

#[cfg(test)]
#[path = "rea_engine_tests.rs"]
mod tests;

#[path = "rea_engine_ghidra.rs"]
mod ghidra;

pub(super) async fn analyze_ghidra(input: WorkerRequest) -> Result<Value> {
	ghidra::analyze(input).await
}
