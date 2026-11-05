// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Fixed Ghidra ELF inventory and bounded function analysis on the existing static owner.
//! Installed engine paths are hash-checked and re-admitted; they are not sealed.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::os::fd::AsRawFd;
use std::path::Path;
use std::sync::{
	atomic::{AtomicU64, Ordering},
	Arc,
};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::time::Instant;

use super::super::linux::{hash_runtime, memfile, open_artifact, snapshot, unchanged, Snapshot};
use super::{pin, run_java, scratch, verify_runtime, JavaLaunch};
use crate::mcp::rea_provider::engine_profile::{
	validate_manifest, InstallationManifest, MAX_INSTALLATION_FILES, MAX_MANIFEST_BYTES,
};
use crate::mcp::rea_provider::{
	ghidra_contract, sha256, GhidraEngineProfile, StaticOperation, WorkerRequest,
};

const MAX_INSTALLATION_BYTES: u64 = 8 * 1024 * 1024 * 1024;

#[derive(Clone)]
struct InstalledFile {
	relative: String,
	before: std::fs::Metadata,
}

struct Installation {
	root: String,
	files: Vec<InstalledFile>,
	classpath: String,
	total_bytes: u64,
	_manifest: Snapshot,
}

async fn file_inventory(root: &str) -> Result<BTreeSet<String>> {
	let base = Path::new(root).join("Ghidra");
	if !tokio::fs::symlink_metadata(&base).await?.is_dir() {
		bail!("Ghidra installation data root must be a real directory");
	}
	let mut directories = vec![base];
	let mut files = BTreeSet::new();
	let mut entries = 0usize;
	while let Some(directory) = directories.pop() {
		let mut listing = tokio::fs::read_dir(directory).await?;
		while let Some(entry) = listing.next_entry().await? {
			entries += 1;
			if entries > 3 * MAX_INSTALLATION_FILES {
				bail!("Ghidra installation entry budget exceeded");
			}
			let metadata = tokio::fs::symlink_metadata(entry.path()).await?;
			if metadata.is_symlink() {
				bail!("Ghidra installation contains a symlink");
			}
			if metadata.is_dir() {
				directories.push(entry.path());
			} else if metadata.is_file() {
				let path = entry.path();
				let relative = path
					.strip_prefix(root)?
					.to_str()
					.context("Ghidra installation path is not UTF-8")?
					.to_owned();
				files.insert(relative);
				if files.len() > MAX_INSTALLATION_FILES {
					bail!("Ghidra installation file budget exceeded");
				}
			} else {
				bail!("Ghidra installation contains a non-regular file");
			}
		}
	}
	Ok(files)
}

fn classpath_priority(path: &str) -> Option<u8> {
	if !path.ends_with(".jar") || !path.contains("/lib/") {
		return None;
	}
	for (index, prefix) in [
		"Ghidra/Framework/",
		"Ghidra/Configurations/",
		"Ghidra/Features/",
		"Ghidra/Processors/",
	]
	.iter()
	.enumerate()
	{
		if path.starts_with(prefix) {
			return Some(index as u8);
		}
	}
	None
}

async fn installation(
	engine: &GhidraEngineProfile,
	protected: &[String],
	deadline: Instant,
) -> Result<Installation> {
	if tokio::fs::canonicalize(&engine.installation_root).await?
		!= Path::new(&engine.installation_root)
	{
		bail!("Ghidra installation root must be canonical");
	}
	let selected = engine.manifest_path.clone();
	let manifest_parent = Path::new(&selected)
		.parent()
		.context("Ghidra manifest parent absent")?
		.to_str()
		.context("manifest parent is not UTF-8")?
		.to_owned();
	let manifest_file = tokio::task::spawn_blocking(move || {
		open_artifact(Path::new(&selected), &[manifest_parent])
	})
	.await??;
	let manifest_snapshot = snapshot(
		tokio::fs::File::from_std(manifest_file),
		&engine.manifest_sha256,
		MAX_MANIFEST_BYTES,
		false,
		deadline,
	)
	.await?;
	let mut input = tokio::fs::File::from_std(manifest_snapshot.file.try_clone()?);
	input.seek(std::io::SeekFrom::Start(0)).await?;
	let mut bytes = Vec::with_capacity(manifest_snapshot.size as usize);
	input.read_to_end(&mut bytes).await?;
	let manifest: InstallationManifest =
		serde_json::from_slice(&bytes).context("Ghidra manifest is not a complete JSON record")?;
	validate_manifest(&manifest, engine)?;
	let expected: BTreeSet<_> = manifest.files.keys().cloned().collect();
	if file_inventory(&engine.installation_root).await? != expected {
		bail!("Ghidra installation files differ from the pinned manifest");
	}
	let mut files = Vec::with_capacity(expected.len());
	let mut total_bytes = 0u64;
	let mut jars = Vec::new();
	for (relative, digest) in &manifest.files {
		let path = format!("{}/{relative}", engine.installation_root);
		if protected
			.iter()
			.any(|root| Path::new(&path).starts_with(root))
		{
			bail!("Ghidra installation file is under a protected host root");
		}
		let verified = pin(
			&path,
			digest,
			vec![engine.installation_root.clone()],
			deadline,
		)
		.await?;
		total_bytes = total_bytes
			.checked_add(verified.before.len())
			.context("Ghidra installation size overflow")?;
		if total_bytes > MAX_INSTALLATION_BYTES {
			bail!("Ghidra installation byte budget exceeded");
		}
		files.push(InstalledFile {
			relative: relative.clone(),
			before: verified.before.clone(),
		});
		if let Some(priority) = classpath_priority(relative) {
			jars.push((priority, path));
		}
	}
	jars.sort();
	let classpath = jars
		.into_iter()
		.map(|(_, path)| path)
		.collect::<Vec<_>>()
		.join(":");
	if classpath.is_empty() || classpath.len() > 64 * 1024 {
		bail!("Ghidra fixed classpath is empty or exceeds its byte budget");
	}
	Ok(Installation {
		root: engine.installation_root.clone(),
		files,
		classpath,
		total_bytes,
		_manifest: manifest_snapshot,
	})
}

async fn verify_installation(installation: &Installation, deadline: Instant) -> Result<()> {
	let expected: BTreeSet<_> = installation
		.files
		.iter()
		.map(|file| file.relative.clone())
		.collect();
	if file_inventory(&installation.root).await? != expected {
		bail!("Ghidra installation inventory changed");
	}
	let root = installation.root.clone();
	let files = installation.files.clone();
	tokio::task::spawn_blocking(move || -> Result<()> {
		for file in files {
			if Instant::now() >= deadline {
				bail!("Ghidra installation identity deadline exceeded");
			}
			let current = open_artifact(
				&Path::new(&root).join(&file.relative),
				std::slice::from_ref(&root),
			)?
			.metadata()?;
			if !unchanged(&file.before, &current) {
				bail!("Ghidra installation path or inode changed");
			}
		}
		Ok(())
	})
	.await??;
	Ok(())
}

async fn bridge_snapshot(
	operation: StaticOperation,
	revision: Option<u32>,
	deadline: Instant,
) -> Result<Snapshot> {
	let bridge = ghidra_contract::bridge(operation, revision)?;
	let mut source = tokio::fs::File::from_std(memfile("hepta-ghidra-bridge")?);
	source.write_all(bridge.as_bytes()).await?;
	source.flush().await?;
	source.seek(std::io::SeekFrom::Start(0)).await?;
	snapshot(
		source,
		&sha256(bridge.as_bytes()),
		64 * 1024,
		false,
		deadline,
	)
	.await
}

async fn analyze_inner(
	input: &WorkerRequest,
	engine: &GhidraEngineProfile,
	work: &Path,
	started: Instant,
	deadline: Instant,
) -> Result<Value> {
	hash_runtime(&input.profile.runtime_sha256, deadline).await?;
	let java = pin(
		&input.profile.backend_executable,
		&input.profile.backend_sha256,
		vec![engine.java_home.clone()],
		deadline,
	)
	.await?;
	let mut runtime = Vec::new();
	for (relative, digest) in &engine.runtime_files {
		runtime.push(
			pin(
				&format!("{}/{relative}", engine.java_home),
				digest,
				vec![engine.java_home.clone()],
				deadline,
			)
			.await?,
		);
	}
	let installation = tokio::time::timeout_at(
		deadline,
		installation(engine, &input.protected_roots, deadline),
	)
	.await
	.context("Ghidra installation identity deadline exceeded")??;
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
	let mut header = [0u8; 4];
	target
		.read_exact(&mut header)
		.await
		.context("captured ELF header is truncated")?;
	if header != *b"\x7fELF" {
		bail!("fixed Ghidra operations accept only captured ELF bytes");
	}
	target.seek(std::io::SeekFrom::Start(0)).await?;
	let bridge = bridge_snapshot(input.request.operation, engine.bridge_revision, deadline).await?;
	let peak = Arc::new(AtomicU64::new(0));
	verify_runtime(&java, &runtime).await?;
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
	verify_runtime(&java, &runtime).await?;
	let version = std::str::from_utf8(&version_out)?
		.lines()
		.next()
		.context("Java version absent")?;
	if !version_status.success()
		|| !version_err.is_empty()
		|| version != input.profile.backend_version
	{
		bail!("Ghidra Java version differs from the admitted profile");
	}
	let mut arguments = vec![
		"-Xmx512m".into(),
		"-XX:MaxMetaspaceSize=256m".into(),
		"-XX:ReservedCodeCacheSize=64m".into(),
		"-XX:CompressedClassSpaceSize=64m".into(),
		"-XX:+UseSerialGC".into(),
		"-XX:ActiveProcessorCount=1".into(),
		"-XX:-UsePerfData".into(),
		"-XX:+DisableAttachMechanism".into(),
		"-Djava.awt.headless=true".into(),
		format!("-Duser.home={}", work.display()),
		format!("-Djava.io.tmpdir={}", work.display()),
		"--class-path".into(),
		installation.classpath.clone(),
		"--source".into(),
		"25".into(),
		format!("/proc/self/fd/{}", bridge.file.as_raw_fd()),
		engine.installation_root.clone(),
		format!("/proc/self/fd/{}", artifact.file.as_raw_fd()),
		input.profile.max_output_bytes.to_string(),
	];
	if input.request.operation != StaticOperation::Inventory {
		arguments.push(ghidra_contract::operation_name(input.request.operation)?.into());
		arguments.push(
			input
				.request
				.function_address
				.clone()
				.unwrap_or_else(|| "-".into()),
		);
	}
	verify_runtime(&java, &runtime).await?;
	verify_installation(&installation, deadline).await?;
	let (stdout, stderr, status) = run_java(
		&java,
		&[bridge.file.as_raw_fd(), artifact.file.as_raw_fd()],
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
	verify_runtime(&java, &runtime).await?;
	verify_installation(&installation, deadline).await?;
	let stdout_text = std::str::from_utf8(&stdout).context("Ghidra stdout is not UTF-8")?;
	let stderr_text = std::str::from_utf8(&stderr).context("Ghidra stderr is not UTF-8")?;
	if status.success() {
		let observation: Value = serde_json::from_str(stdout_text)
			.context("Ghidra bridge omitted its JSON observation")?;
		ghidra_contract::validate_observation(&observation, input, artifact.size)?;
	}
	Ok(json!({
		"schema":"hepta.rea.static-report.v1","request_sha256":sha256(&serde_json::to_vec(input)?),
		"runtime_sha256":input.profile.runtime_sha256,"provider":input.profile.provider,"operation":input.request.operation,
		"backend":{"sha256":input.profile.backend_sha256,"version":version,"size_bytes":java.before.len(),"snapshot":"verified_installed_inode"},
		"ghidra_engine":engine,"bridge_sha256":bridge.sha256,"installation_snapshot":"verified_installed_paths",
		"installation_verified_file_count":installation.files.len(),"installation_verified_bytes":installation.total_bytes,
		"subject":{"selected_path":input.request.artifact_path,"sha256":artifact.sha256,"size_bytes":artifact.size,"snapshot":"sealed_linux_memfd"},
		"backend_success":status.success(),"backend_exit_code":status.code(),"stdout":stdout_text,"stderr":stderr_text,
		"stdout_sha256":sha256(&stdout),"stderr_sha256":sha256(&stderr),"stdout_bytes":stdout.len(),"stderr_bytes":stderr.len(),"output_complete":true,
		"summary":crate::mcp::rea_provider::summary::selected_fields(input.profile.provider,input.request.operation,stdout_text,status.success()),
		"elapsed_ms":started.elapsed().as_millis(),"rea_evidence_compatible":false,
		"coverage":{"scope":"selected_static_backend_operation","status":"partial"},
		"scratch":{"monitored_peak_bytes":peak.load(Ordering::Relaxed),"monitored_limit_bytes":super::MAX_DISK_BYTES,"max_entries":super::MAX_DISK_ENTRIES,"single_file_limit_bytes":16*1024*1024,"poll_interval_ms":250},
		"network_syscalls_denied":true,
		"limitations":[if input.request.operation == StaticOperation::Inventory {
			"Fixed ElfLoader inventory does not perform auto-analysis, decompilation, target execution or project persistence"
		} else {
			"Fixed ELF function analysis is bounded to its declared analyzer profile; decompiled C and cross-references are engine observations, not source-equivalence proofs"
		},
			"Ghidra installation files are hash-checked against a sealed manifest and re-admitted before and after import, but are not sealed execution snapshots",
			"Selected JRE path checks do not attest the complete system shared-library closure; privileged concurrent writers can race observations",
			"Aggregate scratch bytes are sampled every 250 ms rather than enforced by a hard filesystem quota",
			"Durable jobs clean adopted private scratch only after the original process group stops; unknown owner outcomes retain it. Standalone workers have no crash-recovery owner"]
	}))
}

pub(super) async fn analyze(input: WorkerRequest) -> Result<Value> {
	let engine = input
		.profile
		.ghidra_engine
		.as_ref()
		.context("Ghidra profile lacks installation identity")?;
	let started = Instant::now();
	let deadline = started + Duration::from_secs(input.profile.timeout_seconds);
	let work = scratch(&input.profile.working_directory, "ghidra").await?;
	let result = analyze_inner(&input, engine, &work, started, deadline).await;
	let cleanup_owner = work.cleanup_owner();
	let retained_path = work.display().to_string();
	let cleanup = work.finish().await;
	match (result, cleanup) {
		(Ok(mut report), Ok(removed)) => {
			report["scratch"]["removed_after_operation"] = json!(removed);
			report["scratch"]["cleanup_pending"] = json!(!removed);
			report["scratch"]["cleanup_owner"] = json!(cleanup_owner);
			report["native_report_id"] = json!(format!(
				"hepta_rea_static_v1_{}",
				sha256(&serde_json::to_vec(&report)?)
			));
			Ok(report)
		}
		(Err(error), Ok(_)) => Err(error),
		(_, Err(error)) => Err(error)
			.with_context(|| format!("Ghidra scratch cleanup incomplete: {retained_path}")),
	}
}
