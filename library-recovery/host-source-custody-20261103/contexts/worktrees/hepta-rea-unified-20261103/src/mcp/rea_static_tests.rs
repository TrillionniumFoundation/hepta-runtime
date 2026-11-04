// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Actual Linux snapshot immutability and owned-artifact backend checks.

use super::linux::*;
use crate::mcp::rea_provider::{
	sha256, ReaStaticProfile, ReaStaticRequest, StaticOperation, StaticProvider, WorkerRequest,
};
use std::os::fd::AsRawFd;
use std::path::Path;
use std::time::Duration;
use tokio::time::Instant;

#[tokio::test]
async fn snapshot_binds_bytes_and_kernel_seals_prevent_changes() {
	let dir = tempfile::tempdir().unwrap();
	let path = dir.path().join("owned.o");
	tokio::fs::write(&path, b"owned artifact bytes")
		.await
		.unwrap();
	let file = tokio::fs::File::open(&path).await.unwrap();
	let sealed = snapshot(
		file,
		&sha256(b"owned artifact bytes"),
		1024,
		false,
		Instant::now() + Duration::from_secs(5),
	)
	.await
	.unwrap();
	assert_eq!(sealed.size, 20);
	let byte = b'x';
	let result =
		unsafe { libc::pwrite(sealed.file.as_raw_fd(), (&byte as *const u8).cast(), 1, 0) };
	assert_eq!(result, -1);
	assert_eq!(
		std::io::Error::last_os_error().raw_os_error(),
		Some(libc::EPERM)
	);
	tokio::fs::write(&path, b"later source revision")
		.await
		.unwrap();
	let preserved = tokio::fs::read(format!("/proc/self/fd/{}", sealed.file.as_raw_fd()))
		.await
		.unwrap();
	assert_eq!(preserved, b"owned artifact bytes");
	let file = tokio::fs::File::open(&path).await.unwrap();
	assert!(snapshot(
		file,
		&sha256(b"owned artifact bytes"),
		1024,
		false,
		Instant::now() + Duration::from_secs(5)
	)
	.await
	.is_err());
}

#[tokio::test]
async fn snapshot_refuses_oversized_sources() {
	let dir = tempfile::tempdir().unwrap();
	let path = dir.path().join("big");
	tokio::fs::write(&path, [0u8; 17]).await.unwrap();
	let file = tokio::fs::File::open(&path).await.unwrap();
	assert!(snapshot(
		file,
		&sha256(&[0u8; 17]),
		16,
		false,
		Instant::now() + Duration::from_secs(5)
	)
	.await
	.is_err());
}

#[test]
fn artifact_descriptor_admission_refuses_symlink_file_and_parent() {
	use std::os::unix::fs::symlink;
	let dir = tempfile::tempdir().unwrap();
	let inside = dir.path().join("inside");
	let outside = dir.path().join("outside");
	std::fs::create_dir(&inside).unwrap();
	std::fs::create_dir(&outside).unwrap();
	std::fs::write(outside.join("data"), b"private").unwrap();
	symlink(outside.join("data"), inside.join("link")).unwrap();
	symlink(&outside, inside.join("parent")).unwrap();
	let roots = vec![inside.to_string_lossy().to_string()];
	assert!(open_artifact(&inside.join("link"), &roots).is_err());
	assert!(open_artifact(&inside.join("parent/data"), &roots).is_err());
	assert!(open_artifact(&outside.join("data"), &roots).is_err());
	std::fs::write(inside.join("normal"), b"owned").unwrap();
	assert!(open_artifact(&inside.join("normal"), &roots).is_ok());
}

async fn installed_snapshot(path: &str) -> Snapshot {
	let content = tokio::fs::read(path).await.unwrap();
	snapshot(
		tokio::fs::File::open(path).await.unwrap(),
		&sha256(&content),
		64 * 1024 * 1024,
		true,
		Instant::now() + Duration::from_secs(10),
	)
	.await
	.unwrap()
}

#[tokio::test]
#[ignore = "requires installed GNU readelf on an owned Linux host; run explicitly"]
async fn real_gnu_readelf_inspects_own_test_binary_without_executing_it() {
	let backend_path = "/usr/bin/readelf";
	let backend = installed_snapshot(backend_path).await;
	let (version, errors, status) = run_bounded(
		&backend,
		&["--version".into()],
		None,
		8192,
		Instant::now() + Duration::from_secs(10),
	)
	.await
	.unwrap();
	assert!(status.success());
	assert!(errors.is_empty());
	let version = String::from_utf8(version)
		.unwrap()
		.lines()
		.next()
		.unwrap()
		.to_owned();
	let dir = tempfile::tempdir().unwrap();
	let artifact_path = dir.path().join("owned-test-build.elf");
	let own = tokio::fs::read("/proc/self/exe").await.unwrap();
	let hash = sha256(&own);
	tokio::fs::write(&artifact_path, &own).await.unwrap();
	drop(own);
	let profile = ReaStaticProfile {
		host: "owned".into(),
		runtime_executable: std::env::current_exe()
			.unwrap()
			.to_string_lossy()
			.to_string(),
		runtime_sha256: hash.clone(),
		provider: StaticProvider::GnuReadelf,
		backend_executable: backend_path.into(),
		backend_sha256: backend.sha256,
		backend_version: version,
		working_directory: dir.path().to_string_lossy().to_string(),
		input_roots: vec![dir.path().to_string_lossy().to_string()],
		allowed_operations: vec![StaticOperation::Headers],
		max_artifact_bytes: 256 * 1024 * 1024,
		max_output_bytes: 32 * 1024,
		timeout_seconds: 60,
		memory_max_bytes: 1024 * 1024 * 1024,
	};
	let profile_sha256 = sha256(&serde_json::to_vec(&profile).unwrap());
	let input = WorkerRequest {
		schema: "hepta.rea.static-request.v1".into(),
		profile,
		request: ReaStaticRequest {
			profile: "owned".into(),
			profile_sha256,
			idempotency_key: "own-test-build".into(),
			operation: StaticOperation::Headers,
			artifact_path: artifact_path.to_string_lossy().to_string(),
			artifact_sha256: hash.clone(),
		},
		protected_roots: vec![],
	};
	let report = analyze(input.clone()).await.unwrap();
	assert_eq!(report["backend_success"], true);
	assert!(report["stdout"].as_str().unwrap().contains("ELF Header"));
	assert_eq!(report["subject"]["sha256"], hash);
	assert_eq!(report["rea_evidence_compatible"], false);
	let mut bad = input;
	bad.profile.backend_version.push_str(" mismatch");
	bad.request.profile_sha256 = sha256(&serde_json::to_vec(&bad.profile).unwrap());
	assert!(analyze(bad).await.is_err());
	assert!(Path::new(&artifact_path).exists());
}

#[tokio::test]
#[ignore = "requires installed GNU yes/sleep on an owned Linux host; run explicitly"]
async fn real_backend_output_and_deadline_are_bounded_and_reaped() {
	let yes = installed_snapshot("/usr/bin/yes").await;
	assert!(run_bounded(
		&yes,
		&[],
		None,
		1024,
		Instant::now() + Duration::from_secs(2)
	)
	.await
	.unwrap_err()
	.to_string()
	.contains("output bound"));
	let sleep = installed_snapshot("/usr/bin/sleep").await;
	let start = Instant::now();
	assert!(run_bounded(
		&sleep,
		&["10".into()],
		None,
		1024,
		start + Duration::from_millis(50)
	)
	.await
	.unwrap_err()
	.to_string()
	.contains("deadline"));
	assert!(start.elapsed() < Duration::from_secs(3));
}
