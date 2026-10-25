// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Execute only the directory guard in temporary fixtures; no SSH or workloads.
use super::*;
use std::os::unix::fs::{symlink, PermissionsExt};

fn probe(path: &std::path::Path, create: bool) -> std::process::Output {
	std::process::Command::new("python3")
		.arg("-c")
		.arg(format!("{PRIVATE_DIRECTORY_CODE}\nimport sys\nos.umask(0o002)\nprivate_job_directory(sys.argv[1], create={})\n", if create { "True" } else { "False" }))
		.arg(path)
		.output().unwrap()
}

#[test]
fn new_state_jobs_and_job_are_private_under_a_group_writable_umask() {
	let temporary = tempfile::Builder::new()
		.tempdir_in(std::env::temp_dir().canonicalize().unwrap())
		.unwrap();
	let path = temporary.path().join("dedicated/jobs/job-id");
	let output = probe(&path, true);
	assert!(
		output.status.success(),
		"{}",
		String::from_utf8_lossy(&output.stderr)
	);
	for path in [
		&path,
		&path.parent().unwrap().to_path_buf(),
		&path.parent().unwrap().parent().unwrap().to_path_buf(),
	] {
		assert_eq!(
			std::fs::metadata(path).unwrap().permissions().mode() & 0o7777,
			0o700
		);
	}
	assert!(probe(&path, false).status.success());
}

#[test]
fn shared_0755_ancestors_remain_unchanged_while_state_jobs_and_job_are_private() {
	use std::os::unix::fs::MetadataExt;
	let temporary = tempfile::Builder::new()
		.tempdir_in(std::env::temp_dir().canonicalize().unwrap())
		.unwrap();
	let shared = temporary.path().join("shared-parent");
	std::fs::create_dir(&shared).unwrap();
	std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o755)).unwrap();
	let original = std::fs::metadata(&shared).unwrap();
	let path = shared.join("dedicated/jobs/job-id");
	for create in [true, false, true] {
		let output = probe(&path, create);
		assert!(
			output.status.success(),
			"{}",
			String::from_utf8_lossy(&output.stderr)
		);
	}
	let actual = std::fs::metadata(&shared).unwrap();
	assert_eq!(
		(actual.dev(), actual.ino(), actual.uid(), actual.mode()),
		(
			original.dev(),
			original.ino(),
			original.uid(),
			original.mode()
		)
	);
	assert_eq!(actual.mode() & 0o7777, 0o755);
	for directory in [
		shared.join("dedicated"),
		shared.join("dedicated/jobs"),
		path,
	] {
		let info = std::fs::metadata(directory).unwrap();
		assert!(info.is_dir());
		assert_eq!(info.uid(), unsafe { libc::geteuid() });
		assert_eq!(info.mode() & 0o7777, 0o700);
	}
}

#[cfg(target_os = "linux")]
#[test]
fn existing_private_jobs_below_execute_only_shared_ancestor_remain_accessible() {
	assert_ne!(
		unsafe { libc::geteuid() },
		0,
		"permission regression requires an unprivileged user"
	);
	let temporary = tempfile::Builder::new()
		.tempdir_in(std::env::temp_dir().canonicalize().unwrap())
		.unwrap();
	let shared = temporary.path().join("execute-only-parent");
	std::fs::create_dir(&shared).unwrap();
	let path = shared.join("dedicated/jobs/job-id");
	assert!(probe(&path, true).status.success());
	std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o100)).unwrap();
	let existing = probe(&path, false);
	let create = probe(&path, true);
	let mode = std::fs::metadata(&shared).unwrap().permissions().mode() & 0o7777;
	std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o700)).unwrap();
	assert_eq!(mode, 0o100);
	for output in [existing, create] {
		assert!(
			output.status.success(),
			"{}",
			String::from_utf8_lossy(&output.stderr)
		);
	}
	for directory in [
		shared.join("dedicated"),
		shared.join("dedicated/jobs"),
		path,
	] {
		assert_eq!(
			std::fs::metadata(directory).unwrap().permissions().mode() & 0o7777,
			0o700
		);
	}
}

#[cfg(target_os = "linux")]
#[test]
fn unreadable_shared_ancestor_refuses_missing_state_before_any_creation() {
	assert_ne!(
		unsafe { libc::geteuid() },
		0,
		"permission regression requires an unprivileged user"
	);
	for expected_mode in [0o100, 0o300] {
		let temporary = tempfile::Builder::new()
			.tempdir_in(std::env::temp_dir().canonicalize().unwrap())
			.unwrap();
		let shared = temporary.path().join("unreadable-parent");
		std::fs::create_dir(&shared).unwrap();
		std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(expected_mode)).unwrap();
		let output = probe(&shared.join("dedicated/jobs/job-id"), true);
		let observed = std::fs::metadata(&shared);
		std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o700)).unwrap();
		assert!(!output.status.success(), "parent mode {expected_mode:o}");
		assert_eq!(
			observed.unwrap().permissions().mode() & 0o7777,
			expected_mode
		);
		assert_eq!(std::fs::read_dir(&shared).unwrap().count(), 0);
	}
}

#[cfg(target_os = "linux")]
#[test]
fn shared_ancestor_without_search_permission_refuses_existing_private_jobs() {
	assert_ne!(
		unsafe { libc::geteuid() },
		0,
		"permission regression requires an unprivileged user"
	);
	let temporary = tempfile::Builder::new()
		.tempdir_in(std::env::temp_dir().canonicalize().unwrap())
		.unwrap();
	let shared = temporary.path().join("unsearchable-parent");
	std::fs::create_dir(&shared).unwrap();
	let path = shared.join("dedicated/jobs/job-id");
	assert!(probe(&path, true).status.success());
	std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o000)).unwrap();
	let existing = probe(&path, false);
	let create = probe(&path, true);
	let mode = std::fs::metadata(&shared).unwrap().permissions().mode() & 0o7777;
	std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o700)).unwrap();
	assert!(!existing.status.success());
	assert!(!create.status.success());
	assert_eq!(mode, 0o000);
	assert!(path.is_dir());
	assert_eq!(std::fs::read_dir(path).unwrap().count(), 0);
}

#[test]
fn existing_unsafe_parent_is_refused_without_chmod_or_job_creation() {
	for component in ["dedicated", "dedicated/jobs"] {
		let temporary = tempfile::Builder::new()
			.tempdir_in(std::env::temp_dir().canonicalize().unwrap())
			.unwrap();
		let parent = temporary.path().join(component);
		std::fs::create_dir_all(&parent).unwrap();
		std::fs::set_permissions(
			temporary.path().join("dedicated"),
			std::fs::Permissions::from_mode(0o700),
		)
		.unwrap();
		std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o775)).unwrap();
		let path = temporary.path().join("dedicated/jobs/job-id");
		assert!(!probe(&path, true).status.success());
		assert_eq!(
			std::fs::metadata(parent).unwrap().permissions().mode() & 0o7777,
			0o775
		);
		assert!(!path.exists());
	}
}

#[test]
fn symlinked_parent_or_job_never_redirects_creation_to_another_directory() {
	for component in ["dedicated", "dedicated/jobs", "dedicated/jobs/job-id"] {
		let temporary = tempfile::Builder::new()
			.tempdir_in(std::env::temp_dir().canonicalize().unwrap())
			.unwrap();
		let outside = temporary.path().join("outside");
		std::fs::create_dir(&outside).unwrap();
		let link = temporary.path().join(component);
		std::fs::create_dir_all(link.parent().unwrap()).unwrap();
		for parent in [
			temporary.path().join("dedicated"),
			temporary.path().join("dedicated/jobs"),
		] {
			if parent.exists() {
				std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700)).unwrap();
			}
		}
		symlink(&outside, &link).unwrap();
		assert!(
			!probe(&temporary.path().join("dedicated/jobs/job-id"), true)
				.status
				.success()
		);
		assert_eq!(std::fs::read_dir(outside).unwrap().count(), 0);
	}
}

#[test]
fn a_same_owner_private_replacement_cannot_inherit_the_original_launch() {
	use std::os::unix::fs::MetadataExt;
	let temporary = tempfile::Builder::new()
		.tempdir_in(std::env::temp_dir().canonicalize().unwrap())
		.unwrap();
	let path = temporary.path().join("dedicated/jobs/job-id");
	assert!(probe(&path, true).status.success());
	let metadata = std::fs::metadata(&path).unwrap();
	let binding = json!({"device":metadata.dev(),"inode":metadata.ino()});
	std::fs::rename(&path, path.with_file_name("held-original")).unwrap();
	std::fs::create_dir(&path).unwrap();
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
	let output = std::process::Command::new("python3").arg("-c")
		.arg(format!("{PRIVATE_DIRECTORY_CODE}\nimport sys,json\nprivate_bound_job_directory(sys.argv[1],json.loads(sys.argv[2]))\n"))
		.arg(&path).arg(binding.to_string()).output().unwrap();
	assert!(!output.status.success());
	assert!(String::from_utf8_lossy(&output.stderr).contains("identity changed"));
	assert_eq!(std::fs::read_dir(&path).unwrap().count(), 0);
}

#[test]
fn generated_launcher_and_inline_supervisor_keep_bound_stdin_and_original_output() {
	use std::io::Write;
	use std::os::unix::fs::MetadataExt;
	use std::process::{Command, Stdio};
	let temporary = tempfile::Builder::new()
		.tempdir_in(std::env::temp_dir().canonicalize().unwrap())
		.unwrap();
	let job = temporary.path().join("private-state/jobs/fixture");
	let request = json!({"job_id":"fixture","job_dir":job,"unit":"never-submit-fixture",
		"request_fingerprint":"fixture-digest","platform":"macos","execution_mode":"operator",
		"executable":"/bin/cat","args":[],"env":{},"stdin":"original fixture input\n",
		"timeout_seconds":5,"allow_detached_fallback":false});
	// The outer helper's platform branch refuses both launchers. This creates
	// its actual request/runner artifacts without ever submitting a user unit.
	let mut child = Command::new("python3")
		.args(["-I", "-S", "-c"])
		.arg(private_remote_code(START_CODE).unwrap())
		.current_dir(temporary.path())
		.stdin(Stdio::piped())
		.stdout(Stdio::piped())
		.stderr(Stdio::piped())
		.spawn()
		.unwrap();
	child
		.stdin
		.take()
		.unwrap()
		.write_all(&serde_json::to_vec(&request).unwrap())
		.unwrap();
	let refused = child.wait_with_output().unwrap();
	assert!(!refused.status.success());
	assert!(!job.join("owner-intent.json").exists());
	let stored: Value =
		serde_json::from_slice(&std::fs::read(job.join("request.json")).unwrap()).unwrap();
	let metadata = std::fs::metadata(&job).unwrap();
	let mut binding = json!({"device":metadata.dev(),"inode":metadata.ino(),"job_id":"fixture",
		"launch_nonce":stored["launch_nonce"],"request_fingerprint":"fixture-digest"});
	let runner = std::fs::read_to_string(job.join("runner.py")).unwrap();
	binding["inode"] = json!(metadata.ino().wrapping_add(1));
	let invalid = Command::new("python3")
		.args(["-I", "-S", "-c"])
		.arg(&runner)
		.arg(&job)
		.arg(binding.to_string())
		.output()
		.unwrap();
	assert!(!invalid.status.success());
	assert!(!job.join("owner-intent.json").exists());
	binding["inode"] = json!(metadata.ino());
	// Exercise the exact trusted inline source, with a tiny fixture process.
	let output = Command::new("python3")
		.args(["-I", "-S", "-c"])
		.arg(runner)
		.arg(&job)
		.arg(binding.to_string())
		.output()
		.unwrap();
	assert!(
		output.status.success(),
		"{}",
		String::from_utf8_lossy(&output.stderr)
	);
	assert_eq!(
		std::fs::read(job.join("stdout.log")).unwrap(),
		b"original fixture input\n"
	);
	let exit: Value =
		serde_json::from_slice(&std::fs::read(job.join("exit.json")).unwrap()).unwrap();
	assert_eq!(exit["exit_code"], 0);
	assert_eq!(exit["output_complete"], true);
}
