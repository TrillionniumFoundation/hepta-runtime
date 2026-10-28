// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Regression tests for config.
use super::*;

#[test]
fn names_are_strict() {
	assert!(valid_name("rog-1.example"));
	assert!(!valid_name("rog/1"));
	assert!(!valid_name(&"-".repeat(129)));
}

#[test]
fn basename_is_stable() {
	assert_eq!(executable_basename("/usr/bin/systemctl"), "systemctl");
	assert_eq!(executable_basename("python3"), "python3");
}

#[test]
fn privileged_regexes_are_full_match_capable() {
	let regex = Regex::new(r"\A(?:[a-z0-9_-]+)\z").unwrap();
	assert!(regex.is_match("profile-1"));
	assert!(!regex.is_match("profile-1;id"));
}

#[test]
fn operator_mode_is_explicit_and_unknown_modes_fail() {
	let value = serde_json::json!({"ssh_target":"test","remote_state_dir":"/tmp/jobs"});
	let host: HostConfig = serde_json::from_value(value.clone()).unwrap();
	assert_eq!(host.execution_mode, ExecutionMode::Isolated);
	let mut bad = value;
	bad["execution_mode"] = "unrestriced".into();
	assert!(serde_json::from_value::<HostConfig>(bad).is_err());
}

#[test]
fn operator_allows_shell_sudo_and_signals_but_keeps_structural_checks() {
	let mut host: HostConfig = serde_json::from_value(serde_json::json!({"ssh_target":"test","remote_state_dir":"/tmp/jobs","allow_execute":true,"allow_pty":true})).unwrap();
	for executable in ["/bin/bash", "/usr/bin/sudo", "/bin/kill", "/usr/bin/ssh"] {
		assert!(validate_execution("test", &host, executable, &[], None, false).is_err());
	}
	host.execution_mode = ExecutionMode::Operator;
	for executable in ["/bin/bash", "/usr/bin/sudo", "/bin/kill", "/usr/bin/ssh"] {
		assert!(validate_execution(
			"test",
			&host,
			executable,
			&["arbitrary ; | > 中文".into()],
			Some("/tmp"),
			false
		)
		.is_ok());
	}
	assert!(validate_execution(
		"test",
		&host,
		"/bin/bash",
		&["bad\0arg".into()],
		None,
		false
	)
	.is_err());
	assert!(validate_execution("test", &host, "bash", &[], None, false).is_err());
	assert!(validate_execution("test", &host, "/bin/bash", &[], Some("/tmp\0bad"), false).is_err());
	host.allow_pty = false;
	assert!(validate_execution("test", &host, "/bin/bash", &[], None, true).is_err());
}

#[test]
fn operator_config_cannot_pretend_to_be_sandboxed() {
	let mut config: RuntimeConfig = serde_json::from_value(serde_json::json!({"hosts":{"test":{"ssh_target":"test","remote_state_dir":"/tmp/jobs","execution_mode":"operator","allow_execute":true,"allow_job_network":true}}})).unwrap();
	assert!(config.validate().is_ok());
	config
		.hosts
		.get_mut("test")
		.unwrap()
		.protected_path_prefixes
		.push("/private".into());
	assert!(config.validate().is_err());
	config
		.hosts
		.get_mut("test")
		.unwrap()
		.protected_path_prefixes
		.clear();
	config.hosts.get_mut("test").unwrap().allow_job_network = false;
	assert!(config.validate().is_err());
}

#[test]
fn checkpoint_config_is_pinned_and_opt_in_linux_operator_only() {
	let mut c: RuntimeConfig=serde_json::from_value(serde_json::json!({"hosts":{"test":{"ssh_target":"test","remote_state_dir":"/tmp/state","execution_mode":"operator","allow_execute":true,"allow_job_network":true}}})).unwrap();
	assert!(c.validate().is_ok());
	c.hosts.get_mut("test").unwrap().checkpoint_binary = Some("/usr/local/bin/criu".into());
	assert!(c.validate().is_err());
	c.hosts.get_mut("test").unwrap().checkpoint_binary_sha256 = Some("a".repeat(64));
	assert!(c.validate().is_ok());
	c.hosts.get_mut("test").unwrap().platform = Platform::Macos;
	assert!(c.validate().is_err());
	c.hosts.get_mut("test").unwrap().platform = Platform::Linux;
	c.hosts.get_mut("test").unwrap().checkpoint_binary = Some("/tmp/../criu".into());
	assert!(c.validate().is_err());
}

#[test]
fn directory_move_does_not_relocate_configured_roots_or_ancestors() {
	let fixture = tempfile::tempdir().unwrap();
	let a = fixture.path().join("workspace-a");
	let b = fixture.path().join("workspace-b");
	let ancestor = b.join("parent");
	let nested = ancestor.join("protected-workspace");
	let ordinary = b.join("ordinary");
	std::fs::create_dir(&a).unwrap();
	std::fs::create_dir_all(&nested).unwrap();
	std::fs::create_dir(&ordinary).unwrap();
	let roots = vec![a.clone(), b.clone(), nested.clone()];
	assert!(check_directory_move_against_roots(&a, &roots).is_err());
	assert!(check_directory_move_against_roots(&b, &roots).is_err());
	assert!(check_directory_move_against_roots(&ancestor, &roots).is_err());
	assert!(check_directory_move_against_roots(&nested, &roots).is_err());
	assert!(check_directory_move_against_roots(&ordinary, &roots).is_ok());
	assert!(check_directory_move_against_roots(&b.join("missing"), &roots).is_err());
}

#[test]
fn separate_controllers_cannot_claim_same_state_directory() {
	let dir = tempfile::tempdir().unwrap();
	let first = claim_controller_state_dir(dir.path()).unwrap();
	assert!(claim_controller_state_dir(dir.path()).is_err());
	drop(first);
	let recovered = claim_controller_state_dir(dir.path()).unwrap();
	drop(recovered);
}

#[test]
fn controller_owner_is_fenced_across_processes() {
	let dir = tempfile::tempdir().unwrap();
	let probe = |expected: &str| {
		let output = std::process::Command::new(std::env::current_exe().unwrap())
			.arg("controller_owner_child_probe")
			.env("HEPTA_OWNER_TEST_DIR", dir.path())
			.env("HEPTA_OWNER_TEST_EXPECT", expected)
			.output()
			.unwrap();
		assert!(
			output.status.success(),
			"stdout: {} stderr: {}",
			String::from_utf8_lossy(&output.stdout),
			String::from_utf8_lossy(&output.stderr)
		);
	};
	let first = claim_controller_state_dir(dir.path()).unwrap();
	probe("denied");
	drop(first);
	probe("acquired");
}

#[test]
fn controller_owner_child_probe() {
	let Some(directory) = std::env::var_os("HEPTA_OWNER_TEST_DIR") else {
		return;
	};
	let expected = std::env::var("HEPTA_OWNER_TEST_EXPECT").unwrap();
	let result = claim_controller_state_dir(Path::new(&directory));
	assert_eq!(result.is_ok(), expected == "acquired");
}

#[cfg(unix)]
#[test]
fn permissive_owner_lock_is_rejected() {
	use std::os::unix::fs::PermissionsExt;
	let dir = tempfile::tempdir().unwrap();
	let path = dir.path().join("controller.owner.lock");
	std::fs::write(&path, b"").unwrap();
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
	assert!(claim_controller_state_dir(dir.path()).is_err());
}

#[cfg(unix)]
#[test]
fn owner_lock_refuses_symlinked_lockfile() {
	let dir = tempfile::tempdir().unwrap();
	let target = dir.path().join("redirect");
	std::fs::write(&target, b"do not change").unwrap();
	std::os::unix::fs::symlink(&target, dir.path().join("controller.owner.lock")).unwrap();
	assert!(claim_controller_state_dir(dir.path()).is_err());
	assert_eq!(std::fs::read(&target).unwrap(), b"do not change");
}

#[cfg(unix)]
#[test]
fn a20_legacy_controller_lock_also_excludes_the_combined_owner() {
	use std::os::fd::AsRawFd;
	use std::os::unix::fs::OpenOptionsExt;
	let dir = tempfile::tempdir().unwrap();
	let legacy = std::fs::OpenOptions::new()
		.read(true)
		.write(true)
		.create_new(true)
		.mode(0o600)
		.open(dir.path().join("controller.lock"))
		.unwrap();
	assert_eq!(
		unsafe { libc::flock(legacy.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
		0
	);
	assert!(claim_controller_state_dir(dir.path()).is_err());
	drop(legacy);
	let owner = claim_controller_state_dir(dir.path()).unwrap();
	drop(owner);
}

#[cfg(unix)]
#[test]
fn legacy_controller_lock_never_follows_symlink_or_hardlink() {
	let dir = tempfile::tempdir().unwrap();
	let target = dir.path().join("untouched");
	std::fs::write(&target, b"not a lock").unwrap();
	let path = dir.path().join("controller.lock");
	std::os::unix::fs::symlink(&target, &path).unwrap();
	assert!(claim_controller_state_dir(dir.path()).is_err());
	std::fs::remove_file(&path).unwrap();
	std::fs::hard_link(&target, &path).unwrap();
	assert!(claim_controller_state_dir(dir.path()).is_err());
	assert_eq!(std::fs::read(target).unwrap(), b"not a lock");
}
