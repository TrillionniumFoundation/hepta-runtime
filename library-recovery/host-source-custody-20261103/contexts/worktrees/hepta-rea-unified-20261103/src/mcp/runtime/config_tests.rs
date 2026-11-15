// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Regression tests for config.
use super::*;

fn digest_fixture() -> RuntimeConfig {
	serde_json::from_value(serde_json::json!({
		"state_dir":"/synthetic/state",
		"controller_workspace_roots":["/synthetic/workspace"],
		"hosts":{"fixture":{
			"ssh_target":"synthetic-alias",
			"remote_state_dir":"/synthetic/remote",
			"allowed_read_path_prefixes":["/synthetic/read", "/synthetic/中文'\""],
			"privileged_actions":{"inspect":{
				"executable":"/usr/bin/true", "fixed_args":["a b"], "allow_extra_args":true,
				"extra_arg_patterns":["[a-z]+"], "timeout_seconds":17
			}}
		}}
	}))
	.unwrap()
}

#[test]
fn disabled_analysis_extensions_preserve_the_existing_runtime_policy_identity() {
	#[derive(serde::Serialize)]
	struct BeforeAnalysisExtensions<'a> {
		state_dir: &'a PathBuf,
		controller_workspace_roots: &'a Vec<PathBuf>,
		hosts: &'a BTreeMap<String, HostConfig>,
	}
	let config = digest_fixture();
	let original = BeforeAnalysisExtensions {
		state_dir: &config.state_dir,
		controller_workspace_roots: &config.controller_workspace_roots,
		hosts: &config.hosts,
	};
	assert_eq!(
		serde_json::to_vec(&config).unwrap(),
		serde_json::to_vec(&original).unwrap(),
		"disabled analysis must not revoke existing native job observations"
	);
}

#[test]
fn installed_policy_digest_matches_full_json_and_never_reuses_another_config() {
	use sha2::Digest;
	let original = digest_fixture();
	let installed = InstalledRuntimeConfig::new(original.clone());
	assert!(installed.policy_digest.get().is_none());
	let expected: [u8; 32] = sha2::Sha256::digest(serde_json::to_vec(&original).unwrap()).into();
	assert_eq!(installed.policy_digest().unwrap(), expected);
	let mut variants = Vec::new();
	let mut changed = original.clone();
	changed.state_dir = "/synthetic/other-state".into();
	variants.push(changed);
	let mut changed = original.clone();
	changed
		.controller_workspace_roots
		.push("/other-root".into());
	variants.push(changed);
	let mut changed = original.clone();
	changed.hosts.get_mut("fixture").unwrap().ssh_target = "other-alias".into();
	variants.push(changed);
	let mut changed = original.clone();
	changed.hosts.get_mut("fixture").unwrap().execution_mode = ExecutionMode::Operator;
	variants.push(changed);
	let mut changed = original.clone();
	changed
		.hosts
		.get_mut("fixture")
		.unwrap()
		.allowed_read_path_prefixes
		.push("/another-read-root".into());
	variants.push(changed);
	let mut changed = original;
	changed
		.hosts
		.get_mut("fixture")
		.unwrap()
		.privileged_actions
		.get_mut("inspect")
		.unwrap()
		.timeout_seconds += 1;
	variants.push(changed);
	for value in variants {
		let reference: [u8; 32] = sha2::Sha256::digest(serde_json::to_vec(&value).unwrap()).into();
		assert_ne!(reference, expected);
		let other = InstalledRuntimeConfig::new(value);
		assert_eq!(other.policy_digest().unwrap(), reference);
		assert_eq!(other.policy_digest().unwrap(), reference);
		assert_eq!(installed.policy_digest().unwrap(), expected);
	}
}

#[cfg(unix)]
#[test]
fn installed_policy_serialization_failure_stays_deferred_to_digest_requests() {
	use std::os::unix::ffi::OsStringExt;
	let mut config = digest_fixture();
	config.state_dir = PathBuf::from(OsString::from_vec(b"/synthetic/non-utf8-\xff".to_vec()));
	let expected = serde_json::to_vec(&config).unwrap_err().to_string();
	let installed = InstalledRuntimeConfig::new(config.clone());
	assert_eq!(installed.config.state_dir, config.state_dir);
	assert!(installed.policy_digest.get().is_none());
	for _ in 0..2 {
		assert_eq!(installed.policy_digest().unwrap_err().to_string(), expected);
	}
	assert!(installed.policy_digest.get().unwrap().is_err());
}

#[test]
fn installed_policy_digest_binds_normalized_config_and_rejects_reinstallation() {
	let qualified = concat!(module_path!(), "::installed_policy_digest_child_probe");
	let test_name = qualified.split_once("::").unwrap().1;
	let output = std::process::Command::new(std::env::current_exe().unwrap())
		.arg("--exact")
		.arg(test_name)
		.arg("--nocapture")
		.env("HEPTA_POLICY_DIGEST_CHILD", "1")
		.output()
		.unwrap();
	assert!(
		output.status.success(),
		"stdout: {} stderr: {}",
		String::from_utf8_lossy(&output.stdout),
		String::from_utf8_lossy(&output.stderr)
	);
	assert!(
		String::from_utf8_lossy(&output.stdout).contains("installed-policy-digest-child-verified")
	);
}

#[test]
fn installed_policy_digest_child_probe() {
	use sha2::Digest;
	if std::env::var_os("HEPTA_POLICY_DIGEST_CHILD").is_none() {
		return;
	}
	assert!(runtime_config().is_err());
	assert!(runtime_policy_digest().is_err());
	assert!(maybe_runtime_config().is_none());
	let root = tempfile::tempdir().unwrap();
	let mut config = digest_fixture();
	config.state_dir = root.path().join("normalization/../state");
	let unnormalized: [u8; 32] = sha2::Sha256::digest(serde_json::to_vec(&config).unwrap()).into();
	init_runtime(config).unwrap();
	let actual = runtime_config().unwrap();
	assert_eq!(
		actual.state_dir,
		std::fs::canonicalize(root.path().join("state")).unwrap()
	);
	assert!(std::ptr::eq(actual, maybe_runtime_config().unwrap()));
	let expected: [u8; 32] = sha2::Sha256::digest(serde_json::to_vec(actual).unwrap()).into();
	assert_ne!(expected, unnormalized);
	assert_eq!(runtime_policy_digest().unwrap(), expected);
	let mut rejected = digest_fixture();
	rejected.state_dir = root.path().join("rejected-second-state");
	assert!(init_runtime(rejected).is_err());
	assert!(std::ptr::eq(actual, runtime_config().unwrap()));
	assert_eq!(runtime_policy_digest().unwrap(), expected);
	println!("installed-policy-digest-child-verified");
}

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
