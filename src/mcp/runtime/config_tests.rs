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
