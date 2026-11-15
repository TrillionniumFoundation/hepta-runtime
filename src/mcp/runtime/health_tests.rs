// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Adversarial tests for configured-host reachability and redacted failures.
use super::*;
use serde_json::json;

fn host(target: &str) -> HostConfig {
	serde_json::from_value(json!({
		"ssh_target": target,
		"remote_state_dir": "/tmp/hepta-health-test",
		"allow_execute": false,
		"allow_write": false,
		"allow_pty": false
	}))
	.unwrap()
}

fn command(code: &str) -> Command {
	let mut result = Command::new("/bin/sh");
	result.args(["-c", code]);
	result
}

#[test]
fn health_only_accepts_exact_configured_host_names() {
	let config: RuntimeConfig = serde_json::from_value(json!({
		"state_dir": "/tmp/hepta-health-state",
		"hosts": {"main": host("private-user@private-destination")}
	}))
	.unwrap();
	assert_eq!(
		configured_host(&config, "main").unwrap().ssh_target,
		"private-user@private-destination"
	);
	for supplied in [
		"private-user@private-destination",
		"127.0.0.1",
		"main; id",
		"--help",
		"main\n",
	] {
		let error = configured_host(&config, supplied).unwrap_err().to_string();
		assert_eq!(error, "unknown host; call host_list for configured names");
		assert!(!error.contains(supplied));
	}
}

#[test]
fn health_schema_rejects_targets_commands_and_timeout_overrides() {
	for extra in [
		"ssh_target",
		"address",
		"command",
		"timeout_seconds",
		"allow_execute",
	] {
		let mut value = json!({"host": "main"});
		value[extra] = json!("caller-controlled");
		assert!(serde_json::from_value::<HostHealthParams>(value).is_err());
	}
}

#[test]
fn health_pins_ssh_identity_command_and_read_only_options() {
	let host = host("administrator-alias");
	let command = probe_command(&host);
	let args: Vec<_> = command
		.as_std()
		.get_args()
		.map(|s| s.to_str().unwrap())
		.collect();
	assert_eq!(
		&args[args.len() - 3..],
		&["--", "administrator-alias", PROBE_COMMAND]
	);
	for option in [
		"BatchMode=yes",
		"StrictHostKeyChecking=yes",
		"ForwardAgent=no",
		"ClearAllForwardings=yes",
		"PermitLocalCommand=no",
		"RemoteCommand=none",
		"RequestTTY=no",
	] {
		assert!(args.contains(&option));
	}
	assert!(!host.allow_execute && !host.allow_write && !host.allow_pty);
}

#[tokio::test]
async fn health_requires_exact_authenticated_success_response() {
	assert_eq!(
		probe(command(PROBE_COMMAND), Duration::from_secs(1)).await,
		ProbeStatus::Healthy
	);
	assert_eq!(
		probe(
			command("printf 'hepta-host-health-v1\\n'; exit 255"),
			Duration::from_secs(1)
		)
		.await,
		ProbeStatus::SshFailed
	);
	assert_eq!(
		probe(command("printf 'other-service\\n'"), Duration::from_secs(1)).await,
		ProbeStatus::InvalidResponse
	);
}

#[tokio::test]
async fn health_failures_never_emit_stderr_destinations_or_credentials() {
	let status = probe(
		command("printf 'private-user@private-destination secret-token key-path' >&2; exit 255"),
		Duration::from_secs(1),
	)
	.await;
	assert_eq!(status, ProbeStatus::SshFailed);
	let encoded = serde_json::to_string(&status).unwrap();
	assert_eq!(encoded, "\"ssh_failed\"");
	assert!(!encoded.contains("private") && !encoded.contains("secret"));
	let mut missing = Command::new("/nonexistent/private-user/secret-key/ssh");
	missing.arg("private-destination");
	assert_eq!(
		probe(missing, Duration::from_secs(1)).await,
		ProbeStatus::TransportError
	);
}

#[tokio::test]
async fn health_deadline_is_bounded_and_reaps_its_child() {
	let directory = tempfile::tempdir().unwrap();
	let pid_file = directory.path().join("probe.pid");
	let fixture = format!(
		"printf '%s' \"$$\" > {}; exec sleep 5",
		super::super::ssh::shell_quote(pid_file.to_str().unwrap())
	);
	let started = Instant::now();
	assert_eq!(
		probe(command(&fixture), Duration::from_millis(200)).await,
		ProbeStatus::Timeout
	);
	assert!(started.elapsed() < Duration::from_secs(1));
	let pid: i32 = tokio::fs::read_to_string(pid_file)
		.await
		.unwrap()
		.parse()
		.unwrap();
	assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
	assert_eq!(
		std::io::Error::last_os_error().raw_os_error(),
		Some(libc::ESRCH)
	);
}

#[tokio::test]
async fn health_caps_untrusted_login_output() {
	assert_eq!(
		probe(command("printf '%300s' ''"), Duration::from_secs(1)).await,
		ProbeStatus::InvalidResponse
	);
	assert_eq!(
		probe(
			command("exec yes confidential-banner"),
			Duration::from_secs(1)
		)
		.await,
		ProbeStatus::SshFailed
	);
}
