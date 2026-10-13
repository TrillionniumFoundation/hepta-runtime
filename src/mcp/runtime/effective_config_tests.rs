// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Allowlist, hidden-policy noninterference and fail-closed configuration tests.
use super::*;
use serde_json::{json, Value};

fn config() -> RuntimeConfig {
	serde_json::from_value(json!({
		"state_dir": "/SECRET_CONTROLLER_STATE",
		"controller_workspace_roots": ["/SECRET_CONTROLLER_ROOT"],
		"hosts": {
			"primary": {
				"ssh_target": "SECRET_SSH_USER@SECRET_SSH_TARGET",
				"remote_state_dir": "/SECRET_REMOTE_STATE",
				"platform": "linux", "execution_mode": "isolated",
				"allow_execute": true, "allow_pty": false, "allow_write": true,
				"allow_job_network": false, "allow_detached_fallback": false,
				"allowed_cwd_prefixes": ["/SECRET_CWD_ROOT"],
				"allowed_read_path_prefixes": ["/SECRET_READ_ROOT_A", "/SECRET_READ_ROOT_B"],
				"allowed_write_path_prefixes": ["/SECRET_WRITE_ROOT"],
				"protected_path_prefixes": ["/SECRET_PROTECTED_PATH"],
				"protected_argument_substrings": ["SECRET_ARGUMENT_VALUE"],
				"denied_executables": ["SECRET_DENIED_EXECUTABLE"],
				"allowed_dangerous_executables": ["SECRET_ALLOWED_EXECUTABLE"],
				"privileged_actions": {"SECRET_ACTION_NAME": {
					"executable": "/SECRET_PRIVILEGED_EXECUTABLE",
					"fixed_args": ["SECRET_CREDENTIAL_ARGUMENT"],
					"allow_extra_args": true,
					"extra_arg_patterns": ["SECRET_PRIVATE_REGEX"],
					"timeout_seconds": 45
				}}
			},
			"gpu": {
				"ssh_target": "SECRET_GPU_TARGET",
				"remote_state_dir": "/SECRET_GPU_STATE",
				"execution_mode": "operator", "platform": "linux",
				"allow_execute": true, "allow_pty": true, "allow_write": false,
				"allow_job_network": true, "allow_detached_fallback": true,
				"allowed_write_path_prefixes": ["/SECRET_INACTIVE_WRITE_ROOT"],
				"checkpoint_binary": "/SECRET_CHECKPOINT_BINARY",
				"checkpoint_binary_sha256": "0000000000000000000000000000000000000000000000000000000000000000"
			}
		}
	}))
	.unwrap()
}

fn result(config: &RuntimeConfig) -> Value {
	serde_json::from_str(&render_effective_config(Ok(config)).unwrap()).unwrap()
}

#[test]
fn effective_config_parameters_accept_only_empty_object() {
	assert!(serde_json::from_value::<EffectiveConfigParams>(json!({})).is_ok());
	for name in [
		"host",
		"path",
		"policy",
		"env",
		"include_secrets",
		"fingerprint",
		"write",
	] {
		let mut params = json!({});
		params[name] = json!("SECRET_INPUT");
		assert!(serde_json::from_value::<EffectiveConfigParams>(params).is_err());
	}
	let schema = serde_json::to_value(schemars::schema_for!(EffectiveConfigParams)).unwrap();
	assert_eq!(schema["additionalProperties"], false);
	if let Some(properties) = schema.get("properties") {
		assert!(properties.as_object().unwrap().is_empty());
	}
}

#[test]
fn effective_config_preserves_flags_counts_and_alias_order() {
	let config = config();
	config.validate().unwrap();
	let summary = result(&config);
	assert_eq!(summary["schema"], "hepta-effective-config-v1");
	assert_eq!(summary["controller"]["workspace_root_count"], 1);
	assert_eq!(summary["hosts"][0]["alias"], "gpu");
	assert_eq!(summary["hosts"][1]["alias"], "primary");
	let gpu = &summary["hosts"][0];
	assert_eq!(gpu["platform"], "linux");
	assert_eq!(gpu["execution_mode"], "operator");
	assert_eq!(gpu["permissions"]["allow_execute"], true);
	assert_eq!(gpu["permissions"]["allow_write"], false);
	assert_eq!(gpu["file_api"]["write_root_count"], 1);
	assert_eq!(
		gpu["file_api"]["write_paths_authorized_and_configured"],
		false
	);
	assert_eq!(gpu["checkpoint_pin_configured"], true);
	let primary = &summary["hosts"][1];
	assert_eq!(primary["file_api"]["read_root_count"], 2);
	assert_eq!(
		primary["file_api"]["write_paths_authorized_and_configured"],
		true
	);
	assert_eq!(primary["named_privileged_action_count"], 1);
	assert_eq!(summary["policy_mutation_supported"], false);
	assert_eq!(summary["target_probe_performed"], false);
	assert_eq!(
		summary["limits"]["maximum_tool_result_bytes"],
		MAX_RESULT_BYTES
	);
}

#[test]
fn effective_config_never_serializes_secret_fields_or_policy_digests() {
	let config = config();
	let encoded = render_effective_config(Ok(&config)).unwrap();
	assert!(!encoded.contains("SECRET_"));
	assert!(!encoded.contains("0000000000000000000000000000000000000000000000000000000000000000"));
	for forbidden in [
		"ssh_target",
		"remote_state_dir",
		"state_dir",
		"controller_workspace_roots",
		"allowed_cwd_prefixes",
		"protected_path_prefixes",
		"protected_argument_substrings",
		"denied_executables",
		"allowed_dangerous_executables",
		"fixed_args",
		"extra_arg_patterns",
		"checkpoint_binary",
		"sha256",
		"fingerprint",
	] {
		assert!(
			!encoded.contains(forbidden),
			"unexpected serialized field {forbidden}"
		);
	}
	let summary: Value = serde_json::from_str(&encoded).unwrap();
	let keys: std::collections::BTreeSet<_> = summary
		.as_object()
		.unwrap()
		.keys()
		.map(String::as_str)
		.collect();
	assert_eq!(
		keys,
		[
			"schema",
			"scope",
			"semantics",
			"redaction",
			"policy_mutation_supported",
			"target_probe_performed",
			"controller",
			"hosts",
			"limits"
		]
		.into_iter()
		.collect()
	);
}

#[test]
fn effective_config_has_no_hidden_policy_or_secret_hash_oracle() {
	let original = config();
	let before = render_effective_config(Ok(&original)).unwrap();
	let mut changed = original.clone();
	changed.state_dir = "/DIFFERENT_SECRET_STATE".into();
	changed.controller_workspace_roots[0] = "/DIFFERENT_SECRET_ROOT".into();
	for host in changed.hosts.values_mut() {
		host.ssh_target = "DIFFERENT_USER@DIFFERENT_TARGET".into();
		host.remote_state_dir = "/DIFFERENT_REMOTE_STATE".into();
		for root in host
			.allowed_read_path_prefixes
			.iter_mut()
			.chain(host.allowed_write_path_prefixes.iter_mut())
			.chain(host.allowed_cwd_prefixes.iter_mut())
			.chain(host.protected_path_prefixes.iter_mut())
		{
			*root = "/DIFFERENT_PRIVATE_ROOT".into();
		}
		if host.checkpoint_binary.is_some() {
			host.checkpoint_binary = Some("/DIFFERENT_CHECKPOINT".into());
			host.checkpoint_binary_sha256 = Some("1".repeat(64));
		}
		for action in host.privileged_actions.values_mut() {
			action.executable = "/DIFFERENT_EXECUTABLE".into();
			action.fixed_args = vec!["DIFFERENT_SECRET_ARGUMENT".into()];
			action.extra_arg_patterns = vec!["DIFFERENT_REGEX".into()];
		}
	}
	changed.validate().unwrap();
	assert_eq!(before, render_effective_config(Ok(&changed)).unwrap());
}

#[test]
fn effective_config_hides_retrieval_and_validation_failure_details() {
	let error = render_effective_config(Err(anyhow!(
		"cannot open /SECRET_CONFIG_PATH; SECRET_TOKEN; SECRET_USER@SECRET_TARGET"
	)))
	.unwrap_err();
	assert_eq!(error.to_string(), UNAVAILABLE);
	assert!(!format!("{error:?}").contains("SECRET_"));
	let mut invalid = config();
	invalid.controller_workspace_roots = vec!["SECRET_INVALID_RELATIVE_ROOT".into()];
	let error = render_effective_config(Ok(&invalid)).unwrap_err();
	assert_eq!(error.to_string(), UNAVAILABLE);
	assert!(!format!("{error:?}").contains("SECRET_"));
}

#[test]
fn effective_config_empty_roots_never_claim_file_access_or_policy_grants() {
	let mut config = config();
	config.controller_workspace_roots.clear();
	for host in config.hosts.values_mut() {
		host.allowed_read_path_prefixes.clear();
		host.allowed_write_path_prefixes.clear();
	}
	let summary = result(&config);
	assert_eq!(
		summary["controller"]["file_workspace_roots_configured"],
		false
	);
	for host in summary["hosts"].as_array().unwrap() {
		assert_eq!(host["file_api"]["read_paths_configured"], false);
		assert_eq!(
			host["file_api"]["write_paths_authorized_and_configured"],
			false
		);
	}
}

#[test]
fn effective_config_bounds_host_count_and_serialized_response() {
	let mut config = config();
	let template = config.hosts["primary"].clone();
	config.hosts.clear();
	for i in 0..MAX_HOST_ENTRIES {
		config
			.hosts
			.insert(format!("host-{i:03}-{}", "a".repeat(119)), template.clone());
	}
	let encoded = render_effective_config(Ok(&config)).unwrap();
	assert!(encoded.len() <= MAX_SUMMARY_BYTES && encoded.len() <= MAX_RESULT_BYTES);
	config.hosts.insert("one-more-host".into(), template);
	let error = render_effective_config(Ok(&config))
		.unwrap_err()
		.to_string();
	assert_eq!(
		error,
		"effective configuration exceeds the bounded host summary limit"
	);
}

#[test]
fn effective_config_bounds_the_actual_mcp_wire_envelope() {
	let mut config = config();
	let host = config.hosts.values().next().unwrap().clone();
	config.hosts.clear();
	for index in 0..MAX_HOST_ENTRIES {
		config
			.hosts
			.insert(format!("host_{index:03}_{}", "a".repeat(40)), host.clone());
	}
	let text = render_effective_config(Ok(&config)).unwrap();
	let wire =
		rmcp::model::CallToolResult::success(vec![rmcp::model::ContentBlock::text(text.clone())]);
	let bytes = serde_json::to_vec(&wire).unwrap().len();
	assert!(bytes > text.len());
	assert!(bytes <= MAX_SUMMARY_BYTES.min(MAX_RESULT_BYTES));
}
