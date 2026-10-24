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
	assert!(summary["limits"].get("maximum_tool_result_bytes").is_none());
	assert_eq!(
		summary["limits"]["maximum_summary_host_entries"],
		MAX_HOST_ENTRIES
	);
	assert_eq!(
		summary["limits"]["maximum_summary_response_bytes"],
		MAX_SUMMARY_BYTES
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
	let summary: Value = serde_json::from_str(&encoded).unwrap();
	assert!(summary["limits"].get("maximum_tool_result_bytes").is_none());
	let wire = rmcp::model::CallToolResult::success(vec![rmcp::model::ContentBlock::text(encoded)]);
	assert!(serde_json::to_vec(&wire).unwrap().len() <= MAX_SUMMARY_BYTES);
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
	assert!(bytes <= MAX_SUMMARY_BYTES);
}

#[test]
fn effective_config_cache_reuses_exact_summary_and_returns_independent_strings() {
	let config = config();
	let expected = render_effective_config(Ok(&config)).unwrap();
	let cache = OnceLock::new();
	let mut first =
		cached_effective_config(&cache, || render_effective_config(Ok(&config))).unwrap();
	assert_eq!(first, expected);
	first.clear();
	let next = cached_effective_config(&cache, || panic!("warm summary was recomputed")).unwrap();
	assert_eq!(next, expected);
	assert_eq!(cache.get(), Some(&expected));
}

#[test]
fn effective_config_cache_does_not_retain_failed_validation_or_rendering() {
	let cache = OnceLock::new();
	let mut invalid = config();
	invalid.controller_workspace_roots = vec!["SECRET_RELATIVE_ROOT".into()];
	assert_eq!(
		cached_effective_config(&cache, || render_effective_config(Ok(&invalid)))
			.unwrap_err()
			.to_string(),
		UNAVAILABLE
	);
	assert!(cache.get().is_none());
	let mut oversized = config();
	let template = oversized.hosts["primary"].clone();
	for index in 0..MAX_HOST_ENTRIES {
		oversized
			.hosts
			.insert(format!("extra-{index}"), template.clone());
	}
	assert!(cached_effective_config(&cache, || render_effective_config(Ok(&oversized))).is_err());
	assert!(cache.get().is_none());
	let valid = config();
	assert_eq!(
		cached_effective_config(&cache, || render_effective_config(Ok(&valid))).unwrap(),
		render_effective_config(Ok(&valid)).unwrap()
	);
}

#[test]
fn effective_config_concurrent_first_readers_receive_identical_redacted_output() {
	let config = config();
	let expected = render_effective_config(Ok(&config)).unwrap();
	let cache = OnceLock::new();
	let barrier = std::sync::Barrier::new(8);
	std::thread::scope(|scope| {
		let readers: Vec<_> = (0..8)
			.map(|_| {
				scope.spawn(|| {
					barrier.wait();
					cached_effective_config(&cache, || render_effective_config(Ok(&config)))
						.unwrap()
				})
			})
			.collect();
		for reader in readers {
			assert_eq!(reader.join().unwrap(), expected);
		}
	});
	assert!(!cache.get().unwrap().contains("SECRET_"));
}

fn benchmark_config(host_count: usize, large: bool) -> RuntimeConfig {
	let mut config = config();
	let mut template = config.hosts["primary"].clone();
	if large {
		for index in 0..64 {
			template.allowed_read_path_prefixes.push(format!(
				"/SECRET_READ_ROOT_{index}/{}",
				"private-policy-component/".repeat(8)
			));
		}
		let mut action = template.privileged_actions.values().next().unwrap().clone();
		action.extra_arg_patterns = (0..4)
			.map(|index| format!("SECRET_PRIVATE_{index}_[a-zA-Z0-9_.-]{{1,64}}"))
			.collect();
		for index in 0..4 {
			template
				.privileged_actions
				.insert(format!("private-{index}"), action.clone());
		}
	}
	config.hosts.clear();
	for index in 0..host_count {
		config
			.hosts
			.insert(format!("host-{index:03}"), template.clone());
	}
	config
}

#[test]
#[ignore = "manual immutable-summary CPU microbenchmark; not native HTTP or process-start TPS"]
fn effective_config_cache_microbenchmark_six_and_256_hosts() {
	use std::hint::black_box;
	use std::time::Instant;
	let measure = |iterations: usize, compute: &dyn Fn() -> String| {
		let started = Instant::now();
		for _ in 0..iterations {
			black_box(compute());
		}
		started.elapsed().as_secs_f64() * 1_000_000.0 / iterations as f64
	};
	for (host_count, large) in [(6, false), (6, true), (256, false), (256, true)] {
		let config = benchmark_config(host_count, large);
		let expected = render_effective_config(Ok(&config)).unwrap();
		let cache = OnceLock::new();
		let cold_started = Instant::now();
		assert_eq!(
			cached_effective_config(&cache, || render_effective_config(Ok(&config))).unwrap(),
			expected
		);
		let cold_initialization_us = cold_started.elapsed().as_secs_f64() * 1_000_000.0;
		let old_iterations = if host_count == 256 { 2 } else { 32 };
		let warm_iterations = 4096;
		let old = || render_effective_config(Ok(black_box(&config))).unwrap();
		let warm = || {
			cached_effective_config(black_box(&cache), || render_effective_config(Ok(&config)))
				.unwrap()
		};
		let (mut old_round_us, mut warm_round_us) = (Vec::new(), Vec::new());
		for round in 0..6 {
			if round % 2 == 0 {
				old_round_us.push(measure(old_iterations, &old));
				warm_round_us.push(measure(warm_iterations, &warm));
			} else {
				warm_round_us.push(measure(warm_iterations, &warm));
				old_round_us.push(measure(old_iterations, &old));
			}
		}
		let mut old_sorted = old_round_us.clone();
		let mut warm_sorted = warm_round_us.clone();
		old_sorted.sort_by(f64::total_cmp);
		warm_sorted.sort_by(f64::total_cmp);
		let old_median_us = (old_sorted[2] + old_sorted[3]) / 2.0;
		let warm_median_us = (warm_sorted[2] + warm_sorted[3]) / 2.0;
		println!(
			"{}",
			json!({
				"schema":"hepta-effective-config-cache-microbenchmark/v1",
				"hosts":host_count,"large_configuration":large,
				"serialized_config_bytes":serde_json::to_vec(&config).unwrap().len(),
				"summary_bytes":expected.len(),"cold_initialization_us":cold_initialization_us,
				"old_iterations_per_round":old_iterations,"warm_iterations_per_round":warm_iterations,
				"rounds":6,"old_uncached_median_us":old_median_us,"warm_cache_median_us":warm_median_us,
				"speedup":old_median_us/warm_median_us,"old_uncached_round_us":old_round_us,
				"warm_cache_round_us":warm_round_us,"alternating_order":true,
				"first_round_order":"old_then_warm","measurement":"CPU_only",
				"allocations_measured":false,"native_tps_measured":false
			})
		);
	}
}
