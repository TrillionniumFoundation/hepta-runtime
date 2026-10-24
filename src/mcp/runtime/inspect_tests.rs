// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Pinned-action result retention tests; no actions or sudo privileges are configured.
use super::*;

fn projection_config(hosts: usize) -> super::super::config::RuntimeConfig {
	let entries = (0..hosts)
		.map(|index| {
			(
				format!("host-{index:03}"),
				json!({
					"ssh_target":"private-user@private-target.invalid",
					"remote_state_dir":"/private-state",
					"execution_mode":"operator",
					"allow_execute":true,
					"allow_pty":index % 2 == 0,
					"allow_write":index % 3 == 0,
					"privileged_actions":{"public-action":{
						"executable":"/private-executable", "fixed_args":["private-argument"]
					}}
				}),
			)
		})
		.collect::<serde_json::Map<_, _>>();
	serde_json::from_value(json!({"state_dir":"/private-controller", "hosts":entries})).unwrap()
}

#[test]
fn cached_host_projection_preserves_bytes_and_redaction_across_readers() {
	let config = projection_config(6);
	let expected = render_host_list(&config).unwrap();
	let cache = OnceLock::new();
	std::thread::scope(|scope| {
		for _ in 0..16 {
			let (cache, config, expected) = (&cache, &config, &expected);
			scope.spawn(move || assert_eq!(cached_host_list(cache, config).unwrap(), *expected));
		}
	});
	let mut returned = cached_host_list(&cache, &config).unwrap();
	returned.clear();
	assert_eq!(cached_host_list(&cache, &config).unwrap(), expected);
	assert!(!expected.contains("private-"));
	let decoded: Value = serde_json::from_str(&expected).unwrap();
	assert_eq!(decoded["hosts"].as_array().unwrap().len(), 6);
	assert_eq!(
		decoded["hosts"][0]["privileged_actions"],
		json!(["public-action"])
	);
	assert_eq!(decoded["hosts"][0]["allow_pty"], true);
	assert_eq!(decoded["hosts"][1]["allow_pty"], false);
}

#[test]
#[ignore = "manual isolated immutable host projection CPU microbenchmark; not HTTP TPS"]
fn host_projection_cache_microbenchmark_six_and_256_hosts() {
	use std::hint::black_box;
	use std::time::Instant;
	for hosts in [6, 256] {
		let config = projection_config(hosts);
		let cache = OnceLock::new();
		let expected = render_host_list(&config).unwrap();
		assert_eq!(cached_host_list(&cache, &config).unwrap(), expected);
		let iterations = if hosts == 6 { 1024 } else { 64 };
		for round in 0..6 {
			let mut elapsed = [0u128; 2];
			for index in if round % 2 == 0 { [0, 1] } else { [1, 0] } {
				let started = Instant::now();
				for _ in 0..iterations {
					let text = if index == 0 {
						render_host_list(black_box(&config)).unwrap()
					} else {
						cached_host_list(black_box(&cache), black_box(&config)).unwrap()
					};
					assert_eq!(text.len(), expected.len());
					black_box(text);
				}
				elapsed[index] = started.elapsed().as_nanos();
			}
			println!(
				"HOST_PROJECTION_BENCH {}",
				json!({
					"schema":"hepta-host-projection-cache-microbenchmark/v1",
					"measurement":"CPU_only", "native_tps_measured":false,
					"allocations_measured":false, "hosts":hosts, "round":round,
					"iterations":iterations,"summary_bytes":expected.len(),
					"old_total_ns":elapsed[0],"cached_total_ns":elapsed[1],
					"alternating_order":true
				})
			);
		}
	}
}

fn pinned_ack(code: i32, stdout: &str, stderr: &str) -> Value {
	json!({"exit_code":code,"exit_code_authoritative":true,"process_exit_confirmed":true,
		"stdout":stdout,"stderr":stderr,"timed_out":false,"stdout_truncated":false,
		"stderr_truncated":false,"stdout_bytes_seen":stdout.len(),"stderr_bytes_seen":stderr.len(),
		"capture_error":null,"output_complete":true,"output_limit_bytes_per_stream":524288,
		"descendant_termination_confirmed":false})
}

#[test]
fn pinned_action_completion_audit_failure_preserves_real_exit_and_output_without_retry() {
	for code in [0, 7] {
		let output = json!({"exit_code":code,"stdout":"actual action output","stderr":"actual action diagnostics","timed_out":false});
		let retained = retain_privileged_after_audit(
			output.clone(),
			Err(anyhow::anyhow!("PRIVATE_AUDIT_SECRET")),
		);
		for (key, value) in output.as_object().unwrap() {
			assert_eq!(&retained[key], value);
		}
		assert_eq!(retained["audit_recorded"], false);
		assert_eq!(retained["automatic_retry"], false);
		assert!(!retained.to_string().contains("PRIVATE_AUDIT_SECRET"));
	}
	let retained = retain_privileged_after_audit(json!({"exit_code":0,"stdout":"ok"}), Ok(()));
	assert_eq!(retained["audit_recorded"], true);
	assert!(retained.get("audit_warning").is_none());
}

#[test]
fn pinned_action_intent_unknown_ack_and_wire_limits_fail_closed_without_raw_diagnostics() {
	let params: PrivilegedActionParams = serde_json::from_value(
		json!({"host":"main","action":"owned-fixture","idempotency_key":"owned-fixture-key","args":[]}),
	)
	.unwrap();
	assert!(
		require_privileged_intent(Err(anyhow::anyhow!("SECRET_PATH")))
			.unwrap_err()
			.to_string()
			.contains("no action request dispatched")
	);
	for remote in [
		Err(anyhow::anyhow!("RAW_SECRET")),
		Ok(Value::Null),
		Ok(json!("RAW_SECRET")),
		Ok(json!({"exit_code":0,"stdout":"x","stderr":""})),
	] {
		let result = retain_privileged_outcome(&params, remote);
		assert_eq!(result["outcome"], "unknown");
		assert_eq!(result["automatic_retry"], false);
		assert!(!result.to_string().contains("SECRET"));
	}
	let result = retain_privileged_after_audit(Value::Null, Ok(()));
	assert_eq!(result["outcome"], "unknown");
	let normal124 = retain_privileged_outcome(&params, Ok(pinned_ack(124, "", "")));
	assert_eq!(normal124["exit_code"], 124);
	assert_eq!(normal124["timed_out"], false);
	let mut with_extra = pinned_ack(0, "ok", "");
	with_extra["untrusted_extra"] = json!("ACK_SECRET");
	let filtered = retain_privileged_outcome(&params, Ok(with_extra));
	assert_eq!(filtered["host"], "main");
	assert_eq!(filtered["action"], "owned-fixture");
	assert!(!filtered.to_string().contains("ACK_SECRET"));
	for field in [
		"stdout_truncated",
		"process_exit_confirmed",
		"descendant_termination_confirmed",
		"exit_code_authoritative",
	] {
		let mut malformed = pinned_ack(0, "", "");
		malformed[field] = json!("MALFORMED_SECRET");
		assert_eq!(
			retain_privileged_outcome(&params, Ok(malformed))["outcome"],
			"unknown"
		);
	}
	let mut false_timeout = pinned_ack(0, "", "");
	false_timeout["timed_out"] = json!(true);
	assert_eq!(
		retain_privileged_outcome(&params, Ok(false_timeout))["outcome"],
		"unknown"
	);
	let controlled = retain_privileged_outcome(
		&params,
		Ok(pinned_ack(
			0,
			&"\u{1}".repeat(524288),
			&"\u{1}".repeat(524288),
		)),
	);
	assert_eq!(controlled["exit_code"], 0);
	let oversized = retain_privileged_outcome(&params, Ok(pinned_ack(0, &"x".repeat(524289), "")));
	assert_eq!(oversized["outcome"], "unknown");
}
