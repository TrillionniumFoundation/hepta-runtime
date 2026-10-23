// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Pure configuration/serialization fixtures: no global runtime, filesystem or SSH.
use super::super::config::RuntimeConfig;
use super::*;
use rmcp::model::ContentBlock;
use std::collections::BTreeMap;

fn legacy_policy_binding<T: Serialize + ?Sized>(config: &T) -> Result<String> {
	let mut hash = Sha256::new();
	hash.update(b"hepta-runtime/result-policy/v1\0");
	hash.update(serde_json::to_vec(config)?);
	Ok(hash.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

fn config_fixture(hosts: usize, large: bool) -> RuntimeConfig {
	let paths: Vec<_> = (0..if large { 64 } else { 1 })
		.map(|index| {
			format!(
				"/private/政策/{index:03}/{}",
				if large {
					"long-root-component/".repeat(8)
				} else {
					"short".into()
				}
			)
		})
		.collect();
	let actions = if large {
		json!({"inspect": {
			"executable":"/usr/bin/true","fixed_args":["quote=\"; tab=\t; 中文"],
			"allow_extra_args":false,"extra_arg_patterns":[],"timeout_seconds":30
		}})
	} else {
		json!({})
	};
	let hosts: BTreeMap<_, _> = (0..hosts)
		.map(|index| {
			(
				format!("synthetic-policy-{index:03}"),
				json!({
					"ssh_target":format!("synthetic-policy-{index:03}.invalid"),
					"remote_state_dir":format!("/private/remote/{index:03}"),
					"platform":"linux","execution_mode":"isolated",
					"allowed_read_path_prefixes":paths,
					"privileged_actions":actions
				}),
			)
		})
		.collect();
	let config: RuntimeConfig = serde_json::from_value(json!({
		"state_dir":"/private/runtime","controller_workspace_roots":[],"hosts":hosts
	}))
	.unwrap();
	config.validate().unwrap();
	config
}

#[test]
fn policy_digest_keeps_original_domain_and_complete_configuration_bytes() {
	let golden = json!({"state_dir":"/private/runtime","controller_workspace_roots":[],"hosts":{}});
	assert_eq!(
		policy_binding_for(&golden).unwrap(),
		"5537a781186889d877c0a0b0e42008162505bf2c7479af60dd14bb45747afdf7"
	);
	for (host_count, large) in [(6, false), (6, true), (256, false), (256, true)] {
		let config = config_fixture(host_count, large);
		let expected = legacy_policy_binding(&config).unwrap();
		assert_eq!(policy_binding_for(&config).unwrap(), expected);
		let cache = OnceLock::new();
		assert_eq!(
			cached_policy_binding(&cache, || policy_binding_for(&config)).unwrap(),
			expected
		);
		assert_eq!(cache.get(), Some(&expected));
		// The full original digest still binds changes outside the host identity.
		let mut changed = config.clone();
		changed
			.hosts
			.values_mut()
			.next()
			.unwrap()
			.allowed_read_path_prefixes
			.push("/private/additional-root".into());
		assert_ne!(policy_binding_for(&changed).unwrap(), expected);
	}
}

struct RefusedPolicy;

impl Serialize for RefusedPolicy {
	fn serialize<S>(&self, _serializer: S) -> std::result::Result<S::Ok, S::Error>
	where
		S: serde::Serializer,
	{
		Err(serde::ser::Error::custom(
			"synthetic_policy_serialization_failure",
		))
	}
}

#[test]
fn policy_cache_retains_only_success_and_retries_after_serialization_failure() {
	let cache = OnceLock::new();
	let error = cached_policy_binding(&cache, || policy_binding_for(&RefusedPolicy)).unwrap_err();
	assert!(error
		.to_string()
		.contains("synthetic_policy_serialization_failure"));
	assert!(cache.get().is_none());
	let config = config_fixture(6, false);
	let expected = legacy_policy_binding(&config).unwrap();
	assert_eq!(
		cached_policy_binding(&cache, || policy_binding_for(&config)).unwrap(),
		expected
	);
	// A warm successful cell neither repeats serialization nor returns later errors.
	assert_eq!(
		cached_policy_binding(&cache, || policy_binding_for(&RefusedPolicy)).unwrap(),
		expected
	);
}

#[test]
fn concurrent_warm_policy_cache_uses_the_same_full_digest_without_recomputing() {
	use std::sync::{
		atomic::{AtomicUsize, Ordering},
		Barrier,
	};
	let cache = Arc::new(OnceLock::new());
	let computations = Arc::new(AtomicUsize::new(0));
	let config = config_fixture(6, true);
	let expected = legacy_policy_binding(&config).unwrap();
	assert_eq!(
		cached_policy_binding(&cache, || {
			computations.fetch_add(1, Ordering::SeqCst);
			policy_binding_for(&config)
		})
		.unwrap(),
		expected
	);
	let barrier = Arc::new(Barrier::new(9));
	let workers: Vec<_> = (0..8)
		.map(|_| {
			let (cache, computations, barrier, expected) = (
				cache.clone(),
				computations.clone(),
				barrier.clone(),
				expected.clone(),
			);
			std::thread::spawn(move || {
				barrier.wait();
				for _ in 0..128 {
					assert_eq!(
						cached_policy_binding(&cache, || {
							computations.fetch_add(1, Ordering::SeqCst);
							Err(anyhow!("warm cache must not recompute policy"))
						})
						.unwrap(),
						expected
					);
				}
			})
		})
		.collect();
	barrier.wait();
	for worker in workers {
		worker.join().unwrap();
	}
	assert_eq!(computations.load(Ordering::SeqCst), 1);
	assert_eq!(cache.get(), Some(&expected));
}

#[test]
fn counted_final_preview_matches_old_bytes_at_every_retention_wire_cap() {
	for (tool, cap) in [
		("effective_config", 256 * 1024),
		("request_result", 64 * 1024),
	] {
		let id = "a".repeat(64);
		let prefix = "中文\"\\\n\t\u{0000}";
		let response = |padding| {
			let mut result: std::result::Result<CallToolResponse, ErrorData> =
				Ok(CallToolResult::success(vec![ContentBlock::text(format!(
					"{prefix}{}",
					"x".repeat(padding)
				))])
				.into());
			attach_identity(&mut result, &id);
			result
		};
		let mut empty = response(0);
		attach_ack(&mut empty, "durability_unknown_not_dispatched", false);
		let overhead = match empty {
			Ok(CallToolResponse::Complete(value)) => serde_json::to_vec(&value).unwrap().len(),
			_ => unreachable!(),
		};
		for target in [cap - 1, cap, cap + 1] {
			let mut result = response(target - overhead);
			let original = result.clone();
			let mut preview = original.clone();
			attach_ack(&mut preview, "durability_unknown_not_dispatched", false);
			let value = match &preview {
				Ok(CallToolResponse::Complete(value)) => value,
				_ => unreachable!(),
			};
			assert_eq!(serde_json::to_vec(value).unwrap().len(), target);
			assert_eq!(serialized_json_size(value).unwrap(), target);
			reserve_final_wire(&mut result, tool, &id);
			if target <= cap {
				// Counting never changes the original result or inserts its preview ACK.
				match (&result, &original) {
					(
						Ok(CallToolResponse::Complete(actual)),
						Ok(CallToolResponse::Complete(expected)),
					) => {
						assert_eq!(
							serde_json::to_vec(actual).unwrap(),
							serde_json::to_vec(expected).unwrap()
						);
					}
					_ => panic!("within-cap original response must remain complete"),
				}
			} else {
				let error = result.unwrap_err();
				assert!(error.message.contains("exceeds final wire budget"));
				assert_eq!(error.data.unwrap()[ID_META]["request_id"], id);
			}
		}
	}
}

#[test]
#[ignore = "manual isolated immutable-policy CPU microbenchmark; no native HTTP or storage"]
fn immutable_policy_cache_microbenchmark_six_and_256_hosts() {
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
		let config = config_fixture(host_count, large);
		let config_bytes = serde_json::to_vec(&config).unwrap().len();
		let expected = legacy_policy_binding(&config).unwrap();
		let cache = OnceLock::new();
		let cold_started = Instant::now();
		assert_eq!(
			cached_policy_binding(&cache, || policy_binding_for(&config)).unwrap(),
			expected
		);
		let cold_init_us = cold_started.elapsed().as_secs_f64() * 1_000_000.0;
		let old_iterations = if large && host_count == 256 {
			8
		} else if large {
			32
		} else {
			256
		};
		let warm_iterations = 65_536;
		let old = || legacy_policy_binding(black_box(&config)).unwrap();
		let warm =
			|| cached_policy_binding(black_box(&cache), || policy_binding_for(&config)).unwrap();
		let (mut old_us, mut warm_us) = (Vec::new(), Vec::new());
		for round in 0..6 {
			if round % 2 == 0 {
				old_us.push(measure(old_iterations, &old));
				warm_us.push(measure(warm_iterations, &warm));
			} else {
				warm_us.push(measure(warm_iterations, &warm));
				old_us.push(measure(old_iterations, &old));
			}
		}
		let old_round_us = old_us.clone();
		let warm_round_us = warm_us.clone();
		old_us.sort_by(f64::total_cmp);
		warm_us.sort_by(f64::total_cmp);
		let old_median_us = (old_us[2] + old_us[3]) / 2.0;
		let warm_median_us = (warm_us[2] + warm_us[3]) / 2.0;
		println!(
			"{}",
			json!({
				"schema":"hepta-immutable-policy-cache-microbenchmark/v1",
				"hosts":host_count,"large_configuration":large,"serialized_config_bytes":config_bytes,
				"old_iterations_per_round":old_iterations,"warm_iterations_per_round":warm_iterations,"rounds":6,
				"cold_initialization_us":cold_init_us,"old_uncached_median_us":old_median_us,
				"warm_cache_median_us":warm_median_us,"speedup":old_median_us / warm_median_us,
				"old_uncached_round_us":old_round_us,"warm_cache_round_us":warm_round_us,
				"first_round_order":"old_then_warm","alternating_order":true,
				"measurement":"CPU_only","allocations_measured":false,"native_tps_measured":false
			})
		);
	}
}
