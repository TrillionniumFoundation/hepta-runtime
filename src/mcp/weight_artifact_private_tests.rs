// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! An explicitly ignored private test: no checkpoint enters public source or CI.
//! The normal root crate and the canonical owner execute every filesystem effect.

use super::*;

async fn pinned_private_input(pin: &Value) -> Result<Vec<u8>> {
	let path = pin["path"]
		.as_str()
		.ok_or_else(|| anyhow!("private input path missing"))?;
	let metadata = tokio::fs::symlink_metadata(path).await?;
	let size = pin["pin"]["size_bytes"]
		.as_u64()
		.ok_or_else(|| anyhow!("private input size missing"))?;
	if !metadata.is_file()
		|| metadata.file_type().is_symlink()
		|| size > 8 * 1024 * 1024
		|| metadata.len() != size
	{
		bail!("private input is not the bounded pinned file");
	}
	let bytes = tokio::fs::read(path).await?;
	if bytes.len() as u64 != size || pin["pin"]["sha256"] != hex(&Sha256::digest(&bytes)) {
		bail!("private input digest differs");
	}
	Ok(bytes)
}

async fn private_json(path: &Path) -> Result<Value> {
	let metadata = tokio::fs::symlink_metadata(path).await?;
	if !metadata.is_file() || metadata.len() > 1024 * 1024 {
		bail!("bounded result required");
	}
	Ok(serde_json::from_slice(&tokio::fs::read(path).await?)?)
}

async fn save_private_result(path: &Path, value: &Value) -> Result<()> {
	let mut file = tokio::fs::OpenOptions::new()
		.create_new(true)
		.write(true)
		.open(path)
		.await?;
	file.write_all(&serde_json::to_vec_pretty(value)?).await?;
	file.write_all(b"\n").await?;
	file.sync_all().await?;
	tokio::fs::File::open(
		path.parent()
			.ok_or_else(|| anyhow!("result parent missing"))?,
	)
	.await?
	.sync_all()
	.await?;
	Ok(())
}

#[derive(Debug, Serialize)]
struct HelperResult {
	success: bool,
	timed_out: bool,
	reaped: bool,
	exit_code: Option<i32>,
	stdout_sha256: String,
	stderr_sha256: String,
	deadline_milliseconds: u64,
}

async fn bounded_helper(
	helper: &str,
	args: &[String],
	root: &Path,
	name: &str,
	millis: u64,
) -> Result<HelperResult> {
	let stdout_path = root.join(format!("{name}.stdout"));
	let stderr_path = root.join(format!("{name}.stderr"));
	let stdout = tokio::fs::OpenOptions::new()
		.write(true)
		.create_new(true)
		.open(&stdout_path)
		.await?
		.into_std()
		.await;
	let stderr = tokio::fs::OpenOptions::new()
		.write(true)
		.create_new(true)
		.open(&stderr_path)
		.await?
		.into_std()
		.await;
	let mut child = tokio::process::Command::new(helper)
		.args(args)
		.stdin(std::process::Stdio::null())
		.stdout(stdout)
		.stderr(stderr)
		.kill_on_drop(true)
		.spawn()?;
	let (status, timed_out) =
		match tokio::time::timeout(Duration::from_millis(millis), child.wait()).await {
			Ok(status) => (status?, false),
			Err(_) => {
				child.start_kill()?;
				let status = tokio::time::timeout(Duration::from_secs(2), child.wait())
					.await
					.map_err(|_| anyhow!("helper kill/reap deadline exceeded"))??;
				(status, true)
			}
		};
	Ok(HelperResult {
		success: status.success(),
		timed_out,
		reaped: true,
		exit_code: status.code(),
		stdout_sha256: hex(&Sha256::digest(tokio::fs::read(stdout_path).await?)),
		stderr_sha256: hex(&Sha256::digest(tokio::fs::read(stderr_path).await?)),
		deadline_milliseconds: millis,
	})
}

#[tokio::test]
#[ignore = "explicit private source-pinned C fixture and native helper required"]
async fn canonical_f64_private_reject_restores_all_source_bytes() -> Result<()> {
	let case_path = PathBuf::from(std::env::var("HEPTA_PRIVATE_F64_CASE")?);
	let expected_case_sha = std::env::var("HEPTA_PRIVATE_F64_CASE_SHA256")?;
	let output = PathBuf::from(std::env::var("HEPTA_PRIVATE_F64_OUTPUT")?);
	if !case_path.is_absolute() || !output.is_absolute() {
		bail!("absolute private paths required");
	}
	let raw = tokio::fs::read(&case_path).await?;
	if raw.len() > 1024 * 1024 || hex(&Sha256::digest(&raw)) != expected_case_sha {
		bail!("private case identity differs");
	}
	let case: Value = serde_json::from_slice(&raw)?;
	if case["schema"] != "hepta.private-canonical-owner-case.v1"
		|| case["fit"] != 11
		|| case["candidate_id"] != "Q_1"
		|| case["production_admission"] != false
	{
		bail!("only the predeclared private conformance case is allowed");
	}
	let original = pinned_private_input(&case["original_bridge"]).await?;
	let original_json = pinned_private_input(&case["original_json"]).await?;
	let expected_candidate = pinned_private_input(&case["expected_candidate"]).await?;
	pinned_private_input(&case["helper"]).await?;
	let helper = case["helper"]["path"]
		.as_str()
		.ok_or_else(|| anyhow!("helper path missing"))?;
	tokio::fs::create_dir(&output).await?;
	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt;
		tokio::fs::set_permissions(&output, std::fs::Permissions::from_mode(0o700)).await?;
	}
	let mut rows = Vec::new();
	let mut all_passed = true;
	let mut verified_dps = 0;
	for scenario in [
		"forced_rejection_after_conformance",
		"helper_nonzero",
		"helper_timeout",
	] {
		let isolated = output.join(scenario);
		tokio::fs::create_dir(&isolated).await?;
		let source = isolated.join("original.safetensors");
		let state = isolated.join("private-state");
		tokio::fs::write(&source, &original).await?;
		tokio::fs::File::open(&source).await?.sync_all().await?;
		let mut params: PatchTensorParams = serde_json::from_value(case["patch"].clone())?;
		if params.tensor_name != "readout196"
			|| params.edits.len() != 196
			|| params.expected_sha256 != hex(&Sha256::digest(&original))
		{
			bail!("whole F64 readout patch differs");
		}
		params.path = source.to_string_lossy().into_owned();
		let mut wrong = params.clone();
		let first = wrong
			.edits
			.first_mut()
			.ok_or_else(|| anyhow!("missing edit"))?;
		let byte = if first.expected_hex.starts_with('0') {
			"1"
		} else {
			"0"
		};
		first.expected_hex.replace_range(..1, byte);
		assert!(
			apply_with_roots(wrong, std::slice::from_ref(&isolated), &state, None, None)
				.await
				.is_err()
		);
		assert!(tokio::fs::read_dir(store_root(&state).await?)
			.await?
			.next_entry()
			.await?
			.is_none());
		let published =
			apply_with_roots(params, std::slice::from_ref(&isolated), &state, None, None).await?;
		let artifact = PathBuf::from(
			published["artifact_path"]
				.as_str()
				.ok_or_else(|| anyhow!("published path missing"))?,
		);
		let published_bytes = tokio::fs::read(&artifact).await;
		let evaluation_path = isolated.join("NATIVE_EVALUATION.json");
		let evaluate = scenario == "forced_rejection_after_conformance";
		let args = if evaluate {
			vec![
				"evaluate".into(),
				case_path.to_string_lossy().into_owned(),
				expected_case_sha.clone(),
				artifact.to_string_lossy().into_owned(),
				evaluation_path.to_string_lossy().into_owned(),
			]
		} else {
			vec![if scenario == "helper_timeout" {
				"timeout-probe".into()
			} else {
				"reject-probe".into()
			}]
		};
		let deadline = if scenario == "helper_timeout" {
			100
		} else if evaluate {
			15000
		} else {
			5000
		};
		let evaluation = bounded_helper(helper, &args, &isolated, "evaluation", deadline).await;
		// Helper launch/error/nonzero/timeout all reach this canonical restore call.
		// The outer stage leaves reserve for this path; a killed parent is not a recovery proof.
		let restored = restore_with_state(
			published["artifact_id"]
				.as_str()
				.ok_or_else(|| anyhow!("artifact ID missing"))?,
			&state,
		)
		.await?;
		let restored_path = PathBuf::from(
			restored["artifact_path"]
				.as_str()
				.ok_or_else(|| anyhow!("restored path missing"))?,
		);
		let restored_bytes = tokio::fs::read(&restored_path).await?;
		let restore_path = isolated.join("NATIVE_RESTORE.json");
		let args = vec![
			"restored".into(),
			case_path.to_string_lossy().into_owned(),
			expected_case_sha.clone(),
			restored_path.to_string_lossy().into_owned(),
			restore_path.to_string_lossy().into_owned(),
		];
		let restore_check = bounded_helper(helper, &args, &isolated, "restore-check", 5000).await;
		let owner_exact = restored_bytes == original && tokio::fs::read(&source).await? == original;
		let candidate_exact = published_bytes
			.as_ref()
			.is_ok_and(|bytes| *bytes == expected_candidate);
		let helper_expected = evaluation.as_ref().is_ok_and(|r| {
			r.reaped
				&& if evaluate {
					r.success && !r.timed_out
				} else if scenario == "helper_timeout" {
					r.timed_out && !r.success
				} else {
					!r.success && !r.timed_out
				}
		});
		let restore_ok = restore_check
			.as_ref()
			.is_ok_and(|r| r.success && r.reaped && !r.timed_out);
		let eval_json = if evaluate && helper_expected {
			private_json(&evaluation_path).await?
		} else {
			Value::Null
		};
		let restore_json = if restore_ok {
			private_json(&restore_path).await?
		} else {
			Value::Null
		};
		let verified = evaluate
			&& eval_json["status"] == "PASS"
			&& eval_json["full_policy_DPs"] == 1
			&& eval_json["eligible_for_adoption"] == false;
		if verified {
			verified_dps += 1;
		}
		let semantics_ok = (!evaluate || verified)
			&& restore_json["status"] == "PASS"
			&& restore_json["original_bytes_exact"] == true;
		let passed =
			owner_exact && candidate_exact && helper_expected && restore_ok && semantics_ok;
		all_passed &= passed;
		let receipt = json!({"scenario":scenario,"status":if passed {"PASS"} else {"FAILED"},"published":published,"restored":restored,
            "old_byte_mismatch_rejected":true,"candidate_bytes_exact":candidate_exact,"original_bytes_exact":owner_exact,
            "helper":evaluation.as_ref().ok(),"helper_error":evaluation.as_ref().err().map(ToString::to_string),"evaluation":eval_json,"restore_check":restore_json,
            "restore_helper":restore_check.as_ref().ok(),"restore_error":restore_check.as_ref().err().map(ToString::to_string),
            "policy_DPs_reserved":u64::from(evaluate),"policy_DP_requests_attempted":u64::from(evaluate),"policy_DPs_verified":u64::from(verified),
            "actual_policy_DPs":if evaluate && !verified {Value::Null} else {json!(u64::from(evaluate))},"forced_rejection":true,
            "canonical_owner_publications":1,"canonical_owner_restores":1,"private_state_root":state});
		save_private_result(&isolated.join("SCENARIO_RESULT.json"), &receipt).await?;
		rows.push(receipt);
	}
	let receipt = json!({"schema":"hepta.canonical-private-owner-results.v1","status":if all_passed {"PASS"} else {"FAILED"},"case_sha256":expected_case_sha,
        "original_JSON_sha256":hex(&Sha256::digest(&original_json)),"scenarios":rows,"canonical_owner_publications":3,"canonical_owner_restores":3,
        "policy_DPs_reserved":1,"policy_DP_requests_attempted":1,"policy_DPs_verified":verified_dps,"actual_policy_DPs":if verified_dps==1 {json!(1)} else {Value::Null},
        "parent_SIGKILL_recovery_verified":false,"source_is_copy_on_write_and_never_adopted":true,"live_service_calls":0,"production_admission":false,"new_candidate_search":false,"decision":"KEEP_ORIGINAL_AND_STOP"});
	save_private_result(&output.join("OWNER_RESULTS.json"), &receipt).await?;
	assert!(all_passed,"private canonical owner qualification failed after restoration; inspect retained private receipts");
	Ok(())
}

#[path = "weight_artifact_positive_tests.rs"]
mod sufficient_positive;
