// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Explicit private positive research lifecycle. No production adoption API.

use super::*;

const SUFFICIENT_ACCEPTANCE: &str =
	"6f629b4b45b1ff39f4e62a321fc295d149d9c708ed26405c3b94a2317233b369";
const SUFFICIENT_FITS: [u64; 5] = [11, 23, 37, 53, 71];

async fn positive_case(entry: &Value, output: &Path) -> Result<Value> {
	let fit = entry["fit"]
		.as_u64()
		.ok_or_else(|| anyhow!("fit missing"))?;
	let raw = pinned_private_input(&entry["case"]).await?;
	let case: Value = serde_json::from_slice(&raw)?;
	let case_sha = hex(&Sha256::digest(&raw));
	let case_path = entry["case"]["path"]
		.as_str()
		.ok_or_else(|| anyhow!("case path"))?;
	let candidate_id = format!("SUFFICIENT_QB_{fit}");
	if !SUFFICIENT_FITS.contains(&fit)
		|| entry["candidate_id"] != candidate_id
		|| case["schema"] != "hepta.sufficient-canonical-owner-case.v1"
		|| case["fit"] != fit
		|| case["candidate_id"] != candidate_id
		|| case["value_acceptance_sha256"] != SUFFICIENT_ACCEPTANCE
		|| case["production_admission"] != false
		|| case["new_candidate_search"] != false
		|| case["role"] != "exposed_own_law_development"
	{
		bail!("only genuine fixed sufficient-head identities are allowed");
	}
	let original = pinned_private_input(&case["original_bridge"]).await?;
	let original_json = pinned_private_input(&case["original_json"]).await?;
	let expected = pinned_private_input(&case["expected_candidate"]).await?;
	pinned_private_input(&case["helper"]).await?;
	let helper = case["helper"]["path"]
		.as_str()
		.ok_or_else(|| anyhow!("helper"))?;
	let isolated = output.join(format!("fit_{fit}"));
	tokio::fs::create_dir(&isolated).await?;
	let source = isolated.join("original.safetensors");
	let state = isolated.join("private-state");
	let mut file = tokio::fs::OpenOptions::new()
		.create_new(true)
		.write(true)
		.open(&source)
		.await?;
	file.write_all(&original).await?;
	file.sync_all().await?;
	drop(file);
	let mut params: PatchTensorParams = serde_json::from_value(case["patch"].clone())?;
	if params.tensor_name != "readout196"
		|| params.edits.len() != 196
		|| params.expected_sha256 != hex(&Sha256::digest(&original))
	{
		bail!("exact complete F64 patch required");
	}
	params.path = source.to_string_lossy().into_owned();
	let mut wrong = params.clone();
	let first = wrong
		.edits
		.first_mut()
		.ok_or_else(|| anyhow!("missing edit"))?;
	let replacement = if first.expected_hex.starts_with('0') {
		"1"
	} else {
		"0"
	};
	first.expected_hex.replace_range(..1, replacement);
	if apply_with_roots(wrong, std::slice::from_ref(&isolated), &state, None, None)
		.await
		.is_ok()
	{
		bail!("wrong old bytes unexpectedly admitted");
	}
	if tokio::fs::read_dir(store_root(&state).await?)
		.await?
		.next_entry()
		.await?
		.is_some()
	{
		bail!("old-byte rejection left a partial artifact");
	}
	let published =
		apply_with_roots(params, std::slice::from_ref(&isolated), &state, None, None).await?;
	let artifact_id = published["artifact_id"].as_str().map(str::to_owned);
	let evaluation_path = isolated.join("NATIVE_EVALUATION.json");
	let acceptance_path = isolated.join("RESEARCH_ACCEPTED.json");
	let mut attempted_dp = false;
	let mut helper_result = None;
	// Every fallible operation after publication is captured before canonical restore.
	let acceptance: Result<Value> = async {
		let id = artifact_id.as_deref().ok_or_else(|| anyhow!("published artifact id"))?;
		let artifact = PathBuf::from(published["artifact_path"].as_str().ok_or_else(|| anyhow!("artifact path"))?);
		if published["production_eligible"] != false || published["source_modified"] != false
			|| published["behavior_evaluated"] != false || tokio::fs::read(&artifact).await? != expected
		{
			bail!("canonical artifact scope or exact candidate bytes differ");
		}
		let args = vec!["evaluate-sufficient".into(),case_path.into(),case_sha.clone(),
			artifact.to_string_lossy().into_owned(),evaluation_path.to_string_lossy().into_owned()];
		attempted_dp = true;
		let control = bounded_helper(helper, &args, &isolated, "evaluation", 15000).await?;
		let success = control.success && control.reaped && !control.timed_out;
		helper_result = Some(control);
		if !success { bail!("native sufficient helper failed or exceeded its inner deadline"); }
		let evaluation = private_json(&evaluation_path).await?;
		if evaluation["schema"] != "hepta.sufficient-owner-native-evaluation.v1" || evaluation["status"] != "PASS"
			|| evaluation["fit"] != fit || evaluation["candidate_id"] != candidate_id
			|| evaluation["case_sha256"] != case_sha || evaluation["artifact_sha256"] != published["sha256"]
			|| evaluation["full_policy_DPs"] != 1 || evaluation["full_native_DAGs"] != 1
			|| evaluation["verified_policy_DPs"] != 1 || evaluation["all_fixed_targets_uniquely_matched"] != true
			|| evaluation["eligible_for_production_adoption"] != false
			|| evaluation["new_quality_comparison"] != false
		{
			bail!("independent full-task evaluation is not a complete PASS");
		}
		let (mut retained, before, commitment) = open_pinned_artifact(id, &state).await?;
		let retained_sha = file_hash(&mut retained, before.len()).await?;
		unchanged(&before, &retained.metadata().await?)?;
		if retained_sha != commitment || commitment != hex(&Sha256::digest(&expected)) {
			bail!("persistent canonical artifact changed before acceptance");
		}
		let evaluation_bytes = tokio::fs::read(&evaluation_path).await?;
		let accepted = json!({"schema":"hepta.sufficient-research-acceptance.v1","status":"RESEARCH_ACCEPTED",
			"fit":fit,"candidate_id":candidate_id,"case_sha256":case_sha,"artifact_id":id,
			"artifact_sha256":commitment,"canonical_persistent_artifact_reopened":true,
			"evaluation_sha256":hex(&Sha256::digest(&evaluation_bytes)),"evaluation":evaluation,
			"value_acceptance_sha256":SUFFICIENT_ACCEPTANCE,"production_eligible":false,
			"live_pointer_or_service_modified":false,"source_modified":false,
			"decision":"ACCEPT_FIXED_RESEARCH_ARTIFACT_THEN_EXPLICITLY_RESTORE",
			"role":"controller acceptance of an evaluated immutable canonical artifact; not production adoption"});
		save_private_result(&acceptance_path, &accepted).await?;
		if private_json(&acceptance_path).await? != accepted { bail!("acceptance readback differs"); }
		Ok(accepted)
	}.await;
	let restored = match artifact_id.as_deref() {
		Some(id) => restore_with_state(id, &state).await,
		None => Err(anyhow!(
			"canonical publication omitted artifact id; restoration unverified"
		)),
	};
	let restoration: Result<Value> = async {
		let restored = restored.as_ref().map_err(|e| anyhow!(e.to_string()))?;
		let restored_path = PathBuf::from(
			restored["artifact_path"]
				.as_str()
				.ok_or_else(|| anyhow!("restore path"))?,
		);
		if tokio::fs::read(&restored_path).await? != original
			|| tokio::fs::read(&source).await? != original
		{
			bail!("canonical inverse restore or original source bytes differ");
		}
		let restored_receipt = isolated.join("NATIVE_RESTORE.json");
		let args = vec![
			"restored-sufficient".into(),
			case_path.into(),
			case_sha.clone(),
			restored_path.to_string_lossy().into_owned(),
			restored_receipt.to_string_lossy().into_owned(),
		];
		let control = bounded_helper(helper, &args, &isolated, "restore-check", 5000).await?;
		if !control.success || !control.reaped || control.timed_out {
			bail!("restore helper failed");
		}
		let checked = private_json(&restored_receipt).await?;
		if checked["schema"] != "hepta.sufficient-owner-native-restore.v1"
			|| checked["status"] != "PASS"
			|| checked["original_bytes_exact"] != true
			|| checked["full_policy_DPs"] != 0
			|| checked["restored_JSON_sha256"] != hex(&Sha256::digest(&original_json))
		{
			bail!("original JSON/F64 restore contract failed");
		}
		let artifact = PathBuf::from(
			published["artifact_path"]
				.as_str()
				.ok_or_else(|| anyhow!("published path"))?,
		);
		if tokio::fs::read(artifact).await? != expected {
			bail!("restore changed the immutable candidate artifact");
		}
		Ok(json!({"owner":restored,"helper":control,"check":checked}))
	}
	.await;
	let accepted = acceptance.is_ok();
	let passed = accepted && restoration.is_ok();
	let result = json!({"schema":"hepta.sufficient-private-case-result.v1","status":if passed {"PASS"} else {"FAILED_OR_UNKNOWN"},
		"fit":fit,"candidate_id":candidate_id,"case_sha256":case_sha,"published":published,
		"old_byte_mismatch_rejected":true,"canonical_publications":1,"canonical_restore_attempted":artifact_id.is_some(),
		"canonical_restores_verified":u64::from(restoration.is_ok()),"persistent_research_acceptance_verified":accepted,
		"acceptance":acceptance.as_ref().ok(),"acceptance_error":acceptance.as_ref().err().map(ToString::to_string),
		"restoration":restoration.as_ref().ok(),"restoration_error":restoration.as_ref().err().map(ToString::to_string),
		"evaluation_helper":helper_result,"policy_DPs_reserved":1,"policy_DP_requests_attempted":u64::from(attempted_dp),
		"policy_DPs_verified":u64::from(accepted),"actual_policy_DPs":if accepted {json!(1)} else if attempted_dp {Value::Null} else {json!(0)},
		"parent_SIGKILL_recovery_verified":false,"production_eligible":false,
		"source_is_copy_on_write_and_never_adopted":true,"private_state_root":state});
	save_private_result(&isolated.join("CASE_RESULT.json"), &result).await?;
	Ok(result)
}

#[tokio::test]
#[ignore = "five explicit source-pinned sufficient heads and qualified native helper required"]
async fn canonical_f64_sufficient_heads_accept_then_restore() -> Result<()> {
	let queue_path = PathBuf::from(std::env::var("HEPTA_PRIVATE_D3_QUEUE")?);
	let sha = std::env::var("HEPTA_PRIVATE_D3_QUEUE_SHA256")?;
	let output = PathBuf::from(std::env::var("HEPTA_PRIVATE_D3_OUTPUT")?);
	if !queue_path.is_absolute() || !output.is_absolute() {
		bail!("absolute private paths required");
	}
	let raw = tokio::fs::read(&queue_path).await?;
	if raw.len() > 1024 * 1024 || hex(&Sha256::digest(&raw)) != sha {
		bail!("private queue identity differs");
	}
	let queue: Value = serde_json::from_slice(&raw)?;
	if queue["schema"] != "hepta.sufficient-canonical-owner-queue.v1"
		|| queue["value_acceptance_sha256"] != SUFFICIENT_ACCEPTANCE
		|| queue["production_admission"] != false
		|| queue["new_candidate_search"] != false
	{
		bail!("fixed sufficient queue required");
	}
	let cases = queue["cases"].as_array().ok_or_else(|| anyhow!("cases"))?;
	if cases.iter().map(|c| c["fit"].as_u64()).collect::<Vec<_>>()
		!= SUFFICIENT_FITS.map(Some).to_vec()
	{
		bail!("ordered fixed five-fit queue required");
	}
	tokio::fs::create_dir(&output).await?;
	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt;
		tokio::fs::set_permissions(&output, std::fs::Permissions::from_mode(0o700)).await?;
	}
	let mut rows = Vec::new();
	for entry in cases {
		let result = positive_case(entry, &output).await;
		let passed = result.as_ref().is_ok_and(|v| v["status"] == "PASS");
		rows.push(match result { Ok(value) => value, Err(error) => json!({"fit":entry["fit"],"status":"FAILED_OR_UNKNOWN","error":error.to_string(),"actual_policy_DPs":null}) });
		if !passed {
			break;
		}
	}
	let passed = rows.len() == 5 && rows.iter().all(|v| v["status"] == "PASS");
	let result = json!({"schema":"hepta.sufficient-canonical-owner-results.v1","status":if passed {"PASS"} else {"FAILED_OR_UNKNOWN"},
		"queue_sha256":sha,"cases":rows,"fixed_heads_reserved":5,"full_policy_DPs_reserved":5,
		"actual_policy_DPs":if passed {json!(5)} else {Value::Null},"canonical_mutation_calls":if passed {json!(15)} else {Value::Null},
		"canonical_pinned_read_calls":if passed {json!(5)} else {Value::Null},"successful_persistent_effects":if passed {json!(10)} else {Value::Null},
		"research_acceptances_verified":if passed {json!(5)} else {Value::Null},"production_eligible":false,
		"source_is_copy_on_write_and_never_adopted":true,"parent_SIGKILL_recovery_verified":false,
		"new_candidate_search":false,"independent_confirmation":false,"live_service_calls":0,
		"decision":"RESEARCH_ACCEPTED_ARTIFACTS_RESTORED_KEEP_PRODUCTION_ORIGINAL"});
	save_private_result(&output.join("OWNER_RESULTS.json"), &result).await?;
	if !passed {
		bail!("sufficient private lifecycle incomplete; inspect retained receipts");
	}
	Ok(())
}
