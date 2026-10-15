// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Batch validation and escaped response ceilings are independent of host execution.
use super::*;

fn params(paths: Vec<String>) -> MultiReadParams {
	MultiReadParams {
		host: "main".into(),
		paths,
		max_file_bytes: None,
		max_response_bytes: None,
	}
}

#[test]
fn schema_rejects_hidden_authority_and_requires_host_paths() {
	for extra in ["root", "ssh_target", "sudo", "command", "offset"] {
		let mut value = json!({"host":"main","paths":["/tmp/a"]});
		value[extra] = json!("attacker");
		assert!(serde_json::from_value::<MultiReadParams>(value).is_err());
	}
	assert!(serde_json::from_value::<MultiReadParams>(json!({"paths":["/tmp/a"]})).is_err());
	assert!(serde_json::from_value::<MultiReadParams>(json!({"host":"main"})).is_err());
}

#[test]
fn count_paths_and_budgets_are_strict() {
	assert!(validate(&params(vec![])).is_err());
	assert!(validate(&params((0..17).map(|i| format!("/tmp/{i}")).collect())).is_err());
	assert!(validate(&params(vec!["/tmp/a".into(); 2])).is_err());
	for path in [
		"relative",
		"/",
		"/tmp//a",
		"/tmp/./a",
		"/tmp/../a",
		"/tmp/a\0",
	] {
		assert!(validate(&params(vec![path.into()])).is_err(), "{path}");
	}
	assert_eq!(
		validate(&params(vec!["/tmp/中文.txt".into()])).unwrap(),
		(16384, 65536)
	);
	for n in [0, 65537, u64::MAX] {
		let mut p = params(vec!["/tmp/a".into()]);
		p.max_file_bytes = Some(n);
		assert!(validate(&p).is_err());
	}
	for n in [0, 1023, 262145, u64::MAX] {
		let mut p = params(vec!["/tmp/a".into()]);
		p.max_response_bytes = Some(n);
		assert!(validate(&p).is_err());
	}
}

#[test]
fn result_budget_counts_mcp_text_escaping() {
	let value = json!({"files":[{"text":"\\\"\0".repeat(200)}]});
	let text = serde_json::to_string(&value).unwrap();
	let wire = serde_json::to_vec(&CallToolResult::success(vec![ContentBlock::text(
		text.clone(),
	)]))
	.unwrap();
	assert!(wire.len() > text.len());
	assert!(serialize_result(&value, text.len() as u64).is_err());
	assert_eq!(serialize_result(&value, wire.len() as u64).unwrap(), text);
	assert!(serialize_result(&value, (wire.len() - 1) as u64).is_err());
}

#[test]
fn failed_transport_discards_partial_content_and_internal_details() {
	let raw = anyhow::anyhow!("remote helper on internal-ssh-user@secret-target returned invalid JSON; stdout=PRIVATE_FILE_FRAGMENT; stderr=SECRET_PASSWORD");
	let error = redacted_transport_error(raw);
	let rendered = format!("{error:#}");
	assert!(rendered.contains("multi-file read could not complete"));
	for secret in [
		"internal-ssh-user",
		"secret-target",
		"PRIVATE_FILE_FRAGMENT",
		"SECRET_PASSWORD",
		"stdout",
		"stderr",
	] {
		assert!(!rendered.contains(secret), "{rendered}");
	}
	assert!(
		error.source().is_none(),
		"raw error must not remain as a hidden chain"
	);
}
