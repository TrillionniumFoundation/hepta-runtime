// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Literal package declarations, JSON-pointer provenance, non-execution and
//! source identity tests; no npm, browser or JavaScript engine is involved.

use super::*;

fn params(collection: JavascriptCollection) -> InspectJavascriptPackageParams {
	InspectJavascriptPackageParams {
		path: "/unused/package.json".into(),
		expected_sha256: None,
		collection,
		offset: 0,
		limit: 64,
	}
}

fn fixture() -> Vec<u8> {
	serde_json::to_vec(&json!({
		"name": "owned-electron-fixture",
		"version": "1.0.0",
		"main": "dist/main.js",
		"type": "commonjs",
		"exports": {
			".": {"require": "./dist/cjs.js", "import": "./dist/esm.js"},
			"./hidden": null
		},
		"browser": {"./node.js": false},
		"bin": {"owned-cli": "./bin/run.js"},
		"dependencies": {"@owned/core": "workspace:*"},
		"devDependencies": {"electron": "^1.0.0"},
		"scripts": {"start": "electron .", "install": "this string is never executed"}
	}))
	.expect("fixture")
}

#[test]
fn electron_and_main_are_reported_as_declarations_without_runtime_claims() {
	let summary = report(&fixture(), &params(JavascriptCollection::Summary)).expect("summary");
	assert_eq!(summary["summary"]["main_declaration"], "dist/main.js");
	assert_eq!(
		summary["summary"]["electron_dependency_declarations"][0]["name"],
		"electron"
	);
	assert_eq!(summary["summary"]["electron_runtime_observed"], false);
	assert_eq!(summary["summary"]["dependency_declaration_count"], 2);
	assert_eq!(summary["summary"]["script_count"], 2);
	assert_eq!(summary["javascript_executed"], false);
	assert_eq!(summary["dependencies_resolved"], false);
	assert!(summary["rows"].as_array().expect("rows").is_empty());
	assert!(!summary
		.to_string()
		.contains("this string is never executed"));
}

#[test]
fn entries_retain_pointer_provenance_including_blocked_and_browser_false_values() {
	let report = report(&fixture(), &params(JavascriptCollection::Entries)).expect("entries");
	let rows = report["rows"].as_array().expect("rows");
	assert!(rows
		.iter()
		.any(|row| row["json_pointer"] == "/exports/./import" && row["value"] == "./dist/esm.js"));
	assert!(rows
		.iter()
		.any(|row| row["json_pointer"] == "/exports/.~1hidden" && row["value"].is_null()));
	assert!(rows
		.iter()
		.any(|row| row["json_pointer"] == "/browser/.~1node.js" && row["value"] == false));
	assert!(rows
		.iter()
		.any(|row| row["json_pointer"] == "/bin/owned-cli" && row["value"] == "./bin/run.js"));
}

#[test]
fn dependency_and_script_collections_are_literal_and_paginated() {
	let bytes = fixture();
	let mut selection = params(JavascriptCollection::Dependencies);
	selection.limit = 1;
	let first = report(&bytes, &selection).expect("first");
	assert_eq!(first["rows"][0]["name"], "@owned/core");
	assert_eq!(first["rows"][0]["specification"], "workspace:*");
	assert_eq!(
		first["rows"][0]["json_pointer"],
		"/dependencies/@owned~1core"
	);
	assert_eq!(first["next_offset"], 1);
	selection.offset = 1;
	assert!(report(&bytes, &selection).is_err());
	selection.expected_sha256 = Some(sha256(&bytes));
	let second = report(&bytes, &selection).expect("second");
	assert_eq!(second["rows"][0]["name"], "electron");
	assert!(second["next_offset"].is_null());
	let scripts = report(&bytes, &params(JavascriptCollection::Scripts)).expect("scripts");
	assert!(scripts["rows"]
		.as_array()
		.expect("rows")
		.iter()
		.any(|row| row["command"] == "this string is never executed"));
}

#[test]
fn empty_exports_are_distinguished_from_an_absent_declaration() {
	let declared = report(br#"{"exports":{}}"#, &params(JavascriptCollection::Summary))
		.expect("empty exports");
	let absent = report(br#"{}"#, &params(JavascriptCollection::Summary)).expect("absent");
	assert_eq!(declared["summary"]["exports_declaration_present"], true);
	assert_eq!(declared["summary"]["entry_declaration_count"], 0);
	assert_eq!(absent["summary"]["exports_declaration_present"], false);
}

#[test]
fn malformed_duplicate_deep_and_oversized_declarations_fail_explicitly() {
	for source in [
		br#"{"main":"a.js","main":"b.js"}"#.as_slice(),
		br#"{"main":false}"#.as_slice(),
		br#"{"dependencies":{"x":1}}"#.as_slice(),
		br#"{"scripts":{"install":["not","text"]}}"#.as_slice(),
		br#"{"exports":true}"#.as_slice(),
	] {
		assert!(report(source, &params(JavascriptCollection::Summary)).is_err());
	}
	let mut nested = json!("./leaf.js");
	for _ in 0..18 {
		nested = json!({"condition": nested});
	}
	let deep = serde_json::to_vec(&json!({"exports": nested})).expect("deep");
	assert!(report(&deep, &params(JavascriptCollection::Entries)).is_err());
	assert!(report(
		&vec![b' '; MAX_FILE_BYTES as usize + 1],
		&params(JavascriptCollection::Summary)
	)
	.is_err());
}

#[tokio::test]
#[cfg(unix)]
async fn actual_manifest_read_never_executes_script_and_rejects_stale_or_outside_input() {
	let workspace = tempfile::tempdir().expect("workspace");
	let outside = tempfile::tempdir().expect("outside");
	let roots = [workspace.path().to_path_buf()];
	let path = workspace.path().join("package.json");
	let marker = workspace.path().join("must-not-exist");
	let original = serde_json::to_vec(&json!({
		"name": "literal-only",
		"main": "../outside-not-followed.js",
		"scripts": {"install": format!("touch {}", marker.display())}
	}))
	.expect("manifest");
	tokio::fs::write(&path, &original)
		.await
		.expect("manifest write");
	let mut selection = params(JavascriptCollection::Scripts);
	selection.path = path.to_string_lossy().into_owned();
	selection.expected_sha256 = Some(sha256(&original));
	let result: Value = serde_json::from_str(
		&inspect_with_roots(selection.clone(), &roots)
			.await
			.expect("literal inspection"),
	)
	.expect("report");
	assert_eq!(result["entry_files_opened"], false);
	assert!(!tokio::fs::try_exists(&marker)
		.await
		.expect("marker absence"));
	tokio::fs::write(&path, b"{}")
		.await
		.expect("change manifest");
	assert!(inspect_with_roots(selection.clone(), &roots).await.is_err());
	let external = outside.path().join("package.json");
	tokio::fs::write(&external, &original)
		.await
		.expect("external");
	let link = workspace.path().join("linked.json");
	tokio::fs::symlink(&external, &link).await.expect("link");
	for rejected in [external, link] {
		selection.path = rejected.to_string_lossy().into_owned();
		assert!(inspect_with_roots(selection.clone(), &roots).await.is_err());
	}
}
