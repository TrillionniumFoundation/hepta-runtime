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

//! Static IPC and constructor projections captured from the actual fixed npm
//! tool. This is not complete application-graph or REA Evidence equivalence.

use super::*;
use sha2::{Digest, Sha256};
use std::fmt::Write;

fn sha256_hex(bytes: &[u8]) -> String {
	let mut digest = String::with_capacity(64);
	for byte in Sha256::digest(bytes) {
		write!(&mut digest, "{byte:02x}").unwrap();
	}
	digest
}

fn check_original_cases(ids: &[&str]) {
	let reference: Value = serde_json::from_str(include_str!(
		"../../tests/fixtures/rea_javascript/alias-order-original-6.8.0.json"
	))
	.expect("captured original REA fixture");
	assert_eq!(reference["reference"]["version"], "6.8.0");
	assert_eq!(reference["global_qualification"], "HOLD/NO_GO");
	let cases = reference["cases"].as_array().expect("original cases");
	assert_eq!(cases.len(), 13);
	for id in ids {
		let case = cases.iter().find(|case| case["id"] == *id).expect(id);
		let text = case["source"].as_str().expect("original source bytes");
		assert!(
			text.is_ascii(),
			"this finite source-range projection is ASCII only"
		);
		assert_eq!(sha256_hex(text.as_bytes()), case["sha256"], "{id}");
		let inspected = inspect(&AdmittedSource {
			id: (*id).into(),
			syntax: JavascriptSyntax::Javascript,
			module_kind: JavascriptModuleKind::Commonjs,
			text: text.into(),
		})
		.expect("valid inert CommonJS AST");
		let mut calls = Vec::new();
		let mut windows = 0;
		for call in &inspected.electron_calls {
			assert_eq!(call["runtime_observed"], false, "{id}");
			if call["role"] == "window_constructor" {
				windows += 1;
			} else {
				calls.push(json!({
					"api":call["api"], "method":call["method"],
					"role":call["role"], "channel":call["channel"],
					"span":call["span"]
				}));
			}
		}
		assert_eq!(json!(calls), case["expected_ipc_calls"], "{id}");
		assert_eq!(json!(windows), case["expected_browser_windows"], "{id}");
	}
}

#[test]
fn original_source_order_alias_and_mutation_controls_match() {
	check_original_cases(&["before.js", "after.js", "mutated.js"]);
}

#[test]
fn original_alias_chains_shadowing_cycles_and_redeclarations_match() {
	check_original_cases(&[
		"chain-before.js",
		"chain-after.js",
		"shadow.js",
		"shadow-require.js",
		"cycle.js",
		"mutated-alias.js",
		"redeclared.js",
	]);
}

#[test]
fn original_namespace_and_constructor_alias_boundaries_match() {
	check_original_cases(&[
		"namespace-after.js",
		"destructure-after.js",
		"window-after.js",
	]);
}
