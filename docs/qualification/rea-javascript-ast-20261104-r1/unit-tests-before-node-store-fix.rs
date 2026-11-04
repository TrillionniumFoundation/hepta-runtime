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

//! Real AST, symbol-shadowing, candidate-edge, immutable-page and admission
//! regressions. Independent parser fixtures live in tests/fixtures/rea_javascript.

use super::*;

fn source(id: &str, text: &str) -> AdmittedSource {
	AdmittedSource {
		id: id.into(),
		syntax: JavascriptSyntax::Javascript,
		module_kind: JavascriptModuleKind::Module,
		text: text.into(),
	}
}

fn request(sources: Vec<AdmittedSource>, collection: JavascriptGraphCollection) -> WorkerRequest {
	WorkerRequest {
		sources,
		expected_graph_sha256: None,
		collection,
		offset: 0,
		limit: 256,
	}
}

fn graph_sources() -> Vec<AdmittedSource> {
	vec![
		source(
			"src/main.js",
			r#"
			import {ipcMain as main, BrowserWindow} from "electron";
			import {value} from "./util";
			export {value as forwarded} from "./util.js";
			main.handle("fetch:π", () => value);
			main.on("set", () => {});
			const win = new BrowserWindow({webPreferences:{preload:"./preload.cjs"}});
			win.webContents.send("status", value);
			function shadow(main) { main.handle("must-not-link", () => {}); }
		"#,
		),
		AdmittedSource {
			module_kind: JavascriptModuleKind::Commonjs,
			..source(
				"src/preload.cjs",
				r#"
			const {ipcRenderer:r, contextBridge:bridge} = require("electron");
			bridge.exposeInMainWorld("api", {load:() => r.invoke("fetch:π")});
			r.send("set", 1); r.on("status", () => {});
			function shadow(r) { r.invoke("must-not-link"); }
			const decoy = 'ipcMain.handle("text-only", () => {})';
			// ipcRenderer.send("comment-only")
			function shadowRequire(require) { require("not-a-dependency"); }
		"#,
			)
		},
		source(
			"src/util.js",
			"export const value = 7; export default value;",
		),
		source("src/util.ts", "export const other = 8;"),
	]
}

#[test]
fn lexical_electron_calls_produce_only_role_compatible_candidate_edges() {
	let inspected = graph::report(&request(
		graph_sources(),
		JavascriptGraphCollection::IpcEdges,
	))
	.expect("actual AST graph");
	assert_eq!(inspected["counts"]["ipc_candidate_edges"], 3);
	assert_eq!(inspected["counts"]["electron_calls"], 8);
	assert_eq!(inspected["javascript_executed"], false);
	assert_eq!(inspected["complete_application_graph"], false);
	for row in inspected["rows"].as_array().expect("edges") {
		assert_eq!(row["process_pair_proven"], false);
		assert_eq!(row["runtime_observed"], false);
		assert_ne!(row["channel"], "must-not-link");
	}
	let calls = graph::report(&request(
		graph_sources(),
		JavascriptGraphCollection::ElectronCalls,
	))
	.expect("calls");
	assert!(calls["rows"]
		.as_array()
		.expect("calls")
		.iter()
		.any(|call| call["role"] == "window_constructor"
			&& call["literal_preload"] == "./preload.cjs"));
	assert!(calls["rows"]
		.as_array()
		.expect("calls")
		.iter()
		.any(|call| call["role"] == "bridge_exposure" && call["exposure_key"] == "api"));
}

#[test]
fn imports_keep_multiple_selected_extension_candidates_without_loader_claim() {
	let inspected = graph::report(&request(
		graph_sources(),
		JavascriptGraphCollection::Imports,
	))
	.expect("imports");
	let rows = inspected["rows"].as_array().expect("imports");
	let ambiguous = rows
		.iter()
		.find(|row| row["specifier"] == "./util")
		.expect("extensionless");
	assert_eq!(
		ambiguous["target_candidates"]["source_ids"],
		json!(["src/util.js", "src/util.ts"])
	);
	assert_eq!(ambiguous["runtime_resolution_proven"], false);
	assert!(!rows
		.iter()
		.any(|row| row["specifier"] == "not-a-dependency"));
	assert!(!rows.iter().any(|row| row["specifier"] == "text-only"));
}

#[test]
fn typescript_jsx_type_only_imports_and_dynamic_expressions_are_ast_observations() {
	let mut ts = source(
		"renderer.tsx",
		r#"
		import type {Envelope} from "./types";
		import {type OnlyType} from "./type-only";
		import {ipcRenderer as ipc} from "electron";
		export const View = (props: {label:string}) => <div>{props.label}</div>;
		declare const target: string;
		import(target); import("./literal.js"); ipc.send(target); ipc[target]("x");
	"#,
	);
	ts.syntax = JavascriptSyntax::Tsx;
	let inspected = graph::report(&request(
		vec![ts.clone()],
		JavascriptGraphCollection::Imports,
	))
	.expect("TSX");
	let rows = inspected["rows"].as_array().expect("imports");
	assert_eq!(
		rows.iter().filter(|row| row["type_only"] == true).count(),
		2
	);
	assert!(rows
		.iter()
		.any(|row| row["kind"] == "dynamic_import" && row["specifier"].is_null()));
	let unknowns =
		graph::report(&request(vec![ts], JavascriptGraphCollection::Unknowns)).expect("unknowns");
	assert_eq!(unknowns["total_rows"], 3);
}

#[test]
fn reassigned_bindings_fake_modules_and_shadowed_commonjs_exports_are_not_promoted() {
	let mut js = source(
		"preload.cjs",
		r#"
		let ipc = require("electron").ipcRenderer;
		ipc = {send() {}}; ipc.send("not-electron");
		const fake = require("electron-lookalike"); fake.ipcMain.handle("fake", () => {});
		exports.good = 1; module.exports.other = 2;
		function f(exports, module) { exports.bad = 3; module.exports.bad = 4; }
	"#,
	);
	js.module_kind = JavascriptModuleKind::Commonjs;
	let inspected =
		graph::report(&request(vec![js], JavascriptGraphCollection::Exports)).expect("CommonJS");
	assert_eq!(inspected["counts"]["electron_calls"], 0);
	assert_eq!(inspected["total_rows"], 2);
	assert_eq!(inspected["rows"][0]["exported_name"], "good");
	assert_eq!(inspected["rows"][1]["exported_name"], "other");
}

#[test]
fn pagination_is_bound_to_every_selected_source_and_explicit_grammar() {
	let mut selection = request(graph_sources(), JavascriptGraphCollection::Imports);
	selection.limit = 1;
	let first = graph::report(&selection).expect("first page");
	selection.offset = 1;
	assert!(graph::report(&selection).is_err());
	selection.expected_graph_sha256 = Some(first["graph_sha256"].as_str().expect("hash").into());
	assert!(graph::report(&selection).is_ok());
	selection.sources.reverse();
	assert!(
		graph::report(&selection).is_ok(),
		"input order does not alter the graph identity"
	);
	selection.sources[0]
		.text
		.push_str("\n// actual byte change");
	assert!(graph::report(&selection).is_err());
}

#[test]
fn invalid_ast_semantic_errors_utf16_surrogates_and_resource_excess_refuse() {
	for text in [
		"const x = ;",
		"let x; let x;",
		"const pattern=/(/;",
		r#"const x='\uD800';"#,
	] {
		assert!(
			graph::report(&request(
				vec![source("bad.js", text)],
				JavascriptGraphCollection::Summary
			))
			.is_err(),
			"{text}"
		);
	}
	let mut selected = request(
		vec![source("large.js", &" ".repeat(MAX_SOURCE_BYTES + 1))],
		JavascriptGraphCollection::Summary,
	);
	assert!(graph::report(&selected).is_err());
	selected.sources = vec![source("a.js", ""); MAX_SOURCES + 1];
	assert!(graph::report(&selected).is_err());
	for id in ["../a.js", "/a.js", "a/./b.js", "a//b.js", "a\\b.js"] {
		assert!(validate_id(id).is_err());
	}
}

#[tokio::test]
#[cfg(unix)]
async fn source_admission_rejects_outside_symlink_stale_hash_and_does_not_execute() {
	let root = tempfile::tempdir().expect("root");
	let outside = tempfile::tempdir().expect("outside");
	let path = root.path().join("owned.js");
	let marker = root.path().join("must-not-run");
	let text = format!(
		"require('fs').writeFileSync({}, 'bad'); export const a=1;",
		json!(marker)
	);
	let bytes = text.as_bytes();
	tokio::fs::write(&path, bytes).await.expect("source");
	let mut params = InspectJavascriptGraphParams {
		sources: vec![JavascriptSource {
			id: "owned.js".into(),
			path: path.to_string_lossy().into_owned(),
			syntax: JavascriptSyntax::Javascript,
			module_kind: JavascriptModuleKind::Module,
			expected_sha256: Some(sha256(bytes)),
		}],
		expected_graph_sha256: None,
		collection: JavascriptGraphCollection::Summary,
		offset: 0,
		limit: 64,
	};
	let roots = [root.path().to_owned()];
	let inspected: Value = serde_json::from_str(
		&inspect_with_roots(params.clone(), &roots)
			.await
			.expect("admitted analysis"),
	)
	.expect("report");
	assert_eq!(inspected["javascript_executed"], false);
	assert!(!tokio::fs::try_exists(&marker)
		.await
		.expect("marker absence"));
	params.sources[0].expected_sha256 = Some("0".repeat(64));
	assert!(inspect_with_roots(params.clone(), &roots).await.is_err());
	let external = outside.path().join("external.js");
	tokio::fs::write(&external, bytes).await.expect("outside");
	let link = root.path().join("linked.js");
	tokio::fs::symlink(&external, &link).await.expect("symlink");
	for rejected in [external, link] {
		params.sources[0].path = rejected.to_string_lossy().into_owned();
		params.sources[0].expected_sha256 = None;
		assert!(inspect_with_roots(params.clone(), &roots).await.is_err());
	}
}
