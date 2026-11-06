#!/usr/bin/env node
// Copyright 2026 TrillionniumFoundation. Apache-2.0.
// Execute only these authored inert fixture programs with a stub constructor.
// User source and Electron are never loaded by this qualification harness.
// Usage: node SCRIPT RUNTIME_BINARY OUTPUT_JSON
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import vm from "node:vm";
import { fileURLToPath } from "node:url";
import { stripTypeScriptTypes } from "node:module";
import { spawnSync } from "node:child_process";

const [runtime, output] = process.argv.slice(2);
if (!runtime || !output) throw Error("expected RUNTIME_BINARY OUTPUT_JSON");
const runtimePath = path.resolve(runtime);
const sha = bytes => crypto.createHash("sha256").update(bytes).digest("hex");
const optionCases = [
  ["plain.js", "javascript", '{webPreferences:{preload:"./preload.cjs"}}'],
  ["parentheses.js", "javascript", '(({webPreferences:{preload:"./preload.cjs"}}))'],
  ["as-const.ts", "typescript", '({webPreferences:{preload:"./preload.cjs"}} as const)'],
  ["satisfies.ts", "typescript", '({webPreferences:{preload:"./preload.cjs"}} satisfies Record<string, unknown>)'],
  ["type-assertion.ts", "typescript", '(<Record<string, unknown>>{webPreferences:{preload:"./preload.cjs"}})'],
  ["non-null.ts", "typescript", '({webPreferences:{preload:"./preload.cjs"}}!)'],
  ["nested-values.js", "javascript", '({webPreferences:({preload:("./preload.cjs")})})'],
];
const fixtures = optionCases.map(([id, syntax, options]) => ({
  id, syntax, module_kind: "commonjs",
  text: 'const {BrowserWindow}=require("electron"); new BrowserWindow(' + options + ');\n',
}));
const originalFixturePath = fileURLToPath(new URL(
  "../tests/fixtures/rea_javascript/preload-original-rea-6_8_0-679ccf.json", import.meta.url));
const originalFixtureBytes = fs.readFileSync(originalFixturePath);
const originalFixtureSha256 = sha(originalFixtureBytes);
if (originalFixtureSha256 !== "b1640feec76ac2ad11c08b469c103af382b4e4c99a63058dd35db16cc8256509")
  throw Error("fixed original REA preload fixture identity changed");
const originalFixture = JSON.parse(originalFixtureBytes);
if (originalFixture.schema !== "hepta.rea.preload-wrapper-original-projection.v1"
    || originalFixture.reference?.package !== "rea-agents"
    || originalFixture.reference?.version !== "6.8.0"
    || originalFixture.reference?.tool !== "analyze_javascript_application"
    || originalFixture.cases?.length !== fixtures.length)
  throw Error("unexpected original REA preload fixture contract");
const originalCases = new Map(originalFixture.cases.map(item => [item.id, item]));
if (originalCases.size !== fixtures.length) throw Error("duplicate original REA fixture IDs");
for (const source of fixtures) {
  const original = originalCases.get(source.id);
  if (!original || original.syntax !== source.syntax || original.source !== source.text
      || original.source_sha256 !== sha(source.text)
      || original.source_sha256 !== sha(original.source) || original.browser_windows !== 1)
    throw Error("authored/original REA fixture source mismatch: " + source.id);
}
const projectionMatches = (left, right) => left != null && right != null
  && left.preload_declaration_present === right.preload_declaration_present
  && left.literal_preload === right.literal_preload;
const fixtureDirectory = path.resolve(output) + ".fixtures";
fs.mkdirSync(fixtureDirectory, { mode: 0o700 });
const cases = fixtures.map(source => {
  const emitted = source.syntax === "typescript"
    ? stripTypeScriptTypes(source.text, { mode: "transform" }) : source.text;
  fs.writeFileSync(path.join(fixtureDirectory, source.id), source.text, { flag: "wx" });
  fs.writeFileSync(path.join(fixtureDirectory, source.id + ".emitted.js"), emitted, { flag: "wx" });
  const captures = [];
  class BrowserWindow {
    constructor(options) { captures.push(options); }
  }
  const context = vm.createContext({ require(name) {
    if (name !== "electron") throw Error("unexpected authored fixture dependency");
    return { BrowserWindow };
  } }, { codeGeneration: { strings: false, wasm: false } });
  new vm.Script(emitted, { filename: source.id }).runInContext(context, { timeout: 1000 });
  if (captures.length !== 1) throw Error("fixture must instantiate one inert constructor");
  const expected = {
    preload_declaration_present: Object.hasOwn(captures[0].webPreferences ?? {}, "preload"),
    literal_preload: captures[0].webPreferences?.preload ?? null,
  };
  const run = spawnSync(runtimePath, ["rea-javascript-worker"], {
    input: JSON.stringify({ sources: [source], collection: "electron_calls", offset: 0,
      limit: 256, expected_graph_sha256: null }),
    encoding: "utf8", env: {}, cwd: "/", timeout: 25000, maxBuffer: 2 * 1024 * 1024,
  });
  let report = null;
  let parseError = null;
  try { report = JSON.parse(run.stdout); } catch (error) { parseError = String(error); }
  const row = report?.rows?.length === 1 ? report.rows[0] : null;
  const observed = row && Object.fromEntries(Object.keys(expected).map(key => [key, row[key]]));
  const original = originalCases.get(source.id);
  const originalExpected = original.expected;
  const nodeOracleMatched = projectionMatches(observed, expected);
  const originalReaOracleMatched = projectionMatches(observed, originalExpected);
  const oraclesAgree = projectionMatches(expected, originalExpected);
  const runtimeContractPassed = run.status === 0 && !run.error && !parseError
    && report?.analysis_profile === "hepta.javascript-selected-source-graph.v4"
    && report?.javascript_executed === false && row?.runtime_observed === false;
  const passed = runtimeContractPassed && nodeOracleMatched && originalReaOracleMatched && oraclesAgree;
  return {
    id: source.id, syntax: source.syntax, source_sha256: sha(source.text),
    emitted_sha256: sha(emitted), expected, original_expected: originalExpected, observed, passed,
    node_oracle_matched: nodeOracleMatched, original_rea_oracle_matched: originalReaOracleMatched,
    oracles_agree: oraclesAgree, runtime_contract_passed: runtimeContractPassed,
    original_raw_frame_sha256: original.original_raw_frame_sha256,
    original_response_sha256: original.original_response_sha256,
    graph_sha256: report?.graph_sha256 ?? null, analysis_profile: report?.analysis_profile ?? null,
    exit_status: run.status, error: run.error?.message ?? parseError,
    stderr: run.stderr,
  };
});
const result = {
  schema: "hepta.javascript-preload-wrapper-qualification.v1",
  created_at: new Date().toISOString(),
  reference: { name: "node-typescript-transformation-and-inert-constructor", node: process.version,
    executable_sha256: sha(fs.readFileSync(process.execPath)),
    typescript_mode: "transform", authored_fixture_execution_only: true },
  original_reference: {
    fixture: { path: originalFixturePath, sha256: originalFixtureSha256 },
    ...originalFixture.reference, scope: originalFixture.projection_scope,
    observation_mode: "recorded_original_public_mcp_result",
  },
  oracle_summary: {
    denominator: cases.length,
    node_matches: cases.filter(item => item.node_oracle_matched).length,
    original_rea_matches: cases.filter(item => item.original_rea_oracle_matched).length,
    oracles_agree: cases.filter(item => item.oracles_agree).length,
    runtime_contract_passes: cases.filter(item => item.runtime_contract_passed).length,
  },
  runtime: { path: runtimePath, sha256: sha(fs.readFileSync(runtimePath)) },
  analysis_profile: "hepta.javascript-selected-source-graph.v4",
  scope: "finite_preload_literal_observations_only",
  global_qualification: "HOLD/NO_GO", full_rea_parity_claimed: false,
  fixture_directory: fixtureDirectory, cases, passed: cases.every(item => item.passed),
};
fs.writeFileSync(output, JSON.stringify(result, null, 2) + "\n", { flag: "wx" });
console.log(JSON.stringify({ output, passed: result.passed, cases: cases.length,
  oracle_summary: result.oracle_summary }));
if (!result.passed) process.exitCode = 1;
