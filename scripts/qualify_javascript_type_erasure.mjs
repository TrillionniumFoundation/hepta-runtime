#!/usr/bin/env node
// Copyright 2026 TrillionniumFoundation. Apache-2.0.
// Compare the shipped Oxc worker with an independent TypeScript parser and both
// type-erasure modes. Neither emitted JavaScript nor target modules are executed.
// Usage: node this.mjs RUNTIME_BINARY TYPESCRIPT_PACKAGE_DIR OUTPUT_JSON

import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { createRequire } from "node:module";
import { spawnSync } from "node:child_process";

const [runtime, typescriptPackage, output] = process.argv.slice(2);
if (![runtime, typescriptPackage, output].every(value => value && path.isAbsolute(value))) {
  throw new Error("expected absolute RUNTIME_BINARY TYPESCRIPT_PACKAGE_DIR OUTPUT_JSON");
}
const hash = bytes => crypto.createHash("sha256").update(bytes).digest("hex");
const hashFile = file => hash(fs.readFileSync(file));
const packageFile = path.join(typescriptPackage, "package.json");
const packageJson = JSON.parse(fs.readFileSync(packageFile, "utf8"));
if (packageJson.name !== "typescript") throw new Error("reference is not the TypeScript package");
const require = createRequire(packageFile);
const compilerPath = require.resolve(typescriptPackage);
const originalIdentity = {
  runtime_sha256: hashFile(runtime),
  typescript_package_sha256: hashFile(packageFile),
  typescript_implementation_sha256: hashFile(compilerPath),
};
const ts = require(typescriptPackage);
if (ts.version !== packageJson.version) throw new Error("TypeScript version identities differ");

const sources = [
  ["import-declaration", "import type { Foo } from './types';"],
  ["import-type-namespace", "import type * as Types from './types';"],
  ["import-inline", "import { type Foo } from './types';"],
  ["import-inline-alias", "import { type Foo, type Bar as B } from './types';"],
  ["import-mixed", "import { type Foo, value } from './types';"],
  ["import-empty", "import {} from './types';"],
  ["import-side-effect", "import './types';"],
  ["export-declaration", "export type { Foo } from './types';"],
  ["export-inline", "export { type Foo } from './types';"],
  ["export-inline-alias", "export { type Foo, type Bar as B } from './types';"],
  ["export-mixed", "export { type Foo, value } from './types';"],
  ["export-empty", "export {} from './types';"],
  ["export-type-star", "export type * from './types';"],
  ["export-star", "export * from './types';"],
];

function referenceSyntax(text) {
  const ast = ts.createSourceFile("fixture.ts", text, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  if (ast.parseDiagnostics.length || ast.statements.length !== 1) {
    throw new Error("reference fixture did not parse to one declaration");
  }
  const node = ast.statements[0];
  let declarationType, specifiers, kind;
  if (ts.isImportDeclaration(node)) {
    declarationType = node.importClause?.isTypeOnly === true;
    specifiers = node.importClause?.namedBindings
      && ts.isNamedImports(node.importClause.namedBindings)
      ? [...node.importClause.namedBindings.elements] : [];
    // A default binding remains value syntax even beside type-only named ones.
    if (node.importClause?.name) specifiers.push({ isTypeOnly: false });
    kind = "esm_import";
  } else if (ts.isExportDeclaration(node)) {
    declarationType = node.isTypeOnly === true;
    specifiers = node.exportClause && ts.isNamedExports(node.exportClause)
      ? [...node.exportClause.elements] : [];
    kind = node.exportClause && ts.isNamedExports(node.exportClause)
      ? "esm_reexport" : "esm_reexport_all";
  } else {
    throw new Error("reference fixture is not an import/export declaration");
  }
  const inlineOnly = specifiers.length > 0 && specifiers.every(item => item.isTypeOnly === true);
  return {
    kind, specifier: node.moduleSpecifier.text,
    type_only: declarationType || inlineOnly,
    type_only_scope: declarationType ? "declaration" : inlineOnly ? "named_specifiers" : "none",
  };
}

function emittedDependencies(text, verbatimModuleSyntax) {
  const compiled = ts.transpileModule(text, {
    fileName: "fixture.ts", reportDiagnostics: true,
    compilerOptions: {
      module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022,
      verbatimModuleSyntax,
    },
  });
  const errors = (compiled.diagnostics ?? []).filter(diagnostic => diagnostic.category === ts.DiagnosticCategory.Error);
  if (errors.length) throw new Error("TypeScript fixture transpilation failed");
  const ast = ts.createSourceFile("fixture.js", compiled.outputText, ts.ScriptTarget.Latest, true, ts.ScriptKind.JS);
  if (ast.parseDiagnostics.length) throw new Error("emitted reference JavaScript did not parse");
  const dependencies = ast.statements
    .filter(node => (ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) && node.moduleSpecifier)
    .map(node => node.moduleSpecifier.text);
  return { verbatim_module_syntax: verbatimModuleSyntax, output: compiled.outputText, dependencies };
}

const cases = [];
for (const [name, text] of sources) {
  const expected = referenceSyntax(text);
  const erasures = [false, true].map(mode => emittedDependencies(text, mode));
  const request = {
    sources: [{ id: "fixture.ts", syntax: "typescript", module_kind: "module", text }],
    expected_graph_sha256: null, collection: "imports", offset: 0, limit: 16,
  };
  const processResult = spawnSync(runtime, ["rea-javascript-worker"], {
    input: JSON.stringify(request), encoding: "utf8", env: {}, cwd: "/",
    timeout: 25000, maxBuffer: 2 * 1024 * 1024,
  });
  let native = null, parseError = null;
  try { native = JSON.parse(processResult.stdout); }
  catch (error) { parseError = String(error); }
  const row = native?.rows?.length === 1 ? native.rows[0] : null;
  const observed = row && Object.fromEntries(Object.keys(expected).map(key => [key, row[key]]));
  const equal = processResult.status === 0 && !processResult.error && parseError === null
    && native?.analysis_profile === "hepta.javascript-selected-source-graph.v2"
    && native?.javascript_executed === false && row?.runtime_resolution_proven === false
    && JSON.stringify(observed) === JSON.stringify(expected);
  const referenceControls = expected.type_only_scope === "declaration"
    ? erasures.every(mode => mode.dependencies.length === 0)
    : erasures[1].dependencies.includes("./types");
  cases.push({
    name, source: text, source_sha256: hash(text), expected, observed,
    erasures, native, exit_code: processResult.status,
    native_stderr: processResult.stderr, error: processResult.error ? String(processResult.error) : parseError,
    pass: equal && referenceControls,
  });
}

const identitiesUnchanged = originalIdentity.runtime_sha256 === hashFile(runtime)
  && originalIdentity.typescript_package_sha256 === hashFile(packageFile)
  && originalIdentity.typescript_implementation_sha256 === hashFile(compilerPath);
const receipt = {
  schema: "hepta.javascript-type-erasure-differential.v1",
  status: identitiesUnchanged && cases.every(item => item.pass) ? "pass" : "fail",
  scope: "Fourteen explicit syntax fixtures, independent TypeScript parse and two emit modes, actual native worker. This is not full REA parity, MCP lifecycle or live Electron qualification.",
  target_modules_executed: false, dependency_modules_loaded: false,
  reference: {
    name: "typescript", version: ts.version, node_version: process.version,
    package_sha256: originalIdentity.typescript_package_sha256,
    implementation_sha256: originalIdentity.typescript_implementation_sha256,
    modes: ["verbatimModuleSyntax=false", "verbatimModuleSyntax=true"],
  },
  candidate: { runtime_sha256: originalIdentity.runtime_sha256 },
  producer_sha256: hashFile(new URL(import.meta.url)),
  identities_unchanged: identitiesUnchanged,
  cases,
};
fs.writeFileSync(output, JSON.stringify(receipt, null, 2) + "\n", { flag: "wx", mode: 0o600 });
console.log(JSON.stringify({ status: receipt.status, cases: cases.length, passed: cases.filter(item => item.pass).length,
  reference_version: ts.version, runtime_sha256: originalIdentity.runtime_sha256, output }));
if (receipt.status !== "pass") process.exitCode = 1;
