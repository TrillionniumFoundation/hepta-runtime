#!/usr/bin/env node
// Copyright 2026 TrillionniumFoundation. Apache-2.0.
// Independent Babel AST/scope oracle. Target source is parsed as text, never imported.
// Usage: node this.mjs FIXTURES ORACLE_NODE_PROJECT RUNTIME_BINARY OUTPUT_JSON

import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";
import { spawnSync } from "node:child_process";

const [fixtureDir, oracleProject, runtimeBinary, outputFile] = process.argv.slice(2);
if (![fixtureDir, oracleProject, runtimeBinary, outputFile].every(Boolean)) {
  throw new Error("expected FIXTURES ORACLE_NODE_PROJECT RUNTIME_BINARY OUTPUT_JSON");
}
const oracleRequire = createRequire(path.resolve(oracleProject, "package.json"));
const parser = await import(pathToFileURL(oracleRequire.resolve("@babel/parser")));
const traversal = await import(pathToFileURL(oracleRequire.resolve("@babel/traverse")));
const traverse = traversal.default;
const packageVersion = (name) => JSON.parse(fs.readFileSync(
  path.join(oracleProject, "node_modules", name, "package.json"), "utf8")).version;
const parserVersion = packageVersion("@babel/parser");
const traverseVersion = packageVersion("@babel/traverse");
if (parserVersion !== "8.0.6" || traverseVersion !== "8.0.6") {
  throw new Error("reference requires exactly @babel/parser and @babel/traverse 8.0.6");
}
const hash = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const manifest = JSON.parse(fs.readFileSync(path.join(fixtureDir, "manifest.json"), "utf8"));
const sources = manifest.sources.map(({ file, ...source }) => ({
  ...source, text: fs.readFileSync(path.join(fixtureDir, file), "utf8"),
}));
const expected = { imports: [], exports: [], electron_calls: [], ipc_edges: [] };

function unwrap(p) {
  while (p?.node && ["TSAsExpression", "TSSatisfiesExpression", "TSNonNullExpression",
    "TSTypeAssertion", "TSInstantiationExpression", "ParenthesizedExpression"].includes(p.node.type)) {
    p = p.get("expression");
  }
  return p;
}
function literal(p) {
  p = unwrap(p);
  if (p?.isStringLiteral()) return p.node.value;
  if (p?.isTemplateLiteral() && p.node.expressions.length === 0 && p.node.quasis.length === 1) {
    return p.node.quasis[0].value.cooked ?? null;
  }
  return null;
}
function propertyName(p) {
  const property = p.get("property");
  if (!p.node.computed && property.isIdentifier()) return property.node.name;
  return literal(property);
}
function unbound(p, name) {
  p = unwrap(p);
  return p?.isIdentifier({ name }) && !p.scope.getBinding(name);
}
function requireElectron(p) {
  p = unwrap(p);
  return p?.isCallExpression() && !p.node.optional && unbound(p.get("callee"), "require")
    && p.node.arguments.length === 1 && literal(p.get("arguments.0")) === "electron";
}
const components = new Set(["ipcMain", "ipcRenderer", "contextBridge", "BrowserWindow"]);
function electronValue(p, depth = 0) {
  if (depth > 16) return null;
  p = unwrap(p);
  if (!p?.node) return null;
  if (requireElectron(p)) return "electron";
  if (p.isIdentifier()) {
    const binding = p.scope.getBinding(p.node.name);
    if (!binding?.constant) return null;
    const definition = binding.path;
    if (definition.isImportSpecifier() || definition.isImportNamespaceSpecifier() || definition.isImportDefaultSpecifier()) {
      const declaration = definition.parentPath.node;
      if (declaration.source.value !== "electron" || declaration.importKind === "type"
        || definition.node.importKind === "type") return null;
      if (!definition.isImportSpecifier()) return "electron";
      const imported = definition.node.imported.name ?? definition.node.imported.value;
      return components.has(imported) ? imported : null;
    }
    if (definition.isVariableDeclarator()) {
      const value = electronValue(definition.get("init"), depth + 1);
      if (definition.get("id").isIdentifier()) return value;
      if (value === "electron" && definition.get("id").isObjectPattern()) {
        for (const property of definition.get("id.properties")) {
          if (!property.isObjectProperty() || !property.get("value").isIdentifier({ name: binding.identifier.name })) continue;
          const key = property.get("key");
          const imported = !property.node.computed && key.isIdentifier() ? key.node.name : literal(key);
          if (components.has(imported)) return imported;
        }
      }
    }
    return null;
  }
  if (p.isNewExpression() && electronValue(p.get("callee"), depth + 1) === "BrowserWindow") {
    return "window-instance";
  }
  if (p.isMemberExpression() || p.isOptionalMemberExpression()) {
    const object = electronValue(p.get("object"), depth + 1);
    const property = propertyName(p);
    if (object === "electron" && components.has(property)) return property;
    if (object === "window-instance" && property === "webContents") return "webContents";
  }
  return null;
}

for (const source of sources) {
  const plugins = [];
  if (["typescript", "tsx"].includes(source.syntax)) plugins.push("typescript");
  if (["jsx", "tsx"].includes(source.syntax)) plugins.push("jsx");
  const ast = parser.parse(source.text, {
    sourceType: source.module_kind === "commonjs" ? "script" : "module", plugins,
    allowReturnOutsideFunction: source.module_kind === "commonjs", createImportExpressions: true,
    errorRecovery: false,
  });
  const span = (node) => ({
    start: Buffer.byteLength(source.text.slice(0, node.start)),
    end: Buffer.byteLength(source.text.slice(0, node.end)), unit: "utf8_bytes",
  });
  const record = (node, value) => ({ source_id: source.id, span: span(node), ...value });
  const dependency = (p, kind, specifier, type_only = false, bindings = []) => {
    expected.imports.push(record(p.node, { kind, specifier, type_only, bindings }));
  };
  const exportRecord = (value) => expected.exports.push({ source_id: source.id, ...value });
  const exportName = (node) => node?.name ?? node?.value ?? null;
  function observeCall(p) {
    const callee = unwrap(p.get("callee"));
    if (!p.node.optional && unbound(callee, "require")) {
      dependency(p, "commonjs_require", literal(p.get("arguments.0")));
    }
    if (!callee.isMemberExpression() && !callee.isOptionalMemberExpression()) return;
    const receiver = electronValue(callee.get("object"));
    const method = propertyName(callee);
    let role = null;
    let index = 0;
    if (receiver === "ipcMain" && ["handle", "handleOnce"].includes(method)) role = "invoke_handler";
    if (receiver === "ipcMain" && ["on", "once", "addListener"].includes(method)) role = "message_handler";
    if (receiver === "ipcRenderer" && method === "invoke") role = "invoke_sender";
    if (receiver === "ipcRenderer" && ["send", "sendSync", "postMessage"].includes(method)) role = "message_sender";
    if (receiver === "ipcRenderer" && ["on", "once", "addListener"].includes(method)) role = "renderer_handler";
    if (receiver === "webContents" && ["send", "postMessage"].includes(method)) role = "renderer_sender";
    if (receiver === "contextBridge" && ["exposeInMainWorld", "exposeInIsolatedWorld"].includes(method)) {
      role = "bridge_exposure";
      index = method === "exposeInIsolatedWorld" ? 1 : 0;
    }
    if (!role) return;
    const value = literal(p.get(`arguments.${index}`));
    expected.electron_calls.push(record(p.node, {
      api: receiver, method, role,
      channel: role === "bridge_exposure" ? null : value,
      exposure_key: role === "bridge_exposure" ? value : null,
    }));
  }
  traverse(ast, {
    ImportDeclaration(p) {
      const typeOnly = p.node.importKind === "type" || (p.node.specifiers.length > 0
        && p.node.specifiers.every(s => s.type === "ImportSpecifier" && s.importKind === "type"));
      const bindings = p.node.specifiers.map(specifier => ({
        kind: specifier.type === "ImportSpecifier" ? "named" : specifier.type === "ImportDefaultSpecifier" ? "default" : "namespace",
        imported_name: specifier.type === "ImportSpecifier" ? exportName(specifier.imported) : specifier.type === "ImportDefaultSpecifier" ? "default" : "*",
        local_name: specifier.local.name, type_only: p.node.importKind === "type" || specifier.importKind === "type", span: span(specifier),
      }));
      dependency(p, "esm_import", p.node.source.value, typeOnly, bindings);
    },
    ImportExpression(p) { dependency(p, "dynamic_import", literal(p.get("source"))); },
    ExportNamedDeclaration(p) {
      const node = p.node;
      if (node.source) dependency(p,
        node.specifiers.some(specifier => specifier.type === "ExportNamespaceSpecifier") ? "esm_reexport_all" : "esm_reexport",
        node.source.value, node.exportKind === "type");
      if (node.declaration) {
        const typeOnly = node.exportKind === "type" || ["TSInterfaceDeclaration", "TSTypeAliasDeclaration"].includes(node.declaration.type);
        for (const name of Object.keys(p.get("declaration").getBindingIdentifiers())) {
          exportRecord({ kind: "esm_local", exported_name: name, local_name: name,
            imported_name: null, specifier: null, type_only: typeOnly });
        }
      }
      for (const specifier of node.specifiers) {
        const isNamespace = specifier.type === "ExportNamespaceSpecifier";
        exportRecord({
          kind: node.source ? "esm_indirect" : "esm_local",
          exported_name: exportName(specifier.exported),
          local_name: node.source ? null : exportName(specifier.local),
          imported_name: node.source ? (isNamespace ? "*" : exportName(specifier.local)) : null,
          specifier: node.source?.value ?? null,
          type_only: node.exportKind === "type" || specifier.exportKind === "type",
        });
      }
    },
    ExportAllDeclaration(p) {
      dependency(p, "esm_reexport_all", p.node.source.value, p.node.exportKind === "type");
      exportRecord({ kind: "esm_star", exported_name: null, local_name: null,
        imported_name: "* except default", specifier: p.node.source.value,
        type_only: p.node.exportKind === "type" });
    },
    ExportDefaultDeclaration(p) {
      exportRecord({ kind: "esm_local", exported_name: "default", imported_name: null,
        local_name: p.node.declaration.id?.name ?? "*default*", specifier: null, type_only: false });
    },
    AssignmentExpression(p) {
      const left = p.get("left");
      if (!left.isMemberExpression()) return;
      const object = left.get("object");
      const property = propertyName(left);
      let matched = false;
      let exported = property;
      if (unbound(object, "exports")) matched = true;
      if (unbound(object, "module") && property === "exports") { matched = true; exported = "*"; }
      if (object.isMemberExpression() && unbound(object.get("object"), "module") && propertyName(object) === "exports") matched = true;
      if (matched) exportRecord({ kind: "commonjs_assignment", exported_name: exported,
        imported_name: null, local_name: null, specifier: null, type_only: false });
    },
    CallExpression: observeCall,
    OptionalCallExpression: observeCall,
    NewExpression(p) {
      if (electronValue(p.get("callee")) !== "BrowserWindow") return;
      let present = false;
      let preload = null;
      const options = p.get("arguments.0");
      if (options?.isObjectExpression()) {
        for (const property of options.get("properties")) {
          if (!property.isObjectProperty()) continue;
          const key = property.node.computed ? literal(property.get("key")) : exportName(property.node.key);
          if (key !== "webPreferences") continue;
          const preferences = unwrap(property.get("value"));
          if (!preferences.isObjectExpression()) continue;
          for (const preference of preferences.get("properties")) {
            if (!preference.isObjectProperty()) continue;
            const key = preference.node.computed ? literal(preference.get("key")) : exportName(preference.node.key);
            if (key === "preload") { present = true; preload = literal(preference.get("value")); }
          }
        }
      }
      expected.electron_calls.push(record(p.node, { api: "BrowserWindow", method: "new",
        role: "window_constructor", channel: null, exposure_key: null,
        preload_declaration_present: present, literal_preload: preload }));
    },
  });
}

function normalizedCall(row) {
  const result = { source_id: row.source_id, span: row.span, api: row.api, method: row.method,
    role: row.role, channel: row.channel ?? null, exposure_key: row.exposure_key ?? null };
  if (row.role === "window_constructor") {
    result.preload_declaration_present = row.preload_declaration_present;
    result.literal_preload = row.literal_preload;
  }
  return result;
}
function candidateEdges(calls) {
  const roles = { invoke_sender: "invoke_handler", message_sender: "message_handler", renderer_sender: "renderer_handler" };
  const edges = [];
  for (const sender of calls) {
    if (sender.channel === null || !roles[sender.role]) continue;
    for (const receiver of calls) {
      if (receiver.role !== roles[sender.role] || sender.channel !== receiver.channel) continue;
      edges.push({ from: { source_id: sender.source_id, span: sender.span },
        to: { source_id: receiver.source_id, span: receiver.span }, channel: sender.channel,
        sender_role: sender.role, receiver_role: receiver.role });
    }
  }
  return edges;
}
expected.ipc_edges = candidateEdges(expected.electron_calls);
const actual = { imports: [], exports: [], electron_calls: [], ipc_edges: [] };
const nativeReports = {};
for (const collection of Object.keys(actual)) {
  const request = { sources, collection, offset: 0, limit: 256, expected_graph_sha256: null };
  const run = spawnSync(runtimeBinary, ["rea-javascript-worker"], {
    input: JSON.stringify(request), encoding: "utf8", timeout: 30000, maxBuffer: 2 * 1024 * 1024,
    env: {}, cwd: "/",
  });
  if (run.status !== 0 || run.error) throw new Error(`native worker ${collection}: ${run.error ?? run.stderr}`);
  const report = JSON.parse(run.stdout);
  if (report.next_offset !== null || report.javascript_executed !== false || report.rea_evidence_compatible !== false) {
    throw new Error("unexpected native coverage or pagination response");
  }
  nativeReports[collection] = report;
}
actual.imports = nativeReports.imports.rows.map(({ source_id, span, kind, specifier, type_only, bindings }) => ({ source_id, span, kind, specifier, type_only, bindings }));
actual.exports = nativeReports.exports.rows.map(row => ({ source_id: row.source_id, kind: row.kind,
  exported_name: row.exported_name ?? null, imported_name: row.imported_name ?? null,
  local_name: row.local_name ?? null, specifier: row.specifier ?? null, type_only: row.type_only }));
actual.electron_calls = nativeReports.electron_calls.rows.map(normalizedCall);
const nativeCalls = new Map(nativeReports.electron_calls.rows.map(row => [row.node_id, row]));
actual.ipc_edges = nativeReports.ipc_edges.rows.map(row => {
  const from = nativeCalls.get(row.from), to = nativeCalls.get(row.to);
  if (!from || !to || row.runtime_observed !== false || row.process_pair_proven !== false) throw new Error("invalid native candidate edge");
  return { from: { source_id: from.source_id, span: from.span }, to: { source_id: to.source_id, span: to.span },
    channel: row.channel, sender_role: row.sender_role, receiver_role: row.receiver_role };
});
function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])]));
  }
  return value;
}
const sorted = values => values.map(value => JSON.stringify(canonical(value))).sort();
const comparisons = Object.fromEntries(Object.keys(actual).map(key => [key, {
  equal: JSON.stringify(sorted(expected[key])) === JSON.stringify(sorted(actual[key])),
  expected_count: expected[key].length, actual_count: actual[key].length,
  missing: sorted(expected[key]).filter(value => !sorted(actual[key]).includes(value)).map(JSON.parse),
  extra: sorted(actual[key]).filter(value => !sorted(expected[key]).includes(value)).map(JSON.parse),
}]));
const result = {
  schema: "hepta.javascript-babel-ast-differential.v1",
  status: Object.values(comparisons).every(value => value.equal) ? "pass" : "fail",
  oracle: { parser: "@babel/parser", parser_version: parserVersion,
    traversal: "@babel/traverse", traversal_version: traverseVersion, node_version: process.version },
  candidate: { executable_sha256: hash(fs.readFileSync(runtimeBinary)), parser: "oxc", version: "0.144.0",
    graph_sha256: nativeReports.imports.graph_sha256 },
  sources: sources.map(source => ({ id: source.id, syntax: source.syntax, module_kind: source.module_kind,
    sha256: hash(source.text), byte_length: Buffer.byteLength(source.text) })),
  comparisons, expected, actual,
  scope: "Owned finite fixtures; independent AST/scope comparison, not full REA 6.8.0 parity or runtime Electron qualification",
};
fs.mkdirSync(path.dirname(outputFile), { recursive: true });
fs.writeFileSync(outputFile, JSON.stringify(result, null, 2) + "\n");
console.log(JSON.stringify({ status: result.status, comparisons, output: outputFile }));
if (result.status !== "pass") process.exitCode = 1;
