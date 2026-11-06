// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
// Generate finite, independent fixtures with the unmodified published REA.
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { pathToFileURL } from "node:url";
import { createRequire } from "node:module";

const [reference, output] = process.argv.slice(2);
if (!reference || !output || !path.isAbsolute(reference) || !path.isAbsolute(output))
  throw new Error("usage: node rea_residual_unknown_reference.mjs ABS_REFERENCE_PACKAGE ABS_NEW_OUTPUT");
if (fs.existsSync(output)) throw new Error("refusing to replace a prior fixture receipt");
const sha = (data) => crypto.createHash("sha256").update(data).digest("hex");
const files = [
  "package.json", "dist/domain/residualUnknown.js", "dist/domain/evidenceBundle.js",
  "dist/domain/evidence.js", "dist/domain/canonicalDigest.js",
  "dist/domain/functionComparisonSchemas.js", "dist/domain/validationFailure.js",
];
const identities = () => files.map((name) => {
  const bytes = fs.readFileSync(path.join(reference, name));
  return { path: name, bytes: bytes.length, sha256: sha(bytes) };
});
const before = identities();
if (JSON.parse(fs.readFileSync(path.join(reference, "package.json"))).version !== "6.8.0")
  throw new Error("reference package is not the selected published release");
const pins = {
  "dist/domain/residualUnknown.js": "28f97f7b0d5afc95ec65d5eb90295ad97aad140028877246dadfb4abd6603433",
  "dist/domain/evidenceBundle.js": "24796cd112032363d9da0c8f9fc40c46364154e76e21084dfc46d640456f6314",
};
for (const item of before)
  if (pins[item.path] && pins[item.path] !== item.sha256) throw new Error("reference source pin changed");
const moduleAt = (name) => import(pathToFileURL(path.join(reference, "dist/domain", name)).href);
const { createResidualUnknown, residualUnknownSchema } = await moduleAt("residualUnknown.js");
const { digestCanonicalValue } = await moduleAt("canonicalDigest.js");
const { evidenceSemanticContent, parseEvidence } = await moduleAt("evidence.js");
const { createImmutableEvidenceBundle } = await moduleAt("evidenceBundle.js");
const { describeValidationFailure } = await moduleAt("validationFailure.js");
const require = createRequire(path.join(reference, "package.json"));
const { z } = require("zod");
const zodManifest = require.resolve("zod/package.json");
const zodBytes = fs.readFileSync(zodManifest);
const zodIdentity = () => ["v4/core/checks.js", "v4/core/util.js", "v4/locales/en.js"].map(name => {
  const bytes = fs.readFileSync(path.join(path.dirname(zodManifest), name));
  return { path: name, bytes: bytes.length, sha256: sha(bytes) };
});
const zodBefore = zodIdentity();
const copy = (v) => structuredClone(v);
function record(label, patch = {}) {
  const value = {
    subject: null, provider: { id: "rea-finite-fixture", name: "Owned reference fixture", version: "1" },
    analysis_profile: null, predicate_type: "rea.fixture-observation", operation: "fixture",
    parameters: { label }, raw_result: {}, normalized_result: {}, confidence: "observed",
    authority: "shipped-artifact", environment: null, limitations: [], relationship_coverage: null,
    locations: [], evidence_links: [], ...patch,
  };
  return parseEvidence({ ...value, evidence_id: "ev_" + digestCanonicalValue(evidenceSemanticContent(value)) });
}
const observed = record("observed");
const derived = record("derived", {
  confidence: "derived", authority: "controlled-replay",
  environment: { id: "lab", platform: "linux", architecture: "x86_64", isolation: "process" },
});
const inferred = record("inferred", { confidence: "inferred", authority: "analyst-inference" });
const mutation = record("mutation", { predicate_type: "rea.residual-unknown-mutation" });
const records = [observed, derived, inferred, mutation];
function unknown(question = "Why this result?", patch = {}) {
  return createResidualUnknown({
    question, domain: "fixture", severity: "medium",
    supporting_evidence_ids: [observed.evidence_id], contradicting_evidence_ids: [],
    required_authority: null, required_confidence: "observed", required_environment: null,
    recommended_probes: [{ operation: "inspect_elf_notes", rationale: "Inspect the owned fixture" }],
    relationships: [], ...patch,
  }, mutation.evidence_id, null);
}
function restamp(value) {
  const { revision_digest, ...semantic } = value;
  return { ...semantic, revision_digest: digestCanonicalValue(semantic) };
}
function keyOrders(value, location = [], result = []) {
  if (Array.isArray(value)) value.forEach((v, i) => keyOrders(v, [...location, i], result));
  else if (value !== null && typeof value === "object") {
    result.push({ path: location, keys: Object.keys(value) });
    for (const key of Object.keys(value)) keyOrders(value[key], [...location, key], result);
  }
  return result;
}
const base = unknown();
const shapes = [];
function shape(name, value) {
  const input = copy(value);
  const parsed = residualUnknownSchema.safeParse(input);
  shapes.push({
    name, input, wire_sha256: sha(JSON.stringify(input)), key_orders: keyOrders(input),
    expected: parsed.success ? { ok: true, value: parsed.data } : {
      ok: false, description: describeValidationFailure(parsed.error),
      issues: parsed.error.issues.map(({ path, message }) => ({ path, message })),
    },
  });
}
shape("valid-default", base);
shape("valid-comparison-scope", unknown("Function comparison?", {
  domain: "function-comparison",
  comparison_conclusion_scope: { comparison_evidence_id: observed.evidence_id, dimensions: ["assembly", "overall"] },
}));
shape("valid-nel-is-not-js-whitespace", unknown("\u0085Why this result?\u0085", { domain: "\u0085domain\u0085" }));
shape("valid-ecmascript-whitespace", unknown("\ufeffWhy\u2000this\u2028result?\u3000"));
const trim = copy(base);
trim.question = "\ufeff \t" + trim.question + "\u2029";
trim.domain = "  " + trim.domain + "\ufeff";
trim.recommended_probes[0].rationale = " \t" + trim.recommended_probes[0].rationale + " \n";
shape("valid-input-trim-before-digest", trim);
const internal = copy(base);
internal.question = "Why  \tthis result?";
shape("valid-question-internal-space-is-revision-content", restamp(internal));
const withdrawn = restamp({ ...base, status: "resolved",
  resolution: { disposition: "withdrawn", rationale: "No longer in scope", evidence_ids: [] } });
withdrawn.resolution.rationale = "\ufeff " + withdrawn.resolution.rationale + "\t";
shape("valid-withdrawn-rationale-trim-before-digest", withdrawn);
const operationSpaces = copy(base);
operationSpaces.recommended_probes[0].operation = " ";
shape("valid-operation-is-not-trimmed", restamp(operationSpaces));
shape("valid-resolution-id-duplicates-are-not-forbidden", restamp({ ...base, status: "resolved",
  resolution: { disposition: "verified", rationale: "Observed", evidence_ids: [observed.evidence_id, observed.evidence_id] } }));
shape("valid-environment-null-wildcards", restamp({ ...base,
  required_environment: { id: null, platform: null, architecture: null, isolation: null } }));
shape("valid-zero-width-space-is-not-trimmed", unknown("\u200bWhy this result?\u200b"));
for (const value of [null, false, 1, "", [], {}, { question: "x" }])
  shape("root-" + JSON.stringify(value), value);
for (const field of Object.keys(base)) {
  const value = copy(base);
  delete value[field];
  shape("missing-" + field, value);
}
for (const field of ["unknown_id", "revision_digest", "previous_revision_digest", "scope_digest"]) {
  for (const bad of ["", "a", "A".repeat(64), 3, []]) {
    const value = copy(base); value[field] = bad; shape(field + "-" + JSON.stringify(bad), value);
  }
}
for (const bad of [null, false, "1", 0, -1, 0.5, 1.5, 9007199254740992, -9007199254740992]) {
  const value = copy(base); value.revision = bad; shape("revision-" + JSON.stringify(bad), value);
}
for (const field of ["question", "domain"]) {
  for (const bad of ["", " \ufeff\t", [], ["x"], 1]) {
    const value = copy(base); value[field] = bad; shape(field + "-bad-" + JSON.stringify(bad), value);
  }
}
const lengthValues = [null, false, true, -2, -0.5, 0, 0.5, 1, 2, "", " ", "\ufeff", "\u0085",
  "0", "1", "1.", ".5", "-.5", "+1", "1e0", "1e-9", "1e+999", "NaN", "inf",
  "Infinity", "+Infinity", "-Infinity", "0x0", "0X1", "0b1", "0o1", "+0x1", "-0x1",
  "0x", "0b2", "1_0", "0x" + "f".repeat(80), [], [null], [true], [false], [0], [1],
  [""], ["1"], [[[[1]]]], [[0, 1]], [null, null], {}, { valueOf: 0 }];
for (const field of ["question", "domain", "mutation_evidence_ids"]) {
  for (const length of lengthValues) {
    const value = copy(base); value[field] = { length };
    shape(field + "-length-object-" + JSON.stringify(length), value);
  }
}
for (const length of [0, 1, "bad", null, [], [1], {}]) {
  const value = copy(base); value.recommended_probes[0].operation = { length };
  shape("probe-operation-length-object-" + JSON.stringify(length), value);
}
for (const field of ["status", "severity", "required_authority", "required_confidence"]) {
  for (const bad of ["other", null, 1]) {
    const value = copy(base); value[field] = bad; shape(field + "-bad-" + JSON.stringify(bad), value);
  }
}
for (const field of ["supporting_evidence_ids", "contradicting_evidence_ids", "mutation_evidence_ids"]) {
  for (const bad of [null, "", [null], ["EV_" + "a".repeat(64)], [], [observed.evidence_id, observed.evidence_id]]) {
    const value = copy(base); value[field] = bad; shape(field + "-bad-" + JSON.stringify(bad), value);
  }
}
const comparisonBase = unknown("Comparison?", { domain: "function-comparison",
  comparison_conclusion_scope: { comparison_evidence_id: observed.evidence_id, dimensions: ["assembly", "overall"] } });
for (const dims of [[], ["overall", "assembly"], ["assembly", "assembly"], ["unknown"], [null], "assembly"]) {
  const value = copy(comparisonBase); value.comparison_conclusion_scope.dimensions = dims;
  shape("comparison-dimensions-" + JSON.stringify(dims), value);
}
for (const field of ["required_environment", "recommended_probes", "relationships", "resolution"]) {
  for (const bad of [{}, [], "bad", 1, null]) {
    const value = copy(base); value[field] = bad; shape(field + "-shape-" + JSON.stringify(bad), value);
  }
}
for (const disposition of ["verified", "withdrawn", "out-of-scope", "bad", null]) {
  const value = copy(base);
  value.resolution = { disposition, rationale: " \ufeff\t", evidence_ids: [] };
  shape("resolution-" + String(disposition), value);
}
for (const field of ["root", "probe", "environment", "comparison", "resolution", "relationship"]) {
  const value = copy(comparisonBase);
  value.required_environment = { id: null, platform: null, architecture: null, isolation: null };
  value.resolution = { disposition: "withdrawn", rationale: "done", evidence_ids: [] };
  value.relationships = [{ type: "related-to", unknown_id: "unk_" + "a".repeat(64) }];
  const target = { root: value, probe: value.recommended_probes[0], environment: value.required_environment,
    comparison: value.comparison_conclusion_scope, resolution: value.resolution, relationship: value.relationships[0] }[field];
  target.z_extra = 1; target.a_extra = 2;
  shape("unknown-member-order-" + field, value);
}
for (const field of ["root", "probe", "environment", "comparison", "resolution", "relationship"]) {
  const value = copy(comparisonBase);
  value.required_environment = { id: null, platform: null, architecture: null, isolation: null };
  value.status = "resolved";
  value.resolution = { disposition: "withdrawn", rationale: "done", evidence_ids: [] };
  value.relationships = [{ type: "related-to", unknown_id: "unk_" + "a".repeat(64) }];
  const stamped = restamp(value);
  const target = { root: stamped, probe: stamped.recommended_probes[0], environment: stamped.required_environment,
    comparison: stamped.comparison_conclusion_scope, resolution: stamped.resolution, relationship: stamped.relationships[0] }[field];
  Object.defineProperty(target, "__proto__", { value: { length: 0 }, enumerable: true, configurable: true, writable: true });
  shape("own-prototype-key-is-omitted-" + field, stamped);
  target.z_extra = 1; target.a_extra = 2;
  shape("prototype-key-with-ordered-extra-members-" + field, stamped);
  delete target.z_extra; delete target.a_extra;
  target.constructor = null; target.toString = null;
  shape("constructor-and-toString-are-still-extra-members-" + field, stamped);
}
const refinements = [
  ["wrong-identity", v => { v.unknown_id = "unk_" + "a".repeat(64); }],
  ["first-has-predecessor", v => { v.previous_revision_digest = "a".repeat(64); }],
  ["later-missing-predecessor", v => { v.revision = 2; }],
  ["resolved-without-resolution", v => { v.status = "resolved"; }],
  ["unresolved-with-resolution", v => { v.resolution = { disposition: "withdrawn", rationale: "done", evidence_ids: [] }; }],
  ["contradicted-without-evidence", v => { v.status = "contradicted"; }],
  ["self-relationship", v => { v.relationships = [{ type: "related-to", unknown_id: v.unknown_id }]; }],
  ["support-and-contradict", v => { v.contradicting_evidence_ids = [...v.supporting_evidence_ids]; }],
  ["duplicate-relationship", v => { const r = { type: "depends-on", unknown_id: "unk_" + "a".repeat(64) }; v.relationships = [r, copy(r)]; }],
  ["wrong-comparison-domain", v => { v.comparison_conclusion_scope = { comparison_evidence_id: observed.evidence_id, dimensions: ["overall"] }; }],
  ["unsupported-comparison-reference", v => { v.domain = "function-comparison"; v.comparison_conclusion_scope = { comparison_evidence_id: derived.evidence_id, dimensions: ["overall"] }; }],
];
for (const [name, mutate] of refinements) {
  const value = copy(base); mutate(value); shape(name, restamp(value));
}
const graphs = [];
function graph(name, unknowns, selectedRecords = records) {
  for (const value of unknowns) residualUnknownSchema.parse(value);
  for (const value of selectedRecords) parseEvidence(value);
  let expected;
  try { createImmutableEvidenceBundle(selectedRecords, unknowns); expected = { ok: true }; }
  catch (error) { expected = { ok: false, message: error.message, error_type: error.constructor.name }; }
  graphs.push({ name, unknowns: copy(unknowns), records: copy(selectedRecords), expected });
}
graph("empty", []);
graph("one-open", [base]);
const second = restamp({ ...base, revision: 2, previous_revision_digest: base.revision_digest, status: "investigating" });
graph("complete-history-reordered", [second, base]);
graph("history-missing-first", [second]);
graph("history-duplicate-revision", [base, base]);
graph("history-gap", [base, restamp({ ...second, revision: 3 })]);
graph("history-broken-chain", [base, restamp({ ...second, previous_revision_digest: "a".repeat(64) })]);
for (const field of ["supporting_evidence_ids", "contradicting_evidence_ids", "mutation_evidence_ids"]) {
  graph("missing-evidence-" + field, [restamp({ ...base, [field]: ["ev_" + "a".repeat(64)] })]);
}
graph("missing-related-unknown", [restamp({ ...base, relationships: [{ type: "related-to", unknown_id: "unk_" + "a".repeat(64) }] })]);
const other = unknown("Second question?");
for (const type of ["depends-on", "related-to", "contradicts"]) {
  const left = restamp({ ...base, relationships: [{ type, unknown_id: other.unknown_id }] });
  const right = restamp({ ...other, relationships: [{ type, unknown_id: base.unknown_id }] });
  graph(type + "-cycle", [left, right]);
}
const oldHead = restamp({ ...base, relationships: [{ type: "depends-on", unknown_id: other.unknown_id }] });
const newHead = restamp({ ...second, previous_revision_digest: oldHead.revision_digest, relationships: [] });
const otherHead = restamp({ ...other, relationships: [{ type: "depends-on", unknown_id: base.unknown_id }] });
graph("historical-dependency-cycle-is-not-current-head-cycle", [newHead, otherHead, oldHead]);
function resolved(patch = {}, evidenceIds = [observed.evidence_id]) {
  return restamp({ ...base, status: "resolved",
    resolution: { disposition: "verified", rationale: "Observed the owned fixture", evidence_ids: evidenceIds }, ...patch });
}
graph("verified-observation", [resolved()]);
graph("verified-contradiction", [resolved({ contradicting_evidence_ids: [derived.evidence_id] })]);
graph("verified-not-supporting", [resolved({ supporting_evidence_ids: [] })]);
graph("verified-mutation-is-not-resolution-evidence", [resolved({ supporting_evidence_ids: [mutation.evidence_id] }, [mutation.evidence_id])]);
graph("verified-insufficient-confidence", [resolved({ supporting_evidence_ids: [derived.evidence_id] }, [derived.evidence_id])]);
graph("verified-higher-confidence", [resolved({ required_confidence: "derived" })]);
graph("verified-wrong-authority", [resolved({ required_authority: "controlled-replay" })]);
const wild = { id: null, platform: null, architecture: null, isolation: null };
graph("verified-environment-required-even-when-all-wildcards", [resolved({ required_environment: wild })]);
graph("verified-partial-environment", [resolved({
  supporting_evidence_ids: [derived.evidence_id], required_confidence: "derived",
  required_authority: "controlled-replay", required_environment: { ...wild, platform: "linux" },
}, [derived.evidence_id])]);
graph("verified-wrong-environment", [resolved({
  supporting_evidence_ids: [derived.evidence_id], required_confidence: "derived",
  required_environment: { ...wild, id: "another-lab" },
}, [derived.evidence_id])]);
graph("verified-resolution-missing-reference", [resolved({}, ["ev_" + "b".repeat(64)])]);
graph("withdrawn-does-not-require-qualifying-evidence", [restamp({ ...base, status: "resolved",
  resolution: { disposition: "withdrawn", rationale: "No longer in scope", evidence_ids: [] } })]);
const length_checks = [];
const lengthInputs = [null, false, true, 0, 1, "", "a", "\ud83d\ude00", [], ["a"], {},
  ...lengthValues.map(length => ({ length })),
  { length: { toString: null } }, { length: [{ toString: 1 }] },
  { length: [0, { toString: false }] }, { length: [[{ toString: {} }]] }];
for (const input of lengthInputs) {
  for (const minimum of [1, 2]) {
    let expected;
    try {
      const result = z.string().min(minimum).safeParse(copy(input));
      expected = { throws: false, issues: result.success ? [] : result.error.issues
        .filter(issue => issue.code === "too_small")
        .map(({ path, message }) => ({ path, message })) };
    } catch (error) { expected = { throws: true, error_type: error.constructor.name, message: error.message }; }
    length_checks.push({ input, minimum, expected });
  }
}
const after = identities();
if (JSON.stringify(before) !== JSON.stringify(after)) throw new Error("reference changed during generation");
const zodAfter = zodIdentity();
if (JSON.stringify(zodBefore) !== JSON.stringify(zodAfter)) throw new Error("Zod changed during generation");
const report = {
  schema: "hepta.rea.residual-unknown-reference.v1", reference_package: "rea-agents@6.8.0",
  node: { version: process.version, executable: process.execPath, sha256: sha(fs.readFileSync(process.execPath)) },
  zod: { version: JSON.parse(zodBytes).version, package_json_sha256: sha(zodBytes), source_before: zodBefore, source_after: zodAfter },
  source_before: before, source_after: after, source_unchanged: true,
  scope: "Finite direct published-domain fixtures; public MCP, resource and owner qualification remain separate.",
  shapes, graphs, length_checks,
};
fs.mkdirSync(path.dirname(output), { recursive: true });
fs.writeFileSync(output, JSON.stringify(report, null, 2) + "\n", { flag: "wx" });
console.log(JSON.stringify({ output, sha256: sha(fs.readFileSync(output)),
  shapes: shapes.length, valid_shapes: shapes.filter(c => c.expected.ok).length,
  graphs: graphs.length, valid_graphs: graphs.filter(c => c.expected.ok).length,
  length_checks: length_checks.length, original_coercion_exceptions: length_checks.filter(c => c.expected.throws).length }));
