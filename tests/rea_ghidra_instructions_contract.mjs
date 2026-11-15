// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
// Schema-only differential: this never launches Ghidra or opens a document.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { constants, closeSync, fstatSync, fsyncSync, openSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const argv = process.argv.slice(2);
const names = ["--rea-root", "--fixture", "--output"];
assert.equal(argv.length, names.length * 2, "three explicit path arguments are required");
const options = {};
for (let index = 0; index < argv.length; index += 2) {
  assert(names.includes(argv[index]), "unknown argument");
  assert(!(argv[index] in options), "duplicate argument");
  assert.equal(resolve(argv[index + 1]), argv[index + 1], "absolute normalized paths are required");
  options[argv[index]] = argv[index + 1];
}
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
function capture(path, expected) {
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = fstatSync(fd, { bigint: true });
    assert(before.isFile() && before.size <= 1024n * 1024n * 1024n, "regular bounded input required");
    const bytes = readFileSync(fd);
    const after = fstatSync(fd, { bigint: true });
    for (const name of ["dev", "ino", "size", "mtimeNs", "ctimeNs"]) assert.equal(after[name], before[name]);
    assert.equal(BigInt(bytes.length), before.size);
    const pin = { path, bytes: bytes.length, sha256: digest(bytes) };
    if (expected !== undefined) assert.equal(pin.sha256, expected, path);
    return { pin, bytes };
  } finally {
    closeSync(fd);
  }
}
const originalPins = {
  "package.json": "b0fc212f6bea9b4ee6e2b3ab0b52dd95402c229da3b8652127e5f131c3445b39",
  "dist/ghidra/GhidraFunctionValues.js": "a34c606f6cc4989d5b01b4171e4dc830939d2cbbdbcd365b74157f8325e8566c",
  "dist/ghidra/GhidraInventoryValues.js": "d29538770a0558582bbb8050fc0bfadc4dee41fc446e4b1f82447dcca03230b3",
  "dist/domain/hopperValues.js": "bfe7de495a3f4489ccb27541435ee353bf65e59e62520c42622a522834ec0f5b",
  "dist/domain/native/nativeAddress.js": "7a13f92d7c2ba839eb62c1c2139716606ef160d7d7678005afebe79745007397",
  "dist/domain/native/nativeSymbol.js": "f50dcbc2b05436d646ce2acf50b0adc98fedddefb3c62a4b79cf2a6d849ec06a",
  "dist/domain/result.js": "ff6811cc8bc0b60bdba0d98102fca60e39b59808f223f66db6f58304de3dde73",
};
const pins = Object.entries(originalPins).map(([name, expected]) =>
  capture(resolve(options["--rea-root"], name), expected).pin);
assert.equal(JSON.parse(capture(resolve(options["--rea-root"], "package.json")).bytes).version, "6.8.0");
const fixtureRead = capture(options["--fixture"]);
const fixture = JSON.parse(fixtureRead.bytes);
const oracle = await import(pathToFileURL(resolve(options["--rea-root"], "dist/ghidra/GhidraFunctionValues.js")).href);
const operation = "read_function_instructions";
const request = { document: null, procedure: fixture.instruction_window.procedure.address };
const requestResult = oracle.parseGhidraFunctionInput(operation, request);
assert.equal(requestResult.ok, true);
const envelope = { value: fixture.instruction_window, limitations: fixture.instruction_window.limitations };
const observed = oracle.parseGhidraFunctionResult(operation, envelope);
assert.equal(observed.ok, true);
assert.deepEqual(observed.value.value, fixture.instruction_window);
assert.deepEqual(observed.value.limitations, envelope.limitations);
const checks = [{ name: "synthetic_window_passes_original_6_8_0_function_schema", outcome: "accepted" }];
const negatives = [
  ["missing_procedure_symbol", value => { delete value.value.procedure.symbol; }],
  ["missing_body_ranges", value => { delete value.value.procedure.body.ranges; }],
  ["enclosing_span_is_not_exact_total", value => { value.value.procedure.body.total_bytes = 17; }],
  ["wrong_span", value => { value.value.procedure.body.span_bytes = 7; }],
  ["wrong_non_contiguous", value => { value.value.procedure.body.non_contiguous = false; }],
  ["wrong_entry_membership", value => { value.value.procedure.body.contains_entry = false; }],
  ["adjacent_ranges_not_maximal", value => { value.value.procedure.body.ranges[1].start = "0x1006"; }],
  ["overlapping_ranges", value => { value.value.procedure.body.ranges[0].end = "0x1010"; }],
  ["unavailable_body", value => { value.value.procedure.body = { available: false, reason: "not analyzed" }; }],
  ["unobserved_body_provenance", value => { value.value.procedure.body.provenance = "enclosing_range"; }],
  ["unrecognized_symbol_source", value => { value.value.procedure.symbol.source = "guessed"; }],
  ["extra_window_field", value => { value.value.truncated = false; }],
  ["extra_observation_field", value => { value.extra = true; }],
  ["wrong_observation_limitations_type", value => { value.limitations = "complete"; }],
];
for (const [name, mutate] of negatives) {
  const value = structuredClone(envelope);
  mutate(value);
  const parsed = oracle.parseGhidraFunctionResult(operation, value);
  assert.equal(parsed.ok, false, name);
  checks.push({ name, outcome: "rejected", error: String(parsed.error?.message ?? parsed.error) });
}
for (const pin of pins) assert.deepEqual(capture(pin.path, pin.sha256).pin, pin);
assert.deepEqual(capture(fixtureRead.pin.path, fixtureRead.pin.sha256).pin, fixtureRead.pin);
const result = {
  schema: "hepta.rea.ghidra-instructions.schema-oracle.v1",
  scope: "synthetic_fixture_against_original_schema_only",
  original_version: "6.8.0",
  original_direct_module_pins: pins,
  transitive_node_dependency_closure_attested: false,
  node: { ...capture(process.execPath).pin, version: process.version },
  fixture: fixtureRead.pin,
  operation,
  request,
  request_result: requestResult,
  original_result: observed,
  checks,
  checks_expected: 15,
  checks_observed: checks.length,
  engine_executed: false,
  native_runtime_executed: false,
  full_operation_parity: false,
  production_qualified: false,
};
assert.equal(checks.length, 15);
const fd = openSync(options["--output"], constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
try {
  writeFileSync(fd, JSON.stringify(result, null, 2) + "\n");
  fsyncSync(fd);
} finally {
  closeSync(fd);
}
const output = capture(options["--output"]).pin;
process.stdout.write(JSON.stringify({ schema: result.schema, output, checks: checks.length, engine_executed: false }) + "\n");
