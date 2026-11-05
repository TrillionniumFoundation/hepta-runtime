#!/usr/bin/env node
// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0

/**
 * Compare bounded GGUF layout fixtures against the actual REA 6.8.0 modules
 * and optionally the compiled native inherited-descriptor worker.
 * This does not qualify the complete REA model provider or Evidence contract.
 */
import { createHash } from "node:crypto";
import { open, readFile, mkdir, writeFile } from "node:fs/promises";
import { openSync, closeSync } from "node:fs";
import { resolve, join } from "node:path";
import { pathToFileURL } from "node:url";
import { runModelWorker } from "./rea-model-worker-lifecycle.mjs";

const options = {};
for (let i = 2; i < process.argv.length; i += 2) {
  const key = process.argv[i];
  if (!["--rea", "--native", "--work", "--out"].includes(key) || !process.argv[i + 1]) {
    throw new Error("usage: node rea-model-gguf-layout-diff.mjs --rea PACKAGE_DIR --work FIXTURE_DIR [--native BINARY] [--out REPORT_JSON]");
  }
  options[key.slice(2)] = resolve(process.argv[i + 1]);
}
if (!options.rea || !options.work) throw new Error("--rea and --work are required");
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const nativeBinarySha256 = options.native ? hash(await readFile(options.native)) : null;
const packageJson = JSON.parse(await readFile(join(options.rea, "package.json"), "utf8"));
if (packageJson.version !== "6.8.0") throw new Error("oracle must be rea-agents@6.8.0");
const expectedModules = {
  "GgufHeader.js": "6e8f33cdb4e58e4a196e505c7496f160764260e406a7ea8d89bcbb13e1105a42",
  "ModelTensorTypes.js": "ebb648607ca406e09722d6be1e70882d276170080b9ca6dadbd103360c68854d",
};
for (const [name, digest] of Object.entries(expectedModules)) {
  if (hash(await readFile(join(options.rea, "dist/model", name))) !== digest) {
    throw new Error("oracle module hash mismatch: " + name);
  }
}
const { GgufHeader } = await import(pathToFileURL(join(options.rea, "dist/model/GgufHeader.js")));
const { ModelHeaderReader } = await import(pathToFileURL(join(options.rea, "dist/model/ModelHeaderReader.js")));
await mkdir(options.work, { recursive: true });

const layouts = [
  [0, "F32", 1, 4], [1, "F16", 1, 2], [2, "Q4_0", 32, 18],
  [3, "Q4_1", 32, 20], [6, "Q5_0", 32, 22], [7, "Q5_1", 32, 24],
  [8, "Q8_0", 32, 34], [26, "I32", 1, 4], [27, "I64", 1, 8],
  [28, "F64", 1, 8], [29, "IQ1_M", 256, 56], [30, "BF16", 1, 2],
  [34, "TQ1_0", 256, 54], [35, "TQ2_0", 256, 66],
  [39, "MXFP4", 32, 17], [40, "NVFP4", 64, 36], [41, "Q1_0", 128, 18],
  [42, "Q2_0", 64, 18],
];
const cases = [];
const add = (name, type, shape, size, extra = {}) =>
  cases.push({ name, rows: [{ name: "weights", type, shape, offset: 0 }], size, little: true, reaAccept: true, nativeAccept: true, ...extra });
for (const [type, , block, bytes] of layouts) {
  for (const little of [true, false]) {
    const suffix = little ? "le" : "be";
    add("stable-" + type + "-" + suffix, type, [block * 2, 3, 2], bytes * 12, { little });
    add("truncated-" + type + "-" + suffix, type, [block * 2, 3, 2], bytes * 12 - 1,
      { little, reaAccept: false, nativeAccept: false });
  }
}
for (const [type, block] of [[2, 32], [9, 32], [10, 64], [29, 256], [40, 64]]) {
  for (const last of [0, 2]) {
    add("invalid-row-" + type + "-" + last, type, [block / 2, last], 1024,
      { reaAccept: false, nativeAccept: false });
  }
}
for (let type = 9; type <= 25; type++) {
  const block = type === 9 ? 32 : type <= 15 ? 64 : 1;
  for (const little of [true, false]) {
    add("historical-" + type + "-" + (little ? "le" : "be"), type, [block, 2], 1024, { little });
  }
  add("historical-empty-" + type, type, [block, 0], 0);
}
for (const type of [4, 5, 31, 32, 33, 36, 37, 38, 43, 0xffffffff]) {
  add("unknown-empty-" + type, type, [0], 0);
  add("unknown-nonempty-" + type, type, [31], 5);
}
for (const bytes of [36, 40]) add("q8-1-historical-size-" + bytes, 9, [32], bytes);
add("stable-overlap", 2, [64], 128, {
  rows: [{ name: "first", type: 2, shape: [64], offset: 0 }, { name: "second", type: 2, shape: [64], offset: 32 }],
  nativeAccept: false, intentionalDifference: "Native validation already rejects overlapping verified extents; the original GgufHeader parser permits them.",
});
add("stable-aligned-padding", 2, [64], 100, {
  rows: [{ name: "first", type: 2, shape: [64], offset: 0 }, { name: "second", type: 2, shape: [64], offset: 64 }],
});
add("unaligned-offset", 2, [32], 128, {
  rows: [{ name: "weights", type: 2, shape: [32], offset: 1 }],
  reaAccept: false, nativeAccept: false,
});
add("storage-overflow", 27, ["2305843009213693952"], 0, { reaAccept: false, nativeAccept: false });
add("absolute-offset-overflow", 2, [32], 32, {
  rows: [{ name: "weights", type: 2, shape: [32], offset: "18446744073709551584" }],
  reaAccept: false, nativeAccept: false,
});

function fixture(item) {
  const chunks = [Buffer.from("GGUF")];
  const integer = (value, length) => {
    const data = Buffer.alloc(length);
    if (length === 4) item.little ? data.writeUInt32LE(Number(value)) : data.writeUInt32BE(Number(value));
    else item.little ? data.writeBigUInt64LE(BigInt(value)) : data.writeBigUInt64BE(BigInt(value));
    chunks.push(data);
  };
  const string = (value) => { const data = Buffer.from(value); integer(data.length, 8); chunks.push(data); };
  integer(3, 4); integer(item.rows.length, 8); integer(2, 8);
  for (const [key, value] of [["general.quantization_version", 2], ["general.file_type", 7]]) {
    string(key); integer(4, 4); integer(value, 4);
  }
  for (const row of item.rows) {
    string(row.name); integer(row.shape.length, 4);
    for (const dim of row.shape) integer(dim, 8);
    integer(row.type, 4); integer(row.offset, 8);
  }
  const header = Buffer.concat(chunks);
  const dataOffset = Math.ceil(header.length / 32) * 32;
  const payload = Buffer.alloc(item.size);
  for (let i = 0; i < payload.length; i++) payload[i] = i & 255;
  return Buffer.concat([header, Buffer.alloc(dataOffset - header.length), payload]);
}
const normalizeType = (type) => type.replace(/^UNKNOWN_/, "GGML_TYPE_");
function projectRea(value) {
  return { version: value.version, byte_order: value.byte_order, tensor_data_offset: value.tensor_data_offset,
    rows: value.tensors.map((row) => ({ name: row.name, dtype: normalizeType(row.type), type_id: row.type_id,
      shape: row.shape, elements: row.parameter_count, file_offset: row.file_offset, byte_length: row.byte_length,
      storage_length_verified: row.storage_validation === "consistent" })) };
}
function projectNative(value) {
  return { version: value.format_version, byte_order: value.byte_order, tensor_data_offset: value.tensor_data_offset,
    rows: value.result.rows.map((row) => ({ name: row.name, dtype: row.dtype, type_id: row.type_id,
      shape: row.shape, elements: row.elements, file_offset: row.file_offset, byte_length: row.byte_length,
      storage_length_verified: row.storage_length_verified })) };
}
async function oracle(path, size) {
  const file = await open(path, "r");
  try {
    const reader = new ModelHeaderReader(file, size, undefined);
    if ((await reader.take(4)).toString("ascii") !== "GGUF") throw new Error("bad fixture");
    const parsed = await new GgufHeader(reader).read();
    await reader.finish(false);
    return { accepted: true, projection: projectRea(parsed) };
  } catch (error) {
    return { accepted: false, kind: error.kind ?? error.name, message: String(error.message).slice(0, 800) };
  } finally { await file.close(); }
}
async function native(path) {
  const fd = openSync(path, "r");
  try {
    const request = JSON.stringify({ operation: "inspect", collection: "tensors", offset: 0, limit: 256 });
    const result = await runModelWorker(options.native, ["rea-model-worker", "--request", request], fd);
    const lifecycle = result.lifecycle;
    if (result.error) return { accepted: false, harness_failure: result.error, lifecycle };
    if (result.signal) return { accepted: false, harness_failure: { kind: "native_signal", message: result.signal }, lifecycle };
    if (result.status !== 0) return { accepted: false, status: result.status, message: result.stderr.slice(0, 800), lifecycle };
    try {
      return { accepted: true, projection: projectNative(JSON.parse(result.stdout)), lifecycle };
    } catch (error) {
      return { accepted: false, harness_failure: { kind: "invalid_native_reply", message: String(error.message) }, lifecycle };
    }
  } finally { closeSync(fd); }
}
const results = [];
for (const item of cases) {
  const bytes = fixture(item);
  const path = join(options.work, item.name + ".gguf");
  await writeFile(path, bytes, { flag: "wx" });
  const rea = await oracle(path, bytes.length);
  const actual = options.native ? await native(path) : null;
  const reasons = [];
  if (actual?.harness_failure) reasons.push("native harness failed: " + actual.harness_failure.kind);
  if (rea.accepted !== item.reaAccept) reasons.push("oracle acceptance differed from fixture expectation");
  if (actual && actual.accepted !== item.nativeAccept) reasons.push("native acceptance differed from fixture expectation");
  if (actual?.accepted && rea.accepted && JSON.stringify(actual.projection) !== JSON.stringify(rea.projection))
    reasons.push("successful semantic projections differ");
  results.push({ name: item.name, fixture_sha256: hash(bytes), fixture_bytes: bytes.length,
    expected: { rea_accept: item.reaAccept, native_accept: item.nativeAccept },
    intentional_difference: item.intentionalDifference ?? null, rea, native: actual, failures: reasons });
  if (actual?.harness_failure) break;
}
const failures = results.filter((row) => row.failures.length > 0);
const summary = {
  classification: "bounded_model_layout_differential_not_complete_rea_qualification",
  oracle_version: packageJson.version, oracle_module_sha256: expectedModules,
  native_binary_sha256: nativeBinarySha256,
  planned_cases: cases.length, cases: results.length, oracle_accepted: results.filter((row) => row.rea.accepted).length,
  native_executed: options.native !== undefined,
  native_lifecycle_scope: options.native ? "linux_owned_process_group" : null,
  harness_failures: results.filter((row) => row.native?.harness_failure).length,
  mismatches: options.native ? failures.length : null,
  expectation_failures: failures.length, intentional_differences: results.filter((row) => row.intentional_difference).length,
};
if (options.out) await writeFile(options.out, JSON.stringify({ summary, results }, null, 2) + "\n", { flag: "wx" });
console.log(JSON.stringify(summary, null, 2));
if (failures.length) { console.error(JSON.stringify(failures, null, 2)); process.exitCode = 1; }
