// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
// Independent ECMAScript finite-f64 oracle. Node is verification-only:
// production Evidence rendering remains native Rust with existing dependencies.

import { createHash } from "node:crypto";
import { closeSync, mkdirSync, openSync, readFileSync, writeFileSync, writeSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const [output, countText = "1000000"] = process.argv.slice(2);
const randomCount = Number(countText);
if (!output || !Number.isSafeInteger(randomCount) || randomCount < 1000000 || randomCount > 2000000) {
  throw new Error("expected: output directory, deterministic random count in 1000000..2000000");
}
mkdirSync(output, { recursive: true });
const corpusPath = join(output, "number-cases.tsv");
const fd = openSync(corpusPath, "wx", 0o600);
const digest = createHash("sha256");
const view = new DataView(new ArrayBuffer(8));
const mask = (1n << 64n) - 1n;
const sign = 1n << 63n;
const seed = 0x7265615f65766964n;
const groups = {};
let pending = "";
let count = 0;

function flush() {
  if (pending.length === 0) return;
  const bytes = Buffer.from(pending, "utf8");
  let offset = 0;
  while (offset < bytes.length) offset += writeSync(fd, bytes, offset);
  digest.update(bytes);
  pending = "";
}
function emit(bits, group) {
  if (bits < 0n || bits > mask) return;
  const stats = groups[group] ??= { candidates: 0, finite: 0, nonfinite: 0 };
  stats.candidates++;
  view.setBigUint64(0, bits, false);
  const value = view.getFloat64(0, false);
  if (!Number.isFinite(value)) {
    stats.nonfinite++;
    return;
  }
  stats.finite++;
  count++;
  pending += bits.toString(16).padStart(16, "0") + "\t" + JSON.stringify(value) + "\n";
  if (pending.length >= 65536) flush();
}
function pattern(value) {
  view.setFloat64(0, value, false);
  return view.getBigUint64(0, false);
}

// Fixed golden checks keep source-parser, normal/subnormal, exponent notation,
// signed-zero and integer boundaries visible alongside the broad bit corpus.
const golden = [
  [0, "0"], [-0, "0"], [Number.MIN_VALUE, "5e-324"],
  [-Number.MIN_VALUE, "-5e-324"],
  [2.2250738585072014e-308, "2.2250738585072014e-308"],
  [Number.MAX_VALUE, "1.7976931348623157e+308"],
  [1.7976931348623155e308, "1.7976931348623155e+308"],
  [1e-7, "1e-7"], [1e-6, "0.000001"],
  [1e20, "100000000000000000000"], [1e21, "1e+21"],
  [Number.MAX_SAFE_INTEGER, "9007199254740991"],
  [9007199254740992, "9007199254740992"],
  [1000000000000000100, "1000000000000000100"],
];
for (const [value, expected] of golden) {
  if (JSON.stringify(value) !== expected) throw new Error("ECMAScript golden boundary drift");
  for (let delta = -4n; delta <= 4n; delta++) emit(pattern(value) + delta, "golden-neighborhoods");
}

const halfway = [
  0x431548edc45ad881n, 0xc3131d83683658a5n, 0xc314a7f221ea6ee5n,
  0x4310f1159b355b9dn, 0xc3000de31410933an, 0x43161a0e6838e059n,
  0x431c51edfab4dc31n, 0xc2d0d487f5769dc8n, 0xc31c8d8d5c4241a9n,
  0x42e76a82d3067b24n, 0x430024c84a510a02n, 0xc31dc0166e78dda5n,
  0xc301b7eeb7a0ff62n, 0xc30beb217b58f1ban, 0x42ebb09c50bda664n,
  0x43049b79d59c95ean, 0xc2e2f1fa060e6094n, 0xc2eadc9bc03b1c54n,
  0x4315bcbf587d05adn, 0xc31c512513a696a9n,
];
for (const bits of halfway) {
  for (let delta = -4n; delta <= 4n; delta++) {
    emit(bits + delta, "halfway-neighborhoods");
    emit((bits ^ sign) + delta, "halfway-neighborhoods");
  }
}

// Exercise every finite binary exponent with mantissas around both rounding
// boundaries, as well as both signs; candidates are intentionally not deduped.
const mantissas = [0n, 1n, 2n, 3n, 0x3ffffffffffffn, 0x7ffffffffffffn,
  0x8000000000000n, 0x8000000000001n, 0xffffffffffffen, 0xfffffffffffffn];
for (let exponent = 0n; exponent <= 2046n; exponent++) {
  for (const mantissa of mantissas) {
    const bits = (exponent << 52n) | mantissa;
    emit(bits, "binary-exponents");
    emit(bits | sign, "binary-exponents");
  }
}
for (let exponent = -323; exponent <= 308; exponent++) {
  const bits = pattern(10 ** exponent);
  for (let delta = -4n; delta <= 4n; delta++) {
    emit(bits + delta, "decimal-power-neighborhoods");
    emit((bits ^ sign) + delta, "decimal-power-neighborhoods");
  }
}
let state = seed;
for (let index = 0; index < randomCount; index++) {
  state ^= (state << 13n) & mask;
  state ^= state >> 7n;
  state ^= (state << 17n) & mask;
  emit(state, "xorshift64");
}
flush();
closeSync(fd);
const manifest = {
  schema: "hepta.rea.ecmascript-number-oracle.v1",
  generator_sha256: createHash("sha256").update(readFileSync(fileURLToPath(import.meta.url))).digest("hex"),
  node: process.versions.node,
  v8: process.versions.v8,
  reference: "ECMAScript JSON.stringify on DataView-selected IEEE-754 binary64 values",
  seed: seed.toString(16).padStart(16, "0"),
  random_count: randomCount,
  finite_cases: count,
  deduplicated: false,
  groups,
  corpus: "number-cases.tsv",
  corpus_sha256: digest.digest("hex"),
  qualification: "Finite sampled values and explicit neighborhoods; not exhaustive IEEE-754 or full REA compatibility",
};
writeFileSync(join(output, "number-oracle-manifest.json"), JSON.stringify(manifest, null, 2) + "\n");
console.log(JSON.stringify(manifest));
