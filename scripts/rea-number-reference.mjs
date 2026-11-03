// Copyright 2026 TrillionniumFoundation
// Licensed under Apache-2.0.
// Independent, REAL published rea-agents@6.8.0 Evidence number corpus.
// Only CI uses Node; the shipped native REA subset has no Node dependency.

import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const [npmPrefix, output] = process.argv.slice(2);
if (!npmPrefix || !output) {
  throw new Error("expected: installed rea-agents npm prefix, evidence output directory");
}
const root = join(npmPrefix, "node_modules", "rea-agents");
const pkg = JSON.parse(await readFile(join(root, "package.json"), "utf8"));
if (pkg.name !== "rea-agents" || pkg.version !== "6.8.0") {
  throw new Error("pinned published REA package drift");
}
const evidenceModule = await import(pathToFileURL(join(root, "dist/domain/evidence.js")).href);
const profileModule = await import(pathToFileURL(join(root, "dist/domain/analysisProfile.js")).href);
if (typeof evidenceModule.createEvidence !== "function"
  || typeof evidenceModule.parseEvidence !== "function"
  || typeof profileModule.createAnalysisProfile !== "function") {
  throw new Error("published npm 6.8.0 Evidence/profile API is unavailable");
}
const { createEvidence, parseEvidence } = evidenceModule;
const { createAnalysisProfile } = profileModule;
const provider = { id: "hepta-rea-numeric-oracle", name: "Real published REA 6.8.0", version: "6.8.0" };

// Include every ECMAScript exponential/fixed notation boundary, -0,
// subnormal/normal extremes, fractional rounding and signed values. All
// values are JS Number objects, not manually forged digest strings.
const samples = [
  -0, 0, 1, -1, 0.25, -0.25, 1.5, -1.5,
  1e-7, -1e-7, 1e-6, -1e-6, 1.2345e-6, 1e-5, 1e20, 1e21,
  1e22, -1e22, 1.2345678901234567, 1000000000000000100,
  Number.MAX_VALUE, Number.MIN_VALUE, Number.MIN_SAFE_INTEGER,
  Number.MAX_SAFE_INTEGER, 9007199254740992, -9007199254740992,
  1.7976931348623155e308, 2.2250738585072014e-308,
  2.225073858507201e-308, 4.9406564584124654e-324,
  0.0000009999999999999999, 9.999999999999998e20,
];

// Reproducible bit-pattern corpus; finite values only. Broadens coverage
// beyond handpicked decimal edge cases, without nondeterministic Math.random.
const bits = new DataView(new ArrayBuffer(8));
let state = 0x243f6a8885a308d3n;
const mask = (1n << 64n) - 1n;
for (let i = 0; i < 384; i++) {
  state = (state * 6364136223846793005n + 1442695040888963407n) & mask;
  bits.setBigUint64(0, state, false);
  const candidate = bits.getFloat64(0, false);
  if (Number.isFinite(candidate)) samples.push(candidate);
}

const cases = samples.map((value, index) => {
  const parameters = {
    index,
    decimal: value,
    nested: [{ "𐀀": value, "": -value }, 1.23e-7],
  };
  const analysisProfile = createAnalysisProfile(provider, {
    numeric: value,
    array: [value, value === 0 ? -0 : value],
  });
  const relationshipCoverage = index % 3 === 0
    ? { status: "unknown", reason: "no caller-callee analysis performed" }
    : index % 3 === 1
      ? { status: "partial", limitations: ["numeric fixture only"], limited_directions: ["callers"] }
      : { status: "complete" };
  const evidence = createEvidence(undefined, provider, {
    operation: "hepta_number_golden_fixture",
    parameters,
    result: {
      number: value,
      negative: -value,
      fixedAndExponent: [1e-6, 1e-7, 1e20, 1e21],
    },
    rawResult: { inputNumber: value },
    analysisProfile,
    relationshipCoverage,
    confidence: "derived",
    authority: "controlled-replay",
  });
  // An upstream-generated record must parse under upstream's full Zod +
  // digest semantics before it can be used as a Rust comparison fixture.
  const authenticated = parseEvidence(evidence);
  if (authenticated.evidence_id !== evidence.evidence_id) {
    throw new Error("published REA Evidence failed upstream re-verification");
  }
  return evidence;
});
// This is a real upstream-schema edge: ordinary providerSchema.version is
// z.string().nullable() (empty string is valid), while committed profile
// versions require a nonempty string. The previous Rust verifier incorrectly
// rejected the valid empty-string ordinary Evidence provider.
for (const version of ["", null]) {
  const variantProvider = { ...provider, version };
  const evidence = createEvidence(undefined, variantProvider, {
    operation: "hepta_provider_version_nullable_or_empty",
    parameters: { source: "published-reasoned-schema-differential", variant: version },
    result: { providerVersion: version, unknown: true },
    relationshipCoverage: { status: "unknown", reason: "provider version not committed" },
    authority: "controlled-replay",
  });
  const parsed = parseEvidence(evidence);
  if (parsed.evidence_id !== evidence.evidence_id) {
    throw new Error("published REA provider-version fixture failed authentication");
  }
  if (parsed.provider.version !== version || parsed.analysis_profile !== null) {
    throw new Error("published REA provider-version schema drift");
  }
  cases.push(evidence);
}

const encoded = JSON.stringify({ cases });
const checksum = createHash("sha256").update(encoded).digest("hex");
await mkdir(output, { recursive: true });
await writeFile(join(output, "REA_6_8_0_FINITE_NUMBER_EVIDENCE.json"), encoded + "\n");
await writeFile(join(output, "REA_6_8_0_FINITE_NUMBER_MANIFEST.json"),
  JSON.stringify({
    package: "rea-agents@6.8.0",
    source: "published compiled dist/domain/evidence.js and analysisProfile.js",
    cases: cases.length,
    corpusSha256: checksum,
    allVerifiedByUpstreamParseEvidence: true,
    qualification: "finite JS Number samples only; no claim of all IEEE-754 bit patterns",
  }, null, 2) + "\n");
console.log(JSON.stringify({ package: pkg.version, cases: cases.length, corpusSha256: checksum }));
