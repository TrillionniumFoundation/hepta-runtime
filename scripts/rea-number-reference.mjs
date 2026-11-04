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
// Independent 2026-11-04 bit-pattern differential exposed shortest-decimal
// halfway ties missed by the historical 418-record corpus. Rust Display used
// the upper decimal; ECMAScript chooses the even decimal significand. Keep
// these in the real npm producer corpus as well as the small Rust regression.
const halfwayBits = [
  0x431548edc45ad881n, 0xc3131d83683658a5n, 0xc314a7f221ea6ee5n,
  0x4310f1159b355b9dn, 0xc3000de31410933an, 0x43161a0e6838e059n,
  0x431c51edfab4dc31n, 0xc2d0d487f5769dc8n, 0xc31c8d8d5c4241a9n,
  0x42e76a82d3067b24n, 0x430024c84a510a02n, 0xc31dc0166e78dda5n,
  0xc301b7eeb7a0ff62n, 0xc30beb217b58f1ban, 0x42ebb09c50bda664n,
  0x43049b79d59c95ean, 0xc2e2f1fa060e6094n, 0xc2eadc9bc03b1c54n,
  0x4315bcbf587d05adn, 0xc31c512513a696a9n,
];
for (const pattern of halfwayBits) {
  bits.setBigUint64(0, pattern, false);
  samples.push(bits.getFloat64(0, false));
}
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

// Independently classify invalid *upstream* Evidence schemas while keeping
// semantic IDs recomputed for each malformed record. Rust cannot pass this
// gate simply by rejecting stale IDs: upstream's Zod must reject first, and
// the Rust verifier must reject each hash-consistent invalid record.
const canonicalModule = await import(pathToFileURL(join(root, "dist/domain/canonicalDigest.js")).href);
const { digestCanonicalValue } = canonicalModule;
const { evidenceSemanticContent } = evidenceModule;
if (typeof digestCanonicalValue !== "function" || typeof evidenceSemanticContent !== "function") {
  throw new Error("published npm canonical Evidence projection unavailable");
}
const invalidSchemaCases = [];
function mustRejectUpstream(label, mutate, reference = cases[cases.length - 1]) {
  const record = structuredClone(reference);
  mutate(record);
  const { evidence_id: _prior, ...withoutId } = record;
  record.evidence_id = "ev_" + digestCanonicalValue(evidenceSemanticContent(withoutId));
  let rejected = false;
  try {
    parseEvidence(record);
  } catch {
    rejected = true;
  }
  if (!rejected) {
    throw new Error("published REA unexpectedly accepted invalid schema case: " + label);
  }
  invalidSchemaCases.push({ label, record, authenticatedHashButRejectedSchema: true });
}
mustRejectUpstream("provider-version-number", (r) => { r.provider.version = 7; });
mustRejectUpstream("provider-version-boolean", (r) => { r.provider.version = false; });
mustRejectUpstream("unknown-evidence-authority", (r) => { r.authority = "not-authoritative"; });
mustRejectUpstream("unknown-evidence-confidence", (r) => { r.confidence = "maybe"; });
mustRejectUpstream("nonobject-parameters", (r) => { r.parameters = [1, 2]; });
mustRejectUpstream("empty-coverage-reason", (r) => {
  r.relationship_coverage = { status: "unknown", reason: "" };
});
mustRejectUpstream("partial-coverage-empty-limitations", (r) => {
  r.relationship_coverage = { status: "partial", limitations: [] };
});
mustRejectUpstream("empty-coverage-diagnostics", (r) => {
  r.relationship_coverage = { status: "complete", diagnostics: [] };
});
mustRejectUpstream("unknown-coverage-direction", (r) => {
  r.relationship_coverage = { status: "partial", limitations: ["partial"], limited_directions: ["unknown"] };
});
mustRejectUpstream("file-offset-negative", (r) => {
  r.locations = [{ kind: "file-offset", offset: -1 }];
});
mustRejectUpstream("file-offset-fractional", (r) => {
  r.locations = [{ kind: "file-offset", offset: 3.5 }];
});
mustRejectUpstream("file-offset-unsafe-integer", (r) => {
  r.locations = [{ kind: "file-offset", offset: 9007199254740992 }];
});
mustRejectUpstream("invalid-environment-isolation", (r) => {
  r.environment = { id: "env", platform: "linux", architecture: "x86_64", isolation: "root" };
});
mustRejectUpstream("invalid-evidence-link", (r) => {
  r.evidence_links = ["ev_incomplete"];
});
mustRejectUpstream("unexpected-root-field", (r) => { r.injected = "not allowed"; });
mustRejectUpstream("subject-unknown-format", (r) => {
  r.subject = {
    name: "demo", local_path: "/controlled/sample", digest: { sha256: "a".repeat(64) },
    format: "illegal-format", architecture: "x86_64",
  };
});
mustRejectUpstream("subject-raw-only-cpu-on-elf", (r) => {
  r.subject = {
    name: "demo", local_path: "/controlled/sample", digest: { sha256: "a".repeat(64) },
    format: "elf", architecture: "6502",
  };
});
mustRejectUpstream("subject-gamecube-dol-missing-powerpc", (r) => {
  r.subject = {
    name: "demo", local_path: "/controlled/sample", digest: { sha256: "a".repeat(64) },
    format: "gamecube-dol", architecture: null,
  };
});
mustRejectUpstream("profile-empty-committed-provider-version", (r) => {
  r.provider = { id: provider.id, name: provider.name, version: "" };
  r.analysis_profile = {
    provider: r.provider,
    parameters: {},
    digest: digestCanonicalValue({ provider: r.provider, parameters: {} }),
  };
});
mustRejectUpstream("profile-provider-mismatch", (r) => {
  r.analysis_profile = createAnalysisProfile(provider, { issue: "provider mismatch" });
});
await writeFile(join(output, "REA_6_8_0_INVALID_EVIDENCE_SCHEMA.json"),
  JSON.stringify({ cases: invalidSchemaCases }, null, 2) + "\n");

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
