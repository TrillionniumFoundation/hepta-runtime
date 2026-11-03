// Copyright 2026 TrillionniumFoundation
//
// Licensed under the Apache License, Version 2.0.
// Development-only provenance comparator. This is *not* a build equivalence
// proof: npm can publish compiled/minified outputs absent from the Git tree.

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

const [sourceRepo, prefix, output] = process.argv.slice(2);
if (!sourceRepo || !prefix || !output) {
  throw new Error("expected: pinned-git-directory installed-npm-prefix output-directory");
}
const pinnedCommit = "93b8b82db70279e40f484114cff9dc1958dc14ee";
const head = execFileSync("git", ["-C", sourceRepo, "rev-parse", "HEAD"], {
  encoding: "utf8",
}).trim();
if (head !== pinnedCommit) throw new Error("upstream Git source commit drift");
const sourceNames = new Set(execFileSync("git", [
  "-C", sourceRepo, "ls-tree", "-r", "--name-only", "HEAD",
], { encoding: "utf8", maxBuffer: 16 * 1024 * 1024 }).trimEnd().split("\n"));
const npmRoot = join(prefix, "node_modules", "rea-agents");
const npmManifest = JSON.parse(await readFile(join(npmRoot, "package.json"), "utf8"));
const sourceManifest = JSON.parse(execFileSync("git", [
  "-C", sourceRepo, "show", "HEAD:package.json",
], { encoding: "utf8", maxBuffer: 4 * 1024 * 1024 }));
if (npmManifest.name !== "rea-agents" || npmManifest.version !== "6.8.0"
  || sourceManifest.version !== "6.8.0") {
  throw new Error("unexpected upstream Git/npm package identity");
}
const sha = (bytes) => createHash("sha256").update(bytes).digest("hex");
const fingerprint = (bytes) => ({
  sha256: sha(bytes), size: bytes.length,
});
const observed = [];
for (const relative of [
  "package.json",
  "scripts/rea.mjs",
  "src/domain/evidence.ts",
  "src/domain/canonicalDigest.ts",
  "src/domain/canonicalJsonDigestSteps.ts",
  "src/domain/analysisProfile.ts",
  "src/domain/relationshipCoverage.ts",
  "src/domain/evidenceSubject.ts",
  "src/contracts/toolFamilyIds.ts",
]) {
  const source = sourceNames.has(relative)
    ? execFileSync("git", ["-C", sourceRepo, "show", "HEAD:" + relative],
      { maxBuffer: 4 * 1024 * 1024 }) : null;
  let published = null;
  try {
    published = await readFile(join(npmRoot, relative));
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  observed.push({
    relativePath: relative,
    git: source === null ? null : fingerprint(source),
    npm: published === null ? null : fingerprint(published),
    sameBytes: source !== null && published !== null && source.equals(published),
    status: source === null ? "not-in-source-tree"
      : published === null ? "not-in-published-tree"
      : source.equals(published) ? "byte-identical" : "different-bytes",
  });
}
const matchedFields = {};
for (const key of ["name", "version", "type", "bin", "exports", "main", "module"]) {
  const gitValue = sourceManifest[key] ?? null;
  const npmValue = npmManifest[key] ?? null;
  matchedFields[key] = {
    git: gitValue,
    npm: npmValue,
    equal: JSON.stringify(gitValue) === JSON.stringify(npmValue),
  };
}
const result = {
  schema: "hepta.rea.git-npm-provenance.v1",
  gitRepository: "morluto/rea",
  gitCommit: head,
  publishedPackage: "rea-agents@6.8.0",
  packageMetadata: matchedFields,
  selectedSamePathFiles: observed,
  sourceEqualsPublished: "NOT ESTABLISHED",
  limitations: [
    "Only explicitly listed paths are compared, not npm export resolution or all generated JavaScript",
    "A source-only or published-only file does not prove behavioral incompatibility",
    "Exact tool behavior and provider-dependent implementations need independent differential fixtures",
  ],
};
await writeFile(join(output, "REA_6_8_0_GIT_VS_NPM_FILES.json"), JSON.stringify(result, null, 2) + "\n");
console.log(JSON.stringify({
  gitCommit: head,
  samePaths: observed.filter((f) => f.status === "byte-identical").length,
  differentPaths: observed.filter((f) => f.status === "different-bytes").length,
  sourceOnlyPaths: observed.filter((f) => f.status === "not-in-published-tree").length,
  publishedOnlyPaths: observed.filter((f) => f.status === "not-in-source-tree").length,
}));
