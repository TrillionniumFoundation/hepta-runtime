// Copyright 2026 TrillionniumFoundation
//
// Licensed under the Apache License, Version 2.0.
// Development-only REA npm reference oracle: records the actual MCP tool
// catalog of the exact pinned upstream release. Never runs in the Rust runtime.

import { createHash } from "node:crypto";
import { spawn, spawnSync } from "node:child_process";
import { createReadStream } from "node:fs";
import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { createInterface } from "node:readline";

const [prefix, output, archiveDirectory] = process.argv.slice(2);
if (!prefix || !output || !archiveDirectory) {
  throw new Error("expected: prefix output-directory npm-pack-directory");
}
await mkdir(output, { recursive: true });

const packageRoot = join(prefix, "node_modules", "rea-agents");
const manifest = JSON.parse(await readFile(join(packageRoot, "package.json"), "utf8"));
if (manifest.name !== "rea-agents" || manifest.version !== "6.8.0") {
  throw new Error("reference package is not rea-agents@6.8.0");
}

const archives = (await readdir(archiveDirectory)).filter((name) => name.endsWith(".tgz"));
if (archives.length !== 1) throw new Error("need one exact npm pack archive");
const archiveHash = createHash("sha256");
await new Promise((resolve, reject) => {
  const stream = createReadStream(join(archiveDirectory, archives[0]));
  stream.on("data", (chunk) => archiveHash.update(chunk));
  stream.on("end", resolve);
  stream.on("error", reject);
});

const child = spawn(process.execPath, [join(packageRoot, "scripts", "rea.mjs"), "mcp"], {
  cwd: packageRoot,
  env: {
    ...process.env,
    REA_MCP_INPUT_SCHEMA_PROFILE: "compact",
    REA_MCP_OUTPUT_SCHEMA_PROFILE: "full",
  },
  stdio: ["pipe", "pipe", "pipe"],
});
let stderr = "";
child.stderr.setEncoding("utf8");
child.stderr.on("data", (chunk) => {
  stderr = (stderr + chunk).slice(-65536);
});
let failed = null;
const pending = new Map();
const resolvePendingError = (cause) => {
  failed = cause;
  for (const slot of pending.values()) slot.reject(cause);
  pending.clear();
};
child.on("error", resolvePendingError);
child.on("exit", (code, signal) => {
  if (!failed) resolvePendingError(new Error("REA MCP exited: " + code + " " + signal + ": " + stderr));
});
const reader = createInterface({ input: child.stdout, crlfDelay: Infinity });
reader.on("line", (line) => {
  if (line.length > 32 * 1024 * 1024) {
    resolvePendingError(new Error("MCP response line exceeded 32 MiB"));
    child.kill("SIGKILL");
    return;
  }
  let msg;
  try { msg = JSON.parse(line); } catch (error) {
    resolvePendingError(new Error("malformed MCP output: " + String(error)));
    return;
  }
  if (msg.id === undefined || !pending.has(msg.id)) return;
  const slot = pending.get(msg.id);
  pending.delete(msg.id);
  if (msg.error) slot.reject(new Error(JSON.stringify(msg.error)));
  else slot.resolve(msg.result);
});

let serial = 0;
function request(method, params) {
  if (failed) return Promise.reject(failed);
  const id = ++serial;
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      pending.delete(id);
      reject(new Error("REA MCP timed out on " + method + "; stderr: " + stderr));
    }, 90000);
    pending.set(id, {
      resolve: (result) => { clearTimeout(timeout); resolve(result); },
      reject: (error) => { clearTimeout(timeout); reject(error); },
    });
    child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
  });
}
function notify(method) {
  child.stdin.write(JSON.stringify({ jsonrpc: "2.0", method, params: {} }) + "\n");
}

let result;
try {
  const initialized = await request("initialize", {
    protocolVersion: "2025-11-25",
    capabilities: {},
    clientInfo: { name: "hepta-rea-oracle", version: "0.1.0" },
  });
  notify("notifications/initialized");
  const tools = [];
  let cursor = undefined;
  let pages = 0;
  do {
    const response = await request("tools/list", cursor ? { cursor } : {});
    if (!Array.isArray(response?.tools)) {
      throw new Error("REA MCP tools/list returned no tools array");
    }
    tools.push(...response.tools);
    cursor = response.nextCursor ?? response.next_cursor ?? undefined;
    if (++pages > 32) throw new Error("catalog exceeded 32 pages");
  } while (cursor);
  const toolNames = tools.map((tool) => tool.name);
  if (tools.length < 50 || toolNames.some((name) => typeof name !== "string")) {
    throw new Error("suspicious REA MCP tool catalog");
  }
  if (new Set(toolNames).size !== tools.length) {
    throw new Error("duplicate REA tool names");
  }
  const pinned = JSON.parse(await readFile(
    join(process.env.GITHUB_WORKSPACE ?? ".", "docs", "rea-native", "PUBLISHED_6_8_0_ORACLE.json"),
    "utf8",
  ));
  for (const [key, observed] of [
    ["tarballSha256", archiveHash.copy().digest("hex")],
  ]) {
    if (pinned[key] !== observed) throw new Error("REA published release drift: " + key);
  }
  const manifestResult = {
    source: "npm registry rea-agents@6.8.0",
    sourceGitCommitEqualToNpmArchive: "unverified",
    npmTarballFilename: archives[0],
    npmTarballSha256: archiveHash.digest("hex"),
    packageVersion: manifest.version,
    mcpServerName: initialized.serverInfo?.name ?? null,
    negotiatedProtocol: initialized.protocolVersion ?? null,
    schemaProfile: { input: "compact", output: "full" },
    toolCount: tools.length,
    catalogSha256: createHash("sha256").update(JSON.stringify(tools)).digest("hex"),
    toolNamesSha256: createHash("sha256").update(JSON.stringify(toolNames)).digest("hex"),
    limitations: [
      "MCP contract snapshot uses compact input and full output schemas",
      "The npm tarball has not been proven byte-equivalent to the Git source commit",
      "This does not exercise Ghidra/IDA/Hopper, browser or device providers",
    ],
  };
  for (const [key, expectedKey] of [
    ["toolCount", "toolCount"],
    ["catalogSha256", "catalogSha256"],
    ["toolNamesSha256", "toolNamesSha256"],
  ]) {
    if (manifestResult[key] !== pinned[expectedKey]) {
      throw new Error("REA published MCP catalog drift: " + key);
    }
  }
  await writeFile(join(output, "REA_6_8_0_MCP_CATALOG.full-output.json"), JSON.stringify(tools, null, 2) + "\n");
  await writeFile(join(output, "REA_6_8_0_REFERENCE_MANIFEST.json"), JSON.stringify(manifestResult, null, 2) + "\n");
  result = manifestResult;
} finally {
  child.stdin.end();
  child.kill("SIGTERM");
}
// Produce an authentic REA 6.8.0 Evidence record from a real Linux artifact.
// This is separate from MCP tools/list and does not require Ghidra or Hopper.
const cli = join(packageRoot, "scripts", "rea.mjs");
const native = spawnSync(process.execPath, [cli, "inspect-elf-notes", "/usr/bin/true", "--json"], {
  cwd: packageRoot,
  env: process.env,
  encoding: "utf8",
  timeout: 120000,
  maxBuffer: 32 * 1024 * 1024,
});
if (native.error || native.status !== 0) {
  throw new Error("REA CLI fixture failed: " + String(native.error ?? native.stderr));
}
let payload;
try {
  payload = JSON.parse(native.stdout);
} catch (error) {
  throw new Error("REA CLI fixture is not JSON: " + String(error) + ", start=" + native.stdout.slice(0, 400));
}
function locateEvidence(value, remaining = 5) {
  if (remaining <= 0 || value === null || typeof value !== "object") return undefined;
  if (typeof value.evidence_id === "string" && value.normalized_result !== undefined && value.provider !== undefined) return value;
  for (const name of ["result", "evidence", "data", "output", "observation"]) {
    const candidate = locateEvidence(value[name], remaining - 1);
    if (candidate) return candidate;
  }
  return undefined;
}
const reference = locateEvidence(payload);
if (!reference) {
  throw new Error("REA CLI fixture did not include canonical Evidence: " + Object.keys(payload).join(","));
}
await writeFile(join(output, "REA_6_8_0_ELF_NOTES_EVIDENCE.json"), JSON.stringify(reference, null, 2) + "\n");
console.log(JSON.stringify({ ...result, actualEvidenceId: reference.evidence_id, fixtureOperation: reference.operation }));

