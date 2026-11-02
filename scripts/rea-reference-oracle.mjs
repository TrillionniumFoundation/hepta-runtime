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
const inputProfile = process.env.REA_ORACLE_INPUT_PROFILE ?? "compact";
const outputProfile = process.env.REA_ORACLE_OUTPUT_PROFILE ?? "full";
if (!["compact", "full"].includes(inputProfile) || !["full", "off"].includes(outputProfile)) {
  throw new Error("invalid pinned REA oracle schema profile");
}

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
    REA_MCP_INPUT_SCHEMA_PROFILE: inputProfile,
    REA_MCP_OUTPUT_SCHEMA_PROFILE: outputProfile,
  },
  stdio: ["pipe", "pipe", "pipe"],
});
let stderr = "";
child.stderr.setEncoding("utf8");
child.stderr.on("data", (chunk) => {
  stderr = (stderr + chunk).slice(-65536);
});
class RpcFailure extends Error {
  constructor(envelope) {
    super("REA MCP JSON-RPC error: " + JSON.stringify(envelope.error));
    this.name = "RpcFailure";
    this.envelope = envelope;
  }
}
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
  if (msg.error) slot.reject(new RpcFailure(msg));
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
function notify(method, params = {}) {
  child.stdin.write(JSON.stringify({ jsonrpc: "2.0", method, params }) + "\n");
}

// Do not turn an upstream JSON-RPC error into a string or confuse it with a
// tool-result rejection. Transport failure, timeout and unexpected success
// must abort reference capture instead of being accepted as a golden error.
async function captureRejection(method, params, description) {
  try {
    const returned = await request(method, params);
    if (returned?.isError !== true) {
      throw new Error("REA MCP unexpectedly accepted " + description);
    }
    return { delivery: "tool-result", raw: returned };
  } catch (error) {
    if (error instanceof RpcFailure) {
      return { delivery: "json-rpc-error", raw: error.envelope };
    }
    throw error;
  }
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
  // Preserve actual upstream typed errors and transport vs tool-result
  // delivery without regex-based reinterpretation or invented error codes.
  const invalidPathResponse = await captureRejection("tools/call", {
    name: "inspect_rust_binary",
    arguments: { path: "rea-oracle-relative-path.must-be-refused" },
  }, "a relative path");
  const missingPathResponse = await captureRejection("tools/call", {
    name: "inspect_rust_binary",
    arguments: {},
  }, "an omitted required path");
  const missingToolResponse = await captureRejection("tools/call", {
    name: "hepta_rea_oracle_not_an_upstream_tool",
    arguments: {},
  }, "an unknown tool name");
  const unknownMethodResponse = await captureRejection(
    "hepta_rea_oracle/nonexistent_method", {}, "an unknown MCP method",
  );
  // Test that the session survives refused calls and an irrelevant
  // cancellation notification. No in-flight cancellation is proven here.
  const firstPage = tools.slice(0, 1).map((tool) => tool.name);
  const afterErrors = await request("tools/list", {});
  if (JSON.stringify(afterErrors?.tools?.slice(0, 1).map((t) => t.name)) !== JSON.stringify(firstPage)) {
    throw new Error("REA MCP catalog/session changed after rejected calls");
  }
  notify("notifications/cancelled", {
    requestId: 999999999,
    reason: "oracle probe: no outstanding request",
  });
  const afterCancellationNotification = await request("tools/list", {});
  if (JSON.stringify(afterCancellationNotification?.tools?.slice(0, 1).map((t) => t.name)) !== JSON.stringify(firstPage)) {
    throw new Error("REA MCP session lost after irrelevant cancellation notification");
  }
  const protocolTrace = {
    fixture: "rea-agents@6.8.0 MCP initial session / error envelopes",
    schemaProfile: { input: inputProfile, output: outputProfile },
    initializedResponse: initialized,
    initializedNotificationSent: true,
    rejections: {
      relativePath: invalidPathResponse,
      missingPath: missingPathResponse,
      unknownTool: missingToolResponse,
      unknownMethod: unknownMethodResponse,
    },
    sessionContinuation: {
      listAfterRejections: true,
      irrelevantCancellationNotificationSent: true,
      listAfterIrrelevantCancellation: true,
      actualInFlightCancellationQualified: false,
    },
  };
  if (JSON.stringify(protocolTrace).length > 256 * 1024 || JSON.stringify(invalidPathResponse).length > 65536) {
    throw new Error("REA MCP protocol/error oracle exceeded fixture byte budget");
  }
  await writeFile(
    join(output, "REA_6_8_0_INVALID_PATH_MCP_NEGATIVE.json"),
    JSON.stringify(invalidPathResponse, null, 2) + "\n",
  );
  await writeFile(
    join(output, "REA_6_8_0_PROTOCOL_AND_ERRORS.json"),
    JSON.stringify(protocolTrace, null, 2) + "\n",
  );
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
    schemaProfile: { input: inputProfile, output: outputProfile },
    toolCount: tools.length,
    catalogSha256: createHash("sha256").update(JSON.stringify(tools)).digest("hex"),
    toolNamesSha256: createHash("sha256").update(JSON.stringify(toolNames)).digest("hex"),
    limitations: [
      "MCP schema catalog is scoped to the recorded input/output profile",
      "The npm tarball has not been proven byte-equivalent to the Git source commit",
      "This does not exercise Ghidra/IDA/Hopper, browser or device providers",
    ],
  };
  for (const [key, expectedKey] of [
    ["toolCount", "toolCount"],
    ...(inputProfile === "compact" && outputProfile === "full" ? [["catalogSha256", "catalogSha256"]] : []),
    ...(inputProfile === "full" && outputProfile === "off" ? [["catalogSha256", "fullInputCatalogSha256"]] : []),
    ["toolNamesSha256", "toolNamesSha256"],
  ]) {
    if (manifestResult[key] !== pinned[expectedKey]) {
      throw new Error("REA published MCP catalog drift: " + key);
    }
  }
  await writeFile(join(output, "REA_6_8_0_MCP_CATALOG." + inputProfile + "-input." + outputProfile + "-output.json"), JSON.stringify(tools, null, 2) + "\n");
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

