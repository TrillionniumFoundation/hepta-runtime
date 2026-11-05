// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, writeFile, readFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { once } from "node:events";
import { openSync, closeSync } from "node:fs";
import test from "node:test";
import { runModelWorker, modelWorkerFailure, modelWorkerIdentity } from "./rea-model-worker-lifecycle.mjs";

const linux = { skip: process.platform !== "linux", timeout: 7000 };
async function run(code, options = {}) {
  const fd = openSync("/dev/null", "r");
  try { return await runModelWorker(process.execPath, ["-e", code], fd, { timeoutMs: 1200, cleanupMs: 1500, ...options }); }
  finally { closeSync(fd); }
}
function absent(pid) {
  assert.throws(() => process.kill(-pid, 0), (error) => error.code === "ESRCH");
}
function closed(result) {
  assert.equal(result.lifecycle.spawn_observed, true);
  assert.equal(result.lifecycle.exit_observed, true);
  assert.equal(result.lifecycle.close_observed, true);
  assert.equal(result.lifecycle.group_absent_observed, true);
  absent(result.lifecycle.pid); // Independent observation after helper returns.
}

test("model worker success records exit, close and observed group absence", linux, async () => {
  const result = await run("process.stdout.write('ok'); process.stderr.write('note');");
  assert.equal(result.error, null);
  assert.equal(result.status, 0);
  assert.equal(result.stdout, "ok");
  assert.equal(result.stderr, "note");
  closed(result);
});

test("model worker launch error preserves ENOENT without inventing a process group", linux, async () => {
  const fd = openSync("/dev/null", "r");
  let result;
  try { result = await runModelWorker("/definitely-missing-model-worker-" + process.pid, [], fd, { cleanupMs: 100 }); }
  finally { closeSync(fd); }
  assert.equal(result.error.code, "ENOENT");
  assert.equal(result.lifecycle.pid, null);
  assert.equal(result.lifecycle.spawn_observed, false);
  assert.equal(result.lifecycle.close_observed, true);
  assert.equal(result.lifecycle.group_kill_attempted, false);
  assert.equal(result.lifecycle.group_absent_observed, false);
});

test("model worker deadline kills a SIGTERM-resistant worker and preserves timeout", linux, async () => {
  const result = await run("process.on('SIGTERM', () => {}); setInterval(() => {}, 1000);", { timeoutMs: 100 });
  assert.equal(result.error.kind, "timeout");
  assert.equal(result.lifecycle.timed_out, true);
  assert.equal(result.signal, "SIGKILL");
  assert.equal(result.lifecycle.group_kill_sent, true);
  assert.ok(result.lifecycle.elapsed_ms < 3000);
  closed(result);
});

test("model worker output limit terminates the launched group", linux, async () => {
  const result = await run("setInterval(() => process.stdout.write(Buffer.alloc(4096)), 1);", { maxBytes: 128 });
  assert.equal(result.error.kind, "output_limit");
  assert.equal(result.signal, "SIGKILL");
  assert.ok(Buffer.byteLength(result.stdout) <= 128);
  closed(result);
});

test("model worker terminating signal is retained", linux, async () => {
  const result = await run("process.kill(process.pid, 'SIGTERM');");
  assert.equal(result.error, null);
  assert.equal(result.status, null);
  assert.equal(result.signal, "SIGTERM");
  closed(result);
});

test("model worker descendants cannot retain pipes or survive a successful leader; unrelated child survives", linux, async () => {
  const unrelated = spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)"], { stdio: "ignore" });
  const unrelatedExit = once(unrelated, "exit");
  try {
    const result = await run("const {spawn}=require('node:child_process'); const child=spawn(process.execPath,['-e','setInterval(() => {}, 1000)'],{stdio:['ignore',1,2]}); process.stdout.write(String(child.pid)); process.exit(0);");
    assert.equal(result.error, null);
    assert.equal(result.status, 0);
    assert.match(result.stdout, /^\d+$/);
    closed(result);
    assert.equal(process.kill(unrelated.pid, 0), true);
  } finally {
    unrelated.kill("SIGKILL");
    await unrelatedExit;
  }
});

test("model worker rejection requires exit one and the exact expected parser diagnostic", linux, async () => {
  const expected = "GGUF tensor range extends beyond the admitted file";
  for (const [code, diagnostic, kind] of [
    [101, expected, "native_exit"],
    [1, "model worker cannot establish resource limits", "unexpected_native_rejection"],
    [1, expected, null],
  ]) {
    const result = await run("process.stderr.write(" + JSON.stringify("Error: " + diagnostic + "\n") + "); process.exit(" + code + ");");
    closed(result);
    assert.equal(modelWorkerFailure(result, expected)?.kind ?? null, kind);
  }
  const original = { kind: "timeout", code: null, message: "original timeout" };
  assert.equal(modelWorkerFailure({ error: original, signal: "SIGKILL" }, expected), original);
});

test("model worker post-run identity detects an executable changed during launch and read failures", linux, async () => {
  const directory = await mkdtemp(join(process.cwd(), ".model-layout-lifecycle-test-"));
  const binary = join(directory, "owned-worker.cjs");
  try {
    await writeFile(binary, "#!" + process.execPath + "\nrequire('node:fs').appendFileSync(__filename, '\\n// changed during worker\\n');\n", { mode: 0o700 });
    const before = createHash("sha256").update(await readFile(binary)).digest("hex");
    const fd = openSync("/dev/null", "r");
    let result;
    try { result = await runModelWorker(binary, [], fd, { timeoutMs: 1200, cleanupMs: 1500 }); }
    finally { closeSync(fd); }
    assert.equal(result.error, null);
    assert.equal(result.status, 0);
    closed(result);
    const changed = await modelWorkerIdentity(binary, before);
    assert.equal(changed.unchanged, false);
    assert.notEqual(changed.before_sha256, changed.after_sha256);
    assert.equal(changed.error.kind, "native_identity_changed");
    await rm(binary);
    const removed = await modelWorkerIdentity(binary, before);
    assert.equal(removed.error.kind, "native_identity_unreadable");
    assert.equal(removed.error.code, "ENOENT");
  } finally { await rm(directory, { recursive: true, force: true }); }
});
