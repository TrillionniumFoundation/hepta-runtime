// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0

// One Linux process group for the model differential runner; no shell, PID
// matching, or platform-wide cleanup. Escaped sessions are outside this scope.
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { setTimeout as delay } from "node:timers/promises";

export async function runModelWorker(binary, args, fd, {
  timeoutMs = 30000, cleanupMs = 2000, maxBytes = 2 * 1024 * 1024,
} = {}) {
  if (process.platform !== "linux") throw new Error("native model differential lifecycle is qualified only on Linux");
  const started = performance.now();
  const lifecycle = {
    scope: "linux_owned_process_group", pid: null, spawn_observed: false,
    exit_observed: false, close_observed: false, timeout_ms: timeoutMs,
    timed_out: false, interrupted_by: null, exit_code: null, exit_signal: null,
    group_kill_attempted: false, group_kill_sent: false,
    group_absent_observed: false, cleanup_errors: [],
  };
  let child, deadline, cleanupTimer, cleanupUntil, firstError = null;
  let totalBytes = 0;
  const stdout = [], stderr = [];
  let finish;
  const finished = new Promise((resolve) => { finish = resolve; });
  const fail = (kind, error) => {
    if (!firstError) firstError = { kind, code: error?.code ?? null, message: String(error?.message ?? error) };
  };
  const cleanup = () => {
    if (cleanupUntil !== undefined) return;
    cleanupUntil = performance.now() + cleanupMs;
    // detached:true establishes this child's own process group at spawn.
    if (child?.pid) {
      lifecycle.group_kill_attempted = true;
      try {
        process.kill(-child.pid, "SIGKILL");
        lifecycle.group_kill_sent = true;
      } catch (error) {
        if (error.code !== "ESRCH") lifecycle.cleanup_errors.push({ kind: "group_signal", code: error.code, message: error.message });
      }
    }
    cleanupTimer = setTimeout(finish, cleanupMs);
  };
  const interrupt = (signal) => {
    lifecycle.interrupted_by = signal;
    fail("interrupted", signal);
    cleanup();
  };
  const onInt = () => interrupt("SIGINT"), onTerm = () => interrupt("SIGTERM");
  const collect = (chunks) => (bytes) => {
    if (firstError) return;
    totalBytes += bytes.length;
    if (totalBytes > maxBytes) {
      fail("output_limit", "native worker exceeded " + maxBytes + " combined stdout/stderr bytes");
      cleanup();
    } else chunks.push(bytes);
  };
  try {
    child = spawn(binary, args, { detached: true, cwd: "/", env: {}, stdio: [fd, "pipe", "pipe"] });
    lifecycle.pid = child.pid ?? null;
    child.once("spawn", () => { lifecycle.spawn_observed = true; });
    child.once("error", (error) => { fail("spawn_or_process_error", error); cleanup(); });
    child.once("exit", (code, signal) => {
      lifecycle.exit_observed = true;
      lifecycle.exit_code = code;
      lifecycle.exit_signal = signal;
      // Descendants must not survive even a successful leader exit or retain
      // stdout/stderr indefinitely. The group is confined to this launch.
      cleanup();
    });
    child.once("close", () => { lifecycle.close_observed = true; cleanup(); finish(); });
    child.stdout.on("data", collect(stdout));
    child.stderr.on("data", collect(stderr));
    child.stdout.on("error", (error) => { fail("stdout_error", error); cleanup(); });
    child.stderr.on("error", (error) => { fail("stderr_error", error); cleanup(); });
    process.once("SIGINT", onInt);
    process.once("SIGTERM", onTerm);
    deadline = setTimeout(() => {
      lifecycle.timed_out = true;
      fail("timeout", "native worker exceeded " + timeoutMs + " ms wall-clock deadline");
      cleanup();
    }, timeoutMs);
    await finished;
    clearTimeout(deadline);
    // A successful kill() call is not proof of cleanup. Probe the owned group
    // separately; ESRCH is the only observation recorded as group absence.
    if (child.pid) {
      do {
        try { process.kill(-child.pid, 0); }
        catch (error) {
          if (error.code === "ESRCH") lifecycle.group_absent_observed = true;
          else lifecycle.cleanup_errors.push({ kind: "group_probe", code: error.code, message: error.message });
          break;
        }
        if (performance.now() >= cleanupUntil) break;
        await delay(Math.min(20, Math.max(1, cleanupUntil - performance.now())));
      } while (true);
      if (!lifecycle.group_absent_observed) fail("group_cleanup_unobserved", "owned process group absence was not observed within cleanup deadline");
    }
    if (!lifecycle.close_observed) fail("close_unobserved", "native worker close event was not observed within cleanup deadline");
  } catch (error) {
    fail("harness_error", error);
    cleanup();
  } finally {
    clearTimeout(deadline);
    clearTimeout(cleanupTimer);
    process.removeListener("SIGINT", onInt);
    process.removeListener("SIGTERM", onTerm);
    // Do not leave open stream/ChildProcess handles if an OS-level close could
    // not be observed. That outcome remains a harness failure in the report.
    child?.stdout?.destroy();
    child?.stderr?.destroy();
    child?.unref();
  }
  lifecycle.elapsed_ms = Math.round(performance.now() - started);
  return { error: firstError, lifecycle, status: lifecycle.exit_code, signal: lifecycle.exit_signal,
    stdout: Buffer.concat(stdout).toString("utf8"), stderr: Buffer.concat(stderr).toString("utf8") };
}

export function modelWorkerFailure(result, expectedDiagnostic) {
  if (result.error) return result.error;
  if (result.signal) return { kind: "native_signal", code: null, message: result.signal };
  if (result.status === 0) return null;
  if (result.status === 1 && expectedDiagnostic && result.stdout === ""
      && result.stderr.trim() === "Error: " + expectedDiagnostic) return null;
  return { kind: result.status === 1 ? "unexpected_native_rejection" : "native_exit",
    code: result.status, message: result.stderr.slice(0, 800) };
}

export async function modelWorkerIdentity(binary, beforeSha256) {
  const identity = { before_sha256: beforeSha256, after_sha256: null, unchanged: false, error: null };
  try {
    identity.after_sha256 = createHash("sha256").update(await readFile(binary)).digest("hex");
    identity.unchanged = identity.after_sha256 === beforeSha256;
    if (!identity.unchanged) identity.error = { kind: "native_identity_changed", code: null,
      message: "native binary content differs from its pre-run SHA-256" };
  } catch (error) {
    identity.error = { kind: "native_identity_unreadable", code: error.code ?? null, message: error.message };
  }
  return identity;
}
