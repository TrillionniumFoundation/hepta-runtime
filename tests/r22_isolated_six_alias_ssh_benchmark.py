#!/usr/bin/env python3
"""Isolated six logical aliases -> one localhost SSH target. No production units changed."""
import argparse
import hashlib
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import tempfile
import time
import urllib.request
from effect_owner_two_server_legacy_replay_acceptance import Client, local_port

ALIASES = ("perf-a", "perf-b", "perf-c", "perf-d", "perf-e", "perf-f")


def rpc_value(client, tool, arguments):
    envelope = client.rpc("tools/call", {"name": tool, "arguments": arguments})
    if "error" in envelope:
        raise RuntimeError(f"{tool}: MCP error")
    value = envelope.get("result", {})
    if value.get("isError") or len(value.get("content", [])) != 1:
        raise RuntimeError(f"{tool}: tool refusal")
    return json.loads(value["content"][0]["text"])


def batch(clients, function):
    start = time.perf_counter()
    with ThreadPoolExecutor(max_workers=len(clients)) as pool:
        results = list(pool.map(lambda alias: function(alias, clients[alias]), clients))
    return results, round((time.perf_counter() - start) * 1000, 2)


def run_once(binary, label, aliases, seed_count, report_dir, host_overrides=None):
    base = Path(tempfile.mkdtemp(prefix="hepta-r22-isolated-ssh-"))
    base.chmod(0o700)
    state, workspace = base / "state", base / "workspace"
    state.mkdir(mode=0o700)
    workspace.mkdir(mode=0o700)
    token_file = base / "token"
    token = secrets.token_hex(32)
    fd = os.open(token_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as stream:
        stream.write(token + "\n")
    config = base / "runtime.json"
    hosts = {}
    for alias in aliases:
        if host_overrides is not None:
            hosts[alias] = dict(host_overrides[alias])
            continue
        target = base / ("remote-" + alias)
        target.mkdir(mode=0o700)
        hosts[alias] = {
            "ssh_target": "localhost",
            "platform": "linux",
            "execution_mode": "operator",
            "remote_state_dir": str(target),
            "allow_execute": True,
            "allow_pty": False,
            "allow_write": False,
            "allow_job_network": True,
        }
    config.write_text(json.dumps({
        "state_dir": str(state),
        "controller_workspace_roots": [str(workspace)],
        "hosts": hosts,
    }))
    config.chmod(0o600)
    port = local_port()
    env = dict(os.environ)
    for key in ("HEPTA_EFFECT_OWNER_FENCE_REQUIRED", "HEPTA_EFFECT_OWNER_SELF",
                "HEPTA_EFFECT_OWNER_FENCE_DIR"):
        env.pop(key, None)
    server_log = (base / "server.log").open("wb")
    proc = subprocess.Popen([
        str(binary), "mcp", "--path", str(workspace), "--bind",
        f"127.0.0.1:{port}", "--runtime-config", str(config),
        "--auth-token-file", str(token_file),
    ], stdout=server_log, stderr=subprocess.STDOUT, env=env)
    result = {"label": label, "binary_sha256": hashlib.sha256(Path(binary).read_bytes()).hexdigest(),
              "schema": "hepta-r22-six-alias-ssh-isolate.v1",
              "aliases": list(aliases), "seed_records": seed_count,
              "real_physical_host_count": len(aliases) if host_overrides is not None else 1,
              "production_routing_changed": False}
    succeeded = False
    try:
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                raise RuntimeError("isolated controller exited during startup")
            try:
                req = urllib.request.Request(f"http://127.0.0.1:{port}/readyz")
                with urllib.request.urlopen(req, timeout=1) as reply:
                    if reply.status == 200:
                        break
            except Exception:
                time.sleep(.05)
        else:
            raise RuntimeError("isolated controller not ready")
        clients = {alias: Client(port, token) for alias in aliases}
        def create(alias, client):
            params = {"host": alias, "executable": "/usr/bin/true", "args": [],
                      "timeout_seconds": 30,
                      "idempotency_key": f"r22-isolated-{label}-{alias}"}
            value = rpc_value(client, "process_start", params)
            if value.get("job", {}).get("host") != alias or value.get("reused") is not False:
                raise AssertionError("new job identity inconsistent")
            if value.get("launch", {}).get("ok") is not True:
                raise AssertionError("isolated job launch failed")
            return value["job"]["id"]
        ids, result["new_batch_ms"] = batch(clients, create)
        result["created_jobs"] = len(ids)
        jobs = dict(zip(aliases, ids))
        def status(alias, client):
            deadline = time.monotonic() + 20
            while True:
                value = rpc_value(client, "process_status",
                                  {"host": alias, "job_id": jobs[alias]})
                if value.get("state") == "succeeded" and value.get("exit_code") == 0:
                    if value.get("output_complete") is not True:
                        raise AssertionError("incomplete remote output")
                    return True
                if value.get("state") in ("failed", "cancelled", "lost", "timed_out"):
                    raise AssertionError("job did not succeed")
                if time.monotonic() > deadline:
                    raise AssertionError("status never reached terminal success")
                time.sleep(.05)
        statuses, result["status_batch_ms"] = batch(clients, status)
        if not all(statuses):
            raise AssertionError("some jobs incomplete")
        jobs_dir = state / "jobs"
        original = json.loads((jobs_dir / (ids[0] + ".json")).read_text())
        original["idempotency_key"] = None
        for i in range(seed_count):
            row = dict(original)
            row["id"] = f"synthetic-only-{i:05}"
            row["created_unix_ms"] = i
            (jobs_dir / (row["id"] + ".json")).write_text(json.dumps(row))
        result["actual_seeded_json_records"] = seed_count
        def reuse(alias, client):
            params = {"host": alias, "executable": "/usr/bin/true", "args": [],
                      "timeout_seconds": 30,
                      "idempotency_key": f"r22-isolated-{label}-{alias}"}
            value = rpc_value(client, "process_start", params)
            if value.get("job", {}).get("id") != jobs[alias] or value.get("reused") is not True:
                raise AssertionError("idempotent identity changed")
            if value.get("retried_launch") is not False:
                raise AssertionError("unexpected relaunch")
            return value["job"]["id"]
        for phase in ("reuse_cold_batch_ms", "reuse_hot_batch_ms"):
            observed, result[phase] = batch(clients, reuse)
            assert observed == ids
        total_records = len(list(jobs_dir.glob("*.json")))
        if total_records != len(ids) + seed_count:
            raise AssertionError("duplicate or missing durable identities after reuse")
        result["durable_record_count_final"] = total_records
        result["identities_reused_without_relaunch"] = len(ids)
        succeeded = True
    except Exception as exc:
        result["failure"] = type(exc).__name__ + ": " + str(exc)[:240]
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=7)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
        server_log.close()
        result["isolated_state_retained"] = not succeeded
        if succeeded:
            shutil.rmtree(base)
        else:
            result["isolate_path"] = str(base)
        path = report_dir / f"{label}-result.json"
        path.write_text(json.dumps(result, sort_keys=True, indent=2))
    return result


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--baseline", required=True, type=Path)
    p.add_argument("--candidate", required=True, type=Path)
    p.add_argument("--aliases", type=int, default=6)
    p.add_argument("--seed-count", type=int, default=3000)
    p.add_argument("--out", required=True, type=Path)
    p.add_argument("--reverse-order", action="store_true")
    args = p.parse_args()
    if not 1 <= args.aliases <= len(ALIASES) or not 0 <= args.seed_count <= 8000:
        p.error("bounded alias/seed limits required")
    args.out.mkdir(mode=0o700, parents=True, exist_ok=True)
    cases = [("baseline", args.baseline), ("candidate", args.candidate)]
    if args.reverse_order:
        cases.reverse()
    summary = [run_once(binary, label, ALIASES[:args.aliases], args.seed_count,
                        args.out) for label, binary in cases]
    print(json.dumps(summary, indent=2))
    if any("failure" in item for item in summary):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
