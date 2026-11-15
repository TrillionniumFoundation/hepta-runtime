#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Seal a descriptive async read supplement before its first workload."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import types

sys.dont_write_bytecode = True
ROOT = Path("/home/qian/hepta-runtime-optimization-20261106-r36")
HELPER = ROOT / "tools-01/r36_campaign.py"
HELPER_SHA = "7cb886eccbefb6f52464e2c0bbab995d185349864afd9f53eaf1a36334d0ae95"
SELF = ROOT / "supplement-tools-01/seal_protocol.py"
RUNNER = ROOT / "supplement-tools-01/run_async_read_abba.py"
PROTOCOL = ROOT / "async-read-protocol-01.json"
LAUNCHER = ROOT / "supplement-tools-01/held_async_read_supplement.py"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("sealer-sha256", "runner-sha256", "qualification-bindings-sha256"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    assert sys.platform == "linux" and os.geteuid() != 0 and Path(__file__).resolve() == SELF
    assert HELPER.resolve(strict=True) == HELPER and not HELPER.is_symlink()
    raw = HELPER.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == HELPER_SHA
    parent = types.ModuleType("r36_async_sealing_helpers")
    parent.__file__ = str(HELPER)
    exec(compile(raw, str(HELPER), "exec"), parent.__dict__)
    bound = []
    def bind(path, expected=None, retain=False, maximum=128 * 1024 * 1024):
        result = parent.checked(path, expected, maximum, retain)
        bound.append(result[0] if retain else result)
        return result
    sealer = bind(SELF, args.sealer_sha256)
    runner = bind(RUNNER, args.runner_sha256)
    helper = bind(HELPER, HELPER_SHA)
    inputs_id, raw = bind(ROOT / "rust-ci-qualification-bindings-01.json", args.qualification_bindings_sha256, retain=True)
    inputs = json.loads(raw)
    proof = parent.bind_r36_candidate_preparation(inputs, bind)
    example_id, raw = bind(ROOT / "campaign-inputs-01.example.json", retain=True)
    example = json.loads(raw)
    parent.bind_compiler_monitor_inputs(example, bind)
    binaries = {"A": bind(example["baseline"]["binaries"]["hepta-runtime"]["path"], example["baseline"]["binaries"]["hepta-runtime"])}
    _, raw = bind(proof["baseline_qualification"]["path"], proof["baseline_qualification"], retain=True)
    baseline = json.loads(raw)
    assert binaries["A"]["path"] == baseline["binaries"]["hepta-runtime"]["path"]
    assert binaries["A"]["sha256"] == baseline["binaries"]["hepta-runtime"]["sha256"]
    _, raw = bind(ROOT / "qualification-01/report.json", proof["qualification"], retain=True)
    qualified = json.loads(raw)
    binaries["B"] = bind(ROOT / "qualification-01/hepta-runtime", qualified["binaries"]["hepta-runtime"]["sha256"])
    tools = {name: bind(parent.TOOLS / name, parent.HARNESS_FILES[name]) for name in
             ("x230_observation_benchmark.py", "observation_resources.py", "allocator_environment.py")}
    profile = bind(parent.PROFILE, parent.PROFILE_SHA)
    topology = bind(parent.TOPOLOGY, parent.TOPOLOGY_SHA)
    frozen = [bind(path) for path in sorted(parent.FROZEN_JOBS.glob("*.json"))]
    assert len(frozen) == 6
    value = {"schema": "hepta-r36-async-read-supplement-protocol/v1", "sealed": True,
        "created_utc": parent.utc(), "runner": runner, "sealer": sealer, "helper": helper,
        "qualification_bindings": inputs_id, "qualification_proof": proof,
        "observation_example": example_id, "binaries": binaries, "native_tools": tools,
        "profile_template": profile, "topology": topology, "frozen_jobs": frozen,
        "compiler_monitor": example["compiler_monitor"],
        "order": "ABBA", "concurrency": [1, 8], "warmup_per_cell": 12, "measured_per_cell": 24,
        "rounds": 4, "controllers_simultaneously": 1, "tokio_workers": 2, "malloc_arena_max": 1,
        "runtime_flags": ["mcp", "--runtime-config", "FIXTURE_CONFIG", "--runtime-prewarm",
                          "--runtime-audit-group-commit", "--runtime-observation-pool-profile", "FRESH_PINNED_PROFILE"],
        "inner_tools": ["process_status", "process_read"], "host_schedule": "sorted six hosts; 6 status then 6 read, repeating",
        "unique_background_reads": 288, "measured_background_reads": 192, "warmup_background_reads": 96,
        "poll_seconds": 0.01, "operation_deadline_seconds": 45, "workload_budget_seconds": 270,
        "budget_scope": "270-second new-call budget; unchanged native Controller initialization and graceful close keep their original bounded waits. Nominal work is under five minutes, not a five-minute forced-kill promise.",
        "recommended_holder_timeout_seconds": 600,
        "quiescence_seconds": 5, "result_page_bytes": 16384, "maximum_result_bytes": 1048576,
        "automatic_retries": 0, "remote_process_launches": 0, "remote_mutation_tools": 0,
        "no_original_gate_changes": True, "new_adoption_thresholds": None,
        "scope": "One X230 controller's real background read admission and validated result settlement against six existing completed jobs; not remote compute throughput or maximum capacity",
        "admission_metric": "new operation_start RPC latency; cohort receipt rate sums only admission windows, while background dispatch may overlap",
        "settlement_metric": "first admission RPC through completed durable status and full original SDK bytes readback/validation; full cell rate includes all original polling and retrieval",
        "cpu_metric": "same controller PID/birth raw utime+stime around each full timed cell; includes background read, audit, polling and retrieval; not isolated admission CPU or cluster CPU",
        "rss_metric": "original 100 ms /proc resource sampler plus raw cell endpoint VmRSS/VmHWM; sampled peaks may miss transients",
        "validation_outside_timing": "every operation's identical-key receipt plus completed status and unchanged original result; changed-arguments refusal; post-close new-stdio-owner status/result scope refusal",
        "source_contract": "Actual Slot::take tracks admitted work without the stale tool description's historical 4/8 rejection. Offered C8 is neither a configured quota nor maximum supported capacity.",
        "not_covered": ["job compute throughput", "new remote launches", "maximum concurrency", "other async read APIs", "request_start whitelist", "cross-credential HTTP persistence", "power loss", "deployment"],
    }
    assert not any(os.path.lexists(path) for path in (PROTOCOL, LAUNCHER, ROOT / "async-read-abba-01"))
    for item in bound:
        assert parent.checked(item["path"], item) == item
    parent.create(PROTOCOL, parent.canonical(value))
    protocol_id = parent.checked(PROTOCOL)
    wrapper = '''#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Original held-agent entry point for the separately sealed async supplement."""
import argparse, hashlib, os, signal, sys, types
from pathlib import Path
sys.dont_write_bytecode = True
ROOT = Path(%r)
RUNNER = %r
PROTOCOL_SHA = %r
HELPER_SHA = %r
args_parser = argparse.ArgumentParser()
args_parser.add_argument("--launcher-sha256", required=True)
args = args_parser.parse_args()
helper_path = ROOT / "tools-01/r36_campaign.py"
helper_raw = helper_path.read_bytes()
if hashlib.sha256(helper_raw).hexdigest() != HELPER_SHA:
    raise RuntimeError("reviewed helper differs")
helper = types.ModuleType("held_async_verified_helper")
helper.__file__ = str(helper_path)
exec(compile(helper_raw, str(helper_path), "exec"), helper.__dict__)
helper.checked(ROOT / "supplement-tools-01/held_async_read_supplement.py", args.launcher_sha256)
helper.checked(ROOT / "async-read-protocol-01.json", PROTOCOL_SHA)
_, raw = helper.checked(RUNNER["path"], RUNNER, retain=True)
module = types.ModuleType("held_async_read_original")
module.__file__ = RUNNER["path"]
exec(compile(raw, module.__file__, "exec"), module.__dict__)
sys.argv = [module.__file__, "--launcher-sha256", args.launcher_sha256, "--protocol-sha256", PROTOCOL_SHA]
os.umask(0o077)
for number in (signal.SIGINT, signal.SIGTERM):
    signal.signal(number, module.interrupted)
sys.exit(module.main())
''' % (str(ROOT), runner, protocol_id["sha256"], HELPER_SHA)
    parent.create(LAUNCHER, wrapper.encode())
    print(json.dumps({"protocol": protocol_id, "held_launcher": parent.checked(LAUNCHER), "sealed_before_workload": True,
                      "workloads_started": 0, "commands_run": 0}, sort_keys=True))


if __name__ == "__main__":
    os.umask(0o077)
    main()
