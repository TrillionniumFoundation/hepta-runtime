#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Generate source and an explicitly unsealed example; never import target modules."""
import ast
import hashlib
import json
import os
from pathlib import Path
import pprint

HERE = Path(__file__).resolve().parent
BASE = HERE.parent
PREPARER = BASE / "d1-qualification-sealed-01/prepare_qualify.py"
PARENT = BASE / "d1-parent-reference-recovery-01/r35_campaign.py"
ROOT = "/home/qian/hepta-runtime-phase-cost-20261106-d1"


def identity(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def write(name, raw):
    path = HERE / name
    with path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def extract(raw, names):
    tree = ast.parse(raw)
    lines = raw.splitlines(keepends=True)
    output = {}
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in names:
            output[node.name] = b"".join(lines[node.lineno - 1:node.end_lineno])
    assert set(output) == set(names)
    return output


def main():
    preparer_raw, parent_raw = PREPARER.read_bytes(), PARENT.read_bytes()
    assert identity(preparer_raw) == {"bytes": 47509, "sha256": "05fcf39aeb418e626ceec048f51c4919bc5ba0b85d180f89c8580cfa2adf876c"}
    assert identity(parent_raw) == {"bytes": 84362, "sha256": "3707cbc2e3307a29aa6e645afdf8f6da7a5e80d36e90a86d505bd8f18061778c"}
    reusable = {**extract(parent_raw, ["checked"]),
                **extract(preparer_raw, ["native_terminal", "native_stream_pages", "postflight_bytes"])}
    tree = ast.parse(preparer_raw)
    constants = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            name = node.targets[0].id
            if name in {"BASELINE_COMMIT", "STAGES", "DIAGNOSTIC_ENV", "OWNER_POSTFLIGHT_JOB", "OWNER_JOBS", "OWNER_COUNTS"}:
                constants[name] = ast.literal_eval(node.value)
    sealed = BASE / "d1-qualification-sealed-01"
    package = json.loads((sealed / "qualification-package-manifest.json").read_bytes())
    original = {row["path"]: row for row in package["files"]}
    static_names = ["prepare_qualify.py", "qualification-input.json", "cache-owner-closure-inputs.json",
                    "candidate/input.json", "candidate/package-manifest.json", "candidate/candidate.patch",
                    "provenance/source-anchor-and-publication-parent.json"]
    pins = {name: dict(original[name], path=ROOT + "/" + name) for name in static_names}
    for name in static_names:
        assert identity((sealed / name).read_bytes()) == {k: original[name][k] for k in ("bytes", "sha256")}
    candidate = json.loads((sealed / "candidate/input.json").read_bytes())
    build = json.loads((sealed / "qualification-input.json").read_bytes())
    qnames = ["preparation.json", "qualification-terminal-status-01.json", "qualification-01/report.json",
              "qualification-01/source-map.json", "qualification-01/isolated-tests/summary.json",
              "qualification-01/isolated-tests.audit.json"]
    cinames = ["rust-ci-plan-01.json", "rust-ci-01/report.json",
               "rust-ci-01/nextest-output-audit.json", "rust-ci-native-01.json"]
    commands = {
        "cargo-version": ["cargo", "--version"],
        "rustc-version": ["rustc", "--version"],
        "nextest-version": ["cargo", "nextest", "--version"],
        "cargo-check": ["cargo", "check", "--locked", "--all-targets", "--all-features"],
        "nextest-list": ["cargo", "nextest", "list", "--locked", "--all-targets", "--all-features", "--message-format", "json"],
        "nextest-run": ["cargo", "nextest", "run", "--locked", "--all-targets", "--all-features",
                       "--test-threads", "1", "--retries", "0", "--no-fail-fast"],
    }
    environment = {
        "PATH": "/home/qian/hepta-runtime-optimization-20261105-r25/ci-toolchain/nextest-0.9.137/bin:/home/qian/.cargo/bin:/usr/local/bin:/usr/bin:/bin",
        "RUSTUP_TOOLCHAIN": "1.95.0",
        "CARGO_HOME": "/home/qian/hepta-runtime-optimization-20261023/cargo-home-a32-a33-r02",
        "CARGO_TARGET_DIR": ROOT + "/target-build", "CARGO_BUILD_JOBS": "2",
        "CARGO_INCREMENTAL": "0", "CARGO_NET_OFFLINE": "true", "RUST_TEST_THREADS": "1",
        "TOKIO_WORKER_THREADS": "2", "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1",
        "CARGO_TERM_COLOR": "never", "NEXTEST_STATUS_LEVEL": "pass",
        "NEXTEST_FINAL_STATUS_LEVEL": "fail", "NEXTEST_SUCCESS_OUTPUT": "never",
    }
    prefix = '''#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Actual D1 Q-only and Q-plus-native-CI receipts for the C1 diagnostic parent.

This module creates no files and starts no child, host request, compiler,
auditor, measurement or cache operation. The caller must bind the immutable
foundation JSON before passing its body and the original stable file reader.
Both actual result flags are false in the companion unsealed example.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

ROOT = Path("/home/qian/hepta-runtime-phase-cost-20261106-d1")
SOURCE = ROOT / "source"
QUALIFICATION = ROOT / "qualification-01"
BASE = Path("/home/qian/hepta-runtime-optimization-20261105-r24")
CACHE_OWNER = Path("/home/qian/hepta-runtime-optimization-20261106-r35")
CARGO_HOME = Path("/home/qian/hepta-runtime-optimization-20261023/cargo-home-a32-a33-r02")
NEXTEST_ROOT = Path("/home/qian/hepta-runtime-optimization-20261105-r25/ci-toolchain/nextest-0.9.137")
HEX = re.compile(r"[0-9a-f]{64}\\Z")
JOB = re.compile(r"[0-9a-f]{11,16}-[0-9a-f]{4}-[0-9a-f]{4}\\Z")
'''
    values = {**constants, "PINNED": pins, "QUALIFICATION_ARTIFACTS": qnames, "CI_ARTIFACTS": cinames,
              "CHANGED": set(candidate["changed_paths"]), "ADDED": set(candidate["added_paths"]),
              "BASELINE_QUALIFICATION": build["baseline_qualification"],
              "COUNT_KEYS": ("passed", "failed", "ignored", "selected", "retries"),
              "BINARY_NAMES": ("hepta-runtime", "hepta-runtime-jobctl", "native_process_driver"),
              "CI_COMMANDS": commands, "CI_ENVIRONMENT": environment,
              "NEXTEST_BINARY": {"path": "/home/qian/hepta-runtime-optimization-20261105-r25/ci-toolchain/nextest-0.9.137/bin/cargo-nextest",
                                  "bytes": 33831936, "sha256": "9c05bd3c7c5da1286b193873f12b37db386485fa483d8fa0554e68a53d9df550"},
              "CANONICAL_WORKFLOW": {"path": ROOT + "/rust-ci-tools-01/canonical-workflow.yml", "bytes": 7631,
                                     "sha256": "b9061fd671ac5fff33ad47d7ec5787f82cfadd88f5e71d54a8825cb55a02cd51"},
              "PRIVATE_SOURCE_WORKFLOW": {"path": ROOT + "/source/.github/workflows/ci.yml", "bytes": 7235,
                                          "sha256": "5574840f604a3c7963a274592ac2468a43fdd04cdaa7122851c271188a11065d"}}
    for name, value in values.items():
        prefix += name + " = " + pprint.pformat(value, width=110, sort_dicts=False) + "\n"
    body = (HERE / "binding_body.py").read_bytes()
    source = prefix.encode() + b"\n\n" + b"\n\n\n".join(reusable.values()) + b"\n\n\n" + body
    parsed = ast.parse(source)
    generated = extract(source, reusable)
    assert generated == reusable
    calls = [node for node in parsed.body if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)]
    assert not calls
    write("d1_prerequisites.py", source)
    example = {
        "schema": "hepta-d1-c1-prerequisites/v1",
        "qualification_sealed": False, "exact_ci_sealed": False,
        "required_missing_qualification_bindings": ["actual first D1 Q report/preparation/map/audit/summary/native and complete original read pages"],
        "required_missing_exact_ci_bindings": ["actual original exact CI report/plan/audit/native and complete original read pages"],
        "qualification_original_job_id": None, "qualification_read_pages": None,
        "exact_ci_original_job_id": None, "exact_ci_read_pages": None,
        "artifact_map": {**pins, **{name: None for name in qnames + cinames}},
        "performance_acceptance_claim": False,
    }
    write("prerequisites.unsealed.json", canonical(example))
    proof = {
        "schema": "hepta-d1-prerequisite-bindings-construction/v1",
        "source": identity(source),
        "reference_preparer": identity(preparer_raw), "reference_parent": identity(parent_raw),
        "byte_identical_helpers": {name: identity(raw) for name, raw in reusable.items()},
        "source_body": identity(body), "ast_parse_passed": True,
        "actual_future_results_supplied": False,
        "target_imports": 0, "target_function_calls": 0, "host_requests": 0,
        "compiler_or_auditor_or_workload_executions": 0,
        "scope": "Only static text generation, source identity/AST checks and creation of new preparation files.",
    }
    write("construction.json", canonical(proof))
    print(json.dumps(proof, sort_keys=True))


def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


if __name__ == "__main__":
    main()
