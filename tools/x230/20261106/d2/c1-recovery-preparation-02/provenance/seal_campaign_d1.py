#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Seal D1 C1 only after actual Q/CI and mandatory ordinary closure.

Intended for a root-scheduled metadata-only invocation on x230 after Q and CI
and ordinary have closed. Reads the frozen preparation package and the supplied actual
prerequisite document, runs its read-only binder and ordinary verifier, then writes a new staged
Linux/Mac package. It does not install files or invoke the holder/parent.
"""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import types

ROOT = Path("/home/qian/hepta-runtime-phase-cost-20261106-d1")
TOOLS = ROOT / "c1-tools-01"
MAC_ROOT = Path("/Users/qianqi/work/hepta-runtime-d1-launchers-01")
MAC_OUTPUT = Path("/Users/qianqi/work/hepta-runtime-d1-c1-holder-01")
PROFILE = Path("/home/qian/hepta-runtime-optimization-20261023/r11-native-observation-abba-20261103-02/profile/profile.json")
TOPOLOGY = Path("/home/qian/hepta-runtime-optimization-20261104-r16/benchmark-topology.json")
FROZEN = Path("/home/qian/hepta-runtime-optimization-20261023/a31-frozen-originals-r01")
PROFILE_SHA = "fe1e9551b5b8812ad6ed3da018c282b7261f7caeb2f49e4dcfefba7ff784ab08"
TOPOLOGY_SHA = "8c0767d3318131a7d470d9cde8e327a59ce18adf022c8bc1b1d5a0fa9a865287"
HOLDER_SHA = "715e996217c7d33a7483354f16f2d39c9a033f51f3a20a52484495a00262dd65"
ADAPTER_TEMPLATE_SHA = "b49b95b00f67b33b05b726527ee5f63766fe568f7fed6d372f32417d3f811189"
CLARIFICATION_SHA = "7848ccc640e8d44fd042632eda69a93d2b24e07cabb65e83aeef683faeeb8704"
MAX_FILE = 4 * 1024 * 1024
MAX_TOTAL = 16 * 1024 * 1024
MAX_FILES = 128


def need(value, reason):
    if not value:
        raise ValueError(reason)


def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def identity(path, raw):
    return {"path": str(path), "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def stamp(s):
    return (s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode, s.st_nlink,
            s.st_size, s.st_mtime_ns, s.st_ctime_ns)


def regular(path, maximum=MAX_FILE):
    path = Path(path)
    need(path.is_absolute() and path.resolve() == path, "absolute direct source required")
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == os.geteuid()
         and 0 <= before.st_size <= maximum, "owned bounded single-link source required")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        need(stamp(os.fstat(fd)) == stamp(before), "input open stamp changed")
        parts, total = [], 0
        while True:
            part = os.read(fd, min(65536, maximum + 1 - total))
            if not part:
                break
            total += len(part)
            need(total <= maximum, "input bound exceeded")
            parts.append(part)
        need(total == before.st_size and stamp(os.fstat(fd)) == stamp(before) == stamp(path.lstat()),
             "input changed while read")
        return b"".join(parts)
    finally:
        os.close(fd)


def new_file(path, raw):
    need(len(raw) <= MAX_FILE, "staged file exceeds limit")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    need(path.parent.resolve() == path.parent and not os.path.lexists(path), "staged destination exists or is indirect")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(fd)
    finally:
        os.close(fd)
    need(regular(path) == raw, "staged output readback differs")


def module(raw, path, name):
    value = types.ModuleType(name)
    value.__file__ = str(path)
    sys.modules[name] = value
    exec(compile(raw, str(path), "exec", optimize=0), value.__dict__)
    return value


def assignment(raw, name, value):
    source = raw.decode("utf-8")
    tree = ast.parse(source)
    declarations = [node for node in tree.body if isinstance(node, ast.Assign)
                    and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
                    and node.targets[0].id == name]
    need(len(declarations) == 1 and isinstance(declarations[0].value, ast.Constant)
         and declarations[0].value.value is None, "unsealed assignment is not exactly None")
    declaration = declarations[0]
    lines = source.splitlines(keepends=True)
    new = "".join(lines[:declaration.lineno - 1]) + name + " = " + repr(value) + "\n" + "".join(lines[declaration.end_lineno:])
    new_tree = ast.parse(new)
    replaced = [node for node in new_tree.body if isinstance(node, ast.Assign)
                and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
                and node.targets[0].id == name]
    need(len(replaced) == 1 and ast.literal_eval(replaced[0].value) == value,
         "actual assignment did not roundtrip")
    replaced[0].value = ast.Constant(value=None)
    need(ast.dump(new_tree, include_attributes=False) == ast.dump(tree, include_attributes=False),
         "sealing changed code outside the single actual assignment")
    return new.encode()


def seal(args):
    source_root = Path(__file__).resolve().parent
    manifest_raw = regular(source_root / "package-manifest.json")
    manifest = json.loads(manifest_raw)
    need(manifest.get("schema") == "hepta-d1-c1-outer-preparation/v1"
         and manifest.get("sealed") is False, "frozen unsealed preparation manifest required")
    rows = manifest["files"]
    need(isinstance(rows, list) and 1 <= len(rows) <= MAX_FILES, "preparation inventory bound differs")
    sources = {}
    for row in rows:
        relative = Path(row["path"])
        need(not relative.is_absolute() and relative.as_posix() == row["path"]
             and all(part not in {"", ".", ".."} for part in relative.parts) and row["path"] not in sources,
             "invalid or duplicate source member")
        raw = regular(source_root / relative)
        need(identity(row["path"], raw) == row, "frozen source identity differs: " + row["path"])
        sources[row["path"]] = raw
    need(sum(len(raw) for raw in sources.values()) <= MAX_TOTAL, "source package bound exceeded")
    need(hashlib.sha256(sources["run_c1_phase_cost.unsealed.py"]).hexdigest() == ADAPTER_TEMPLATE_SHA
         and hashlib.sha256(sources["held_agent_campaign_02.py"]).hexdigest() == HOLDER_SHA
         and hashlib.sha256(sources["pre-execution-clarification-01.json"]).hexdigest() == CLARIFICATION_SHA,
         "original adapter/holder/required clarification differs")
    prerequisites_raw = regular(args.prerequisites)
    prerequisites = json.loads(prerequisites_raw)
    need(prerequisites.get("qualification_sealed") is True and prerequisites.get("exact_ci_sealed") is True,
         "only complete actual D1 Q and CI prerequisites can be sealed")
    parent = module(sources["d1_campaign.unsealed.py"], source_root / "d1_campaign.unsealed.py", "_d1_seal_original_helpers")
    binder = module(sources["d1_prerequisites.py"], source_root / "d1_prerequisites.py", "_d1_seal_prerequisite_binder")
    proof = binder.bind_d1_prerequisites(prerequisites, parent.checked)
    need(proof["passed"] is True and len(proof["source_tested"]) == 222,
         "actual first D1 qualification/CI closure did not pass")
    ordinary_source = sources["ordinary/verify_ordinary_02.py"]
    ordinary_pins = {
        "verifier": identity(parent.ORDINARY_VERIFIER, ordinary_source),
        "verification_input": parent.checked(parent.ORDINARY_INPUT, maximum=4 * 1024 * 1024),
        "postflight": parent.checked(parent.ORDINARY_POSTFLIGHT, maximum=16 * 1024 * 1024),
    }
    ordinary_bindings = []
    def bind_ordinary(path, expected=None, maximum=128 * 1024 * 1024, retain=False):
        result = parent.checked(path, expected, maximum, retain)
        ordinary_bindings.append(result[0] if retain else result)
        return result
    ordinary_proof = parent.bind_ordinary_prerequisite(ordinary_pins, bind_ordinary, binder, proof)
    source_before = parent.source_inputs(ROOT / "source")
    baseline_before = parent.source_inputs(parent.BASELINE_ROOT / "source")
    need(parent.qualification_projection(source_before) == proof["source_tested"],
         "current actual D1 source does not match qualification")
    need(set(source_before["files"]) == set(baseline_before["files"]) | set(proof["added_paths"])
         and {name for name in source_before["files"]
              if source_before["files"][name] != baseline_before["files"].get(name)} == set(proof["changed_paths"]),
         "additional build/config/source input changed outside the reviewed diagnostic patch")
    foundation = canonical(prerequisites)
    foundation_pin = identity(ROOT / "c1-prerequisites-01.json", foundation)

    def original_pin(path):
        matches = [pin for pin in prerequisites["artifact_map"].values() if pin.get("path") == str(path)]
        need(len(matches) == 1, "unique actual prerequisite pin missing: " + str(path))
        return matches[0]

    profile_pin = parent.checked(PROFILE, PROFILE_SHA, maximum=262144)
    topology_pin = parent.checked(TOPOLOGY, TOPOLOGY_SHA, maximum=262144)
    originals = sorted(FROZEN.glob("*.json"))
    need(len(originals) == 6, "six fixed original job inputs required")
    original_pins = [parent.checked(path, maximum=65536) for path in originals]
    adapter_spec = {
        "schema": "hepta-d1-c1-phase-cost-input/v1", "sealed": True, "root": str(ROOT),
        "reference_directory": str(TOOLS / "reference"),
        "qualified_feature_binary": proof["binaries"]["hepta-runtime"],
        "qualification_report": original_pin(ROOT / "qualification-01/report.json"),
        "qualification_terminal": original_pin(ROOT / "qualification-terminal-status-01.json"),
        "qualified_source_map": original_pin(ROOT / "qualification-01/source-map.json"),
        "outer_input_manifest": foundation_pin, "profile_template": profile_pin, "topology": topology_pin,
        "frozen_jobs": original_pins, "benchmark_output": str(ROOT / "c1-observation-01"),
        "evidence_output": str(ROOT / "c1-adapter-evidence-01"), "socket_parent": "/home/qian/hd1c01",
    }
    adapter = assignment(sources["run_c1_phase_cost.unsealed.py"], "SPEC", adapter_spec)
    adapter_pin = identity(TOOLS / "run_c1_phase_cost.py", adapter)
    binder_pin = identity(TOOLS / "d1_prerequisites.py", sources["d1_prerequisites.py"])
    monitor = {}
    for name, path in parent.COMPILER_MONITOR_PATHS.items():
        raw = sources[Path(path).relative_to(TOOLS).as_posix()]
        monitor[name] = identity(path, raw)
    actual = {"sealed": True, "prerequisites": foundation_pin, "qualification_binder": binder_pin,
              "ordinary": ordinary_pins, "adapter": adapter_pin, "adapter_spec": adapter_spec, "compiler_monitor": monitor}
    parent_source = assignment(sources["d1_campaign.unsealed.py"], "ACTUAL", actual)
    parent_pin = identity(TOOLS / "d1_campaign.py", parent_source)
    inputs = {"schema": "hepta-d1-c1-campaign-inputs/v1", "sealed": True, "attempt": "01",
              "launcher_sha256": parent_pin["sha256"], "prerequisites": foundation_pin,
              "qualification_binder": binder_pin, "ordinary": ordinary_pins,
              "adapter": adapter_pin, "compiler_monitor": monitor}
    linux = {}
    for relative, (size, sha) in parent.STATIC_INPUTS.items():
        raw = sources[relative]
        need(len(raw) == size and hashlib.sha256(raw).hexdigest() == sha, "original runtime tool identity differs")
        linux["c1-tools-01/" + relative] = raw
    linux.update({
        "c1-tools-01/d1_prerequisites.py": sources["d1_prerequisites.py"],
        "c1-tools-01/run_c1_phase_cost.py": adapter,
        "c1-tools-01/d1_campaign.py": parent_source,
        "c1-prerequisites-01.json": foundation,
        "c1-campaign-inputs-01.json": canonical(inputs),
    })
    mac = {"held_agent_campaign_02.py": sources["held_agent_campaign_02.py"], "d1_campaign.py": parent_source}
    need(parent.source_inputs(ROOT / "source") == source_before
         and parent.source_inputs(parent.BASELINE_ROOT / "source") == baseline_before,
         "source inputs changed during metadata sealing")
    for pin in proof["binaries"].values():
        parent.checked(pin["path"], pin)
    for pin in ordinary_bindings:
        need(parent.checked(pin["path"], pin) == pin, "ordinary original changed during metadata sealing")
    need(len(linux) + len(mac) <= MAX_FILES
         and sum(len(raw) for raw in [*linux.values(), *mac.values()]) <= MAX_TOTAL,
         "sealed artifact size/count bound exceeded")
    output = Path(args.output)
    need(output.is_absolute() and output.resolve() == output and not os.path.lexists(output),
         "fresh direct seal output required")
    output.mkdir(mode=0o700)
    entries = []
    for target, prefix, members in (("x230", ROOT, linux), ("mac", MAC_ROOT, mac)):
        for relative, raw in sorted(members.items()):
            staged = output / target / relative
            new_file(staged, raw)
            entries.append({"target": target, "staged_path": target + "/" + relative,
                            "destination": str(prefix / relative), "bytes": len(raw),
                            "sha256": hashlib.sha256(raw).hexdigest()})
    argv = ["/usr/bin/python3", "-B", str(MAC_ROOT / "held_agent_campaign_02.py"),
            "--remote-script", str(MAC_ROOT / "d1_campaign.py"), "--out", str(MAC_OUTPUT),
            "--timeout-seconds", "3600"]
    sealed = {
        "schema": "hepta-d1-c1-outer-seal/v1", "sealed": True,
        "source_package_manifest": identity(source_root / "package-manifest.json", manifest_raw),
        "actual_prerequisite_input": identity(args.prerequisites, prerequisites_raw),
        "prerequisites": foundation_pin, "qualification_and_exact_ci": proof,
        "ordinary_inputs": ordinary_pins, "ordinary_supplement": ordinary_proof,
        "source_inputs": source_before, "baseline_source_inputs": baseline_before,
        "adapter": adapter_pin, "parent": parent_pin, "holder_sha256": HOLDER_SHA,
        "pre_execution_clarification_sha256": CLARIFICATION_SHA,
        "files": entries, "file_count": len(entries), "payload_bytes": sum(row["bytes"] for row in entries),
        "operator_argv": argv, "mac_holder_output": str(MAC_OUTPUT),
        "source_sealing_only": True, "workload_started": False, "installed": False,
        "actual_measurement": None, "automatic_retries": 0, "performance_acceptance_claim": False,
        "scope": "two stages only; original held-agent/quiet90/monitor/native-auditor and owner closure remain required",
    }
    sealed_manifest_raw = canonical(sealed)
    sealed_manifest_identity = identity(output / "seal-manifest.json", sealed_manifest_raw)
    new_file(output / "seal-manifest.json", sealed_manifest_raw)
    new_file(output / "operator-argv.json", canonical({"argv": argv, "not_executed": True}))
    new_file(output / "install_campaign.py", sources["install_campaign.py"])
    print(json.dumps({"output": str(output), "seal_manifest": sealed_manifest_identity,
                      "parent": parent_pin, "adapter": adapter_pin,
                      "file_count": len(entries), "payload_bytes": sealed["payload_bytes"],
                      "installed": False, "workload_started": False}, sort_keys=True), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prerequisites", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    seal(args)


if __name__ == "__main__":
    os.umask(0o077)
    main()
