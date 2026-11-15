# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Retain and recheck the additional reachable RawValue storage observations."""
from pathlib import Path
import hashlib
import json
import lzma
import struct
import time
import traceback

import result_storage_raw_value_cases as cases

FIXTURE_SHA = "ca54a3fba9539c53a59fcac0280736fb45b4922fadb8e672ee2b103efc685d34"
FIXTURES = "tests/hia_native/fixtures/result_storage_reference/raw_value"
sha = lambda data: hashlib.sha256(data).hexdigest()
encoded = lambda value: (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()
identity = lambda raw: {"bytes": len(raw), "sha256": sha(raw)}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def regular(path):
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), "RawValue input is not an owned regular file")
    return path.read_bytes()


def fixture(root, domain):
    require(domain in cases.DOMAINS, "unknown RawValue storage domain")
    require(Path(cases.__file__).resolve() == (Path(root) / "tests/hia_native/result_storage_raw_value_cases.py").resolve(),
        "RawValue case generator is outside the pinned checkout")
    folder = Path(root) / FIXTURES
    manifest_raw = regular(folder / "manifest.json")
    require(sha(manifest_raw) == FIXTURE_SHA, "fixed RawValue storage reference changed")
    manifest = json.loads(manifest_raw)
    require(manifest["schema"] == "hepta.result-storage.raw-value-fixtures.v1"
        and set(manifest["domains"]) == set(cases.DOMAINS)
        and manifest["observation_kind"] == "retained-original-fixture"
        and manifest["actual_original_executions_by_reader"] == 0,
        "RawValue storage reference scope differs")
    result = {}
    for name, row in manifest["files"].items():
        require(Path(name).name == name and name.endswith(".xz"), "RawValue fixture path escaped")
        compressed = regular(folder / name)
        require(identity(compressed) == row["compressed"], "compressed RawValue fixture changed")
        result[name[:-3]] = lzma.decompress(compressed)
        require(identity(result[name[:-3]]) == row["uncompressed"], "complete RawValue fixture changed")
    capture = json.loads(result["capture.json"])
    require(capture["status"] == "PASS" and capture["fresh_storage_qualification"] is False
        and capture["source_commit"] == "86b5099550d92a4a9433257926929cb7656203f5",
        "RawValue reference capture is incomplete")
    wire, stdout, stderr = (result[domain + "." + channel] for channel in ("stdin", "stdout", "stderr"))
    require(wire == cases.inputs(domain) and not stderr, "complete RawValue input domain differs")
    receipt = next(row for row in capture["checks"] if row["command"][0].endswith(
        "hia-safe-dto-reference" if domain == "safe_dto" else "hia-request-retention-reference"))
    require(receipt["exit_code"] == 0 and receipt["reaped"] is True and receipt["timed_out"] is False
        and receipt["timeout_seconds"] == 180
        and all(receipt[channel] == identity(raw) for channel, raw in (("stdin", wire), ("stdout", stdout), ("stderr", stderr))),
        "actual retained RawValue reference process changed")
    observations, counts = cases.admit_reference(domain, stdout)
    require(manifest["domains"][domain] == counts, "RawValue accepted/refused extent differs")
    return wire, stdout, observations, counts


def expected_bytes(domain, row, observed):
    if domain == "safe_dto":
        return b"HRSDR001" + struct.pack("<3Q", int(observed["accepted"]),
            {"host_list": 1, "effective_config": 2, "host_health": 3}[row["tool"]], 0)
    from test_result_retention import STATES
    record = observed["record_json"].encode()
    payload = json.loads(record)["payload_bytes"] or 0
    return b"HRRTR001" + struct.pack("<3Q", STATES.index(observed["state"]), len(record), payload) + record


def request(domain, row, observed):
    if domain == "safe_dto":
        from test_result_safe_dto import query
        return query(row["tool"], observed["canonical_body"].encode())
    from test_result_retention import request as make
    return make(row, observed["canonical_body"].encode())


def run_native(root, domain, folder, executable, make_bridge):
    from test_result_safe_dto import ConfigChild
    root, folder, executable = Path(root), Path(folder), Path(executable)
    folder.mkdir(mode=0o700)
    wire, stdout, observations, counts = fixture(root, domain)
    (folder / "reference.stdin").write_bytes(wire)
    (folder / "reference.stdout").write_bytes(stdout)
    config = folder / "config.json"
    config.write_bytes(encoded({"state_dir": str(folder / "state"), "hosts": cases.configured_hosts()}))
    config.chmod(0o600)
    report = {"schema": "hepta.result-storage.raw-value-native.v1", "status": "FAIL", "domain": domain,
        "counts": counts, "fixture_sha256": FIXTURE_SHA, "cases": [],
        "config_executable": identity(regular(executable)), "new_original_processes": 0,
        "whole_runtime_replaced": False, "production_activated": False, "old_stack_removal_qualified": False}
    save = lambda: (folder / "result.json").write_bytes(encoded(report))
    started = time.monotonic();save()
    config_child = ConfigChild(executable, config, folder / "state", folder)
    bridge = make_bridge(config_child)
    failed = True
    try:
        with (folder / "native-owner.stdin.bin").open("xb") as incoming, \
                (folder / "native-owner.stdout.bin").open("xb") as outgoing:
            for ordinal, (row, observed) in enumerate(zip(cases.cases(domain), observations, strict=True)):
                query = request(domain, row, observed)
                incoming.write(struct.pack("<Q", len(query)) + query)
                code, raw, children = bridge.run(query)
                outgoing.write(struct.pack("<2Q", code, len(raw)) + raw)
                record = {"ordinal": ordinal, "label": row["label"], "input": identity(query),
                    "output": identity(raw), "native_code": code, "children": children,
                    "passed": code == len(raw) and raw == expected_bytes(domain, row, observed)}
                report["cases"].append(record);save()
                require(record["passed"], "RawValue native storage result differs: " + row["label"])
        failed = False
    except BaseException:
        (folder / "failure.txt").write_text(traceback.format_exc())
        raise
    finally:
        config_child.close(failed)
        report.update(native_process=config_child.receipt, native_entries=bridge.entries,
            elapsed_seconds=time.monotonic() - started)
        save()
    report["status"] = "PASS";save()
    return summary(report)


def summary(report):
    return {key: value for key, value in report.items() if key not in ("cases", "native_process")}


def native_evidence(root, domain, folder, executable):
    from result_storage_native_evidence import frames, exhausted, configuration, match_child
    folder, executable = Path(folder), Path(executable)
    wire, stdout, observations, counts = fixture(root, domain)
    report = json.loads(regular(folder / "result.json"))
    require(report["schema"] == "hepta.result-storage.raw-value-native.v1" and report["status"] == "PASS"
        and report["domain"] == domain and report["counts"] == counts and report["fixture_sha256"] == FIXTURE_SHA
        and report["new_original_processes"] == 0
        and all(report.get(key) is False for key in ("whole_runtime_replaced", "production_activated", "old_stack_removal_qualified"))
        and type(report["elapsed_seconds"]) in (int, float) and 0 <= report["elapsed_seconds"] <= 180,
        "RawValue native completion or scope differs")
    require(regular(folder / "reference.stdin") == wire and regular(folder / "reference.stdout") == stdout,
        "RawValue retained reference bytes differ")
    require(report["config_executable"] == identity(regular(executable)), "RawValue configuration image changed")
    config = folder / "config.json"
    require(json.loads(regular(config)) == {"state_dir": str(folder / "state"), "hosts": cases.configured_hosts()},
        "RawValue administrator configuration changed")
    incoming = frames(folder / "native-owner.stdin.bin")
    outgoing = frames(folder / "native-owner.stdout.bin", code=True)
    config_stream = configuration(folder, executable, config, report)
    for ordinal, (row, observed, record) in enumerate(zip(cases.cases(domain), observations, report["cases"], strict=True)):
        query = request(domain, row, observed)
        code, raw = next(outgoing)
        require(next(incoming) == query and record["ordinal"] == ordinal and record["label"] == row["label"]
            and record["input"] == identity(query) and record["output"] == identity(raw)
            and code == record["native_code"] == len(raw) and record["passed"] is True
            and raw == expected_bytes(domain, row, observed), "complete RawValue native case differs")
        children = ([child for child in record["children"] if child["child"] == 2] if domain == "safe_dto" else
            [child for call in record["children"] if call["name"] == "dto"
                for child in call["nested"] if child["child"] == 2])
        for child in children:
            match_child(config_stream, child)
    exhausted(incoming);exhausted(outgoing);exhausted(config_stream)
    require(report["native_entries"] == counts["cases"] + sum(len(row["children"]) for row in report["cases"]),
        "RawValue native owner entry count differs")
    return summary(report)


def replay_original(root, binary, folder, native, domain, environment, run):
    root, folder, native = Path(root), Path(folder), Path(native)
    folder.mkdir(mode=0o700)
    wire, stdout, _, counts = fixture(root, domain)
    require(regular(native / "reference.stdin") == wire and regular(native / "reference.stdout") == stdout,
        "admitted RawValue native reference changed before original replay")
    config = folder / "config.json"
    config.write_bytes(encoded({"state_dir": str(folder / "state"), "hosts": cases.configured_hosts()}))
    config.chmod(0o600)
    actual, error, receipt = run([binary, "--runtime-config", config], "complete", folder,
        root, environment, data=wire)
    require(actual == stdout and not error, "fresh complete RawValue original/native result differs")
    return receipt, counts["cases"]


def verify_original(root, binary, folder, native, domain, verify_process):
    root, folder, native = Path(root), Path(folder), Path(native)
    wire, stdout, _, counts = fixture(root, domain)
    require(regular(native / "reference.stdin") == wire and regular(native / "reference.stdout") == stdout,
        "RawValue native reference changed during original admission")
    config = folder / "config.json"
    require(json.loads(regular(config)) == {"state_dir": str(folder / "state"), "hosts": cases.configured_hosts()},
        "original RawValue administrator fixture changed")
    receipt, actual = verify_process(folder, "complete", [binary, "--runtime-config", config], root, data=wire)
    require(actual["stdout"] == stdout and not actual["stderr"], "fresh complete RawValue original bytes changed")
    return receipt, counts["cases"]
