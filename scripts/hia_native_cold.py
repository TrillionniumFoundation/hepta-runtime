"""Validate source-matched upstream full cold qualification evidence.

The caller executes the unchanged upstream 180-second replay. A runtime boolean
never replaces its actual report, process receipt and complete source export.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
from hia_native_build import HEPTA_COMMIT, HEPTA_TREE

CONTRACT = "docs/HIA_SELFHOST_CORE_SUPPORT.json"
OUTER_CHECKS = {
    "nested_process_exit_zero", "owned_process_tree_cleanup_confirmed",
    "nested_full_qualification_pass", "source_export_hashes_preserved",
    "origin_hashes_preserved", "export_manifest_matches_qualification",
    "isolated_python_without_site", "no_inherited_seed_or_successor_images",
    "no_inherited_home_or_python_cache", "no_bytecode_cache_created",
    "no_ancestor_git_identity",
}
NESTED_CHECKS = 5049


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def regular(path: Path) -> bytes:
    if not path.is_file() or path.is_symlink() or path.resolve() != path:
        raise ValueError("cold evidence must be a regular unsymlinked file: " + str(path))
    return path.read_bytes()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError("full compiler cold evidence differs: " + message)


def validate_cold_evidence(report_path: Path, *, dependency: dict, compiler_sha256: str) -> dict:
    require((dependency.get("commit"), dependency.get("tree")) == (HEPTA_COMMIT, HEPTA_TREE),
            "active dependency identity")
    report_raw = regular(report_path)
    cold = json.loads(report_raw)
    folder = report_path.with_suffix(".cold")
    source_root = folder / "source"
    contract_raw = regular(source_root / CONTRACT)
    require(digest(contract_raw) == dependency["files"][CONTRACT], "pinned support contract")
    contract = json.loads(contract_raw)
    expected = {**contract["source_identity"]["files"], CONTRACT: digest(contract_raw)}
    for name, value in expected.items():
        relative = Path(name)
        require(not relative.is_absolute() and ".." not in relative.parts, "source path")
        require(dependency["files"].get(name) == value, "source outside pinned dependency: " + name)
        require(digest(regular(source_root / relative)) == value, "exported source: " + name)
    require(cold.get("schema") == "hepta.hia.selfhost-cold-replay.v1"
            and cold.get("status") == "COLD_SELFHOST_REPLAY_PASS", "successful upstream status")
    require(cold.get("profile") == contract["profile"] and cold.get("source_manifest") == expected,
            "matching support profile and exact source manifest")
    checks = cold.get("checks", {})
    require(set(checks) == OUTER_CHECKS and all(value is True for value in checks.values()),
            "all 11 original outer checks")
    require(cold.get("qualification_wall_limit_seconds") == 180
            and cold.get("cleanup_wall_limit_seconds") == 3
            and type(cold.get("returncode")) is int and cold["returncode"] == 0,
            "unchanged 180-second qualification and 3-second cleanup budgets")

    owner_raw = regular(folder / "process-owner.json")
    request_raw = regular(folder / "process-owner.json.request.json")
    actual_owner = json.loads(owner_raw)
    request = json.loads(request_raw)
    owner = cold.get("process_owner", {})
    require(owner == dict(actual_owner, supervisor_returncode=0, receipt_sha256=digest(owner_raw)),
            "original owned-process receipt")
    require(owner.get("schema") == "hepta.hia.selfhost-process-owner.v1"
            and owner.get("status") == "OWNED_PROCESS_COMPLETED"
            and type(owner.get("returncode")) is int and owner["returncode"] == 0
            and owner.get("timed_out") is False
            and owner.get("exit_observed_before_deadline") is True
            and owner.get("qualification_seconds") == 180 and owner.get("cleanup_seconds") == 3
            and owner.get("request_sha256") == digest(request_raw)
            and owner.get("implementation_sha256") == expected["tools/hia_selfhost_process_owner.py"],
            "actual process completion before the original deadline")
    cleanup = owner.get("cleanup", {})
    require(cleanup.get("complete") is True and cleanup.get("observed_echild") is True
            and cleanup.get("leader_reaped") is True and cleanup.get("remaining_direct_children") == []
            and cleanup.get("deadline_exceeded") is False, "confirmed owned-process cleanup")
    require(request.get("qualification_seconds") == 180 and request.get("cleanup_seconds") == 3
            and request["deadline_ns"] - request["started_ns"] == 180_000_000_000
            and request.get("implementation_sha256") == owner["implementation_sha256"],
            "unchanged process-owner request")

    export_request_raw = regular(folder / "request.json")
    export_request = json.loads(export_request_raw)
    nested_path = folder / "qualification.json"
    require(cold.get("nested_report") == str(nested_path), "nested report path")
    require(export_request.get("source_root") == str(source_root)
            and export_request.get("source_manifest") == expected
            and export_request.get("preexisting_generated_artifacts") == []
            and export_request.get("command") == request.get("command"), "fresh source-only invocation")
    command = request["command"]
    require(len(command) == 7 and command[1:4] == ["-I", "-S", "-B"]
            and command[4:] == [str(source_root / "tools/qualify_hia_selfhost.py"),
                                "--output", str(nested_path)], "isolated original qualifier command")
    require(request.get("cwd") == str(folder / "home") and request.get("env") == {
        "PATH": "/usr/bin:/bin", "HOME": str(folder / "home"), "TMPDIR": str(folder / "tmp"),
        "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "TZ": "UTC"}, "fresh home and controlled environment")

    nested_raw = regular(nested_path)
    require(digest(nested_raw) == cold.get("nested_report_sha256"), "original nested report digest")
    nested = json.loads(nested_raw)
    require(nested.get("status") == "SELF_HOSTED_FIXED_CORE_PASS"
            and nested.get("source_manifest") == expected
            and nested.get("checkout", {}).get("kind") == "source_export", "complete source-matched nested gate")
    nested_checks = nested.get("checks", {})
    require(len(nested_checks) == NESTED_CHECKS and all(value is True for value in nested_checks.values()),
            "all 5049 nested checks at the pinned compiler version")
    generations = [item["produced_sha256"] for item in nested["generations"]]
    require(generations == cold.get("generation_sha256") == [compiler_sha256] * 3,
            "cold B1/B2/B3 images match the actual runtime compiler")
    require(nested["seed"]["python"].get("isolated") is True
            and nested["seed"]["python"].get("no_site") is True, "isolated hosted seed")
    artifacts = {
        report_path.name: digest(report_raw),
        folder.name + "/qualification.json": digest(nested_raw),
        folder.name + "/request.json": digest(export_request_raw),
        folder.name + "/process-owner.json": digest(owner_raw),
        folder.name + "/process-owner.json.request.json": digest(request_raw),
    }
    for name in ("stdout.log", "stderr.log", "process-owner.json.stdout.log", "process-owner.json.stderr.log"):
        artifacts[folder.name + "/" + name] = digest(regular(folder / name))
    return {
        "schema": "hepta.runtime.compiler-cold-evidence.v1", "status": "PASS",
        "compiler_commit": HEPTA_COMMIT, "compiler_tree": HEPTA_TREE,
        "compiler_image_sha256": compiler_sha256, "profile": contract["profile"],
        "qualification_wall_limit_seconds": 180, "cleanup_wall_limit_seconds": 3,
        "checks_passed": len(checks), "checks_total": len(checks),
        "nested_checks_passed": len(nested_checks), "nested_checks_total": len(nested_checks),
        "wall_elapsed_ns": cold["wall_elapsed_ns"], "cleanup_complete": True,
        "source_files": len(expected),
        "source_manifest_sha256": digest(json.dumps(expected, sort_keys=True, separators=(",", ":")).encode()),
        "artifact_sha256": artifacts, "matching_source_full_cold_qualified": True,
        "whole_runtime_replaced": False,
    }
