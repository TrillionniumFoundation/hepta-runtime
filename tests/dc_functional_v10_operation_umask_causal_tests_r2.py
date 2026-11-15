#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Owned native causal proof: original fixture with 0022 versus explicit 0700.

Original approved harness bytes and product permissions stay unchanged. Only
original Popen handles and their exact local readonly helper adapter are used.
No real SSH, production token, service, business job or deployment is changed.
"""
import argparse
import hashlib
import json
import os
import pathlib
import stat
import subprocess
import sys
import types

OLD_SHA = "3c3e53a1f9e63954e251580ed643be743da4add4702b166faece762b4486b5fa"
MCP_SHA = "e2b29f987d3aaa863d7bf6879d0d6a835a807c133c5c355b6a4e69bce9c3e216"
STAGE_SHA = "80fb34a7d55157032a5a8da007d31f289eb2862746ea16747de7b3cb305f0582"
CONTRACT_SHA = "12994454084369fb31e44f0e1ceb7a7f2ace5bbed33057789399cf895e70d553"
PREVIOUS_SHA = "3eb628812d0c70b9af8393ecf9d0ce47f69b1438a134148f75ae2dd3132e6761"


def snapshot(path, expected, limit=1048576):
    path = pathlib.Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        first = os.fstat(fd)
        if not stat.S_ISREG(first.st_mode) or first.st_nlink != 1 or first.st_size > limit:
            raise ValueError("bounded single-link reviewed source/artifact required")
        chunks, count = [], 0
        while count <= first.st_size:
            chunk = os.read(fd, min(1048576, first.st_size + 1 - count))
            if not chunk:
                break
            chunks.append(chunk)
            count += len(chunk)
        fields = lambda s: (s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode, s.st_nlink,
                             s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        if count != first.st_size or fields(first) != fields(os.fstat(fd)) or fields(first) != fields(path.lstat()):
            raise ValueError("reviewed descriptor/name changed")
    finally:
        os.close(fd)
    raw = b"".join(chunks)
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError("reviewed source/artifact digest differs")
    return raw


def loaded(name, path, expected):
    raw = snapshot(path, expected)
    module = types.ModuleType(name)
    module.__file__ = str(path)
    sys.modules[name] = module
    exec(compile(raw, str(path), "exec"), module.__dict__)
    return module


def private_write(path, value):
    raw = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        position = 0
        while position < len(raw):
            count = os.write(fd, raw[position:])
            if count <= 0:
                raise OSError("short owned causal receipt write")
            position += count
        os.fsync(fd)
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("repo-root", "binary", "expected-binary-sha256", "expected-source-fingerprint",
                 "expected-head", "new-harness", "expected-new-harness-sha256", "out"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    root, binary, newpath = (pathlib.Path(value).resolve(strict=True) for value in
                             (args.repo_root, args.binary, args.new_harness))
    output = pathlib.Path(args.out).resolve()
    if output.exists():
        raise ValueError("never overwrite earlier causal evidence")
    # These helper modules only define the already reviewed source observer.
    loaded("mcp_tool_contract", root / "deploy/mcp_tool_contract.py", MCP_SHA)
    stage = loaded("_causal_reviewed_stage", root / "deploy/stage_dc_successor.py", STAGE_SHA)
    baseline = stage.source_identity(root)
    if (baseline["base_HEAD"] != args.expected_head or baseline["source_code_fingerprint"] != args.expected_source_fingerprint):
        raise ValueError("explicit CODEHEAD/full compiler identity differs")
    snapshot(binary, args.expected_binary_sha256, 512 * 1024 * 1024)
    oldpath = root / "tests/dc_functional_v10_operation_acceptance.py"
    snapshot(oldpath, OLD_SHA)
    snapshot(newpath, args.expected_new_harness_sha256)
    contract = root / "deploy/contracts/hepta-runtime-full-operator-v10.json"
    previous = root / "deploy/contracts/hepta-runtime-full-operator-v9.json"
    snapshot(contract, CONTRACT_SHA)
    snapshot(previous, PREVIOUS_SHA)
    output.mkdir(mode=0o700)
    report = {"schema": "hepta-v10-operation-owned-umask-causal-v1", "source_before": baseline,
        "original_harness_sha256": OLD_SHA, "new_harness_sha256": args.expected_new_harness_sha256,
        "binary_sha256": args.expected_binary_sha256, "child_umask_forced": "0022", "cases": [],
        "original_ci_failure_cause_not_observed_directly": True,
        "real_ssh_qualified": False, "six_machine_qualified": False, "model_origin_qualified": False,
        "full_dc_replacement_qualified": False, "installed_runtime_changed": False, "desktop_commander_changed": False}
    original_popen = subprocess.Popen
    def owned_popen(argv, *positional, **keywords):
        if not isinstance(argv, list) or len(argv) < 2 or pathlib.Path(argv[0]) != binary or argv[1] != "mcp":
            raise ValueError("only owned candidate controller Popen allowed")
        keywords["umask"] = 0o022
        return original_popen(argv, *positional, **keywords)
    try:
        for label, path, pin, expected_code in (("original_missing_private_state", oldpath, OLD_SHA, 1),
                ("new_explicit_private_state", newpath, args.expected_new_harness_sha256, 0)):
            if stage.source_identity(root) != baseline:
                raise ValueError("whole compiler/CODEHEAD identity changed before owned case")
            module = loaded("_owned_causal_" + label, path, pin)
            module.ROOT = root  # Explicit frozen checkout for both source identity and exact helpers.
            case = {"case": label, "expected_exit_code": expected_code, "observed_state_modes": [],
                    "first_admission_observed": False, "first_admission_sdk_is_error": None,
                    "first_admission_error_category": "not_observed", "native_protocol_qualified": False}
            original_start, original_raw = module.Controller.start, module.Client.raw_call
            def observed_start(controller):
                client = original_start(controller)
                cfg = json.loads(controller.config.read_bytes())
                state = pathlib.Path(cfg["state_dir"])
                if state.parent != controller.config.parent:
                    raise ValueError("owned fixture state reference differs")
                info = state.lstat()
                if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
                    raise ValueError("owned fixture state directory required")
                case["observed_state_modes"].append(format(stat.S_IMODE(info.st_mode), "04o"))
                return client
            def observed_raw(client, tool, arguments, meta=None):
                result = original_raw(client, tool, arguments, meta)
                if (not case["first_admission_observed"] and tool == "operation_start" and
                    arguments.get("operation", {}).get("tool") == "read_multiple_files" and
                    set(arguments.get("operation", {}).get("arguments", {})) == {"host", "paths", "max_file_bytes", "max_response_bytes"}):
                    case["first_admission_observed"] = True
                    case["first_admission_sdk_is_error"] = result.get("isError") is True
                    texts = [part.get("text") for part in result.get("content", []) if part.get("type") == "text"]
                    # Publish only an enum for the exact public Rust source literal.
                    case["first_admission_error_category"] = ("private_async_directory_unavailable"
                        if result.get("isError") is True and texts == ["private async directory unavailable"]
                        else "other_tool_error" if result.get("isError") is True else "none")
                return result
            module.Controller.start, module.Client.raw_call = observed_start, observed_raw
            outfile = output / (label + ".json")
            arguments = [str(path), "--binary", str(binary), "--expected-binary-sha256", args.expected_binary_sha256,
                "--expected-source-fingerprint", args.expected_source_fingerprint, "--expected-head", args.expected_head,
                "--previous-contract", str(previous), "--expected-previous-contract-sha256", PREVIOUS_SHA,
                "--contract", str(contract), "--expected-contract-sha256", CONTRACT_SHA, "--out", str(outfile)]
            previous_argv = sys.argv
            original_module_subprocess = module.subprocess
            def readonly_git(argv, *positional, **keywords):
                if argv != ["git", "-C", str(root), "rev-parse", "HEAD"]:
                    raise ValueError("only original fixed readonly Git identity call allowed")
                return subprocess.check_output(argv, *positional, **keywords)
            module.subprocess = types.SimpleNamespace(Popen=owned_popen,
                check_output=readonly_git, DEVNULL=subprocess.DEVNULL, TimeoutExpired=subprocess.TimeoutExpired)
            try:
                sys.argv = arguments
                code = module.main()
            finally:
                sys.argv, module.subprocess = previous_argv, original_module_subprocess
            receipt = json.loads(outfile.read_bytes())
            case.update(observed_exit_code=code, owned_controller_cleanup=receipt.get("owned_controller_cleanup"),
                        owned_helper_cleanup=receipt.get("owned_helper_cleanup"), passed_checks=len(receipt.get("checks", [])),
                        failed_phase=receipt.get("failed_phase"), error_frames=receipt.get("error_frames", []))
            if code != expected_code or case["owned_controller_cleanup"] is not True or case["owned_helper_cleanup"] is not True:
                raise ValueError("owned native causal outcome/cleanup differs")
            if expected_code:
                if (case["observed_state_modes"] != ["0755"] or case["first_admission_sdk_is_error"] is not True or
                    case["first_admission_error_category"] != "private_async_directory_unavailable"):
                    raise ValueError("specific native state-mode refusal was not observed")
            else:
                if (not case["observed_state_modes"] or any(mode != "0700" for mode in case["observed_state_modes"]) or
                    case["first_admission_sdk_is_error"] is not False or receipt.get("complete") is not True or case["passed_checks"] != 16):
                    raise ValueError("explicit private-state full native positive proof missing")
                case["native_protocol_qualified"] = True
            report["cases"].append(case)
            private_write(output / (label + "-causal.json"), case)
        report["source_after"] = stage.source_identity(root)
        if report["source_after"] != baseline:
            raise ValueError("whole compiler/CODEHEAD identity changed")
        snapshot(binary, args.expected_binary_sha256, 512 * 1024 * 1024)
        snapshot(oldpath, OLD_SHA)
        snapshot(newpath, args.expected_new_harness_sha256)
        report["complete_owned_causal_proof"] = True
        private_write(output / "receipt.json", report)
        print("PASS_OWNED_UMASK0022_REFUSAL_AND_EXPLICIT0700_NATIVE16", flush=True)
    finally:
        if subprocess.Popen is not original_popen:
            raise ValueError("global subprocess Popen unexpectedly changed")


if __name__ == "__main__":
    try:
        main()
    except BaseException as error:
        print("OWNED_UMASK_CAUSAL_FAILED_TYPE", type(error).__name__, file=sys.stderr)
        raise SystemExit(1)
