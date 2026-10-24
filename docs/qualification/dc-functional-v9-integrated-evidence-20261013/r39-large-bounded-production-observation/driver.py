#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Root-reviewed R39 production observation plan. Do not execute during preparation.

The caller must first coordinate a quiet process_start window and supply the
exact pushed checker HEAD, independently reviewed driver SHA and metadata-only
credential dev/ino. This driver performs no activation, service operation,
candidate execution, signal, repair, adoption, replay or production cleanup. Every outcome
is HOLD. Its only observation provider is the pinned real jobs-only adapter.
"""
import argparse
import hashlib
import json
import os
import pathlib
import re
import stat
import subprocess
import sys
import types

ROOT = pathlib.Path("/home/qian-qi/hepta-runtime-dc-functional-20261013")
BRANCH = "refs/heads/feat/operator-parity-20261006"
CHECKER = pathlib.Path("/home/qian-qi/hepta-successor-preflight-checker-large-bounded-20261014-r39")
OUTPUT = pathlib.Path("/home/qian-qi/hepta-runtime-successor-v9-preflight-5037262-20261014-r39")
RETAINED = pathlib.Path("/home/qian-qi/hepta-runtime-successor-v9-inventory-retained-5037262-20261014-r39")
PUBLIC = ROOT / "docs/qualification/dc-functional-v9-integrated-evidence-20261013/r39-large-bounded-production-observation"
SOURCE = pathlib.Path("/home/qian-qi/hepta-runtime-v9-code-frozen-5037262-20261013")
SOURCE_HEAD = "50372629e0522d19b5bc4c1a800bfc311e4597f9"
SOURCE_FP = "b376418a2b3346a707dfd2592f99ce6fbceb6c86c8445995069f1e4ac0ed32bf"
STAGE = pathlib.Path("/home/qian-qi/hepta-runtime-successor-v9-stage-5037262-20261013-r1/manifest.json")
STAGE_SHA = "70357b2065afa9a9f9b5206047bf4134365b540685ac95e2e2588361b0d89689"
REVIEW = pathlib.Path("/home/qian-qi/hepta-runtime-successor-v9-private-profile-5037262-20261013-r1/review.json")
REVIEW_SHA = "32b3d300e1a7c10c32a3669095d23a731ef6d40b42a957a2b07db8771f456d76"
CONFIG = pathlib.Path("/home/qian-qi/.config/hepta-runtime-operator/runtime.json")
CONFIG_SHA = "ebd29c10ed8498f2662c5bab556de701a628e8870631db40cc1e6719db70fac5"
TOKEN = pathlib.Path("/home/qian-qi/.config/hepta-runtime-operator/token")
ENDPOINT = "http://127.0.0.1:8790/mcp"
HOSTS = ("main", "pocket4", "rog", "mac", "x230", "ai395")
PROTECTED = {"hepta-runtime-operator.service": 2863,
             "hepta-openai-full-operator.service": 2873,
             "desktop-commander-remote.service": 2809}
CODE_PINS = {
    "deploy/preflight_dc_successor.py": "7bfcf63208db6992fd31bd398caf4fb5635e5f8253803b1141f71bd0d2d7fb61",
    "deploy/dc_successor_inventory.py": "a198944235a8b71763a612d077bf41c8915028487beb96888da003868e24e5c9",
    "deploy/stage_dc_successor.py": "80fb34a7d55157032a5a8da007d31f289eb2862746ea16747de7b3cb305f0582",
    "deploy/mcp_tool_contract.py": "e2b29f987d3aaa863d7bf6879d0d6a835a807c133c5c355b6a4e69bce9c3e216",
    "deploy/contracts/hepta-runtime-full-operator-v4.json": "d36610d575146805f4c02d89210abd360b4d42acc8736d1966f20d0d724704b1",
}
FIXTURE_PINS = {
    "tests/dc_successor_preflight_tests.py": "d4c7ec13ba794ef02e0bc3e7f3aa7f5c864947dae912efda8ec9ffbfad9e6d8c",
    "tests/dc_successor_inventory_tests.py": "3e0431497a23d56b5f8aeb81c4035173a819134ca44cae48d802b9972849876f",
    "tests/dc_successor_stage_tests.py": "25ebb15d02c73adcb7052b64fc405d4c5aad244edcc69f4f3f851294e98f86e7",
}
MAX_CODE_BYTES = 1024 * 1024
MAX_CAPTURE_BYTES = 32 * 1024 * 1024


def fp(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns, info.st_uid, info.st_gid, info.st_nlink, info.st_mode)


def directory(path):
    path = pathlib.Path(path)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("canonical absolute directory required")
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def token_metadata(expected):
    """No token FD, bytes or digest: only no-follow linked metadata."""
    parent = directory(TOKEN.parent)
    try:
        first_parent = os.fstat(parent)
        if first_parent.st_uid != os.getuid() or stat.S_IMODE(first_parent.st_mode) != 0o700:
            raise ValueError("private credential parent refused")
        first = os.stat(TOKEN.name, dir_fd=parent, follow_symlinks=False)
        if (not stat.S_ISREG(first.st_mode) or first.st_uid != os.getuid()
                or first.st_nlink != 1 or stat.S_IMODE(first.st_mode) not in (0o400, 0o600)
                or (first.st_dev, first.st_ino) != expected):
            raise ValueError("expected credential identity refused")
        after = os.stat(TOKEN.name, dir_fd=parent, follow_symlinks=False)
        linked_parent = TOKEN.parent.lstat()
        if (fp(first) != fp(after) or fp(first) != fp(TOKEN.lstat())
                or (first_parent.st_dev, first_parent.st_ino, first_parent.st_uid, first_parent.st_mode)
                != (linked_parent.st_dev, linked_parent.st_ino, linked_parent.st_uid, linked_parent.st_mode)):
            raise ValueError("credential metadata changed")
        return fp(first)
    finally:
        os.close(parent)


def read_code(path, expected_sha, credential_identity):
    path = pathlib.Path(path)
    token_before = token_metadata(credential_identity)
    if path == TOKEN or fp(path.lstat())[:2] == token_before[:2]:
        raise ValueError("credential cannot be a code or evidence input")
    parent = directory(path.parent)
    descriptor = None
    try:
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                             dir_fd=parent)
        first = os.fstat(descriptor)
        if (not stat.S_ISREG(first.st_mode) or first.st_nlink != 1
                or first.st_uid != os.getuid() or first.st_size > MAX_CODE_BYTES
                or fp(first)[:2] == token_before[:2]):
            raise ValueError("bounded ordinary code input required")
        raw = bytearray()
        while len(raw) <= first.st_size:
            chunk = os.read(descriptor, first.st_size + 1 - len(raw))
            if not chunk:
                break
            raw.extend(chunk)
        after = os.fstat(descriptor)
        linked = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        if len(raw) != first.st_size or fp(first) != fp(after) or fp(after) != fp(linked):
            raise ValueError("code input changed during exact read")
        if token_metadata(credential_identity) != token_before:
            raise ValueError("credential changed during code verification")
        raw = bytes(raw)
        if hashlib.sha256(raw).hexdigest() != expected_sha:
            raise ValueError("reviewed code SHA differs")
        return raw
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent)


def absent(path):
    parent = directory(path.parent)
    try:
        try:
            os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            return
        raise FileExistsError("create-only destination exists; reconcile without retry")
    finally:
        os.close(parent)


def new_directory(path):
    parent = directory(path.parent)
    try:
        os.mkdir(path.name, mode=0o700, dir_fd=parent)
        os.fsync(parent)
    finally:
        os.close(parent)


def save_new(path, raw):
    parent = directory(path.parent)
    try:
        first = os.fstat(parent)
        if first.st_uid != os.getuid() or stat.S_IMODE(first.st_mode) != 0o700:
            raise ValueError("private output directory refused")
        descriptor = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                             0o600, dir_fd=parent)
        with os.fdopen(descriptor, "wb") as writer:
            created = os.fstat(writer.fileno())
            if (not stat.S_ISREG(created.st_mode) or created.st_uid != os.getuid()
                    or created.st_nlink != 1 or stat.S_IMODE(created.st_mode) != 0o600):
                raise ValueError("new private file metadata refused")
            writer.write(raw)
            writer.flush()
            os.fsync(writer.fileno())
            written = os.fstat(writer.fileno())
            linked = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            if (fp(written) != fp(linked) or written.st_size != len(raw)
                    or (created.st_dev, created.st_ino, created.st_uid, created.st_nlink, created.st_mode)
                    != (written.st_dev, written.st_ino, written.st_uid, written.st_nlink, written.st_mode)):
                raise ValueError("new private file changed during publication")
        os.fsync(parent)
        after = os.fstat(parent)
        linked_parent = path.parent.lstat()
        if ((first.st_dev, first.st_ino, first.st_uid, first.st_mode)
                != (after.st_dev, after.st_ino, after.st_uid, after.st_mode)
                or (after.st_dev, after.st_ino, after.st_uid, after.st_mode)
                != (linked_parent.st_dev, linked_parent.st_ino, linked_parent.st_uid, linked_parent.st_mode)):
            raise ValueError("output parent changed")
    finally:
        os.close(parent)


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def git(*arguments):
    result = subprocess.run(["git", "-C", str(ROOT), *arguments], check=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    if len(result.stdout) > MAX_CODE_BYTES:
        raise ValueError("bounded Git observation exceeded")
    return result.stdout


def pushed_head(expected):
    if git("rev-parse", "HEAD").decode().strip() != expected:
        raise ValueError("current checker HEAD differs")
    rows = git("ls-remote", "origin", BRANCH).decode().splitlines()
    if len(rows) != 1 or rows[0].split() != [expected, BRANCH]:
        raise ValueError("exact checker HEAD is not pushed")


def load_raw(name, path, raw):
    if name in sys.modules:
        raise ValueError("repository helper imported before reviewed raw gate")
    module = types.ModuleType(name)
    module.__file__ = str(path)
    sys.modules[name] = module
    exec(compile(raw, str(path), "exec"), module.__dict__)
    return module


def protected_identity(P):
    observation = P.service_observation(TOKEN)
    units = observation.get("units", {})
    if set(units) != set(PROTECTED):
        raise ValueError("three protected units required")
    processes = {}
    for unit, pid in PROTECTED.items():
        if units[unit].get("ActiveState") != "active" or units[unit].get("MainPID") != str(pid):
            raise ValueError("protected production PID differs")
        processes[unit] = P.process_observation(pid)
        if processes[unit].get("uid") != os.getuid():
            raise ValueError("protected production UID differs")
    return {"services": observation, "processes": processes}


def summary(inventory):
    if inventory is None:
        return {"observed": False, "observed_job_rows": None, "actual_total_jobs_claimed": None}
    jobs = inventory["jobs"]
    return {"observed": True, "observed_job_rows": len(jobs),
            "actual_total_jobs_claimed": None,
            "observed_rows_are_an_exhaustive_total_claim": False,
            "status_observed_rows": sum(row.get("status_observed") is True for row in jobs),
            "unknown_or_unobserved_state_rows": sum(row.get("state") == "unknown" or row.get("status_observed") is not True for row in jobs),
            "membership_complete": inventory["membership_complete"],
            "status_observation_complete": inventory["status_observation_complete"],
            "status_authoritative_complete": inventory["status_authoritative_complete"],
            "bindings_complete": inventory["bindings_complete"],
            "jobs_complete": inventory["jobs_complete"],
            "ptys_complete": False, "streams_complete": False,
            "dispatch": {"native_complete": False, "facade_complete": False, "admission_frozen": False},
            "errors": inventory["errors"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checker-head", required=True)
    parser.add_argument("--expected-driver-sha256", required=True)
    parser.add_argument("--expected-token-dev", required=True, type=int)
    parser.add_argument("--expected-token-ino", required=True, type=int)
    args = parser.parse_args()
    public_started = False
    stage = "admission"
    observed = None
    real_observer_entered = False
    retained_inventory_saved = False
    production_before = production_after = None
    token_before = None
    result = None
    failure = None
    closure_stable = False
    credentials_stable = False
    extra_guard_intact = False
    P = I = None
    guarded_inode = None
    expected_identity = (args.expected_token_dev, args.expected_token_ino)
    try:
        if (os.getuid() != 1000 or expected_identity[0] < 0 or expected_identity[1] <= 0
                or not re.fullmatch("[0-9a-f]{40}", args.checker_head)
                or not re.fullmatch("[0-9a-f]{64}", args.expected_driver_sha256)):
            raise ValueError("explicit reviewed pins required")
        token_before = token_metadata(expected_identity)
        driver_raw = read_code(pathlib.Path(__file__).absolute(), args.expected_driver_sha256, expected_identity)
        pushed_head(args.checker_head)
        for path in (CHECKER, OUTPUT, RETAINED, PUBLIC):
            absent(path)
        blobs = {}
        for relative, pin in {**CODE_PINS, **FIXTURE_PINS}.items():
            raw = git("show", args.checker_head + ":" + relative)
            if hashlib.sha256(raw).hexdigest() != pin:
                raise ValueError("committed checker or fixture source SHA differs")
            if relative in CODE_PINS:
                blobs[relative] = raw
        new_directory(PUBLIC)
        public_started = True
        save_new(PUBLIC / "driver.py", driver_raw)
        cli = ["--stage-manifest", str(STAGE), "--stage-manifest-sha256", STAGE_SHA,
               "--source-root", str(SOURCE), "--output-directory", str(OUTPUT),
               "--profile-review-manifest", str(REVIEW), "--profile-review-manifest-sha256", REVIEW_SHA,
               "--inventory-observer", "large-bounded", "--inventory-budget-seconds", "300",
               "--inventory-rpc-timeout-seconds", "30"]
        save_new(PUBLIC / "00-intent.json", encoded({"schema": "hepta-r39-large-bounded-readonly-observation-intent-v1",
            "checker_head": args.checker_head, "exact_remote_HEAD_verified": True,
            "code_pins": CODE_PINS, "fixture_source_pins": FIXTURE_PINS,
            "driver_sha256": args.expected_driver_sha256, "checker": str(CHECKER),
            "source_root": str(SOURCE), "candidate_source_HEAD": SOURCE_HEAD,
            "candidate_compile_source_fingerprint": SOURCE_FP,
            "stage_manifest": {"path": str(STAGE), "sha256": STAGE_SHA},
            "private_profile_proof": {"path": str(REVIEW), "sha256": REVIEW_SHA},
            "runtime_config": {"path": str(CONFIG), "sha256": CONFIG_SHA},
            "expected_token_metadata_identity": {"dev": expected_identity[0], "ino": expected_identity[1]},
            "credential_inode_guard": "original metadata-only function return plus exact expected dev/ino comparison",
            "fixed_endpoint": ENDPOINT, "fixed_hosts": HOSTS, "cli": cli,
            "inventory_budget_seconds": 300, "inventory_rpc_timeout_seconds": 30,
            "output": str(OUTPUT), "private_retained_observation": str(RETAINED),
            "effect_result_known": False, "automatic_retry": False,
            "production_mutation_or_candidate_execution": False, "new_backup_or_profile_copy": False,
            "token_file_copy_read_or_hash_by_driver": False, "full_DC_replacement_qualified": False,
            "observation_window_or_admission_freeze_proven_by_this_driver": False}))
        stage = "freeze-reviewed-code"
        new_directory(CHECKER)
        new_directory(CHECKER / "deploy")
        new_directory(CHECKER / "deploy/contracts")
        for relative, raw in blobs.items():
            save_new(CHECKER / relative, raw)
        new_directory(RETAINED)
        sys.dont_write_bytecode = True
        verified = {relative: read_code(CHECKER / relative, pin, expected_identity)
                    for relative, pin in CODE_PINS.items()}
        load_raw("mcp_tool_contract", CHECKER / "deploy/mcp_tool_contract.py", verified["deploy/mcp_tool_contract.py"])
        S = load_raw("stage_dc_successor", CHECKER / "deploy/stage_dc_successor.py", verified["deploy/stage_dc_successor.py"])
        I = load_raw("dc_successor_inventory", CHECKER / "deploy/dc_successor_inventory.py", verified["deploy/dc_successor_inventory.py"])
        P = load_raw("preflight_dc_successor", CHECKER / "deploy/preflight_dc_successor.py", verified["deploy/preflight_dc_successor.py"])
        if (P.ENDPOINT != ENDPOINT or tuple(P.HOSTS) != HOSTS or tuple(I.HOSTS) != HOSTS
                or I.MAX_BUDGET_SECONDS != 300 or I.MAX_RPC_SECONDS != 30
                or I.MAX_RECORDS != 16384 or I.HTTP_MAX_BYTES != 32 * 1024 * 1024):
            raise ValueError("pinned jobs-only bounds or authority differ")
        original_inode = I.credential_inode
        def guarded_inode(path):
            identity = original_inode(path)
            if pathlib.Path(path) != TOKEN or identity != expected_identity:
                raise I.InventoryError("CredentialChanged")
            return identity
        I.credential_inode = guarded_inode
        stage = "verify-live-readonly-inputs"
        if guarded_inode(TOKEN) != expected_identity:
            raise I.InventoryError("CredentialChanged")
        P.refuse_token_source(CONFIG, TOKEN)
        _, config_pin = S.read_pinned(CONFIG, CONFIG_SHA, "fixed main runtime configuration")
        parsed_args = P.parser().parse_args(cli)
        manifest, _, _ = P.validate_stage(parsed_args)
        if (manifest["source"]["base_HEAD"] != SOURCE_HEAD
                or manifest["source"]["source_code_fingerprint"] != SOURCE_FP
                or manifest["baseline"]["auth_token_file"] != str(TOKEN)
                or manifest["baseline"]["live_files"]["runtime_config"]["path"] != str(CONFIG)
                or manifest["baseline"]["live_files"]["runtime_config"]["sha256"] != CONFIG_SHA):
            raise ValueError("stage is not the fixed source/config/credential authority")
        production_before = protected_identity(P)
        stage = "real-large-bounded-observation"
        def real_observer(value):
            nonlocal observed, real_observer_entered, retained_inventory_saved
            real_observer_entered = True
            actual = P.large_bounded_inventory_observation(value, budget_seconds=300.0, rpc_timeout=30.0)
            observed = I.sanitized_inventory(actual)
            if (observed["ptys_complete"] is not False or observed["streams_complete"] is not False
                    or any(flag is not False for flag in observed["dispatch"].values())):
                raise ValueError("jobs-only observation widened other completeness fields")
            data = encoded(observed)
            if len(data) > MAX_CAPTURE_BYTES:
                raise ValueError("bounded retained observation exceeded")
            save_new(RETAINED / "observed-inventory.json", data)
            retained_inventory_saved = True
            return actual  # Original actual result; no synthetic statuses or fixture responses.
        prepared = P.prepare_preflight(parsed_args, inventory_probe=real_observer)
        stage = "publish-validated-HOLD"
        if (prepared["report"]["status"] != "HOLD"
                or prepared["report"]["full_dc_replacement_qualified"] is not False
                or prepared["report"]["private_profile_review"]["prepared"] is not True
                or prepared["report"]["private_profile_review"]["administrator_review_completed"] is not False):
            raise ValueError("preflight cannot grant cutover or profile-review authority")
        result = P.publish(prepared, parsed_args)
        if result["status"] != "HOLD" or result["activated"] is not False:
            raise ValueError("unexpected preflight publication authority")
    except Exception as error:
        failure = {"stage": stage, "error_type": type(error).__name__, "private_exception_message_saved": False}
    finally:
        if P is not None:
            try:
                production_after = protected_identity(P)
            except Exception as error:
                failure = {"stage": "final-production-identity", "error_type": type(error).__name__, "private_exception_message_saved": False}
        try:
            credentials_stable = token_before is not None and token_metadata(expected_identity) == token_before
            if P is not None:
                extra_guard_intact = guarded_inode is not None and I.credential_inode is guarded_inode
            if public_started:
                pushed_head(args.checker_head)
                read_code(pathlib.Path(__file__).absolute(), args.expected_driver_sha256, expected_identity)
                for relative, pin in CODE_PINS.items():
                    read_code(CHECKER / relative, pin, expected_identity)
                for relative, pin in {**CODE_PINS, **FIXTURE_PINS}.items():
                    if hashlib.sha256(git("show", args.checker_head + ":" + relative)).hexdigest() != pin:
                        raise ValueError("final committed dependency differs")
                closure_stable = True
        except Exception as error:
            failure = {"stage": "final-input-closure", "error_type": type(error).__name__, "private_exception_message_saved": False}
        if not public_started:
            print(json.dumps({"status": "HOLD", "validation_complete": False,
                              "error_type": failure["error_type"] if failure is not None else "ObservationError",
                              "private_exception_message_saved": False,
                              "create_only_outputs_started": False}), file=sys.stderr)
            return 1
        stable_production = production_before is not None and production_after == production_before
        settled = {"schema": "hepta-r39-large-bounded-readonly-observation-settled-v1",
            "status": "HOLD", "checker_head": args.checker_head,
            "driver_sha256": args.expected_driver_sha256, "code_pins": CODE_PINS,
            "fixture_source_pins": FIXTURE_PINS, "fixture_tests_executed_by_driver": False,
            "source_closure_before_after_stable": closure_stable,
            "credential_metadata_before_after_stable": credentials_stable,
            "additional_expected_inode_guard_intact": extra_guard_intact,
            "production_identities_before": production_before, "production_identities_after": production_after,
            "production_identities_stable": stable_production,
            "inventory": summary(observed), "failure": failure, "checker_publication": result,
            "validation_complete": bool(result and result.get("validation_complete") is True and failure is None
                                        and closure_stable and credentials_stable and stable_production and extra_guard_intact),
            "private_retained_observation": str(RETAINED / "observed-inventory.json") if retained_inventory_saved else None,
            "real_adapter_entered": real_observer_entered, "real_adapter_returned_observation": observed is not None,
            "actual_HTTP_request_count_claimed": None, "synthetic_or_fixture_statuses_injected": False,
            "credential_inode_original_function_replaced_with_fake": False,
            "original_observer_full_stat_checks_before_every_new_RPC_unchanged": True,
            "candidate_compiled_source_relabelled": False, "candidate_activated": False,
            "services_changed_by_driver": False, "production_signals_adoption_replay_repair_cleanup": False,
            "new_backups_or_profile_copies": False, "auth_token_file_hashed_or_copied": False,
            "auth_token_read_scope": "only audited non-hashing RAM reader supplied to fixed-loopback actual adapter",
            "PTY_stream_dispatch_admission_complete": False, "administrator_profile_review_granted": False,
            "full_DC_replacement_qualified": False, "business_replacement_qualified": False,
            "actual_run_is_not_cutover_or_CI_or_business_acceptance": True,
            "automatic_retry": False, "retain_independent_observation_and_production_paths_on_failure": True,
            "new_report_bundle_rollback_may_remove_its_owned_new_OUTPUT": True,
            "DC_rescue_retained": True}
        try:
            if public_started:
                save_new(PUBLIC / "01-settled.json", encoded(settled))
        except Exception as error:
            print(json.dumps({"status": "HOLD", "validation_complete": False,
                              "error_type": type(error).__name__, "retained_paths_not_retried": True}), file=sys.stderr)
            return 1
        print(json.dumps(settled, sort_keys=True))
    return 0 if settled["validation_complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
