#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Offline V9 signal-fixture safety protocol: new explicitly pinned source; no runtime acceptance.

Every target operation and every recovery-record write is mocked. Generated
remote Python is parsed, never executed. No controller, native candidate, SSH,
service, health endpoint, remote fixture, or signal is started by this suite.
The child/bridge bytes and five signal phases remain the frozen V6 algorithm;
these safety tests do not constitute new signal or full replacement acceptance.
"""
import ast
import copy
import hashlib
import json
import pathlib
import subprocess
import sys
import unittest
from unittest import mock

sys.dont_write_bytecode = True
root = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / "tests"))
import argparse
import importlib.util
import re
import subprocess

BASELINE_HEAD="3c924c02416ef23f747d99a536c027fb246f2b8e"
BASELINE_JSON_SHA="4ef7eb288773b1e7f073ac07573669b2097c95187ebcf7eecb0ad38c10b98811"
ORIGINAL_V8_LOADER_SHA="ae4958001986b56e26871d7f1c2f3e7f543e6bda37fbc3d1b832c8435e84870e"
V8_CONTRACT_SHA="b64769210b9913fbdab28f7d0e95b7ef300d8710b3f1eeea74afcfac25b08318"
V9_CONTRACT_SHA="3eb628812d0c70b9af8393ecf9d0ce47f69b1438a134148f75ae2dd3132e6761"

def _pinned_file(relative,expected):
    path=root/relative
    if not re.fullmatch('[0-9a-f]{64}',expected) or path.is_symlink() or not path.is_file():
        raise ValueError('ordinary explicitly pinned V9 safety input required')
    data=path.read_bytes()
    if hashlib.sha256(data).hexdigest()!=expected:
        raise ValueError('V9 safety pre-import SHA differs: '+relative)
    return path

def _bootstrap():
    parser=argparse.ArgumentParser(description='V9-only mock/AST safety suite; explicit pre-import source pins')
    for name in ('signal-harness','health-harness','version-helper','loader','tool-helper','http-helper'):
        parser.add_argument('--expected-'+name+'-sha256',required=True)
    args,remaining=parser.parse_known_args()
    sys.argv=[sys.argv[0],*remaining]
    supplied={
        'tests/dc_functional_v9_signal_audit_acceptance.py':args.expected_signal_harness_sha256,
        'tests/dc_functional_v9_health_multiread_acceptance.py':args.expected_health_harness_sha256,
        'tests/dc_functional_v9_version_pin.py':args.expected_version_helper_sha256,
        'tests/dc_successor_contract.py':args.expected_loader_sha256,
        'deploy/mcp_tool_contract.py':args.expected_tool_helper_sha256,
        'tests/runtime_http_acceptance.py':args.expected_http_helper_sha256,
        'tests/dc_parity_release_six_host_acceptance.py':'f9ec9fdeb9a5aaa77cb6f813aa7afe4dd3db24f199731a20d579f687c3883227',
        'tests/dc_functional_v8_signal_audit_acceptance.py':'3b7c30bc34ed76fb2f194a26615004db5c22519182a29c9673b860aea858151e',
        'tests/dc_functional_v8_health_multiread_acceptance.py':'0812beefd088d523b89513b793da9c729fc64e1dc204406194e98ee72e0c23c8',
        'tests/dc_functional_v6_signal_audit_acceptance.py':'09c1a651992347eb02d70fb077db84713a807978b13482a3a96d96b44669aaf3',
        'tests/host_health_acceptance.py':'73f1105414b5362ab007843b4138ac7dc3bb43766630da7f70406283705cd5ea',
        'tests/multi_read_six_host_acceptance.py':'55b91cc2ef6207e0f23eefd3584a890621e8bf075926aa676f3b79debaf35f57',
        'deploy/contracts/hepta-runtime-full-operator-v8.json':V8_CONTRACT_SHA,
        'deploy/contracts/hepta-runtime-full-operator-v9.json':V9_CONTRACT_SHA,
        'tests/fixtures/dc_successor_contract_v8_ae495800.py':ORIGINAL_V8_LOADER_SHA,
        'docs/qualification/v9-harness-drafts-20261013/original-active-script-baseline-r1.json':BASELINE_JSON_SHA,
    }
    for relative,pin in supplied.items():_pinned_file(relative,pin)
    baseline=json.loads((root/'docs/qualification/v9-harness-drafts-20261013/original-active-script-baseline-r1.json').read_text())
    if (baseline['base_HEAD']!=BASELINE_HEAD or baseline['copied_script_and_contract_files']['tests/dc_successor_contract.py']['sha256']!=ORIGINAL_V8_LOADER_SHA):
        raise ValueError('original V8 loader baseline differs')
    historical=(root/'tests/fixtures/dc_successor_contract_v8_ae495800.py').read_bytes()
    if hashlib.sha256(historical).hexdigest()!=ORIGINAL_V8_LOADER_SHA:
        raise ValueError('archived historical loader bytes differ; old results cannot authorize the V9 loader')
    # Neither historical loader nor historical test main is imported/executed.
    return args,supplied,{'base_HEAD':BASELINE_HEAD,'loader_sha256':ORIGINAL_V8_LOADER_SHA,
        'loader_bytes':len(historical),'archived_byte_reference':'tests/fixtures/dc_successor_contract_v8_ae495800.py',
        'archived_loader_imported':False,'Git_history_object_needed':False,'historical_run_qualification_borrowed':False}

pin_args,PREIMPORT_PINS,ORIGINAL_V8_LOADER_PROVENANCE=_bootstrap()

def _load(relative,name):
    path=_pinned_file(relative,PREIMPORT_PINS[relative])
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module

H=_load('tests/dc_functional_v9_signal_audit_acceptance.py','offline_v9_signal')

old = root / "tests/dc_functional_v6_signal_audit_acceptance.py"
new = root / "tests/dc_functional_v9_signal_audit_acceptance.py"
old_expected = "09c1a651992347eb02d70fb077db84713a807978b13482a3a96d96b44669aaf3"
new_expected = pin_args.expected_signal_harness_sha256
INPUTS = [
    pathlib.Path(__file__).resolve(), old, new,
    root / "tests/dc_parity_release_six_host_acceptance.py",
    root / "tests/runtime_http_acceptance.py",
    root / "tests/dc_successor_contract.py",
    root / "deploy/mcp_tool_contract.py",
]
INPUTS.extend(root/relative for relative in PREIMPORT_PINS if root/relative not in INPUTS)


def input_bindings():
    return {path.relative_to(root).as_posix(): {
        "bytes": path.stat().st_size,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    } for path in INPUTS}


def ack(item):
    return {"schema": "hepta-v8-owned-signal-fixture-v1",
            **{key: item[key] for key in ("host", "base", "root", "nonce", "uid", "platform")}}


def calls_named(source, names):
    tree = ast.parse(source)
    return [node for node in ast.walk(tree) if isinstance(node, ast.Call) and (
        (isinstance(node.func, ast.Attribute) and node.func.attr in names)
        or (isinstance(node.func, ast.Name) and node.func.id in names))]


def readonly(source):
    """Reject writes by AST; do not execute even a purported read-only script."""
    tree = ast.parse(source)
    assert not calls_named(source, {"mkdir", "makedirs", "write_text", "write_bytes",
        "unlink", "rmtree", "replace", "rename", "remove", "fchmod", "fsync"})
    assert not any(isinstance(node, ast.Attribute) and node.attr in {
        "O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_EXCL"} for node in ast.walk(tree))


class Offline(unittest.TestCase):
    def setUp(self):
        self.item = H.planned_fixture("main", dict(H.HOSTS)["main"], "1" * 32)
        self.path = pathlib.Path("/synthetic/no-file-written.json")
        self.sources = []
        self.records = []
        self.events = []

    def save(self, path, item):
        self.assertEqual(path, self.path)
        self.records.append(copy.deepcopy(item))
        self.events.append("save")

    def env(self):
        return {"parent": self.item["parent"], "uid": 1000, "platform": self.item["platform"]}

    def remote(self, ssh, source):
        self.assertEqual(ssh, self.item["ssh_target"])
        ast.parse(source)
        self.sources.append(source)
        self.events.append("ssh")
        if len(self.sources) == 1:
            readonly(source)
            return self.env()
        if len(self.sources) == 2:
            return ack(self.item)
        readonly(source)
        return {"present": True, "owned": True, "readonly": True, "layout_complete": True}

    def prepare(self, side_effect=None):
        with mock.patch.object(H, "target_python", side_effect=side_effect or self.remote), \
             mock.patch.object(H, "save_fixture_record", side_effect=self.save):
            return H.prepare_fixture(self.item["ssh_target"], self.item, self.path)

    def assert_one_create(self):
        self.assertEqual(sum(bool(calls_named(source, {"mkdir"})) for source in self.sources), 1)
        self.assertEqual(self.item["base"], "/tmp/hepta-v8-signal-audit-" + "1" * 32)
        self.assertEqual(self.item["nonce"], "1" * 32)
        if len(self.sources) > 2:
            readonly(self.sources[-1])

    def test_plans_are_fixed_host_authority_nonce_path_and_mac_parent(self):
        self.assertEqual(self.item["base"],
            self.item["parent"] + "/hepta-v8-signal-audit-" + "1" * 32)
        mac = H.planned_fixture("mac", dict(H.HOSTS)["mac"], "a" * 32)
        self.assertEqual(mac["parent"], "/private/tmp")
        self.assertEqual(mac["platform"], "macos")
        for name, ssh, nonce in [
            ("rog", "localhost", "1" * 32), ("other", "localhost", "1" * 32),
            ("main", dict(H.HOSTS)["main"], "../root"),
            ("main", dict(H.HOSTS)["main"], "A" * 32),
        ]:
            with self.subTest(name=name, nonce=nonce), self.assertRaises(ValueError):
                H.planned_fixture(name, ssh, nonce)

    def test_success_is_one_create_after_uid_durable_attempt_and_before_confirm(self):
        result = self.prepare()
        self.assertIs(result, self.item)
        self.assertTrue(result["prepare_confirmed"])
        self.assertTrue(result["prepare_attempted"])
        self.assertEqual(self.events, ["ssh", "save", "ssh", "save"])
        self.assertEqual(len(self.records), 2)
        self.assertEqual(self.records[0]["uid"], 1000)
        self.assertFalse(self.records[0]["prepare_confirmed"])
        self.assertTrue(self.records[0]["prepare_attempted"])
        self.assertTrue(self.records[1]["prepare_confirmed"])
        self.assert_one_create()

    def test_main_saves_all_planned_paths_before_first_prepare(self):
        tree = ast.parse(new.read_text())
        main = next(node for node in tree.body
                    if isinstance(node, ast.FunctionDef) and node.name == "main")
        plans = [node.lineno for node in ast.walk(main)
                 if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                 and node.func.id == "save_fixture_record"]
        prepares = [node.lineno for node in ast.walk(main)
                    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                    and node.func.id == "prepare_fixture"]
        self.assertTrue(plans)
        self.assertTrue(prepares)
        self.assertLess(min(plans), min(prepares))

    def test_lost_prepare_ack_reconciles_same_path_readonly_and_still_raises(self):
        error = H.TargetOperationError("NonzeroSSHExit", 255, b"ack transport lost", b"")
        def remote(ssh, source):
            result = self.remote(ssh, source)
            if len(self.sources) == 2:
                raise error
            return result
        with self.assertRaises(H.TargetOperationError) as caught:
            self.prepare(remote)
        self.assertIs(caught.exception, error)
        self.assertEqual(len(self.sources), 3)
        self.assert_one_create()
        self.assertFalse(self.item["prepare_confirmed"])
        self.assertTrue(self.item["prepare_attempted"])
        self.assertTrue(self.item["reconcile_readonly"]["readonly"])
        self.assertTrue(self.item["reconcile_readonly"]["owned"])
        self.assertFalse(self.records[-1]["prepare_confirmed"])
        self.assertEqual(self.records[-1]["base"], self.item["base"])
        with mock.patch.object(H, "target_python") as transport:
            for operation in ("remove", "release", "ready", "counter"):
                with self.subTest(operation=operation), self.assertRaises(ValueError):
                    H.owned_query(self.item["ssh_target"], self.item, operation)
            transport.assert_not_called()

    def test_wrong_nonce_root_uid_or_platform_ack_never_adopts_returned_metadata(self):
        for field, bad in [
            ("nonce", "2" * 32), ("root", "/not-owned"), ("uid", 999),
            ("platform", "macos"), ("base", "/not-owned"),
        ]:
            with self.subTest(field=field):
                self.setUp()
                def remote(ssh, source):
                    value = self.remote(ssh, source)
                    if len(self.sources) == 2:
                        return {**value, field: bad}
                    return value
                with self.assertRaises(ValueError):
                    self.prepare(remote)
                self.assertEqual(len(self.sources), 3)
                self.assert_one_create()
                self.assertFalse(self.item["prepare_confirmed"])
                self.assertEqual(self.item["uid"], 1000)
                self.assertEqual(self.item["root"], self.item["base"] + "/workspace")
                self.assertEqual(self.item["platform"], "linux")

    def test_environment_failure_performs_no_create_and_keeps_unattempted_plan(self):
        for bad in [
            {"parent": "/elsewhere", "uid": 1000, "platform": "linux"},
            {"parent": "/tmp", "uid": True, "platform": "linux"},
            {"parent": "/tmp", "uid": 1000, "platform": "macos"},
        ]:
            with self.subTest(environment=bad):
                self.setUp()
                def remote(ssh, source):
                    self.sources.append(source)
                    readonly(source)
                    return bad
                with self.assertRaises(ValueError):
                    self.prepare(remote)
                self.assertEqual(len(self.sources), 1)
                self.assertEqual(self.records, [])
                self.assertFalse(self.item["prepare_attempted"])
                self.assertIsNone(self.item["uid"])

    def test_environment_transport_failure_never_attempts_create(self):
        def remote(ssh, source):
            self.sources.append(source)
            readonly(source)
            raise H.TargetOperationError("TimeoutExpired")
        with self.assertRaises(H.TargetOperationError):
            self.prepare(remote)
        self.assertEqual(len(self.sources), 1)
        self.assertFalse(self.item["prepare_attempted"])
        self.assertEqual(self.records, [])

    def test_missing_fixture_after_lost_ack_is_readonly_observation_and_run_still_fails(self):
        def remote(ssh, source):
            value = self.remote(ssh, source)
            if len(self.sources) == 2:
                raise H.TargetOperationError("TimeoutExpired")
            if len(self.sources) == 3:
                return {"present": False, "owned": False, "readonly": True}
            return value
        with self.assertRaises(H.TargetOperationError):
            self.prepare(remote)
        self.assertEqual(self.item["reconcile_readonly"],
                         {"present": False, "owned": False, "readonly": True})
        self.assertFalse(self.item["prepare_confirmed"])
        self.assert_one_create()

    def test_failed_reconcile_retains_plan_diagnostic_without_second_create(self):
        def remote(ssh, source):
            value = self.remote(ssh, source)
            if len(self.sources) == 2:
                raise H.TargetOperationError("NonzeroSSHExit", 255, b"prepare failed")
            if len(self.sources) == 3:
                raise H.TargetOperationError("TimeoutExpired", None, b"reconcile failed")
            return value
        with self.assertRaises(H.TargetOperationError):
            self.prepare(remote)
        self.assertEqual(self.item["reconcile_error_type"], "TargetOperationError")
        self.assertEqual(self.item["reconcile_transport"]["transport_error_type"], "TimeoutExpired")
        self.assertFalse(self.item["prepare_confirmed"])
        self.assertIsNone(self.item["reconcile_readonly"])
        self.assert_one_create()

    def test_reconcile_cannot_claim_writable_or_malformed_confirmation(self):
        self.item.update(uid=1000, prepare_attempted=True)
        for invalid in [
            {"present": True, "owned": True, "readonly": False, "layout_complete": True},
            {"present": True, "owned": True, "readonly": True},
            {"present": "yes", "owned": True, "readonly": True, "layout_complete": True},
            None,
        ]:
            with self.subTest(acknowledgement=invalid), \
                 mock.patch.object(H, "target_python", return_value=invalid):
                with self.assertRaises(ValueError):
                    H.reconcile_fixture(self.item["ssh_target"], self.item)

    def test_guard_ast_binds_nonce_path_owner_private_modes_single_link_and_nofollow(self):
        self.item.update(uid=1000, prepare_confirmed=True)
        source = H.fixture_guard(self.item)
        readonly(source)
        tree = ast.parse(source)
        attributes = {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
        self.assertTrue({"O_NOFOLLOW", "O_NONBLOCK", "O_RDONLY", "O_DIRECTORY",
            "st_uid", "st_nlink", "st_mode", "st_dev", "st_ino"} <= attributes)
        comparisons = [ast.unparse(node) for node in ast.walk(tree) if isinstance(node, ast.Compare)]
        self.assertTrue(any("st_nlink == 1" in expression for expression in comparisons))
        self.assertTrue(any("S_IMODE(mi.st_mode) == 384" in expression for expression in comparisons))
        self.assertTrue(any("S_IMODE(info.st_mode) == 448" in expression for expression in comparisons))
        self.assertTrue(any("S_IMODE(child.st_mode) == 448" in expression for expression in comparisons))
        marker_compares = [node for node in ast.walk(tree) if isinstance(node, ast.Compare)
                           and isinstance(node.left, ast.Name) and node.left.id == "ownership"]
        self.assertEqual(len(marker_compares), 1)
        self.assertEqual(ast.literal_eval(marker_compares[0].comparators[0]), ack(self.item))
        for operation in ("ready", "counter", "release", "remove"):
            with mock.patch.object(H, "target_python", return_value={"ok": True}) as transport:
                H.owned_query(self.item["ssh_target"], self.item, operation)
                generated = transport.call_args.args[1]
                ast.parse(generated)
                self.assertIn(source, generated)
                if operation == "remove":
                    guard_line = next(node.lineno for node in ast.walk(ast.parse(generated))
                        if isinstance(node, ast.Compare) and isinstance(node.left, ast.Name)
                        and node.left.id == "ownership")
                    remove_line = next(node.lineno for node in ast.walk(ast.parse(generated))
                        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                        and node.func.attr == "rmtree")
                    self.assertLess(guard_line, remove_line)

    def test_target_transport_uses_fixed_ssh_argv_and_type_only_errors(self):
        response = subprocess.CompletedProcess([], 0, stdout='{"observed":true}', stderr="")
        with mock.patch.object(H.subprocess, "run", return_value=response) as run:
            self.assertEqual(H.target_python(self.item["ssh_target"], 'print("fixture")'),
                             {"observed": True})
            argv = run.call_args.args[0]
            self.assertEqual(argv[0], "/usr/bin/ssh")
            self.assertIn("StrictHostKeyChecking=yes", argv)
            self.assertIn("ForwardAgent=no", argv)
            self.assertIn("BatchMode=yes", argv)
            self.assertEqual(argv[-2], self.item["ssh_target"])
            self.assertEqual(run.call_args.kwargs["timeout"], 35)
        with mock.patch.object(H.subprocess, "run", side_effect=subprocess.TimeoutExpired(
                "ssh", 35, output=b"private stdout", stderr=b"private stderr")):
            with self.assertRaises(H.TargetOperationError) as caught:
                H.target_python(self.item["ssh_target"], "readonly")
            self.assertEqual(caught.exception.transport_error_type, "TimeoutExpired")
            self.assertNotIn("private", str(caught.exception))

    def test_transport_diagnostic_redacts_credentials_headers_and_controller_location(self):
        raw = (b"password=secretpass\naccess_token=secretaccess\n"
               b"Authorization: Bearer secretbearer\nX-Hepta-Runtime-Token: secretheader\n"
               b"Mcp-Session-Id: sessionsecret\nknown-token /private/controller/path\n")
        error = H.TargetOperationError("NonzeroSSHExit", 255, raw, b"private ack stdout")
        result = error.diagnostic("known-token", "/private/controller/path")
        rendered = json.dumps(result)
        for secret in ("secretpass", "secretaccess", "secretbearer", "secretheader",
                       "sessionsecret", "known-token", "/private/controller/path", "private ack stdout"):
            self.assertNotIn(secret, rendered)
        self.assertEqual(result["stdout_sha256"], hashlib.sha256(b"private ack stdout").hexdigest())
        self.assertIn("REDACTED", rendered)

    def test_all_embedded_static_programs_compile_without_file_creation(self):
        ast.parse(new.read_text())
        ast.parse(H.CHILD_SOURCE)
        ast.parse(H.BRIDGE_SOURCE)
        self.item["uid"] = 1000
        ast.parse(H.fixture_guard(self.item))
        ast.parse(H.fixture_guard(self.item, require_layout=False))
        with mock.patch.object(H, "target_python", return_value={
                "present": False, "owned": False, "readonly": True}) as transport:
            H.reconcile_fixture(self.item["ssh_target"], self.item)
            readonly(transport.call_args.args[1])

    def test_embedded_child_and_bridge_literal_bytes_are_identical_to_frozen_v6(self):
        def constants(path):
            tree = ast.parse(path.read_text())
            result = {}
            for node in tree.body:
                if (isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name)
                        and node.targets[0].id in ("CHILD_SOURCE", "BRIDGE_SOURCE")):
                    result[node.targets[0].id] = ast.literal_eval(node.value).encode()
            return result
        old_constants, new_constants = constants(old), constants(new)
        self.assertEqual(set(old_constants), {"CHILD_SOURCE", "BRIDGE_SOURCE"})
        self.assertEqual(new_constants, old_constants)

    def test_signal_phase_algorithm_and_final_exact_count_log_are_unchanged(self):
        def phase(path):
            tree = ast.parse(path.read_text())
            loops = [node for node in ast.walk(tree)
                     if isinstance(node, ast.For) and isinstance(node.target, ast.Tuple)
                     and [element.id for element in node.target.elts
                          if isinstance(element, ast.Name)] == ["phase", "mode", "count"]]
            self.assertEqual(len(loops), 1)
            stdout = [node.value for node in ast.walk(tree)
                      if isinstance(node, ast.Constant) and isinstance(node.value, bytes)
                      and node.value.startswith(b"READY\nTERM_COUNT=")]
            self.assertEqual(len(stdout), 1)
            return loops[0], stdout[0]
        old_phase, old_stdout = phase(old)
        new_phase, new_stdout = phase(new)
        expected = [
            ("normal", "normal", 1),
            ("completion_audit_failure", "completion_audit_failure", 2),
            ("intent_audit_failure", "intent_audit_failure", 2),
            ("lost_ack", "lost_ack", 3), ("invalid_ack", "invalid_ack", 4),
        ]
        self.assertEqual(ast.literal_eval(new_phase.iter), expected)
        self.assertEqual(ast.literal_eval(old_phase.iter), expected)
        self.assertEqual(ast.dump(new_phase, include_attributes=False),
                         ast.dump(old_phase, include_attributes=False))
        self.assertEqual(new_stdout,
            b"READY\nTERM_COUNT=1\nTERM_COUNT=2\nTERM_COUNT=3\nTERM_COUNT=4\nRELEASED\n")
        self.assertEqual(new_stdout, old_stdout)

    def test_diagnostic_redacts_header_keyword_lines_without_colons(self):
        raw = (b"Authorization=privateAUTH\nx-hepta-runtime-token privateTOKEN\n"
               b"MCP-SESSION-ID privateSESSION\n")
        result = H.TargetOperationError("NonzeroSSHExit", 255, raw, b"").diagnostic()
        rendered = json.dumps(result)
        for secret in ("privateAUTH", "privateTOKEN", "privateSESSION"):
            self.assertNotIn(secret, rendered)
        self.assertIn("REDACTED", rendered)

    def test_old_v6_exact_bytes_are_frozen(self):
        self.assertEqual(hashlib.sha256(old.read_bytes()).hexdigest(), old_expected)
        self.assertEqual(old.stat().st_size, 30498)


def main():
    before = input_bindings()
    if (before[old.relative_to(root).as_posix()] != {"bytes": 30498, "sha256": old_expected}
            or before[new.relative_to(root).as_posix()] != {"bytes": new.stat().st_size, "sha256": new_expected}):
        raise ValueError("explicit V9 source or historical algorithm pin differs")
    result = unittest.TextTestRunner(verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(Offline))
    after = input_bindings()
    print("AUDIT_BINDINGS", json.dumps({
        "before": before, "after": after, "stable": before == after,
        "no_effects": True, "ssh_mocked": True, "recovery_writes_mocked": True,
        "real_signal_qualified_by_suite": False,
        "full_dc_replacement_qualified": False,"candidate_version":9,
        "original_v8_loader_provenance":ORIGINAL_V8_LOADER_PROVENANCE,
        "prior_V8_tests_or_native_results_borrowed":False,"explicit_preimport_pins":PREIMPORT_PINS,
    }, sort_keys=True))
    raise SystemExit(0 if result.wasSuccessful() and before == after else 1)


if __name__ == "__main__":
    main()
