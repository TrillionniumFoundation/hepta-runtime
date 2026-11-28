#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Negative controls for the external installed-public qualification reader.

Synthetic files below test refusal logic only. They never run the integration
driver, produce an installation qualification, or replace the real native gate.
"""
from __future__ import annotations

import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location(
    "hia_installed_public_jobs", Path(__file__).with_name("hia_installed_public_jobs_integration.py"))
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


class InstallationReaderControls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.installation = self.root / "installation"
        self.controller = self.installation / "controller" / ("a" * 64)
        self.controller.mkdir(parents=True, mode=0o700)
        self.catalog = b'{"fixture":"reader-controls-only"}\n'
        image = bytearray(64)
        image[:7] = b"\x7fELF\x02\x01\x01"
        image[16:20] = b"\x02\x00\x3e\x00"
        self.image = bytes(image)
        self.manifest = {"schema": "hepta.hia.mcp.controller.v26", "files": {}}
        for role in gate.ROLES:
            raw = self.catalog if role == gate.ROLES[0] else self.image
            self.write(self.controller / role, raw)
            self.manifest["files"][role] = gate.sha(raw)
        self.write_manifest()
        self.write(self.installation / "hia-agent-worker", self.image)
        self.write(self.installation / "worker.json", b'{"synthetic":true}\n')
        self.base = {"state_dir": str(self.root / "state"), "sentinel": {"preserve": 7},
            "hosts": {gate.HOST: {"platform": "linux", "execution_mode": "operator",
                "allow_execute": True, "allow_write": True, "allow_detached_fallback": False}},
            "hia_worker": {"host": gate.HOST, "timeout_seconds": 120}}
        self.config = copy.deepcopy(self.base)
        self.config["hosts"][gate.HOST]["native_jobs"] = {
            key: {"executable": str(self.controller / role), "sha256": self.manifest["files"][role]}
            for key, role in gate.JOB_ROLES.items()}
        self.config["hia_worker"].update({"worker_sha256": "1" * 64, "backend_sha256": "2" * 64,
            "catalog_sha256": gate.sha(self.catalog),
            "native_helpers_sha256": gate.sha((self.installation / "worker.json").read_bytes()),
            "python_executable": str(self.installation / "hia-agent-worker"),
            "native_helpers_manifest": str(self.installation / "worker.json")})
        self.write_config()

    def tearDown(self):
        self.temporary.cleanup()

    def write(self, path, raw, mode=0o600):
        path.write_bytes(raw)
        path.chmod(mode)

    def write_manifest(self):
        self.write(self.controller / "hia-controller.json", json.dumps(self.manifest).encode())

    def write_config(self):
        self.write(self.installation / "runtime-config.json", json.dumps(self.config).encode())

    def read(self):
        return gate.installed_binding(self.installation, self.base, self.catalog)

    def test_reader_accepts_exact_physical_binding_without_claiming_execution(self):
        _, _, _, binding = self.read()
        self.assertEqual(set(binding["roles"]), set(gate.ROLES))
        self.assertNotIn("qualified", binding)
        self.assertNotIn("installed", binding)

    def test_missing_extra_and_legacy_controller_inventories_are_refused(self):
        for mode in ("missing", "extra", "legacy"):
            with self.subTest(mode=mode):
                value = copy.deepcopy(self.manifest)
                if mode == "missing":
                    value["files"].pop("hia-job-launch")
                elif mode == "extra":
                    value["files"]["unadmitted-role"] = "1" * 64
                else:
                    value["schema"] = "hepta.hia.mcp.controller.v25"
                with self.assertRaisesRegex(RuntimeError, "nineteen-role"):
                    gate.controller_manifest(json.dumps(value))

    def test_missing_host_selection_cannot_be_a_native_public_gate(self):
        self.config["hosts"][gate.HOST].pop("native_jobs")
        self.write_config()
        with self.assertRaisesRegex(RuntimeError, "complete host native_jobs"):
            self.read()

    def test_unused_role_pin_is_still_checked(self):
        self.config["hosts"][gate.HOST]["native_jobs"]["cancel"]["sha256"] = "0" * 64
        self.write_config()
        with self.assertRaisesRegex(RuntimeError, "host role pin"):
            self.read()

    def test_native_role_bytes_must_match_the_actual_manifest(self):
        self.write(self.controller / "hia-job-submit", self.image + b"changed")
        with self.assertRaisesRegex(RuntimeError, "role differs"):
            self.read()

    def test_physical_role_cannot_be_replaced_by_a_link(self):
        path = self.controller / "hia-job-entry"
        path.rename(path.with_name("retained-entry"))
        path.symlink_to("retained-entry")
        with self.assertRaisesRegex(RuntimeError, "not from this real installation"):
            self.read()

    def test_host_policy_and_unrelated_configuration_are_preserved(self):
        self.config["sentinel"]["preserve"] = 9
        self.write_config()
        with self.assertRaisesRegex(RuntimeError, "unrelated"):
            self.read()
        self.config["sentinel"]["preserve"] = 7
        self.config["hosts"][gate.HOST]["allow_detached_fallback"] = True
        self.write_config()
        with self.assertRaisesRegex(RuntimeError, "strict Linux operator"):
            self.read()

    def test_native_worker_profile_cannot_be_substituted(self):
        self.write(self.installation / "worker.json", b'{"synthetic":"changed"}\n')
        with self.assertRaisesRegex(RuntimeError, "Worker profile pin"):
            self.read()

    def test_ordinary_reader_refuses_writable_multilink_and_symlink_files(self):
        path = self.root / "ordinary"
        self.write(path, b"captured")
        self.assertEqual(gate.ordinary(path, 8), b"captured")
        path.chmod(0o622)
        with self.assertRaisesRegex(RuntimeError, "unsafe ordinary"):
            gate.ordinary(path, 8)
        path.chmod(0o600)
        os.link(path, self.root / "hardlink")
        with self.assertRaisesRegex(RuntimeError, "unsafe ordinary"):
            gate.ordinary(path, 8)
        (self.root / "hardlink").unlink()
        linked = self.root / "symlink"
        linked.symlink_to(path.name)
        with self.assertRaises(OSError):
            gate.ordinary(linked, 8)


class ReceiptAndWitnessControls(unittest.TestCase):
    def test_installer_receipt_requires_real_typed_success_and_selected_package(self):
        receipt = {"schema": "hepta.hia.native-worker-install.v1", "installed": True,
                   "source_attested": True, "package_sha256": "a" * 64}
        self.assertEqual(gate.install_receipt(json.dumps(receipt), "a" * 64), receipt)
        for field, value in (("installed", 1), ("source_attested", False),
                             ("package_sha256", "b" * 64), ("schema", "synthetic-fixture")):
            with self.subTest(field=field):
                changed = {**receipt, field: value}
                with self.assertRaisesRegex(RuntimeError, "bound success receipt"):
                    gate.install_receipt(json.dumps(changed), "a" * 64)

    def test_ambiguous_json_and_nonfinite_values_are_refused(self):
        for raw in ('{"files":{},"files":{}}', '{"installed":NaN}'):
            with self.assertRaises(RuntimeError):
                gate.strict_json(raw)

    def test_witness_binds_actual_bytes_original_job_nonce_and_typed_protocol(self):
        request = {"job_id": "original", "launch_nonce": "a" * 32, "terminal_publication_protocol": 1}
        terminal = {**request, "output_complete": True, "output_durable": True, "exit_code": 17}
        raw = json.dumps(terminal).encode()
        witness = {**request, "exit_sha256": gate.sha(raw)}
        self.assertEqual(gate.validate_witness(request, raw, witness, "original"), terminal)
        for field, value in (("job_id", "another"), ("launch_nonce", "b" * 32),
                             ("terminal_publication_protocol", True), ("exit_sha256", "0" * 64)):
            with self.subTest(field=field):
                with self.assertRaises(RuntimeError):
                    gate.validate_witness(request, raw, {**witness, field: value}, "original")
        changed = json.dumps({**terminal, "exit_code": 0}).encode()
        with self.assertRaisesRegex(RuntimeError, "actual terminal bytes"):
            gate.validate_witness(request, changed, witness, "original")
        incomplete = json.dumps({**terminal, "output_durable": False}).encode()
        with self.assertRaisesRegex(RuntimeError, "durably"):
            gate.validate_witness(request, incomplete, {**witness, "exit_sha256": gate.sha(incomplete)}, "original")

    def test_rebound_witness_refuses_boolean_float_null_and_missing_exit_codes(self):
        request = {"job_id": "original", "launch_nonce": "a" * 32, "terminal_publication_protocol": 1}
        for code in (False, True, 0.0, None, "0", "missing"):
            with self.subTest(code=code):
                terminal = {**request, "output_complete": True, "output_durable": True}
                if code != "missing":
                    terminal["exit_code"] = code
                raw = json.dumps(terminal).encode()
                witness = {**request, "exit_sha256": gate.sha(raw)}
                with self.assertRaisesRegex(RuntimeError, "exact integer"):
                    gate.validate_witness(request, raw, witness, "original")
        # The native supervisor publishes a signed integer for cancellation,
        # so no null/boolean exception is admitted by this native-only reader.
        terminal["exit_code"] = -15
        raw = json.dumps(terminal).encode()
        self.assertEqual(gate.validate_witness(request, raw,
            {**request, "exit_sha256": gate.sha(raw)}, "original")["exit_code"], -15)

    def test_public_observation_requires_a_typed_confirmed_terminal_code(self):
        observed = {"job_id": "original", "exit_code": 0,
                    "terminal_publication_confirmed": True, "automatic_retry": False}
        self.assertEqual(gate.validate_observation(observed, "original"), observed)
        for field, value in (("exit_code", False), ("exit_code", 0.0), ("exit_code", None),
                             ("terminal_publication_confirmed", 1), ("automatic_retry", 0),
                             ("job_id", "another")):
            with self.subTest(field=field, value=value):
                with self.assertRaisesRegex(RuntimeError, "typed outcome"):
                    gate.validate_observation({**observed, field: value}, "original")

    def test_public_stream_cursors_eofs_and_counts_refuse_boolean_aliases(self):
        stream = {"offset": 0, "next_offset": 0, "bytes_hex": "", "eof": True}
        self.assertEqual(gate.decode_stream(stream, 0), (b"", 0))
        for field, value in (("offset", False), ("offset", 0.0), ("next_offset", False),
                             ("next_offset", 0.0), ("eof", 1)):
            with self.subTest(field=field, value=value):
                with self.assertRaises(RuntimeError):
                    gate.decode_stream({**stream, field: value}, 0)
        terminal = {"log_bytes": {"stdout": {"seen": 0, "stored": 0}},
                    "log_eof": {"stdout": True}}
        gate.validate_output_counts(terminal, {"stdout": b""})
        for field in ("seen", "stored"):
            for value in (False, 0.0, None):
                with self.subTest(field=field, value=value):
                    changed = copy.deepcopy(terminal)
                    changed["log_bytes"]["stdout"][field] = value
                    with self.assertRaisesRegex(RuntimeError, "byte counts"):
                        gate.validate_output_counts(changed, {"stdout": b""})

    def test_install_trace_refuses_hosted_execs_and_missing_native_children(self):
        with tempfile.TemporaryDirectory() as temporary:
            trace = Path(temporary) / "trace"
            direct = '10 execve("/native/hia-worker-install", ["/native/hia-worker-install"], 0x0) = 0\n'
            native = '11 execveat(4, "", ["hia-worker-install-owner"], 0x0, AT_EMPTY_PATH) = 0\n'
            trace.write_text(direct + native)
            self.assertEqual(gate.trace_native_install(trace, Path("/native/hia-worker-install"))["descriptor_execs"], 1)
            for bad in (direct, direct + native + '12 execve("/usr/bin/python3", [], 0x0) = 0\n',
                        direct + '11 execveat(4, "owner", [], 0x0, 0) = 0\n',
                        direct + '11 execveat(4, "owner", [""], 0x0, AT_EMPTY_PATH) = 0\n',
                        direct + native.replace("= 0", "= -1 EACCES (Permission denied)")):
                trace.write_text(bad)
                with self.assertRaises(RuntimeError):
                    gate.trace_native_install(trace, Path("/native/hia-worker-install"))

    def test_install_trace_pairs_each_process_continuation_and_counts_actual_success(self):
        with tempfile.TemporaryDirectory() as temporary:
            trace = Path(temporary) / "trace"
            direct = '10 execve("/native/hia-worker-install", [], 0x0) = 0\n'
            unfinished = '11 execveat(4, "", ["owner"], 0x0, AT_EMPTY_PATH <unfinished ...>\n'
            failed = '12 execveat(5, "", ["owner"], 0x0, AT_EMPTY_PATH) = -1 EACCES (Permission denied)\n'
            resumed = '11 <... execveat resumed>) = 0\n'
            trace.write_text(direct + unfinished + failed + resumed)
            result = gate.trace_native_install(trace, Path("/native/hia-worker-install"))
            self.assertEqual((result["descriptor_attempts"], result["descriptor_execs"],
                              result["descriptor_failures"]), (2, 1, 1))
            for bad in (direct + unfinished, direct + resumed,
                        direct + unfinished + resumed.replace("11 ", "12 "),
                        direct + unfinished + resumed.replace("execveat", "execve"),
                        direct + unfinished + resumed.replace("= 0", "= -1 EACCES (Permission denied)"),
                        direct + unfinished + resumed.replace("= 0", "= ?"),
                        direct + unfinished + unfinished + resumed):
                with self.subTest(trace=bad):
                    trace.write_text(bad)
                    with self.assertRaises(RuntimeError):
                        gate.trace_native_install(trace, Path("/native/hia-worker-install"))

    def test_timed_out_owned_invocation_is_retained_and_not_replayed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            marker = root / "once"
            source = "import pathlib,time; pathlib.Path(%r).open('x').write('once'); time.sleep(30)" % str(marker)
            with self.assertRaisesRegex(RuntimeError, "failed; original output"):
                gate.run_owned([sys.executable, "-I", "-B", "-c", source], root, "timeout-control",
                               cwd=root, env={}, timeout=0.15)
            self.assertEqual(marker.read_text(), "once")
            command = json.loads((root / "timeout-control.command.json").read_bytes())
            self.assertTrue(command["timed_out"])
            self.assertLess(command["exit_code"], 0)
            self.assertEqual(sorted(path.name for path in root.iterdir()),
                             ["once", "timeout-control.command.json", "timeout-control.stderr", "timeout-control.stdout"])


if __name__ == "__main__":
    unittest.main()
