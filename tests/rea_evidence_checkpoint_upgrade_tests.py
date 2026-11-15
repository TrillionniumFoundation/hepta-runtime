#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Offline regressions for the finite checkpoint upgrade observer.

These tests consume committed original bytes and actual native HTTP observations.
They do not launch a runtime, use credentials, or qualify an upgrade themselves.
"""
from __future__ import annotations

import copy
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "rea_evidence_checkpoint_upgrade.py"
FIXTURES = ROOT / "tests" / "fixtures" / "rea_evidence_checkpoint"
PUBLIC = FIXTURES / "upgrade-public-order"
spec = importlib.util.spec_from_file_location("rea_upgrade_observer_tests_module", SCRIPT)
upgrade = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = upgrade
spec.loader.exec_module(upgrade)

PINS = {
    "call-026-unknown-verified-complete.json": (55178, "e6420a795dd15d1a44437dd4d540b008195bd603089839f779ecf100d011ca18"),
    "wire.jsonl": (47737, "dc95e62a9008731bae830389ef0470e95edfbffbe10ff973c0efc76af8b4657d"),
    "wire-0055-sent.json.gz": (110, "cd4c4c5eb273be358d625bcc3d8a4a867aff46816d0c2764e024c88305e30f84"),
    "wire-0056-received.json.gz": (1915, "63a215e60664c2f818fcba90d72ee9a8e49b19e36c561076cc1e83de71cb1570"),
    "call-003-cold-complete.json": (54507, "2731674c30c89cc91124430db061599626410a23562faa0820ba36694a89fc71"),
    "native-c25-cold-empty.http": (463, "2dc55a72fe08fac6240439cab6c7119be1252025b8d09ff7a8648f82a104593f"),
    "native-b2-apk-summary.result.json": (13705, "33ab788f423ae21e971a52d755b78f6dfcea05718fe261d5a5ab0c61d475a72f"),
}


def raw_fixture(name):
    raw = (PUBLIC / name).read_bytes()
    size, digest = PINS[name]
    if len(raw) != size or hashlib.sha256(raw).hexdigest() != digest:
        raise AssertionError("committed observation bytes changed: " + name)
    return raw


def http_result(raw):
    bodies = []
    for block in raw.decode().replace("\r\n", "\n").split("\n\n"):
        text = "\n".join(line[5:].lstrip(" ") for line in block.splitlines() if line.startswith("data:"))
        if text.strip():
            bodies.append(upgrade.parse(text))
    if len(bodies) != 1:
        raise AssertionError("expected one actual SSE JSONRPC response")
    return bodies[0]["result"]


class ObserverCases(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="rea-upgrade-unit-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.fixture = upgrade.parse((FIXTURES / "unknown-verified.json").read_bytes())

    def output(self, name="output"):
        output = self.root / name
        output.mkdir()
        (output / "inputs").mkdir()
        return output

    def observed_orders(self):
        return upgrade.consume_original_public_record_order(
            PUBLIC / "call-026-unknown-verified-complete.json", self.fixture, self.output()
        )[0]

    def fixture_copy(self):
        directory = self.root / "copied-observations"
        directory.mkdir()
        for name in PINS:
            (directory / name).write_bytes(raw_fixture(name))
        return directory

    def test_actual_observation_bytes_and_source_provenance(self):
        provenance = upgrade.parse((PUBLIC / "provenance.json").read_bytes())
        self.assertEqual(provenance["payload_executed_by_these_tests"], False)
        self.assertEqual(provenance["original_reference"]["npm"], "rea-agents@6.8.0")
        self.assertEqual(provenance["original_reference"]["tarball_sha256"],
                         "8d542ec76a9cb350584b60a6c9c088706ff812d5bb5b094c20c95b6dc25698bb")
        for name, (size, digest) in PINS.items():
            with self.subTest(name=name):
                raw = raw_fixture(name)
                row = provenance["files"][name]
                self.assertEqual((len(raw), hashlib.sha256(raw).hexdigest()), (size, digest))
                self.assertEqual((row["bytes"], row["sha256"]), (size, digest))

    def test_real_original_main_call_and_two_gzip_frames_are_consumed(self):
        output = self.output()
        rows, proof = upgrade.consume_original_public_record_order(
            PUBLIC / "call-026-unknown-verified-complete.json", self.fixture, output
        )
        self.assertEqual([len(row["keys"]) for row in rows], [16, 17, 16])
        self.assertEqual(proof["original_jsonrpc_id"], 28)
        self.assertTrue(proof["consumed_in_this_run"])
        self.assertFalse(proof["actual_response_reordered"])
        self.assertFalse(proof["fixture_values_replaced_with_historical_paths"])
        self.assertEqual((output / "inputs/public-record-order.original-call.json").read_bytes(),
                         raw_fixture("call-026-unknown-verified-complete.json"))
        for direction, name in (("sent", "wire-0055-sent.json.gz"), ("received", "wire-0056-received.json.gz")):
            self.assertEqual((output / ("inputs/public-record-order.original-" + direction + ".jsonrpc")).read_bytes(),
                             gzip.decompress(raw_fixture(name)))

    def test_real_original_cold_call_supplies_complete_unknown_order(self):
        keys, proof = upgrade.consume_original_public_order(PUBLIC / "call-003-cold-complete.json", self.output())
        self.assertEqual(keys, upgrade.UNKNOWN_KEYS)
        self.assertEqual(proof["unknown_revisions"], [1, 2, 3])
        self.assertEqual(proof["derived_bundle_keys"], upgrade.BUNDLE_KEYS)
        self.assertTrue(proof["consumed_in_this_run"])

    def test_expected_envelope_uses_observed_17_fields_preserving_authored_children(self):
        rows = self.observed_orders()
        expected = upgrade.expected_bundle(self.fixture, record_orders=rows)
        authored = self.fixture["records"][1]
        projected = expected["records"][1]
        self.assertEqual(projected, authored)
        self.assertEqual(list(projected)[7], "caller_input_path")
        self.assertEqual(list(authored)[-1], "caller_input_path")
        self.assertEqual(upgrade.orders(projected["parameters"]), upgrade.orders(authored["parameters"]))
        self.assertEqual(projected["caller_input_path"], authored["caller_input_path"])
        original = upgrade.parse(raw_fixture("call-026-unknown-verified-complete.json"))["response"]["result"]
        historical = upgrade.parse(original["content"][0]["text"])["result"]["records"][1]
        self.assertNotEqual(projected["caller_input_path"], historical["caller_input_path"])
        self.assertEqual([row["revision"] for row in expected["unknowns"]], [1, 2, 3])

    def test_fixture_physical_root_order_is_not_a_public_delivery_oracle(self):
        rows = self.observed_orders()
        expected = upgrade.expected_bundle(self.fixture, record_orders=rows)
        body = {"result": expected}
        reply = {"content": [{"type": "text", "text": json.dumps(body, separators=(",", ":"), ensure_ascii=False)}],
                 "structuredContent": upgrade.expected_http_structured(body),
                 "_meta": {"provenance": {"untrusted_content": True, "source": "analysis_target"}}}
        upgrade.expected_delivery(reply, expected, "observed envelope")
        incorrect = copy.deepcopy(expected)
        incorrect["records"] = copy.deepcopy(self.fixture["records"])
        self.assertEqual(incorrect, expected)
        with self.assertRaisesRegex(RuntimeError, "exact public text differs"):
            upgrade.expected_delivery(reply, incorrect, "unobserved fixture envelope")

    def test_expected_records_require_real_observed_order_input(self):
        with self.assertRaisesRegex(RuntimeError, "requires the consumed original"):
            upgrade.expected_bundle(self.fixture)

    def test_expected_record_identity_operation_and_full_keyset_are_strict(self):
        rows = self.observed_orders()
        for kind in ("id", "operation", "extra", "missing"):
            with self.subTest(kind=kind):
                changed = copy.deepcopy(self.fixture)
                if kind == "id":
                    changed["records"][1]["evidence_id"] = "ev_" + "0" * 64
                elif kind == "operation":
                    changed["records"][1]["operation"] = "different"
                elif kind == "extra":
                    changed["records"][1]["unexpected"] = None
                else:
                    del changed["records"][1]["caller_input_path"]
                with self.assertRaisesRegex(RuntimeError, "identity/operation/key set"):
                    upgrade.expected_bundle(changed, record_orders=rows)

    def test_expected_unknown_requires_complete_field_set(self):
        rows = self.observed_orders()
        for mutation in ("extra", "missing"):
            with self.subTest(mutation=mutation):
                changed = copy.deepcopy(self.fixture)
                if mutation == "extra":
                    changed["unknowns"][0]["unexpected"] = None
                else:
                    del changed["unknowns"][0]["question"]
                with self.assertRaisesRegex(RuntimeError, "Unknown fields differ"):
                    upgrade.expected_bundle(changed, record_orders=rows)

    def test_expected_unknown_requires_complete_revision_history(self):
        rows = self.observed_orders()
        changed = copy.deepcopy(self.fixture)
        changed["unknowns"][1]["revision"] = 7
        with self.assertRaisesRegex(RuntimeError, "complete original Unknown history"):
            upgrade.expected_bundle(changed, record_orders=rows)

    def test_unknown_order_cannot_be_replaced_with_alphabetic_order(self):
        with self.assertRaisesRegex(RuntimeError, "observed Unknown order differs"):
            upgrade.expected_bundle(self.fixture, sorted(upgrade.UNKNOWN_KEYS), self.observed_orders())

    def test_same_bytes_call_pin_is_not_mocked_for_semantically_equal_json(self):
        copied = self.fixture_copy()
        path = copied / "call-026-unknown-verified-complete.json"
        path.write_bytes(path.read_bytes() + b" ")
        with self.assertRaisesRegex(RuntimeError, "pinned SHA256 mismatch"):
            upgrade.consume_original_public_record_order(path, self.fixture, self.output())

    def test_same_bytes_manifest_pin_is_enforced(self):
        copied = self.fixture_copy()
        path = copied / "wire.jsonl"
        path.write_bytes(path.read_bytes() + b"\n")
        with self.assertRaisesRegex(RuntimeError, "pinned SHA256 mismatch"):
            upgrade.consume_original_public_record_order(copied / "call-026-unknown-verified-complete.json", self.fixture, self.output())

    def test_same_bytes_gzip_pin_rejects_changed_received_frame(self):
        copied = self.fixture_copy()
        path = copied / "wire-0056-received.json.gz"
        raw = bytearray(path.read_bytes())
        raw[-1] ^= 1
        path.write_bytes(raw)
        with self.assertRaisesRegex(RuntimeError, "pinned SHA256 mismatch"):
            upgrade.consume_original_public_record_order(copied / "call-026-unknown-verified-complete.json", self.fixture, self.output())

    def test_partial_original_frame_set_is_refused(self):
        copied = self.fixture_copy()
        (copied / "wire-0055-sent.json.gz").unlink()
        with self.assertRaises(FileNotFoundError):
            upgrade.consume_original_public_record_order(copied / "call-026-unknown-verified-complete.json", self.fixture, self.output())

    def test_unknown_original_observation_pin_is_enforced(self):
        path = self.root / "cold-call.json"
        path.write_bytes(raw_fixture("call-003-cold-complete.json") + b" ")
        with self.assertRaisesRegex(RuntimeError, "pinned SHA256 mismatch"):
            upgrade.consume_original_public_order(path, self.output())


class HttpChannelCases(unittest.TestCase):
    def setUp(self):
        self.empty = http_result(raw_fixture("native-c25-cold-empty.http"))
        self.evidence = upgrade.parse(raw_fixture("native-b2-apk-summary.result.json"))

    def test_actual_native_text_and_structured_have_distinct_valid_orders(self):
        body = upgrade.parse(self.empty["content"][0]["text"])
        self.assertNotEqual(upgrade.orders(body), upgrade.orders(self.empty["structuredContent"]))
        expected = {key: [] for key in upgrade.BUNDLE_KEYS}
        self.assertEqual(upgrade.expected_delivery(self.empty, expected, "actual c25"), expected)

    def test_copying_text_order_into_http_structured_is_rejected(self):
        changed = copy.deepcopy(self.empty)
        changed["structuredContent"] = upgrade.parse(changed["content"][0]["text"])
        with self.assertRaisesRegex(RuntimeError, "HTTP structured object order differs"):
            upgrade.tool_json(changed, True)

    def test_copying_structured_order_into_text_is_rejected(self):
        changed = copy.deepcopy(self.empty)
        changed["content"][0]["text"] = json.dumps(changed["structuredContent"], separators=(",", ":"))
        with self.assertRaisesRegex(RuntimeError, "exact public text differs"):
            upgrade.expected_delivery(changed, {key: [] for key in upgrade.BUNDLE_KEYS}, "wrong text order")

    def test_exact_text_is_not_weakened_to_parsed_value(self):
        changed = copy.deepcopy(self.empty)
        changed["content"][0]["text"] += " "
        self.assertEqual(upgrade.tool_json(changed, True), upgrade.tool_json(self.empty, True))
        with self.assertRaises(RuntimeError):
            upgrade.same_delivery(changed, self.empty, "whitespace is observable")
        with self.assertRaisesRegex(RuntimeError, "exact public text differs"):
            upgrade.expected_delivery(changed, {key: [] for key in upgrade.BUNDLE_KEYS}, "whitespace")

    def test_cross_stage_full_calltoolresult_still_exact(self):
        upgrade.same_delivery(self.empty, copy.deepcopy(self.empty), "unchanged")
        changed = copy.deepcopy(self.empty)
        changed["_meta"]["provenance"]["source"] = "other"
        with self.assertRaisesRegex(RuntimeError, "CallToolResult differs"):
            upgrade.same_delivery(changed, self.empty, "changed provenance")

    def test_actual_b2_direct_evidence_has_strict_sixteen_fields(self):
        result = upgrade.evidence_json(self.evidence, "inspect_analysis_view")
        self.assertEqual(list(result), upgrade.EVIDENCE_KEYS)
        self.assertEqual(result["evidence_id"], "ev_fd45e4e6ae9292edaec13256c90f3bf413c21b13e1a4c92932a122a1a9d6a5a6")
        self.assertNotEqual(upgrade.orders(result), upgrade.orders(self.evidence["structuredContent"]))

    def changed_evidence(self, change):
        reply = copy.deepcopy(self.evidence)
        body = upgrade.parse(reply["content"][0]["text"])
        change(body)
        reply["content"][0]["text"] = json.dumps(body, separators=(",", ":"), ensure_ascii=False)
        reply["structuredContent"] = upgrade.expected_http_structured(body)
        return reply

    def test_direct_evidence_rejects_result_wrapper(self):
        changed = copy.deepcopy(self.evidence)
        body = {"result": upgrade.parse(changed["content"][0]["text"])}
        changed["content"][0]["text"] = json.dumps(body)
        changed["structuredContent"] = upgrade.expected_http_structured(body)
        with self.assertRaisesRegex(RuntimeError, "direct Evidence member set/order"):
            upgrade.evidence_json(changed, "inspect_analysis_view")

    def test_direct_evidence_rejects_optional_import_field_or_missing_field(self):
        for mutation in ("extra", "missing"):
            with self.subTest(mutation=mutation):
                changed = self.changed_evidence(
                    lambda body: body.__setitem__("caller_input_path", "/not-an-import") if mutation == "extra" else body.pop("raw_result")
                )
                with self.assertRaisesRegex(RuntimeError, "direct Evidence member set/order"):
                    upgrade.evidence_json(changed, "inspect_analysis_view")

    def test_direct_evidence_rejects_wrong_operation_or_identity(self):
        for field, value in (("operation", "different"), ("evidence_id", "ev_short")):
            with self.subTest(field=field):
                changed = self.changed_evidence(lambda body: body.__setitem__(field, value))
                with self.assertRaises(RuntimeError):
                    upgrade.evidence_json(changed, "inspect_analysis_view")

    def test_direct_evidence_rejects_wrong_structured_order(self):
        changed = copy.deepcopy(self.evidence)
        changed["structuredContent"] = upgrade.parse(changed["content"][0]["text"])
        with self.assertRaisesRegex(RuntimeError, "Evidence structured object order differs"):
            upgrade.evidence_json(changed, "inspect_analysis_view")

    def test_direct_evidence_rejects_missing_target_provenance(self):
        changed = copy.deepcopy(self.evidence)
        del changed["_meta"]
        with self.assertRaisesRegex(RuntimeError, "Evidence target-content provenance differs"):
            upgrade.evidence_json(changed, "inspect_analysis_view")

    def test_bundle_decoder_refuses_direct_evidence(self):
        with self.assertRaisesRegex(RuntimeError, "compatibility result wrapper differs"):
            upgrade.tool_json(self.evidence, True)

    def test_plain_native_checkpoint_receipt_keeps_direct_object_contract(self):
        body = {"checkpoint_id": "ecp1_" + "0" * 64, "records": 5}
        reply = {"content": [{"type": "text", "text": json.dumps(body)}], "isError": False}
        self.assertEqual(upgrade.tool_json(reply), body)
        with self.assertRaisesRegex(RuntimeError, "compatibility result wrapper differs"):
            upgrade.tool_json(reply, True)


class EntrypointCases(unittest.TestCase):
    """Exercise the real entrypoint guard with isolated ordinary files, no runtime."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="rea-upgrade-entrypoint-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.repo = self.root / "repo"
        (self.repo / "scripts").mkdir(parents=True)
        (self.repo / "tests").mkdir()
        self.repository = self.repo / "scripts/rea_evidence_checkpoint_upgrade.py"
        self.repository.write_bytes(b"# offline repository entrypoint\n")
        self.external = self.root / "reviewed.py"
        self.external.write_bytes(b"# offline external entrypoint\n")
        self.summary = self.root / "summary.json"
        self.binding = self.root / "binding.json"
        self.write_build_binding(self.repo)
        self.args = SimpleNamespace(
            tests_dir=self.repo / "tests", external_reviewed_runner=None,
            external_reviewed_runner_sha256=None, external_reviewed_runner_bytes=None,
            replaced_repo_runner_sha256=None, replaced_repo_runner_bytes=None,
            new_binding=self.binding, new_binding_sha256=upgrade.sha(self.binding.read_bytes()),
        )

    def write_build_binding(self, actual_repo):
        self.summary.write_text(json.dumps({"inputs": {"repo": str(actual_repo)}}))
        self.binding.write_text(json.dumps({
            "schema": "hepta.rea.p0p5.build-binding.v1",
            "build_summary": upgrade.identity(self.summary),
        }))

    def external_args(self):
        args = copy.copy(self.args)
        args.external_reviewed_runner = str(self.external)
        args.external_reviewed_runner_sha256 = upgrade.sha(self.external.read_bytes())
        args.external_reviewed_runner_bytes = self.external.stat().st_size
        args.replaced_repo_runner_sha256 = upgrade.sha(self.repository.read_bytes())
        args.replaced_repo_runner_bytes = self.repository.stat().st_size
        return args

    def select(self, args=None, executing=None, invoked=None):
        args = args or self.external_args()
        return upgrade.select_runner_source(args, self.repo, executing or str(self.external), invoked or str(self.external))

    def test_default_repository_mode_preserves_original_guard(self):
        result = upgrade.select_runner_source(self.args, self.repo, str(self.repository), str(self.repository))
        self.assertEqual(result["binding"]["mode"], "repository")
        self.assertIsNone(result["repository_raw"])
        with self.assertRaisesRegex(RuntimeError, "must belong to the selected current"):
            self.select(self.args)

    def test_default_mode_rejects_unrequested_external_pins(self):
        args = copy.copy(self.args)
        args.external_reviewed_runner_sha256 = "0" * 64
        with self.assertRaisesRegex(RuntimeError, "pins require the explicit"):
            self.select(args, str(self.repository), str(self.repository))

    def test_explicit_external_mode_binds_actual_and_replaced_bytes(self):
        result = self.select()
        binding = result["binding"]
        self.assertEqual(binding["actual___file__"], str(self.external))
        self.assertEqual(binding["actual_argv_entrypoint"], str(self.external))
        self.assertEqual(result["raw"], self.external.read_bytes())
        self.assertEqual(result["repository_raw"], self.repository.read_bytes())
        self.assertFalse(binding["external_runner_is_compiled_source"])
        self.assertEqual(binding["repository_source_relative_path"], "scripts/rea_evidence_checkpoint_upgrade.py")

    def test_external_mode_requires_every_pin(self):
        for name in ("external_reviewed_runner_sha256", "external_reviewed_runner_bytes",
                     "replaced_repo_runner_sha256", "replaced_repo_runner_bytes"):
            with self.subTest(name=name):
                args = self.external_args()
                setattr(args, name, None)
                with self.assertRaisesRegex(RuntimeError, "requires both SHA256 and byte-count"):
                    self.select(args)

    def test_external_mode_refuses_wrong_hash_or_length(self):
        for name, value in (("external_reviewed_runner_sha256", "0" * 64),
                            ("replaced_repo_runner_sha256", "0" * 64),
                            ("external_reviewed_runner_bytes", 1),
                            ("replaced_repo_runner_bytes", 1)):
            with self.subTest(name=name):
                args = self.external_args()
                setattr(args, name, value)
                with self.assertRaises(RuntimeError):
                    self.select(args)

    def test_external_mode_refuses_wrong_new_binding_pin(self):
        args = self.external_args()
        args.new_binding_sha256 = "0" * 64
        with self.assertRaisesRegex(RuntimeError, "pinned SHA256 mismatch"):
            self.select(args)

    def test_external_mode_refuses_bound_repo_mismatch(self):
        other = self.root / "different-build-repo"
        other.mkdir()
        self.write_build_binding(other)
        args = self.external_args()
        args.new_binding_sha256 = upgrade.sha(self.binding.read_bytes())
        with self.assertRaisesRegex(RuntimeError, "differs from the actual bound build"):
            self.select(args)

    def test_external_mode_refuses_actual_argv_mismatch(self):
        another = self.root / "another.py"
        another.write_bytes(self.external.read_bytes())
        with self.assertRaisesRegex(RuntimeError, "actual __file__/argv entrypoint differs"):
            self.select(invoked=str(another))

    def test_external_mode_refuses_lexical_dot_and_parent_aliases(self):
        args = self.external_args()
        args.external_reviewed_runner = str(self.root) + "/./reviewed.py"
        with self.assertRaisesRegex(RuntimeError, "canonical spelling"):
            self.select(args)
        with self.assertRaisesRegex(RuntimeError, "lexical alias"):
            self.select(invoked=str(self.root) + "/./reviewed.py")
        alias = str(self.repo / "../reviewed.py")
        args = self.external_args()
        args.external_reviewed_runner = alias
        with self.assertRaisesRegex(RuntimeError, "without aliases"):
            self.select(args, alias, alias)

    def test_external_mode_refuses_symlink(self):
        alias = self.root / "linked.py"
        alias.symlink_to(self.external)
        args = self.external_args()
        args.external_reviewed_runner = str(alias)
        with self.assertRaisesRegex(RuntimeError, "without aliases"):
            self.select(args, str(alias), str(alias))

    def test_external_mode_refuses_hardlinked_input(self):
        alias = self.root / "hardlinked.py"
        os.link(self.external, alias)
        with self.assertRaisesRegex(RuntimeError, "single-link regular file"):
            self.select()

    def test_external_mode_cannot_relabel_an_in_repository_runner(self):
        args = self.external_args()
        args.external_reviewed_runner = str(self.repository)
        args.external_reviewed_runner_sha256 = upgrade.sha(self.repository.read_bytes())
        args.external_reviewed_runner_bytes = self.repository.stat().st_size
        with self.assertRaisesRegex(RuntimeError, "must be outside"):
            self.select(args, str(self.repository), str(self.repository))

    def test_selected_build_summary_bytes_are_mandatory(self):
        self.summary.write_bytes(self.summary.read_bytes() + b" ")
        with self.assertRaisesRegex(RuntimeError, "pinned SHA256 mismatch"):
            self.select()


if __name__ == "__main__":
    unittest.main()
