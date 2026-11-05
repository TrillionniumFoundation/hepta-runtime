#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# Licensed under the Apache License, Version 2.0.
"""Integrity/refusal tests for the development-only compatibility ledger."""

from contextlib import redirect_stdout
from copy import deepcopy
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import warnings
import zipfile


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts/rea_compatibility_ledger.py"
if not MODULE_PATH.exists():
    MODULE_PATH = Path(__file__).with_name("rea_compatibility_ledger.py")
SPEC = importlib.util.spec_from_file_location("rea_compatibility_ledger", MODULE_PATH)
ledger = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ledger)


class LedgerIntegrityTests(unittest.TestCase):
    def test_duplicate_json_members_are_not_silently_overwritten(self):
        with self.assertRaisesRegex(ledger.LedgerError, "duplicate JSON"):
            ledger.parse_json(b'{"name":"first","name":"second"}')

    def test_nonfinite_constants_are_refused(self):
        for value in (b"NaN", b"Infinity", b"-Infinity", b"1e400", b"-1e400"):
            with self.subTest(value=value), self.assertRaises(ledger.LedgerError):
                ledger.parse_json(value)

    def test_catalog_compaction_preserves_string_and_number_tokens(self):
        raw = b' [ { "s" : "a b\\\" c\\\\ d", "n" : 1e+20, "z": -0 } ] \n'
        expected = b'[{"s":"a b\\\" c\\\\ d","n":1e+20,"z":-0}]'
        self.assertEqual(ledger.compact_json_bytes(raw), expected)

    def test_malformed_catalog_is_not_hashed_as_valid(self):
        with self.assertRaises(ledger.LedgerError):
            ledger.compact_json_bytes(b'{"input": "unterminated}')

    def test_relative_paths_and_symlink_escapes_are_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "root"
            root.mkdir()
            for path in ("../escape", "/etc/passwd", "a/../../escape", "C:\\data", ""):
                with self.subTest(path=path), self.assertRaises(ledger.LedgerError):
                    ledger.relative_path(root, path)
            (root / "link").symlink_to(Path(temporary))
            with self.assertRaises(ledger.LedgerError):
                ledger.relative_path(root, "link/escape")

    def mapping(self):
        return {"schema": "hepta.rea.capability-map.v1", "runtime_baseline": "baseline",
                "interfaces": {"rea_example": {"source_paths": ["src/mcp/server.rs"]}},
                "auxiliary_capabilities": {},
                "family_defaults": {"artifact": {"implementation": "absent",
                                                   "native_routes": []}},
                "overrides": {}, "behavior_gates": {}}

    def test_mapping_cannot_declare_a_passed_qualification(self):
        mapping = self.mapping()
        mapping["qualification"] = "PASS"
        with self.assertRaisesRegex(ledger.LedgerError, "qualification cannot"):
            ledger.validate_map(mapping, ["inspect_example"], ["artifact"])

    def test_mapping_cannot_rename_partial_to_equivalent(self):
        mapping = self.mapping()
        mapping["overrides"]["inspect_example"] = {"implementation": "equivalent"}
        with self.assertRaisesRegex(ledger.LedgerError, "implementation state"):
            ledger.validate_map(mapping, ["inspect_example"], ["artifact"])

    def test_mapping_cannot_invent_an_upstream_tool_or_native_handler(self):
        mapping = self.mapping()
        mapping["overrides"]["invented_tool"] = {"implementation": "absent"}
        with self.assertRaisesRegex(ledger.LedgerError, "outside the published"):
            ledger.validate_map(mapping, ["inspect_example"], ["artifact"])
        mapping = self.mapping()
        mapping["overrides"]["inspect_example"] = {"native_routes": ["rea_invented"]}
        with self.assertRaisesRegex(ledger.LedgerError, "undeclared native"):
            ledger.validate_map(mapping, ["inspect_example"], ["artifact"])

    def test_runtime_inventory_detects_added_and_deleted_native_handlers(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            server = root / "src/mcp/server.rs"
            server.parent.mkdir(parents=True)
            server.write_text("\tasync fn rea_example(\n")
            result = ledger.runtime_inventory(root, self.mapping())
            self.assertEqual(result["interfaces"], ["rea_example"])
            server.write_text("\tasync fn rea_example(\n\tasync fn rea_new(\n")
            with self.assertRaisesRegex(ledger.LedgerError, "unmapped=.*rea_new"):
                ledger.runtime_inventory(root, self.mapping())
            server.write_text("// handler removed\n")
            with self.assertRaisesRegex(ledger.LedgerError, "absent=.*rea_example"):
                ledger.runtime_inventory(root, self.mapping())

    def fixture_inputs(self, root, cache):
        tool = {"name": "inspect_example", "inputSchema": {"type": "object"},
                "outputSchema": {"type": "object"}}
        full = [{"name": tool["name"], "inputSchema": tool["inputSchema"]}]
        compact_raw = (json.dumps([tool], indent=2) + "\n").encode()
        full_raw = (json.dumps(full, indent=2) + "\n").encode()
        raw_by_path = {"compact.json": compact_raw, "full.json": full_raw}
        pin = {"publishedPackage": "fixture@1", "upstreamGitSource": "fixture-commit",
               "toolCount": 1, "catalogSha256": ledger.sha256(ledger.compact_json_bytes(compact_raw)),
               "fullInputCatalogSha256": ledger.sha256(ledger.compact_json_bytes(full_raw)),
               "toolNamesSha256": ledger.sha256(b'["inspect_example"]')}
        (root / "pin.json").write_text(json.dumps(pin))
        (cache / "oracle").mkdir(parents=True)
        for path, raw in raw_by_path.items():
            (cache / "oracle" / path).write_bytes(raw)
        return {"schema": "hepta.rea.compatibility-inputs.v1", "published_pin_path": "pin.json",
                "published_package": "fixture@1", "source_commit": "fixture-commit",
                "reference_files": [{"path": p, "sha256": ledger.sha256(b), "bytes": len(b)}
                                    for p, b in raw_by_path.items()],
                "source_files": [], "catalogs": [
                    {"id": "compact_input_full_output", "path": "compact.json", "pin_field": "catalogSha256"},
                    {"id": "full_input_off_output", "path": "full.json", "pin_field": "fullInputCatalogSha256"}]}

    def test_authenticated_catalog_requires_both_independent_profiles(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cache = root / "cache"
            inputs = self.fixture_inputs(root, cache)
            _, catalogs = ledger.verify_inputs(root, cache, inputs)
            self.assertEqual(len(catalogs), 2)
            inputs["catalogs"] = inputs["catalogs"][:1]
            with self.assertRaisesRegex(ledger.LedgerError, "both independent"):
                ledger.verify_inputs(root, cache, inputs)

    def test_reference_byte_tamper_is_refused_before_classification(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cache = root / "cache"
            inputs = self.fixture_inputs(root, cache)
            path = cache / "oracle/compact.json"
            path.write_bytes(path.read_bytes().replace(b"inspect_example", b"inspect_mutated"))
            with self.assertRaisesRegex(ledger.LedgerError, "reference input identity"):
                ledger.verify_inputs(root, cache, inputs)

    def test_raw_pin_update_cannot_hide_wrong_catalog_semantic_digest(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cache = root / "cache"
            inputs = self.fixture_inputs(root, cache)
            path = cache / "oracle/full.json"
            path.write_bytes(path.read_bytes().replace(b"object", b"string"))
            for item in inputs["reference_files"]:
                if item["path"] == "full.json":
                    item.update(sha256=ledger.sha256(path.read_bytes()), bytes=path.stat().st_size)
            with self.assertRaisesRegex(ledger.LedgerError, "semantic digest drift"):
                ledger.verify_inputs(root, cache, inputs)

    def test_restore_rejects_duplicate_zip_members_without_network(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "1.zip"
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                with zipfile.ZipFile(archive, "w") as bundle:
                    bundle.writestr("same.json", "{}")
                    bundle.writestr("same.json", "[]")
            inputs = {"artifact": {"id": 1, "sha256": ledger.sha256(archive.read_bytes())},
                      "reference_files": [], "source_files": []}
            with self.assertRaisesRegex(ledger.LedgerError, "duplicate archive"):
                ledger.restore(root, inputs, "/nonexistent/gh")

    def test_unknown_mapping_gate_is_refused(self):
        mapping = self.mapping()
        mapping["overrides"]["inspect_example"] = {"extra_gates": ["self_declared_pass"]}
        with self.assertRaisesRegex(ledger.LedgerError, "unknown behavior gate"):
            ledger.validate_map(mapping, ["inspect_example"], ["artifact"])

    def test_auxiliary_cli_is_separate_from_published_tool_count_and_detects_drift(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "src/mcp").mkdir(parents=True)
            (root / "src/mcp/server.rs").write_text("\tasync fn rea_example(\n")
            (root / "src/cli.rs").write_text("\tReaExample,\n")
            (root / "src/main.rs").write_text("Commands::ReaExample => {}\n")
            mapping = self.mapping()
            mapping["auxiliary_capabilities"]["example_cli"] = {
                "kind": "rust_cli", "variant": "ReaExample", "source_paths": ["src/main.rs"],
                "entrypoint": "hepta-runtime rea-example", "scope": "test-only source discovery"}
            result = ledger.runtime_inventory(root, mapping)
            self.assertEqual(result["interface_count"], 1)
            self.assertEqual(result["auxiliary_capabilities"][0]["source_presence"], "PRESENT")
            (root / "src/cli.rs").write_text("\tReaExample,\n\tReaNew,\n")
            with self.assertRaisesRegex(ledger.LedgerError, "unmapped REA CLI"):
                ledger.runtime_inventory(root, mapping)

    def test_discovery_cannot_be_used_as_provider_qualification(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "probe.py").write_bytes(b"read-only probe")
            value = {"qualification": "DISCOVERY_ONLY"}
            environment = {"schema": "hepta.rea.compatibility-environment.v1",
                           "probe": {"path": "probe.py", "sha256": ledger.sha256(b"read-only probe")},
                           "observations": [{"host": "fixture", "exit_code": 0,
                                             "output_complete": True, "output_durable": True,
                                             "observation": value,
                                             "stdout_sha256": ledger.sha256((json.dumps(value, sort_keys=True) + "\n").encode())}],
                           "components": {"engine": {"qualification": "NOT_ESTABLISHED", "observed_hosts": ["fixture"]}}}
            ledger.validate_environment(root, environment)
            environment["components"]["engine"]["qualification"] = "PASS"
            with self.assertRaisesRegex(ledger.LedgerError, "cannot declare parity"):
                ledger.validate_environment(root, environment)

    def test_having_no_external_dependencies_does_not_close_code_or_differential_blockers(self):
        result = ledger.remaining_blockers({"missing": "parser semantics"}, [], ["results"])
        self.assertEqual([row["category"] for row in result], ["code_and_contracts", "behavioral_differential"])
        self.assertTrue(all(row["status"] == "OPEN" for row in result))

    def offline_fixture(self, root):
        """Synthetic local snapshot; no raw reference cache or Git checkout."""
        names = ["inspect_example", "inspect_second"]
        pin = {"publishedPackage": "fixture@1", "upstreamGitSource": "fixture-commit",
               "tarballSha256": "a" * 64, "catalogSha256": "b" * 64,
               "fullInputCatalogSha256": "c" * 64, "toolCount": len(names),
               "toolNamesSha256": ledger.sha256(json.dumps(names, separators=(",", ":")).encode())}
        (root / "pin.json").write_text(json.dumps(pin))
        (root / "src/mcp").mkdir(parents=True)
        (root / "src/mcp/server.rs").write_text("    pub(crate) async fn rea_example (\n")
        (root / "src/cli.rs").write_text("    ReaExample,\n")
        (root / "src/main.rs").write_text("Commands::ReaExample => {}\n")
        (root / "probe.py").write_bytes(b"read-only probe")
        mapping = self.mapping()
        mapping["family_defaults"]["artifact"].update(
            scope="synthetic limited scope", missing="implement and qualify", dependencies=[])
        mapping["behavior_gates"] = {"results": {"common": True, "requirement": "independent expected facts"}}
        mapping["auxiliary_capabilities"] = {"example_worker": {
            "kind": "rust_cli", "variant": "ReaExample", "source_paths": ["src/main.rs"],
            "entrypoint": "hepta-runtime rea-example", "scope": "synthetic internal worker"}}
        observation = {"qualification": "DISCOVERY_ONLY", "observed": []}
        environment = {"schema": "hepta.rea.compatibility-environment.v1",
                       "probe": {"path": "probe.py", "sha256": ledger.sha256(b"read-only probe")},
                       "observations": [{"host": "fixture", "exit_code": 0,
                                         "output_complete": True, "output_durable": True,
                                         "observation": observation,
                                         "stdout_sha256": ledger.sha256((json.dumps(observation, sort_keys=True) + "\n").encode())}],
                       "components": {}}
        snapshots = [{"upstream_tool": name, "catalog_index": index, "family": "artifact",
                      "source_contract_paths": ["src/artifact.ts"],
                      "schema_fingerprints": {"algorithm": ledger.SCHEMA_FINGERPRINT_ALGORITHM,
                                              "full_input": "d" * 64, "compact_input": "e" * 64,
                                              "full_output": None},
                      "upstream_annotations": {"readOnlyHint": True}}
                     for index, name in enumerate(names)]
        inputs = {"schema": "hepta.rea.compatibility-inputs.v1", "published_pin_path": "pin.json",
                  "published_package": "fixture@1", "source_commit": "fixture-commit",
                  "tool_families": ["artifact"], "expected_source_only_tools": [],
                  "catalog_snapshot_sha256": ledger.digest_json(snapshots)}
        stored = ledger.assemble_ledger(root, pin, inputs, mapping, environment, snapshots)
        for path, value in ((ledger.INPUTS_PATH, inputs), (ledger.MAP_PATH, mapping),
                            (ledger.ENVIRONMENT_PATH, environment), (ledger.LEDGER_PATH, stored)):
            ledger.write_json(root / path, value)
        return inputs, mapping, environment, stored

    def test_offline_check_needs_no_cache_network_process_or_current_git_head(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs, mapping, environment, stored = self.offline_fixture(root)
            output = io.StringIO()
            with mock.patch.object(ledger, "verify_inputs", side_effect=AssertionError("raw cache used")), \
                    mock.patch.object(ledger.subprocess, "run", side_effect=AssertionError("process used")), \
                    redirect_stdout(output):
                self.assertEqual(ledger.main(["check-mapping", "--root", str(root)]), 0)
            result = json.loads(output.getvalue())
            self.assertEqual(result["mapping_check"], "PASS")
            self.assertEqual(result["raw_reference_authenticity"], "NOT_REVERIFIED")
            self.assertEqual(result["parity_gate"], "OPEN")
            self.assertEqual(stored["runtime"]["baseline_commit"], "baseline")
            self.assertFalse((root / ".git").exists())
            self.assertFalse((root / "cache").exists())
            self.assertEqual(ledger.check_mapping(root, inputs, mapping, environment, stored), stored)

    def test_offline_check_retains_strict_parity_gate_and_rejects_cache_argument(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.offline_fixture(root)
            with redirect_stdout(io.StringIO()):
                self.assertEqual(ledger.main(["check-mapping", "--root", str(root), "--require-parity"]), 3)
            with self.assertRaisesRegex(ledger.LedgerError, "does not read --cache"):
                ledger.main(["check-mapping", "--root", str(root), "--cache", str(root / "missing")])

    def test_operation_candidate_is_not_a_qualification_without_receipts(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs, mapping, environment, stored = self.offline_fixture(root)
            mapping["overrides"]["inspect_example"] = {"implementation": "operation_candidate"}
            actual = ledger.assemble_ledger(root, ledger.published_pin(root, inputs), inputs,
                                             mapping, environment, ledger.snapshot_rows(stored["tools"]))
            self.assertEqual(actual["summary"]["qualified_tools"], 0)
            self.assertEqual(actual["summary"]["open_tools"], 2)
            self.assertEqual(actual["tools"][0]["qualification"]["status"], "OPEN")
            self.assertEqual(actual["tools"][0]["qualification"]["passed_gates"], [])

    def test_optional_empty_index_preserves_inventory_and_fake_pass_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs, mapping, environment, stored = self.offline_fixture(root)
            index = root / "docs/rea-native/compatibility/REA_6_8_0_QUALIFICATIONS.json"
            ledger.write_json(index, {"schema": "hepta.rea.operation-qualifications.v1", "entries": []})
            with mock.patch.object(ledger.subprocess, "run", side_effect=AssertionError("process used")):
                self.assertEqual(ledger.check_mapping(root, inputs, mapping, environment, stored), stored)
            ledger.write_json(index, {"schema": "hepta.rea.operation-qualifications.v1", "entries": [], "qualified": True})
            with self.assertRaisesRegex(ValueError, "handwritten PASS"):
                ledger.check_mapping(root, inputs, mapping, environment, stored)

    def test_offline_check_rejects_count_name_order_and_index_drift(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs, mapping, environment, stored = self.offline_fixture(root)
            for mutation in ("count", "name", "duplicate", "order", "index"):
                value = deepcopy(stored)
                if mutation == "count":
                    value["tools"].pop()
                elif mutation == "name":
                    value["tools"][0]["upstream_tool"] = "invented_tool"
                elif mutation == "duplicate":
                    value["tools"][1]["upstream_tool"] = value["tools"][0]["upstream_tool"]
                elif mutation == "order":
                    value["tools"].reverse()
                else:
                    value["tools"][0]["catalog_index"] = 7
                with self.subTest(mutation=mutation), self.assertRaises(ledger.LedgerError):
                    ledger.check_mapping(root, inputs, mapping, environment, value)

    def test_offline_check_binds_immutable_snapshot_beyond_name_digest(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs, mapping, environment, stored = self.offline_fixture(root)
            for field, replacement in (("family", "invented"),
                                       ("source_contract_paths", ["src/forged.ts"]),
                                       ("schema_fingerprints", {"full_input": "f" * 64}),
                                       ("upstream_annotations", {"readOnlyHint": False})):
                value = deepcopy(stored)
                value["tools"][0][field] = replacement
                with self.subTest(field=field), self.assertRaises(ledger.LedgerError):
                    ledger.check_mapping(root, inputs, mapping, environment, value)

    def test_offline_check_rejects_row_and_summary_fake_qualification(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs, mapping, environment, stored = self.offline_fixture(root)
            for mutation in ("status", "passed_gates", "summary", "implementation", "gate_requirement"):
                value = deepcopy(stored)
                if mutation == "status":
                    value["tools"][0]["qualification"]["status"] = "PASS"
                elif mutation == "passed_gates":
                    value["tools"][0]["qualification"]["passed_gates"] = ["results"]
                elif mutation == "summary":
                    value["summary"].update(qualified_tools=2, open_tools=0)
                elif mutation == "implementation":
                    value["tools"][0]["native_implementation"] = "equivalent"
                else:
                    value["behavior_gates"]["results"]["requirement"] = "PASS"
                with self.subTest(mutation=mutation), self.assertRaisesRegex(ledger.LedgerError, "stored ledger differs"):
                    ledger.check_mapping(root, inputs, mapping, environment, value)

    def test_offline_check_reprojects_mapping_even_if_mapping_digest_is_updated(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs, mapping, environment, stored = self.offline_fixture(root)
            mapping["family_defaults"]["artifact"]["scope"] = "changed scope"
            stored["mapping_sha256"] = ledger.digest_json(mapping)
            with self.assertRaisesRegex(ledger.LedgerError, "stored ledger differs"):
                ledger.check_mapping(root, inputs, mapping, environment, stored)

    def test_offline_check_detects_stale_source_bytes_and_unmapped_handlers(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs, mapping, environment, stored = self.offline_fixture(root)
            path = root / "src/mcp/server.rs"
            original = path.read_text()
            path.write_text(original + "// semantic implementation changed\n")
            with self.assertRaisesRegex(ledger.LedgerError, "stored ledger differs"):
                ledger.check_mapping(root, inputs, mapping, environment, stored)
            path.write_text(original + "    pub async fn rea_unmapped(\n")
            with self.assertRaisesRegex(ledger.LedgerError, "unmapped=.*rea_unmapped"):
                ledger.check_mapping(root, inputs, mapping, environment, stored)

    def test_offline_check_cannot_hide_cli_coverage_by_emptying_auxiliary_map(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs, mapping, environment, stored = self.offline_fixture(root)
            mapping["auxiliary_capabilities"] = {}
            with self.assertRaisesRegex(ledger.LedgerError, "unmapped REA CLI"):
                ledger.check_mapping(root, inputs, mapping, environment, stored)

    def test_handwritten_pass_is_refused_in_interfaces_auxiliary_and_gate_declarations(self):
        for section, key in (("interfaces", "rea_example"), ("auxiliary_capabilities", "example_worker"),
                             ("behavior_gates", "results")):
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                inputs, mapping, environment, stored = self.offline_fixture(root)
                mapping[section][key]["qualification"] = "PASS"
                with self.subTest(section=section), self.assertRaisesRegex(ledger.LedgerError, "no handwritten PASS"):
                    ledger.check_mapping(root, inputs, mapping, environment, stored)

    def test_offline_check_binds_observation_and_probe_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs, mapping, environment, stored = self.offline_fixture(root)
            changed = deepcopy(environment)
            changed["observations"][0]["observation"]["observed"] = ["unverified engine"]
            with self.assertRaisesRegex(ledger.LedgerError, "stdout identity mismatch"):
                ledger.check_mapping(root, inputs, mapping, changed, stored)
            (root / "probe.py").write_bytes(b"changed probe")
            with self.assertRaisesRegex(ledger.LedgerError, "probe source changed"):
                ledger.check_mapping(root, inputs, mapping, environment, stored)


if __name__ == "__main__":
    unittest.main()
