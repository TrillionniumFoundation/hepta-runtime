#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Physically corrupt complete shell receipts and require their refusal."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import hia_native_shell_qualification as q


class ShellEvidenceTests(unittest.TestCase):
    def test_complete_corpus_and_physical_corruptions(self):
        output = Path(os.environ["HIA_SHELL_QUALIFICATION_OUTPUT"]).resolve(strict=True)
        results = {}
        envs = {"terminal_clean": "HIA_TERMINAL_MANIFEST", "shell_gate": "HIA_SHELL_GATE_MANIFEST"}
        for key, profile in q.COMPONENTS.items():
            manifest = Path(os.environ[envs[key]]).resolve(strict=True)
            original = output / profile["folder"]
            admitted = q.read_corpus(ROOT, original, key, manifest)
            self.assertGreater(admitted["semantic_cases"], 0)
            with tempfile.TemporaryDirectory(prefix="hia-shell-evidence-") as temporary:
                folder = Path(temporary) / "corpus"
                shutil.copytree(original, folder)
                pristine = {name: (folder / name).read_bytes() for name in (*q.CORPUS_FILES, "native-corpus.json")}
                names = []
                for case in q.EVIDENCE_REFUSALS:
                    with self.subTest(component=key, corruption=case):
                        for name, raw in pristine.items():
                            path = folder / name
                            if path.is_symlink():
                                path.unlink()
                            path.write_bytes(raw)
                        meta = q.decode(pristine["native-corpus.json"])
                        if case == "failed_status":
                            meta["status"] = "FAIL"
                        elif case == "contradictory_error":
                            meta["error"] = "the retained native process failed"
                        elif case == "wrong_mode":
                            meta["mode"] = "gate" if profile["mode"] == "terminal" else "terminal"
                        elif case == "invented_rust":
                            meta["rust_oracle_executed_by_this_suite"] = True
                        elif case == "production_claim":
                            meta["production_shell_execution_qualified"] = True
                        elif case == "source_digest":
                            meta["source_sha256"] = "0" * 64
                        elif case == "manifest_digest":
                            meta["manifest_sha256"] = "0" * 64
                        elif case == "module_identity":
                            meta["module"]["image_sha256"] = "0" * 64
                        elif case == "boolean_count":
                            meta["transport_control_count"] = True
                        elif case == "category_count":
                            name = next(iter(meta["categories"]))
                            meta["categories"][name] += 1
                        elif case in ("changed_input", "truncated_output"):
                            name = "input.bin" if case == "changed_input" else "native-output.bin"
                            raw = bytearray(pristine[name])
                            if case == "changed_input":
                                raw[-1] ^= 1
                            else:
                                del raw[-1:]
                            (folder / name).write_bytes(raw)
                            meta["files"][name] = q.pin(raw)
                        elif case == "semantic_row":
                            name = "cases.jsonl"
                            rows = [q.decode(line) for line in pristine[name].splitlines()]
                            rows[-1]["output_sha256"] = "0" * 64
                            raw = b"".join(q.encoded(row) + b"\n" for row in rows)
                            (folder / name).write_bytes(raw)
                            meta["files"][name] = q.pin(raw)
                        elif case.startswith("control_"):
                            name = "transport-controls.jsonl"
                            rows = [q.decode(line) for line in pristine[name].splitlines()]
                            if case == "control_missing":
                                rows.pop()
                                meta["transport_control_count"] -= 1
                            elif case == "control_output_changed":
                                row = next(row for row in rows if row["output_capacity"])
                                row["output_after_hex"] = "00" + row["output_after_hex"][2:]
                            else:
                                rows[0]["native_return"] = 0
                            raw = b"".join(q.encoded(row) + b"\n" for row in rows)
                            (folder / name).write_bytes(raw)
                            meta["files"][name] = q.pin(raw)
                        elif case == "missing_file":
                            (folder / "native-output.bin").unlink()
                        elif case == "symlink_file":
                            path = folder / "native-output.bin"
                            path.unlink()
                            path.symlink_to(original / "native-output.bin")
                        elif case == "duplicate_json":
                            raw = pristine["native-corpus.json"].rstrip()
                            (folder / "native-corpus.json").write_bytes(raw[:-1] + b',"status":"PASS"}\n')
                        else:
                            self.fail("undeclared corruption")
                        if case != "duplicate_json":
                            (folder / "native-corpus.json").write_bytes(q.encoded(meta) + b"\n")
                        with self.assertRaises((ValueError, OSError)):
                            q.read_corpus(ROOT, folder, key, manifest)
                        names.append(case)
                results[key] = names
        print(json.dumps({"schema": "hepta.runtime.shell-evidence-controls.v1", "status": "PASS",
                          "cases": results, "refusals": sum(map(len, results.values())),
                          "native_semantic_calls_added": 0}, sort_keys=True))


if __name__ == "__main__":
    unittest.main()
