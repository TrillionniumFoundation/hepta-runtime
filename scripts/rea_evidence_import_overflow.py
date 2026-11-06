#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Actual body overflow followed by public import, retained pages and export.

Both real MCP producers parse the same controlled APK. Each completes beyond
the original 10 MiB response boundary, exports its complete parent, then a new
session publicly imports that parent and reconstructs all six digest pages.
A third session imports the complete history and exports identical bytes.
This finite Linux regression does not establish full REA replacement.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

import rea_apk_export_qualification as a
import rea_operation_qualification as q
import rea_analysis_view_recovery as recovery
import rea_evidence_import_qualification as imports
from rea_full_qualification import Selection, SourceMonitor


ALIASES = {**imports.ALIASES, "inspect_apk_signature": "rea_inspect_apk_signature_evidence",
           "inspect_analysis_view": "rea_inspect_analysis_view"}
OPEN_REQUIREMENTS = ["all-evidence-provider-and-file-resource-profiles", "complete-public-capability-parity",
                     "full-final-combination-build-receipt", "real-multi-host-failure-recovery",
                     "complete-cost-comparison"]


class Session(imports.Session):
    def call(self, name, operation, arguments):
        tool = ALIASES[operation] if self.label == "native" else operation
        response = self.client.call(tool, arguments)
        value = q.tool_value(response)
        row = {"id": name, "operation": operation, "arguments": arguments,
               "value": value, "orders": imports.orders(value)}
        self.rows.append(row)
        saved = recovery.save_gzip(self.output / (f"call-{len(self.rows):02d}-{name}.json.gz"),
                                   {**row, "response": response})
        self.state["rows"].append({"id": name, "operation": operation, "artifact": saved})
        return value


def discovery(session, name, count, parent_id):
    result = imports.payload(session.call(name, "get_evidence_bundle", {"detail": "summary"}))
    q.require(result["total_retained_records"] == count and result["unknown_revisions"] == 0
              and len(result["records"]) == count
              and any(record["evidence_id"] == parent_id for record in result["records"]),
              "public import lost the complete retained parent or derived history")
    return result


def export(session, name, path, count):
    result = imports.payload(session.call(name, "export_evidence_bundle",
                                         {"path": str(path), "overwrite": True}))
    before = q.identity(path)
    raw = path.read_bytes()
    q.require(result == {"path": str(path), "bytes": len(raw), "records": count, "unknowns": 0}
              and q.identity(path) == before, "complete export receipt or stable file differs")
    (session.output / (name + ".json")).write_bytes(raw)
    session.state.setdefault("exports", {})[name] = before
    return raw


def exercise_producer(session, apk, seed):
    limits = recovery.overflow(session.call("body-overflow", "inspect_apk_signature",
                                          {"path": str(apk), "detail": "complete"}),
                               "inspect_apk_signature")
    parent_id = limits["evidence_id"]
    q.require(limits["evidence_reference"] == {"kind": "retained-evidence", "evidence_id": parent_id},
              "completed body overflow did not return a usable complete reference")
    discovery(session, "producer-discovery", 1, parent_id)
    raw = export(session, "seed-export", seed, 1)
    bundle = q.parse_json(raw)
    imports.check_bundle(bundle, 1, 0)
    q.require(bundle["records"][0]["evidence_id"] == parent_id, "seed export omitted its complete parent")
    return parent_id, raw


def exercise_import(session, seed, complete, parent_id):
    imports.counts(session.call("public-import", "import_evidence_bundle", {"path": str(seed)}), 1, 0, 1)
    discovery(session, "import-discovery", 1, parent_id)
    recovery.overflow(session.call("bundle-overflow", "get_evidence_bundle", {}), "get_evidence_bundle")
    source = {"kind": "retained-evidence", "evidence_id": parent_id}
    summary = a.payload(session.call("summary", "inspect_analysis_view",
                                     {"source": source, "view": {"kind": "summary"}}))
    pages, offset = [], 0
    while True:
        q.require(offset == len(pages) and offset < 6, "invalid retained page continuation")
        page = a.payload(session.call("page-" + str(offset), "inspect_analysis_view", {
            "source": source, "view": {"kind": "apk-signature", "collection": "digests", "offset": offset, "limit": 1}}))
        coverage = page["normalized_result"]["coverage"]
        q.require(page["normalized_result"]["parent_evidence_id"] == parent_id
                  and coverage["status"] == "page" and coverage["examined"] == 1
                  and coverage["total"] == 6 and len(page["normalized_result"]["items"]) == 1,
                  "imported parent page lost identity, bytes or coverage")
        pages.append(page)
        if coverage["exhausted"]:
            q.require(len(pages) == 6 and coverage["next_offset"] is None, "premature page exhaustion")
            break
        q.require(coverage["next_offset"] == offset + 1, "page continuation skipped data")
        offset = coverage["next_offset"]
    raw = export(session, "complete-export", complete, 8)
    recovery.verify_export(q.parse_json(raw), parent_id, pages, summary)
    discovery(session, "after-export-discovery", 8, parent_id)
    session.state["checks"].append({"id": "all-six-imported-pages-reconstruct-complete-export", "status": "PASS"})
    return pages, raw


def exercise_cold(session, complete, restored, parent_id, pages, expected):
    imports.counts(session.call("cold-import", "import_evidence_bundle", {"path": str(complete)}), 8, 0, 8)
    discovery(session, "cold-discovery", 8, parent_id)
    page = a.payload(session.call("cold-page", "inspect_analysis_view", {
        "source": {"kind": "retained-evidence", "evidence_id": parent_id},
        "view": {"kind": "apk-signature", "collection": "digests", "offset": 1, "limit": 1}}))
    q.require(page == pages[1], "cold complete-history import changed the large page")
    raw = export(session, "cold-export", restored, 8)
    q.require(raw == expected, "cold public import lost complete canonical bytes")
    return raw


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("binary", "reference-package", "reference-tarball", "node", "repo", "output-dir"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--binary-sha256", required=True)
    args = parser.parse_args(argv)
    q.require(all(value.is_absolute() for value in vars(args).values() if isinstance(value, Path)), "all paths must be absolute")
    out = args.output_dir
    out.mkdir(parents=True, exist_ok=False)
    report = {"schema": "hepta.rea.public-import-overflow.v1", "qualified": False, "status": "OPEN",
              "open_requirements": OPEN_REQUIREMENTS, "sessions": {}, "comparisons": [], "errors": []}
    sessions = {}
    monitor = selection = before = None
    try:
        report["binary_before"] = q.identity(args.binary)
        q.require(report["binary_before"]["sha256"] == args.binary_sha256, "frozen binary hash differs")
        report["reference_before"] = q.reference_package(args.reference_package, args.reference_tarball)
        report["node"] = q.identity(args.node.resolve())
        q.require(report["node"]["sha256"] == a.NODE_SHA256, "unexpected Node binary")
        selection = Selection(args.repo, out / "unused-target", out)
        monitor = SourceMonitor(selection)
        monitor.start()
        before = selection.snapshot()
        q.write_json(out / "producer-before.json", before)
        workspace = out / "workspace"
        workspace.mkdir(mode=0o700)
        apk, seed, complete, restored = (workspace / name for name in
                                         ("overflow.apk", "seed.json", "complete.json", "restored.json"))
        apk.write_bytes(recovery.oversized_apk((args.repo / "tests/fixtures/rea_apk_signature/rotation-v31.apk").read_bytes()))
        report["fixture"] = q.identity(apk)
        config = out / "runtime.json"
        q.write_json(config, {"controller_workspace_roots": [str(workspace)], "state_dir": str(out / "state"),
                             "hosts": {"never-connect": {"ssh_target": "never-connect-invalid", "remote_state_dir": str(out / "unused-remote"),
                                                         "allow_execute": False, "allow_pty": False, "allow_write": False, "allow_job_network": False}}})
        environment = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "REA_MCP_INPUT_SCHEMA_PROFILE": "full", "REA_MCP_OUTPUT_SCHEMA_PROFILE": "full"}
        producers = (("reference", [str(args.node), str(args.reference_package / "scripts/rea.mjs"), "mcp"], environment),
                     ("native", [str(args.binary), "mcp", "--runtime-config", str(config)], {}))
        exports = {}
        for label, command, env in producers:
            for scenario in ("producer", "import", "cold"):
                session = Session(label, scenario, command, env, workspace, out / (label + "-" + scenario), report)
                sessions[(label, scenario)] = session
                if scenario == "producer":
                    parent_id, seed_bytes = exercise_producer(session, apk, seed)
                elif scenario == "import":
                    pages, complete_bytes = exercise_import(session, seed, complete, parent_id)
                else:
                    cold_bytes = exercise_cold(session, complete, restored, parent_id, pages, complete_bytes)
                session.close()
            exports[label] = (seed_bytes, complete_bytes, cold_bytes)
        for scenario in ("producer", "import", "cold"):
            left, right = sessions[("reference", scenario)], sessions[("native", scenario)]
            q.require([row["id"] for row in left.rows] == [row["id"] for row in right.rows], "producer request sequence differs")
            for old, new in zip(left.rows, right.rows):
                q.require(old["arguments"] == new["arguments"], "producers received different inputs")
                differences = a.differences(old["value"], new["value"]) + a.differences(old["orders"], new["orders"], "$/orders")
                report["comparisons"].append({"id": scenario + "/" + old["id"], "status": "FAIL" if differences else "PASS", "differences": differences})
        for index, name in enumerate(("seed", "complete", "cold")):
            report["comparisons"].append({"id": name + "-canonical-export-bytes", "status": "PASS" if exports["reference"][index] == exports["native"][index] else "FAIL"})
    except Exception as exc:
        report["errors"].append({"type": type(exc).__name__, "message": str(exc)})
    finally:
        for session in sessions.values():
            if not session.client.closed:
                try:
                    session.close()
                except Exception as exc:
                    report["errors"].append({"type": type(exc).__name__, "message": "cleanup: " + str(exc)})
        if monitor is not None:
            events = monitor.stop()
            q.write_json(out / "producer-events.json", events)
            after = selection.snapshot()
            q.write_json(out / "producer-after.json", after)
            report["source_unchanged"] = before == after and events["event_count"] == 0 and not events["errors"]
            if not report["source_unchanged"]:
                report["errors"].append({"type": "SourceChanged", "message": "selected producer sources changed"})
        try:
            report["binary_after"] = q.identity(args.binary)
            report["reference_after"] = q.reference_package(args.reference_package, args.reference_tarball)
            q.require(report["binary_before"] == report["binary_after"] and report["reference_before"] == report["reference_after"], "producer identity changed")
        except Exception as exc:
            report["errors"].append({"type": type(exc).__name__, "message": str(exc)})
    expected = {label + "/" + scenario: count for label in ("reference", "native")
                for scenario, count in (("producer", 3), ("import", 12), ("cold", 4))}
    observed = {label + "/" + scenario: len(session.rows) for (label, scenario), session in sessions.items()}
    passed = sum(row["status"] == "PASS" for row in report["comparisons"])
    report["counts"] = observed
    report["finite_status"] = "PASS" if not report["errors"] and observed == expected and len(report["comparisons"]) == 22 and passed == 22 else "FAIL"
    q.write_json(out / "qualification.json", report)
    print(json.dumps({"finite_status": report["finite_status"], "qualified": False, "passed": passed,
                      "comparisons": len(report["comparisons"]), "errors": report["errors"], "receipt": q.identity(out / "qualification.json")}))
    return 0 if report["finite_status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
