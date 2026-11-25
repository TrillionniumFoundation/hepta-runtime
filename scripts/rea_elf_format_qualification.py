#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Run the reviewed finite ELF format corpus through both real public MCPs."""

from __future__ import annotations

import argparse
from pathlib import Path
import subprocess

import rea_elf_format_fixtures as fixtures
import rea_operation_evidence as evidence
import rea_operation_qualification as q
from rea_full_qualification import Selection, SourceMonitor


SCHEMA = "hepta.rea.elf-format-qualification.v2"
NODE_SHA256 = "94efd062ed066c1a0b332e18249859c905e920eeada5df55d24c99b919629a90"
FILES = ("scripts/rea_elf_format_fixtures.py", "scripts/rea_elf_format_qualification.py",
         "scripts/rea_elf_format_evidence.py", "tests/rea_elf_format_tests.py")


def config_for(output):
    return {"controller_workspace_roots": [str(output / "workspace")], "state_dir": str(output / "state"),
            "hosts": {"never-connect": {"ssh_target": "never-connect-invalid",
                       "remote_state_dir": str(output / "unused-remote"), "allow_execute": False,
                       "allow_pty": False, "allow_write": False, "allow_job_network": False}}}


def check_case(case, response):
    value = q.tool_value(response)
    if case["kind"] == "error":
        q.require("rpc_error" in value or value.get("isError") is True,
                  "reviewed malformed/unsupported input unexpectedly succeeded")
        return None
    record = q.evidence_value(response)
    q.require(record["operation"] == "inspect_elf_notes" and q.json_equal(record["provider"], q.PROVIDER),
              "success lost the frozen operation/provider identity")
    q.require(record["evidence_id"] == q.semantic_evidence_id(record), "independent semantic ID differs")
    result = record["normalized_result"]
    q.require(q.json_equal(result["artifact"], case["fixture"]), "success names different input bytes")
    q.require(result["format"] == "elf" + str(case["bits"]) and result["byte_order"] == case["byte_order"],
              "independent ELF class/order differs")
    q.require(len(result["entries"]) == 1 and result["entries"][0]["owner"] == "GNU"
              and result["entries"][0]["descriptor"]["hex"] == bytes(range(20)).hex(),
              "independent GNU note bytes differ")
    q.require(q.json_equal(record["parameters"], {"max_file_bytes": 67108864, "max_entries": 32,
                                                 **case["arguments"]}), "defaulted parameters differ")
    return record


def arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("repo", "binary", "reference-package", "reference-tarball", "node", "output-dir"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--binary-sha256", required=True)
    parser.add_argument("--build-summary", type=Path)
    parser.add_argument("--build-summary-sha256")
    return parser.parse_args(argv)


def main(argv=None):
    args = arguments(argv)
    for name in ("repo", "binary", "reference_package", "reference_tarball", "node", "output_dir"):
        q.require(getattr(args, name).is_absolute(), "all selected paths must be absolute")
    q.require(args.repo.resolve() == Path(__file__).resolve().parents[1], "execute the selected repository's producer")
    q.require((args.build_summary is None) == (args.build_summary_sha256 is None), "incomplete build receipt pin")
    q.require(not args.output_dir.exists(), "refusing to reuse an evidence directory")
    output = args.output_dir
    output.mkdir(mode=0o700, parents=True)
    report = {"schema": SCHEMA, "profile": fixtures.PROFILE, "operation": "inspect_elf_notes",
              "qualified": False, "cases": [], "sessions": {}, "errors": []}
    clients, monitor = {}, None
    exit_code = 1
    try:
        report["reference_before"] = q.reference_package(args.reference_package, args.reference_tarball)
        report["native_before"] = q.identity(args.binary)
        q.require(report["native_before"]["sha256"] == args.binary_sha256, "native binary pin differs")
        report["node_before"] = q.identity(args.node.resolve())
        q.require(report["node_before"]["sha256"] == NODE_SHA256, "Node binary pin differs")
        report["node_version"] = subprocess.check_output([str(args.node), "--version"], env={}, timeout=10).decode().strip()
        q.require(report["node_version"] == "v22.23.4", "unreviewed Node version")
        report["producer_before"] = [{**q.identity(args.repo / name), "path": name} for name in FILES]
        selection = Selection(args.repo, output / "unused-target", output)
        monitor = SourceMonitor(selection)
        monitor.start()
        source = selection.snapshot()
        report["source_before"] = q.artifact_json(output, "source-before.json", source)
        if args.build_summary is not None:
            from rea_build_evidence import capture_build
            report["build_evidence"], _ = capture_build(args.build_summary, args.build_summary_sha256,
                                                       output, source, report["native_before"])
        workspace = output / "workspace"
        workspace.mkdir(mode=0o700)
        manifest = fixtures.corpus(workspace, write=True)
        report["workspace"] = str(workspace)
        report["manifest"] = q.artifact_json(output, "manifest.json", manifest)
        config = output / "runtime.json"
        q.write_json(config, config_for(output))
        report["config"] = q.artifact_reference(config, output)
        environment = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "REA_MCP_INPUT_SCHEMA_PROFILE": "full",
                       "REA_MCP_OUTPUT_SCHEMA_PROFILE": "full"}
        for label, command, env in (
            ("reference", [str(args.node), str(args.reference_package / "scripts/rea.mjs"), "mcp"], environment),
            ("native", [str(args.binary), "mcp", "--runtime-config", str(config)], {}),
        ):
            client = q.Mcp(command, workspace, env, output / label)
            clients[label] = client
            client.initialize()
            report["sessions"][label] = {"tools": q.artifact_json(output, label + "-tools.json", client.tools())}
        retained = {}
        for case in manifest["cases"]:
            row = {"id": case["id"]}
            for label, tool in (("reference", "inspect_elf_notes"), ("native", "rea_inspect_elf_notes")):
                response = clients[label].call(tool, case["arguments"])
                row[label] = q.artifact_json(output, "cases/" + case["id"] + "." + label + ".json", response)
            report["cases"].append(row)
            # A failed expectation is retained without omitting later observations.
            try:
                record = check_case(case, evidence.artifact_json(output, row["reference"]))
                check_case(case, evidence.artifact_json(output, row["native"]))
                if record is not None:
                    retained[record["evidence_id"]] = record
            except (KeyError, TypeError, ValueError) as error:
                report["errors"].append({"case": case["id"], "error": str(error)})
        report["retention"] = {}
        for label, tool in (("reference", "get_evidence_bundle"), ("native", "rea_get_evidence_bundle")):
            response = clients[label].call(tool, {})
            report["retention"][label] = q.artifact_json(output, label + "-retention.json", response)
            q.check_retention_response({"arguments": {}}, response, list(retained.values()))
        report["fixtures_after"] = {name: q.identity(Path(item["path"])) for name, item in manifest["fixtures"].items()}
        report["reference_after"] = q.reference_package(args.reference_package, args.reference_tarball)
        report["native_after"] = q.identity(args.binary)
        report["node_after"] = q.identity(args.node.resolve())
        report["source_after"] = q.artifact_json(output, "source-after.json", selection.snapshot())
        report["producer_after"] = [{**q.identity(args.repo / name), "path": name} for name in FILES]
        exit_code = 0 if not report["errors"] else 1
    except BaseException as error:
        report["errors"].append({"stage": "execution", "error": type(error).__name__ + ": " + str(error)})
    finally:
        for label, client in clients.items():
            try:
                close = client.close()
                report["sessions"].setdefault(label, {}).update({
                    "wire": q.artifact_reference(client.output / "wire.jsonl", output),
                    "launch": q.artifact_reference(client.output / "launch.json", output),
                    "close": q.artifact_reference(client.output / "close.json", output)})
                if not evidence.owner_closed(close):
                    exit_code = 1
            except BaseException as error:
                report["errors"].append({"stage": label + "-close", "error": str(error)})
                exit_code = 1
        if monitor is not None:
            events = monitor.stop()
            report["source_events"] = q.artifact_json(output, "source-events.json", events)
            if events != {"event_count": 0, "retained_events": [], "events_truncated": False, "errors": []}:
                exit_code = 1
        report["producer_exit_code"] = exit_code
        q.write_json(output / "qualification.json", report)
    print(q.json_bytes({"report": str(output / "qualification.json"), "exit_code": exit_code,
                        "qualified": False, "cases_recorded": len(report["cases"])}).decode(), end="")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
