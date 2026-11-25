#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Compose independently replayed receipts for one finite Linux-local profile.

This separate index never promotes a row in the 229-operation compatibility
ledger. Its nine gate names describe only SCOPE below. The original operation,
family and lifecycle receipts retain their original OPEN assessments unchanged.
"""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

import rea_build_evidence as build
import rea_elf_evidence_family_evidence as family
import rea_elf_format_evidence as formats
import rea_lifecycle_evidence as lifecycle
import rea_operation_evidence as operation
import rea_operation_qualification as q
import rea_readback_capacity_evidence as capacity


SCHEMA = "hepta.rea.scoped-operation-index.v2"
PROFILE = "rea-agents-6.8.0/inspect_elf_notes/linux-local/v2"
ROLES = ("operation", "family", "lifecycle", "format", "readback_capacity")
GATES = ("contracts", "results", "evidence", "typed_outcomes", "limits_and_cancellation",
         "source_package_boundary", "format_architecture_corpus", "retention_and_pagination",
         "effects_and_recovery")
SCOPE = {
    "transport": "Linux x86_64 local stdio, frozen Node 22.23.4 and REA 6.8.0",
    "operation": "inspect_elf_notes; the fixed v1 cases and regenerated 99-case format corpus",
    "family": "finite ELF-dependent get/export/import and unsupported-analysis-view observations",
    "lifecycle": "active reference/native capture cancellation and EOF, native worker deadline and parallel completion",
    "readback": "native immutable byte snapshots, count/aggregate/per-snapshot limits and recovery, separate from upstream parity",
    "recovery": "explicit export/import into a new owner; no implicit process persistence",
    "build": "same selected source, toolchain, native binary and full original build matrix",
}
EXCLUDED = (
    "whole inspect_elf_notes replacement and the 229-operation/18-family ledger",
    "unbounded format/architecture space and the complete historic 5,244-input decoder corpus",
    "reference worker-deadline injection (the frozen parser has no separate worker)",
    "active readback-encoder cancellation, all provider and arbitrary concurrent-fault profiles",
    "cross-platform, multihost, remote providers, installed services and hostile-operator attestation",
)


def derive_gates(op, fam, life, fmt, cache, build_bound):
    """Inputs are consumer results, never producer PASS or qualification flags."""
    cases = op["case_comparisons"]
    op_pass = bool(cases) and all(row.get("passed") is True and row.get("opaque_response_equal") is True
                                 and row.get("parsed_result_equal") is True for row in cases.values())
    fmt_pass = bool(fmt["cases"]) and all(row.get("passed") is True and row.get("opaque_response_equal") is True
                                         for row in fmt["cases"].values()) and fmt["retention"]["opaque_response_equal"] is True
    fam_pass = len(fam["comparisons"]) == 50 and all(row["status"] == "PASS" for row in fam["comparisons"])
    active = all(life["gates"].get(name) == "PASS" for name in (
        "active-cancellation-owner-drain", "unknown-cancellation-boundary",
        "native-worker-deadline-owner-drain", "parallel-independent-request-completion"))
    eof = life["gates"].get("active-eof-owner-drain") == "PASS"
    errors = [row for row in fmt["cases"].values() if row["expected_outcome"] == "error"]
    readback = fam["native_readback"]
    cache_pass = (cache["normal_owner_closes"] == 3 and cache["results"] == {
        "extension-count": {"distinct_live_snapshots": 4, "count_refusals": 1, "restored_zero": True},
        "extension-total-bytes": {"retained_before_refusal": 2, "aggregate_refusals": 1, "restored_zero": True},
        "extension-single-bytes": {"per_snapshot_refusals": 1, "restored_zero": True}})
    outcomes = {
        "contracts": op["schema_equal"] is True and fam_pass,
        "results": op_pass and fmt_pass and fam_pass,
        "evidence": op_pass and fmt_pass and fam_pass and op["retention_equal"] is True,
        "typed_outcomes": bool(errors) and all(row["passed"] is True for row in errors) and active,
        "limits_and_cancellation": op_pass and fmt_pass and fam_pass and active and cache_pass,
        "source_package_boundary": build_bound,
        "format_architecture_corpus": op_pass and fmt_pass,
        "retention_and_pagination": fam_pass and readback["pages"] > 1 and readback["reconstructed_bytes"] > 0 and cache_pass,
        "effects_and_recovery": fam_pass and fam["normal_owner_closes"] == 8 and eof and op["cold_session_empty"] is True,
    }
    q.require(set(outcomes) == set(GATES), "reviewed gate set differs")
    return {name: "PASS" if outcomes[name] else "OPEN" for name in GATES}


def validate_index(repo, index_path, expected_sha256):
    repo, index_path = Path(repo), Path(index_path)
    q.require(repo.is_absolute() and index_path.is_absolute(), "explicit absolute paths are required")
    raw = build.read_regular(index_path.parent, index_path.name, q.MAX_WIRE_BYTES)
    q.require(hashlib.sha256(raw).hexdigest() == expected_sha256, "composition index digest differs")
    index = q.parse_json(raw)
    q.require(set(index) == {"schema", "profile", "operation", "scope", "receipts"}
              and index["schema"] == SCHEMA and index["profile"] == PROFILE
              and index["operation"] == "inspect_elf_notes" and index["scope"] == SCOPE,
              "unreviewed composition profile or handwritten verdict")
    rows = index["receipts"]
    q.require(isinstance(rows, list) and [row.get("role") for row in rows] == list(ROLES),
              "receipt roles are missing, repeated or reordered")
    reports, paths = {}, {}
    for row in rows:
        q.require(set(row) == {"role", "report", "sha256"}, "receipt entries may only select role/path/digest")
        path = operation.contained_path(index_path.parent, row["report"])
        content = build.read_regular(path.parent, path.name, q.MAX_WIRE_BYTES)
        q.require(hashlib.sha256(content).hexdigest() == row["sha256"], "component receipt digest differs")
        reports[row["role"]], paths[row["role"]] = q.parse_json(content), path
    # The legacy consumer's path contract is intentionally preserved. New
    # execution outputs can live under excluded docs/qualification/ in repo.
    relative = paths["operation"].relative_to(repo).as_posix()
    pins = {row["role"]: row["sha256"] for row in rows}
    assessed = {
        "operation": operation.validate_report(repo, relative, pins["operation"]),
        "family": family.validate_report(repo, paths["family"], pins["family"]),
        "lifecycle": lifecycle.validate_lifecycle_receipt(repo, paths["lifecycle"], pins["lifecycle"]),
        "format": formats.validate_report(repo, paths["format"], pins["format"]),
        "readback_capacity": capacity.validate_report(repo, paths["readback_capacity"], pins["readback_capacity"]),
    }
    q.require(assessed["lifecycle"]["profile"] == lifecycle.PROFILE,
              "legacy lifecycle profile does not observe independent parallel requests")
    sources, binaries, nodes, builds = set(), set(), set(), set()
    native = reports["operation"]["native_before"]
    for role in ROLES:
        report, assessment = reports[role], assessed[role]
        source = operation.artifact_json(paths[role].parent, report["source_before"])
        sources.add(source["tree_sha256"])
        binary = report["binary_before"] if role in {"family", "readback_capacity"} else report["native_before"]
        binaries.add((binary["bytes"], binary["sha256"]))
        if role != "readback_capacity":
            node = report["node_binary"] if role == "operation" else report["node_before"]
            nodes.add((node["bytes"], node["sha256"]))
        if role != "lifecycle":
            binding = assessment.get("build_source_binding")
            q.require(binding is not None, "component lacks the original full build/source evidence: " + role)
            builds.add(binding["build_summary_sha256"])
    q.require(len(sources) == len(binaries) == len(nodes) == len(builds) == 1,
              "component observations belong to different source/binary/Node/build combinations")
    q.require(next(iter(nodes))[1] == formats.producer.NODE_SHA256, "unreviewed Node executable")
    life_report = reports["lifecycle"]
    source_bytes = operation.read_artifact(paths["lifecycle"].parent, life_report["binary_source_receipt"])
    q.require(hashlib.sha256(source_bytes).hexdigest() == next(iter(builds)),
              "lifecycle's retained build receipt is not the independently validated full matrix")
    gates = derive_gates(assessed["operation"], assessed["family"], assessed["lifecycle"],
                         assessed["format"], assessed["readback_capacity"], True)
    complete = all(value == "PASS" for value in gates.values())
    return {"schema": "hepta.rea.scoped-operation-assessment.v2", "profile": PROFILE, "scope": SCOPE,
            "status": "SCOPED_COMPOSITION_VERIFIED" if complete else "OPEN", "qualified": False,
            "scoped_composition_verified": complete,
            "upstream_operation_qualified": False, "ledger_promotions": 0, "gates": gates,
            "excluded_requirements": list(EXCLUDED), "index_sha256": expected_sha256,
            "source_tree_sha256": next(iter(sources)), "native_binary": native,
            "build_summary_sha256": next(iter(builds)), "component_assessments": assessed}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--index", type=Path, required=True)
    parser.add_argument("--sha256", required=True)
    args = parser.parse_args(argv)
    result = validate_index(args.repo, args.index, args.sha256)
    print(q.json_bytes(result).decode(), end="")
    return 0 if result["scoped_composition_verified"] else 3


if __name__ == "__main__":
    raise SystemExit(main())
