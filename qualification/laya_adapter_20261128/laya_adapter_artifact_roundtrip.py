#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Apply the already sealed actual Laya adapter candidate with native byte APIs.

This is a zero-forward artifact lifecycle qualification. It performs no candidate
selection, quality evaluation, training, encoder execution or deployment. The
native generic API validates actual safetensors storage and exact prior bytes;
the compiler additionally enforces this one fixed four-tensor research scope.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import secrets
import socket
import stat
import struct
import sys
import time

import late_quote_mcp_relocated as m

t = m.t
require, read, parse, digest = m.require, m.read, m.parse, m.digest
PARENT = "52adec4b889f2898d554877e3534f3121503f88850920868e9adc5b6547a7a73"
CANDIDATE = "ddc4dbbb17d14a33b468bb1282281455941f944d84b868a8bb49f22432e2246f"
MAIN_SHA = "9763f0c078a46c7367703bb7d072003fe2136cf6e5f59656f7733e6f90ac40e9"
TENSOR = "model.scorer.3.A"
SHAPES = {"model.scorer.1.A": [2, 768], "model.scorer.1.B": [4, 2],
          "model.scorer.3.A": [1, 768], "model.scorer.3.B": [1, 1]}
PROVENANCE = {
    "candidate_name": "direct_last_1.0",
    "candidate_selected_before_test": True,
    "candidate_seal_file_sha256": "81a14ed1a800047ec57e55ba43fbee308093390abb9a4baa733a65ba33b68f38",
    "candidate_seal_digest": "c245fefd0562b0a63b9899427bbd2da058939ddc1b8d888871db45bb21e935f1",
    "historical_result_file_sha256": "df5062792c7dfb4537c830271c8bdd178110e1c18c75ec1b2a566cd2aca390a2",
    "historical_result_digest": "f2796652234f0aa919aef0b900a6ca9628e99de100a7f2670cbdb41295bc09c1",
    "feature_manifest_file_sha256": "12b62bed64b33afc5138f788c7aa8685924cbdae81753346880e5cce5711c2e1",
    "feature_manifest_digest": "11061fc869b7ac7c72ab5153766b75be51661d5661313be3edfaeaf6fda969bc",
    "historical_quality_not_recomputed_here": True,
}
SCHEMA = "hepta.laya.native-exact-adapter-artifact.v1"
BUDGET = {"server_starts": 2, "rpc_wire_calls": 8, "tool_calls": 4,
          "roundtrip_wire_calls": 0, "roundtrip_new_intents": 0,
          "recover_wire_calls": 0, "crash_attempts": 0,
          "wall_seconds": 120, "server_cpu_seconds": 30,
          "server_address_space_bytes": 2 * 1024**3, "server_tokio_worker_threads": 2,
          "model_forwards": 0, "training_steps": 0, "maximum_changed_words": 671,
          "automatic_retry": False}
t.BUDGET = BUDGET


def directory(raw):
    require(len(raw) == 9572, "fixed actual adapter byte length differs")
    n = struct.unpack_from("<Q", raw)[0]
    require(0 < n <= 4096 and 8 + n < len(raw), "bounded safetensors header required")
    header = parse(raw[8:8+n])
    require(set(header) == set(SHAPES), "actual four-tensor adapter required")
    cursor = 0
    for name in SHAPES:
        row = header[name]
        count = math.prod(SHAPES[name])
        require(row == {"dtype": "F32", "shape": SHAPES[name],
                        "data_offsets": [cursor, cursor + count * 4]},
                "tensor shape, dtype or contiguous storage differs")
        values = struct.unpack_from("<" + "f" * count, raw, 8+n+cursor)
        require(all(math.isfinite(x) for x in values), "finite actual F32 tensors required")
        cursor += count * 4
    require(8+n+cursor == len(raw), "unaccounted safetensors payload")
    return header, 8+n


def compile_exact(parent, candidate, source_path):
    require(digest(parent) == PARENT and digest(candidate) == CANDIDATE,
            "previously sealed parent and candidate commitments required")
    header, payload = directory(parent)
    other, candidate_payload = directory(candidate)
    require(header == other and payload == candidate_payload,
            "candidate changes tensor storage or metadata")
    lo, hi = header[TENSOR]["data_offsets"]
    start, end = payload+lo, payload+hi
    require(parent[:start] == candidate[:start] and parent[end:] == candidate[end:],
            "candidate changes protected tensors, header or trailing bytes")
    edits = [{"index": i, "expected_hex": parent[start+i*4:start+i*4+4].hex(),
              "replacement_hex": candidate[start+i*4:start+i*4+4].hex()}
             for i in range(768)
             if parent[start+i*4:start+i*4+4] != candidate[start+i*4:start+i*4+4]]
    require(len(edits) == 671 <= 1024, "actual sealed candidate edit count differs")
    changed_bytes = sum(a != b for a, b in zip(parent, candidate))
    require(changed_bytes == 1843, "actual sealed candidate byte difference differs")
    request = {"path": str(source_path), "expected_sha256": PARENT,
               "tensor_name": TENSOR, "edits": edits}
    proof = {"schema": SCHEMA+".compile", "parent_sha256": PARENT,
             "candidate_sha256": CANDIDATE, "tensor_name": TENSOR,
             "tensor_shape": [1, 768], "dtype": "F32", "file_span": [start, end],
             "changed_f32_words": len(edits), "changed_bytes": changed_bytes,
             "all_other_bytes_equal": True, "header_bytes_equal": True,
             "other_three_tensor_bytes_equal": True, "B_is_multiplicative_not_bias": True,
             "float_arithmetic_or_rounding_used_for_edit": False,
             "candidate_selection_performed": False, "model_forwards": 0,
             "optimizer_steps": 0, "provenance": PROVENANCE}
    return request, proof


def source_check():
    require(digest(read(Path(m.__file__).resolve())) == MAIN_SHA,
            "reviewed source identity helper differs")
    require(digest(read(Path(t.__file__).resolve())) == m.TRANSPORT_SHA,
            "reviewed original HTTP transport differs")


def plan(args):
    source_check()
    root = Path(args.root)
    m.private_dir(root)
    require(not any(root.iterdir()), "fresh empty isolated qualification root required")
    ci = m.ci_check(Path(args.ci_receipt))
    identity = t.package_check(args.binary, args.package_manifest, m.SOURCE_COMMIT, m.SOURCE_TREE)
    parent, candidate = read(args.parent, 16384), read(args.candidate, 16384)
    request, proof = compile_exact(parent, candidate, root/"workspace/parent.safetensors")
    for name in ("workspace", "state", "credentials", "evidence"):
        (root/name).mkdir(mode=0o700)
    t.write_bytes_once(root/"workspace/parent.safetensors", parent)
    t.write_bytes_once(root/"workspace/expected_candidate.safetensors", candidate)
    for owner in ("a", "b"):
        t.write_bytes_once(root/"credentials"/("operator-"+owner+".token"),
                           secrets.token_hex(32).encode())
    policy = {"state_dir": str(root/"state"),
              "controller_workspace_roots": [str(root/"workspace")],
              "hosts": {"denied": {"ssh_target": "never-connect-laya-artifact-research",
                  "remote_state_dir": str(root/"no-remote"), "allow_execute": False,
                  "allow_pty": False, "allow_write": False, "allow_job_network": False}}}
    policy_sha = t.write_once(root/"policy.json", policy)
    sockets = [socket.socket() for _ in range(2)]
    try:
        for sock in sockets:
            sock.bind(("127.0.0.1", 0))
        ports = [sock.getsockname()[1] for sock in sockets]
    finally:
        for sock in sockets:
            sock.close()
    value = {"schema": SCHEMA, "root": str(root), "identity": identity, "ci": ci,
             "binary": str(Path(args.binary)), "package_manifest": str(Path(args.package_manifest)),
             "driver_sha256": digest(read(Path(__file__).resolve())),
             "transport_sha256": m.TRANSPORT_SHA, "helper_sha256": MAIN_SHA,
             "ports": ports, "policy_sha256": policy_sha, "budget": BUDGET,
             "request": request, "compilation": proof,
             "original_inputs": {"parent": str(Path(args.parent)), "candidate": str(Path(args.candidate))}}
    print(json.dumps({"plan": str(root/"plan.json"),
                      "sha256": t.write_once(root/"plan.json", value),
                      "model_forwards": 0, "training_steps": 0}))


def load_plan(path):
    source_check()
    raw = read(path, 256*1024, private=True)
    value = parse(raw)
    root = Path(value["root"])
    require(Path(path) == root/"plan.json" and value["schema"] == SCHEMA
            and value["budget"] == BUDGET, "fixed Laya artifact plan differs")
    require(value["driver_sha256"] == digest(read(Path(__file__).resolve()))
            and value["transport_sha256"] == m.TRANSPORT_SHA and value["helper_sha256"] == MAIN_SHA,
            "frozen qualification source differs")
    require(t.package_check(value["binary"], value["package_manifest"], m.SOURCE_COMMIT, m.SOURCE_TREE)
            == value["identity"] and m.ci_check(Path(value["ci"]["path"])) == value["ci"],
            "native qualified release or full CI differs")
    for name in ("", "workspace", "state", "credentials", "evidence"):
        m.private_dir(root/name)
    require(not any((root/"state").iterdir()), "native state must initially be empty")
    require(len(value["ports"]) == len(set(value["ports"])) == 2
            and all(type(p) is int and 1024 <= p <= 65535 for p in value["ports"]),
            "distinct loopback ports required")
    require(digest(read(root/"policy.json", private=True)) == value["policy_sha256"], "policy differs")
    parent = read(root/"workspace/parent.safetensors", 16384, private=True)
    candidate = read(root/"workspace/expected_candidate.safetensors", 16384, private=True)
    request, proof = compile_exact(parent, candidate, root/"workspace/parent.safetensors")
    require(request == value["request"] and proof == value["compilation"],
            "actual exact prior/replacement words or scope differ from plan")
    tokens = {k: read(root/"credentials"/("operator-"+k+".token"), private=True).decode("ascii")
              for k in ("a", "b")}
    require(tokens["a"] != tokens["b"] and all(len(x) == 64 and all(c in "0123456789abcdef" for c in x)
                                               for x in tokens.values()), "private credential shape")
    return raw, value, root, tokens, parent, candidate


def run(args):
    raw, value, root, tokens, parent, candidate = load_plan(Path(args.plan))
    rec = t.Recorder(root, value, tokens)
    status, failure, cleanup, servers, receipts = "FAIL_OR_INCOMPLETE", None, [], [], {}
    rec.record("run-intent.json", {"plan_sha256": digest(raw), "budget": BUDGET,
                                   "model_forwards": 0, "training_steps": 0})
    try:
        server = t.Server(rec, "patch-owner", "a", value["ports"][0])
        servers.append(server)
        client = t.Client(server, "main")
        first = client.call("weight_artifact_patch", value["request"])
        require(first["reused"] is False and first["behavior_evaluated"] is False
                and first["changed_bytes"] == 1843, "first native patch receipt differs")
        require(t.artifact(root, first, CANDIDATE) == candidate,
                "native candidate differs bytewise from previously sealed candidate")
        require(read(root/"workspace/parent.safetensors", private=True) == parent, "source was modified")
        before = m.effects(root)
        again = client.call("weight_artifact_patch", value["request"])
        require(again["artifact_id"] == first["artifact_id"] and again["reused"] is True
                and t.artifact(root, again, CANDIDATE) == candidate and m.effects(root) == before,
                "identical native patch did not reuse unchanged artifact state")
        receipts.update(first_patch=first, repeated_patch=again)
        server.stop()
        (root/"workspace/parent.safetensors").unlink()
        rec.record("source-deleted-before-cold-restore.json", {
            "owned_workspace_copy_only": True, "source_path": value["request"]["path"],
            "source_sha256": PARENT, "source_exists": False,
            "original_input_files_modified": False})
        cold = t.Server(rec, "cold-restore-owner", "a", value["ports"][1])
        servers.append(cold)
        client = t.Client(cold, "main")
        restored = client.call("weight_artifact_restore", {"artifact_id": first["artifact_id"]})
        require(restored["reused"] is False and restored["behavior_evaluated"] is False,
                "first inverse receipt differs")
        require(t.artifact(root, restored, PARENT, first["artifact_id"]) == parent,
                "native inverse did not recover every original byte")
        before = m.effects(root)
        repeated = client.call("weight_artifact_restore", {"artifact_id": first["artifact_id"]})
        require(repeated["artifact_id"] == restored["artifact_id"] and repeated["reused"] is True
                and t.artifact(root, repeated, PARENT, first["artifact_id"]) == parent
                and m.effects(root) == before, "identical cold inverse altered native state")
        require(not (root/"workspace/parent.safetensors").exists(), "restore recreated deleted workspace source")
        receipts.update(cold_restore=restored, repeated_cold_restore=repeated)
        require(rec.counts == {"server_starts": 2, "rpc_wire_calls": 8, "tool_calls": 4,
                "roundtrip_wire_calls": 0, "roundtrip_new_intents": 0,
                "recover_wire_calls": 0, "crash_attempts": 0}, "frozen operation count differs")
        status = "PASS"
    except BaseException as error:
        failure = {"type": type(error).__name__, "message": str(error)}
    finally:
        for server in reversed(servers):
            try:
                server.stop(kill=status != "PASS")
            except BaseException as error:
                cleanup.append({"server": server.label, "type": type(error).__name__, "message": str(error)})
        if status == "PASS" and not cleanup:
            try:
                rec.remaining_seconds()
            except BaseException as error:
                cleanup.append({"stage": "wall_acceptance", "type": type(error).__name__, "message": str(error)})
        if cleanup:
            status = "FAIL_OR_INCOMPLETE"
        result = {"schema": SCHEMA+".result", "status": status, "failure": failure,
                  "cleanup_errors": cleanup, "plan_sha256": digest(raw),
                  "identity": value["identity"], "compilation": value["compilation"],
                  "receipts": receipts, "counts": rec.counts, "budget": BUDGET,
                  "wall_seconds": time.monotonic()-rec.started,
                  "source_deleted_before_cold_restore": not (root/"workspace/parent.safetensors").exists(),
                  "model_forwards": 0, "optimizer_steps": 0, "new_quality_evaluation": False,
                  "full_encoder_native_execution": False, "production_deployment": False,
                  "candidate_selection_performed": False, "automatic_retry": False,
                  "function_graph_or_task_route_modified": False,
                  "scope": "Exact actual adapter byte lifecycle only; previous quality evidence is unchanged."}
        sha = rec.record("RESULT.json", result)
        print(json.dumps({"status": status, "result": str(rec.evidence_root/"RESULT.json"),
                          "sha256": sha, "failure": failure, "cleanup_errors": cleanup}))
    return 0 if status == "PASS" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    p = sub.add_parser("plan")
    for name in ("root", "binary", "package-manifest", "ci-receipt", "parent", "candidate"):
        p.add_argument("--"+name, required=True)
    p = sub.add_parser("run")
    p.add_argument("--plan", required=True)
    args = parser.parse_args()
    return plan(args) if args.action == "plan" else run(args)


if __name__ == "__main__":
    sys.exit(main())
