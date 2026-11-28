#!/usr/bin/env python3
"""One bounded engineering replay of a CI-qualified closed late-quote MCP profile.

The previously qualified HTTP transport is pinned independently. This driver never
modifies a live service or retries an uncertain effect under a replacement key.
The three model batches were already observed in scientific/CLI experiments.
"""

import argparse
import ctypes
import importlib.util
import json
import os
from pathlib import Path
import secrets
import select
import signal
import socket
import stat
import struct
import sys
import threading
import time

HERE = Path(__file__).resolve().parent
TRANSPORT_SHA = "8c2eb9a1405a2c4606a03800ada15de12bc8df70ea82a312b6b3a31e45d50391"
PROFILE = "smallhcsn_late_quote_min_mark4_task_route_v1"
import hashlib
transport = HERE / "transport_reference.py"
if hashlib.sha256(transport.read_bytes()).hexdigest() != TRANSPORT_SHA:
    raise ValueError("frozen transport source changed")
spec = importlib.util.spec_from_file_location("late_quote_transport", transport)
t = importlib.util.module_from_spec(spec)
spec.loader.exec_module(t)
require = t.require

BUDGET = {
    "server_starts": 4, "rpc_wire_calls": 50, "tool_calls": 32,
    "roundtrip_wire_calls": 10, "roundtrip_new_intents": 4,
    "recover_wire_calls": 6, "crash_attempts": 1,
    "complete_model_forward_upper_bound": 29,
    "pure_compiler_invocation_upper_bound": 8,
    "wall_seconds": 900, "server_cpu_seconds": 180,
    "server_address_space_bytes": 2 * 1024**3,
    "server_tokio_worker_threads": 2, "optimizer_steps": 0,
    "automatic_retry": False,
}
t.BUDGET = BUDGET


def file_pin(path):
    path = Path(path).resolve(strict=True)
    raw = t.read(path)
    return {"path": str(path), "bytes": len(raw), "sha256": t.digest(raw)}


def pinned(pin):
    raw = t.read(Path(pin["path"]))
    require(len(raw) == pin["bytes"] and t.digest(raw) == pin["sha256"], "pinned input changed")
    return raw


def case_from_cli(name, path, root):
    source = t.parse(t.read(path))
    require(source["schema"] == "hepta.late-quote-qualification.v1", "wrong existing CLI request")
    material = {}
    pins = {}
    for key in ("parent", "late_profile", "late_input", "retention_profile", "retention_input"):
        pin = file_pin(source[key]["path"])
        require(pin["sha256"] == source[key]["sha256"], "prior source pin changed")
        pins[key] = pin
        material[key] = pinned(pin)
    owned = root / "workspace" / (name + ".safetensors")
    t.write_bytes_once(owned, material["parent"])
    request = {
        "profile_json": material["late_profile"].decode(),
        "raw_input_hex": material["late_input"].hex(),
        "retention_profile_json": material["retention_profile"].decode(),
        "retention_raw_input_hex": material["retention_input"].hex(),
        "minimum_accuracy_percent": 95, "maximum_update_l2_norm": 1.0,
    }
    return {"name": name, "source_path": str(owned), "parent_sha256": t.digest(material["parent"]),
            "original_inputs": pins, "request": request, "already_observed_batch": True}


def plan(args):
    root = args.root.resolve(strict=True)
    require(args.root == root and stat.S_IMODE(root.stat().st_mode) == 0o700, "owned canonical 0700 root required")
    require(root.stat().st_uid == os.geteuid() and sys.platform == "linux", "Linux owned research root required")
    for path in (args.binary, args.package_manifest, args.ci_admission):
        require(path.is_absolute() and path.is_relative_to(root), "qualified release must be copied inside owned root")
    admission = t.parse(t.read(args.ci_admission))
    require(admission["schema"] == "hepta.late-quote.operator-ci-admission.v1", "missing verified CI admission")
    require(admission["exact_head_conclusion"] == "success" and admission["prospective_merge_conclusion"] == "success",
            "both original CI lanes must pass before this execution")
    identity = t.package_check(args.binary, args.package_manifest, admission["source_commit"], admission["source_tree"])
    require(identity["binary_sha256"] == admission["binary_sha256"]
            and identity["package_manifest_sha256"] == admission["package_manifest_sha256"]
            and str(identity["ci_run_id"]) == str(admission["ci_run_id"]), "CI package/admission mismatch")
    for name in ("workspace", "state", "credentials", "evidence"):
        (root / name).mkdir(mode=0o700)
    for owner in ("a", "b"):
        t.write_bytes_once(root / "credentials" / ("operator-" + owner + ".token"), secrets.token_hex(32).encode())
    policy = {"state_dir": str(root / "state"), "controller_workspace_roots": [str(root / "workspace")],
              "hosts": {"denied": {"ssh_target": "never-connect-late-quote-engineering-replay",
                  "remote_state_dir": str(root / "no-remote"), "allow_execute": False,
                  "allow_pty": False, "allow_write": False, "allow_job_network": False}}}
    policy_sha = t.write_once(root / "policy.json", policy)
    require(len(args.case) == 3, "exactly three already observed checkpoint cases required")
    cases = [case_from_cli("case-" + str(i + 1), path.resolve(strict=True), root) for i, path in enumerate(args.case)]
    crash = dict(cases[2])
    crash.update(name="same-sha-crash", source_path=str(root / "workspace" / "same-sha-crash.safetensors"))
    t.write_bytes_once(Path(crash["source_path"]), pinned(crash["original_inputs"]["parent"]))
    reservations = [socket.socket() for _ in range(4)]
    try:
        for sock in reservations:
            sock.bind(("127.0.0.1", 0))
        ports = [sock.getsockname()[1] for sock in reservations]
    finally:
        for sock in reservations:
            sock.close()
    value = {"schema": "hepta.late-quote.real-mcp-plan.v1", "root": str(root), "binary": str(args.binary),
             "package_manifest": str(args.package_manifest), "ci_admission": file_pin(args.ci_admission),
             "identity": identity, "driver": file_pin(Path(__file__)), "transport": file_pin(transport),
             "cases": cases, "crash_case": crash, "ports": ports, "policy_sha256": policy_sha,
             "budget": BUDGET, "prepared_without_native_execution": True,
             "engineering_replay_of_already_observed_batches": True, "scientific_holdout_claim": False,
             "crash_rule": "one wc1 publication observation; SIGSTOP only owned process group, prove candidate present and inverse absent, SIGKILL, cold original-plan recovery; missed boundary is recorded failure without a new key"}
    pin = t.write_once(root / "plan.json", value)
    print(json.dumps({"plan": str(root / "plan.json"), "sha256": pin, "native_execution_performed": False}))


def schema_refusal(raw, request_id):
    require(isinstance(raw, str) and len(raw.encode()) <= t.MAX_WIRE, "bounded schema-refusal response required")
    if raw.lstrip().startswith("{"):
        records = [t.parse(raw)]
    else:
        records, data = [], []
        for line in raw.replace("\r\n", "\n").replace("\r", "\n").split("\n") + [""]:
            if not line:
                if data:
                    payload = "\n".join(data)
                    if payload:
                        records.append(t.parse(payload))
                    data = []
            elif line == "data" or line.startswith("data:"):
                value = "" if line == "data" else line[5:]
                data.append(value[1:] if value.startswith(" ") else value)
    require(all(isinstance(record, dict) for record in records), "RPC refusal records must be objects")
    matches = [record for record in records if type(record.get("id")) is type(request_id) and record.get("id") == request_id]
    require(len(matches) == 1, "unique same-type schema-refusal request identity required")
    refusal = matches[0]
    error = refusal.get("error")
    require(refusal.get("jsonrpc") == "2.0" and "result" not in refusal
            and isinstance(error, dict) and type(error.get("code")) is int and error["code"] == -32602,
            "only exact JSON-RPC invalid-params is admitted for this schema negative control")
    return refusal


class Client(t.Client):
    def call(self, name, args, denied=False, invalid_schema=False):
        rec = self.server.recorder
        require(not invalid_schema or denied, "schema-refusal handling is restricted to the declared negative control")
        rec.reserve("tool_calls")
        if name == "rea_model_session_weight":
            kind = args["operation"]["kind"]
            if kind == "late_quote_roundtrip":
                rec.reserve("roundtrip_wire_calls")
            elif kind == "late_quote_recover":
                rec.reserve("recover_wire_calls")
        try:
            wire = self.rpc("tools/call", {"name": name, "arguments": args})
        except ValueError as error:
            if not invalid_schema or str(error) != "MCP protocol error":
                raise
            label = f"{self.server.label}-{self.label}-{self.request_id:03d}"
            original = t.parse(t.read(rec.evidence_root / (label + "-response.json"), private=True))
            require(original["status"] == 200 and t.digest(original["raw_utf8"].encode()) == original["raw_sha256"],
                    "original recorded schema-refusal wire identity differs")
            refusal = schema_refusal(original["raw_utf8"], self.request_id)
            rec.record(label + "-validated-schema-refusal.json", {"original_response_sha256": original["raw_sha256"],
                       "jsonrpc_error": refusal, "additional_rpc_sent": False})
            return refusal
        if denied:
            require(wire.get("isError") is True, "negative admission unexpectedly succeeded")
            return wire
        require(not wire.get("isError", False), "required MCP call was refused: " + str(wire))
        rows = [row["text"] for row in wire.get("content", []) if row.get("type") == "text"]
        require(len(rows) == 1, "one complete MCP text result required")
        value = t.parse(rows[0])
        require(wire.get("structuredContent") is None or wire["structuredContent"] == value, "wire representations differ")
        return value


def arguments(case, sid, kind, **fields):
    return {"session_id": sid, "parent_sha256": case["parent_sha256"], "profile": PROFILE,
            "operation": {"kind": kind, **fields}}


def outer(value):
    require(value["schema"] == "hepta.rea.session-late-quote-research.v1" and value["fixed_scope"] == PROFILE,
            "closed authority receipt differs")
    require(value["credential_metadata_resume"] is True and value["paths_derived_from_session"] is True,
            "actual credential/session scope missing")
    for key in ("accepted_for_activation", "production_eligible", "automatic_retry", "background_crash_recovery",
                "upstream_provenance_verified", "global_ndu_optimality_verified"):
        require(value[key] is False, "unsupported scope claim")
    return value["result"]


def effects(root):
    rows = {}
    for category in ("weight-artifacts-v1", "weight-cohort-journal-v1"):
        base = root / "state" / category
        if not base.exists():
            rows[category] = "absent"
            continue
        for path in sorted([base, *base.rglob("*")]):
            info = path.lstat()
            require(not stat.S_ISLNK(info.st_mode) and path.resolve(strict=True) == path, "effect path changed identity")
            require(info.st_uid == os.geteuid(), "unowned effect")
            row = {"inode": info.st_ino, "device": info.st_dev, "mode": stat.S_IMODE(info.st_mode),
                   "mtime_ns": info.st_mtime_ns, "ctime_ns": info.st_ctime_ns}
            if path.is_file():
                row["sha256"] = t.digest(t.read(path, 2 * 1024**2, private=True))
            else:
                row["children"] = sorted(p.name for p in path.iterdir())
            rows[str(path.relative_to(root / "state"))] = row
    require(len(rows) <= 4096, "bounded effect inventory")
    return rows


def prepare(client, case):
    rec = client.server.recorder
    opened = client.call("rea_model_session_open", {"path": case["source_path"], "expected_sha256": case["parent_sha256"]})
    sid = opened["session_id"]
    before = effects(rec.root)
    started = time.monotonic()
    ready = outer(client.call("rea_model_session_weight", arguments(case, sid, "late_quote_prepare", request=case["request"])))
    wall = time.monotonic() - started
    require(effects(rec.root) == before, "prepare wrote a weight effect")
    require(ready["model_forward_calls"] == 0 and ready["journal_written"] is False
            and ready["candidate_published"] is False and ready["compilation_label_reads"] == 0, "prepare boundary differs")
    require(ready["parent_function"]["artifact_sha256"] == case["parent_sha256"]
            and ready["keep_function"]["artifact_sha256"] == case["parent_sha256"], "KEEP weights differ from parent")
    require(ready["parent_function"] != ready["keep_function"], "graph-only function identity was collapsed")
    rec.record(case["name"] + "-preparation.json", {"session_id": sid, "result": ready, "observed_rpc_wall_seconds": wall,
               "compiler_invocations_this_prepare": 1, "model_forward_calls": 0})
    return {"session_id": sid, "prepared": ready, "prepare_rpc_wall_seconds": wall}


def verify_inverse(root, case, prepared, value):
    require(value["weights_graph_route_initial_state_and_evaluator_restored"] is True, "full inverse was not verified")
    receipt = value["restoration"]
    expected = root / "state" / "weight-artifacts-v1" / receipt["artifact_id"] / "model.safetensors"
    require(receipt["artifact_path"] == str(expected), "noncanonical inverse artifact")
    require(t.read(expected, private=True) == pinned(case["original_inputs"]["parent"]), "complete restored bytes differ")
    capsule = receipt["function_capsule"]
    function = capsule["function"]
    require(function == prepared["parent_function"] and capsule["parent_function"] == prepared["parent_function"]
            and capsule["normal_route_function"] == prepared["parent_function"],
            "complete original artifact/graph/route/state/evaluator function identity differs")
    require(function["graph"] == "original" and function["request_route"] == "original_fixed_profile"
            and function["initial_state_contract"] == "fixed_reset_step0_six_tick_v1", "inverse failed semantic identity")
    require(capsule["route_contract"]["late_request_graph"] == "original"
            and capsule["route_contract"]["late_request_requires_checked_task"] is False, "inverse retained bridge routing")
    require(receipt["artifact_id"] != value["candidate"]["artifact_id"], "candidate/inverse manifests collapsed")
    require(value["source_modified"] is False and value["shared_model_activated"] is False
            and value["optimizer_steps"] == 0 and value["global_ndu_optimality_verified"] is False, "unsupported mutation/quality claim")


def execute_case(client, case, opened):
    rec = client.server.recorder
    rec.reserve("roundtrip_new_intents")
    args = arguments(case, opened["session_id"], "late_quote_roundtrip", request=case["request"],
                     expected_journal_id=opened["prepared"]["journal_id"])
    started = time.monotonic()
    value = outer(client.call("rea_model_session_weight", args))
    wall = time.monotonic() - started
    verify_inverse(rec.root, case, opened["prepared"], value)
    require(value["research_roundtrip_verified"] is True and value["candidate_goal_met"] is True,
            "measured task-scoped graph failed its declared quality gates")
    require(value["unconditional_graph_accepted"] is False, "known negative control unexpectedly accepted")
    require(value["scoped_retention_uses_same_selected_weights"] is True
            and value["scoped_retention_requires_conditional_graph_routing"] is True, "retention identity misreported")
    cost = {"prepare_preflight_seconds": opened["prepared"]["source_admission_and_preparation_wall_seconds"],
            "roundtrip_preflight_seconds": value["original_preparation_wall_seconds"],
            "complete_prepare_and_roundtrip_rpc_wall_seconds": opened["prepare_rpc_wall_seconds"] + wall,
            "compiler_invocations_prepare_plus_first_roundtrip": 2,
            "completed_model_forward_calls": value["new_complete_forward_results_this_request"],
            "optimizer_steps": 0, "billing_cost_measured": False}
    cost["sum_of_both_preflight_seconds"] = cost["prepare_preflight_seconds"] + cost["roundtrip_preflight_seconds"]
    rec.record(case["name"] + "-completed.json", {"result": value, "cost": cost})
    before = effects(rec.root)
    repeats = []
    for number in (1, 2):
        repeated = outer(client.call("rea_model_session_weight", args))
        require(repeated["new_complete_forward_results_this_request"] == 0
                and repeated["pure_compiler_invocations_this_request"] == 0
                and repeated["reused_original_result"] is True, "same request replayed computation")
        require(repeated["restoration"]["artifact_id"] == value["restoration"]["artifact_id"], "same request republished inverse")
        require(effects(rec.root) == before, "same request rewrote durable weight state")
        repeats.append(repeated)
        rec.record(case["name"] + "-repeat-" + str(number) + ".json", repeated)
    return {"initial": value, "cost": cost, "repeats": repeats}


def recover_case(client, case, opened, expected_new=None):
    ready = opened["prepared"]
    value = outer(client.call("rea_model_session_weight", arguments(case, opened["session_id"], "late_quote_recover",
                 journal_id=ready["journal_id"], expected_plan_sha256=ready["plan_sha256"])))
    verify_inverse(client.server.recorder.root, case, ready, value)
    require(value["original_source_path_opened"] is False and value["pure_compiler_invocations_this_request"] == 0
            and value["selection_replayed_on_recovery"] is False and value["parent_or_candidate_forward_replayed"] is False,
            "recovery replayed a compiled phase or opened the original source")
    if expected_new is not None:
        require(value["new_complete_forward_results_this_request"] == expected_new, "recovery forward count differs")
    return value


class Watch(t.PublicationWatch):
    def next_expected(self, name, deadline):
        while time.monotonic() < deadline:
            ready, _, _ = select.select([self.fd], [], [], min(0.05, max(0.0, deadline - time.monotonic())))
            if not ready:
                continue
            raw = os.read(self.fd, 65536)
            at = 0
            while at + 16 <= len(raw):
                _, mask, _, length = struct.unpack_from("iIII", raw, at)
                found = raw[at + 16:at + 16 + length].split(b"\0", 1)[0].decode()
                at += 16 + length
                require(mask & 0x00004000 == 0, "inotify overflow")
                if mask & 0x80 and found == name:
                    return
        raise TimeoutError("candidate publication not observed; no replacement request")


def crash_once(server, client, case, opened):
    rec, root = server.recorder, server.recorder.root
    rec.reserve("crash_attempts")
    rec.reserve("roundtrip_new_intents")
    ready = opened["prepared"]
    require(ready["parent_function"]["artifact_sha256"] == ready["sign_function"]["artifact_sha256"],
            "this crash case must distinguish same-weight graph functions")
    store = root / "state" / "weight-artifacts-v1"
    watcher = Watch(store)
    outcome = {}
    def send():
        try:
            outcome["response"] = client.call("rea_model_session_weight", arguments(case, opened["session_id"],
                "late_quote_roundtrip", request=case["request"], expected_journal_id=ready["journal_id"]))
        except BaseException as error:
            outcome["transport_error"] = type(error).__name__
    thread = threading.Thread(target=send, daemon=True)
    thread.start()
    try:
        watcher.next_expected(ready["keep_artifact_id"], time.monotonic() + min(60, rec.remaining_seconds()))
        os.killpg(server.process.pid, signal.SIGSTOP)
        t.wait_for_owned_stop(server.process, time.monotonic() + 5)
        candidate = store / ready["keep_artifact_id"]
        manifest = t.parse(t.read(candidate / "manifest.json", private=True))
        require(manifest["target_sha256"] == case["parent_sha256"]
                and manifest["research_binding"]["function"] == ready["keep_function"], "observed function differs")
        require(t.read(candidate / "model.safetensors", private=True) == pinned(case["original_inputs"]["parent"]),
                "same-SHA crash candidate has different bytes")
        inverses = []
        for path in store.glob("wc1_*/manifest.json"):
            row = t.parse(t.read(path, private=True))
            if row.get("parent_artifact_id") == ready["keep_artifact_id"]:
                inverses.append(row["artifact_id"])
        original = root / "state" / "weight-cohort-journal-v1" / ready["journal_id"]
        saved = t.parse(t.read(original / "late-intent.json", private=True))
        decision = t.parse(t.read(original / "late-decision.json", private=True))
        require(saved["plan_sha256"] == ready["plan_sha256"] and decision["action"] == "keep"
                and decision["selected_artifact_id"] == ready["keep_artifact_id"], "original frozen decision differs")
        phase_records = {}
        for phase in ("parent", "candidate", "restored"):
            for kind in ("charge", "result"):
                name = "late-" + phase + "-" + kind + ".json"
                path = original / name
                phase_records[name] = t.digest(t.read(path, private=True)) if path.exists() else None
        evidence = {"schema": "hepta.late-quote.real-mcp-crash-boundary.v1", "candidate_artifact_id": ready["keep_artifact_id"],
                    "same_parent_weight_bytes": True, "different_function_identity": True,
                    "observed_inverse_artifacts_before_kill": inverses,
                    "candidate_outcome_already_present": (root / "state" / "weight-cohort-journal-v1" /
                        manifest["request"]["request_id"] / "outcome.json").exists(),
                    "original_plan_sha256": ready["plan_sha256"], "phase_records_before_kill": phase_records,
                    "owned_process_group_only": True, "synthetic_failpoint_used": False}
        rec.record("actual-crash-boundary.json", evidence)
        require(not inverses, "inverse already published; crash window missed, no automatic retry")
    finally:
        watcher.close()
        server.stop(kill=True)
        thread.join(timeout=15)
        require(not thread.is_alive(), "killed owned server left a pending HTTP call")
        rec.record("actual-crash-wire-outcome.json", outcome)
    require(server.process.returncode == -signal.SIGKILL, "owned server was not actually hard-killed")
    Path(case["source_path"]).unlink()
    return evidence


def run(args):
    raw = t.read(args.plan)
    require(t.digest(raw) == args.plan_sha256, "prepared execution plan changed")
    value = t.parse(raw)
    require(value["schema"] == "hepta.late-quote.real-mcp-plan.v1" and value["budget"] == BUDGET, "wrong plan/budget")
    pinned(value["driver"]); pinned(value["transport"]); pinned(value["ci_admission"])
    root = Path(value["root"])
    require(args.plan.parent == root and root.is_absolute() and root.resolve(strict=True) == root,
            "execution plan must remain in its canonical owned root")
    for directory in (root, *(root / name for name in ("workspace", "state", "credentials", "evidence"))):
        info = directory.lstat()
        require(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode)
                and directory.resolve(strict=True) == directory
                and stat.S_IMODE(info.st_mode) == 0o700 and info.st_uid == os.geteuid(),
                "private canonical owned directories are required at execution time")
    require(not any((root / "state").iterdir()) and not any((root / "evidence").iterdir()),
            "execution state/evidence must be untouched; an uncertain run cannot restart")
    require(len(value["ports"]) == 4 and len(set(value["ports"])) == 4
            and all(type(port) is int and 1024 <= port <= 65535 for port in value["ports"]),
            "distinct bounded loopback ports required")
    require(t.digest(t.read(root / "policy.json")) == value["policy_sha256"], "owned policy changed")
    identity = t.package_check(Path(value["binary"]), Path(value["package_manifest"]),
                              value["identity"]["source_commit"], value["identity"]["source_tree"])
    require(identity == value["identity"], "actual qualified executable changed")
    for case in [*value["cases"], value["crash_case"]]:
        for pin in case["original_inputs"].values():
            pinned(pin)
        require(t.digest(t.read(Path(case["source_path"]), private=True)) == case["parent_sha256"], "source copy differs")
    tokens = {owner: t.read(root / "credentials" / ("operator-" + owner + ".token"), private=True).decode()
              for owner in ("a", "b")}
    require(tokens["a"] != tokens["b"] and all(len(token) == 64 and all(c in "0123456789abcdef" for c in token)
                                               for token in tokens.values()), "distinct fixed-shape private owner tokens required")
    rec = t.Recorder(root, value, tokens)
    rec.record("execution-intent.json", {"plan_sha256": args.plan_sha256, "binary_sha256": identity["binary_sha256"],
               "budget": BUDGET, "automatic_retry": False, "scientific_holdout_claim": False})
    servers, opened, completed = [], [], []
    failure = None
    result = {"status": "INCOMPLETE", "engineering_replay_of_already_observed_batches": True,
              "ci_identity": identity, "budget": BUDGET, "source_provenance_independently_verified": False}
    def server(label, owner, index):
        item = t.Server(rec, label, owner, value["ports"][index]); servers.append(item)
        return item, Client(item, "client")
    try:
        first, client = server("initial", "a", 0)
        for case in value["cases"]:
            opened.append(prepare(client, case))
            completed.append(execute_case(client, case, opened[-1]))
        before = effects(root)
        wrong = arguments(value["cases"][0], opened[0]["session_id"], "late_quote_prepare", request=value["cases"][0]["request"])
        wrong["parent_sha256"] = ("0" if wrong["parent_sha256"][0] != "0" else "1") + wrong["parent_sha256"][1:]
        client.call("rea_model_session_weight", wrong, denied=True)
        wrong["parent_sha256"] = value["cases"][0]["parent_sha256"]
        wrong["profile"] = "smallhcsn_centered_sender_drive_and_bias40_v1"
        client.call("rea_model_session_weight", wrong, denied=True, invalid_schema=True)
        require(effects(root) == before, "denied parent/profile changed durable effects")
        first.stop()
        other, other_client = server("other-owner", "b", 1)
        other_client.call("rea_model_session_weight", arguments(value["cases"][0], opened[0]["session_id"],
                          "late_quote_prepare", request=value["cases"][0]["request"]), denied=True)
        require(effects(root) == before, "other-owner refusal changed durable weight state")
        other.stop()
        for case in value["cases"]:
            Path(case["source_path"]).unlink()
        cold, cold_client = server("cold-recovery", "a", 2)
        for case, admission in zip(value["cases"], opened):
            before = effects(root)
            recovered = recover_case(cold_client, case, admission, 0)
            require(effects(root) == before, "completed cold recovery rewrote original effects")
            rec.record(case["name"] + "-cold-recovery.json", recovered)
        crash = value["crash_case"]
        crash_ready = prepare(cold_client, crash)
        crash_boundary = crash_once(cold, cold_client, crash, crash_ready)
        last, last_client = server("post-kill-recovery", "a", 3)
        recovered = recover_case(last_client, crash, crash_ready, 2)
        require(recovered["reused_original_result"] is False, "crash case was already complete before kill")
        rec.record("crash-first-recovery.json", recovered)
        original = root / "state" / "weight-cohort-journal-v1" / crash_ready["prepared"]["journal_id"]
        for name, before_sha in crash_boundary["phase_records_before_kill"].items():
            if name.startswith("late-restored-"):
                continue
            path = original / name
            after_sha = t.digest(t.read(path, private=True)) if path.exists() else None
            require(after_sha == before_sha, "cold recovery replayed or rewrote a parent/candidate phase")
        before = effects(root)
        repeated = recover_case(last_client, crash, crash_ready, 0)
        require(effects(root) == before, "repeat cold crash recovery rewrote or republished effects")
        rec.record("crash-second-recovery.json", repeated)
        total = sum(row["initial"]["attempt_ledger"]["completed_forward_calls_with_durable_results"] for row in completed)
        total += recovered["attempt_ledger"]["completed_forward_calls_with_durable_results"]
        require(total <= BUDGET["complete_model_forward_upper_bound"], "full-model call cap exceeded")
        result.update(status="PASS", cases=completed, crash_recovery=recovered,
                      complete_forward_results_observed=total, optimizer_steps=0,
                      observed_forward_count_is_durable_results_only=True,
                      charged_partial_forward_work_may_be_unobserved=recovered["attempt_ledger"]["unobserved_partial_work_possible"],
                      source_bound_complete_and_partial_forward_upper_bound=BUDGET["complete_model_forward_upper_bound"],
                      native_services_started=rec.counts["server_starts"], actual_sigkill_count=1,
                      full_function_inverse_verified=True, same_key_replay_additional_forwards=0,
                      recovery_requires_explicit_caller=True, live_service_or_model_activated=False,
                      scoped_retention_is_conditional_graph_routing=True, global_ndu_optimality_verified=False)
    except BaseException as error:
        failure = error
        result.update(status="FAIL_OR_INCOMPLETE", error_type=type(error).__name__, message=str(error),
                      completed_cases=completed, automatic_retry=False)
    finally:
        cleanup_errors = []
        for item in reversed(servers):
            try:
                item.stop(kill=result["status"] != "PASS")
            except BaseException as error:
                cleanup_errors.append({"server": item.label, "stage": "stop", "error": type(error).__name__, "message": str(error)})
        shutdowns = []
        for item in servers:
            try:
                shutdowns.append(t.parse(t.read(rec.evidence_root / (item.label + "-shutdown.json"))))
            except BaseException as error:
                cleanup_errors.append({"server": item.label, "stage": "shutdown_receipt", "error": type(error).__name__, "message": str(error)})
        result["observed_owned_process_sigkill_count"] = sum(row["signals_sent"].count("SIGKILL") for row in shutdowns)
        result["owned_shutdown_receipts_complete"] = len(shutdowns) == len(servers)
        if result["status"] == "PASS" and result["observed_owned_process_sigkill_count"] != 1:
            cleanup_errors.append({"stage": "signals", "message": "successful qualification requires exactly one observed SIGKILL"})
        if cleanup_errors:
            result.update(status="FAIL_OR_INCOMPLETE", cleanup_errors=cleanup_errors)
        result.update(actual_request_counts=rec.counts, observed_total_wall_seconds=time.monotonic() - rec.started)
        rec.record("RESULT.json", result)
    if failure is not None:
        raise failure
    require(result["status"] == "PASS", "owned-process cleanup did not qualify")
    print(json.dumps({"status": result["status"], "result": str(rec.evidence_root / "RESULT.json"),
                      "model_forward_results": result["complete_forward_results_observed"], "optimizer_steps": 0}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    p = commands.add_parser("plan")
    p.add_argument("--root", type=Path, required=True)
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--package-manifest", type=Path, required=True)
    p.add_argument("--ci-admission", type=Path, required=True)
    p.add_argument("--case", type=Path, action="append", required=True)
    p.set_defaults(function=plan)
    p = commands.add_parser("run")
    p.add_argument("--plan", type=Path, required=True)
    p.add_argument("--plan-sha256", required=True)
    p.set_defaults(function=run)
    args = parser.parse_args()
    args.function(args)


if __name__ == "__main__":
    main()
