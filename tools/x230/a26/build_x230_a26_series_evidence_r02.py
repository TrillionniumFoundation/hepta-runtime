#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Publish an A26 series from frozen artifacts, without running a workload.

Complete parsed reports, receipts, input manifests and every recorded failure
are retained. Structural completeness, comparison validity and candidate
validation have separate verdicts. Driver slots never imply binary versions.
Outputs are create-only; inputs are opened read-only and checked for changes.
"""

import argparse
from collections import Counter
from functools import lru_cache
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import sys

import build_x230_evidence as common
import build_x230_six_running_evidence as six_running


SERIES_SCHEMA = "hepta-x230-a26-series-execution/v1"
PLAN_SCHEMA = "hepta-x230-a26-series-plan/v1"
HEX256 = re.compile(r"[0-9a-f]{64}\Z")
SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*\Z")
HOSTS = ("ai395", "mac", "main", "pocket4", "rog", "x230")
QUAL_STAGES = ["format", "fmt-check", "clippy", "test", "release"]
JSON_LIMIT = 128 * 1024 * 1024
LOG_LIMIT = 64 * 1024 * 1024
STAGE_IDS = ["standard_compare", "standard_candidate", "capacity_compare", "capacity_candidate",
             "fairness_compare", "fairness_candidate", "calibration", "soak", "completed_recovery",
             "single_running", "six_running"]
COVERAGE = ["C1", "C4", "C8", "C16", "fairness", "calibration", "soak", "completed_recovery", "single_running", "six_running"]
HELPER_NAMES = {"x230_observation_benchmark.py", "x230_observation_fairness.py", "x230_observation_soak.py",
                "x230_observation_soak_resources_20261024.py", "x230_controller_recovery_check.py",
                "x230_native_lifecycle_canary.py", "x230_six_running_recovery_canary.py"}
PROOF_PREFIX = b"HEPTA_X230_SPAWN_PROOF_FAILURE_JSON "
canonical, sha = common.canonical, common.sha


def mapping(value):
    return value if isinstance(value, dict) else {}


def sequence(value):
    return value if isinstance(value, list) else []


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key; refusing lossy publication")
        result[key] = value
    return result


def reject_constant(_value):
    raise ValueError("non-finite JSON number")


def decode(raw):
    return json.loads(raw, object_pairs_hook=unique, parse_constant=reject_constant)


def fingerprint(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_size,
            value.st_mtime_ns, value.st_ctime_ns)


def read_file(path, limit=JSON_LIMIT):
    """Hash every byte, bound retained bytes, refuse links and changing files."""
    path = path.absolute()
    if path != path.resolve():
        raise ValueError("symlink or indirect input path refused")
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    hashed, content, size = hashlib.sha256(), bytearray(), 0
    with os.fdopen(descriptor, "rb") as source:
        before = os.fstat(source.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("nonregular input refused")
        while True:
            block = source.read(65536)
            if not block:
                break
            hashed.update(block)
            size += len(block)
            if len(content) < limit:
                content.extend(block[:limit - len(content)])
        after = os.fstat(source.fileno())
    if (fingerprint(before) != fingerprint(after)
            or fingerprint(after) != fingerprint(path.lstat()) or size != before.st_size):
        raise ValueError("input changed during complete read")
    return {"present": True, "bytes": size, "sha256": hashed.hexdigest(),
            "retention_limit_exceeded": size > limit}, bytes(content)


class Inputs:
    def __init__(self):
        self.files = {}
        self.errors = []

    def read(self, path, label, limit=JSON_LIMIT, parse=True, required=True):
        if label in self.files:
            raise ValueError("duplicate evidence input label")
        try:
            receipt, raw = read_file(path, limit)
            self.files[label] = receipt
            if receipt["retention_limit_exceeded"]:
                raise ValueError("input exceeds bounded parsing limit; full hash retained")
            value = decode(raw) if parse else raw
            self.files[label]["parsed"] = parse
            return value
        except (OSError, ValueError, UnicodeError) as error:
            present = not isinstance(error, FileNotFoundError)
            item = self.files.setdefault(label, {"present": present})
            item["read_error"] = {"type": type(error).__name__,
                                  "errno": getattr(error, "errno", None), "message": str(error)}
            if present or required:
                self.errors.append({"input": label, **item["read_error"]})
            return None

    def hash_only(self, path, label):
        if label in self.files:
            raise ValueError("duplicate evidence input label")
        try:
            receipt, _raw = read_file(path, 0)
            receipt.pop("retention_limit_exceeded")
            self.files[label] = {**receipt, "content_retained": False, "content_policy": "opaque hash receipt only"}
        except (OSError, ValueError) as error:
            self.files[label] = {"present": not isinstance(error, FileNotFoundError),
                "read_error": {"type": type(error).__name__, "errno": getattr(error, "errno", None), "message": str(error)}}
            self.errors.append({"input": label, **self.files[label]["read_error"]})
        return self.files[label]


class CompleteSanitizer(common.Sanitizer):
    """Preserve every key/row; private values become hash receipts in place."""
    private_keys = common.Sanitizer.identity_keys | common.Sanitizer.secret_keys | {
        "ppid", "owner_pid", "controller_pid", "birth", "start_ticks", "agent_identity",
        "process_identity", "agent_socket_identity", "uid", "gid", "dev", "ino",
        "hostname", "fixture_identity", "launch_nonce", "nonce", "idempotency_key",
        "held_agent_socket_identity", "socket_identity", "peer"}
    opaque_keys = {"base64", "bytes_hex", "b64", "stdin_base64", "stdout_base64", "stderr_base64",
                   "argv", "args", "arguments", "command", "raw_argv", "argv_bytes",
                   "payload", "raw", "raw_payload", "raw_request", "raw_response",
                   "content", "text", "env", "environment", "environment_variables",
                   "secret", "secrets", "credential", "credentials"}
    encoded_token = re.compile(r"(?<![A-Za-z0-9+/_=-])[A-Za-z0-9+/_-]{80,}={0,2}(?![A-Za-z0-9+/_=-])")
    embedded_command = re.compile(r"(?i)(?:\bcommand\s+['\"]?\[|\b(?:argv|args|arguments|command)['\"]?\s*[:=]\s*\[|\b(?:stdin_base64|stdout_base64|stderr_base64|bytes_hex|payload)['\"]?\s*[:=])")

    def __init__(self, value):
        super().__init__(value)
        self.pids, self.private_values = set(), set()

        def visit(item):
            if isinstance(item, dict):
                for key, value in item.items():
                    lowered = key.lower()
                    if lowered in self.private_keys:
                        if "pid" in lowered and (type(value) is int or isinstance(value, str) and value.isdigit()):
                            self.pids.add(str(value))
                        elif isinstance(value, str) and len(value) >= 6 and value not in HOSTS:
                            self.private_values.add(value)
                    visit(value)
            elif isinstance(item, list):
                for value in item:
                    visit(value)
        visit(value)
        # Rules are fixed after discovery. Preserve the original sequential
        # replacement order while avoiding sorting, compilation and marker
        # hashing again for every key and string leaf.
        self._pid_rules = tuple(re.compile(r"(?<![A-Za-z0-9_])" + re.escape(pid)
            + r"(?![A-Za-z0-9_])") for pid in sorted(self.pids, key=len, reverse=True))
        self._private_rules = tuple((private, "<private-identity:" + sha(private.encode())[:12] + ">")
            for private in sorted(self.private_values, key=len, reverse=True))
        # Repeated metadata keys/values share pure string results only. The
        # bounded cache neither removes records nor retains very large strings.
        self._short_strings = lru_cache(maxsize=8192)(self._string_uncached)

    @staticmethod
    def opaque_receipt(value):
        raw = canonical(value)
        result = {"redacted": True, "canonical_value_sha256": sha(raw),
                  "canonical_value_bytes": len(raw), "decoded_for_publication": False}
        if isinstance(value, str):
            result.update(encoded_characters=len(value), encoded_utf8_sha256=sha(value.encode()))
        return result

    def string(self, value):
        if HEX256.fullmatch(value):
            return value
        if len(value) <= 512:
            return self._short_strings(value)
        return self._string_uncached(value)

    def _string_uncached(self, value):
        if HEX256.fullmatch(value):
            return value
        if self.embedded_command.search(value):
            return "<opaque-command-bearing-text:" + sha(value.encode()) + ">"
        value = super().string(value)
        value = re.sub(r"(report-final-)[0-9]+(?=-)", r"\1<pid>", value)
        value = re.sub(r'(?i)(\b(?:pid|ppid|child_pid|owner_pid|controller_pid)["\s:=]+)[0-9]+',
                       lambda found: found[1] + "<pid>", value)
        for rule in self._pid_rules:
            value = rule.sub("<pid>", value)
        for private, replacement in self._private_rules:
            value = value.replace(private, replacement)
        return self.encoded_token.sub(lambda found: "<opaque-encoded:" + sha(found[0].encode()) + ">", value)

    def __call__(self, value):
        if isinstance(value, list):
            return [self(item) for item in value]
        if isinstance(value, dict):
            result = {}
            for key, item in value.items():
                public_key = self.string(key)
                if public_key in result:
                    raise ValueError("sanitized key collision; refusing lossy publication")
                lowered = key.lower()
                if (lowered in self.private_keys or lowered in self.opaque_keys
                        or "base64" in lowered or lowered.endswith("_hex")):
                    result[public_key] = self.opaque_receipt(item)
                else:
                    result[public_key] = self(item)
            return result
        return self.string(value) if isinstance(value, str) else value


def receipt_matches(actual, declared):
    return (mapping(actual).get("present") is True
            and type(mapping(declared).get("bytes")) is int
            and isinstance(mapping(declared).get("sha256"), str)
            and all(actual.get(key) == declared.get(key) for key in ("bytes", "sha256")))


def digest_matches(actual, digest):
    return (mapping(actual).get("present") is True and isinstance(digest, str)
            and HEX256.fullmatch(digest) is not None and actual.get("sha256") == digest)


def valid_source_map(value):
    return (isinstance(value, dict) and bool(value)
            and all(isinstance(key, str) and key and not Path(key).is_absolute()
                    and ".." not in Path(key).parts and isinstance(digest, str)
                    and HEX256.fullmatch(digest) for key, digest in value.items()))


def source_map_digest(value):
    return (sha(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())
            if valid_source_map(value) else None)


def counts(rows):
    return {"recorded_rows": len(rows), "successes": sum(mapping(row).get("okay") is True for row in rows),
            "failures": sum(mapping(row).get("okay") is False for row in rows),
            "unknown_outcomes": sum(type(mapping(row).get("okay")) is not bool for row in rows)}


def inventory(value):
    """Count recorded objects, not unique RPCs; repeated report copies stay copies."""
    outcomes, errors = [], []

    def visit(item, pointer):
        if isinstance(item, dict):
            if "okay" in item:
                outcomes.append({"json_pointer": pointer, "row": item})
            for key, child in item.items():
                escaped = key.replace("~", "~0").replace("/", "~1")
                child_pointer = pointer + "/" + escaped
                if (key == "error" or key.endswith("_error") or key == "errors") and child not in (None, [], {}):
                    errors.append({"json_pointer": child_pointer, "value": child})
                visit(child, child_pointer)
        elif isinstance(item, list):
            for index, child in enumerate(item):
                visit(child, pointer + "/" + str(index))
    visit(value, "")
    return {"recorded_outcome_objects": counts([row["row"] for row in outcomes]),
            "all_failure_or_unknown_outcome_objects": [row for row in outcomes if row["row"].get("okay") is not True],
            "recorded_error_objects": len(errors), "all_error_objects": errors,
            "counts_are_report_objects_not_unique_rpc_count": True}


def outcome_rows(report, fairness=False):
    rounds = sequence(report.get("rounds"))
    if fairness:
        timed = [row for rnd in rounds for cell in sequence(mapping(rnd).get("cells"))
                 for wave in sequence(mapping(cell).get("waves")) for row in sequence(mapping(wave).get("rows"))]
        metadata = [row for rnd in rounds for row in sequence(mapping(rnd).get("metadata_observations"))]
        metadata += [row for rnd in rounds for cell in sequence(mapping(rnd).get("cells"))
                     for wave in sequence(mapping(cell).get("waves"))
                     for row in sequence(mapping(wave).get("metadata_observations"))]
    else:
        timed = [row for rnd in rounds for cell in sequence(mapping(rnd).get("cells"))
                 for row in sequence(mapping(cell).get("rows"))]
        metadata = []
    initial = [row for rnd in rounds for row in sequence(mapping(rnd).get("initial_complete_outputs"))]
    final_key = "final_complete_outputs" if fairness else "restart_checks"
    final = [row for rnd in rounds for row in sequence(mapping(rnd).get(final_key))]
    return {"timed": timed, "initial_output_checks": initial, final_key: final,
            "metadata_observations": metadata}


def rows_passed(value, length=None):
    return (isinstance(value, list) and bool(value) and (length is None or len(value) == length)
            and all(isinstance(row, dict) and row.get("okay") is True for row in value))


def observation_summary(report, spec, candidate_sha, baseline_sha):
    fairness = spec.get("kind") == "fairness"
    rounds, order = sequence(report.get("rounds")), spec.get("order", "")
    roles = mapping(spec.get("role_by_slot"))
    binaries = {slot: candidate_sha if role == "A26" else baseline_sha for slot, role in roles.items()}
    schema = "hepta-x230-readonly-observation-" + ("fairness" if fairness else "abba") + "/v1"
    shared = {
        "schema": report.get("schema") == schema,
        "order_and_slot_binary_identities": report.get("order") == order and report.get("binary_sha256") == binaries,
        "two_workers_and_no_effects_or_retries": report.get("tokio_workers") == 2 and all(report.get(key) == 0
            for key in ("effect_starts", "remote_mutation_tool_calls", "automatic_rpc_retries")),
        "source_originals_and_binaries_unchanged": all(report.get(key) is True
            for key in ("source_originals_unchanged", "binary_hashes_unchanged")),
        "recorded_rounds_form_requested_prefix": bool(rounds) and len(rounds) <= len(order)
            and [mapping(rnd).get("version") for rnd in rounds] == list(order[:len(rounds)])
            and [mapping(rnd).get("index") for rnd in rounds] == list(range(len(rounds))),
    }
    if fairness:
        shared["fairness_dimensions_and_integrity"] = (report.get("waves_per_cell") == 8
            and report.get("calls_per_wave") == 10 and report.get("wave_retry_count") == 0
            and all(report.get(key) is True for key in ("private_originals_unchanged", "current_agent_unchanged")))
    else:
        shared["observation_dimensions"] = (report.get("calls_per_cell") == spec.get("calls")
            and report.get("concurrency") == spec.get("concurrency"))
    details, slot_metrics = [], {}
    for index, raw in enumerate(rounds):
        rnd, structural = mapping(raw), []
        cells = sequence(rnd.get("cells"))
        if fairness:
            structural += [len(cells) == 3 and {mapping(cell).get("name") for cell in cells}
                           == {"balanced", "hot_only", "skew"}]
            for cell_raw in cells:
                cell = mapping(cell_raw)
                waves = sequence(cell.get("waves"))
                structural += [cell.get("requested_waves") == 8 and len(waves) == 8]
                structural += [isinstance(mapping(wave).get("rows"), list) and len(wave["rows"]) == 10
                               and isinstance(mapping(wave).get("metadata_observations"), list)
                               and bool(wave["metadata_observations"]) for wave in waves]
            structural += [isinstance(rnd.get("metadata_observations"), list)
                           and len(rnd["metadata_observations"]) == 1]
            final_key, final_count, shutdown_keys = "final_complete_outputs", 6, ("shutdown",)
        else:
            structural += [[mapping(cell).get("concurrency") for cell in cells] == spec.get("concurrency")]
            for cell_raw in cells:
                cell = mapping(cell_raw)
                rows = sequence(cell.get("rows"))
                structural += [isinstance(cell.get("rows"), list) and len(rows) == cell.get("calls") == spec.get("calls"),
                               sum(mapping(row).get("okay") is True for row in rows) == cell.get("successes")]
            final_key, final_count, shutdown_keys = "restart_checks", 12, ("shutdown", "restart_shutdown")
        structural += [isinstance(rnd.get("initial_complete_outputs"), list) and len(rnd["initial_complete_outputs"]) == 6,
                       isinstance(rnd.get(final_key), list) and len(rnd[final_key]) == final_count,
                       isinstance(rnd.get("startup"), dict)]
        if not fairness:
            structural.append(isinstance(rnd.get("restart_startup"), dict))
        structural += [isinstance(rnd.get(key), dict) for key in shutdown_keys]
        groups = outcome_rows({"rounds": [rnd]}, fairness)
        calls_pass = all(rows_passed(rows) for rows in groups.values() if rows) and bool(groups["timed"])
        if fairness:
            gates_pass = all(mapping(cell).get("passed") is True
                and mapping(cell).get("gate_failures") == 0 and mapping(cell).get("metadata_failures") == 0
                and all(mapping(wave).get("tail_calls_submitted") == 2
                    and all(mapping(wave).get(key) is True for key in
                            ("passed", "gate_passed", "final_metadata_consistent", "all_final_metadata_completed"))
                    for wave in sequence(mapping(cell).get("waves"))) for cell in cells)
        else:
            gates_pass = all(mapping(cell).get("no_success_filtering") is True
                and common.numeric(mapping(cell).get("seconds")) and cell["seconds"] > 0 for cell in cells)
        details.append({"index": rnd.get("index"), "slot": rnd.get("version"),
            "runtime_role": roles.get(rnd.get("version")), "structural_complete": all(structural),
            "raw_round_passed": rnd.get("passed"), "call_groups": {key: counts(rows) for key, rows in groups.items()},
            "all_recorded_calls_passed": calls_pass,
            "clean_orderly_shutdowns": all(common.normal_shutdown(rnd.get(key)) is True for key in shutdown_keys),
            "round_scope_passed": all(structural) and calls_pass and gates_pass and rnd.get("passed") is True
                and all(common.normal_shutdown(rnd.get(key)) is True for key in shutdown_keys)})
    for slot, role in roles.items():
        own = [mapping(rnd) for rnd in rounds if mapping(rnd).get("version") == slot]
        cells = [mapping(cell) for rnd in own for cell in sequence(rnd.get("cells"))]
        own_details = [row for row in details if row["slot"] == slot]
        statistics = {}
        if fairness:
            for name in ("balanced", "hot_only", "skew"):
                chosen = [cell for cell in cells if cell.get("name") == name]
                converted = [{**cell, "rows": [row for wave in sequence(cell.get("waves"))
                    for row in sequence(mapping(wave).get("rows"))]} for cell in chosen]
                statistics[name] = common.aggregate(converted, lambda value: value)
        else:
            for concurrency in sequence(spec.get("concurrency")):
                statistics[str(concurrency)] = common.aggregate(
                    [cell for cell in cells if cell.get("concurrency") == concurrency], lambda value: value)
        slot_metrics[slot] = {"runtime_role": role, "binary_sha256": binaries.get(slot),
            "requested_rounds": order.count(slot), "recorded_rounds": len(own),
            "structural_complete": bool(own_details) and len(own) == order.count(slot)
                and all(row["structural_complete"] for row in own_details),
            "scope_passed": bool(own_details) and len(own) == order.count(slot)
                and all(row["round_scope_passed"] for row in own_details) and all(shared.values()),
            "metrics": statistics, "resources": common.sampling_summary(
                [mapping(rnd.get(key)).get("resources") for rnd in own
                 for key in ("shutdown", "restart_shutdown") if isinstance(rnd.get(key), dict)], lambda value: value)}
    candidate_slots = [slot for slot in roles if roles[slot] == "A26" and slot in order]
    groups = outcome_rows(report, fairness)
    shutdowns = [rnd[key] for rnd in map(mapping, rounds) for key in ("shutdown", "restart_shutdown")
                 if isinstance(rnd.get(key), dict)]
    if isinstance(report.get("interrupted_shutdown"), dict):
        shutdowns.append(report["interrupted_shutdown"])
    return {"kind": "fairness" if fairness else "observation", "shared_scope_checks": shared,
        "structural_complete": len(rounds) == len(order) and bool(details)
            and all(row["structural_complete"] for row in details),
        "candidate_structural_complete": bool(candidate_slots)
            and all(slot_metrics[slot]["structural_complete"] for slot in candidate_slots),
        "candidate_scope_passed": bool(candidate_slots) and all(slot_metrics[slot]["scope_passed"] for slot in candidate_slots),
        "candidate_not_exercised": not any(row["runtime_role"] == "A26" for row in details),
        "slot_results": slot_metrics, "rounds": details,
        "call_groups": {key: counts(rows) for key, rows in groups.items()},
        "all_failure_rows": {key: [row for row in rows if mapping(row).get("okay") is not True] for key, rows in groups.items()},
        "shutdown_receipt_count": len(shutdowns),
        "clean_orderly_eof_shutdown_count": sum(common.normal_shutdown(row) is True for row in shutdowns),
        "same_binary_slots": len(set(binaries.values())) == 1,
        "performance_comparison_generated": False, "raw_passed": report.get("passed")}


def recovery_summary(report, spec, candidate_sha):
    kind = spec.get("kind")
    shared = {"raw_passed": report.get("passed") is True,
              "no_rpc_retries": report.get("automatic_rpc_retries") == 0}
    if kind == "completed_recovery":
        details = common.summarize_recovery(report, lambda value: value)
        required = ("before_checks", "after_checks", "recovery_shutdown", "descendant_observation",
                    "metadata_before_death", "metadata_after_death", "metadata_after_recovery", "metadata_final",
                    "socket_artifacts_before_death", "old_socket_artifacts_after_death", "old_socket_artifacts_after_recovery",
                    "initial_startup", "recovery_startup")
        shared.update(schema=report.get("schema") == "hepta-x230-controller-abrupt-readonly-recovery/v1",
            binary=report.get("binary_sha256") == candidate_sha and report.get("binary_hash_unchanged") is True,
            complete_calls=rows_passed(report.get("before_checks"), 12) and rows_passed(report.get("after_checks"), 12),
            read_only_same_job_recovery=report.get("read_only_recovery_passed") is True,
            observed_descendants_exited=mapping(report.get("descendant_observation")).get("all_sampled_descendants_exited") is True,
            own_controller_sigkill=report.get("controller_death_exit_code") == -9,
            orderly_shutdown=common.normal_shutdown(report.get("recovery_shutdown")) is True,
            metadata=all(mapping(report.get(name)).get(key) is True for name in
                ("metadata_before_death", "metadata_after_death", "metadata_after_recovery", "metadata_final")
                for key in ("source_originals_unchanged", "private_originals_unchanged")))
    elif kind == "single_running":
        details = common.summarize_lifecycle(report, lambda value: value)
        required = ("calls", "before_crash_status", "first_recovered_status", "same_key_reuse", "terminal_status",
                    "terminal_publication_receipt", "complete_outputs", "shutdown", "first_startup", "restart_startup")
        status = mapping(report.get("terminal_status"))
        reuse = mapping(report.get("same_key_reuse"))
        shared.update(schema=report.get("schema") == "hepta-x230-native-lifecycle-canary/v2",
            binary=report.get("candidate_sha256") == candidate_sha, calls=rows_passed(report.get("calls")),
            start_requests=report.get("job_start_requests") == 2, execution_once=report.get("execution_count") == 1,
            input=report.get("stdin_bytes") == 4096, same_original=reuse.get("reused") is True
                and reuse.get("retried_launch") is False and reuse.get("job_id") == report.get("job_id"),
            original_running_across_restart=all(mapping(report.get(key)).get("state") == "running"
                for key in ("before_crash_status", "first_recovered_status")),
            durable_terminal=status.get("state") == "succeeded" and status.get("exit_code") == 0
                and all(status.get(key) is True for key in ("output_complete", "output_durable", "terminal_publication_confirmed")),
            publication=all(mapping(report.get("terminal_publication_receipt")).get(key) is True for key in
                ("strict_integer_protocol_verified", "request_exit_witness_identity_matches", "status_matches_persisted_exit", "terminal_publication_confirmed")),
            orderly_shutdown=common.normal_shutdown(report.get("shutdown")) is True,
            final_integrity=all(report.get(key) is True for key in ("binary_unchanged", "source_record_unchanged", "current_agent_unchanged")))
    else:
        hosts = mapping(report.get("hosts"))
        details = {"hosts": {host: six_running.summarize_host(host, hosts.get(host), report, lambda value: value) for host in HOSTS},
                   "native_calls": six_running.calls_summary(report.get("native_calls"), lambda value: value),
                   "independent_ssh_calls": six_running.calls_summary(report.get("ssh_calls"), lambda value: value)}
        required = ("hosts", "native_calls", "ssh_calls", "shutdown", "intentional_crash", "retained_controller_records")
        retained = sequence(report.get("retained_controller_records"))
        original_ids = {(host, mapping(hosts.get(host)).get("job_id")) for host in HOSTS}
        retained_ids = [(mapping(row).get("host"), mapping(row).get("job_id")) for row in retained]
        starts = Counter(mapping(row).get("host") for row in sequence(report.get("native_calls"))
                         if mapping(row).get("tool") == "process_start" and row.get("phase") == "launch")
        reuses = Counter(mapping(row).get("host") for row in sequence(report.get("native_calls"))
                         if mapping(row).get("tool") == "process_start" and row.get("phase") == "recover_same_original")
        hostnames = [mapping(mapping(hosts.get(host)).get("prepare")).get("hostname") for host in HOSTS]
        crash = mapping(report.get("intentional_crash"))
        shared.update(schema=report.get("schema") == "hepta-six-running-controller-recovery/v1",
            binary=report.get("candidate_sha256") == candidate_sha, six_hosts=set(hosts) == set(HOSTS),
            native_calls=rows_passed(report.get("native_calls")), ssh_calls=rows_passed(report.get("ssh_calls")),
            input=report.get("stdin_bytes") == 4096, new_starts=report.get("new_start_call_count") == 6,
            same_key_reuses=report.get("same_key_lookup_call_count") == 6,
            original_jobs_running_through_crash=all(row["checks_passed"] for row in details["hosts"].values()),
            orderly_shutdown=common.normal_shutdown(report.get("shutdown")) is True,
            exact_six_original_records=len(retained) == 6 and set(retained_ids) == original_ids
                and all(mapping(row).get("original_bytes_unchanged") is True for row in retained)
                and report.get("final_controller_record_errors") == [],
            six_distinct_recorded_hostnames=all(isinstance(value, str) and value for value in hostnames) and len(set(hostnames)) == 6,
            exactly_one_new_start_and_reuse_per_host=starts == reuses == Counter(HOSTS),
            own_controller_sigkill=crash.get("exit_code") == -9 and crash.get("observed_descendant_survivors") == []
                and "reader_error" in crash and crash["reader_error"] is None and crash.get("unmatched_responses") == 0,
            final_integrity=all(report.get(key) is True for key in ("source_originals_unchanged", "binary_unchanged",
                "current_agent_unchanged", "distinct_reported_hostnames", "controller_records_unchanged_after_shutdown")))
    structural = all(key in report for key in required)
    return {"kind": kind, "structural_complete": structural, "candidate_scope_passed": structural and all(shared.values()),
            "candidate_structural_complete": structural,
            "candidate_not_exercised": not bool(report), "checks": shared, "details": details,
            "raw_passed": report.get("passed"), "abrupt_cleanup_complete": report.get("abrupt_cleanup_complete"),
            "full_crash_cleanup_claim": False}


def summarize_report(report, spec, candidate_sha, baseline_sha):
    if not isinstance(report, dict):
        return {"present_and_parsed": False, "structural_complete": False,
                "candidate_structural_complete": False, "candidate_scope_passed": False, "candidate_not_exercised": None}
    try:
        result = (observation_summary(report, spec, candidate_sha, baseline_sha)
            if spec.get("kind") in ("observation", "fairness") else recovery_summary(report, spec, candidate_sha))
    except (KeyError, ValueError, TypeError, AttributeError) as error:
        result = {"structural_complete": False, "candidate_structural_complete": False, "candidate_scope_passed": False,
                  "summary_error": {"type": type(error).__name__, "message": str(error)}}
    if spec.get("stage_id") == "soak":
        cells = [mapping(cell) for rnd in sequence(report.get("rounds")) for cell in sequence(mapping(rnd).get("cells"))]
        result["minimum_540_second_C8_cell"] = (len(cells) == 1 and cells[0].get("concurrency") == 8
            and common.numeric(cells[0].get("seconds")) and cells[0]["seconds"] >= 540)
        result["candidate_scope_passed"] &= result["minimum_540_second_C8_cell"]
        result["timeline_sampling"] = [mapping(mapping(rnd).get("shutdown")).get("resources")
            for rnd in sequence(report.get("rounds"))]
    result.update(present_and_parsed=True, retained_object_inventory=inventory(report))
    return result


def qualification_checks(qualification, receipt, inputs, plan, before, runner):
    source = qualification.get("source_tested")
    source_digest = source_map_digest(source)
    candidate = mapping(qualification.get("binary")).get("sha256")
    source_receipt = mapping(receipt.get("source"))
    stages = sequence(qualification.get("stages"))
    independent_stages = sequence(receipt.get("stages"))
    files = mapping(before.get("files"))
    helper_bindings = {name: {"expected_sha256": digest,
        "frozen_manifest_matches": any(Path(path).name == name and mapping(value).get("sha256") == digest
            for path, value in files.items())} for name, digest in mapping(plan.get("helpers")).items()}
    bound_files = [mapping(value) for value in files.values()]
    checks = {
        "qualification_raw_schema_and_pass": qualification.get("schema") == "runtime-candidate-qualification/v1"
            and qualification.get("qualified") is True and qualification.get("service_changes") is False,
        "qualification_exact_five_successful_stages": [mapping(stage).get("name") for stage in stages] == QUAL_STAGES
            and all(type(mapping(stage).get("returncode")) is int and stage["returncode"] == 0 for stage in stages),
        "qualified_source_manifest_valid_equal": source_digest is not None and source == qualification.get("source_after"),
        "independent_receipt_bound_to_raw_qualification": receipt.get("schema") == "hepta-x230-qualification-independent-receipt/v1"
            and receipt.get("candidate") == "A26" and receipt.get("qualified") is True
            and receipt.get("source_report_sha256") == inputs.files["qualification.json"].get("sha256")
            and receipt.get("source_report_bytes") == inputs.files["qualification.json"].get("bytes")
            and receipt.get("success_checks_evaluated") is True and receipt.get("unmet_checks") == []
            and bool(mapping(receipt.get("verification")))
            and all(value is True for value in mapping(receipt.get("verification")).values()),
        "independent_source_map_and_count_bindings": source_digest is not None
            and source_digest == source_receipt.get("tested_map_sha256") == source_receipt.get("after_map_sha256")
            == source_receipt.get("actual_map_sha256") == plan.get("source_map_sha256")
            and source_receipt.get("tested_file_count") == source_receipt.get("after_file_count")
            == source_receipt.get("actual_file_count") == len(mapping(source)) == plan.get("source_file_count"),
        "independent_stage_log_bindings": [mapping(stage).get("name") for stage in independent_stages] == QUAL_STAGES
            and all(mapping(measured).get("log_hash_verified") is True
                and mapping(measured).get("actual_log_sha256") == mapping(original).get("log_sha256")
                for measured, original in zip(independent_stages, stages)),
        "both_compiled_artifacts_independently_bound": all(mapping(receipt.get(key)).get("verified") is True
            and mapping(receipt.get(key)).get("reported_sha256") == mapping(qualification.get(key)).get("sha256")
            and mapping(mapping(receipt.get(key)).get("copied")).get("sha256") == mapping(qualification.get(key)).get("sha256")
            for key in ("binary", "test_binary")),
        "qualification_and_receipt_bound_by_plan": digest_matches(inputs.files["qualification.json"], plan.get("qualification_sha256"))
            and digest_matches(inputs.files["qualification-receipt.json"], plan.get("qualification_receipt_sha256")),
        "runner_source_bound_by_plan": runner is not None and digest_matches(inputs.files["runner.py"], plan.get("runner_sha256")),
        "candidate_binary_bound": isinstance(candidate, str) and HEX256.fullmatch(candidate) is not None
            and candidate == plan.get("candidate_sha256")
            and any(value.get("sha256") == candidate for value in bound_files),
        "baseline_binary_bound": isinstance(plan.get("baseline_sha256"), str)
            and HEX256.fullmatch(plan["baseline_sha256"]) is not None
            and any(value.get("sha256") == plan.get("baseline_sha256") for value in bound_files),
        "all_frozen_helpers_bound": set(helper_bindings) == HELPER_NAMES
            and all(row["frozen_manifest_matches"] and isinstance(row["expected_sha256"], str)
                    and HEX256.fullmatch(row["expected_sha256"]) for row in helper_bindings.values()),
        "qualified_source_exactly_matches_frozen_snapshot": source_digest is not None and before.get("source") == source,
        "qualification_receipt_and_runner_in_frozen_files": all(
            any(value.get("sha256") == inputs.files[label].get("sha256")
                and value.get("bytes") == inputs.files[label].get("bytes") for value in bound_files)
            for label in ("qualification.json", "qualification-receipt.json", "runner.py")),
    }
    return checks, {"binary_sha256": candidate, "source_map_sha256": source_digest,
        "source_file_count": len(mapping(source)), "helpers": helper_bindings,
        "publisher_rehashed_runtime_or_source_files": False,
        "binding_scope": "Frozen full input manifests and the supplied independent qualification receipt are checked; this publisher does not rerun their verification."}


def safe_child(path, parent):
    return (path.is_absolute() and path.parent == parent and path != parent
            and path.name not in {".", ".."} and path.absolute() == path.resolve())


def safe_relative(value):
    return (isinstance(value, str) and value and not Path(value).is_absolute()
            and all(part not in {"", ".", ".."} for part in value.split("/")))


def log_payload(raw):
    """Retain every log line; command-bearing content is later replaced in place."""
    if raw is None:
        return None
    try:
        value = raw.decode("utf-8")
    except UnicodeError:
        return {"encoding": "non-UTF8", "content_redacted": True, "bytes": len(raw), "sha256": sha(raw)}
    result = []
    for number, line in enumerate(value.splitlines(keepends=True), 1):
        try:
            content = decode(line)
            kind = "json"
        except (ValueError, UnicodeError):
            content, kind = line, "line"
        result.append({"line": number, "kind": kind, "original_utf8_bytes": len(line.encode()),
                       "original_utf8_sha256": sha(line.encode()), "value": content})
    return {"encoding": "UTF-8", "complete_line_count": len(result), "lines": result}


def artifacts_for_stage(directory, stage_id, declared, inputs):
    receipts, payloads, errors, events = {}, {}, [], []
    actual = set()
    try:
        if directory.exists():
            for path in directory.rglob("*"):
                if path.is_file() or path.is_symlink():
                    actual.add(path.relative_to(directory).as_posix())
    except OSError as error:
        errors.append({"type": type(error).__name__, "message": str(error)})
    declared = mapping(declared)
    for relative in sorted(actual | set(declared)):
        if not safe_relative(relative):
            errors.append({"artifact": relative, "reason": "unexpected artifact path; not followed"})
            continue
        is_report = Path(relative).name.startswith("report")
        is_json = is_report or Path(relative).suffix == ".json"
        is_log = Path(relative).name in {"stdout.log", "stderr.log"} or Path(relative).suffix in {".stdout", ".stderr"}
        label = stage_id + "/artifacts/" + relative
        if is_json or is_log:
            value = inputs.read(directory / relative, label, JSON_LIMIT if is_json else LOG_LIMIT, parse=is_json)
            payloads[relative] = value if is_json else log_payload(value)
        else:
            value = None
            inputs.hash_only(directory / relative, label)
            payloads[relative] = {"opaque_artifact": True, "original": inputs.files[label]}
        receipts[relative] = {"actual": inputs.files[label], "declared": declared.get(relative),
                              "matches_declared": receipt_matches(inputs.files[label], declared.get(relative))}
        if is_log and Path(relative).name == "stderr.log" and value is not None:
            for number, line in enumerate(value.splitlines(), 1):
                if PROOF_PREFIX in line:
                    slot = next((part.rsplit("-", 1)[-1] for part in Path(relative).parts
                                 if re.fullmatch(r"round-[0-9]+-[AB]", part)), "B")
                    events.append({"path": relative, "line": number, "slot": slot, "line_sha256": sha(line)})
    return {"receipts": receipts, "payloads": payloads, "errors": errors, "events": events,
            "declared_and_actual_sets_equal": set(declared) == actual,
            "all_actual_hashes_match": bool(receipts) and all(row["matches_declared"] for row in receipts.values()),
            "all_reports_parsed": all(isinstance(value, dict) for name, value in payloads.items()
                if Path(name).name.startswith("report")),
            "main_report": payloads.get("report.json"), "actual_paths": sorted(actual)}


def planned_spec_valid(spec):
    name = spec.get("stage_id")
    roles = spec.get("role_by_slot")
    expected_roles = {"A": "A20" if name and name.endswith("_compare") else "A26", "B": "A26"}
    if name not in STAGE_IDS or roles != expected_roles or spec.get("helper") not in HELPER_NAMES:
        return False
    if name.startswith("standard") or name.startswith("capacity"):
        return (spec.get("kind") == "observation" and spec.get("calls") == 96
            and spec.get("concurrency") == ([1, 4, 8] if name.startswith("standard") else [16])
            and spec.get("order") == ("ABBA" if name.endswith("compare") else "B")
            and (name != "capacity_compare" or spec.get("capacity_exception") is True))
    if name.startswith("fairness"):
        return (spec.get("kind") == "fairness" and spec.get("order") == "ABBA"
                and spec.get("waves") == 8 and spec.get("gate_budget_ms") == 120)
    if name in {"calibration", "soak"}:
        return (spec.get("kind") == "observation" and spec.get("order") == "B" and spec.get("concurrency") == [8]
                and spec.get("calls") == (192 if name == "calibration" else None))
    return spec.get("kind") == name


def expected_coverage(stage_id):
    if stage_id.startswith("standard"):
        return {"C1", "C4", "C8"}
    if stage_id.startswith("capacity"):
        return {"C16"}
    if stage_id.startswith("fairness"):
        return {"fairness"}
    return {stage_id}


def expected_controller_stderr(report, spec):
    report, paths = mapping(report), []
    if spec.get("kind") in {"observation", "fairness"}:
        for value in sequence(report.get("rounds")):
            row = mapping(value)
            base = "round-" + str(row.get("index")) + "-" + str(row.get("version"))
            if "startup" in row:
                paths.append(base + ("/controller/stderr.log" if spec["kind"] == "fairness" else "/first/stderr.log"))
            if "restart_startup" in row:
                paths.append(base + "/restart/stderr.log")
    elif spec.get("kind") == "completed_recovery":
        for field, folder in (("initial_startup", "before-death"), ("recovery_startup", "after-death")):
            if field in report:
                paths.append("fixture/" + folder + "/stderr.log")
    else:
        for field, folder in (("first_startup", "first-controller"), ("restart_startup", "restarted-controller")):
            if field in report:
                paths.append(folder + "/stderr.log")
    return paths


def calibrated_spec_matches(spec, executed, soak_plan, stage_reports):
    if spec.get("stage_id") != "soak":
        return executed == spec
    calibration = mapping(stage_reports.get("calibration"))
    rounds = sequence(calibration.get("rounds"))
    cells = sequence(mapping(rounds[0]).get("cells")) if rounds else []
    cell = mapping(cells[0]) if len(cells) == 1 else {}
    seconds, successes = cell.get("seconds"), cell.get("successes")
    if not common.numeric(seconds) or seconds <= 0 or type(successes) is not int or successes != 192:
        return False
    import math
    count = math.ceil(successes / seconds * 600 / 12) * 12
    return (12 <= count <= 60000 and executed == {**spec, "calls": count}
        and soak_plan.get("calls") == count and soak_plan.get("concurrency") == 8
        and soak_plan.get("basis_stage_id") == "calibration" and soak_plan.get("basis_successes") == successes
        and soak_plan.get("basis_seconds") == seconds and soak_plan.get("target_seconds") == 600
        and soak_plan.get("minimum_cell_seconds") == 540 and soak_plan.get("maximum_calls") == 60000
        and soak_plan.get("trial_retries") == 0)


def compressed(value):
    raw = canonical(value)
    output = io.BytesIO()
    with gzip.GzipFile(fileobj=output, mode="wb", filename="", mtime=0, compresslevel=9) as target:
        target.write(raw)
    return output.getvalue(), {"uncompressed_bytes": len(raw), "uncompressed_sha256": sha(raw)}


def create_only(path, raw):
    with path.open("xb") as output:
        output.write(raw)
        output.flush()
        os.fsync(output.fileno())
    return {"bytes": len(raw), "sha256": sha(raw)}


def build(args):
    inputs = Inputs()
    series_root = args.series.absolute().parent
    development_root = series_root.parent
    series = inputs.read(args.series, "series.json")
    plan = inputs.read(series_root / "plan.json", "plan.json")
    if not isinstance(series, dict) or series.get("schema") != SERIES_SCHEMA:
        raise ValueError("an A26 series.json with the exact schema is required")
    if not isinstance(plan, dict) or plan.get("schema") != PLAN_SCHEMA:
        raise ValueError("the exact A26 plan must be readable before any recorded path is followed")
    before = inputs.read(series_root / "inputs-before.json", "inputs-before.json")
    after = inputs.read(series_root / "inputs-after.json", "inputs-after.json")
    qualification = inputs.read(args.qualification, "qualification.json")
    qualification_receipt = inputs.read(args.qualification_receipt, "qualification-receipt.json")
    runner = inputs.read(args.runner, "runner.py", 1024 * 1024, parse=False)
    before, after = mapping(before), mapping(after)
    qualification, qualification_receipt = mapping(qualification), mapping(qualification_receipt)
    soak_plan = inputs.read(series_root / "soak-plan.json", "soak-plan.json", required=False)
    soak_plan = mapping(soak_plan)
    checks, qualification_binding = qualification_checks(qualification, qualification_receipt, inputs, plan, before, runner)
    candidate, baseline = plan.get("candidate_sha256"), plan.get("baseline_sha256")
    specs = sequence(plan.get("specs"))
    ids = [mapping(spec).get("stage_id") for spec in specs]
    if any(not isinstance(name, str) or not SAFE_NAME.fullmatch(name) for name in ids) or len(ids) != len(set(ids)):
        raise ValueError("unsafe or duplicate stage identifier in plan")
    output_paths = [Path(mapping(spec).get("output_directory", "")) for spec in specs]
    outputs_valid = (all(safe_child(path, development_root) for path in output_paths)
                     and len(set(output_paths)) == len(output_paths) and series_root not in output_paths)
    checks.update({
        "plan_bound_by_series": digest_matches(inputs.files["plan.json"], series.get("plan_sha256")),
        "frozen_before_bound_by_plan_and_series": digest_matches(inputs.files["inputs-before.json"], plan.get("inputs_before_sha256"))
            and series.get("inputs_before_sha256") == plan.get("inputs_before_sha256"),
        "final_snapshot_bound_by_series": digest_matches(inputs.files["inputs-after.json"], series.get("inputs_after_sha256")),
        "source_and_full_frozen_inputs_unchanged": bool(before) and before == after and series.get("final_inputs_unchanged") is True,
        "all_series_identity_bindings_match_plan": all(series.get(key) == plan.get(key) for key in
            ("runner_sha256", "qualification_sha256", "qualification_receipt_sha256", "candidate_sha256", "baseline_sha256")),
        "candidate_label_A26": series.get("candidate") == plan.get("candidate") == "A26",
        "exact_predeclared_stage_specs": ids == STAGE_IDS and all(planned_spec_valid(mapping(spec)) for spec in specs),
        "fixed_safe_output_directories": outputs_valid,
        "no_retries_or_production_service_changes_declared": plan.get("automatic_rpc_retries") == plan.get("trial_retries") == 0
            and plan.get("production_services_changed") is False and plan.get("workers") == 2,
        "series_has_final_receipt": common.numeric(series.get("finished_unix"))
            and common.numeric(series.get("started_unix")) and series["finished_unix"] >= series["started_unix"],
        "every_plan_stage_has_a_state": set(mapping(series.get("stages"))) == set(ids)
            and all(mapping(value).get("state") in {"not-run", "running", "completed", "failed"}
                    for value in mapping(series.get("stages")).values()),
    })
    rows = sequence(series.get("experiments"))
    recorded_ids = [mapping(row).get("stage_id") for row in rows]
    checks["every_experiment_has_unique_planned_identity"] = (isinstance(series.get("experiments"), list)
        and len(recorded_ids) == len(set(str(name) for name in recorded_ids))
        and all(name in ids for name in recorded_ids))
    try:
        receipt_names = {path.name[:-len(".receipt.json")] for path in series_root.glob("*.receipt.json")}
    except OSError:
        receipt_names = set()
        checks["stage_receipt_inventory_readable"] = False
    checks["receipt_inventory_matches_recorded_experiments"] = receipt_names == set(recorded_ids)
    stages, payloads, reports = {}, {}, {}
    for spec_raw, directory in zip(specs, output_paths):
        spec = mapping(spec_raw)
        stage_id = spec["stage_id"]
        declarations = [mapping(row) for row in rows if mapping(row).get("stage_id") == stage_id]
        row = declarations[0] if len(declarations) == 1 else {}
        receipt_path = series_root / (stage_id + ".receipt.json")
        state = mapping(mapping(series.get("stages")).get(stage_id))
        actual_directory = safe_child(directory, development_root) and directory.exists()
        recorded = bool(declarations) or os.path.lexists(receipt_path) or actual_directory
        stage_payload = {"plan_spec": spec, "series_declarations": declarations, "receipt": None,
                         "driver_logs": {}, "artifacts": {}}
        payloads[stage_id] = stage_payload
        if not recorded:
            stages[stage_id] = {"state": state.get("state"), "recorded": False,
                "reason": state.get("reason"), "runtime_role_by_slot": spec.get("role_by_slot"),
                "structural_complete": False, "candidate_structural_complete": False, "candidate_scope_passed": False,
                "recorded_artifact_integrity_passed": state.get("state") == "not-run",
                "all_recorded_reports_parsed_and_retained": True}
            continue
        receipt = inputs.read(receipt_path, stage_id + ".receipt.json")
        stage_payload["receipt"] = receipt
        receipt = mapping(receipt)
        artifact = (artifacts_for_stage(directory, stage_id, receipt.get("artifact_hashes"), inputs)
            if safe_child(directory, development_root) else {"receipts": {}, "payloads": {}, "errors": [{"reason": "unsafe output path; not followed"}],
                "events": [], "all_reports_parsed": False, "declared_and_actual_sets_equal": False,
                "all_actual_hashes_match": False, "main_report": None, "actual_paths": []})
        stage_payload["artifacts"] = artifact["payloads"]
        report = artifact["main_report"]
        reports[stage_id] = report
        executed_spec = mapping(receipt.get("spec"))
        report_summary = summarize_report(report, executed_spec or spec, candidate, baseline)
        declared_logs = mapping(receipt.get("driver_logs"))
        driver_log_checks = {}
        for stream in ("stdout", "stderr"):
            label = stage_id + "." + stream + ".log"
            raw = inputs.read(series_root / label, label, LOG_LIMIT, parse=False)
            stage_payload["driver_logs"][stream] = log_payload(raw)
            driver_log_checks[stream] = receipt_matches(inputs.files[label], declared_logs.get(stream))
        expected_stderr = sequence(receipt.get("expected_controller_stderr"))
        assessment = mapping(receipt.get("assessment"))
        main_receipt = mapping(mapping(artifact["receipts"].get("report.json")).get("actual"))
        stage_checks = {
            "one_exact_series_receipt": len(declarations) == 1
                and {key: value for key, value in row.items() if key not in {"receipt_path", "receipt_sha256"}} == receipt,
            "receipt_hash_and_path_bound": digest_matches(inputs.files[stage_id + ".receipt.json"], row.get("receipt_sha256"))
                and row.get("receipt_path") == str(receipt_path),
            "stage_identity_and_paths_match_plan": receipt.get("stage_id") == stage_id and receipt.get("kind") == spec.get("kind")
                and receipt.get("role_by_slot") == spec.get("role_by_slot") and receipt.get("order") == spec.get("order")
                and receipt.get("output_directory") == str(directory) and receipt.get("report_path") == str(directory / "report.json"),
            "executed_spec_matches_predeclaration": calibrated_spec_matches(spec, executed_spec, soak_plan, reports),
            "main_report_hash_bound": isinstance(report, dict) and digest_matches(main_receipt, receipt.get("report_sha256")),
            "raw_passed_agrees_with_report": isinstance(report, dict) and type(report.get("passed")) is bool
                and receipt.get("raw_passed") is report.get("passed"),
            "all_artifact_paths_and_hashes_bound": artifact["declared_and_actual_sets_equal"] and artifact["all_actual_hashes_match"],
            "all_recorded_reports_parsed": artifact["all_reports_parsed"] and isinstance(report, dict),
            "all_driver_log_hashes_bound": set(declared_logs) == {"stdout", "stderr"} and all(driver_log_checks.values()),
            "spawn_proof_event_inventory_matches_complete_stderr": receipt.get("spawn_proof_events") == artifact["events"],
            "frozen_inputs_after_stage_equal_before": bool(before) and receipt.get("inputs_after") == before,
            "declared_input_unchanged_agrees": receipt.get("inputs_unchanged") is (receipt.get("inputs_after") == before),
            "stage_state_matches_receipt": state.get("state") == ("completed" if receipt.get("accepted_for_continuation") is True else "failed")
                and state.get("raw_passed") is receipt.get("raw_passed")
                and state.get("accepted_for_continuation") is receipt.get("accepted_for_continuation"),
            "controller_stderr_inventory_complete": receipt.get("expected_controller_stderr") == expected_controller_stderr(report, spec)
                and any(Path(name).name == "stderr.log" for name in artifact["receipts"]),
        }
        # This checks preservation of attempted controller logs, not that a
        # failed constructor ever returned a startup receipt.
        if "expected_controller_stderr" in receipt:
            stage_checks["all_declared_controller_stderr_present"] = (isinstance(receipt["expected_controller_stderr"], list)
                and all(name in artifact["receipts"] for name in expected_stderr))
        artifact_integrity = all(stage_checks.values()) and not artifact["errors"]
        accepted_checks = {
            "artifact_integrity": artifact_integrity,
            "recorded_stage_accepted": receipt.get("accepted_for_continuation") is True,
            "driver_completed_without_interruption": type(receipt.get("driver_returncode")) is int
                and receipt.get("interrupted") is False,
            "runner_collected_without_error": not any(key in receipt for key in ("runner_error", "final_collection_error"))
                and receipt.get("collection_errors") == [],
            "runner_assessment_allows_continuation": assessment.get("safe_to_continue") is True
                and assessment.get("candidate_failure") is False and assessment.get("shared_failures") == [],
            "candidate_emitted_no_proof_failure_events": not any(mapping(spec.get("role_by_slot")).get(event.get("slot")) == "A26"
                for event in artifact["events"]),
        }
        stages[stage_id] = {"state": state.get("state"), "recorded": True,
            "runtime_role_by_slot": spec.get("role_by_slot"), "spec": executed_spec, "report": report_summary,
            "structural_complete": report_summary["structural_complete"],
            "candidate_structural_complete": report_summary["candidate_structural_complete"],
            "candidate_scope_passed": report_summary["candidate_scope_passed"] and all(accepted_checks.values()),
            "recorded_artifact_integrity_passed": artifact_integrity,
            "all_recorded_reports_parsed_and_retained": artifact["all_reports_parsed"] and isinstance(report, dict),
            "verification": stage_checks, "continuation_verification": accepted_checks,
            "accepted_for_continuation_verified": all(accepted_checks.values()),
            "raw_passed": receipt.get("raw_passed"), "driver_returncode": receipt.get("driver_returncode"),
            "runner_assessment": assessment, "artifact_receipts": artifact["receipts"],
            "artifact_errors": artifact["errors"], "spawn_proof_events": artifact["events"],
            "driver_log_hash_checks": driver_log_checks}
    if "soak" in reports:
        checks["soak_calibration_report_hash_bound"] = (soak_plan.get("basis_report_sha256")
            == mapping(next((row for row in rows if mapping(row).get("stage_id") == "calibration"), {})).get("report_sha256"))
    coverage = {}
    declared_coverage = mapping(series.get("coverage"))
    for key in COVERAGE:
        value = mapping(declared_coverage.get(key))
        evidence = sequence(value.get("evidence_stage_ids"))
        eligible = [name for name in evidence if name in stages and key in expected_coverage(name)]
        coverage[key] = {"reported_state": value.get("state"), "evidence_stage_ids": evidence,
            "structural_complete": bool(eligible) and len(eligible) == len(evidence)
                and all(stages[name]["candidate_structural_complete"] for name in eligible),
            "candidate_scope_passed": value.get("state") == "passed" and bool(eligible)
                and len(eligible) == len(evidence) and all(stages[name]["candidate_scope_passed"] for name in eligible)}
    checks["exact_coverage_categories_recorded"] = set(declared_coverage) == set(COVERAGE)
    checks["all_present_inputs_read_without_error"] = not inputs.errors
    recorded_stages = [stage for stage in stages.values() if stage["recorded"]]
    artifact_integrity = (bool(recorded_stages) and all(checks.values())
        and all(stage["recorded_artifact_integrity_passed"] for stage in stages.values()))
    candidate_passed = (artifact_integrity and series.get("candidate_validation_passed") is True
        and series.get("completed") is True and all(row["candidate_scope_passed"] for row in coverage.values())
        and all(stage.get("accepted_for_continuation_verified") is True for stage in recorded_stages)
        and not any(key in series for key in ("error", "final_error")))
    comparison_valid = (candidate_passed and series.get("comparison_valid") is True
        and series.get("comparison_invalid_reasons") == [] and candidate != baseline
        and all(stages.get(name, {}).get("accepted_for_continuation_verified") is True
            and mapping(stages[name].get("runner_assessment")).get("complete_for_scope") is True
            and not mapping(stages[name].get("runner_assessment")).get("baseline_only_failure")
            and all(mapping(slot).get("scope_passed") is True
                    for slot in mapping(mapping(stages[name].get("report")).get("slot_results")).values())
            for name in ("standard_compare", "capacity_compare", "fairness_compare")))
    preserved = (bool(recorded_stages) and all(stage["all_recorded_reports_parsed_and_retained"] for stage in recorded_stages)
        and all(name in stages for name in recorded_ids)
        and checks["receipt_inventory_matches_recorded_experiments"])
    bundle = {"series": series, "plan": plan, "inputs_before": before, "inputs_after": after,
              "soak_plan": soak_plan or None, "qualification": qualification, "qualification_receipt": qualification_receipt}
    clean = CompleteSanitizer({"bundle": bundle, "stage_payloads": payloads, "stages": stages,
                               "input_errors": inputs.errors, "input_receipts": inputs.files})
    # Complete all transformations before creating any output. A sanitizer key
    # collision or invalid numeric value cannot leave a deceptively complete set.
    public_bundle = clean(bundle)
    public_payloads = {name: clean(value) for name, value in payloads.items()}
    summary = {"schema": "hepta-x230-a26-series-public-evidence/v1", "candidate": "A26",
        "candidate_binary_sha256": candidate, "baseline_binary_sha256": baseline,
        "raw_candidate_validation_passed": series.get("candidate_validation_passed"),
        "candidate_validation_passed": candidate_passed, "raw_comparison_valid": series.get("comparison_valid"),
        "comparison_valid": comparison_valid, "comparison_invalid_reasons": series.get("comparison_invalid_reasons"),
        "artifact_integrity_passed": artifact_integrity, "verification": checks, "qualification_binding": qualification_binding,
        "coverage": coverage, "stages": stages, "original_input_receipts": inputs.files, "input_errors": inputs.errors,
        "performance_comparison_generated": False, "performance_adoption": False, "production_runtime_changed": False,
        "production_runtime_changed_field_scope": "The supplied frozen runner declares no production service mutation; this publisher itself only reads inputs and creates its fresh output directory.",
        "full_crash_cleanup_claim": False,
        "preservation": {"all_recorded_report_rows_and_errors_retained": preserved,
            "all_parsed_reports_preserved_without_success_filtering": True,
            "every_plan_stage_has_explicit_status": set(stages) == set(ids),
            "unknown_outcomes_never_promoted_to_pass": True, "payloads_decoded_for_publication": False,
            "private_artifacts_bound_by_hash_without_publishing_raw_bytes": True},
        "method": {**common.METHOD, "slot_identity": "A/B denote scheduling slots. Their runtime roles and exact binary hashes come from each frozen stage spec.",
            "structural_complete": "Dimensions and required record presence are checked independently of successful outcomes; a complete failed round stays complete.",
            "candidate_validation": "Only the frozen plan's required candidate checks are covered. This verdict does not assert full SIGKILL cleanup or removal of socket residue.",
            "bindings": "Actual received report, receipt, log and stage-artifact hashes are checked. Source/helper/runtime identities are bound through frozen input manifests and the supplied independent qualification receipt."},
        "builder_sha256": sha(Path(__file__).read_bytes()),
        "dependency_sha256": {Path(module.__file__).name: sha(Path(module.__file__).read_bytes()) for module in (common, six_running)},
        "limitations": ["No binaries, tests, RPCs, or SSH commands are executed by this publisher.",
            "Complete preservation covers rows the drivers actually recorded; calls lost before any report write cannot be reconstructed.",
            "Hash bindings are evidence integrity checks, not signatures or independent proof that a producer was honest.",
            "A20-only failure invalidates the comparison permanently; later A26-only coverage cannot repair it.",
            "Same-A26 fairness slots and single-B soak do not supply a baseline performance comparison.",
            "Orderly EOF shutdown, observed descendant exit, original-job recovery, and socket cleanup remain separate outcomes.",
            "Sampled process resources are lower bounds and can include errors; retained timelines do not prove exhaustive process containment.",
            "Recovery canaries do not test host reboot, physical power loss, WAN partition, or all future loads."]}
    public_summary = clean(summary)
    if os.path.lexists(args.output_dir):
        raise ValueError("output directory must be fresh")
    source_path = qualification.get("source")
    if isinstance(source_path, str) and args.output_dir.absolute().is_relative_to(Path(source_path)):
        raise ValueError("publication output must be outside the qualified source tree")
    args.output_dir.mkdir(mode=0o700, parents=False, exist_ok=False)
    artifacts = {}

    def emit(name, value, compress=False):
        raw, extra = compressed(value) if compress else (canonical(value), {})
        artifacts[name] = {**create_only(args.output_dir / name, raw), **extra}

    emit("series.complete.sanitized.json", public_bundle)
    for name, value in public_payloads.items():
        if stages[name]["recorded"]:
            emit(name + ".complete.sanitized.json.gz", value, True)
            report = mapping(value["artifacts"]).get("report.json")
            if report is not None:
                emit(name + ".report.complete.sanitized.json.gz", report, True)
    public_summary["public_artifacts"] = artifacts
    create_only(args.output_dir / "summary.json", canonical(public_summary))
    descriptor = os.open(args.output_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return public_summary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("series", "qualification", "qualification-receipt", "runner", "output-dir"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args(argv)
    if os.path.lexists(args.output_dir):
        parser.error("output directory must be fresh")
    try:
        result = build(args)
    except (OSError, ValueError, TypeError) as error:
        print(json.dumps({"publication_completed": False, "error_type": type(error).__name__,
                          "message": CompleteSanitizer({})(str(error))}), file=sys.stderr)
        return 2
    print(json.dumps({"publication_completed": True,
        "candidate_validation_passed": result["candidate_validation_passed"],
        "comparison_valid": result["comparison_valid"],
        "artifact_integrity_passed": result["artifact_integrity_passed"],
        "performance_comparison_generated": False}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
