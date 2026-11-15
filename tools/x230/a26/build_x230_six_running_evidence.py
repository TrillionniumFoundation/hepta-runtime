#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Publish create-only six-host running-job recovery evidence and a complete sanitized report.

No encoded payload is decoded or published. Qualification is checked against the
measured harness, exact candidate binary and unchanged tested source manifest.
"""

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re

from build_x230_evidence import Sanitizer, canonical, normal_shutdown, sha


HOSTS = ("ai395", "mac", "main", "pocket4", "rog", "x230")
HEX256 = re.compile(r"[0-9a-f]{64}\Z")
PHASES = ("prepare", "launch", "before_crash_running", "before_crash_independent",
          "recover_same_original", "after_crash_independent", "release", "terminal")


def mapping(value):
    return value if isinstance(value, dict) else {}


def sequence(value):
    return value if isinstance(value, list) else []


class CompleteSanitizer(Sanitizer):
    """Retain every report key/row, replacing payloads and private identities by receipts."""
    opaque = {"base64", "bytes_hex", "b64", "args", "arguments", "command", "payload",
              "raw", "raw_payload", "raw_request", "raw_response", "content", "text",
              "stdin_base64", "stdout_base64", "stderr_base64"}
    private_identity = Sanitizer.identity_keys | Sanitizer.secret_keys | {
        "hostname", "fixture_identity", "launch_nonce", "nonce", "birth", "start_ticks",
        "ppid", "owner_pid", "controller_pid", "idempotency_key", "agent_identity",
        "dev", "ino", "uid", "gid", "agent_socket_identity", "process_identity"}
    encoded_token = re.compile(r"(?<![A-Za-z0-9+/_=-])[A-Za-z0-9+/_-]{80,}={0,2}(?![A-Za-z0-9+/_=-])")

    def __init__(self, report):
        super().__init__(report)
        self.private_values = set()

        def visit(value):
            if isinstance(value, dict):
                for key, item in value.items():
                    if (key.lower() in self.private_identity and isinstance(item, str)
                            and len(item) >= 6 and item not in HOSTS):
                        self.private_values.add(item)
                    visit(item)
            elif isinstance(value, list):
                for item in value:
                    visit(item)
        visit(report)

    @staticmethod
    def opaque_receipt(value):
        data = canonical(value)
        result = {"redacted": True, "canonical_value_sha256": sha(data),
                  "canonical_value_bytes": len(data), "decoded_for_publication": False}
        if isinstance(value, str):
            result.update(encoded_characters=len(value), encoded_utf8_sha256=sha(value.encode()))
        return result

    def string(self, value):
        value = super().string(value)
        for private in sorted(self.private_values, key=len, reverse=True):
            value = value.replace(private, "<private-identity:" + sha(private.encode())[:12] + ">")
        # Timeout/error strings can include an entire encoded command argument.
        # Keep the surrounding failure, but never rely only on dictionary keys.
        return self.encoded_token.sub(
            lambda found: "<opaque-encoded:" + sha(found[0].encode())[:12] + ">", value)

    def __call__(self, value):
        if isinstance(value, list):
            return [self(item) for item in value]
        if isinstance(value, dict):
            result = {}
            for key, item in value.items():
                lowered = key.lower()
                if (lowered in self.opaque or lowered in self.private_identity
                        or "base64" in lowered or lowered.endswith("_hex")):
                    result[self.string(key)] = self.opaque_receipt(item)
                else:
                    result[self.string(key)] = self(item)
            return result
        return self.string(value) if isinstance(value, str) else value


def file_receipt(value):
    if not isinstance(value, dict):
        return None
    return {"bytes": value.get("bytes"), "sha256": value.get("sha256")}


def file_matches(value, size, digest):
    return (type(size) is int and size >= 0 and isinstance(digest, str)
            and HEX256.fullmatch(digest) is not None and file_receipt(value) == {"bytes": size, "sha256": digest})


def qualification_checks(report, qualification, harness_bytes):
    before, after = qualification.get("source_tested"), qualification.get("source_after")
    stages = sequence(qualification.get("stages"))
    names = [mapping(stage).get("name") for stage in stages]
    binary = mapping(qualification.get("binary")).get("sha256")
    source_valid = (isinstance(before, dict) and bool(before)
                    and all(isinstance(path, str) and isinstance(digest, str)
                            and HEX256.fullmatch(digest) for path, digest in before.items()))
    checks = {
        "qualification_schema_matches": qualification.get("schema") == "runtime-candidate-qualification/v1",
        "qualification_passed": qualification.get("qualified") is True,
        "source_manifest_valid_and_unchanged": bool(source_valid and before == after),
        "all_five_qualification_stages_succeeded": (
            len(names) == 5 and set(names) == {"format", "fmt-check", "clippy", "test", "release"}
            and all(type(mapping(stage).get("returncode")) is int and stage["returncode"] == 0 for stage in stages)),
        "candidate_matches_qualified_binary": (
            isinstance(binary, str) and HEX256.fullmatch(binary) is not None
            and report.get("candidate_sha256") == binary),
        "measured_harness_matches_supplied_harness": report.get("script_sha256") == sha(harness_bytes),
    }
    source_digest = (hashlib.sha256(json.dumps(before, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
                     if source_valid else None)
    return checks, {"binary_sha256": binary, "source_file_count": len(before) if isinstance(before, dict) else None,
                    "tested_source_map_sha256": source_digest,
                    "stages": [{key: mapping(stage).get(key) for key in ("name", "returncode", "seconds", "log_sha256")}
                               for stage in stages]}


def summarize_host(host, row, report, clean):
    row = mapping(row)
    terminal = mapping(row.get("terminal"))
    status = mapping(terminal.get("status"))
    recovered = mapping(row.get("recover_same_original"))
    reuse = mapping(recovered.get("same_key_reuse"))
    before = mapping(row.get("before_crash_independent"))
    after = mapping(row.get("after_crash_independent"))
    before_files = mapping(mapping(before.get("proof")).get("files"))
    after_files = mapping(mapping(after.get("proof")).get("files"))
    files = mapping(mapping(terminal.get("independent_proof")).get("files"))
    job_id = row.get("job_id")
    ids = [mapping(mapping(row.get("launch")).get("job")).get("id"),
           mapping(mapping(row.get("before_crash_running")).get("status")).get("job_id"),
           mapping(recovered.get("first_status")).get("job_id"), mapping(reuse.get("job")).get("id"),
           mapping(reuse.get("status")).get("job_id"), status.get("job_id")]
    original_request = before_files.get("request.json")
    outputs = mapping(terminal.get("outputs"))
    checks = {
        "all_host_phases_completed": all(isinstance(row.get(phase), dict) and "error" not in row[phase] for phase in PHASES),
        "same_original_job_identity": isinstance(job_id, str) and bool(job_id) and all(value == job_id for value in ids),
        "running_before_crash": mapping(mapping(row.get("before_crash_running")).get("status")).get("state") == "running",
        "running_after_crash": mapping(recovered.get("first_status")).get("state") == "running",
        "same_key_reuses_without_relaunch": reuse.get("reused") is True and reuse.get("retried_launch") is False
            and reuse.get("launch") is None and mapping(reuse.get("status")).get("state") == "running",
        "request_bytes_preserved": isinstance(original_request, dict)
            and original_request == after_files.get("request.json") == files.get("request.json"),
        "launch_nonce_preserved": isinstance(before.get("launch_nonce"), str)
            and re.fullmatch(r"[0-9a-f]{32}", before["launch_nonce"]) is not None
            and before["launch_nonce"] == after.get("launch_nonce"),
        "stdin_preserved": all(file_matches(items.get("stdin.bin"), report.get("stdin_bytes"), report.get("stdin_sha256"))
                               for items in (before_files, after_files, files)),
        "execution_once": terminal.get("execution_count") == 1
            and file_matches(files.get("execution-marker"), 9, sha(b"EXECUTED\n")),
        "identity_preserved_harness_verdict": terminal.get("original_identity_preserved") is True,
        "durable_terminal": status.get("state") == "succeeded" and status.get("exit_code") == 0
            and status.get("output_complete") is True and status.get("output_durable") is True
            and status.get("terminal_publication_confirmed") is True and terminal.get("terminal_publication_confirmed") is True,
        "output_digests_match_independent_files": all(file_matches(files.get(stream + ".log"),
            mapping(outputs.get(stream)).get("bytes"), mapping(outputs.get(stream)).get("sha256"))
            for stream in ("stdout", "stderr")),
        "publication_files_recorded": all(isinstance(files.get(name), dict)
            and isinstance(files[name].get("sha256"), str) and HEX256.fullmatch(files[name]["sha256"])
            for name in ("request.json", "exit.json", "exit.witness.json")),
    }
    return {"host": host, "job_id": job_id, "checks": checks, "checks_passed": all(checks.values()),
            "execution_count": terminal.get("execution_count"),
            "original_identity_preserved": terminal.get("original_identity_preserved"),
            "stdin": {"bytes": report.get("stdin_bytes"), "sha256": report.get("stdin_sha256")},
            "outputs": clean(outputs), "terminal_status": clean(status),
            "terminal_publication_confirmed": terminal.get("terminal_publication_confirmed"),
            "publication_file_receipts": {name: file_receipt(files.get(name))
                for name in ("request.json", "exit.json", "exit.witness.json")},
            "phase_errors": {phase: clean(row[phase]["error"]) for phase in PHASES
                if isinstance(row.get(phase), dict) and "error" in row[phase]},
            "phases_observed": [phase for phase in PHASES if phase in row]}


def calls_summary(rows, clean):
    rows = sequence(rows)
    failed = [row for row in rows if mapping(row).get("okay") is not True]
    return {"calls": len(rows), "successes": len(rows) - len(failed), "failures": len(failed),
            "by_host": clean(dict(Counter(str(mapping(row).get("host", "<missing>")) for row in rows))),
            "by_phase": clean(dict(Counter(str(mapping(row).get("phase", "<not recorded>")) for row in rows))),
            "by_tool_or_mode": clean(dict(Counter(str(mapping(row).get("tool", mapping(row).get("mode", "<missing>"))) for row in rows))),
            "all_failure_rows": clean(failed)}


def create_only(path, value):
    data = canonical(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as target:
        target.write(data)
        target.flush()
        os.fsync(target.fileno())
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return {"sha256": sha(data), "bytes": len(data)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--qualification", type=Path, required=True)
    parser.add_argument("--harness", type=Path, required=True)
    parser.add_argument("--output-summary", type=Path, required=True)
    parser.add_argument("--output-report", type=Path, required=True)
    parser.add_argument("--candidate-label", default="A25")
    args = parser.parse_args()
    if args.output_report.absolute() == args.output_summary.absolute():
        parser.error("summary and complete report must have different output paths")
    for path in (args.output_report, args.output_summary):
        if os.path.lexists(path):
            parser.error("create-only output already exists: " + str(path))
    raw, qualification_raw, harness = args.input.read_bytes(), args.qualification.read_bytes(), args.harness.read_bytes()
    report, qualification = json.loads(raw), json.loads(qualification_raw)
    if not isinstance(report, dict) or report.get("schema") != "hepta-six-running-controller-recovery/v1":
        parser.error("unsupported canary report schema")
    if not isinstance(qualification, dict):
        parser.error("qualification report must be an object")
    clean = CompleteSanitizer(report)
    checked, qualification_summary = qualification_checks(report, qualification, harness)
    hosts = mapping(report.get("hosts"))
    host_summaries = {host: summarize_host(host, hosts.get(host), report, clean) for host in HOSTS}
    native, ssh = calls_summary(report.get("native_calls"), clean), calls_summary(report.get("ssh_calls"), clean)
    retained = sequence(report.get("retained_controller_records"))
    original_ids = {(host, mapping(hosts.get(host)).get("job_id")) for host in HOSTS}
    recorded_ids = [(mapping(row).get("host"), mapping(row).get("job_id")) for row in retained]
    starts = Counter(mapping(row).get("host") for row in sequence(report.get("native_calls"))
                     if mapping(row).get("tool") == "process_start" and row.get("phase") == "launch")
    reuses = Counter(mapping(row).get("host") for row in sequence(report.get("native_calls"))
                     if mapping(row).get("tool") == "process_start" and row.get("phase") == "recover_same_original")
    crash = mapping(report.get("intentional_crash"))
    hostnames = [mapping(mapping(hosts.get(host)).get("prepare")).get("hostname") for host in HOSTS]
    checked.update({
        "raw_canary_passed": report.get("passed") is True,
        "exact_six_host_membership": set(hosts) == set(HOSTS),
        "all_host_checks_passed": all(row["checks_passed"] for row in host_summaries.values()),
        "all_native_and_ssh_calls_passed": native["calls"] > 0 and ssh["calls"] > 0 and native["failures"] == ssh["failures"] == 0,
        "normal_shutdown_passed": normal_shutdown(report.get("shutdown")) is True,
        "owned_controller_sigkill_observed": crash.get("exit_code") == -9
            and crash.get("observed_descendant_survivors") == []
            and "reader_error" in crash and crash["reader_error"] is None and crash.get("unmatched_responses") == 0,
        "six_distinct_hostnames_recorded": all(isinstance(value, str) and value for value in hostnames)
            and len(set(hostnames)) == 6,
        "six_original_controller_records_retained": len(retained) == 6 and set(recorded_ids) == original_ids
            and all(mapping(row).get("original_bytes_unchanged") is True for row in retained)
            and report.get("final_controller_record_errors") == [],
        "single_launch_and_single_reuse_per_host": report.get("new_start_call_count") == 6
            and report.get("same_key_lookup_call_count") == 6 and starts == reuses == Counter(HOSTS),
        "unchanged_inputs_and_agent": all(report.get(key) is True for key in (
            "source_originals_unchanged", "binary_unchanged", "current_agent_unchanged",
            "distinct_reported_hostnames", "controller_records_unchanged_after_shutdown")),
    })
    qualified = all(checked.values())
    provenance = {"source_report_sha256": sha(raw), "source_report_bytes": len(raw),
                  "qualification_report_sha256": sha(qualification_raw), "harness_sha256": sha(harness),
                  "builder_sha256": sha(Path(__file__).read_bytes()),
                  "base_sanitizer_sha256": sha(Path(__file__).with_name("build_x230_evidence.py").read_bytes())}
    privacy = {"encoded_payloads_decoded": False, "all_native_and_ssh_rows_retained": True,
               "all_phase_and_failure_records_retained": True, "metadata_bytes_and_sha256_retained": True,
               "redactions": ["base64 and bytes_hex payloads", "commands, arguments and raw content",
                              "private paths, hostnames, process and fixture identities", "launch nonces and credential identities"],
               "payload_receipts_hash_original_encoded_values": True}
    complete = {"schema": "hepta-six-running-sanitized-report/v1", **provenance,
                "privacy": privacy, "report": clean(report)}
    summary = {"schema": "hepta-six-running-public-evidence/v1", "candidate_label": args.candidate_label,
               "raw_report_passed": report.get("passed"), "qualified_canary": qualified, "passed": qualified,
               "phase": report.get("phase"), "verification": checked,
               "unmet_checks": [key for key, value in checked.items() if not value],
               **provenance, "qualification": qualification_summary, "hosts": host_summaries,
               "native_calls": native, "ssh_calls": ssh, "phases": clean(report.get("phases")),
               "shutdown": clean(report.get("shutdown")), "intentional_crash": clean(report.get("intentional_crash")),
               "interrupted_shutdown": clean(report.get("interrupted_shutdown")),
               "retained_controller_records": clean(retained), "final_controller_record_errors": clean(report.get("final_controller_record_errors")),
               "errors": {key: clean(report[key]) for key in ("error", "cleanup_error", "final_check_error", "report_save_error") if key in report},
               "privacy": privacy, "limitations": clean(report.get("not_covered")),
               "witness_interpretation": "Exact witness binding was checked by the measured harness; this builder compares recorded receipts without decoding payloads or rerunning the canary."}
    summary["complete_sanitized_report"] = create_only(args.output_report, complete)
    receipt = create_only(args.output_summary, summary)
    print(json.dumps({"qualified_canary": qualified, "raw_report_passed": report.get("passed"),
                      "summary": receipt, "complete_report": summary["complete_sanitized_report"],
                      "unmet_checks": summary["unmet_checks"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
