#!/usr/bin/env python3
"""Read-only verification of the frozen R31 original native receipt companion.

No archive is extracted, no archived code is executed, and no native workload
is submitted. The optional receipt output is create-only.
"""
import argparse
import datetime
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import tarfile


ARCHIVE_SHA = "451ad971ab9d1d05db6c0ee6a201edf8d6383134a2730b35f694ce239f1e379e"
MANIFEST_SHA = "45cbf30d8d049d77169ad54dda537aef6002cbc613b117f3b3370b7a1aa19588"
SUMMARY_SHA = "7e388326114b5be8abfc835cead435de0c597e8b2124442d4e293360937208d6"
SOURCE_MAP_SHA = "a4c654bd8b5057fb6884c36172b198eedcfcddab8e2b291155a4e73146707a3f"
QUALIFICATION_ARCHIVE_SHA = "f802c5fed5e3b79773825a12cbe9c888570e3ea19f954009857350e93c8071d2"
ORIGINAL_MEMBER_ROOT = PurePosixPath(
    "/workspace/scratch/806ba5f52f94/r31-review-root-operations-01/native-originals-companion-01"
)
COUNTS = {"passed": 1653, "failed": 0, "ignored": 34, "selected": 1687, "retries": 0}
EXPECTED_JOBS = {
    "preparation-attempt-01": ("1a1ae1597f5-fc05-5d3e", "failed", 1, 161, 656),
    "qualification-v2": ("1a1ae1c32b8-fc05-5d7a", "succeeded", 0, 1110, 0),
    "component-01": ("1a1adfb2959-fc05-5c58", "succeeded", 0, 125, 0),
}
STAGES = ["format", "fmt-check", "harness-tests", "clippy", "test-build",
          "isolated-tests", "audit-isolated-tests", "release"]


def need(value, reason):
    if not value:
        raise ValueError(reason)


def digest(body):
    return hashlib.sha256(body).hexdigest()


def identity(body):
    return {"bytes": len(body), "sha256": digest(body)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--qualification-archive", type=Path, required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()

    original = args.archive.read_bytes()
    need(len(original) == 18855 and digest(original) == ARCHIVE_SHA, "frozen companion identity differs")
    contents = {}
    with tarfile.open(args.archive, "r:gz") as archive:
        for member in archive.getmembers():
            path = PurePosixPath(member.name)
            need(member.isfile() and not path.is_absolute() and ".." not in path.parts
                 and path.as_posix() == member.name and member.name not in contents,
                 "nonregular, unsafe, or duplicate companion member")
            need(0 <= member.size <= 65536, "oversized companion member")
            body = archive.extractfile(member).read()
            need(len(body) == member.size, "short companion member")
            contents[member.name] = body
    need(len(contents) == 20 and sum(map(len, contents.values())) == 60982,
         "frozen companion inventory differs")
    need(identity(contents["manifest.json"]) == {"bytes": 11301, "sha256": MANIFEST_SHA},
         "frozen manifest identity differs")
    manifest = json.loads(contents["manifest.json"])
    need(manifest["schema"] == "hepta-r31-native-originals-companion/v1", "manifest schema differs")

    referenced = set()

    def bound(entry, member_name=None):
        if member_name is None:
            path = PurePosixPath(entry["path"])
            need(path.is_relative_to(ORIGINAL_MEMBER_ROOT), "manifest artifact outside fixed member root")
            member_name = path.relative_to(ORIGINAL_MEMBER_ROOT).as_posix()
        need(member_name in contents, "missing manifest member: " + member_name)
        body = contents[member_name]
        need(identity(body) == {"bytes": entry["bytes"], "sha256": entry["sha256"]},
             "member identity differs: " + member_name)
        referenced.add(member_name)
        return body

    jobs = manifest["original_native_jobs"]
    need(len(jobs) == 3 and {row["label"] for row in jobs} == set(EXPECTED_JOBS), "job inventory differs")
    job_receipts = []
    terminals = {}
    raw_logs = {}
    for row in jobs:
        label = row["label"]
        job_id, state, exit_code, stdout_bytes, stderr_bytes = EXPECTED_JOBS[label]
        need((row["job_id"], row["host"], row["state"], row["exit_code"])
             == (job_id, "x230", state, exit_code), "manifest job identity differs")
        terminal_body = bound(row["native_terminal_exact_content_text"])
        terminal = json.loads(terminal_body)
        terminals[label] = terminal
        need(terminal["job_id"] == job_id and terminal["state"] == state and terminal["exit_code"] == exit_code,
             "terminal job result differs")
        for key in ("audit_recorded", "output_complete", "output_durable", "terminal_publication_confirmed"):
            need(terminal[key] is True, "incomplete or nondurable terminal: " + key)
        for key in ("automatic_retry", "cancelled", "timed_out"):
            need(terminal[key] is False, "terminal has retry/cancellation/timeout: " + key)
        need(terminal["terminal_publication_protocol"] == 1, "terminal protocol differs")
        envelope = json.loads(bound(row["native_status_envelope"]))
        expected_keys = {"file", "request", "result"}
        if label != "component-01":
            expected_keys.add("tool")
        need(set(envelope) == expected_keys
             and ("tool" not in envelope or envelope["tool"]
                  == "mcp__codex_apps__heptaruntime_mac_controller_process_status")
             and envelope["request"] == {"host": "x230", "job_id": job_id}
             and envelope["result"]["isError"] is False, "status envelope identity differs")
        blocks = envelope["result"]["content"]
        need(len(blocks) == 1 and blocks[0]["type"] == "text"
             and blocks[0]["text"].encode("utf-8") == terminal_body,
             "terminal bytes differ from original status content.text")
        reads = []
        for entry in row["original_read_envelopes"]:
            read_envelope = json.loads(bound(entry))
            need(read_envelope["request"]["host"] == "x230"
                 and read_envelope["request"]["job_id"] == job_id
                 and read_envelope["result"]["isError"] is False, "read envelope identity differs")
            read_blocks = read_envelope["result"]["content"]
            need(len(read_blocks) == 1 and read_blocks[0]["type"] == "text", "read envelope content differs")
            result = json.loads(read_blocks[0]["text"])
            need(result["job_id"] == job_id and result["audit_recorded"] is True, "read job/audit differs")
            reads.append((read_envelope["request"], result))
        streams = {}
        raw_logs[label] = {}
        for stream_name, expected_size in (("stdout", stdout_bytes), ("stderr", stderr_bytes)):
            stream = row["streams"][stream_name]
            stored = bound(stream["artifact"])
            need(len(stored) == expected_size and stream["complete_to_terminal_bytes"] is True,
                 "manifest stream completeness differs")
            need(terminal["log_bytes"][stream_name] == {"seen": expected_size, "stored": expected_size}
                 and terminal["log_errors"][stream_name] is None
                 and terminal["log_synced"][stream_name] is True
                 and terminal["log_truncated"][stream_name] is False,
                 "terminal stream retention differs")
            offset = 0
            pieces = []
            ranges = []
            for request, result in reads:
                chunk = result[stream_name]
                body = bytes.fromhex(chunk["bytes_hex"])
                need(request[stream_name + "_offset"] == offset == chunk["offset"]
                     and chunk["next_offset"] == offset + len(body)
                     and chunk["next_offset"] <= chunk["size"]
                     and (not chunk["eof"] or chunk["next_offset"] == chunk["size"]),
                     "noncontiguous or inconsistent original stream range")
                need(chunk["text"].encode("utf-8") == body, "original text and byte representations differ")
                ranges.append({"offset": offset, "next_offset": chunk["next_offset"],
                    "eof_at_that_read": chunk["eof"], "observed_stream_size_at_read": chunk["size"],
                    "bytes": len(body), "sha256": digest(body)})
                pieces.append(body)
                offset = chunk["next_offset"]
            need(ranges == stream["ranges"] and b"".join(pieces) == stored and offset == expected_size,
                 "original stream reconstruction differs")
            need(reads[-1][1][stream_name]["eof"] is True
                 and reads[-1][1][stream_name]["size"] == expected_size,
                 "last read does not cover final durable stream")
            raw_logs[label][stream_name] = stored
            streams[stream_name] = dict(identity(stored), ranges=len(ranges),
                contiguous_from_zero=True, matches_original_hex_and_text=True,
                matches_final_seen_and_stored=True)
        job_receipts.append({"label": label, "job_id": job_id, "host": "x230", "state": state,
            "exit_code": exit_code, "terminal_exact_content_text": identity(terminal_body),
            "original_status_envelope_bytes_match": True,
            "original_status_envelope_has_tool_name_field": "tool" in envelope,
            "output_complete": True,
            "output_durable": True, "automatic_retry": False, "streams": streams})

    qualification_lines = [json.loads(line) for line in raw_logs["qualification-v2"]["stdout"].splitlines()]
    need(len(qualification_lines) == 18, "qualification stdout row count differs")
    exits = []
    for index, stage in enumerate(STAGES):
        start, end = qualification_lines[index * 2:index * 2 + 2]
        need(start == {"stage": stage, "state": "started"} and end["stage"] == stage
             and end["exit"] == 0 and end["seconds"] > 0, "qualification stage sequence differs")
        exits.append(end)
    qualified_job = next(row for row in jobs if row["label"] == "qualification-v2")
    need(exits == qualified_job["eight_original_stages"]
         and qualification_lines[-2]["qualified"] is True
         and qualification_lines[-2]["error"] is None
         and qualification_lines[-1]["passed"] is True
         and qualification_lines[-1]["qualification_returncode"] == 0
         and qualification_lines[-1]["error"] is None, "qualification completion rows differ")
    initial_prep = json.loads(raw_logs["preparation-attempt-01"]["stdout"])
    need(initial_prep["passed"] is False and initial_prep["qualification_returncode"] is None
         and initial_prep["error"] == "PermissionError: [Errno 13] Permission denied: '/proc/3766/cwd'",
         "original failed preparation differs")
    component = json.loads(raw_logs["component-01"]["stdout"])
    need(component["passed"] is True and component["samples"] == 62 and component["cleanup_kills"] == 0,
         "original component completion differs")

    for name, entry in manifest["qualification_summary_and_final_source_map"].items():
        bound(entry, name)
    need(referenced | {"manifest.json", "README.md"} == set(contents)
         and len(referenced) == 18, "extra or unbound companion artifact")
    need(digest(contents["isolated-summary-original.json"]) == SUMMARY_SHA
         and digest(contents["qualified-source-map-original.json"]) == SOURCE_MAP_SHA,
         "frozen summary/source map identity differs")
    summary = json.loads(contents["isolated-summary-original.json"])
    source_map = json.loads(contents["qualified-source-map-original.json"])
    need({key: summary[key] for key in COUNTS} == COUNTS == manifest["qualified_summary_counts"]
         and summary["success"] is True and summary["filter"] == ""
         and summary["enumeration_errors"] == [], "qualified summary counts/scope differ")
    need(sum(row["inventory_count"] for row in summary["binaries"]) == COUNTS["selected"]
         and sum(len(row["ignored_names"]) for row in summary["binaries"]) == COUNTS["ignored"],
         "summary binary inventories do not support selected/ignored counts")
    need(summary["source_manifest_sha256"] == SOURCE_MAP_SHA and len(source_map) == 222,
         "summary source binding differs")
    for name, expected_sha in source_map.items():
        path = PurePosixPath(name)
        need(not path.is_absolute() and ".." not in path.parts
             and re.fullmatch(r"[0-9a-f]{64}", expected_sha), "unsafe source map entry")
        file = args.source.joinpath(*path.parts)
        need(file.is_file() and not file.is_symlink() and digest(file.read_bytes()) == expected_sha,
             "local qualified compiler input differs: " + name)

    qualification_archive = args.qualification_archive.read_bytes()
    need(digest(qualification_archive) == QUALIFICATION_ARCHIVE_SHA, "qualification archive identity differs")
    with tarfile.open(args.qualification_archive, "r:gz") as archive:
        for local_name, archived_name in (
            ("isolated-summary-original.json", "qualification-01/isolated-tests/summary.json"),
            ("qualified-source-map-original.json", "qualification-01/source-map.json"),
        ):
            need(archive.extractfile(archived_name).read() == contents[local_name],
                 "companion differs from original qualification archive: " + local_name)
        for label, archived_name in (
            ("qualification-v2", "qualification-terminal-status-01.json"),
            ("preparation-attempt-01", "preparation-attempt-01-native.json"),
        ):
            need(json.load(archive.extractfile(archived_name)) == terminals[label],
                 "original terminal semantics differ across archives: " + label)

    result = {
        "schema": "hepta-r31-native-originals-independent-verification/v1",
        "verified_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "passed": True,
        "archive": dict(identity(original), filename=args.archive.name),
        "manifest": dict(identity(contents["manifest.json"]), member="manifest.json"),
        "members": [dict(identity(body), path=name) for name, body in sorted(contents.items())],
        "regular_members": len(contents), "expanded_bytes": sum(map(len, contents.values())),
        "manifest_bound_members": len(referenced),
        "archive_digest_covers_manifest_and_readme": True,
        "original_native_jobs": job_receipts,
        "original_qualification_stages": exits,
        "qualified_summary_counts": COUNTS,
        "qualified_source_map": dict(identity(contents["qualified-source-map-original.json"]),
            compiler_input_count=len(source_map), local_compiler_input_hashes_equal=True),
        "original_qualification_archive": dict(identity(qualification_archive),
            filename=args.qualification_archive.name, summary_and_source_map_bytes_equal=True,
            qualification_and_failed_preparation_terminal_objects_equal=True),
        "verification_scope": {
            "local_reads_only": True,
            "archive_extracted": False,
            "archive_code_executed": False,
            "native_workload_submitted": False,
            "test_or_benchmark_rerun": False,
            "full_per_case_qualification_audit_replayed": False,
            "whole_runtime_performance_established": False,
            "saturated_cancellation_established": False,
            "hosted_actions_passed": False,
        },
        "verifier": dict(identity(Path(__file__).read_bytes()), filename=Path(__file__).name),
    }
    output = (json.dumps(result, sort_keys=True, indent=2) + "\n").encode()
    if args.out:
        with args.out.open("xb") as stream:
            stream.write(output)
    print(json.dumps({"passed": True, "archive_sha256": ARCHIVE_SHA,
        "regular_members": len(contents), "expanded_bytes": sum(map(len, contents.values())),
        "native_jobs": len(jobs), "qualification_stages": len(exits),
        "qualified_summary_counts": COUNTS, "qualified_compiler_inputs": len(source_map),
        "receipt": str(args.out) if args.out else None, "receipt_sha256": digest(output)}))


if __name__ == "__main__":
    main()
