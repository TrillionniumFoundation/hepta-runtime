#!/usr/bin/env python3
"""Extract two overflow error fixtures from the completed B2 public MCP transcript.

This is an offline, create-only extractor. It starts no REA, native runtime,
debuggee, compiler or device. Original request/response bytes remain unchanged.
"""
from __future__ import annotations
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import stat

PINS = {
    "summary": ("candidate-b2-imports-r1/summary.json", "28de1d2f391ed1014b5adcf1f29aeb5c5727cede73f646aff4358aeb63df9c5f"),
    "profile": ("candidate-b2-import22-r1/qualification.json", "3a297628838b70f154bdc119f1ef2d767b0a606f7d42eb30be6b3e0abfd9230d"),
    "audit": ("candidate-b2-imports-r1/import22-raw-audit.json", "90c377d15dd740c8b0add911418ac5315713cdf93eec7dd26bac34d4c4c59ecc"),
    "outer": ("qualification-fixed-b2-r1/imports-outer-terminal.json", "04ae16f7ed1fd1de9b2f9718e4a469d965ee4734d41228163754147f354f569b"),
}
CASES = ("producer/body-overflow", "import/bundle-overflow")
SNAPSHOTS = {}


def require(value, why):
    if not value:
        raise ValueError(why)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def stamp(meta):
    return tuple(getattr(meta, key) for key in
                 ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns"))


def read(path, maximum=16 * 1024 * 1024):
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and before.st_size <= maximum, "unbounded or nonregular input")
        raw = stream.read(maximum + 1)
        require(stamp(before) == stamp(os.fstat(stream.fileno())) == stamp(path.lstat())
                and len(raw) == before.st_size, "input changed during read")
    identity = dict(path=str(path), bytes=len(raw), sha256=sha(raw))
    previous = SNAPSHOTS.setdefault(str(path), identity)
    require(previous == identity, "previously consumed input changed")
    return raw


def identity(path):
    raw = read(path)
    return dict(path=str(path), bytes=len(raw), sha256=sha(raw))


def parse(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate JSON member")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs)


def pinned(root, name):
    relative, digest = PINS[name]
    path = root / relative
    raw = read(path)
    require(sha(raw) == digest, "fixed " + name + " changed")
    return parse(raw), identity(path)


def recover(path, entry, maximum=65536):
    require(type(entry["raw_bytes"]) is int and 0 <= entry["raw_bytes"] <= maximum,
            "selected raw artifact exceeds its allowance")
    compressed = read(path, maximum + 65536)
    require(len(compressed) == entry["gzip_bytes"] and sha(compressed) == entry["gzip_sha256"],
            "compressed artifact differs")
    with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as stream:
        raw = stream.read(maximum + 1)
    require(len(raw) == entry["raw_bytes"] and sha(raw) == entry["raw_sha256"],
            "raw bytes differ from original manifest")
    return raw


def wire(directory, entry):
    require(entry["encoding"] == "gzip-original-jsonrpc-line"
            and Path(entry["path"]).name == entry["path"], "invalid frame member")
    raw = recover(directory / entry["path"], entry)
    require(raw.endswith(b"\n") and raw.count(b"\n") == 1, "not one complete JSONRPC line")
    message = parse(raw)
    require(message.get("jsonrpc") == "2.0", "not a JSONRPC frame")
    return raw, message


def session_call(profile, root, label, scenario, case_id):
    directory = root / (label + "-" + scenario)
    state = profile["sessions"][label + "/" + scenario]
    rows = [row for row in state["rows"] if row["id"] == case_id]
    require(len(rows) == 1, "selected case absent or duplicated")
    artifact = rows[0]["artifact"]
    path = Path(artifact["path"])
    require(path.parent == directory and path.name.startswith("call-"), "row path escapes session")
    row = parse(recover(path, artifact))
    require(row["id"] == case_id, "row ID differs")
    entries = [parse(line) for line in read(directory / "wire.jsonl").splitlines()]
    require(len(entries) < 1000 and len({x["path"] for x in entries}) == len(entries),
            "invalid bounded transcript")
    response_id = row["response"]["id"]
    requests = []
    responses = []
    initialization = {}
    for entry in entries:
        # All requests are short and have no embedded target bytes. Large
        # unrelated successful responses are left untouched.
        if entry["direction"] == "sent":
            raw, message = wire(directory, entry)
            if message.get("method") == "initialize":
                initialization["request"] = dict(entry=entry, raw_hex=raw.hex())
                initialization["request_id"] = message["id"]
            if message.get("id") == response_id:
                requests.append((entry, raw, message))
        elif entry["direction"] == "received" and entry["raw_bytes"] <= 65536:
            raw, message = wire(directory, entry)
            if message.get("id") == response_id:
                responses.append((entry, raw, message))
            if message.get("id") == initialization.get("request_id"):
                initialization["response"] = dict(entry=entry, raw_hex=raw.hex())
                initialization["protocol_version"] = message["result"]["protocolVersion"]
    require(len(requests) == len(responses) == 1, "request/response association differs")
    request_entry, request_raw, request = requests[0]
    response_entry, response_raw, response = responses[0]
    require(request["method"] == "tools/call" and request["params"]["arguments"] == row["arguments"]
            and response == row["response"], "row is not the actual public frame")
    require("request" in initialization and "response" in initialization, "missing negotiation")
    close = state["close"]
    require(close["returncode"] == 0 and close["forced_cleanup"] == [] and close["reader_stopped"]
            and close["owner_pidfd_exited"] and close["process_group_gone"], "incomplete MCP owner cleanup")
    require(parse(read(directory / "close.json")) == close, "close receipt differs")
    return dict(operation=row["operation"], arguments=row["arguments"],
                request_wire_hex=request_raw.hex(), response_wire_hex=response_raw.hex(),
                request_wire_record=request_entry, response_wire_record=response_entry,
                row_artifact=identity(path), wire_manifest=identity(directory / "wire.jsonl"),
                close=close, initialization=initialization), response


def verify_outer(outer, summary_pin):
    job = outer["start"]["job"]["id"]
    terminal = outer["status"]
    require(job == terminal["job_id"] == "1a1af68713e-fc05-6843"
            and terminal["state"] == "failed" and terminal["exit_code"] == 1,
            "the actual B2 two-error RED must remain RED")
    require(all(terminal[name] for name in ("output_complete", "output_durable", "terminal_publication_confirmed"))
            and not any(terminal[name] for name in ("automatic_retry", "timed_out", "cancelled")),
            "outer terminal is incomplete")
    streams = {}
    for name in ("stdout", "stderr"):
        cursor, blocks = 0, []
        for page in outer["reads"]:
            response, request = page["response"], page["request"]
            data = bytes.fromhex(response[name]["bytes_hex"])
            require(request["job_id"] == response["job_id"] == job
                    and request[name + "_offset"] == response[name]["offset"] == cursor
                    and response[name]["next_offset"] == cursor + len(data), "outer cursor mismatch")
            cursor += len(data)
            blocks.append(data)
        require(terminal["log_bytes"][name] == dict(seen=cursor, stored=cursor)
                and terminal["log_synced"][name] and not terminal["log_truncated"][name]
                and terminal["log_errors"][name] is None, "outer log custody differs")
        streams[name] = b"".join(blocks)
    require(streams["stderr"] == b"" and parse(streams["stdout"].splitlines()[-1])["receipt"] == summary_pin,
            "outer stdout does not bind this summary")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    require(args.evidence_root.is_absolute() and args.output.is_absolute(), "absolute paths required")
    require(not args.output.exists(), "fixture output is create-only")
    summary, summary_pin = pinned(args.evidence_root, "summary")
    profile, profile_pin = pinned(args.evidence_root, "profile")
    audit, audit_pin = pinned(args.evidence_root, "audit")
    outer, outer_pin = pinned(args.evidence_root, "outer")
    verify_outer(outer, summary_pin)
    require(summary["source_commit"] == "6c224e4d913dd596e44fb936e22b447531f8962b"
            and summary["source_git_tree"] == "5d75e3bfdcaa20b43b4f170288b4221ceb9040ad"
            and summary["runtime"]["sha256"] == "170117339fdeeb6632a6df545fbfba4fce8254f41dd763b55df6b38cee57858f"
            and summary["errors"] == [] and summary["passed"] is False, "candidate/result identity differs")
    require(profile["binary_before"] == profile["binary_after"] == summary["runtime"]
            and profile["reference_before"] == profile["reference_after"]
            and profile["errors"] == [] and profile["source_unchanged"], "producer custody differs")
    require(profile["reference_before"]["version"] == "6.8.0"
            and profile["reference_before"]["file_count"] == 2398
            and profile["reference_before"]["files_sha256"] == "8f5a44ea76e5d93b27f8882d902e9449d7f41895e5428c213fe6ed3619592891"
            and profile["node"]["sha256"] == "94efd062ed066c1a0b332e18249859c905e920eeada5df55d24c99b919629a90",
            "fixed original identity differs")
    require(audit["denominator"] == 22 and audit["passed_comparisons"] == 20
            and [row["id"] for row in audit["cases"] if row["status"] != "PASS"] == list(CASES),
            "actual remaining failures differ")
    root = args.evidence_root / "candidate-b2-import22-r1"
    fixture = dict(schema="hepta.rea.overflow-error-text.original.v1", qualified=False,
                   scope="Two actual original/native public MCP error frames; no new execution or full raw-frame equivalence.",
                   provenance=dict(extractor=identity(Path(__file__).resolve()), wrapper_summary=summary_pin,
                                   qualification=profile_pin, raw_audit=audit_pin, outer_terminal=outer_pin,
                                   source_commit=summary["source_commit"], source_git_tree=summary["source_git_tree"],
                                   runtime=summary["runtime"], node=profile["node"],
                                   reference_package=profile["reference_before"], original_red_preserved=True),
                   cases=[], inputs=[], setup=[])
    apk = profile["fixture"]
    require(identity(Path(apk["path"])) == apk, "authored APK changed")
    fixture["inputs"].append(apk)
    seed = profile["sessions"]["reference/producer"]["exports"]["seed-export"]
    require(seed == profile["sessions"]["native/producer"]["exports"]["seed-export"]
            and identity(Path(seed["path"])) == seed, "same public seed export changed")
    fixture["inputs"].append(seed)
    for case_id in CASES:
        scenario, short = case_id.split("/")
        captures, responses = {}, {}
        for label in ("reference", "native"):
            captures[label], responses[label] = session_call(profile, root, label, scenario, short)
        require(captures["reference"]["operation"] == captures["native"]["operation"]
                and captures["reference"]["arguments"] == captures["native"]["arguments"], "paired inputs differ")
        old = responses["reference"]["result"]["content"][0]["text"]
        new = responses["native"]["result"]["content"][0]["text"]
        require(parse(old) == parse(new) and old != new, "expected actual presentation-only regression absent")
        error = parse(old)["error"]
        limits = error["details"]["reported_limits"]
        require(error["details"]["operation"] == captures["reference"]["operation"], "error operation differs")
        fixture["cases"].append(dict(id=case_id, operation=captures["reference"]["operation"],
            arguments=captures["reference"]["arguments"], reference=captures["reference"], native=captures["native"],
            measurement=dict(response_bytes=10485760, bytes_at_least=limits["response_bytes_at_least"],
                             code_units_at_least=limits["response_code_units_at_least"], constraint=limits["constraint"]),
            retained=limits.get("evidence_reference"), bundle_summary=False))
    require(fixture["cases"][0]["arguments"]["path"] == apk["path"], "APK request is not the bound input")
    for label in ("reference", "native"):
        setup, _response = session_call(profile, root, label, "import", "public-import")
        require(setup["arguments"]["path"] == seed["path"], "import request is not the bound seed")
        fixture["setup"].append(dict(label=label, call=setup, seed_input=seed))
    for observed in list(SNAPSHOTS.values()):
        require(identity(Path(observed["path"])) == observed, "consumed input changed")
    raw = (json.dumps(fixture, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False) + "\n").encode()
    require(len(raw) <= 128 * 1024, "fixture exceeds its small regression allowance")
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    directory = os.open(args.output.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    print(json.dumps(dict(fixture=identity(args.output), cases=2, native_executed=False,
                          original_executed=False, original_red_preserved=True)), flush=True)


if __name__ == "__main__":
    main()
