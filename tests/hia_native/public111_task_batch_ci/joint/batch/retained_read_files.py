"""Read all 926 filesystem rows and complete native/original persistent states."""
from pathlib import Path
from collections import Counter
import gzip
import hashlib
import io
import json
import os
import shutil
import stat
import struct
import sys

from receipt_support import ROOT, PIN, SHA, require, regular, read_json, exact, put
from body_observations import read_native
sys.path.insert(0, str(ROOT / "corpus/state_reference"))
import native_observations as native_state
import observations as original_state

DOMAINS = {"all_fifty": 1, "early_admission": 16, "existing_mode": 7,
    "full_five_mib_content": 1, "full_five_mib_file": 1, "missing_path": 3,
    "ordered_validation": 260, "original_endings": 232, "read_directory": 1,
    "resolved_conflict_apply": 400, "strict_invalid_utf8": 1,
    "symlink_replaced_after_followed_read": 1, "temporary_is_directory": 1,
    "temporary_name_too_long": 1}
FILES = ("requests.bin.gz", "stdout.bin.gz", "normalized.bin.gz", "filesystem.bin.gz",
         "events.jsonl.gz", "stderr.bin")


def packet(stream, maximum):
    length, = struct.unpack("<Q", exact(stream, 8))
    require(length <= maximum, "private fixture packet limit")
    return exact(stream, length)


def filesystem_group(stream, ordinal, expected):
    digest = hashlib.sha256()
    total = 0
    rows = []
    for wanted in expected:
        head = exact(stream, 16)
        hn, dn = struct.unpack("<2Q", head)
        require(0 < hn < (1 << 20) and dn <= (512 << 20), "filesystem complete span bound")
        metadata = exact(stream, hn)
        require(metadata.endswith(b"\n"), "filesystem metadata line")
        row = json.loads(metadata)
        require(row.pop("ordinal") == ordinal, "filesystem ordinal")
        raw_name = bytes.fromhex(row["path_hex"])
        require(raw_name and not raw_name.startswith(b"/") and b"\0" not in raw_name
                and all(p not in (b"", b".", b"..") for p in raw_name.split(b"/")), "filesystem raw name")
        require(row["kind"] in (stat.S_IFREG, stat.S_IFDIR, stat.S_IFLNK)
                and type(row["mode"]) is int and 0 <= row["mode"] <= 0o7777
                and type(row["links"]) is int and row["links"] >= 1, "filesystem node metadata")
        content_hash = hashlib.sha256()
        digest.update(head)
        digest.update(metadata)
        total += 16 + hn
        left = dn
        while left:
            raw = exact(stream, min(left, 1 << 20))
            digest.update(raw)
            content_hash.update(raw)
            total += len(raw)
            left -= len(raw)
        if row["kind"] == stat.S_IFREG and "read_errno" not in row:
            require(dn == row["bytes"], "complete file bytes were omitted")
            row["sha256"] = content_hash.hexdigest()
        else:
            require(dn == 0, "non-file or unreadable node supplied file bytes")
        require(row == wanted, "complete filesystem record differs")
        rows.append(row)
    end = exact(stream, 16)
    require(struct.unpack("<2Q", end) == (0, ordinal), "filesystem snapshot terminator")
    digest.update(end)
    total += 16
    require([row["path_hex"] for row in rows] == sorted(set(row["path_hex"] for row in rows)),
            "filesystem snapshot raw name order/uniqueness")
    return {"bytes": total, "sha256": digest.hexdigest()}


def read_capture(capture, *, native):
    capture = Path(capture)
    report = read_json(capture / "result.json")
    require(report["schema"] == "hepta.runtime.rebuilt-batch-callable-files.v1"
            and report["status"] == "PASS" and report["exit_code"] == 0, "file corpus completion")
    require(report["requests"] == report["body_requests"] == 926 and report["domains"] == DOMAINS,
            "full published file domain changed")
    require(report["outer_timeout_seconds"] == 180 and 0 <= report["elapsed_seconds"] < 180,
            "file corpus deadline")
    require(report["inherits_outer_process_group"] is True and report["native_thread_identity_claimed"] is False,
            "file corpus process custody")
    require(type(report["process_id"]) is int and report["process_id"] > 0
            and type(report["process_group"]) is int and report["process_group"] > 0, "file corpus process identity")
    for key in ("fresh_current_original_compared", "full_async_cancellation_qualified", "public_batch_qualified"):
        require(report[key] is False, "standalone file producer inflated scope")
    for name in FILES:
        require(PIN(regular(capture / name)) == report[name], "file corpus artifact changed: " + name)
    with gzip.open(capture / "events.jsonl.gz", "rb") as stream:
        lines = stream.read()
    require(lines.endswith(b"\n"), "incomplete file event line")
    events = [json.loads(line) for line in lines.splitlines()]
    require(len(events) == 926 and Counter(row["domain"] for row in events) == Counter(DOMAINS), "file case events")
    total_files = input_bytes = response_bytes = 0
    outcomes = Counter()
    last_snapshot = None
    with gzip.open(capture / "requests.bin.gz", "rb") as requests, \
         gzip.open(capture / "stdout.bin.gz", "rb") as responses, \
         gzip.open(capture / "normalized.bin.gz", "rb") as normalized, \
         gzip.open(capture / "filesystem.bin.gz", "rb") as filesystem:
        setup = ((b"HVCACH01" + bytes(40), b"HVCAR001" + bytes(24)),
                 (b"HHISTQ01" + bytes(56), b"HHISTR01" + bytes(56)))
        require(report["setup_frames"] == [{"input_hex": a.hex(), "output_hex": b.hex()} for a, b in setup],
                "actual initial shared state frames")
        for a, b in setup:
            require(packet(requests, 64) == a and packet(responses, 64) == b, "fixture state initialization")
            input_bytes += 8 + len(a)
            response_bytes += 8 + len(b)
        for ordinal, event in enumerate(events, 1):
            wire = packet(requests, 512 << 20)
            result = packet(responses, 0xfffeffff)
            require(event["ordinal"] == ordinal and len(wire) >= 64 and wire[:8] == b"HFBWT001",
                    "body input ordinal or header")
            context, pn, dn, count, rn, present, zero = struct.unpack_from("<7Q", wire, 8)
            require(context in (1, 2) and present in (0, 1) and zero == 0
                    and 64 + pn + dn + rn == len(wire), "complete body input fields")
            require(len(result) >= 32 and result[:8] == b"HFBWR001", "actual body response header")
            kind, length, zero = struct.unpack_from("<3Q", result, 8)
            require(kind in (0, 1) and length == len(result) - 32 and zero == 0, "complete body result span")
            result[32:].decode("utf-8")
            require((len(wire), SHA(wire), len(result), SHA(result), kind) == tuple(event[k] for k in
                ("request_bytes", "request_sha256", "response_bytes", "response_sha256", "outcome")),
                "event did not retain complete actual body input/output")
            require(exact(normalized, 12) == struct.pack("<QI", ordinal, len(result))
                    and exact(normalized, len(result)) == result, "normalized stream changed body bytes")
            last_snapshot = filesystem_group(filesystem, ordinal, event["filesystem"])
            total_files += sum(row.get("bytes", 0) for row in event["filesystem"] if "read_errno" not in row)
            input_bytes += 8 + len(wire)
            response_bytes += 8 + len(result)
            outcomes["success" if kind == 0 else "original_error"] += 1
        for stream in (requests, responses, normalized, filesystem):
            require(stream.read(1) == b"", "unindexed complete file-corpus stream suffix")
    require(dict(outcomes) == report["outcomes"] and total_files == report["observed_file_bytes"],
            "complete file corpus totals differ")
    if native:
        states = read_native(capture / "stderr.bin", 926)
    else:
        # Fully consume the strict original state/hint decoder even before a
        # comparison is requested. No replay or model is hidden in the reader.
        frames = 0
        for _ in original_states(capture / "stderr.bin", events):
            frames += 1
        require(frames == 926, "original state observations incomplete")
        states = {"operations": 926, "complete_frames": 6482,
                  "bytes": report["stderr.bin"]["bytes"], "sha256": report["stderr.bin"]["sha256"]}
    return {"status": "PASS", "body_requests": 926, "complete_input_bytes": input_bytes,
        "complete_response_bytes": response_bytes, "complete_observed_file_bytes": total_files,
        "state_observations": states, "last_filesystem_group": last_snapshot,
        "reader_process_launches": 0, "public_batch_qualified": False}, events


def original_frame(stream, magic):
    header = exact(stream, 16)
    require(header[:8] == magic, "original observer frame order")
    size, = struct.unpack_from("<Q", header, 8)
    require(16 <= size <= (512 << 20), "original observer complete extent")
    return header + exact(stream, size - 16)


def original_states(path, events):
    with Path(path).open("rb") as stream:
        for generation, event in enumerate(events, 1):
            states = {}
            for phase in (0, 1):
                if phase == 1:
                    raw = original_frame(stream, b"HLBBHT01")
                    require(len(raw) >= 48, "original hint extent")
                    size, gen, op, kind, count = struct.unpack_from("<5Q", raw, 8)
                    require((size, gen, op, kind, count) == (48, generation, 1, event["outcome"], 0)
                            and len(raw) == 48, "original Batch unexpectedly published a hint")
                for name, magic, parse in (("cache", b"HLCSCS01", original_state.cache),
                        ("history", b"HLTBHS01", original_state.history),
                        ("locks", b"HLTBLK01", original_state.locks)):
                    value = parse(original_frame(stream, magic))
                    require(value["phase"] == phase, "original state phase")
                    if name != "cache":
                        require(value["generation"] == generation, "original state generation")
                    if name == "locks":
                        require(all(n == 1 for n in value["entries"].values()), "original return retained a file lock")
                    states[phase, name] = value
            yield states
        require(stream.read(1) == b"", "unindexed original observer suffix")


def native_states(path):
    with Path(path).open("rb") as stream:
        for generation in range(1, 927):
            states = {}
            for phase in (0, 1):
                for owner, name, parse in ((7, "locks", native_state.locks),
                        (3, "history", native_state.history), (5, "cache", native_state.cache)):
                    head = exact(stream, 64)
                    magic, size, p, gen, slot, cap, z0, z1 = struct.unpack("<8s7Q", head)
                    require(magic == b"HLBBNA01" and (p, gen, slot) == (phase, generation, owner)
                            and size == 64 + cap and not (z0 or z1)
                            and 4096 <= cap <= 1207959552 and cap % 4096 == 0, "native complete state frame")
                    states[phase, name] = parse(exact(stream, cap), phase, generation)
            yield states
        require(stream.read(1) == b"", "unindexed native observer suffix")


def same_stream(a, b):
    count = 0
    with gzip.open(a, "rb") as left, gzip.open(b, "rb") as right:
        while True:
            x, y = left.read(1 << 20), right.read(1 << 20)
            require(x == y, "complete original/native stream differs: " + Path(a).name)
            count += len(x)
            if not x:
                return count


def compare(native, original):
    native, original = Path(native), Path(original)
    n, nevents = read_capture(native, native=True)
    r, revents = read_capture(original, native=False)
    nr, rr = read_json(native / "result.json"), read_json(original / "result.json")
    require(nr["fixture"] == rr["fixture"] and nr["effective_uid"] == rr["effective_uid"],
            "the two bodies did not run at the same actual path/permission identity")
    require(nevents == revents, "complete original/native file event rows differ")
    total = sum(same_stream(native / name, original / name) for name in FILES[:-1])
    comparisons = 0
    for ordinal, (left, right) in enumerate(zip(native_states(native / "stderr.bin"),
            original_states(original / "stderr.bin", revents), strict=True), 1):
        require(left == right, "complete actual cache/history/lock state differs at operation " + str(ordinal))
        comparisons += 6
    require(comparisons == 5556, "persistent state comparison incomplete")
    return {"status": "PASS", "body_requests_per_side": 926, "complete_stream_comparison_bytes": total,
        "complete_persistent_state_comparisons": comparisons,
        "native_state_bytes": n["state_observations"]["bytes"],
        "original_state_bytes": r["state_observations"]["bytes"],
        "all_returned_locks_quiescent": True, "same_actual_fixture_path": True,
        "all_original_hint_observations_empty": True, "reader_process_launches": 0,
        "public_batch_qualified": False, "full_async_cancellation_qualified": False,
        "remote_sftp_qualified": False, "whole_runtime_replaced": False}


def retire(capture, fixture):
    capture, fixture = Path(capture), Path(fixture).absolute()
    report = read_json(capture / "result.json")
    require(report["fixture"] == str(fixture) and fixture.is_dir()
            and not fixture.is_symlink() and fixture.resolve() == fixture, "exact fixture retirement ownership")
    proof, events = read_capture(capture, native=report["stderr.bin"]["bytes"] > 0
        and regular(capture / "stderr.bin")[:8] == b"HLBBNA01")
    from qualify_files import inventory
    current = io.BytesIO()
    rows, _ = inventory(fixture, current, 926)
    raw = current.getvalue()
    require(rows == events[-1]["filesystem"] and PIN(raw) == proof["last_filesystem_group"],
            "actual fixture changed after its complete final archive")
    path = capture / "final-filesystem.bin.gz"
    require(not path.exists(), "fixture already archived")
    with gzip.open(path, "xb", compresslevel=1) as stream:
        stream.write(raw)
    with gzip.open(path, "rb") as stream:
        require(filesystem_group(stream, 926, events[-1]["filesystem"]) == PIN(raw)
                and stream.read(1) == b"", "complete final archive reread failed")
    # Only the just-created, exact admitted fixture directory is retired. Every
    # retained byte, mode, raw name and symlink target above was checked first.
    for current, directories, _ in os.walk(fixture, topdown=True, followlinks=False):
        os.chmod(current, 0o700)
        directories[:] = [name for name in directories if not (Path(current) / name).is_symlink()]
    shutil.rmtree(fixture)
    receipt = {"status": "RETIRED_AFTER_COMPLETE_ARCHIVE_READBACK", "fixture": str(fixture),
        "body_requests": 926, "archive": dict(path=path.name, **PIN(regular(path))),
        "complete_final_group": PIN(raw), "reader_process_launches": 0}
    put(capture / "retirement.json", receipt)
    return receipt


def check_retired(capture):
    capture = Path(capture)
    report = read_json(capture / "result.json")
    receipt = read_json(capture / "retirement.json")
    require(receipt["status"] == "RETIRED_AFTER_COMPLETE_ARCHIVE_READBACK"
            and receipt["fixture"] == report["fixture"] and receipt["body_requests"] == 926
            and receipt["reader_process_launches"] == 0,
            "retirement receipt")
    require(receipt["archive"] == dict(path="final-filesystem.bin.gz", **PIN(regular(capture / "final-filesystem.bin.gz"))),
            "retirement archive bytes")
    with gzip.open(capture / "events.jsonl.gz", "rb") as stream:
        final = json.loads(stream.read().splitlines()[-1])
    with gzip.open(capture / "final-filesystem.bin.gz", "rb") as stream:
        require(filesystem_group(stream, 926, final["filesystem"]) == receipt["complete_final_group"]
                and stream.read(1) == b"", "retired complete files differ")
    return receipt
