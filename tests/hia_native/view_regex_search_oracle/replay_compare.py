"""Compare retained search bytes and observations, without search semantics.

This comparison must be paired with the native producer's admission. It does
not establish that arbitrary files supplied as a corpus came from an ELF.
"""
from __future__ import annotations

import gzip
import importlib.util
import json
import math
from pathlib import Path

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("_search_compare_cases", ROOT / "cases.py")
cases = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cases)


def require(condition, detail):
    if not condition:
        raise AssertionError(detail)


def _object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate evidence JSON key")
        result[key] = value
    return result


def _finite(value):
    if type(value) is float:
        require(math.isfinite(value), "nonfinite evidence number")
    elif type(value) is dict:
        for item in value.values():
            _finite(item)
    elif type(value) is list:
        for item in value:
            _finite(item)


def json_value(raw):
    value = json.loads(raw, object_pairs_hook=_object,
        parse_constant=lambda token: (_ for _ in ()).throw(AssertionError("nonfinite JSON")))
    _finite(value)
    return value


def inside(root, relative):
    require(type(relative) is str and relative, "artifact path must be nonempty text")
    rel = Path(relative)
    require(not rel.is_absolute() and all(part not in (".", "..") for part in rel.parts),
            "artifact escapes corpus")
    root = root.resolve()
    path = root
    for part in rel.parts:
        path = path / part
        require(not path.is_symlink(), "artifact path contains symlink")
    require(path.is_file() and path.resolve().is_relative_to(root), "artifact is not a regular file")
    return path


def captured(root, relative):
    with gzip.open(inside(root, relative), "rb") as stream:
        return stream.read()


def rows(path):
    result = {}
    for encoded in path.read_bytes().split(b"\n"):
        if not encoded:
            continue
        row = json_value(encoded)
        cid = row["case_id"]
        require(type(cid) is int and cid not in result, "duplicate or noninteger native case id")
        result[cid] = row
    return result


def compare_case(corpus, native, original, request):
    expected_input = cases.encode_cases([request])
    meta, blobs = original["metadata"], original["blobs"]
    cid = request["metadata"]["case_id"]
    require(native["case_id"] == meta["case_id"] == cid, "case identity mismatch")
    require(meta["name"] == request["metadata"]["name"], "original case name differs")
    require(captured(corpus, native["input_path"]) == expected_input,
            f"{cid}: complete independent input differs")
    counts = dict(body_bytes=0, base_bytes=0, cache_bytes=0,
                  read_snapshot_bytes=0, cancelled_base_bytes=0, logical_io=0)
    outcome = meta["outcome"]
    cancelled = outcome.get("cancelled", False)
    require(type(cancelled) is bool and cancelled == request["metadata"]["cancel_after_render"],
            "original cancellation differs")
    require(type(native["cancelled"]) is bool and native["cancelled"] == cancelled,
            "native cancellation differs")
    body = captured(corpus, native["body_path"])
    if cancelled:
        require(body == b"" and outcome["publication_bytes"] == 0,
                "cancelled search published bytes")
        before = meta["before_cancel"]
        expected_base = blobs[before["blob"]] if before["ok"] else before["error"].encode()
        expected_status = 0 if before["ok"] else 1
        counts["cancelled_base_bytes"] = len(expected_base)
    else:
        require(type(native["ok"]) is bool and native["ok"] is outcome["ok"],
                "result success type/value differs")
        require(body == blobs[outcome["blob"]], f"{cid}: complete visible body differs")
        counts["body_bytes"] = len(body)
        expected_status = 0 if outcome["ok"] else 1
        expected_base = blobs[meta["rendered"]["blob"]] if outcome["ok"] else body
    require(type(native["after_render_status"]) is int and
            native["after_render_status"] == expected_status, "result gate status differs")
    require(captured(corpus, native["after_render_path"]) == expected_base,
            f"{cid}: complete base after result gate differs")
    counts["base_bytes"] = len(expected_base)
    for name in ("cache_before", "cache_after"):
        require(len(native[name]) == len(meta[name]), "cache probe count differs")
        for actual, reference in zip(native[name], meta[name]):
            require(actual["path_hex"] == reference["path_hex"] and
                    type(actual["present"]) is bool and actual["present"] is reference["present"],
                    "cache probe identity/presence differs")
            if reference["present"]:
                raw = captured(corpus, actual["content_path"])
                require(raw == blobs[reference["blob"]], f"{cid}: complete cached value differs")
                counts["cache_bytes"] += len(raw)
            else:
                require(actual.get("content_path") is None, "absent cache probe has content")
    original_io = [event for event in meta["events"] if event["kind"] == "io"]
    require(len(native["io"]) == len(original_io), "logical I/O event count differs")
    for actual, reference in zip(native["io"], original_io):
        require(actual["event"] == reference["event"] and type(actual["occurrence"]) is int
                and actual["occurrence"] == reference["occurrence"], "I/O order or occurrence differs")
        for key in ("ok", "value", "size", "is_file", "is_dir", "error"):
            if key in reference["result"]:
                value = reference["result"][key]
                require(type(actual[key]) is type(value) and actual[key] == value,
                        f"{cid}: I/O {key} differs")
        if "snapshot_blob" in reference["result"]:
            raw = captured(corpus, actual["snapshot_path"])
            require(raw == blobs[reference["result"]["snapshot_blob"]],
                    f"{cid}: complete raw read snapshot differs")
            counts["read_snapshot_bytes"] += len(raw)
        counts["logical_io"] += 1
    return counts


def compare_native(corpus, output):
    native = rows(inside(corpus, "native-cases.jsonl"))
    identifiers = {row["metadata"]["case_id"] for row in cases.iter_cases()}
    require(set(native) == identifiers, "native corpus does not contain the exact search cases")
    totals = dict(body_bytes=0, base_bytes=0, cache_bytes=0,
                  read_snapshot_bytes=0, cancelled_base_bytes=0, logical_io=0)
    domains = dict(regex_search_cases=0, whole_preparation_cases=0)
    with inside(output, "original.stdout").open("rb") as stream:
        originals = cases.read_records(stream, cases.OUTPUT_MAGIC)
        for request in cases.iter_cases():
            original = next(originals)
            counts = compare_case(corpus, native[request["metadata"]["case_id"]], original, request)
            key = "regex_search_cases" if request["metadata"]["domain"] == "regex-search" else "whole_preparation_cases"
            domains[key] += 1
            for key, value in counts.items():
                totals[key] += value
        require(next(originals, None) is None, "extra original search record")
    return dict(cases=len(identifiers), **domains, compared=totals,
                every_input_byte_equal=True, every_visible_body_byte_equal=True,
                every_after_gate_base_byte_equal=True, every_cache_probe_byte_equal=True,
                every_logical_io_observation_equal=True, every_raw_read_snapshot_byte_equal=True,
                native_producer_requires_separate_admission=True,
                whole_view_migrated=False, whole_runtime_replaced=False)
