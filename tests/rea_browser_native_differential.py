#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Compare real native/Python HAR fixtures against each other and authored bytes.

Reads retained qualifications only; starts no browser, job, listener or network
request. The fixed fixture oracle is deliberately independent of both adapters.
Full HAR equality is not required: generated harness HTML, random origins and
transport/timing metadata are retained as differences outside the body contract.
"""
import argparse
import base64
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
from urllib.parse import urlsplit

REQUESTS = ["/text", "/text", "/empty", "/binary", "/missing"]
AUTHORED = {
    "before": {"/text": b"HEPTA_LOCAL_BEFORE\n", "/empty": b"",
               "/binary": bytes.fromhex("00fffe804845505441"),
               "/missing": b"partial authored response"},
    "after": {"/text": b"HEPTA_LOCAL_AFTER\n", "/empty": b"",
              "/binary": bytes.fromhex("00fffe804845505441"),
              "/missing": b"partial authored response"},
}
MIME = {"/text": "text/plain; charset=utf-8",
        "/empty": "text/plain; charset=utf-8",
        "/binary": "application/octet-stream",
        "/missing": "text/plain; charset=utf-8"}
PHASES = ("before", "after")
MAX_JSON_BYTES = 16 * 1024 * 1024


def digest(data):
    return hashlib.sha256(data).hexdigest()


def fingerprint(path, expected=None):
    path = Path(path).absolute()
    before = path.stat()
    if not path.is_file():
        raise ValueError("not a regular evidence file: " + str(path))
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    after = path.stat()
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
        raise ValueError("evidence changed while reading: " + str(path))
    result = {"path": str(path), "sha256": value.hexdigest(), "bytes": after.st_size}
    if expected is not None:
        result.update(expected_sha256=expected, matches_expected=value.hexdigest() == expected)
        if not result["matches_expected"]:
            raise ValueError("evidence SHA-256 mismatch: " + str(path))
    return result


def read_json(path, expected=None):
    info = fingerprint(path, expected)
    if info["bytes"] > MAX_JSON_BYTES:
        raise ValueError("JSON evidence exceeds budget: " + str(path))
    data = Path(path).read_bytes()
    if digest(data) != info["sha256"]:
        raise ValueError("evidence changed after fingerprint: " + str(path))
    return json.loads(data), info


def require(condition, description):
    if not condition:
        raise ValueError(description)


def argument(arguments, flag):
    require(arguments.count(flag) == 1, "one pinned argument required: " + flag)
    index = arguments.index(flag)
    require(index + 1 < len(arguments), "argument value absent: " + flag)
    return arguments[index + 1]


def byte_identity(value):
    if value is None:
        return None
    return {"bytes": len(value), "sha256": digest(value), "bytes_hex": value.hex()}


def source_observations(recorded):
    observations = {}
    for name, expected in recorded.items():
        try:
            current = fingerprint(name)
            current["matches_recorded"] = current["sha256"] == expected
        except (OSError, ValueError) as error:
            current = {"path": name, "matches_recorded": False, "error": str(error)}
        observations[name] = current
    return {"recorded_qualification_sha256": recorded,
            "current_files": observations,
            "all_current_files_match_recorded": all(
                value["matches_recorded"] for value in observations.values()),
            "scope": "Recorded source hashes describe the original qualified run. Current source changes are reported separately; current files are not substituted for historical source."}


def body_projection(entry):
    content = entry["response"].get("content", {})
    metadata = entry.get("_hepta", {})
    recorded = "text" in content
    encoding = content.get("encoding")
    if not recorded:
        representation = decoded = None
        state = "missing"
    else:
        require(isinstance(content["text"], str), "HAR content.text must be UTF-8 text")
        representation = content["text"].encode("utf-8")
        require(encoding in (None, "base64"), "unsupported recorded HAR encoding")
        if encoding == "base64":
            decoded = base64.b64decode(representation, validate=True)
            state = "base64"
        else:
            decoded = representation
            state = "empty" if not representation else "complete"
    return {
        "status": entry["response"]["status"],
        "recorded": recorded,
        "encoding": encoding,
        "derived_body_state": state,
        "declared_body_state": metadata.get("body_state"),
        "representation": byte_identity(representation),
        "decoded": byte_identity(decoded),
        "declared_representation_sha256": metadata.get("representation_sha256"),
        "declared_decoded_sha256": metadata.get("decoded_representation_sha256"),
        "network_loading_complete": metadata.get("network_loading_complete"),
        "body_missing_reason": metadata.get("body_missing_reason"),
        "raw_wire_body_identity": metadata.get("raw_wire_body_identity"),
    }


def body_metadata(entry):
    content = entry["response"].get("content", {})
    return {
        "size_present": "size" in content,
        "size": content.get("size"),
        "encoding_present": "encoding" in content,
        "mime_type_present": "mimeType" in content,
        "mime_type": content.get("mimeType"),
    }


def expected_body(phase, path):
    source = AUTHORED[phase][path]
    missing = path == "/missing"
    encoded = path == "/binary"
    representation = None if missing else base64.b64encode(source) if encoded else source
    decoded = None if missing else source
    state = "missing" if missing else "base64" if encoded else "empty" if not source else "complete"
    return {
        "status": 200, "recorded": not missing,
        "encoding": "base64" if encoded else None,
        "derived_body_state": state, "declared_body_state": state,
        "representation": byte_identity(representation), "decoded": byte_identity(decoded),
        "declared_representation_sha256": None if missing else digest(representation),
        "declared_decoded_sha256": None if missing else digest(decoded),
        "network_loading_complete": not missing,
        "body_missing_reason": "net::ERR_CONTENT_LENGTH_MISMATCH" if missing else None,
        "raw_wire_body_identity": False,
    }


def expected_metadata(phase, path):
    missing = path == "/missing"
    return {
        "size_present": not missing,
        "size": None if missing else len(AUTHORED[phase][path]),
        "encoding_present": path == "/binary",
        "mime_type_present": True,
        "mime_type": MIME[path].split(";", 1)[0],
    }


_ABSENT = object()


def differences(left, right, prefix=""):
    found = []
    if isinstance(left, dict) and isinstance(right, dict):
        for key in sorted(set(left) | set(right)):
            a, b = left.get(key, _ABSENT), right.get(key, _ABSENT)
            path = prefix + "/" + str(key).replace("~", "~0").replace("/", "~1")
            if a is _ABSENT or b is _ABSENT:
                found.append({"path": path, "native_present": a is not _ABSENT,
                              "python_present": b is not _ABSENT,
                              "native": None if a is _ABSENT else a,
                              "python": None if b is _ABSENT else b})
            else:
                found.extend(differences(a, b, path))
    elif isinstance(left, list) and isinstance(right, list):
        if left != right:
            found.append({"path": prefix, "native": left, "python": right})
    elif type(left) is not type(right) or left != right:
        found.append({"path": prefix, "native": left, "python": right})
    return found


def load_side(qualification_path, implementation):
    qualification, q_info = read_json(qualification_path)
    require(qualification.get("qualified") is True, "input qualification did not pass")
    require(qualification.get("capture_implementation") == implementation,
            "qualification implementation differs from its argument")
    workspace = Path(qualification["workspace"])
    runtime = fingerprint(workspace / "hepta-runtime-qualified", qualification["runtime_sha256"])
    request, request_info = read_json(workspace / "capture-request.json")
    args = request["args"]
    manifest_path = Path(argument(args, "--manifest"))
    manifest_sha = argument(args, "--expected-sha256")
    manifest, manifest_info = read_json(manifest_path, manifest_sha)
    final = qualification["capture_receipt"]
    require(final.get("phase") == "complete", "capture did not publish complete event")
    receipt, receipt_info = read_json(final["receipt_path"], final["receipt_sha256"])
    require(receipt["manifest_sha256"] == manifest_sha, "capture manifest pin mismatch")
    require(manifest.get("schema") == "hepta.rea.local-browser-capture.v1", "fixture schema mismatch")
    require(manifest.get("requests") == REQUESTS, "unsupported fixture request schedule; update the independent oracle explicitly")
    resources = manifest["resources"]
    require(len(resources) == len(MIME), "fixed fixture resource count mismatch")
    by_path = {item["url_path"]: item for item in resources}
    require(set(by_path) == set(MIME), "fixed fixture URL paths mismatch")
    recorded_sources = receipt.get("sources", receipt.get("source_resources"))
    require(isinstance(recorded_sources, list), "capture source manifest absent")
    capture_sources = {item["url_path"]: item for item in recorded_sources}
    require(set(capture_sources) == set(MIME), "capture source manifest paths mismatch")
    source_files = []
    for path, resource in by_path.items():
        require(resource["mime_type"] == MIME[path], "fixture MIME declaration mismatch")
        expected_delivery = "truncated" if path == "/missing" else "complete"
        require(resource.get("delivery", "complete") == expected_delivery, "fixture delivery mismatch")
        for phase in PHASES:
            chosen = resource.get(phase, resource["before"])
            filename = chosen["file"]
            require(Path(filename).name == filename, "fixture source must be a local file name")
            source_path = manifest_path.parent / filename
            info = fingerprint(source_path, chosen["sha256"])
            data = source_path.read_bytes()
            require(digest(data) == info["sha256"], "source changed after fingerprint")
            require(data == AUTHORED[phase][path], "authored fixture bytes do not match independent oracle")
            admitted = capture_sources[path][phase]
            require(admitted["file"] == filename and admitted["sha256"] == info["sha256"]
                    and admitted["bytes"] == len(data), "capture source manifest mismatch")
            source_files.append({"phase": phase, "url_path": path, **info,
                                 "independent_authored_bytes": byte_identity(AUTHORED[phase][path]),
                                 "independent_bytes_match": True})
    origin = receipt["loopback"]["origin"]
    probe_origin = receipt["loopback"]["negative_probe_origin"]
    require(urlsplit(origin).scheme == "http" and urlsplit(origin).hostname == "127.0.0.1",
            "source origin is not owned loopback HTTP")
    if implementation == "native-rust":
        require(receipt["native_worker_sha256"] == runtime["sha256"], "native worker pin mismatch")
    interpreter = None
    if qualification.get("python"):
        identity = qualification["python"]
        interpreter = fingerprint(identity["realpath"], identity["sha256"])
        interpreter["invocation_path"] = identity["invocation_path"]
    phases, har_identity = {}, {}
    for phase in PHASES:
        artifact = final["artifacts"][phase]
        raw_artifact = receipt["artifacts"][phase]
        require(raw_artifact["path"] == artifact["path"] and raw_artifact["sha256"] == artifact["sha256"],
                "capture event and receipt HAR identity mismatch")
        har, info = read_json(artifact["path"], artifact["sha256"])
        require(info["bytes"] == artifact["bytes"] == raw_artifact["bytes"], "HAR byte-count pin mismatch")
        entries = har["log"]["entries"]
        counts, selected, incidental = Counter(), {}, []
        for index, entry in enumerate(entries):
            url = entry["request"]["url"]
            parsed = urlsplit(url)
            entry_origin = parsed.scheme + "://" + parsed.netloc
            path = parsed.path
            require(not parsed.query and not parsed.fragment, "unexpected fixture query or fragment")
            if path in by_path:
                require(entry_origin == origin, "selected path was observed at a different origin")
                counts[path] += 1
                key = (path, counts[path])
                require(entry["request"]["method"] == "GET", "unexpected selected request method")
                selected[key] = {"entry_index": index, "url": url, "entry": entry,
                                 "projection": body_projection(entry), "metadata": body_metadata(entry)}
            else:
                require((path == "/__hepta_fixture__" and entry_origin == origin)
                        or (path == "/__hepta_blocked__" and entry_origin == probe_origin),
                        "unexpected non-manifest request outside fixed harness/probe scope")
                incidental.append({"entry_index": index, "url": url, "url_path": path,
                                   "projection": body_projection(entry), "metadata": body_metadata(entry)})
        require(counts == Counter(REQUESTS), "missing or extra selected request occurrence")
        require(Counter(item["url_path"] for item in incidental)
                == Counter(["/__hepta_fixture__", "/__hepta_blocked__"]),
                "fixed harness/probe occurrence mismatch")
        phases[phase] = {"selected": selected, "incidental": incidental}
        har_identity[phase] = info
    identity = {
        "qualification": q_info, "capture_receipt": receipt_info,
        "original_capture_request": request_info,
        "original_job_id": qualification["capture_job_id"],
        "runtime_binary": runtime, "python_interpreter": interpreter,
        "manifest": manifest_info, "source_files": source_files, "har": har_identity,
        "source_identity": source_observations(qualification["helper_sources"]),
        "observed_browser_version": qualification["observed_browser"],
        "browser_executable_sha256_recorded": False,
        "source_origin": origin, "probe_origin": probe_origin,
    }
    return identity, phases


def compare(native, python):
    native_identity, native_phases = native
    python_identity, python_phases = python
    rows, manual, metadata_findings, incidental = [], [], [], []
    pair_equal = expected_equal = metadata_equal = expected_metadata_equal = True
    for phase in PHASES:
        a_selected = native_phases[phase]["selected"]
        b_selected = python_phases[phase]["selected"]
        require(set(a_selected) == set(b_selected), "selected key sets differ")
        for path, occurrence in sorted(a_selected):
            a, b = a_selected[(path, occurrence)], b_selected[(path, occurrence)]
            key = {"phase": phase, "url_path": path, "occurrence": occurrence}
            expected, expected_meta = expected_body(phase, path), expected_metadata(phase, path)
            equal = a["projection"] == b["projection"]
            metadata_match = a["metadata"] == b["metadata"]
            pair_equal &= equal
            metadata_equal &= metadata_match
            native_oracle, python_oracle = a["projection"] == expected, b["projection"] == expected
            native_meta, python_meta = a["metadata"] == expected_meta, b["metadata"] == expected_meta
            expected_equal &= native_oracle and python_oracle
            expected_metadata_equal &= native_meta and python_meta
            manual.append({"key": key, "authored_source_bytes": byte_identity(AUTHORED[phase][path]),
                           "expected_observation": expected, "expected_body_metadata": expected_meta,
                           "native_observation_matches": native_oracle,
                           "python_observation_matches": python_oracle,
                           "native_metadata_matches": native_meta, "python_metadata_matches": python_meta})
            rows.append({"key": key,
                         "native_entry_index": a["entry_index"], "python_entry_index": b["entry_index"],
                         "native_url": a["url"], "python_url": b["url"],
                         "native": a["projection"], "python": b["projection"],
                         "selected_body_projection_equal": equal,
                         "body_projection_differences": differences(a["projection"], b["projection"]),
                         "native_metadata": a["metadata"], "python_metadata": b["metadata"],
                         "body_metadata_equal": metadata_match,
                         "raw_entry_differences": differences(a["entry"], b["entry"])})
            if not (metadata_match and native_meta and python_meta):
                metadata_findings.append({
                    "key": key, "native": a["metadata"], "python": b["metadata"],
                    "expected": expected_meta,
                    "reason": "Missing body is unrecorded, not an empty body; content.size must remain absent when no bytes were captured."
                    if path == "/missing" else "Selected body metadata differs from the independently declared fixture."})
        a_extra = {row["url_path"]: row for row in native_phases[phase]["incidental"]}
        b_extra = {row["url_path"]: row for row in python_phases[phase]["incidental"]}
        for path in sorted(set(a_extra) | set(b_extra)):
            a, b = a_extra.get(path), b_extra.get(path)
            incidental.append({
                "phase": phase, "url_path": path, "native": a, "python": b,
                "body_equality_required": False,
                "reason": "Generated fixed harness HTML is implementation-owned and contains a random probe origin."
                if path == "/__hepta_fixture__" else
                "Negative probe is outside manifest-selected resources; actual status/body/MIME differences are retained."})
    qualified = pair_equal and expected_equal and metadata_equal and expected_metadata_equal
    return {
        "schema": "hepta.rea.browser-native-differential.v1",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "comparison_completed": True, "qualified": qualified,
        "qualification_scope": "Fixed manifest resources, phase plus URL path plus occurrence; status, recorded UTF-8 representation and decoded bytes/digests, encoding, body state and truthful body metadata.",
        "selected_pairs": len(rows),
        "selected_body_projection_equal": pair_equal,
        "independent_authored_body_oracle_passed": expected_equal,
        "selected_body_metadata_equal": metadata_equal,
        "independent_truthful_body_metadata_passed": expected_metadata_equal,
        "raw_har_bytes_equal": {
            phase: native_identity["har"][phase]["sha256"] == python_identity["har"][phase]["sha256"]
            for phase in PHASES},
        "full_har_equivalence_claimed": False,
        "raw_http_wire_equivalence_claimed": False,
        "application_behavior_equivalence_claimed": False,
        "identity": {"native": native_identity, "python": python_identity},
        "manual_oracle_basis": {
            "source": "Literal authored fixture values in this independent script, not either capture output or a producer-generated expected body.",
            "bytes": {phase: {path: byte_identity(data) for path, data in values.items()}
                      for phase, values in AUTHORED.items()},
            "representation_basis": "Exact UTF-8 bytes of HAR content.text; base64 remains encoded for representation identity and is separately decoded with strict validation.",
            "missing_semantics": "Source contains an authored truncated response, but missing recorded content carries no observed representation/decoded bytes, hash, or length. It is never coerced to empty bytes."},
        "manual_checks": manual, "pairs": rows,
        "selected_body_metadata_findings": metadata_findings,
        "excluded_incidental_observations": incidental,
        "excluded_from_equality": ["generated fixed harness HTML", "random loopback origin/port",
                                  "negative probe incidental metadata", "transport/timing/header/order serialization metadata"],
        "current_source_observation_is_historical_attestation": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native-qualification", type=Path, required=True)
    parser.add_argument("--python-qualification", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = {"schema": "hepta.rea.browser-native-differential.v1",
              "comparison_completed": False, "qualified": False}
    try:
        native = load_side(args.native_qualification, "native-rust")
        python = load_side(args.python_qualification, "python-reference")
        report = compare(native, python)
    except (OSError, ValueError, KeyError, TypeError) as error:
        report["failure"] = str(error)
    report["differential_script"] = fingerprint(Path(__file__).resolve())
    report["arguments"] = {"native_qualification": str(args.native_qualification.absolute()),
                           "python_qualification": str(args.python_qualification.absolute())}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    encoded = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")
    with args.output.open("xb") as stream:
        stream.write(encoded)
    print(json.dumps({"report": str(args.output.absolute()), "report_sha256": digest(encoded),
                      "comparison_completed": report["comparison_completed"],
                      "qualified": report["qualified"],
                      "selected_pairs": report.get("selected_pairs"),
                      "selected_body_projection_equal": report.get("selected_body_projection_equal"),
                      "independent_authored_body_oracle_passed": report.get("independent_authored_body_oracle_passed"),
                      "selected_body_metadata_equal": report.get("selected_body_metadata_equal"),
                      "metadata_findings": len(report.get("selected_body_metadata_findings", [])),
                      "failure": report.get("failure")}), flush=True)
    return 0 if report["qualified"] else 1


if __name__ == "__main__":
    sys.exit(main())
