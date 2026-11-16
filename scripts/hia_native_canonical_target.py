"""Bind the selected current canonical policy to unchanged historical carriers."""
from pathlib import Path
import hashlib
import json
import stat

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = "native/canonical_path_target.json"
REFERENCE = "tests/hia_native/canonical_path_target/config.rs"
NATIVE = "native/canonical_path.hepta"
HELPER = "scripts/hia_native_canonical_target.py"
TARGET = "native/migration_target.json"
TARGET_COMMIT = "d3d75c30719db966b004756f610007a7c723729e"
TARGET_TREE = "612e145513961556ac8844b5cc978f9b5175e4d4"
TARGET_PATH = "src/mcp/runtime/config.rs"
TARGET_BLOB = "52edc1b2301eaaf12f4aea6e160346be2eed1054"
REFERENCE_BYTES = 27112
REFERENCE_SHA256 = "75a95e0376eb2ebf92f4dbbc0f8d93cbe4aa53ae35c78aa144589d226bf9c7c6"
FUNCTION_START = 21947
FUNCTION_BYTES = 1379
FUNCTION_SHA256 = "9c8595c09bde097c0ed2ffd1654cd43aad89205e5a99aa26ded05cb47dcb55ab"
HISTORICAL_SHA256 = "228f83aa263920ef16e6fca93ce52292cae3cecae5be4b47788a7070fee97f35"
HISTORICAL_FUNCTION_SHA256 = "28f34d58e939541ea485a8e50541ab379742b7873d33dc5cf9bacd36fcbeb509"
NATIVE_SHA256 = "1299634c825a52dafc3e3561aa673073cbdfaed877497fb848275768a6fa4f16"


def need(condition, message):
    if not condition:
        raise ValueError("current canonical policy source: " + message)


def pin(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def regular(root, name):
    root = Path(root).resolve(strict=True)
    relative = Path(name)
    need(not relative.is_absolute() and all(part not in ("", ".", "..") for part in relative.parts),
         "source name escapes root")
    path = root
    for number, part in enumerate(relative.parts):
        path = path / part
        mode = path.lstat().st_mode
        need(not stat.S_ISLNK(mode), "source path contains a symbolic link")
        need(stat.S_ISREG(mode) if number == len(relative.parts) - 1 else stat.S_ISDIR(mode),
             "source path is not a regular file/directory")
    before = path.stat()
    raw = path.read_bytes()
    after = path.stat()
    identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns)
    need(identity(before) == identity(after) and len(raw) == before.st_size,
         "source changed while reading")
    return raw


def object_pairs(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def document(raw):
    value = json.loads(raw, object_pairs_hook=object_pairs)
    need(type(value) is dict, "JSON object required")
    return value


def selected_function(root=ROOT):
    raw = regular(root, REFERENCE)
    need(pin(raw) == {"bytes": REFERENCE_BYTES, "sha256": REFERENCE_SHA256},
         "complete current target config differs")
    blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
    need(blob == TARGET_BLOB, "complete target Git blob differs")
    body = raw[FUNCTION_START:FUNCTION_START + FUNCTION_BYTES]
    need(body.startswith(b"fn canonical_policy_path(") and body.endswith(b"\n}"),
         "selected function boundary differs")
    need(pin(body) == {"bytes": FUNCTION_BYTES, "sha256": FUNCTION_SHA256},
         "selected current function differs")
    return body


def source_evidence(root=ROOT):
    body = selected_function(root)
    target = document(regular(root, TARGET))
    need(target.get("schema") == "hepta.runtime.hia-migration-target.v1"
         and target.get("repository") == "TrillionniumFoundation/hepta-runtime"
         and target.get("target_commit") == TARGET_COMMIT
         and target.get("target_tree") == TARGET_TREE,
         "migration target identity differs")
    rows = target.get("source_files")
    need(type(rows) is list and all(type(row) is dict for row in rows), "target inventory differs")
    names = [row.get("path") for row in rows]
    need(len(set(names)) == len(names), "duplicate target source path")
    selected = [row for row in rows if row.get("path") == TARGET_PATH]
    need(selected == [{"path": TARGET_PATH, "mode": "100644", "git_blob": TARGET_BLOB,
                       "bytes": REFERENCE_BYTES}], "selected target inventory row differs")
    native = regular(root, NATIVE)
    need(hashlib.sha256(native).hexdigest() == NATIVE_SHA256, "selected HIA owner differs")
    expected = {
        "schema": "hepta.runtime.canonical-policy-current-target-source.v1",
        "target_commit": TARGET_COMMIT, "target_tree": TARGET_TREE,
        "target_path": TARGET_PATH, "target_git_blob": TARGET_BLOB,
        "reference_source": REFERENCE,
        "reference": {"bytes": REFERENCE_BYTES, "sha256": REFERENCE_SHA256},
        "unchanged_function": {"name": "canonical_policy_path", "start": FUNCTION_START,
                               "end": FUNCTION_START + FUNCTION_BYTES, **pin(body)},
        "historical_config_sha256": HISTORICAL_SHA256,
        "historical_function_sha256": HISTORICAL_FUNCTION_SHA256,
        "native_source": NATIVE, "native_source_sha256": NATIVE_SHA256,
        "caller_and_sdk_reference_versions_unchanged": True,
        "physical_policy_function_is_current_target": True,
        "whole_runtime_target_qualified": False, "production_activated": False,
        "old_stack_removal_qualified": False,
    }
    actual = document(regular(root, MANIFEST))
    canonical = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    need(canonical(actual) == canonical(expected), "selected-policy manifest differs")
    return actual


def source_pins(root=ROOT):
    source_evidence(root)
    return {name: pin(regular(root, name)) for name in (MANIFEST, REFERENCE, HELPER, TARGET, NATIVE)}


def historical_span(raw):
    need(type(raw) is bytes and hashlib.sha256(raw).hexdigest() == HISTORICAL_SHA256,
         "complete historical carrier differs")
    marker = b"fn canonical_policy_path("
    need(raw.count(marker) == 1, "historical function occurrence differs")
    start = raw.index(marker)
    end = raw.index(b"\n}", start) + 2
    need(hashlib.sha256(raw[start:end]).hexdigest() == HISTORICAL_FUNCTION_SHA256,
         "historical selected function differs")
    return start, end


def overlay_historical_config(original, root=ROOT):
    start, end = historical_span(original)
    return original[:start] + selected_function(root) + original[end:]


def verify_compiled_config(original, compiled, root=ROOT):
    policy = source_evidence(root)
    start, end = historical_span(original)
    expected = original[:start] + selected_function(root) + original[end:]
    need(type(compiled) is bytes and compiled == expected,
         "compiled carrier is not the exact selected function replacement")
    return {
        "current_target_policy": policy,
        "historical_config": pin(original), "compiled_config": pin(compiled),
        "historical_function": {"start": start, "end": end, **pin(original[start:end])},
        "unchanged_prefix": pin(original[:start]), "unchanged_suffix": pin(original[end:]),
        "other_historical_config_bytes_unchanged": True,
        "selected_function_bytes_unchanged": True,
        "whole_runtime_target_qualified": False,
    }
