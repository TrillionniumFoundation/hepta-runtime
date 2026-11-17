"""Mechanical cache-miss admission controls; never execute retained module bodies."""
from __future__ import annotations
import hashlib
import importlib.util
import marshal
import os
from pathlib import Path
import stat
import sys
import tempfile
import types
import read_only_guard as guard
import retained_cache_reads as cache_reads

NAMES = [
    "changed-source", "changed-original-reader", "changed-retained-copy",
    "missing-retained-copy", "source-alias", "retained-alias",
    "existing-bytecode", "dangling-bytecode-alias", "aliased-bytecode-parent",
    "source-root-alias", "unlisted-cache-probe", "cache-write",
]


def need(value, label):
    if not value:
        raise ValueError(label)


def state(root):
    result = {}
    for path in [root] + sorted(root.rglob("*")):
        info = path.lstat()
        row = {key: getattr(info, key) for key in
               ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")}
        if stat.S_ISREG(info.st_mode):
            raw = path.read_bytes()
            row["sha256"] = hashlib.sha256(raw).hexdigest()
        elif stat.S_ISLNK(info.st_mode):
            row["link"] = os.readlink(path)
        else:
            need(stat.S_ISDIR(info.st_mode), "control fixture ordinary entries only")
        result[path.relative_to(root).as_posix()] = row
    return result


def fixture(home, original_source):
    source, capture = home / "source", home / "capture"
    source.mkdir(parents=True)
    capture.mkdir()
    pins = dict(cache_reads.READERS)
    for original, retained, size, digest in cache_reads.COPIES:
        pins[original] = (size, digest)
    for relative, (size, digest) in pins.items():
        raw = cache_reads.exact_file(original_source, relative, size, digest)
        target = source / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
    for original, retained, size, digest in cache_reads.COPIES:
        target = capture / retained
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((source / original).read_bytes())
    (capture / "CAPTURE.json").write_bytes(b'{"mechanical_cache_probe":true}\n')
    (home / "foreign").write_bytes(b"outside the guarded source and capture\n")
    return source, capture


def run(original_source):
    original_source = cache_reads.ordinary_root(original_source)
    admissions, refusals = [], []
    with tempfile.TemporaryDirectory(prefix="hia-retained-cache-controls-") as temporary:
        root = Path(temporary)
        for number in range(2):
            home = root / ("admission-" + str(number))
            source, capture = fixture(home, original_source)
            binding = cache_reads.admit(source, capture)
            events = []
            def operation():
                compiled = []
                for index, (_, retained, _, _) in enumerate(cache_reads.COPIES):
                    path = capture / retained
                    name = "_historical_cache_source_control_" + str(index)
                    spec = importlib.util.spec_from_file_location(name, path)
                    need(spec is not None and spec.loader is not None, "actual importlib source loader")
                    code = spec.loader.get_code(name)
                    need(isinstance(code, types.CodeType) and code.co_filename == str(path),
                         "complete actual get_code result without execution")
                    expected = compile(path.read_bytes(), str(path), "exec", dont_inherit=True)
                    raw, expected_raw = marshal.dumps(code), marshal.dumps(expected)
                    need(raw == expected_raw, "actual cache miss compiled the entire original source")
                    compiled.append({"retained": retained, "bytes": len(raw),
                                     "sha256": hashlib.sha256(raw).hexdigest(), "hex": raw.hex()})
                need(cache_reads.admit(source, capture) == binding, "four cache misses remain absent")
                return {"binding": binding, "compiled_sources": compiled, "module_bodies_executed": 0}
            proof = guard.guarded(operation, roots=[capture, source], foreign_path=home / "foreign",
                                  external_files=binding["external_files"], diagnostics=events)
            need(len(events) == 12 and all(row["phase"] == "probes" for row in events),
                 "cache fallback had no denied reader operations")
            cache_reads.verify(binding, proof["before"], proof["external_before"],
                               source_root=source, capture_root=capture)
            admissions.append({"name": "complete-cache-miss-" + str(number),
                               "guard": proof, "diagnostics": events})

        for label in NAMES:
            home = root / label
            source, capture = fixture(home, original_source)
            admitted_source = source
            original, retained, _, _ = cache_reads.COPIES[0]
            src, saved = source / original, capture / retained
            cache = Path(importlib.util.cache_from_source(str(saved)))
            if label == "changed-source":
                src.write_bytes(src.read_bytes() + b"\n")
            elif label == "changed-original-reader":
                path = source / next(iter(cache_reads.READERS))
                path.write_bytes(path.read_bytes() + b"\n")
            elif label == "changed-retained-copy":
                saved.write_bytes(saved.read_bytes() + b"\n")
            elif label == "missing-retained-copy":
                saved.unlink()
            elif label == "source-alias":
                src.unlink()
                src.symlink_to(saved)
            elif label == "retained-alias":
                saved.unlink()
                saved.symlink_to(src)
            elif label == "existing-bytecode":
                cache.parent.mkdir()
                cache.write_bytes(b"must never be imported")
            elif label == "dangling-bytecode-alias":
                cache.parent.mkdir()
                cache.symlink_to(home / "not-present")
            elif label == "aliased-bytecode-parent":
                other = home / "outside-cache"
                other.mkdir()
                cache.parent.symlink_to(other, target_is_directory=True)
            elif label == "source-root-alias":
                admitted_source = home / "aliased-source"
                admitted_source.symlink_to(source, target_is_directory=True)
            before = state(home)
            events = []
            outcome = None
            try:
                if label in ("unlisted-cache-probe", "cache-write"):
                    binding = cache_reads.admit(source, capture)
                    def forbidden():
                        if label == "cache-write":
                            cache.write_bytes(b"forbidden")
                        else:
                            other = cache.with_name("unlisted." + sys.implementation.cache_tag + ".pyc")
                            try:
                                other.read_bytes()
                            except OSError:
                                pass
                    guard.guarded(forbidden, roots=[capture, source], foreign_path=home / "foreign",
                                  external_files=binding["external_files"], diagnostics=events)
                else:
                    cache_reads.admit(admitted_source, capture)
            except (ValueError, OSError) as error:
                outcome = {"type": type(error).__name__, "message": str(error)}
            need(outcome is not None, "admitted invalid cache fixture: " + label)
            after = state(home)
            need(before == after, "cache rejection changed any complete fixture bytes or metadata")
            if label == "unlisted-cache-probe":
                need(outcome == {"type": "ValueError", "message": "reader attempted a forbidden operation"}
                     and len(events) == 13 and events[-1]["phase"] == "reader"
                     and events[-1]["kind"] == "foreign-read", "unlisted probe remains forbidden")
            elif label == "cache-write":
                need(outcome == {"type": "PermissionError",
                                 "message": "history-aggregate read-only guard: file-write"}
                     and len(events) == 13 and events[-1]["phase"] == "reader"
                     and events[-1]["kind"] == "file-write", "all bytecode writes remain forbidden")
            else:
                need(events == [], "admission failed before reader execution")
            refusals.append({"name": label, "outcome": outcome, "before": before, "after": after,
                             "diagnostics": events, "module_bodies_executed": 0})
    return {"schema": "hepta.history.retained-cache-controls.v1", "status": "PASS",
            "admissions": admissions, "refusals": refusals, "complete_admissions": 2,
            "source_compilations_without_execution": 8, "original_guard_probes": 48,
            "module_bodies_executed": 0, "native_or_rust_executions": 0}
