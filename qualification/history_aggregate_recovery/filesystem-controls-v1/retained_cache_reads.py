"""Admit four absent importlib probes for exact retained historical sources.

This does not load bytecode, change the original loaders or cache their results.
The same full source bytes are read by the unchanged historical readers.
"""
from __future__ import annotations
import hashlib
import importlib.util
import os
from pathlib import Path
import stat
import sys

READERS = {
    "tests/hia_native/filesystem_parity/strict_reference.py": (50571, "b7cfe2fba7ec3290d993ccad754a019d2d5e4b73af208c8a4daa8ddb9135bab5"),
    "tests/hia_native/filesystem_sdk_oracle/strict_reference.py": (63637, "cbf0848f546425a0b825ac7dbe9741e891e7c78b7c932a5b6e7ce602443e3c4d"),
}
COPIES = (
    ("tests/hia_native/filesystem_parity/oracle/verify_sources.py",
     "filesystem-parity/original/build/verified-source/verify_sources.py",
     2398, "6aa7438a71bd1913b7fa347d1a05b424c05ec33d1601c2306dab5faf0536a776"),
    ("tests/hia_native/filesystem_parity/cases.py",
     "filesystem-parity/original/cases.py",
     12031, "f2d3efb4e3da4a800206c018908bd5999a6d14b31dc8a7dd81a502413111dedb"),
    ("tests/hia_native/filesystem_sdk_oracle/cases.py",
     "filesystem-public/reference-source/cases.py",
     17379, "9bb4cc6f0c0afdc520c27b07224b85194eed9bbf3644f7a2450a8831a2ebd3b8"),
    ("tests/hia_native/filesystem_sdk_oracle/oracle/verify_sources.py",
     "filesystem-public/reference-source/oracle/verify_sources.py",
     8329, "ea711d71d4bf2943fe5293102c73b76c35c14262c42873a8369f343c30c9e428"),
)
SCHEMA = "hepta.history.retained-cache-miss-admission.v1"


def need(value, label):
    if not value:
        raise ValueError(label)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def ordinary_root(value):
    path = Path(value).absolute()
    need(path.resolve(strict=True) == path and stat.S_ISDIR(path.lstat().st_mode),
         "ordinary non-aliased source/capture root")
    return path


def exact_file(root, relative, size, digest):
    path = root / relative
    need(path.is_relative_to(root) and path.resolve(strict=True) == path,
         "exact retained source path")
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
         "single owned regular source file")
    raw = path.read_bytes()
    after = path.lstat()
    fields = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
    need(all(getattr(info, key) == getattr(after, key) for key in fields)
         and len(raw) == size and sha(raw) == digest,
         "complete fixed historical source bytes: " + relative)
    return raw


def admit(source, capture):
    source, capture = ordinary_root(source), ordinary_root(capture)
    need(source != capture and not source.is_relative_to(capture)
         and not capture.is_relative_to(source), "separate source and capture roots")
    need(sys.dont_write_bytecode is True, "bytecode writes must remain disabled")
    readers = []
    for relative, (size, digest) in READERS.items():
        exact_file(source, relative, size, digest)
        readers.append({"path": relative, "pin": {"bytes": size, "sha256": digest}})
    copies, external = [], []
    for original, retained, size, digest in COPIES:
        raw = exact_file(source, original, size, digest)
        need(exact_file(capture, retained, size, digest) == raw,
             "entire retained source equals its original source")
        path = capture / retained
        cache = Path(importlib.util.cache_from_source(str(path))).absolute()
        need(cache.parent.parent == path.parent and cache.parent.name == "__pycache__"
             and cache.name == path.stem + "." + sys.implementation.cache_tag + ".pyc",
             "exact current importlib cache path")
        need(cache.resolve(strict=False) == cache and not os.path.lexists(cache),
             "only an absent non-aliased bytecode probe may be admitted")
        copies.append({"source": original, "retained": retained,
                       "pin": {"bytes": size, "sha256": digest},
                       "cache": str(cache), "absent": True})
        external.append(str(cache))
    return {
        "schema": SCHEMA, "status": "PASS",
        "source_root": str(source), "capture_root": str(capture),
        "python_cache_tag": sys.implementation.cache_tag,
        "readers": readers, "copies": copies, "external_files": external,
        "bytecode_writes_disabled": True,
        "original_reader_functions_modified": False, "module_results_cached": False,
        "native_or_rust_executions": 0,
    }


def verify(binding, before, external, *, source_root, capture_root):
    """Pure record validation; all physical source bytes were read above."""
    source_root, capture_root = str(source_root), str(capture_root)
    expected_keys = {
        "schema", "status", "source_root", "capture_root", "python_cache_tag",
        "readers", "copies", "external_files", "bytecode_writes_disabled",
        "original_reader_functions_modified", "module_results_cached", "native_or_rust_executions",
    }
    need(set(binding) == expected_keys and binding["schema"] == SCHEMA
         and binding["status"] == "PASS" and binding["source_root"] == source_root
         and binding["capture_root"] == capture_root
         and binding["bytecode_writes_disabled"] is True
         and binding["original_reader_functions_modified"] is False
         and binding["module_results_cached"] is False
         and type(binding["native_or_rust_executions"]) is int
         and binding["native_or_rust_executions"] == 0,
         "complete exact retained cache admission fields")
    tag = binding["python_cache_tag"]
    need(type(tag) is str and tag.startswith("cpython-")
         and tag[8:].isascii() and tag[8:].isdigit(), "literal CPython cache tag")
    readers = [{"path": name, "pin": {"bytes": size, "sha256": digest}}
               for name, (size, digest) in READERS.items()]
    need(binding["readers"] == readers, "both unchanged whole original loader sources")
    for row in readers:
        saved = before["1:" + row["path"]]
        need({"bytes": saved["bytes"], "sha256": saved["sha256"]} == row["pin"],
             "original reader source in full guarded snapshot")
    expected, paths = [], []
    for original, retained, size, digest in COPIES:
        path = Path(capture_root) / retained
        cache = str(path.parent / "__pycache__" / (path.stem + "." + tag + ".pyc"))
        pin = {"bytes": size, "sha256": digest}
        expected.append({"source": original, "retained": retained,
                         "pin": pin, "cache": cache, "absent": True})
        paths.append(cache)
        for key in ("1:" + original, "0:" + retained):
            saved = before[key]
            need({"bytes": saved["bytes"], "sha256": saved["sha256"]} == pin,
                 "entire retained and original Python source snapshots")
        need(external.get(cache) == {"absent": True}
             and "0:" + str(Path(cache).relative_to(capture_root)) not in before,
             "declared bytecode probe was absent in the complete owned tree")
    need(binding["copies"] == expected and binding["external_files"] == paths
         and len(set(paths)) == 4, "only the exact four cache misses are admitted")
    return True
