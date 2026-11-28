"""Fresh locked original Rust replay against complete native publication bytes.

The reference input is generated independently. Captured native input must
match it byte for byte; expected result text and JSON execute only in Rust.
Native syscall/ACK correctness remains the separate native publisher suite.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import time

ROOT = Path(__file__).resolve().parent


def _sibling(name):
    spec = importlib.util.spec_from_file_location(f"_hia_result_publication_original.{name}", ROOT / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


cases = _sibling("cases")
sources = _sibling("verify_sources")


def digest(path):
    state = hashlib.sha256()
    with Path(path).open("rb") as stream:
        while block := stream.read(1 << 20):
            state.update(block)
    return state.hexdigest()


def corpus_path(corpus: Path, relative: str) -> Path:
    path = Path(relative)
    if path.is_absolute() or ".." in path.parts:
        raise AssertionError("corpus artifacts must be relative descendants")
    full = (corpus / path).resolve()
    if not full.is_relative_to(corpus.resolve()) or not full.is_file():
        raise AssertionError(f"missing or escaped corpus artifact: {relative}")
    return full


def prepare_input(corpus: Path, output: Path):
    rows = {}
    with (corpus / "semantic-cases.jsonl").open(encoding="utf-8") as stream:
        for line in stream:
            row = json.loads(line)
            if row["case_id"] in rows:
                raise AssertionError("duplicate native semantic case")
            rows[row["case_id"]] = row
    compared_input = 0
    input_pins = []

    def checked_cases():
        nonlocal compared_input
        generated = set()
        for case in cases.iter_cases():
            cid = case["case_id"]
            if cid not in rows:
                raise AssertionError(f"missing independent semantic case: {cid}")
            generated.add(cid)
            row = rows[cid]
            if row["mode"] != case["mode"] or row["is_error"] != case["is_error"]:
                raise AssertionError(f"captured case identity differs: {cid}")
            expected = cases.encode_cases([case])
            path = corpus_path(corpus, row["input_path"])
            offset = 0
            with gzip.open(path, "rb") as native:
                while offset < len(expected):
                    block = native.read(min(1 << 20, len(expected) - offset))
                    if not block or block != expected[offset:offset + len(block)]:
                        raise AssertionError(f"native input differs from independent generator: {cid} at {offset}")
                    offset += len(block)
                if native.read(1):
                    raise AssertionError(f"native input has trailing bytes: {cid}")
            input_sha = hashlib.sha256(expected).hexdigest()
            if ("input_bytes" in row and row["input_bytes"] != len(expected)) or (
                    "input_sha256" in row and row["input_sha256"] != input_sha):
                raise AssertionError(f"native input receipt differs: {cid}")
            compared_input += len(expected)
            input_pins.append({"case_id": cid, "path": row["input_path"],
                               "gzip_sha256": digest(path), "bytes": len(expected),
                               "sha256": input_sha})
            yield case
        if generated != set(rows):
            raise AssertionError("native corpus contains an unregistered semantic case")

    with output.open("xb+") as stream:
        metadata = cases.write_cases(stream, checked_cases())
    return rows, {"cases": len(rows), "independent_input_bytes": output.stat().st_size,
                  "independent_input_sha256": digest(output),
                  "captured_input_bytes_compared": compared_input,
                  "every_captured_input_byte_equal": True,
                  "cases_metadata": metadata, "input_pins": input_pins}


def compare_output(corpus: Path, original: Path, rows: dict):
    compared = 0
    largest = 0
    over_eight = 0
    seen = set()
    result_rows = []
    with original.open("rb") as reference:
        if reference.read(8) != cases.OUTPUT_MAGIC:
            raise AssertionError("original output magic differs")
        raw_count = reference.read(8)
        if len(raw_count) != 8:
            raise AssertionError("original output count missing")
        count = struct.unpack("<Q", raw_count)[0]
        if count != len(rows):
            raise AssertionError("original/native case counts differ")
        for _ in range(count):
            header = reference.read(16)
            if len(header) != 16:
                raise AssertionError("truncated original output header")
            cid, length = struct.unpack("<QQ", header)
            if cid in seen or cid not in rows:
                raise AssertionError("original output case identity differs")
            seen.add(cid)
            row = rows[cid]
            path = corpus_path(corpus, row["output_path"])
            offset = 0
            state = hashlib.sha256()
            with gzip.open(path, "rb") as native:
                while offset < length:
                    size = min(1 << 20, length - offset)
                    expected, actual = reference.read(size), native.read(size)
                    if len(expected) != size or expected != actual:
                        raise AssertionError({"case_id": cid, "offset": offset,
                                              "expected_chunk_bytes": len(expected),
                                              "native_chunk_bytes": len(actual),
                                              "expected_sha256": hashlib.sha256(expected).hexdigest(),
                                              "native_sha256": hashlib.sha256(actual).hexdigest()})
                    state.update(actual)
                    offset += size
                if native.read(1):
                    raise AssertionError(f"native output has trailing bytes: {cid}")
            if length != row["output_bytes"] or state.hexdigest() != row["output_sha256"]:
                raise AssertionError(f"native output receipt differs: {cid}")
            compared += length
            largest = max(largest, length)
            over_eight += int(length > (8 << 20))
            result_rows.append({"case_id": cid, "path": row["output_path"],
                                "gzip_sha256": digest(path), "output_bytes": length,
                                "output_sha256": state.hexdigest(), "every_byte_equal": True})
        if reference.read(1):
            raise AssertionError("trailing original output bytes")
    if seen != set(rows):
        raise AssertionError("incomplete original output coverage")
    return {"cases": len(seen), "compared_body_bytes": compared,
            "largest_body_bytes": largest, "bodies_over_eight_mib": over_eight,
            "every_output_byte_equal": True, "output_pins": result_rows}


def compare_publications(corpus: Path, original: Path, semantic_rows: dict,
                         semantic_corpus: Path | None = None):
    """Compare complete successful ELF stdout with the same fresh Rust output.

    ACK receipts and interrupted/failed writes belong to the native tests. This
    comparison accepts only a completed stdout publication for an independently
    generated case; it does not synthesize a successful result for a partial run.
    """
    semantic_corpus = corpus if semantic_corpus is None else semantic_corpus
    manifest = corpus / "publisher-cases.jsonl"
    index = {}
    with original.open("rb") as reference:
        if reference.read(8) != cases.OUTPUT_MAGIC:
            raise AssertionError("original output magic differs")
        count = struct.unpack("<Q", cases._read_exact(reference, 8))[0]
        for _ in range(count):
            cid, length = struct.unpack("<QQ", cases._read_exact(reference, 16))
            if cid in index:
                raise AssertionError("duplicate original output case")
            index[cid] = (reference.tell(), length)
            reference.seek(length, os.SEEK_CUR)
        if reference.tell() != original.stat().st_size or set(index) != set(semantic_rows):
            raise AssertionError("original publication index is incomplete")
    results = []
    seen = set()
    total = 0
    with manifest.open(encoding="utf-8") as records, original.open("rb") as reference:
        for line in records:
            row = json.loads(line)
            run_id, cid = row["run_id"], row["case_id"]
            if run_id in seen or cid not in index:
                raise AssertionError("invalid successful publisher case identity")
            if "returncode" in row and row["returncode"] != 0:
                raise AssertionError("failed publisher is not a complete original result")
            if (row["mode"] != semantic_rows[cid]["mode"]
                    or row["is_error"] != semantic_rows[cid]["is_error"]):
                raise AssertionError("publisher logical mode differs")
            seen.add(run_id)
            native_input = corpus_path(corpus, row["input_path"])
            logical_input = corpus_path(semantic_corpus, semantic_rows[cid]["input_path"])
            input_hash, input_size = hashlib.sha256(), 0
            with gzip.open(native_input, "rb") as published, gzip.open(logical_input, "rb") as logical:
                while True:
                    left, right = published.read(1 << 20), logical.read(1 << 20)
                    if left != right:
                        raise AssertionError(f"publisher input differs from checked independent case: {run_id}")
                    if not left:
                        break
                    input_hash.update(left)
                    input_size += len(left)
            if row["input_bytes"] != input_size or row["input_sha256"] != input_hash.hexdigest():
                raise AssertionError(f"publisher input receipt differs: {run_id}")
            offset, length = index[cid]
            reference.seek(offset)
            native_output = corpus_path(corpus, row["output_path"])
            state = hashlib.sha256()
            remaining = length
            with gzip.open(native_output, "rb") as actual:
                while remaining:
                    size = min(1 << 20, remaining)
                    expected, native = reference.read(size), actual.read(size)
                    if len(expected) != size or native != expected:
                        raise AssertionError({"publisher_run": run_id, "case_id": cid,
                                              "mismatch_at": length - remaining})
                    state.update(native)
                    remaining -= size
                if actual.read(1):
                    raise AssertionError(f"publisher stdout has trailing bytes: {run_id}")
            if row["output_bytes"] != length or row["output_sha256"] != state.hexdigest():
                raise AssertionError(f"publisher output receipt differs: {run_id}")
            total += length
            results.append({"run_id": run_id, "case_id": cid, "output_bytes": length,
                            "input_path": row["input_path"], "input_gzip_sha256": digest(native_input),
                            "output_path": row["output_path"], "output_gzip_sha256": digest(native_output),
                            "output_sha256": state.hexdigest(), "every_stdout_byte_equal": True})
    if not results:
        raise AssertionError("no successful actual ELF publisher outputs captured")
    return {"runs": len(results), "compared_stdout_bytes": total,
            "every_stdout_byte_equal": True, "manifest_sha256": digest(manifest),
            "publisher_pins": results, "partial_and_failed_runs_are_separate_native_qualification": True}


def run(args, execute_callback=None, environment=None):
    """Record two real processes using the optional q.record_check callback.

    Callback signature: name, command, timeout, env, input_bytes; result is a
    subprocess.CompletedProcess with byte stdout/stderr. A fresh output path
    and fresh target are required; cached Cargo dependency downloads are fine.
    """
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    started = time.monotonic()
    crate = output / "crate"
    source_check = sources.materialize(ROOT, args.runtime_root.resolve(), crate)
    rows, inputs = prepare_input(args.corpus.resolve(), output / "original-input.bin")
    publisher_corpus = (getattr(args, "publisher_corpus", None) or args.corpus).resolve()
    if not (publisher_corpus / "publisher-cases.jsonl").is_file():
        raise AssertionError("complete original replay requires an actual ELF publication corpus")
    env = dict(os.environ if environment is None else environment)
    env["CARGO_BUILD_JOBS"] = "2"
    offline = bool(getattr(args, "offline", False))
    if offline:
        env["CARGO_NET_OFFLINE"] = "true"

    def capture(name, command, prefix, timeout):
        if execute_callback is None:
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    timeout=timeout, env=env)
        else:
            result = execute_callback(name=name, command=command, timeout=timeout,
                                      env=env, input_bytes=None)
        prefix.with_suffix(".stdout").write_bytes(result.stdout)
        prefix.with_suffix(".stderr").write_bytes(result.stderr)
        if result.returncode:
            raise AssertionError({"process": name, "returncode": result.returncode,
                                  "stderr_path": str(prefix.with_suffix(".stderr"))})

    target = output / "cargo-target"
    capture("result-publication-rust-compile",
            [args.cargo, "build", "--locked", *(["--offline"] if offline else []),
             "--manifest-path", str(crate / "Cargo.toml"), "--target-dir", str(target)],
            output / "build", 180)
    binary = target / "debug/hepta-result-publication-original-oracle"
    original_output = output / "original-output.bin"
    capture("result-publication-rust-compare",
            [str(binary), str(output / "original-input.bin"), str(original_output)],
            output / "original-replay", 120)
    original_summary = json.loads((output / "original-replay.stdout").read_text())
    compared = compare_output(args.corpus.resolve(), original_output, rows)
    publications = compare_publications(publisher_corpus, original_output, rows, args.corpus.resolve())
    if (original_summary["cases"] != inputs["cases"]
            or original_summary["body_bytes"] != compared["compared_body_bytes"]
            or not original_summary["original_append_function_executed"]):
        raise AssertionError("original replay summary differs")
    report = {"schema": "hepta.runtime.result-publication.fresh-original-replay.v1",
              "status": "PASS", "seconds": time.monotonic() - started,
              "fresh_locked_build": True, "top_level_subprocesses": 2,
              "source_check": source_check, "original_summary": original_summary,
              "input_comparison": inputs, "output_comparison": compared,
              "publisher_output_comparison": publications,
              "native_manifest_sha256": digest(args.corpus / "semantic-cases.jsonl"),
              "original_output_sha256": digest(original_output),
              "rust_executable_sha256": digest(binary),
              "driver_sha256": digest(ROOT / "src/main.rs"),
              "cargo_lock_sha256": digest(ROOT / "Cargo.lock"),
              "native_syscall_ack_suite_required_separately": True,
              "native_scheduler_qualified": False, "filesystem_callers_replaced": False,
              "unbounded_api_equivalence_proved_by_finite_tests": False}
    (output / "RESULT.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--cargo", default="cargo")
    parser.add_argument("--runtime-root", type=Path, required=True)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--publisher-corpus", type=Path, help="Defaults to the semantic corpus directory")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--offline", action="store_true", help="Use an already populated Cargo cache")
    args = parser.parse_args()
    report = run(args)
    print(json.dumps({key: value for key, value in report.items()
                      if key not in ("input_comparison", "output_comparison")}, sort_keys=True))
