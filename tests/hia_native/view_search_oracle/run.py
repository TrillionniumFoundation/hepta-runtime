"""Fresh locked original Rust execution for the fixed literal search corpus."""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parent
HARNESS_FILES = ("Cargo.toml", "Cargo.lock", "README.md", "source_manifest.json",
                 "cases.py", "verify_sources.py", "replay_compare.py", "run.py")


def sibling(name):
    spec = importlib.util.spec_from_file_location("_view_search_original_" + name,
                                                 ROOT / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


cases, source, replay = (sibling(name) for name in ("cases", "verify_sources", "replay_compare"))


def identity(path):
    digest = hashlib.sha256()
    size = 0
    with Path(path).open("rb") as stream:
        while block := stream.read(1 << 20):
            digest.update(block)
            size += len(block)
    return dict(bytes=size, sha256=digest.hexdigest())


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode() + b"\n"


def reference_summary(output):
    count = dict(cases=0, literal_search_cases=0, whole_preparation_cases=0,
                 successful=0, errors=0, cancelled=0, body_bytes=0,
                 rendered_bytes=0, raw_read_bytes=0, logical_io=0,
                 read_calls=0, metadata_calls=0, cache_probe_bytes=0)
    names = []
    with (output / "original.stdout").open("rb") as stream:
        originals = cases.read_records(stream, cases.OUTPUT_MAGIC)
        for expected in cases.iter_cases():
            request = expected["metadata"]
            original = next(originals)
            meta, blobs = original["metadata"], original["blobs"]
            assert (meta["case_id"], meta["name"], meta["session"]) == (
                request["case_id"], request["name"], request["session"])
            assert sorted(meta["fired_hooks"]) == list(range(len(request["hooks"])))
            assert meta["outside_scope_hints_empty"] is True
            count["cases"] += 1
            count["literal_search_cases" if request["domain"] == "literal-search" else
                  "whole_preparation_cases"] += 1
            outcome = meta["outcome"]
            if request["cancel_after_render"]:
                assert outcome == {"cancelled": True, "publication_bytes": 0}
                assert meta["before_cancel"] is not None
                count["cancelled"] += 1
            else:
                assert type(outcome["ok"]) is bool
                assert len(blobs[outcome["blob"]]) == outcome["bytes"]
                assert outcome["hints"] == outcome["hints_remaining"] == []
                count["successful" if outcome["ok"] else "errors"] += 1
                count["body_bytes"] += outcome["bytes"]
            rendered = meta["rendered"]
            assert type(rendered["ok"]) is bool
            if rendered["ok"]:
                assert len(blobs[rendered["blob"]]) == rendered["bytes"]
                count["rendered_bytes"] += rendered["bytes"]
            observed_counts = {}
            for event in meta["events"]:
                if event["kind"] == "mutation":
                    hook = request["hooks"][event["hook"]]
                    assert all(event[key] == hook[key] for key in ("event", "occurrence", "when"))
                    continue
                assert event["kind"] == "io"
                name = event["event"]
                occurrence = observed_counts.get(name, 0) + 1
                assert event["occurrence"] == occurrence
                observed_counts[name] = occurrence
                count["logical_io"] += 1
                result = event["result"]
                assert type(result["ok"]) is bool
                if name == "read" and result["ok"]:
                    assert len(blobs[result["snapshot_blob"]]) == result["bytes"]
                    count["raw_read_bytes"] += result["bytes"]
            assert observed_counts == meta["io_counts"]
            count["read_calls"] += observed_counts.get("read", 0)
            count["metadata_calls"] += observed_counts.get("metadata", 0)
            for side in ("cache_before", "cache_after"):
                assert len(meta[side]) == len(request["cache_probes"])
                for probe, path in zip(meta[side], request["cache_probes"]):
                    assert probe["path_hex"] == path and type(probe["present"]) is bool
                    if probe["present"]:
                        assert len(blobs[probe["blob"]]) == probe["bytes"]
                        count["cache_probe_bytes"] += probe["bytes"]
                    else:
                        assert probe["blob"] is None and probe["bytes"] == 0
            names.append(dict(case_id=meta["case_id"], name=meta["name"], domain=request["domain"],
                              rendered_bytes=rendered.get("bytes"),
                              result_bytes=outcome.get("bytes"),
                              ok=outcome.get("ok"), cancelled=request["cancel_after_render"],
                              io_counts=observed_counts))
        assert next(originals, None) is None
    assert count["cases"] == 72 and count["literal_search_cases"] == 71
    assert count["whole_preparation_cases"] == 1 and count["cancelled"] == 1
    (output / "case-summary.json").write_bytes(canonical(names))
    return dict(**count, actual_tokio_io=True, actual_unchanged_search=True,
                actual_original_mcp_router=False, alternative_path_search=False,
                directory_search=False, regex_search=False,
                whole_view_migrated=False, whole_runtime_replaced=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cargo", type=Path, required=True)
    parser.add_argument("--rustc", type=Path, required=True)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--native-corpus", type=Path)
    args = parser.parse_args()
    output = args.output.absolute()
    output.mkdir(parents=True, exist_ok=False)
    inputs_before = {name: identity(ROOT / name) for name in HARNESS_FILES}
    runtime_root = args.runtime_root.resolve()
    materialized = source.materialize(runtime_root, output / "crate")
    with (output / "input.bin").open("xb") as stream:
        assert cases.write_cases(stream) == 72
    env = dict(os.environ)
    env["RUSTC"] = str(args.rustc.absolute())
    env["CARGO_TARGET_DIR"] = str(output / "target")
    env["CARGO_BUILD_JOBS"] = "2"
    env["PATH"] = str(args.cargo.absolute().parent) + os.pathsep + env.get("PATH", "")
    records = []

    def run(name, command, stdin_path=None):
        started = time.monotonic()
        returncode = None
        timed_out = False
        spawn_error = None
        with contextlib.ExitStack() as stack:
            stdin = stack.enter_context(stdin_path.open("rb")) if stdin_path else subprocess.DEVNULL
            stdout = stack.enter_context((output / (name + ".stdout")).open("xb"))
            stderr = stack.enter_context((output / (name + ".stderr")).open("xb"))
            try:
                result = subprocess.run(command, cwd=output / "crate", env=env, stdin=stdin,
                                        stdout=stdout, stderr=stderr, timeout=180)
                returncode = result.returncode
            except subprocess.TimeoutExpired:
                timed_out = True
            except OSError as error:
                spawn_error = str(error)
        records.append(dict(name=name, command=command, cwd=str(output / "crate"),
            timeout_seconds=180, elapsed_seconds=time.monotonic() - started,
            exit_code=returncode, timed_out=timed_out, spawn_error=spawn_error,
            stdin=None if stdin_path is None else identity(stdin_path),
            stdout=identity(output / (name + ".stdout")),
            stderr=identity(output / (name + ".stderr"))))
        (output / "process-receipts.json").write_bytes(canonical(records))
        if timed_out or spawn_error or returncode != 0:
            raise AssertionError(f"{name} failed; complete process receipt and streams retained")

    cargo, rustc = str(args.cargo.absolute()), str(args.rustc.absolute())
    run("rust-version", [rustc, "--version"])
    command = [cargo, "build", "--locked"]
    if args.offline:
        command.append("--offline")
    command += ["--manifest-path", str(output / "crate/Cargo.toml"), "--release"]
    run("build", command)
    binary = output / "target/release/hepta-view-search-original-oracle"
    run("original", [str(binary), str(output / "fixtures")], output / "input.bin")
    summary = reference_summary(output)
    comparison = None if args.native_corpus is None else replay.compare_native(args.native_corpus.resolve(), output)
    inputs_after = {name: identity(ROOT / name) for name in HARNESS_FILES}
    assert inputs_before == inputs_after
    source.check_sources(runtime_root)
    report = dict(schema="hepta.runtime.view-search-original-reference.v1",
        status="REFERENCE_READY" if comparison is None else "BYTES_EQUAL_REQUIRES_NATIVE_ADMISSION",
        materialization=materialized, reference=summary, native_comparison=comparison,
        processes=records, harness_inputs=inputs_before, harness_unchanged=True,
        companion_inputs={name: identity(source.COMPANION / name) for name in source.COMPANION_FILES},
        build_environment={key: env[key] for key in ("RUSTC", "CARGO_TARGET_DIR", "CARGO_BUILD_JOBS", "CARGO_NET_OFFLINE", "RUSTUP_TOOLCHAIN") if key in env},
        explicit_offline=args.offline, independent_input=identity(output / "input.bin"),
        original_output=identity(output / "original.stdout"),
        case_summary=identity(output / "case-summary.json"), binary=identity(binary),
        whole_view_migrated=False, whole_runtime_replaced=False)
    (output / "result.json").write_bytes(canonical(report))
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
