"""Fresh locked Rust replay of native request-context and response-hint corpora.

Expected semantics execute the immutable original Rust bodies and real Tokio
scopes. Python performs framing, source checks, byte comparisons and receipts.
"""
from __future__ import annotations
import argparse
import base64
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import time

if __package__:
    from .cases import cases
    from .verify_sources import materialize
else:
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from cases import cases
    from verify_sources import materialize

ROOT = Path(__file__).resolve().parent


def digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def execute(command, output, *, stdin=None, timeout=120, env=None):
    with (output.with_suffix(".stdout")).open("wb") as out, output.with_suffix(".stderr").open("wb") as err:
        process = subprocess.run(command, stdin=stdin, stdout=out, stderr=err, timeout=timeout, env=env)
    if process.returncode:
        raise AssertionError({"command": command, "returncode": process.returncode,
            "stderr_path": str(output.with_suffix(".stderr"))})


def event_for(frame):
    magic, op, size, reserved = struct.unpack_from("<8s3Q", frame)
    assert magic == b"HRCXQ001" and reserved == 0 and len(frame) == 32 + size
    payload = frame[32:]
    names = {1: "init", 2: "enter", 3: "exit", 4: "push", 5: "drain", 6: "peek", 7: "cache", 8: "destroy"}
    event = {"op": names[op]}
    if op == 2:
        assert len(payload) == 8
        event["cache"] = struct.unpack("<Q", payload)[0]
    elif op == 4:
        event["hint"] = payload.decode("utf-8", "strict")
    else:
        assert not payload
    return event


def prepare_context(corpus, output):
    groups, boundaries = {}, []
    counts = {"semantic_rows": 0, "original_accessor_rows": 0,
        "private_peek_observations": 0, "lifecycle_adapter_rows": 0,
        "native_boundary_rows_without_rust_semantics": 0}
    with gzip.open(corpus / "native-events.jsonl.gz", "rt", encoding="utf-8") as stream:
        for line in stream:
            row = json.loads(line)
            if row["classification"] == "native-boundary-refusal":
                boundaries.append(row)
                counts["native_boundary_rows_without_rust_semantics"] += 1
                continue
            assert row["classification"] == "independent-model-native-state"
            wire = base64.b64decode(row["input_base64"], validate=True)
            native = base64.b64decode(row["output_base64"], validate=True)
            assert hashlib.sha256(wire).hexdigest() == row["input_sha256"]
            assert hashlib.sha256(native).hexdigest() == row["output_sha256"]
            op = struct.unpack_from("<Q", wire, 8)[0]
            assert op == row["operation"]
            key = ("original_accessor_rows" if op in (4, 5, 7) else
                "private_peek_observations" if op == 6 else "lifecycle_adapter_rows")
            counts[key] += 1
            counts["semantic_rows"] += 1
            groups.setdefault(row["session"], []).append((wire, native, row["ordinal"]))
    with (output / "context-input.jsonl").open("w", encoding="utf-8") as stream:
        for session, rows in groups.items():
            item = {"op": "trace", "id": session, "events": [event_for(row[0]) for row in rows]}
            stream.write(json.dumps(item, ensure_ascii=False, separators=(",", ":")) + "\n")
    (output / "native-boundaries-not-a-rust-domain.json").write_text(json.dumps(boundaries, indent=2) + "\n")
    summary = json.loads((corpus / "summary.json").read_text())
    assert summary["corpus_sha256"] == digest(corpus / "native-events.jsonl.gz")
    assert summary["counts"]["semantic_rows"] == counts["semantic_rows"]
    assert summary["counts"]["native_calls"] == counts["semantic_rows"] + len(boundaries)
    return groups, counts


def compare_context(original_output, groups):
    steps, compared, seen = 0, 0, set()
    with original_output.open(encoding="utf-8") as stream:
        for line in stream:
            record = json.loads(line)
            session = record["id"]
            assert session not in seen
            seen.add(session)
            rows = groups[session]
            assert len(record["steps"]) == len(rows)
            for index, (reference, (wire, native, ordinal)) in enumerate(zip(record["steps"], rows)):
                assert reference["index"] == index
                assert bytes.fromhex(reference["input_hex"]) == wire
                expected = bytes.fromhex(reference["output_hex"])
                if expected != native:
                    raise AssertionError({"session": session, "ordinal": ordinal, "index": index,
                        "expected_sha256": hashlib.sha256(expected).hexdigest(),
                        "native_sha256": hashlib.sha256(native).hexdigest()})
                steps += 1
                compared += len(native)
    assert seen == set(groups)
    return {"sessions": len(seen), "compared_rows": steps, "compared_response_bytes": compared,
        "every_response_byte_equal": True}


def compare_response(corpus, reference):
    compared, count, body_bytes = 0, 0, 0
    with gzip.open(corpus / "native-output.bin.gz", "rb") as native, reference.open("rb") as original:
        while True:
            a, b = native.read(65536), original.read(65536)
            assert a == b, {"offset": compared, "native_chunk": len(a), "reference_chunk": len(b)}
            if not a:
                break
            compared += len(a)
    with reference.open("rb") as stream:
        while header := stream.read(16):
            assert len(header) == 16
            code, size = struct.unpack("<QQ", header)
            assert code == size
            payload = stream.read(size)
            assert len(payload) == size
            body_bytes += size
            count += 1
    return {"cases": count, "framed_bytes": compared, "body_bytes": body_bytes,
        "every_output_byte_equal": True, "output_sha256": digest(reference),
        "post_drain_list_supplied_verbatim": True, "dedup_applied_by_composer": False}


def run(args, execute_callback=None, environment=None):
    """Optional callback accepts record_check-compatible name/command/timeout/env/input_bytes.

    It must return subprocess.CompletedProcess. Exactly three top-level calls
    are recorded, and every original function executes in the fresh Rust build.
    """
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    started = time.monotonic()
    crate = output / "crate"
    source_check = materialize(ROOT, args.runtime_root, crate)
    env = dict(os.environ if environment is None else environment)
    env["CARGO_BUILD_JOBS"] = "2"
    offline = bool(getattr(args, "offline", False))
    if offline:
        env["CARGO_NET_OFFLINE"] = "true"
    def capture(name, command, prefix, *, stdin=None, timeout=120):
        if execute_callback is None:
            return execute(command, prefix, stdin=stdin, timeout=timeout, env=env)
        process = execute_callback(name=name, command=command, timeout=timeout, env=env,
            input_bytes=None if stdin is None else stdin.read())
        prefix.with_suffix(".stdout").write_bytes(process.stdout)
        prefix.with_suffix(".stderr").write_bytes(process.stderr)
        if process.returncode:
            raise AssertionError({"name": name, "returncode": process.returncode})
    target = output / "cargo-target"
    capture("request-context-rust-compile", [args.cargo, "build", "--locked", *(["--offline"] if offline else []),
        "--manifest-path", str(crate / "Cargo.toml"), "--target-dir", str(target)], output / "build", timeout=180)
    binary = target / "debug/hepta-request-context-original-oracle"

    controls = output / "original-controls.jsonl"
    groups, classifications = prepare_context(args.context_corpus, output)
    control_rows = cases()
    controls.write_text("".join(json.dumps(row, ensure_ascii=True, separators=(",", ":")) + "\n" for row in control_rows))
    combined = output / "combined-input.jsonl"
    with combined.open("wb") as dest:
        for path in (controls, output / "context-input.jsonl"):
            with path.open("rb") as src:
                shutil.copyfileobj(src, dest)
    with combined.open("rb") as stream:
        capture("request-context-rust-compare", [str(binary)], output / "combined-original", stdin=stream, timeout=120)
    with (output / "combined-original.stdout").open("rb") as stream, (output / "original-controls.stdout").open("wb") as original, (output / "context-original.stdout").open("wb") as captured:
        for index, line in enumerate(stream):
            (original if index < len(control_rows) else captured).write(line)
    with (output / "original-controls.stdout").open() as stream:
        first = json.loads(stream.readline())
    assert first["ok"] and first["case_count"] == 13
    context = compare_context(output / "context-original.stdout", groups)
    assert context["compared_rows"] == classifications["semantic_rows"]
    del groups

    response_input = output / "response-input.bin"
    with gzip.open(args.response_corpus / "input.bin.gz", "rb") as src, response_input.open("wb") as dest:
        shutil.copyfileobj(src, dest)
    response_output = output / "response-original.bin"
    capture("response-hints-rust-compare", [str(binary), "--append-corpus", str(response_input), str(response_output)],
        output / "response-original", timeout=60)
    response = compare_response(args.response_corpus, response_output)

    # This direction is separate: original Rust-generated traces -> actual HIA.
    extra = None
    if args.context_manifest is not None:
        if __package__:
            from .replay_original import replay
        else:
            from replay_original import replay
        extra = replay(output / "original-controls.stdout", args.context_manifest,
            args.runtime_root, output / "original-to-native")

    report = {"schema": "hepta.runtime.request-context.fresh-original-replay.v1", "status": "PASS",
        "source_check": source_check, "seconds": time.monotonic() - started,
        "fresh_locked_build": True, "original_dependency_lock_match": True,
        "top_level_subprocesses": 3,
        "rust_executable_sha256": digest(binary), "driver_sha256": digest(ROOT / "src/main.rs"),
        "cargo_lock_sha256": digest(ROOT / "Cargo.lock"), "tokio_scenarios": first,
        "native_context_to_original": {**context, **classifications},
        "native_response_to_original": response, "original_to_native_extra": extra,
        "native_context_corpus_sha256": digest(args.context_corpus / "native-events.jsonl.gz"),
        "native_response_input_sha256": digest(args.response_corpus / "input.bin.gz"),
        "native_response_output_sha256": digest(args.response_corpus / "native-output.bin.gz"),
        "native_scheduler_qualified": False, "unbounded_api_equivalence_proved": False,
        "production_cutover_qualified": False}
    (output / "RESULT.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--cargo", default="cargo")
    parser.add_argument("--runtime-root", type=Path, required=True)
    parser.add_argument("--context-corpus", type=Path, required=True)
    parser.add_argument("--response-corpus", type=Path, required=True)
    parser.add_argument("--context-manifest", type=Path)
    parser.add_argument("--offline", action="store_true", help="Use only an already populated Cargo cache")
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    print(json.dumps(run(arguments), sort_keys=True))
