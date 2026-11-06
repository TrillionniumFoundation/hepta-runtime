#!/usr/bin/env python3
"""Read-only, pinned R5 build receipt consumption; never launches the built binary."""
import argparse
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tarfile
import tomllib
import zlib

sys.dont_write_bytecode = True
SOURCE_COMMIT = "fe3223cabbd2a8f1aa75a4ab57507bdb72291242"
SOURCE_TREE = "1a83f83cf62bf3d96e50c944722977b6971ffe686aecd131cab5e728dd802424"
SOURCE_RECEIPT_SHA = "7b10276e2c34502345594139b3a89ab4b0f5d3634e89a2a54efaff732e51c314"
MODULE_PINS = {
    "rea_build_evidence": "39920349c977affe142b05beeac7034577246c551b5f915c2d976c0f91c62093",
    "rea_full_qualification": "8a6594e1e146d5f841539c125a83c6aed88e175586f2ecf81d022da43bd8a0ed",
}
ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
SHA256 = re.compile(r"[0-9a-f]{64}")
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False, allow_nan=False) + "\n").encode()


def save(path, raw):
    with path.open("xb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    return {"path": str(path), "bytes": len(raw), "sha256": sha(raw)}


def load_pinned_module(repo, name):
    path = repo / "scripts" / (name + ".py")
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, "module is not a single-link regular file")
    raw = path.read_bytes()
    require(sha(raw) == MODULE_PINS[name], "reviewed module SHA differs: " + name)
    # Execute the exact bytes just pinned, rather than reopen by import path.
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    exec(compile(raw, str(path), "exec"), module.__dict__)
    return module


def parse_nextest(stdout, stderr):
    """Retain raw logs elsewhere; parse counts without changing evidence bytes."""
    lines = [ANSI.sub("", line).strip() for line in (stdout + b"\n" + stderr).decode("utf-8").splitlines()]
    starts = [line for line in lines if line.startswith("Starting ")]
    summaries = [line for line in lines if line.startswith("Summary [")]
    require(len(starts) == 1 and len(summaries) == 1, "nextest start/terminal summary is missing or duplicated")
    start = re.fullmatch(r"Starting (\d+) tests across (\d+) binar(?:y|ies)(?: \((\d+) tests skipped\))?", starts[0])
    summary = re.fullmatch(r"Summary \[([^\]]+)\] (\d+) tests run: (\d+) passed(?: \((\d+) slow\))?(?:, (\d+) skipped)?", summaries[0])
    require(start is not None and summary is not None, "unreviewed nextest summary syntax")
    count, passed, skipped, slow = int(summary[2]), int(summary[3]), int(summary[5] or 0), int(summary[4] or 0)
    require(count > 0 and count == passed == int(start[1]) and skipped == int(start[3] or 0), "nextest start/run/pass/skip counts differ")
    require(int(start[2]) > 0 and slow <= passed, "invalid binary/slow counts")
    rows = []
    for line in lines:
        if line.startswith("PASS "):
            match = re.fullmatch(r"PASS\s+\[[^\]]+\]\s+\(\s*(\d+)/(\d+)\)\s+(.+)", line)
            require(match is not None and int(match[2]) == count, "invalid nextest PASS row")
            rows.append({"counter": int(match[1]), "test_identity": match[3], "line": line})
        require(not re.match(r"(?:FAIL|TIMEOUT|LEAK|FLAKY|XFAIL)\s+\[", line), "nextest contains a non-PASS terminal row")
    require(len(rows) == count and [row["counter"] for row in rows] == list(range(1, count + 1)), "PASS counters are incomplete, duplicated or reordered")
    require(len({row["test_identity"] for row in rows}) == count, "duplicate nextest test identity")
    return {
        "tests_run": count, "passed": passed, "binaries_reported": int(start[2]),
        "reported_skipped": skipped, "reported_slow": slow,
        "verbatim_start": starts[0], "verbatim_summary": summaries[0], "pass_rows": rows,
        "skip_scope": "Reported nextest skipped count; this log does not identify each ignored/filtered test. No doctest claim.",
    }


def git(repo, *args):
    environment = dict(os.environ, GIT_OPTIONAL_LOCKS="0")
    result = subprocess.run(["git", "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false", *args],
                            cwd=repo, env=environment, capture_output=True, timeout=30, check=True)
    return result.stdout


def bind_git_source(repo, selection, snapshot, build):
    require(git(repo, "rev-parse", "--verify", SOURCE_COMMIT + "^{commit}").decode().strip() == SOURCE_COMMIT, "source commit is unavailable")
    inventory = {}
    for entry in git(repo, "ls-tree", "-r", "-z", "--full-tree", SOURCE_COMMIT).split(b"\0"):
        if not entry:
            continue
        header, raw_name = entry.split(b"\t", 1)
        mode, kind, blob = header.decode("ascii").split()
        name = raw_name.decode("utf-8")
        build.relative_name(name)
        require(name not in inventory, "duplicate Git tree entry")
        if selection.source(repo / name):
            require(kind == "blob" and mode in {"100644", "100755"} and re.fullmatch(r"[0-9a-f]{40}", blob), "selected Git entry is not a regular SHA1 blob")
            inventory[name] = (mode, blob)
    require(set(inventory) == {row["path"] for row in snapshot["files"]}, "working snapshot paths differ from selected source commit")
    rows = []
    for item in snapshot["files"]:
        raw = build.read_regular(repo, item["path"], maximum=MAX_ARCHIVE_BYTES)
        require(len(raw) == item["bytes"] and sha(raw) == item["sha256"], "source changed during Git binding")
        object_id = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
        mode, expected = inventory[item["path"]]
        require(object_id == expected, "working file differs from source commit blob: " + item["path"])
        require(mode == ("100755" if int(item["mode"], 8) & 0o111 else "100644"), "Git executable bit differs")
        rows.append({"path": item["path"], "git_mode": mode, "git_blob_sha1": object_id, "sha256": item["sha256"]})
    return {"source_commit": SOURCE_COMMIT, "current_head_observed": git(repo, "rev-parse", "HEAD").decode().strip(),
            "selected_files": rows, "selected_file_count": len(rows),
            "scope": "Source commit is independently bound by Git blob bytes and executable bits; current HEAD is publication metadata and is not substituted for the binary source commit."}


def archive_bundle(output, bundle, build, source, native):
    names = [item["path"] for item in [bundle["summary"]] + bundle["artifacts"]]
    require(len(names) == 22 and len(set(names)) == 22, "unexpected bundle inventory")
    plain = io.BytesIO()
    with tarfile.open(fileobj=plain, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name in names:
            raw = build.read_regular(output, name)
            entry = tarfile.TarInfo(name)
            entry.size, entry.mode, entry.mtime = len(raw), 0o644, 0
            archive.addfile(entry, io.BytesIO(raw))
    import gzip
    packed = gzip.compress(plain.getvalue(), mtime=0)
    saved = save(output / "original-build-evidence.tar.gz", packed)
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    unpacked = decoder.decompress(packed, MAX_ARCHIVE_BYTES + 1)
    require(len(unpacked) <= MAX_ARCHIVE_BYTES and decoder.eof and not decoder.unconsumed_tail and not decoder.unused_data,
            "archive exceeds bounds or contains trailing/multiple gzip members")
    replay = output / "relocated-archive-readback"
    replay.mkdir(mode=0o700)
    (replay / "build-evidence").mkdir(mode=0o700)
    read_names = []
    with tarfile.open(fileobj=io.BytesIO(unpacked), mode="r:") as archive:
        for entry in archive:
            require(entry.name in names and entry.name not in read_names and entry.isreg() and not entry.pax_headers,
                    "archive member type/name/duplication differs")
            raw = archive.extractfile(entry).read(MAX_ARCHIVE_BYTES + 1)
            require(len(raw) == entry.size and len(raw) <= MAX_ARCHIVE_BYTES, "archive member is truncated or excessive")
            save(replay / entry.name, raw)
            read_names.append(entry.name)
    require(read_names == names, "archive members are missing or reordered")
    repeated = build.validate_bundle(replay, bundle, source, native)
    return {"archive": saved, "members": names, "member_count": len(names),
            "safe_unpack_and_relocated_consumer": repeated,
            "scope": "Exactly 22 original summary/source/monitor/log files. Executable contents, dependency cache, toolchain, repository checkout and resource sidecars are outside this archive."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--source-receipt", type=Path, required=True)
    parser.add_argument("--summary", type=Path, required=True)
    parser.add_argument("--summary-sha256", required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--binary-sha256", required=True)
    parser.add_argument("--binary-bytes", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--resource-sidecar", action="append", default=[], metavar="ABSOLUTE_PATH=SHA256")
    args = parser.parse_args()
    os.umask(0o077)
    require(all(path.is_absolute() for path in (args.repo, args.source_receipt, args.summary, args.binary, args.output)), "explicit absolute paths required")
    require(SHA256.fullmatch(args.summary_sha256) and SHA256.fullmatch(args.binary_sha256) and args.binary_bytes > 0, "final summary/binary pins required")
    build = load_pinned_module(args.repo, "rea_build_evidence")
    producer = load_pinned_module(args.repo, "rea_full_qualification")
    raw_receipt = build.read_regular(args.source_receipt.parent, args.source_receipt.name, build.MAX_JSON_BYTES)
    require(sha(raw_receipt) == SOURCE_RECEIPT_SHA, "source freeze receipt SHA differs")
    receipt = build.parse_json(raw_receipt)
    require(receipt["source_commit"] == SOURCE_COMMIT and receipt["source_tree_sha256"] == SOURCE_TREE, "not the reviewed final R5 source")
    raw_summary = build.read_regular(args.summary.parent, args.summary.name, build.MAX_JSON_BYTES)
    require(sha(raw_summary) == args.summary_sha256, "final summary pin differs")
    summary = build.parse_json(raw_summary)
    require(summary.get("status") == "passed" and summary.get("qualified") is True, "producer matrix is incomplete or failed")
    require(summary["inputs"]["repo"] == str(args.repo) and summary["inputs"]["output_dir"] == str(args.summary.parent), "matrix execution directories differ")
    selection = producer.Selection(args.repo, Path(summary["inputs"]["target_dir"]), args.summary.parent)
    snapshot = selection.snapshot()
    require(snapshot["tree_sha256"] == SOURCE_TREE, "current selected source differs from R5")
    frozen_path = Path(receipt["selected_snapshot"]["path"])
    frozen_raw = build.read_regular(frozen_path.parent, frozen_path.name, build.MAX_JSON_BYTES)
    require(len(frozen_raw) == receipt["selected_snapshot"]["bytes"] and sha(frozen_raw) == receipt["selected_snapshot"]["sha256"], "frozen snapshot pin differs")
    require(build.parse_json(frozen_raw) == snapshot, "freeze/current snapshot differ")
    native = producer.build_artifact_file(args.binary, str(args.binary))
    require(native["sha256"] == args.binary_sha256 and native["bytes"] == args.binary_bytes, "supplied final binary pins differ")
    git_binding = bind_git_source(args.repo, selection, snapshot, build)
    args.output.mkdir(mode=0o700, exist_ok=False)
    self_raw = Path(__file__).read_bytes()
    self_ref = save(args.output / "consumer.py", self_raw)
    save(args.output / "source-commit-r5.json", raw_receipt)
    save(args.output / "independent-source-before.json", json_bytes(snapshot))
    save(args.output / "git-source-binding.json", json_bytes(git_binding))
    save(args.output / "native-file-observation.json", json_bytes(native))
    bundle, assessment = build.capture_build(args.summary, args.summary_sha256, args.output, snapshot, native)
    require(build.validate_bundle(args.output, bundle, snapshot, native) == assessment, "copied bundle differs on independent replay")
    save(args.output / "bundle.json", json_bytes(bundle))
    parsed_runs = {}
    for index, name in ((7, "nextest-all-features"), (8, "nextest-no-default-features")):
        stdout = build.read_regular(args.output, f"build-evidence/{index:02d}-{name}.stdout.log")
        stderr = build.read_regular(args.output, f"build-evidence/{index:02d}-{name}.stderr.log")
        parsed_runs[name] = parse_nextest(stdout, stderr)
    parsed_ref = save(args.output / "nextest-terminal-and-rows.json", json_bytes(parsed_runs))
    manifest = tomllib.loads(build.read_regular(args.repo, "Cargo.toml").decode("utf-8"))
    actual_features = assessment["compiler_artifact"]["features"]
    require(len(actual_features) == len(set(actual_features)) and set(actual_features) == set(manifest.get("features", {})), "final compiler all-features set differs from frozen package features")
    archive = archive_bundle(args.output, bundle, build, snapshot, native)
    sidecars = []
    for index, item in enumerate(args.resource_sidecar):
        path_string, expected = item.rsplit("=", 1)
        path = Path(path_string)
        require(path.is_absolute() and SHA256.fullmatch(expected), "resource sidecar needs exact absolute path and SHA")
        raw = build.read_regular(path.parent, path.name, build.MAX_JSON_BYTES)
        require(sha(raw) == expected, "resource sidecar pin differs")
        copied = save(args.output / f"resource-sidecar-{index:02d}-{path.name}", raw)
        sidecars.append({"original_path": path_string, "copied": copied, "raw_utf8": raw.decode("utf-8")})
    after = selection.snapshot()
    require(after == snapshot, "source changed during independent consumption")
    require(producer.build_artifact_file(args.binary, str(args.binary)) == native, "binary changed during independent consumption")
    for name, expected in MODULE_PINS.items():
        require(sha(build.read_regular(args.repo, "scripts/" + name + ".py")) == expected, "consumer/producer changed during replay")
    require(build.validate_bundle(args.output, bundle, after, native) == assessment, "final archive revalidation differs")
    save(args.output / "independent-source-after.json", json_bytes(after))
    report = {
        "schema": "hepta.rea.r5-independent-build-assessment.v1", "qualified": False,
        "build_source_binary_binding_verified": True, "source_commit": SOURCE_COMMIT,
        "source_tree_sha256": SOURCE_TREE, "source_file_count": snapshot["file_count"],
        "independent_consumer": self_ref, "frozen_module_pins": MODULE_PINS,
        "source_commit_receipt_sha256": SOURCE_RECEIPT_SHA, "build_assessment": assessment,
        "nextest_full_rows": parsed_ref,
        "nextest": {name: {key: value for key, value in result.items() if key != "pass_rows"} for name, result in parsed_runs.items()},
        "final_compiler_observation": assessment["compiler_artifact"],
        "archive": archive, "resource_sidecars": sidecars,
        "resource_scope": "Separate pinned sidecar observations, not a build/operation gate. Systemd-unit attribution requires the retained launch/outcome metadata; no release cost, disk budget or deployment qualification inferred.",
        "scope": "Read-only final R5 matrix/source/commit/binary binding. Nine successful build stages, actual per-test PASS rows and exact raw receipts. The binary was hashed, never executed by this consumer. Library assessment executed_binary_path names the supplied observed file only. Trusted producer, toolchain and dependency cache; no REA operation, Provider parity, cross-platform or P0-P5 qualification.",
        "original_receipts_modified": False, "current_git_head_observed": git_binding["current_head_observed"],
    }
    saved = save(args.output / "assessment.json", json_bytes(report))
    print(json.dumps({"assessment": saved, "qualified": False, "build_source_binary_binding_verified": True,
                      "source_commit": SOURCE_COMMIT, "source_tree_sha256": SOURCE_TREE,
                      "nextest": report["nextest"], "archive": archive["archive"]}, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(json.dumps({"status": "INVALID", "qualified": False, "error": type(error).__name__ + ": " + str(error)}, sort_keys=True), file=sys.stderr)
        raise SystemExit(1)
