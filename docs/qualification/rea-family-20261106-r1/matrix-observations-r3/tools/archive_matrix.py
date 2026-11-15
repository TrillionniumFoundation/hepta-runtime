#!/usr/bin/env python3
"""Archive the already completed independent R5 build audit, without building/running the binary."""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import tarfile
import types

sys.dont_write_bytecode = True
CONSUMER_SHA = "e968fc1dce065446e821e2e6b9ff23c8368b67be4102829eedb7a34f3361925f"
ARCHIVER_HELPER_SHA = "64f82fbfa0b45de72fdea31999764ac6b2d175acf27bd7ea8341263e14ce9af3"
ASSESSMENT_SHA = "48b7045b56cbbdb91ac67fa5ab67245279d466be4fd53a7ffe9749b799632fdd"
JOBS = {"matrix": ("1a1b271e886-fc05-7e0b", "2bef0828684f9631addeb7963a0511c462bc6cb4fd1de164d66b593984be9512"),
        "independent-consumer": ("1a1b29ce966-fc05-7eee", "7a10184cb984d93b3b09dd08abafe25cc3101c4e7ed3648a2bfda09d4efdde85")}


def pinned_module(path, name, expected):
    raw = path.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == expected
    module = types.ModuleType(name)
    module.__file__ = str(path)
    sys.modules[name] = module
    exec(compile(raw, str(path), "exec"), module.__dict__)
    return module


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("repo", "evidence", "tools", "repair-tools", "run", "worker-jobs", "output", "readback"):
        parser.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    helper = pinned_module(args.tools / "consume_matrix.py", "consume_matrix", CONSUMER_SHA)
    archiver = pinned_module(args.repair_tools / "archive_prechecks.py", "_pinned_repair_archiver", ARCHIVER_HELPER_SHA)
    build = helper.load_pinned_module(args.repo, "rea_build_evidence")
    stored, original_pins = {}, []
    def retain(root, name, member):
        assert member not in stored
        raw = build.read_regular(root, name, 16 * 1024 * 1024)
        stored[member] = raw
        original_pins.append({"path": member, "original_path": str(root / name), "bytes": len(raw), "sha256": helper.sha(raw)})
        return raw
    for directory, dirs, files in os.walk(args.run, followlinks=False):
        for name in dirs:
            assert stat.S_ISDIR((Path(directory) / name).lstat().st_mode)
        for name in sorted(files):
            relative = (Path(directory) / name).relative_to(args.run).as_posix()
            retain(args.run, relative, "consumer-run/" + relative)
            assert len(stored) <= 256
    raw_assessment = stored["consumer-run/assessment.json"]
    assert helper.sha(raw_assessment) == ASSESSMENT_SHA
    assessment = build.parse_json(raw_assessment)
    assert assessment["qualified"] is False and assessment["build_source_binary_binding_verified"] is True
    assert assessment["source_commit"] == helper.SOURCE_COMMIT and assessment["source_tree_sha256"] == helper.SOURCE_TREE
    assert assessment["independent_consumer"]["sha256"] == CONSUMER_SHA
    bundle = build.parse_json(stored["consumer-run/bundle.json"])
    source = build.parse_json(stored["consumer-run/independent-source-before.json"])
    native = build.parse_json(stored["consumer-run/native-file-observation.json"])
    assert build.validate_bundle(args.run, bundle, source, native) == assessment["build_assessment"]
    for name in ("consume_matrix.py", "consumer_preflight_tests.py", "REVIEW.md", "prepared-manifest.json", "peer-review.json"):
        retain(args.tools, name, "tools/" + name)
    assert stored["tools/consume_matrix.py"] == stored["consumer-run/consumer.py"]
    for name, expected in helper.MODULE_PINS.items():
        raw = retain(args.repo, "scripts/" + name + ".py", "tools/" + name + ".py")
        assert helper.sha(raw) == expected
    stored["tools/archive_matrix.py"] = Path(__file__).read_bytes()
    retain(args.repair_tools, "archive_prechecks.py", "tools/archive_prechecks.py")
    for name in ("source-commit-r5.json", "final-source-r5.snapshot.json", "r5_freeze_and_matrix_r3.py",
                 "matrix-r3-launch.json", "matrix-r3-wrapper-outcome.json", "matrix-r3-resources.stdout", "matrix-r3-resources.stderr"):
        retain(args.evidence, name, "originals/" + name)
    assert helper.sha(stored["originals/source-commit-r5.json"]) == helper.SOURCE_RECEIPT_SHA
    assert helper.sha(stored["originals/r5_freeze_and_matrix_r3.py"]) == "a7297d873ef1014cb4d12092ffe623c09ad0b69d32e5d9b9b914eab40f269c31"
    assert build.parse_json(stored["originals/final-source-r5.snapshot.json"]) == source
    for item in assessment["resource_sidecars"]:
        raw = stored["originals/" + Path(item["original_path"]).name]
        assert helper.sha(raw) == item["copied"]["sha256"] and len(raw) == item["copied"]["bytes"]
    job_facts = []
    for label, (job_id, exit_sha) in JOBS.items():
        pieces = {}
        for name in ("request.json", "runner.py", "child.json", "launch.json", "owner-intent.json", "started.json",
                     "exit.json", "exit.witness.json", "stdout.log", "stderr.log"):
            pieces[name] = retain(args.worker_jobs, job_id + "/" + name, "originals/jobs/" + label + "/" + name)
        assert helper.sha(pieces["exit.json"]) == exit_sha
        closed, request = build.parse_json(pieces["exit.json"]), build.parse_json(pieces["request.json"])
        assert closed["job_id"] == request["job_id"] == job_id and closed["exit_code"] == 0
        assert closed["launch_nonce"] == request["launch_nonce"] and closed["terminal_publication_protocol"] == 1
        assert closed["output_complete"] is True and closed["output_durable"] is True
        assert not closed["cancelled"] and not closed["timed_out"]
        assert not any(closed["log_truncated"].values()) and not any(closed["log_errors"].values())
        for stream in ("stdout", "stderr"):
            assert closed["log_bytes"][stream]["seen"] == closed["log_bytes"][stream]["stored"] == len(pieces[stream + ".log"])
            assert closed["log_synced"][stream] is True
        assert pieces["stderr.log"] == b""
        assert request["executable"] == "/bin/sh" and request["args"][0] == "-c" and len(request["args"]) == 2
        stored["derived/" + label + "-actual-command.sh"] = request["args"][1].encode()
        if label == "independent-consumer":
            observed = build.parse_json(pieces["stdout.log"])
            assert observed["assessment"]["sha256"] == ASSESSMENT_SHA and observed["assessment"]["bytes"] == len(raw_assessment)
            assert observed["qualified"] is False and observed["build_source_binary_binding_verified"] is True
            assert observed["archive"]["sha256"] == helper.sha(stored["consumer-run/original-build-evidence.tar.gz"])
        job_facts.append({"job_id": job_id, "label": label, "exit_code": 0, "exit_sha256": exit_sha,
                          "stdout_bytes": len(pieces["stdout.log"]), "stderr_bytes": len(pieces["stderr.log"]),
                          "complete_durable_outputs": True})
    members = [{"path": name, "bytes": len(raw), "sha256": helper.sha(raw)} for name, raw in sorted(stored.items())]
    stored["members-manifest.json"] = helper.json_bytes({"schema": "hepta.rea.matrix-observation-members.v1", "qualified": False,
                                                          "files": members, "original_file_provenance": original_pins})
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name, raw in sorted(stored.items()):
            entry = tarfile.TarInfo(name)
            entry.size, entry.mode, entry.mtime = len(raw), 0o644, 0
            archive.addfile(entry, io.BytesIO(raw))
    packed = gzip.compress(buffer.getvalue(), mtime=0)
    unpacked = archiver.safe_unpack(packed, args.readback, build)
    assert {row["path"]: (row["bytes"], row["sha256"]) for row in unpacked["files"]} == {
        name: (len(raw), helper.sha(raw)) for name, raw in stored.items()}
    replayed = build.validate_bundle(args.readback / "consumer-run", bundle, source, native)
    assert replayed == assessment["build_assessment"]
    for item in original_pins:
        p = Path(item["original_path"])
        raw = build.read_regular(p.parent, p.name, 16 * 1024 * 1024)
        assert helper.sha(raw) == item["sha256"] and len(raw) == item["bytes"]
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    archive_ref = helper.save(args.output / "matrix-observations.tar.gz", packed)
    helper.save(args.output / "assessment.json", raw_assessment)
    # Retain the original 22-file archive independently for simple receipt replay.
    inner_ref = helper.save(args.output / "original-build-evidence.tar.gz", stored["consumer-run/original-build-evidence.tar.gz"])
    replay = {"schema": "hepta.rea.matrix-observation-archive-replay.v1", "qualified": False,
              "original_independent_assessment_sha256": ASSESSMENT_SHA, "build_assessment_replayed": replayed,
              "member_count": unpacked["file_count"], "safe_unpack_readback": True,
              "all_members_exact": True, "originals_unchanged_after_archive": True,
              "scope": "Actual relocated artifact replay of the completed original independent audit. This archive replay uses its retained source/binary observations; it does not re-execute or freshly observe an external binary, rebuild, or promote operation qualification."}
    replay_ref = helper.save(args.output / "archive-replay.json", helper.json_bytes(replay))
    manifest = {"schema": "hepta.rea.matrix-observation-archive-manifest.v1", "qualified": False,
                "source_commit": helper.SOURCE_COMMIT, "source_tree_sha256": helper.SOURCE_TREE,
                "assessment": {"path": "assessment.json", "bytes": len(raw_assessment), "sha256": ASSESSMENT_SHA},
                "archive": dict(archive_ref, path="matrix-observations.tar.gz"),
                "original_22_file_archive": dict(inner_ref, path="original-build-evidence.tar.gz"),
                "archive_replay": dict(replay_ref, path="archive-replay.json"),
                "member_count": unpacked["file_count"], "members": unpacked["files"],
                "closed_jobs": job_facts, "original_file_provenance": original_pins,
                "native_binary_contents_included": False, "source_checkout_contents_included": False,
                "originals_modified": False}
    manifest_ref = helper.save(args.output / "manifest.json", helper.json_bytes(manifest))
    (args.output / "tools").mkdir()
    for name in ("consume_matrix.py", "consumer_preflight_tests.py", "rea_build_evidence.py", "rea_full_qualification.py",
                 "archive_matrix.py", "archive_prechecks.py", "REVIEW.md", "prepared-manifest.json", "peer-review.json"):
        helper.save(args.output / "tools" / name, stored["tools/" + name])
    readme = """# Independent R5 build and matrix observations

The completed nine-stage matrix and its independent original-receipt consumer passed for
source commit `fe3223cabbd2a8f1aa75a4ab57507bdb72291242`. The 1,429 selected execution inputs
have tree SHA256 `1a83f83cf62bf3d96e50c944722977b6971ffe686aecd131cab5e728dd802424`.
The independent consumer bound every selected Git blob and executable bit to that commit;
current publication HEAD is recorded separately.

| Test configuration | Actual PASS rows | Binaries reported | Reported skipped | Reported slow |
| --- | ---: | ---: | ---: | ---: |
| All features | 2,327 | 18 | 40 | 0 |
| No default features | 2,298 | 17 | 28 | 0 |

Each row is independently recovered from the complete nextest logs, including unique test
identities and sequential counters. These are two feature-specific executions, not 4,625
distinct tests. Skipped counts are reported totals: individual skipped identities and
doctests are not claimed. Both Clippy configurations and formatting passed. The other
stages retain actual Cargo/Rust/nextest version output and the explicit final native build.

The final binary was 51,146,872 bytes with SHA256
`260205be5fd4cdf363b8f426002c057d1d939ce299843f979770a585bb72faf6`.
Cargo identified its real binary target, `default` and `remote-fs` features, `fresh: false`,
optimization level 1, zero debuginfo and a non-test profile. Development/test debuginfo were
set to zero and incremental compilation was disabled. The independent audit hashed the
binary before and after consumption and never executed it. Binary contents are excluded
from Git and this package; the observed original path and full file identity are retained.

Matrix job `1a1b271e886-fc05-7e0b` and independent-consumer job
`1a1b29ce966-fc05-7eee` both exited 0 with complete durable stdout and empty stderr.
Their exact worker requests, inline commands, launcher, raw terminal records and output
bytes are retained. The matrix's nine stage exits and the independent audit's actual
result are separate evidence. The original source-freeze receipt, immutable launcher,
launch/outcome metadata and raw resource query are included without rewriting them.

Resource observations belong to the complete user-systemd developer-build unit, including
launcher overhead. Its 400% CPU-time quota, 12 GiB memory limit and zero-swap limit matched
the requested profile. Observed MemoryPeak was 6,863,306,752 bytes and CPUUsageNSec was
2,791,605,110,000. I/O accounting was unavailable. These are not per-stage measurements,
release costs, storage-budget measurements or deployment qualification.

`assessment.json` is the exact 19,952-byte independent result, SHA256
`48b7045b56cbbdb91ac67fa5ab67245279d466be4fd53a7ffe9749b799632fdd`.
`original-build-evidence.tar.gz` holds exactly the 22 original summary/source/monitor/log
files. `matrix-observations.tar.gz` additionally preserves the independent snapshot/Git/
binary observations, actual original replay outputs, complete per-test rows, scripts,
peer review, preparation data-check source and the terminal job metadata. No build or test
was rerun for archiving. The source/monitor records bind the completed build; toolchain and
dependency cache remain trusted external inputs rather than included or hermetically
reproduced artifacts.

Every archive member was bounded, validated against unsafe names/duplicates/links/special
files, physically extracted into a new private root and read back. The frozen build
consumer successfully replayed the exact 22-file bundle from that relocated root;
`archive-replay.json` records that actual result. This replay checks retained observations
and does not claim to freshly observe a binary that is absent from the archive. All
original file hashes were rechecked after sealing and no original receipt was modified.

The scripts in `tools/` include the frozen independent consumer, its seven pure-log data
checks, both pinned repository modules and the archive helper. Full independent source
and binary re-observation requires the matching source checkout and separately retained
binary. A receipt-only replay uses the preserved `consumer-run/bundle.json`,
`independent-source-before.json` and `native-file-observation.json` with
`rea_build_evidence.validate_bundle` rooted at the extracted `consumer-run` directory.
Recorded original absolute execution paths remain metadata; artifact reads use that root.

The result verifies this local build/source/binary binding. Operation qualification stays
`qualified: false` and 0/229. ELF/Evidence behavior, complete Ghidra Evidence equality,
cross-platform support, release deployment and remaining P0–P5 work require their own
separate observations. Later documentation/evidence commits do not change the recorded
binary source commit.
"""
    readme_ref = helper.save(args.output / "README.md", readme.encode())
    print(json.dumps({"archive": archive_ref, "manifest": manifest_ref, "archive_replay": replay_ref,
                      "readme": readme_ref, "original_22_file_archive": inner_ref,
                      "member_count": unpacked["file_count"], "qualified": False,
                      "native_binary_contents_included": False}, sort_keys=True))


if __name__ == "__main__":
    main()
