#!/usr/bin/env python3
"""Seal closed R5 repair observations only; active matrix outputs are excluded."""
import argparse
import gzip
import io
import json
import os
from pathlib import Path
import re
import stat
import tarfile
import zlib
from consume_matrix import (SOURCE_COMMIT, SOURCE_RECEIPT_SHA, SOURCE_TREE, bind_git_source,
                            git, json_bytes, load_pinned_module, parse_nextest, require, save, sha)

BASE_COMMIT = "b3bac9e47fd09ee2c6bb0d62802bd55b7662f366"
JOBS = {
    "part-a-bootstrap": ("1a1b2444dec-fc05-7d3e", 1),
    "part-a-corrected": ("1a1b245f180-fc05-7d46", 0),
    "part-b-initial": ("1a1b267f662-fc05-7deb", 0),
    "part-b-corrected": ("1a1b26f9dd7-fc05-7e03", 1),
}
MATRIX_JOB = "1a1b271e886-fc05-7e0b"
PINS = {
    "r5-approved-repairs-part-a.tar.gz": "fa349924e2e103b1281fb528e3574bec0916bd251784b1602c065de8d351f81c",
    "r5-approved-repairs-part-b.tar.gz": "508b15649387affcc3598e57817e02629f4597796b46e27bfe91e7a594893cf3",
    "r5-ghidra-client-review.tar.gz": "134b015f895433fca30194976069ba4b667c72f13fb927ce3ed55efddf074c4b",
    "r5-ghidra-harness-review.tar.gz": "b529a716ca9979f285efcd75567fec3bcd00501e838e91a249e723aba8c3c25a",
    "ghidra-mcp-client-review-r1.tar.gz": "39fed4d0d3751c09e3cbe7d22ed88e69f810d1be0fd15ab4e6973bbf39a3a452",
    "ghidra-xrefs-review-r1.tar.gz": "dec617fb7f8d07d543c8b35a534a41007248c18bfa75ef6ef5f22a7c67c6f9a3",
    "ghidra-mcp-capture-r4-review-r1.tar.gz": "bfe5d4f4870e19c43e17a6aa37a1a53cae84f7a9daea824f287fca5ba8aed2ad",
    "ghidra-r4-state-consumer-r1.tar.gz": "aeabef9a7d310cec0656310a62f6dcd30a29285aeb9f61c23ce1217cf045e4b8",
    "ghidra-xrefs-peer-review.json": "4febaa7ae4b115e88710fcab91e6546791c5d9fdb3d486da3795700de7148146",
    "source-commit-r5.json": SOURCE_RECEIPT_SHA,
    "final-source-r5.snapshot.json": "004784d72734f34193a94eb04243bc24e7780260441f188e52fd09c64635befc",
    "r5_freeze_and_matrix_r3.py": "a7297d873ef1014cb4d12092ffe623c09ad0b69d32e5d9b9b914eab40f269c31",
    "r5_b_integrate_and_check.py": "f4e41edb329bc9bc3b189d880e3760379bc444ffe116625dc42baa1a0fd6da52",
    "matrix-r3-launch.json": "f1b56f1d0c8918dd30bef83d15125c551b262d76b6e61d34b20fb49bf31a7917",
    "repair-checks-r5-b-r2/summary.json": "e4006eb11d50b4e0c497bd684b48b945c128489c6ba7c7bc2b24700546a5a159",
    "repair-checks-r5-b-r2/stderr.log": "7128e7ff531b8f7228379761eafb651d58c5e4111393c0161294da2ea3dcbf7c",
    "repair-checks-r5-b-r2/independent-reassessment.json": "9ca77cf4e7a50c5bf310a49851f64bbe79f8206d912ee9f3967402bdf7c4e045",
}
ROOTS = ("repair-checks-r5-a", "repair-checks-r5-a-r2", "repair-checks-r5-b", "repair-checks-r5-b-r2")
NEW_TESTS = (
    "reference_spaces_use_unsigned_offsets_and_exact_utf8_percent_encoding",
    "references_are_bound_to_actual_body_ranges_in_each_direction",
    "raw_reference_limit_includes_synthetic_and_duplicate_observations",
    "reference_counts_refuse_type_coercions_overflow_and_unfounded_duplicates",
    "reference_budget_trimming_preserves_scan_facts_and_separate_omissions",
    "reference_identity_includes_primary_but_excludes_descriptive_fields",
    "actual_owned_original_reference_projection_fits_the_revision_four_contract",
    "revision_four_reference_summary_distinguishes_filtering_from_output_limits",
)
MAX_UNPACKED = 128 * 1024 * 1024


def safe_unpack(raw, destination, build):
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    plain = decoder.decompress(raw, MAX_UNPACKED + 1)
    require(len(plain) <= MAX_UNPACKED and decoder.eof and not decoder.unconsumed_tail and not decoder.unused_data,
            "bounded single-member gzip requirement failed")
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    members, seen, total = [], set(), 0
    with tarfile.open(fileobj=io.BytesIO(plain), mode="r:") as archive:
        for entry in archive:
            name = entry.name.rstrip("/") if entry.isdir() else entry.name
            build.relative_name(name)
            require(name not in seen and len(seen) < 4096, "duplicate or excessive archive inventory")
            seen.add(name)
            require(entry.isdir() or entry.isreg(), "archive links/special files are forbidden")
            require(not entry.sparse and 0 <= entry.size <= MAX_UNPACKED, "sparse or excessive member")
            target = destination / name
            if entry.isdir():
                target.mkdir(mode=0o700, parents=True, exist_ok=True)
                continue
            total += entry.size
            require(total <= MAX_UNPACKED, "aggregate unpack budget exceeded")
            content = archive.extractfile(entry).read(entry.size + 1)
            require(len(content) == entry.size, "truncated archive member")
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            save(target, content)
            require(build.read_regular(destination, name, MAX_UNPACKED) == content, "extracted member readback differs")
            members.append({"path": name, "bytes": len(content), "sha256": sha(content)})
    return {"file_count": len(members), "total_file_bytes": total, "files": members,
            "safe_unpack_readback": True, "archive_sha256": sha(raw)}


def python_tests(raw):
    lines = raw.decode("utf-8").splitlines()
    summaries = [re.fullmatch(r"Ran (\d+) tests? in [0-9.]+s", line) for line in lines]
    summaries = [match for match in summaries if match]
    rows = [line for line in lines if line.startswith("test_") and line.endswith(" ... ok")]
    require(len(summaries) == 1 and lines[-1] == "OK" and len(rows) == int(summaries[0][1]), "Python unittest rows/summary differ")
    return {"passed": len(rows), "actual_rows": rows, "verbatim_summary": summaries[0][0]}


def changed_files(repo):
    def tree(commit):
        result = {}
        for row in git(repo, "ls-tree", "-r", "-z", "--full-tree", commit).split(b"\0"):
            if not row:
                continue
            meta, name = row.split(b"\t", 1)
            mode, kind, oid = meta.decode("ascii").split()
            result[name.decode("utf-8")] = {"mode": mode, "kind": kind, "git_object_id": oid}
        return result
    before, after = tree(BASE_COMMIT), tree(SOURCE_COMMIT)
    rows = []
    for name in sorted(before.keys() | after.keys()):
        if before.get(name) == after.get(name):
            continue
        row = {"path": name, "status": "added" if name not in before else "deleted" if name not in after else "modified"}
        for label, inventory in (("before", before), ("after", after)):
            item = inventory.get(name)
            if item is None:
                row[label] = None
            else:
                require(item["kind"] == "blob", "changed non-blob Git entry is outside scope")
                raw = git(repo, "cat-file", "blob", item["git_object_id"])
                require(len(raw) <= MAX_UNPACKED, "changed Git blob exceeds allowance")
                row[label] = dict(item, bytes=len(raw), sha256=sha(raw))
        rows.append(row)
    return {"schema": "hepta.rea.commit-change-manifest.v1", "base_commit": BASE_COMMIT,
            "source_commit": SOURCE_COMMIT, "change_count": len(rows), "files": rows,
            "scope": "Exact committed blob identities, independent of later working-tree evidence additions; rename heuristics are not used."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ("repo", "evidence", "worker-jobs", "job-observations", "output", "private-readback"):
        parser.add_argument("--" + flag, required=True, type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    build = load_pinned_module(args.repo, "rea_build_evidence")
    producer = load_pinned_module(args.repo, "rea_full_qualification")
    stored, origins = {}, []
    def retain(root, name, archived):
        require(archived not in stored, "duplicate archive path")
        raw = build.read_regular(root, name, MAX_UNPACKED)
        stored[archived] = raw
        origins.append({"path": archived, "bytes": len(raw), "sha256": sha(raw), "original_path": str(root / name)})
        return raw
    for name in PINS:
        if "/" not in name:
            retain(args.evidence, name, "originals/evidence/" + name)
    for name in ("source-commit-r5.stdout", "source-commit-r5.stderr", "repair-staging-r5-a.json"):
        retain(args.evidence, name, "originals/evidence/" + name)
    for root_name in ROOTS:
        root = args.evidence / root_name
        require(stat.S_ISDIR(root.lstat().st_mode), "closed repair root is not a directory")
        count = 0
        for raw_dir, dirs, files in os.walk(root, followlinks=False):
            for name in dirs:
                require(not (Path(raw_dir) / name).is_symlink(), "closed repair archive has a directory symlink")
            for name in sorted(files):
                relative = (Path(raw_dir) / name).relative_to(args.evidence).as_posix()
                retain(args.evidence, relative, "originals/evidence/" + relative)
                count += 1
                require(count <= 1024, "excessive closed repair inventory")
    for name, expected in PINS.items():
        require(sha(stored["originals/evidence/" + name]) == expected, "pinned original differs: " + name)
    def original(name):
        return stored["originals/evidence/" + name]
    def parsed(name):
        return build.parse_json(original(name))
    job_facts = []
    metadata_names = ("request.json", "runner.py", "child.json", "launch.json", "owner-intent.json", "started.json")
    for label, (job, expected_exit) in JOBS.items():
        retained_metadata = {}
        for name in metadata_names + ("exit.json", "exit.witness.json", "stdout.log", "stderr.log"):
            retained_metadata[name] = retain(args.worker_jobs, job + "/" + name, "originals/jobs/" + label + "/" + name)
        status = build.parse_json(retain(args.job_observations, label + ".status.json", "observed-tool-results/" + label + ".status.json"))
        read = build.parse_json(retain(args.job_observations, label + ".read.json", "observed-tool-results/" + label + ".read.json"))
        require(status["job_id"] == read["job_id"] == job and type(status["exit_code"]) is int and status["exit_code"] == expected_exit,
                "actual wrapper terminal identity/exit differs")
        require(status["output_complete"] is True and status["output_durable"] is True and status["terminal_publication_confirmed"] is True,
                "wrapper output was not durably complete")
        require(not status["timed_out"] and not status["cancelled"] and not any(status["log_truncated"].values()) and not any(status["log_errors"].values()),
                "wrapper status reports incomplete or truncated observation")
        for stream in ("stdout", "stderr"):
            item = read[stream]
            raw = bytes.fromhex(item["bytes_hex"])
            require(item["eof"] is True and item["offset"] == 0 and item["next_offset"] == item["size"] == len(raw)
                    and item["text"].encode() == raw == retained_metadata[stream + ".log"], "wrapper complete raw stream binding differs")
        request = build.parse_json(retained_metadata["request.json"])
        require(request["job_id"] == job and request["executable"] == "/bin/sh" and len(request["args"]) == 2 and request["args"][0] == "-c", "wrapper request binding differs")
        command = request["args"][1].encode("utf-8")
        command_path = "derived/launch-commands/" + label + ".sh"
        stored[command_path] = command
        job_facts.append({"label": label, "job_id": job, "wrapper_exit_code": expected_exit,
                          "command_path": command_path, "command_sha256": sha(command), "stdout_bytes": len(retained_metadata["stdout.log"]),
                          "stderr_bytes": len(retained_metadata["stderr.log"]), "complete_raw_job_output_verified": True})
    matrix_request = None
    for name in metadata_names:
        raw = retain(args.worker_jobs, MATRIX_JOB + "/" + name, "originals/jobs/matrix-r3-launch-only/" + name)
        if name == "request.json":
            matrix_request = build.parse_json(raw)
    require(matrix_request["job_id"] == MATRIX_JOB and matrix_request["args"][0] == "-c" and len(matrix_request["args"]) == 2,
            "matrix launch command binding differs")
    stored["derived/launch-commands/matrix-r3-actual-inline.sh"] = matrix_request["args"][1].encode()
    require("os.execv" in matrix_request["args"][1] and "r5_freeze_and_matrix_r3.py" in matrix_request["args"][1], "actual matrix command lacks observed wrapper exec")
    bootstrap = parsed("repair-checks-r5-a/bootstrap-failure.json")
    require(bootstrap["test_commands_started"] is False and bootstrap["process_status"]["exit_code"] == 1,
            "bootstrap failure must not become a test run")
    stage_facts = {}
    for name in ("repair-checks-r5-a-r2", "repair-checks-r5-b"):
        report = parsed(name + "/summary.json")
        stages = []
        for stage in report["stages"]:
            require(stage["exit_code"] == 0, "targeted subprocess did not succeed")
            for stream in ("stdout", "stderr"):
                raw = original(name + "/" + stage[stream]["path"])
                require(sha(raw) == stage[stream]["sha256"] and ("bytes" not in stage[stream] or len(raw) == stage[stream]["bytes"]), "targeted log pin differs")
            fact = {"name": stage["name"], "subprocess_exit_code": stage["exit_code"], "argv": stage["argv"]}
            if stage["name"].startswith("python-"):
                fact["actual_unittest_log"] = python_tests(original(name + "/" + stage["stderr"]["path"]))
            if stage["name"].startswith("rust-"):
                fact["actual_nextest_log"] = parse_nextest(original(name + "/" + stage["stdout"]["path"]), original(name + "/" + stage["stderr"]["path"]))
            stages.append(fact)
        stage_facts[name] = stages
    require(stage_facts["repair-checks-r5-a-r2"][-1]["actual_nextest_log"]["passed"] == 3
            and stage_facts["repair-checks-r5-b"][-1]["actual_nextest_log"]["passed"] == 3, "initial filter scope differs")
    require(all(" mcp::rea_contract::tests::" in row["test_identity"]
                for row in stage_facts["repair-checks-r5-b"][-1]["actual_nextest_log"]["pass_rows"]), "B1 unexpectedly included another test family")
    corrected = parsed("repair-checks-r5-b-r2/summary.json")
    require(corrected["exit_code"] == 0 and corrected.get("failure") and corrected["passed_lines"] == 0,
            "failed original postprocessor evidence changed")
    actual = parse_nextest(original("repair-checks-r5-b-r2/stdout.log"), original("repair-checks-r5-b-r2/stderr.log"))
    require(actual["passed"] == 31 and actual["reported_skipped"] == 2242, "corrected actual nextest count differs")
    observed = {}
    for name in NEW_TESTS:
        matches = [row for row in actual["pass_rows"] if row["test_identity"].endswith("::" + name)]
        require(len(matches) == 1, "new regression missing or duplicated: " + name)
        observed[name] = matches[0]
    require(original("repair-checks-r5-b-r2/source-before.json") == original("repair-checks-r5-b-r2/source-after.json")
            == original("final-source-r5.snapshot.json"), "B2/final source snapshots differ")
    require(original("repair-checks-r5-a-r2/source-before.json") == original("repair-checks-r5-a-r2/source-after.json"), "A2 source changed")
    require(parsed("repair-checks-r5-a-r2/source-events.json") == {"event_count": 0, "retained_events": [], "events_truncated": False, "errors": []}, "A2 source monitoring differs")
    require(original("repair-checks-r5-b/source-before-checks.json") == original("repair-checks-r5-b/source-after-checks.json") == original("final-source-r5.snapshot.json"), "B1/final source snapshots differ")
    snapshot = parsed("final-source-r5.snapshot.json")
    build.check_snapshot(snapshot)
    require(snapshot["tree_sha256"] == SOURCE_TREE and parsed("source-commit-r5.json")["source_commit"] == SOURCE_COMMIT, "final source identity differs")
    selection = producer.Selection(args.repo, Path(str(args.repo) + "-target"), args.evidence / "matrix-r3")
    require(selection.snapshot() == snapshot, "current selected source differs while sealing repair evidence")
    git_binding = bind_git_source(args.repo, selection, snapshot, build)
    changes = changed_files(args.repo)
    stored["derived/git-source-binding.json"] = json_bytes(git_binding)
    stored["derived/b3-to-r5-committed-change-manifest.json"] = json_bytes(changes)
    args.private_readback.mkdir(mode=0o700, parents=True, exist_ok=False)
    nested = []
    for name in PINS:
        if name.endswith(".tar.gz"):
            nested.append({"original_path": "originals/evidence/" + name,
                           "unpacked": safe_unpack(original(name), args.private_readback / "nested" / name[:-7], build)})
    result = {
        "schema": "hepta.rea.r5-repair-observation-archive.v1", "qualified": False,
        "source_commit": SOURCE_COMMIT, "source_tree_sha256": SOURCE_TREE,
        "job_observations": job_facts, "targeted_stage_observations": stage_facts,
        "corrected_filter_observation": {"original_wrapper_exit_code": 1, "nextest_subprocess_exit_code": 0,
            "original_postprocessor_result_preserved": True, "actual_nextest": actual, "eight_new_test_rows": observed},
        "review_archive_member_readbacks": nested,
        "source_change_manifest_path": "derived/b3-to-r5-committed-change-manifest.json",
        "source_change_count": changes["change_count"],
        "scope": "Closed repair/source-freeze observations and reviewed candidates only. A1 bootstrap failed before tests. A2 and B1 each ran three opaque-error Rust tests. B1 Python suites are finite client/harness tests. B2 actually ran 31 Rust tests including all eight new regressions, while its original postprocessor wrapper failed. Preserve original exits and add this separate log assessment. Full matrix-r3 activity, built binary, real R5 MCP/Ghidra run and full operation qualification are excluded.",
        "matrix_launch_only": {"job_id": MATRIX_JOB, "actual_wrapper_script": "r5_freeze_and_matrix_r3.py", "wrapper_script_sha256": PINS["r5_freeze_and_matrix_r3.py"],
            "actual_inline_command_path": "derived/launch-commands/matrix-r3-actual-inline.sh", "unused_wrapper_version_claimed": False,
            "scope": "Immutable launch/request/source receipt only; no active stdout/stderr/summary or terminal outcome included."},
        "private_r4_state_consumer_scope": "Offline rejection tests and peer-reviewed consumer source only. No actual final-binary 23-observation result is inferred.",
        "originals_modified": False,
    }
    stored["derived/assessment.json"] = json_bytes(result)
    member_manifest = [{"path": name, "bytes": len(raw), "sha256": sha(raw)} for name, raw in sorted(stored.items())]
    stored["members-manifest.json"] = json_bytes({"schema": "hepta.rea.repair-archive-members.v1", "files": member_manifest,
                                                  "original_file_provenance": origins, "qualified": False})
    plain = io.BytesIO()
    with tarfile.open(fileobj=plain, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name, raw in sorted(stored.items()):
            info = tarfile.TarInfo(name)
            info.size, info.mode, info.mtime = len(raw), 0o644, 0
            archive.addfile(info, io.BytesIO(raw))
    packed = gzip.compress(plain.getvalue(), mtime=0)
    replayed = safe_unpack(packed, args.private_readback / "outer", build)
    require({row["path"]: (row["bytes"], row["sha256"]) for row in replayed["files"]}
            == {name: (len(raw), sha(raw)) for name, raw in stored.items()}, "complete outer archive readback differs")
    for origin in origins:
        p = Path(origin["original_path"])
        current = build.read_regular(p.parent, p.name, MAX_UNPACKED)
        require(len(current) == origin["bytes"] and sha(current) == origin["sha256"], "original changed during sealing")
    require(selection.snapshot() == snapshot, "selected source changed during sealing")
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    archive_ref = save(args.output / "repair-observations.tar.gz", packed)
    save(args.output / "assessment.json", json_bytes(result))
    manifest = {"schema": "hepta.rea.repair-observations-manifest.v1", "qualified": False,
                "source_commit": SOURCE_COMMIT, "source_tree_sha256": SOURCE_TREE,
                "archive": dict(archive_ref, path="repair-observations.tar.gz"),
                "member_count": replayed["file_count"], "members": replayed["files"],
                "safe_unpack_readback": True, "original_file_provenance": origins,
                "nested_archive_count": len(nested), "active_matrix_outputs_included": False}
    manifest_ref = save(args.output / "manifest.json", json_bytes(manifest))
    (args.output / "tools").mkdir()
    for name in ("archive_prechecks.py", "consume_matrix.py", "consumer_preflight_tests.py"):
        save(args.output / "tools" / name, (Path(__file__).parent / name).read_bytes())
    readme = """# R5 repair and source-freeze observations

This archive preserves the closed repair prechecks and their original failures for source commit
`fe3223cabbd2a8f1aa75a4ab57507bdb72291242`. It does not assert operation qualification.
The execution-input tree is `1a83f83cf62bf3d96e50c944722977b6971ffe686aecd131cab5e728dd802424`.

| Observation | Actual result | Scope |
| --- | --- | --- |
| Part A bootstrap, job `1a1b2444dec-fc05-7d3e` | Wrapper exit 1 | Invalid `SourceSelection` import; no tests started. |
| Part A corrected, job `1a1b245f180-fc05-7d46` | Wrapper exit 0 | Format check, 32 Python tests and 3 opaque-error Rust tests. Intermediate source tree, before Part B. |
| Part B initial, job `1a1b267f662-fc05-7deb` | Wrapper exit 0 | Format check and 47 finite Python tests. The incorrect Rust filter selected only the same 3 error-contract tests. |
| Part B corrected filter, job `1a1b26f9dd7-fc05-7e03` | Nextest exit 0; wrapper exit 1 | 31 actual Rust PASS rows and 2242 reported skipped; all 8 new regressions occur exactly once. The postprocessor regex was over-escaped. |

`assessment.json` is a new independent reading of the actual logs. The original Part B corrected
summary (`e4006e…`), stderr (`7128e7…`), failed wrapper output and prior independent assessment
(`9ca77c…`) remain byte-for-byte present. No command was rerun to replace a failure.

The archive contains all eight pinned private review archives, including the additional R4 state
consumer rejection-test package. Those offline tests do not prove that a future actual Provider
run produced all 23 required observations. It also preserves the original worker request, launch,
runner and terminal records for the four closed jobs; complete stdout/stderr are independently
matched to durable process-read observations. The exact inline shell source is extracted from
each authoritative request's `args[1]` without rewriting its text.

The actual matrix launcher `r5_freeze_and_matrix_r3.py` (`a7297d…`) and the matrix job's immutable
launch metadata are included. Its inline prelude independently reassessed the 31 tests before
`os.execv` entered that script. No unused wrapper version is claimed. The running matrix's
stdout, stderr, summary, final binary and resource outcome are excluded from this package.

`manifest.json` pins every archive member. Every retained nested archive and the complete outer
archive were bounded, rejected for links/special files/unsafe or duplicate names, extracted into
new private directories and read back. `derived/b3-to-r5-committed-change-manifest.json` identifies
each changed Git blob between the original base and the R5 source commit; it is separate from
later documentation/evidence commits. Selected working source matched the frozen snapshot before
and after sealing. The scripts in `tools/` reproduce the derivation with explicitly supplied roots;
they do not run Cargo, the runtime binary or an analysis engine.

These are finite prechecks and source/provenance observations. They do not replace the complete
nine-stage matrix, real ELF/Evidence or Ghidra tasks, cross-platform qualification, release costs,
or the remaining P0–P5 requirements. The 229-operation qualified count remains zero.
"""
    readme_ref = save(args.output / "README.md", readme.encode())
    print(json.dumps({"archive": archive_ref, "manifest": manifest_ref, "readme": readme_ref,
                      "member_count": replayed["file_count"], "nested_archive_count": len(nested),
                      "source_change_count": changes["change_count"], "qualified": False,
                      "active_matrix_outputs_included": False, "originals_modified": False}, sort_keys=True))


if __name__ == "__main__":
    main()
