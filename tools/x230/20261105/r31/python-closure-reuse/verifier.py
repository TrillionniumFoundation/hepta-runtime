#!/usr/bin/env python3
"""Read-only, fixed-commit comparison of R29 Python evidence and published R31.

Only this verifier runs. Git reads are local (lazy fetch disabled); original
archives are opened in memory, never extracted and never imported or executed.
The JSON proof is written to stdout only after every required check succeeds.
"""

import argparse
import difflib
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import shlex
import stat
import subprocess
import sys
import tarfile


COMMIT = "c039688312ceb09b3d26d1cdd50f9118eb11129f"
BASELINE = "baab4def80be7af015b2e7a594cb302f66c4130e"
JOB = "1a1ad72111c-fc05-59eb"
R29 = "tools/x230/20261105/r29/"
R31 = "tools/x230/20261105/r31/"
ARCHIVES = {
    "qualification-ci-01.tar.xz": (1942216, "bfe5852ce915f8430862d6ac456bf366cac4df33b03c542cfb80290d49a895b3"),
    "native-operations-custody-01.tar.xz": (7443600, "8fe9b50926f919a6e1a74f8df1b6ed80c0f4080ff6ed1a178cafb1f25ba1c05c"),
}
MANIFEST_SHA = "bf0df5f7d19ebd149854fbf75887fb0fb136f18a63a0c240abf8420655fb195e"
INPUT_SHA = "b54654aa5ea0a414b860a215d6bf0caef73c3b03adccdf7da83fc7f336003383"
PRIVATE_SHA = "5574840f604a3c7963a274592ac2468a43fdd04cdaa7122851c271188a11065d"
CHANGED = ["src/mcp/runtime/jobs.rs", "src/mcp/runtime/jobs_cancel_wait_fixture.py",
           "src/mcp/runtime/jobs_cancel_wait_tests.rs"]
DISCOVERY = ["tools/x230/20261028", "tools/x230/20261029", "tools/x230/20261030"]
NATIVE_PREFIX = "payload/806ba5f52f94/benchmark-r29/python-ci-operations-01/"


def require(value, message):
    if not value:
        raise ValueError(message)


def identity(body):
    return {"bytes": len(body), "sha256": hashlib.sha256(body).hexdigest()}


def git_blob(body):
    return hashlib.sha1(b"blob " + str(len(body)).encode() + b"\0" + body).hexdigest()


def regular_read(path):
    path = Path(path).absolute()
    require(not any(p.is_symlink() for p in (path, *path.parents)), f"symlink: {path}")
    before = path.stat()
    require(stat.S_ISREG(before.st_mode) and before.st_size <= 4 * 1024 * 1024,
            f"nonregular or oversized local input: {path}")
    body = path.read_bytes()
    after = path.stat()
    require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
            f"local input changed during read: {path}")
    return body, "100755" if before.st_mode & 0o111 else "100644"


def member(tar, name):
    item = tar.getmember(name)
    require(item.isfile() and item.size <= 4 * 1024 * 1024, f"invalid archive member: {name}")
    with tar.extractfile(item) as stream:
        body = stream.read()
    require(len(body) == item.size, f"short archive member: {name}")
    return body


def unwrap(operation):
    result = operation["result"]
    require(result.get("isError") is False, "original native operation returned an error")
    text = [x["text"] for x in result["content"] if x["type"] == "text"]
    require(len(text) == 1, "ambiguous original native response")
    return json.loads(text[0])


def verify(args):
    env = dict(os.environ, GIT_NO_LAZY_FETCH="1", GIT_TERMINAL_PROMPT="0", GIT_OPTIONAL_LOCKS="0")

    def git(*argv):
        return subprocess.check_output(["git", "-C", str(args.repo), *argv], env=env)

    def published(path):
        return git("show", COMMIT + ":" + path)

    require(git("rev-parse", COMMIT + "^{commit}").decode().strip() == COMMIT, "commit mismatch")
    tree = {}
    for record in git("ls-tree", "-r", "-z", COMMIT).split(b"\0"):
        if record:
            metadata, path = record.split(b"\t", 1)
            mode, kind, oid = metadata.decode().split()
            tree[path.decode()] = (mode, kind, oid)

    archive_refs = []
    archives = []
    for name, (size, sha) in ARCHIVES.items():
        path = R29 + "evidence/" + name
        body = published(path)
        require(identity(body) == {"bytes": size, "sha256": sha}, f"archive pin mismatch: {path}")
        archive_refs.append({"git_path": path, "git_blob": tree[path][2], **identity(body)})
        tar = tarfile.open(fileobj=io.BytesIO(body), mode="r:xz")
        names = [m.name for m in tar.getmembers()]
        require(len(names) == len(set(names)), "duplicate archive member")
        archives.append(tar)
    qc, custody = archives
    artifacts = []

    def saved(tar, name):
        body = member(tar, name)
        artifacts.append({"archive": "qualification-ci-01.tar.xz" if tar is qc else
                          "native-operations-custody-01.tar.xz", "member": name, **identity(body)})
        return body

    manifest_body = saved(qc, "published-python-inputs/ci-gate-manifest.json")
    require(identity(manifest_body)["sha256"] == MANIFEST_SHA, "manifest pin mismatch")
    manifest = json.loads(manifest_body)
    report_body = saved(qc, "python-ci01/report.json")
    outer_body = saved(qc, "python-launch01/receipt.json")
    terminal_body = saved(qc, "native-terminals/python-ci-terminal-status-01.json")
    for name, body in [("python-report.json", report_body), ("python-outer.json", outer_body),
                       ("python-native.json", terminal_body)]:
        require(published(R29 + "receipts/" + name) == body, f"published receipt differs: {name}")
    report, outer, terminal = map(json.loads, (report_body, outer_body, terminal_body))
    require(report["schema"] == "hepta-r25-external-python-ci-results/v1", "report schema")
    require(report["passed"] is True and report["retry_count"] == 0
            and report["final_inputs_unchanged"] is True and report["verify_only"] is False
            and bool(report["finished_utc"]), "original Python result did not pass")
    require(report["manifest_sha256"] == MANIFEST_SHA, "report/manifest mismatch")
    require(report["head_commit"] == manifest["head_commit"]
            and report["head_root_tree"] == manifest["head_root_tree"]
            and report["workflow_git_blob"] == manifest["workflow_git_blob"], "original input identity")
    require(outer["passed"] is True and outer["runner_returncode"] == 0
            and outer["retry_count"] == 0 and outer["gates_executed"] == 18
            and outer["failed_gates"] == [] and outer["finished_unix"] > outer["started_unix"], "outer result")
    require(outer["candidate_binding_before"] == outer["candidate_binding_after"], "historical binding changed")
    require(outer["candidate_binding_after"]["passed"] is True
            and outer["candidate_binding_after"]["python_ci_result_reused_from_R25"] is False, "historical execution")
    require({k: outer["report"][k] for k in ("bytes", "sha256")} == identity(report_body), "outer/report identity")
    require(outer["manifest"] == identity(manifest_body), "outer/manifest identity")
    for result in (report, outer):
        require(result["hosted_actions_passed"] is False and result["rust_executed"] is False
                and result["performance_executed"] is False, "original evidence scope")

    gates = manifest["python_gates"]
    require(len(gates) == len(report["gates"]) == 18, "original gate count")
    require([g["id"] for g in gates] == [f"python-{i:02d}" for i in range(1, 19)], "gate order")
    commands = [g["argv"] for g in gates]
    require(set(manifest["workflow"]["jobs"]) == {"runtime-head-ci", "runtime-merge-ci"}, "workflow jobs")
    for job in manifest["workflow"]["jobs"].values():
        extracted = [shlex.split(line.strip()) for step in job["steps"]
                     for line in step.get("run", "").splitlines()
                     if line.strip().startswith("/usr/bin/python3 ")]
        require(extracted == commands, "original manifest workflow commands differ")
    gate_proof = []
    stream_bytes = 0
    for expected, actual in zip(gates, report["gates"]):
        require(all(actual[k] == expected[k] for k in ("id", "argv", "workflow_step")), "gate identity")
        require(actual["passed"] is True and actual["returncode"] == 0
                and actual["timeout"] is False and actual["signals"] == []
                and actual["inputs_unchanged"] is True, f"failed gate: {expected['id']}")
        streams = {}
        for stream in ("stdout", "stderr"):
            name = "python-ci01/" + actual[stream + "_file"]
            require(name == f"python-ci01/{expected['id']}.{stream}", "gate stream path")
            body = saved(qc, name)
            require(identity(body) == {"bytes": actual[stream + "_bytes"],
                                       "sha256": actual[stream + "_sha256"]}, "gate stream identity")
            streams[stream] = {"member": name, **identity(body)}
            stream_bytes += len(body)
        gate_proof.append({**expected, "passed": True, "returncode": 0, "streams": streams})
    for stream in ("stdout", "stderr"):
        body = saved(qc, "python-launch01/runner." + stream + ".log")
        require(identity(body) == outer["runner_" + stream], "outer runner stream identity")
    runner = saved(qc, "published-python-inputs/run_ci_python_gates.py")
    require(identity(runner) == outer["runner"] and identity(runner)["sha256"] == report["harness_sha256"],
            "original runner identity")
    launcher = saved(qc, "python-tools01/launch_python_ci_01.py")
    require(identity(launcher) == outer["launcher_source"], "original launcher identity")

    require(terminal["job_id"] == JOB and terminal["state"] == "succeeded" and terminal["exit_code"] == 0,
            "native result")
    require(all(terminal[k] is True for k in ("audit_recorded", "output_complete", "output_durable",
                                              "terminal_publication_confirmed")), "native output incomplete")
    require(all(terminal[k] is False for k in ("automatic_retry", "timed_out", "cancelled")), "native retry/failure")
    for name, expected in [("actual-report-01.json", report_body), ("actual-launch-receipt-01.json", outer_body),
                           ("actual-native-terminal-01.json", terminal_body)]:
        require(saved(custody, NATIVE_PREFIX + name) == expected, "native/QC companion mismatch")
    status_op = json.loads(saved(custody, NATIVE_PREFIX + "status-02.json"))
    require(status_op["request"] == {"host": "x230", "job_id": JOB} and unwrap(status_op) == terminal,
            "original native status differs")
    read_op = json.loads(saved(custody, NATIVE_PREFIX + "read-complete-01.json"))
    require(read_op["request"]["job_id"] == JOB and read_op["request"]["host"] == "x230"
            and read_op["request"]["stdout_offset"] == read_op["request"]["stderr_offset"] == 0, "native read request")
    read = unwrap(read_op)
    require(read["job_id"] == JOB and read["audit_recorded"] is True, "native read identity")
    native_streams = {}
    for stream in ("stdout", "stderr"):
        body = saved(custody, NATIVE_PREFIX + "complete-" + stream + "-01.log")
        descriptor = read[stream]
        require(bytes.fromhex(descriptor["bytes_hex"]) == body and descriptor["eof"] is True
                and descriptor["offset"] == 0 and descriptor["size"] == descriptor["next_offset"] == len(body),
                "native raw read/log closure")
        require(terminal["log_bytes"][stream] == {"seen": len(body), "stored": len(body)}
                and terminal["log_errors"][stream] is None and terminal["log_synced"][stream] is True
                and terminal["log_truncated"][stream] is False, "native terminal/log closure")
        native_streams[stream] = identity(body)
        if stream == "stdout":
            require(json.loads(body) == outer, "native stdout/outer receipt mismatch")

    inputs = manifest["input_files"]
    paths = [item["path"] for item in inputs]
    require(len(paths) == len(set(paths)) == 85, "input closure count")
    require(sum(x["bytes"] for x in inputs) == manifest["input_total_bytes"], "input byte total")
    input_proof = []
    for expected in inputs:
        path = expected["path"]
        require(not PurePosixPath(path).is_absolute() and ".." not in PurePosixPath(path).parts, "input path")
        original = member(qc, "published-python-inputs/ci-inputs/" + path)
        current = published(path)
        local, local_mode = regular_read(args.source / path)
        require(identity(original) == {k: expected[k] for k in ("bytes", "sha256")}, "archived input identity: " + path)
        require(original == current == local, "input bytes differ: " + path)
        require(git_blob(original) == expected["git_blob"], "input blob identity: " + path)
        require(tree[path] == (expected["git_mode"], "blob", expected["git_blob"])
                and local_mode == expected["git_mode"], "input Git mode differs: " + path)
        input_proof.append(dict(expected))
    discoveries = {}
    require(sorted(manifest["python_discovery_files"]) == DISCOVERY, "discovery roots")
    for directory in DISCOVERY:
        archived = sorted(p for p in paths if p.startswith(directory + "/") and p.endswith("_tests.py"))
        published_set = sorted(p for p in tree if p.startswith(directory + "/") and p.endswith("_tests.py"))
        local = sorted(p.relative_to(args.source).as_posix()
                       for p in (args.source / directory).rglob("*_tests.py"))
        require(archived == published_set == local == manifest["python_discovery_files"][directory],
                "discovery set differs: " + directory)
        discoveries[directory] = archived

    input_body = published(R31 + "input.json")
    require(identity(input_body)["sha256"] == INPUT_SHA, "R31 frozen input pin")
    r31_input = json.loads(input_body)
    require(r31_input["baseline_commit"] == BASELINE and r31_input["changed_paths"] == CHANGED,
            "R31 scope differs")
    patch = published(R31 + "candidate.patch")
    require(identity(patch)["sha256"] == r31_input["patch_sha256"], "R31 patch pin")
    changes = git("diff", "--name-only", BASELINE, COMMIT, "--", "src", "Cargo.toml", "Cargo.lock",
                  "examples", "rustfmt.toml", "build.rs", ".cargo", "rust-toolchain", "rust-toolchain.toml").decode().splitlines()
    require(changes == CHANGED and not set(changes).intersection(paths), "R31 source/closure overlap")
    overlap = sorted(set(r31_input["candidate_compile_inputs"]).intersection(paths))
    require(overlap == ["src/mcp/runtime/fileio.py"], "unexpected compiler/Python input overlap")
    require(r31_input["candidate_compile_inputs"][overlap[0]] == identity(published(overlap[0]))["sha256"],
            "R31 overlapping input differs")

    workflow_path = manifest["workflow_path"]
    require(workflow_path == ".github/workflows/ci.yml" and isinstance(manifest["workflow_git_blob"], str)
            and tree[workflow_path][2] == manifest["workflow_git_blob"], "workflow blob structure/identity")
    canonical = published(workflow_path)
    private, _ = regular_read(args.private_workflow_copy)
    require(identity(private) == {"bytes": 7235, "sha256": PRIVATE_SHA}, "private workflow copy pin")
    require(private != canonical, "known private workflow difference disappeared")
    private_diff = list(difflib.unified_diff(canonical.decode().splitlines(), private.decode().splitlines(),
                                           fromfile="published-R31/ci.yml", tofile="private-x230-SOURCE/ci.yml", lineterm=""))
    for tar in archives:
        tar.close()
    return {
        "schema": "hepta-r31-historical-python-input-reuse/v1", "verified": True,
        "scope": "Same-input historical Python regression evidence for the published R31 commit; no new gate execution.",
        "published_commit": COMMIT, "published_root_tree": git("rev-parse", COMMIT + "^{tree}").decode().strip(),
        "baseline_source_commit": BASELINE,
        "verifier": {"file": "verifier.py", **identity(Path(__file__).read_bytes())},
        "original_archives": archive_refs, "original_artifacts_checked": artifacts,
        "historical_execution": {
            "job_id": JOB, "original_result_passed": True, "native_terminal": terminal,
            "native_streams_checked": native_streams, "manifest_input_head": manifest["head_commit"],
            "manifest_workflow_git_blob": manifest["workflow_git_blob"], "workflow_git_blob_type": "string",
            "source": report["source"], "started_utc": report["started_utc"], "finished_utc": report["finished_utc"],
            "python": report["python"], "platform": report["platform"], "environment_adjustments": report["environment_adjustments"],
            "retry_count": 0, "commands": gate_proof, "gate_streams_checked": 36, "gate_stream_bytes_checked": stream_bytes,
            "outer_runner_streams_checked": 2, "native_raw_streams_checked": 2,
        },
        "input_comparison": {
            "count": 85, "total_bytes": manifest["input_total_bytes"], "all_equal": True,
            "compared": ["R29 archived dependency input bytes", "fixed published R31 Git blobs and modes",
                         "local frozen source bytes and Git-equivalent executable mode"],
            "local_frozen_source": str(args.source.absolute()), "files": input_proof,
            "mode_scope": "Git 100644/100755 equals the local executable bit. Archive container permissions are normalized and are not Git mode evidence.",
            "discovery_sets_equal": True, "discovery_sets": discoveries,
        },
        "r31_change_scope": {
            "input": {"git_path": R31 + "input.json", **identity(input_body)},
            "patch": {"git_path": R31 + "candidate.patch", **identity(patch)},
            "source_paths_changed_from_R24": changes, "changed_paths_in_python_closure": [],
            "compiler_input_overlap": overlap,
            "new_pidfd_fixture_in_historical_python_closure": False,
        },
        "known_private_source_difference": {
            "path": workflow_path, "canonical_published": identity(canonical),
            "private_copy_file": args.private_workflow_copy.name, "private_copy": identity(private),
            "workflow_in_85_item_closure": True, "private_source_full_closure_identity_claimed": False,
            "diff": private_diff,
            "meaning": "The copied private x230 workflow omits the 20261029 and 20261030 discovery commands in both jobs. This proof applies to published R31 and the full local frozen source, not to the entire private x230 SOURCE directory.",
        },
        "limits": {
            "new_R31_python_gate_execution": False, "hosted_actions_pass": False,
            "prospective_merge_pass": False, "R31_Rust_validation_inferred": False,
            "performance_adoption_inferred": False, "current_external_environment_equivalence_proved": False,
            "complete_dynamic_dependency_discovery_reperformed": False,
            "remote_calls": 0, "archive_extractions": 0, "archived_program_executions": 0,
            "input_or_source_modifications": 0,
            "note": "The inherited 85-file manifest and its historical command results are checked, not an unlimited proof of all possible external dependencies. Rust, new fixture behavior, hosted status, current interpreter/packages and merge validation remain separate evidence.",
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True, help="local Git repo containing the pinned commit")
    parser.add_argument("--source", type=Path, required=True, help="complete local frozen R31 source, not the sparse worktree")
    parser.add_argument("--private-workflow-copy", type=Path,
                        default=Path(__file__).with_name("private-source-workflow-original.yml"))
    args = parser.parse_args()
    try:
        proof = verify(args)
    except (ValueError, KeyError, OSError, subprocess.SubprocessError, tarfile.TarError) as exc:
        print(f"verification failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(proof, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
