#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Create the local R35 Mac script package; never execute a packaged program."""
import ast
import base64
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import pprint
import stat
import tarfile

HERE = Path(__file__).resolve().parent
RECOVERY = HERE.parent
OUT = HERE / "sealed-01"
ROOT = "/home/qian/hepta-runtime-optimization-20261106-r35"
MAC = "/Users/qianqi/work/hepta-runtime-r35-recovery-20261106/parent-staging/mac-launchers-01"
Q_JOB = "1a1af619097-fc05-6813"
CI_JOB = "1a1af88c330-fc05-696f"
HOLDER_SHA = "715e996217c7d33a7483354f16f2d39c9a033f51f3a20a52484495a00262dd65"
Q_FILES = {
    "qualification-report.json": ("qualification-01/report.json", 83363, "5369433b6eb2db62a907593f1b679f968b411d0cde96ce9eabe8e124420cf8e1"),
    "preparation.json": ("preparation.json", 62335, "4770faa3c73ec2e9287fd43154ad5f9b6df149d85767ddb5f18e6aeb153ea1cc"),
    "source-map.json": ("qualification-01/source-map.json", 24156, "87f085a95a1c1925ecc444b46c996a0aec399c74ce7d0c32afff572e24055313"),
    "isolated-summary.json": ("qualification-01/isolated-tests/summary.json", 6878, "10eb5d260f26f15cfea9334ddc6f22456f22dea54ad1b755e118fd49cc67d904"),
    "isolated-audit.json": ("qualification-01/isolated-tests.audit.json", 1419928, "cdd5497f7646ddca0ba028cf2d93d4df76c737a87569e19e9596625620397894"),
    "qualification-terminal-status-01.json": ("qualification-terminal-status-01.json", 731, "8b171dde1644b1c9cacfc126be053484a3649031f946c648db7a69f9be404844"),
    "qualification-native-read-01.json": ("qualification-native-read-01.json", 3812, "4275444d755edf7b4893827ff2224fa1d70aee529a6ac2e1be4c0c5989a5a043"),
}


def need(value, reason):
    if not value:
        raise ValueError(reason)


def identity(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def read(path, size=None, digest=None):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= 2 * 1024 * 1024,
             "unsafe or oversized local input")
        raw = stream.read(2 * 1024 * 1024 + 1)
        keys = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_mode", "st_nlink")
        stamp = lambda value: tuple(getattr(value, key) for key in keys)
        need(len(raw) == before.st_size and stamp(before) == stamp(os.fstat(stream.fileno())) == stamp(path.lstat()),
             "local input changed while read")
    need(size is None or len(raw) == size, "local original size differs")
    need(digest is None or identity(raw)["sha256"] == digest, "local original SHA differs")
    return raw


def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def write(name, raw):
    with (OUT / name).open("xb") as stream:
        stream.write(raw)


def original_native(terminal, output, job_id):
    need(terminal["job_id"] == output["job_id"] == job_id and terminal["state"] == "succeeded"
         and type(terminal["exit_code"]) is int and terminal["exit_code"] == 0,
         "successful original native identity required")
    need(all(terminal[key] is False for key in ("automatic_retry", "cancelled", "timed_out"))
         and all(terminal[key] is True for key in ("output_complete", "output_durable", "terminal_publication_confirmed"))
         and terminal["terminal_publication_protocol"] == 1, "original native closure incomplete")
    streams = {}
    for name in ("stdout", "stderr"):
        part = output[name]
        raw = bytes.fromhex(part["bytes_hex"])
        need(part["offset"] == 0 and part["eof"] is True
             and part["next_offset"] == part["size"] == len(raw)
             and part["text"].encode() == raw
             and terminal["log_bytes"][name] == {"seen": len(raw), "stored": len(raw)}
             and terminal["log_synced"][name] is True
             and terminal["log_errors"][name] is None
             and terminal["log_truncated"][name] is False, "original native stream differs")
        streams[name] = raw
    return streams


INSTALLER_BODY = r'''

def need(value, reason):
    if not value:
        raise ValueError(reason)


def identity(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def owned_directory(path):
    need(path.is_absolute() and path.resolve(strict=True) == path, "indirect directory path")
    value = path.lstat()
    need(stat.S_ISDIR(value.st_mode) and value.st_uid == os.geteuid(), "operator-owned directory required")
    return value


def read_back(directory_fd, name, expected):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory_fd)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == os.geteuid()
             and 0 < before.st_size <= 128 * 1024, "unsafe installed member")
        raw = stream.read(128 * 1024 + 1)
        keys = ("st_dev", "st_ino", "st_uid", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
        stamp = lambda value: tuple(getattr(value, key) for key in keys)
        need(len(raw) == before.st_size and stamp(before) == stamp(os.fstat(stream.fileno()))
             == stamp(os.stat(name, dir_fd=directory_fd, follow_symlinks=False)), "installed member changed")
    need(identity(raw) == expected, "installed member identity differs")


def main():
    need(sys.platform == "darwin" and os.geteuid() != 0, "native non-root Mac operator required")
    raw = base64.b64decode(ARCHIVE_BASE64, validate=True)
    need(identity(raw) == PACKAGE["archive"] and len(raw) <= 128 * 1024, "compressed package identity differs")
    with gzip.GzipFile(fileobj=io.BytesIO(raw), mode="rb") as stream:
        expanded = stream.read(512 * 1024 + 1)
    need(len(expanded) <= 512 * 1024, "expanded tar exceeds bound")
    files = {}
    with tarfile.open(fileobj=io.BytesIO(expanded), mode="r:") as archive:
        for member in archive:
            name = pathlib.PurePosixPath(member.name)
            need(member.isfile() and name.name == member.name and name.name not in (".", "..")
                 and member.name in PACKAGE["members"] and member.name not in files
                 and len(files) < 5 and 0 < member.size <= 128 * 1024, "unsafe package member")
            data = archive.extractfile(member).read(128 * 1024 + 1)
            need(len(data) == member.size and identity(data) == PACKAGE["members"][member.name],
                 "package member identity differs")
            files[member.name] = data
    expected_names = {"held_agent_campaign_02.py", "r35_campaign.py", "r35_lifecycle_campaign.py",
                      "launcher-seal-manifest.json", "operator-argv.json"}
    need(set(files) == set(PACKAGE["members"]) == expected_names
         and sum(map(len, files.values())) == PACKAGE["expanded_file_bytes"], "fixed package set differs")
    manifest = json.loads(files["launcher-seal-manifest.json"])
    commands = json.loads(files["operator-argv.json"])
    need(manifest["schema"] == "hepta-r35-mac-launcher-seal/v1"
         and manifest["remote_root"] == PACKAGE["remote_root"]
         and manifest["proposed_mac_directory"] == str(TARGET)
         and manifest["commands"] == commands == PACKAGE["commands"], "package domain or operator argv differs")
    need(manifest["qualification_job_id"] == PACKAGE["qualification_job_id"]
         and manifest["qualification_counts"] == PACKAGE["qualification_counts"]
         and manifest["exact_ci_original_job_id"] == PACKAGE["exact_ci_original_job_id"]
         and manifest["exact_ci_final_result"] is None, "original qualification or pending CI metadata differs")
    need(manifest["holder_bytes_unchanged"] is True and manifest["protocol_change"] is False
         and manifest["native_holder_or_ssh_agent_started"] is False
         and manifest["normal_observation_started_by_this_task"] is False, "package claims execution or protocol change")
    need(set(manifest["files"]) == expected_names - {"launcher-seal-manifest.json", "operator-argv.json"},
         "script identity inventory differs")
    for name, pin in manifest["files"].items():
        need(identity(files[name]) == pin, "sealed script differs")
    need(manifest["files"]["held_agent_campaign_02.py"] == PACKAGE["original_holder"], "original holder changed")

    # All package and metadata checks above finish before the first filesystem mutation.
    owned_directory(WORK)
    need(TARGET == WORK / "hepta-runtime-r35-recovery-20261106/parent-staging/mac-launchers-01",
         "fixed target namespace required")
    need(not os.path.lexists(TARGET), "create-only launcher target already exists")
    chain = [WORK / "hepta-runtime-r35-recovery-20261106",
             WORK / "hepta-runtime-r35-recovery-20261106/parent-staging", TARGET]
    for path in chain[:-1]:
        if os.path.lexists(path):
            owned_directory(path)
        else:
            need(path.resolve(strict=False) == path, "indirect new ancestor")
    os.umask(0o077)
    created = []
    for path in chain:
        if not os.path.lexists(path):
            os.mkdir(path, 0o700)
            created.append(str(path))
        else:
            need(path != TARGET, "create-only target appeared")
        owned_directory(path)
    target_before = owned_directory(TARGET)
    directory_fd = os.open(TARGET, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        need((os.fstat(directory_fd).st_dev, os.fstat(directory_fd).st_ino)
             == (target_before.st_dev, target_before.st_ino), "target changed while opened")
        for name, data in sorted(files.items()):
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600, dir_fd=directory_fd)
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            read_back(directory_fd, name, PACKAGE["members"][name])
        need(set(os.listdir(directory_fd)) == expected_names, "installed directory inventory differs")
        after = owned_directory(TARGET)
        need((after.st_dev, after.st_ino) == (target_before.st_dev, target_before.st_ino), "installed directory changed")
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    for path in reversed([WORK] + chain[:-1]):
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    print(json.dumps({"schema": "hepta-r35-mac-launcher-installation-result/v1", "installed": True,
        "target": str(TARGET), "archive": PACKAGE["archive"], "files": PACKAGE["members"],
        "file_count": 5, "expanded_file_bytes": PACKAGE["expanded_file_bytes"], "created_directories": created,
        "holder_started": False, "ssh_agent_started": False, "ssh_connections_started": 0,
        "workloads_started": 0, "automatic_retries": 0, "ci_result_inferred": False}, sort_keys=True))


if __name__ == "__main__":
    main()
'''


def main():
    qdir = RECOVERY / "r35-qualified-originals-01"
    qraw = {name: read(qdir / name, size, sha) for name, (_, size, sha) in Q_FILES.items()}
    q = json.loads(qraw["qualification-report.json"])
    qterminal = json.loads(qraw["qualification-terminal-status-01.json"])
    qread = json.loads(qraw["qualification-native-read-01.json"])
    original_native(qterminal, qread, Q_JOB)
    qverification = json.loads(read(RECOVERY / "r35-qualification-archive-template-01/actual-original-verification-01.json",
                                  5127, "dbb669af05864bbae6bf4ec0c20c9ce8a1f654588b1796d4ec51d015bf9b65d9"))
    counts = qverification["counts"]
    need(qverification["qualification_job_id"] == Q_JOB and qverification["recorded_outcome"] == "passed"
         and counts == {"passed": 1645, "failed": 0, "ignored": 34, "selected": 1679, "retries": 0}
         and q["qualified"] is True and all(row["returncode"] == 0 for row in q["stages"]), "actual qualification differs")
    postraw = read(qdir / "qualification-postflight-01.json", 8190,
                   "99e198adfeecb2f09b25d928a157a5067ef4a10315b1ead52134721665df630d")
    post = json.loads(postraw)
    need(post["passed"] is True and post["qualified"] is True and post["qualification_job_id"] == Q_JOB
         and post["counts"] == counts and post["compiler_input_count"] == 220
         and post["current_source_matches_qualified_map"] is True, "actual qualification postflight differs")
    for name, pin in post["retained_programs"].items():
        need({k: pin[k] for k in ("path", "sha256")} == q["binaries"][name], "postflight retained program differs")

    parent_dir = RECOVERY / "r35-parent-installed-originals-01"
    receipt_raw = read(parent_dir / "parent-tools-install-01.json", 26099,
                       "542fee8a1f146105125e402be5d7892709b76ff29ae273b162ffc4bff4f16bed")
    receipt = json.loads(receipt_raw)
    pt_raw = read(qdir / "parent-install-native-01.json", 731,
                  "38bf066213a890e2e0dce529241cf009769da33aa6040e7e67a3c233201ae069")
    pr_raw = read(qdir / "parent-install-read-01.json", 3667,
                  "ca6b91023ac46797ecd52fcbc10d67969cb1f799a7146a72fbaa3c23e59d0c77")
    pt, pr = json.loads(pt_raw), json.loads(pr_raw)
    streams = original_native(pt, pr, "1a1af801235-fc05-6921")
    installed = json.loads(streams["stdout"])
    need(streams["stderr"] == b"" and installed["installed"] is True and installed["workloads_started"] == 0
         and installed["receipt"] == dict(path=ROOT + "/parent-tools-install-01.json", **identity(receipt_raw))
         and receipt["passed"] is True and receipt["workloads_started"] == 0, "actual parent installation differs")

    generated = RECOVERY / "r35-observation-template-01/generated"
    bundle_raw = read(generated / "runner-bundle-manifest.json")
    need(identity(bundle_raw) == {k: receipt["bundle"][k] for k in ("bytes", "sha256")}, "installed bundle differs")
    bundle = json.loads(bundle_raw)
    scripts = {}
    for name in ("r35_campaign.py", "r35_lifecycle_campaign.py"):
        pin = bundle["files"][name]
        scripts[name] = read(generated / name, pin["bytes"], pin["sha256"])
        need(scripts[name] == read(RECOVERY / "r35-observation-template-01/mac-launchers-01" / name),
             "pre-reviewed Mac parent differs")
        ast.parse(scripts[name])
    holder = read(RECOVERY / "r34-mac-launchers-01/sealed-01/held_agent_campaign_02.py", 11374, HOLDER_SHA)
    need(holder == read(RECOVERY / "r35-observation-template-01/mac-launchers-01/held_agent_campaign_02.py"),
         "pre-reviewed original holder differs")
    scripts["held_agent_campaign_02.py"] = holder
    ast.parse(holder)

    examples = {}
    for label, name in (("campaign_example", "campaign-inputs-01.example.json"),
                        ("lifecycle_example", "lifecycle-inputs-01.example.json")):
        raw = read(parent_dir / name)
        pin = dict(path=ROOT + "/" + name, **identity(raw))
        need(pin == installed[label] == receipt["files"][pin["path"]], "actual installed example differs")
        examples[label] = pin
    for label, name in (("campaign_preparer", "prepare_campaign_inputs.py"),
                        ("lifecycle_preparer", "prepare_lifecycle_inputs.py")):
        raw = read(generated / name)
        need(identity(raw) == bundle["files"][name]
             and installed[label] == dict(path=ROOT + "/tools-01/" + name, **identity(raw)),
             "actual installed materializer differs")
    need(json.loads(read(parent_dir / "campaign-inputs-01.example.json"))["launcher_sha256"]
         == identity(scripts["r35_campaign.py"])["sha256"], "example parent differs")
    need(json.loads(read(parent_dir / "lifecycle-inputs-01.example.json"))["launcher_sha256"]
         == identity(scripts["r35_lifecycle_campaign.py"])["sha256"], "example lifecycle parent differs")

    commands = {
        "materialize_observation": ["/usr/bin/python3", "-B", ROOT + "/tools-01/prepare_campaign_inputs.py",
            "--example-sha256", examples["campaign_example"]["sha256"],
            "--preparer-sha256", installed["campaign_preparer"]["sha256"],
            "--preparation-sha256", identity(qraw["preparation.json"])["sha256"],
            "--qualification-terminal-sha256", identity(qraw["qualification-terminal-status-01.json"])["sha256"],
            "--qualification-job-id", Q_JOB],
        "observation_holder": ["/usr/bin/python3", "-B", "-u", MAC + "/held_agent_campaign_02.py",
            "--remote-script", MAC + "/r35_campaign.py", "--out", "/Users/qianqi/work/hepta-runtime-r35-observation-holder-01",
            "--timeout-seconds", "3600"],
        "materialize_normal_lifecycle_after_observation_gate": ["/usr/bin/python3", "-B", ROOT + "/tools-01/prepare_lifecycle_inputs.py",
            "--example-sha256", examples["lifecycle_example"]["sha256"],
            "--preparer-sha256", installed["lifecycle_preparer"]["sha256"]],
        "normal_lifecycle_holder_after_observation_gate": ["/usr/bin/python3", "-B", "-u", MAC + "/held_agent_campaign_02.py",
            "--remote-script", MAC + "/r35_lifecycle_campaign.py", "--out", "/Users/qianqi/work/hepta-runtime-r35-lifecycle-holder-01",
            "--timeout-seconds", "3600"],
    }
    lc_names = ("lifecycle-tools-manifest-01.json", "run_lifecycle_abba_01.py", "run_six_host_cancel_recovery_timed.py")
    lifecycle_pins = {name: receipt["files"][ROOT + "/lifecycle-tools-01/" + name] for name in lc_names}
    expected_lc = {
        "lifecycle-tools-manifest-01.json": (4066, "eb50cd7ab0376c4b3dc768e8d184fdc23eeaa90c2ce5bdd4b9e9ac551448504e"),
        "run_lifecycle_abba_01.py": (14787, "e01357cfb04f72f1ee1d56747df81b572e55c1528d2941f8dbbb0aa5e9a2ac84"),
        "run_six_host_cancel_recovery_timed.py": (30163, "54186d9750952061b54b255a509848ce72a252d676f584dd288edd263883c0d8"),
    }
    need(all((lifecycle_pins[n]["bytes"], lifecycle_pins[n]["sha256"]) == expected_lc[n] for n in lc_names),
         "actual R35 lifecycle tool identity differs")
    manifest = {
        "schema": "hepta-r35-mac-launcher-seal/v1", "status": "scripts_sealed_ci_completion_pending_not_deployed_by_this_task",
        "remote_root": ROOT, "proposed_mac_directory": MAC, "files": {n: identity(b) for n, b in sorted(scripts.items())},
        "holder_reference_git_blob": "c642b45500ed44abee56ba45614932855cd29892", "holder_bytes_unchanged": True,
        "parent_bytes_equal_to_reviewed_generated_R35_tools": True, "protocol_change": False,
        "qualification_job_id": Q_JOB, "qualification_counts": counts,
        "qualification_originals": {remote: dict(path=ROOT + "/" + remote, bytes=size, sha256=sha)
                                    for _, (remote, size, sha) in Q_FILES.items()},
        "qualification_postflight": dict(path=ROOT + "/qualification-postflight-01.json", **identity(postraw)),
        "candidate_binaries": post["retained_programs"],
        "source_map_sha256": identity(qraw["source-map.json"])["sha256"],
        "baseline_commit": "baab4def80be7af015b2e7a594cb302f66c4130e",
        "changed_paths_from_r24": post["changed_paths_from_r24"],
        "parent_installation": {"job_id": pt["job_id"], "original_terminal": identity(pt_raw),
            "original_read": identity(pr_raw), "original_stdout": identity(streams["stdout"]),
            "original_stderr": identity(streams["stderr"]), "receipt": installed["receipt"],
            "bundle": receipt["bundle"], **examples,
            "campaign_preparer": installed["campaign_preparer"], "lifecycle_preparer": installed["lifecycle_preparer"],
            "evidence_source": "exact local original installer terminal/read/receipt/example bytes, no new remote read by this task"},
        "actual_installed_lifecycle_tool_pins": lifecycle_pins,
        "exact_ci_original_job_id": CI_JOB, "exact_ci_job_identity_source": "coordinator reported actual original launch",
        "exact_ci_final_result": None, "exact_ci_completed_receipts": None,
        "exact_ci_prerequisite": "coordinator must close the original successful native/report/audit/source evidence before observation; this script package infers no CI result",
        "commands": commands,
        "normal_lifecycle_gate": "actual original observation gate must pass before normal lifecycle input materialization or holder launch",
        "normal_protocol_scope": "unchanged accepted-R24 normal observation, original boundary/recovery and conditional normal lifecycle; no R34 reserve-specific capacity campaign is added",
        "mac_directory_existence_or_deployment_not_observed": True, "native_holder_or_ssh_agent_started": False,
        "normal_observation_started_by_this_task": False, "observation_input_materialized_by_this_task": False,
        "remote_calls": 0,
    }
    OUT.mkdir(exist_ok=False)
    for name, raw in scripts.items():
        write(name, raw)
    write("launcher-seal-manifest.json", canonical(manifest))
    write("operator-argv.json", canonical(commands))
    members = {name: read(OUT / name) for name in sorted([*scripts, "launcher-seal-manifest.json", "operator-argv.json"])}
    tar_buffer = io.BytesIO()
    with tarfile.open(fileobj=tar_buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, raw in members.items():
            item = tarfile.TarInfo(name)
            item.size, item.mode, item.mtime, item.uid, item.gid = len(raw), 0o600, 0, 0, 0
            item.uname = item.gname = ""
            archive.addfile(item, io.BytesIO(raw))
    compressed = io.BytesIO()
    with gzip.GzipFile(fileobj=compressed, filename="", mode="wb", mtime=0, compresslevel=9) as stream:
        stream.write(tar_buffer.getvalue())
    archive_raw = compressed.getvalue()
    need(len(archive_raw) <= 128 * 1024 and len(tar_buffer.getvalue()) <= 512 * 1024, "package exceeds installer bounds")
    package = {"schema": "hepta-r35-mac-launcher-create-only-install-package/v1", "remote_root": ROOT,
        "target": MAC, "archive": identity(archive_raw), "members": {n: identity(b) for n, b in members.items()},
        "expanded_file_bytes": sum(map(len, members.values())), "qualification_job_id": Q_JOB,
        "qualification_counts": counts, "exact_ci_original_job_id": CI_JOB, "commands": commands,
        "original_holder": identity(holder), "installation_or_holder_execution_performed": False}
    write("r35-mac-launchers-01.tar.gz", archive_raw)
    write("package-identity.json", canonical(package))
    installer = ('#!/usr/bin/env python3\n# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0\n'
        '"""Install five frozen R35 Mac launcher files once; never launch them."""\n'
        'import base64,gzip,hashlib,io,json,os,pathlib,stat,sys,tarfile\n'
        'WORK=pathlib.Path("/Users/qianqi/work")\nTARGET=pathlib.Path(' + repr(MAC) + ')\n'
        'PACKAGE=' + pprint.pformat(package, sort_dicts=True, width=100) + '\n'
        'ARCHIVE_BASE64=' + repr(base64.b64encode(archive_raw).decode()) + '\n' + INSTALLER_BODY).encode()
    ast.parse(installer)
    write("install_r35_mac_launchers_01.py", installer)
    delivery = {"schema": "hepta-r35-mac-launcher-deployment-instructions/v1", "installer": identity(installer),
        "installer_remote_path": "/Users/qianqi/work/install_r35_mac_launchers_01.py",
        "installer_argv": ["/usr/bin/python3", "-B", "/Users/qianqi/work/install_r35_mac_launchers_01.py"],
        "installer_cwd": "/Users/qianqi/work", "target": MAC, "package": identity(archive_raw),
        "file_count": 5, "selected_bytes": package["expanded_file_bytes"],
        "ci_completion_pending_at_package_creation": True, "holder_started": False, "remote_calls": 0,
        "partial_failure_policy": "preserve partial create-only files and original native/read; no automatic retry, overwrite or rollback"}
    write("delivery.json", canonical(delivery))
    print(json.dumps({"created_local_package": True, "directory": str(OUT), "installer": identity(installer),
        "archive": identity(archive_raw), "selected_bytes": package["expanded_file_bytes"],
        "member_count": len(members), "ci_final_result": None, "remote_calls": 0}, sort_keys=True))


if __name__ == "__main__":
    main()
