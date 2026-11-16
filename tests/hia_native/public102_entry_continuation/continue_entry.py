"""Continue only the missing installed entry from complete, same-head captured bytes.

The source Authority job remains cancelled. All old semantic receipts and budgets
are preserved; the immutable complete readers remain the admission authority.
"""
from pathlib import Path, PurePosixPath
import argparse
import hashlib
import json
import os
import shutil
import stat
import sys
import zipfile

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
BASELINE_GIT = "790b6dd4df5b9dc39ec5201fa462a7f26b88dd58"
PART_BYTES = 128 * 1024 * 1024
AUTHORITY_STATUS = "READONLY_PUBLIC102_AUTHORITY259_HANDSHAKE324_PUBLIC90_TRANSPORT24_PASS"
JOINT_STATUS = "READONLY_AUTHORITY102_AND_COMPLETE_BATCH_PASS"


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def regular(path):
    info = path.lstat()
    assert stat.S_ISREG(info.st_mode) and info.st_nlink == 1
    assert path.resolve(strict=True) == path.absolute()
    return info


def pin(path):
    info = regular(path)
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    assert path.stat().st_size == info.st_size
    return dict(bytes=info.st_size, sha256=digest)


def git_blob(path):
    raw = path.read_bytes()
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


def doc(path):
    regular(path)
    return json.loads(path.read_bytes())


def put(path, value):
    with path.open("xb") as stream:
        stream.write(encoded(value))


def safe(name):
    path = PurePosixPath(name)
    assert name and not path.is_absolute() and ".." not in path.parts
    assert str(path) == name and "\\" not in name
    return Path(*path.parts)


def files(root):
    rows = {}
    for directory, children, names in os.walk(root, followlinks=False):
        folder = Path(directory)
        assert folder.resolve(strict=True) == folder.absolute()
        assert all(not (folder / name).is_symlink() for name in children)
        for name in names:
            path = folder / name
            rows[path.relative_to(root).as_posix()] = pin(path)
    return rows


def source():
    profile = doc(HERE / "SOURCE.json")
    assert profile["schema"] == "hepta.public102.entry-continuation.source.v1"
    assert set(profile["files"]) == {"continue_entry.py", "BASELINE.json", "authority-cancelled.log"}
    assert set(files(HERE)) == set(profile["files"]) | {"SOURCE.json"}
    for name, blob in profile["files"].items():
        assert git_blob(HERE / name) == blob, name
    assert git_blob(HERE / "BASELINE.json") == BASELINE_GIT
    baseline = doc(HERE / "BASELINE.json")
    assert baseline["runtime_commit"] == "7afd543feea2938b08ae8c10f1c6a911f23621ed"
    assert baseline["source_workflow_run"] == 43926475626
    assert baseline["authority_job_conclusion"] == "cancelled"
    assert baseline["batch_job_conclusion"] == "success"
    assert pin(HERE / "authority-cancelled.log") == {
        key: baseline["full_log"][key] for key in ("bytes", "sha256")}
    return baseline


def extractor(joint, baseline):
    assert pin(joint / "joint-source.json")["sha256"] == baseline["joint_profile_sha256"]
    profile = doc(joint / "joint-source.json")
    name = "extract_archive.py"
    expected = profile["files"][name]
    actual = pin(joint / name)
    assert actual == {key: expected[key] for key in actual}
    assert git_blob(joint / name) == expected["git_blob"]
    namespace = {"__name__": "_complete_frozen_archive_extractor", "__file__": str(joint / name)}
    exec(compile((joint / name).read_bytes(), str(joint / name), "exec"), namespace)
    return namespace["extract"]


def validate_artifact(metadata, archive, expected, baseline):
    value = doc(metadata)
    assert value["id"] == expected["id"]
    assert value["name"] == expected["name"] and value["expired"] is False
    assert value["size_in_bytes"] == expected["bytes"]
    assert value["digest"] == "sha256:" + expected["sha256"]
    assert value["workflow_run"]["id"] == baseline["source_workflow_run"]
    assert value["workflow_run"]["head_sha"] == baseline["runtime_commit"]
    assert pin(archive) == {key: expected[key] for key in ("bytes", "sha256")}
    return value


def unzip(archive, output, expected_members=None):
    assert not output.exists()
    output.mkdir(parents=True)
    rows = {}
    with zipfile.ZipFile(archive) as zipped:
        for member in zipped.infolist():
            path = output / safe(member.filename)
            assert member.filename not in rows and not member.is_dir()
            assert stat.S_IFMT(member.external_attr >> 16) in (0, stat.S_IFREG)
            path.parent.mkdir(parents=True, exist_ok=True)
            size = 0
            digest = hashlib.sha256()
            with zipped.open(member) as stream, path.open("xb") as destination:
                while block := stream.read(1 << 20):
                    destination.write(block)
                    digest.update(block)
                    size += len(block)
            assert size == member.file_size
            rows[member.filename] = dict(bytes=size, sha256=digest.hexdigest())
    if expected_members is not None:
        assert rows == expected_members
    return rows


def prepare(a, baseline):
    assert not a.root.exists()
    a.root.mkdir(parents=True)
    expected = baseline["authority_artifact"]
    metadata = validate_artifact(a.metadata, a.archive, expected, baseline)
    rows = unzip(a.archive, a.root / "download", expected["members"])
    extract = extractor(a.joint, baseline)
    result = extract("authority",
        a.root / "download/joint-authority-evidence.tar.gz",
        a.root / "download/joint-authority-evidence.archive.json",
        a.root / "authority")
    for name, identity in baseline["original_archive_files"].items():
        assert pin(a.root / "authority" / safe(name)) == identity, name
    run = a.root / "authority/run"
    recipe = doc(run / "RECIPE.json")
    origin = Path(recipe["producer_identity"]["output"])
    identity = recipe["producer_identity"]
    # The new entry really executes at these restored, original runner paths.
    # No producer string, command, receipt or module manifest is rewritten.
    assert Path.cwd() == Path(identity["cwd"]) == Path(os.environ["GITHUB_WORKSPACE"])
    assert Path(identity["source"]) == a.joint / "authority"
    assert Path(identity["hepta"]) == Path.cwd() / "compiler"
    assert identity["python"] == sys.executable == "/usr/bin/python3"
    assert origin == Path(os.environ["RUNNER_TEMP"]) / "joint-authority-output"
    assert recipe["status"] == "PASS" and recipe["fresh_public_102"] is True
    assert recipe["current_owner_original_rows"] == 243 and recipe["current_public_owner_rows"] == 16
    assert not origin.exists() and not (run / "installed-main-entry").exists()
    assert doc(run / "main-default-entry/PROCESS.json")["status"] == "ACTUAL_ISOLATED_DEFAULT_ENTRY_CAPTURED"
    put(a.root / "PREPARED.json", dict(
        schema="hepta.public102.entry-continuation.prepared.v1",
        baseline=baseline, artifact_metadata=metadata, archive=pin(a.archive),
        zip_members=rows, extraction=result, original_run=str(origin),
        original_job_remains_cancelled=True, original_capture_rewritten=False,
        new_semantic_replays=0, new_rust_processes=0))
    run.rename(origin)


def restored_run(a):
    return Path(doc(a.root / "PREPARED.json")["original_run"])


def preserved(a):
    run = restored_run(a)
    previous = doc(a.root / "authority/artifact-manifest.json")["files"]
    expected = {name.removeprefix("run/"): value for name, value in previous.items() if name.startswith("run/")}
    actual = files(run)
    assert {name: actual[name] for name in expected} == expected
    new = {name: value for name, value in actual.items() if name not in expected}
    assert new and all(name.startswith("installed-main-entry/") for name in new)
    receipt = doc(run / "installed-main-entry/PROCESS.json")
    assert receipt["status"] == "ACTUAL_MAIN_DEFAULT_ENTRY_CAPTURED" and receipt["exit_code"] == 0
    assert receipt["cleanup_errors"] == receipt["failures"] == []
    return dict(status="ALL_ORIGINAL_CAPTURE_FILES_UNCHANGED",
        original_regular_files=len(expected), original_regular_bytes=sum(x["bytes"] for x in expected.values()),
        original_files_sha256=hashlib.sha256(encoded(expected)).hexdigest(),
        added_files=new, added_files_only_installed_main_entry=True,
        original_job_remains_cancelled=True)


def seal_proof(a, baseline):
    result = preserved(a)
    proof = restored_run(a) / "installed-main-entry/continuation-proof"
    assert not proof.exists()
    proof.mkdir()
    put(proof / "PRESERVED.json", result)
    shutil.copyfile(a.root / "PREPARED.json", proof / "PREPARED.json")
    source_out = proof / "source"
    source_out.mkdir()
    for name in ("continue_entry.py", "BASELINE.json", "authority-cancelled.log", "SOURCE.json"):
        shutil.copyfile(HERE / name, source_out / name)
    prior = proof / "prior-authority"
    prior.mkdir()
    for name in ("artifact-manifest.json", "ARTIFACT.json", "EXPORT_READER.json",
                 "EXPORT_READER.stdout", "EXPORT_READER.stderr", "EXPORT_READBACK.json"):
        shutil.copyfile(a.root / "authority" / name, prior / name)
    for name in ("joint-authority-evidence.archive.json", "joint-authority-reader.json", "joint-entry-reader.json"):
        shutil.copyfile(a.root / "download" / name, prior / name)
    records = a.root / "records"
    required = {"authority-reader.json", "isolated-entry-reader.json", "actual-main-entry.stdout",
        "actual-main-entry-reader.json", "installed-source-controls.json"}
    assert set(files(records)) == required
    for name in sorted(required):
        shutil.copyfile(records / name, proof / name)
    put(proof / "FILES.json", files(proof))
    put(a.root / "PRESERVED.json", preserved(a))
    print(json.dumps(dict(status="SAME_HEAD_ENTRY_CONTINUATION_CAPTURED",
        reference_semantic_job=baseline["authority_job"], reference_job_conclusion="cancelled",
        fresh_semantic_replay_executions=0, fresh_rust_executions=0,
        original_capture_files=result["original_regular_files"],
        original_capture_bytes=result["original_regular_bytes"]), sort_keys=True))


def split(a):
    index = doc(a.index)
    assert index["schema"] == "hepta.public102-authority.archive.v1"
    assert index["status"] == AUTHORITY_STATUS and index["complete_archive_reread"] is True
    assert index["readonly_export_reader_error"] is None
    assert pin(a.archive) == {key: index[key] for key in ("bytes", "sha256")}
    assert not a.output.exists()
    a.output.mkdir(parents=True)
    parts = []
    with a.archive.open("rb") as stream:
        while block := stream.read(PART_BYTES):
            name = "part%02d.bin" % len(parts)
            (a.output / name).write_bytes(block)
            parts.append(dict(name=name, bytes=len(block), sha256=hashlib.sha256(block).hexdigest()))
    assert 1 <= len(parts) <= 8
    put(a.output / "parts.json", dict(schema="hepta.public102.entry-continuation.parts.v1",
        archive=pin(a.archive), index=pin(a.index), parts=parts))
    shutil.copyfile(a.index, a.output / "archive.json")
    print(json.dumps(dict(status="COMPLETE_CONTINUATION_ARCHIVE_SPLIT", parts=len(parts),
        archive=pin(a.archive)), sort_keys=True))


def join(a):
    parts = doc(a.index)
    assert parts["schema"] == "hepta.public102.entry-continuation.parts.v1"
    assert a.metadata is not None and pin(a.metadata) == parts["index"]
    expected = parts["parts"]
    assert 1 <= len(expected) <= 8
    assert [x["name"] for x in expected] == ["part%02d.bin" % i for i in range(len(expected))]
    assert set(files(a.root)) == {x["name"] for x in expected}
    assert not a.output.exists()
    with a.output.open("xb") as destination:
        for i, row in enumerate(expected):
            path = a.root / row["name"]
            assert pin(path) == {key: row[key] for key in ("bytes", "sha256")}
            assert 0 < row["bytes"] <= PART_BYTES
            if i + 1 != len(expected):
                assert row["bytes"] == PART_BYTES
            with path.open("rb") as source_stream:
                shutil.copyfileobj(source_stream, destination, 1 << 20)
    assert pin(a.output) == parts["archive"]
    print(json.dumps(dict(status="ALL_PARTS_AND_COMPLETE_ARCHIVE_HASH_PASS",
        archive=pin(a.output), parts=len(expected)), sort_keys=True))


def prepare_batch(a, baseline):
    expected = baseline["batch_artifact"]
    metadata = validate_artifact(a.metadata, a.archive, expected, baseline)
    assert not a.root.exists()
    a.root.mkdir(parents=True)
    rows = unzip(a.archive, a.root / "download")
    result = extractor(a.joint, baseline)("batch",
        a.root / "download/joint-batch-evidence/batch-public-complete.tar.gz",
        a.root / "download/joint-batch-evidence/archive.json", a.root / "batch")
    put(a.root / "PREPARED.json", dict(schema="hepta.public102.entry-continuation.batch.v1",
        artifact_metadata=metadata, zip=pin(a.archive), zip_members=rows, extraction=result))
    print(json.dumps(result, sort_keys=True))


def final(a, baseline):
    authority = a.authority
    proof = authority / "run/installed-main-entry/continuation-proof"
    before = doc(proof / "FILES.json")
    assert files(proof) == before | {"FILES.json": pin(proof / "FILES.json")}
    for name in ("continue_entry.py", "BASELINE.json", "authority-cancelled.log", "SOURCE.json"):
        assert (proof / "source" / name).read_bytes() == (HERE / name).read_bytes()
    assert pin(proof / "prior-authority/artifact-manifest.json") == baseline["original_archive_files"]["artifact-manifest.json"]
    for name in ("run/RECIPE.json", "run/verification.json"):
        assert pin(authority / name) == baseline["original_archive_files"][name]
    old = doc(proof / "prior-authority/artifact-manifest.json")["files"]
    wanted = {name.removeprefix("run/"): value for name, value in old.items() if name.startswith("run/")}
    current = files(authority / "run")
    assert {name: current[name] for name in wanted} == wanted
    assert all(name in wanted or name.startswith("installed-main-entry/") for name in current)
    joint = doc(a.records / "joint-complete.json")
    entry = doc(a.records / "installed-main-relocated.json")
    assert joint["status"] == JOINT_STATUS
    assert joint["readonly"]["complete_before_after_equal"] is True
    assert len(joint["readonly"]["probes"]) == 11
    evidence = joint["evidence"]
    assert evidence["authority_domains"] == dict(original_owner=243, current_public_owner=16,
        handshake_sessions=54, handshake_responses=324, public_responses=90, transport_cases=24,
        codec_eof_reference_cases=4, current_profile_native_groups=23, historical_profile_groups=7)
    assert evidence["batch_domains"] == dict(private_rows_per_provider=1777, stdio_rows_per_provider=28,
        typed_legacy=417, typed_modern=417, filesystem=926, session=17, evidence_refusals=21, evidence_admissions=2)
    assert entry["evidence"]["status"] == "ACTUAL_MAIN_DEFAULT_ENTRY_EQUALS_QUALIFIED_PUBLIC102"
    assert len(entry["probes"]) == 11 and entry["before"] == entry["after"]
    result = dict(schema="hepta.public102.same-head-entry-continuation.v1",
        status="SAME_HEAD_FRESH_CAPTURE_DEFAULT_ENTRY_AND_JOINT_READONLY_PASS",
        qualified_runtime_commit=baseline["runtime_commit"], original_workflow_run=baseline["source_workflow_run"],
        original_authority_job=baseline["authority_job"], original_authority_job_conclusion="cancelled",
        original_batch_job=baseline["batch_job"], original_batch_job_conclusion="success",
        original_cancellation_relabelled=False, source_head_unchanged=True,
        original_semantic_domains=evidence["authority_domains"], batch_domains=evidence["batch_domains"],
        actual_installed_main_entry=True, actual_entry_relocated_reader=True,
        complete_original_capture_files_preserved=len(wanted),
        complete_unchanged_component_readers=True, complete_source_and_entry_controls=True,
        fresh_rust_or_semantic_replay_in_continuation=False,
        new_checked_reuse_entry_members=102, new_fresh_member_compiles=0,
        immutable_joint_recipe=baseline["joint_commit"], source_files=files(HERE),
        readonly_reports={name:pin(a.records/name) for name in sorted(files(a.records))},
        current_public_ordinary_profile_qualified=True,
        whole_runtime_replaced=False, full_sdk_qualified=False, full_async_qualified=False,
        remote_batch_qualified=False, production_activated=False, old_path_removed=False)
    put(a.output, result)
    print(json.dumps(result, sort_keys=True))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("mode", choices=("prepare", "seal-proof", "split", "join", "prepare-batch", "final", "source"))
    for name in ("root", "joint", "archive", "metadata", "index", "output", "authority", "records"):
        p.add_argument("--"+name, type=Path)
    a = p.parse_args()
    for name in ("root", "joint", "archive", "metadata", "index", "output", "authority", "records"):
        path = getattr(a, name)
        if path is not None:
            setattr(a, name, path.absolute())
    baseline = source()
    if a.mode == "source":
        print(json.dumps(dict(status="CONTINUATION_SOURCE_PASS", files=files(HERE),
            runtime_commit=baseline["runtime_commit"], native_or_rust_executions=0),sort_keys=True))
    elif a.mode == "prepare": prepare(a, baseline)
    elif a.mode == "seal-proof": seal_proof(a, baseline)
    elif a.mode == "split": split(a)
    elif a.mode == "join": join(a)
    elif a.mode == "prepare-batch": prepare_batch(a, baseline)
    else: final(a, baseline)


if __name__ == "__main__":
    main()
