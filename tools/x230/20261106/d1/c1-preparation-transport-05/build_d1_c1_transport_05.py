#!/usr/bin/env python3
"""Package the frozen unsealed D1 C1 source without importing any target."""
import ast
import base64
import gzip
import hashlib
import io
import json
import tarfile
from pathlib import Path

SRC = Path("/tmp/hepta-runtime-recovery-20261106/d1-c1-parent-template-05")
OUT = Path("/tmp/hepta-runtime-recovery-20261106/d1-c1-preparation-transport-05")
REMOTE = Path("/home/qian/hepta-runtime-phase-cost-20261106-d1")


def ident(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def write_new(path, raw):
    with path.open("xb") as stream:
        stream.write(raw)
    assert path.read_bytes() == raw


def main():
    assert not OUT.exists()
    manifest_raw = (SRC / "package-manifest.json").read_bytes()
    assert ident(manifest_raw) == {"bytes": 13228, "sha256": "40693bc863122eff6c554aa18e4c4394e9a6c17a90753b2761deaa920382c38e"}
    manifest = json.loads(manifest_raw)
    members = {}
    for row in manifest["files"]:
        raw = (SRC / row["path"]).read_bytes()
        assert ident(raw) == {key: row[key] for key in ("bytes", "sha256")}
        members[row["path"]] = raw
    members["package-manifest.json"] = manifest_raw
    assert len(members) == 43 and sum(map(len, members.values())) == 564059
    assert manifest["sealed"] is False and manifest["revision"] == "05"
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, raw in sorted(members.items()):
            item = tarfile.TarInfo(name)
            item.size, item.mode, item.mtime = len(raw), 0o600, 0
            item.uid = item.gid = 0
            item.uname = item.gname = ""
            archive.addfile(item, io.BytesIO(raw))
    tar_raw = stream.getvalue()
    compressed = gzip.compress(tar_raw, compresslevel=6, mtime=0)
    # Verify the exact package in memory; no tar member is extracted to a path.
    with tarfile.open(fileobj=io.BytesIO(gzip.decompress(compressed)), mode="r:") as archive:
        actual = {}
        for item in archive:
            assert item.type == tarfile.REGTYPE and not item.pax_headers
            assert item.name not in actual and item.name in members
            actual[item.name] = archive.extractfile(item).read()
        assert actual == members
    installer_original = (SRC / "install_campaign.py").read_text()
    tree = ast.parse(installer_original)
    lines = installer_original.splitlines(True)
    names = ("need", "canonical", "identity", "stamp", "regular", "directory", "sync_directory", "write_new")
    functions = {node.name: "".join(lines[node.lineno - 1:node.end_lineno]) for node in tree.body if isinstance(node, ast.FunctionDef)}
    helpers = "\n\n".join(functions[name] for name in names) + "\n\n"
    header = '''#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Install the exact unsealed D1 C1 preparation once; execute no packaged code."""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
import tarfile

ROOT = Path("/home/qian/hepta-runtime-phase-cost-20261106-d1")
DEST = ROOT / "c1-parent-preparation-05"
RECEIPT = ROOT / "c1-preparation-install-05.json"
ARCHIVE = ROOT / "c1-parent-preparation-05.tar.gz"
MAX_FILE = 4 * 1024 * 1024
MAX_TOTAL = 16 * 1024 * 1024
MAX_FILES = 128
MAX_TAR = MAX_TOTAL + MAX_FILES * 1024 + 10240
EXPECTED_MANIFEST = {"bytes": 13228, "sha256": "40693bc863122eff6c554aa18e4c4394e9a6c17a90753b2761deaa920382c38e"}
EXPECTED_MEMBERS = 43
EXPECTED_PAYLOAD_BYTES = 564059
'''
    header += "EXPECTED_ARCHIVE = " + repr(ident(compressed)) + "\n\n\n"
    body = '''def install(args):
    need(not sys.flags.optimize and sys.platform == "linux" and os.geteuid() == 1000,
         "original non-root x230 operator and normal Python are required")
    need(Path(args.archive) == ARCHIVE, "fixed source archive path is required")
    directory(ROOT)
    archive_raw = regular(ARCHIVE)
    need(len(archive_raw) == EXPECTED_ARCHIVE["bytes"]
         and hashlib.sha256(archive_raw).hexdigest() == EXPECTED_ARCHIVE["sha256"],
         "exact source archive differs")
    with gzip.GzipFile(fileobj=io.BytesIO(archive_raw), mode="rb") as compressed:
        tar_raw = compressed.read(MAX_TAR + 1)
    need(len(tar_raw) <= MAX_TAR, "source archive expansion exceeds the bound")
    members, total = {}, 0
    with tarfile.open(fileobj=io.BytesIO(tar_raw), mode="r:") as archive:
        for item in archive:
            name = item.name
            relative = Path(name)
            need(item.type == tarfile.REGTYPE and not item.pax_headers
                 and not getattr(item, "sparse", None)
                 and not relative.is_absolute() and relative.as_posix() == name
                 and all(part not in {"", ".", ".."} for part in relative.parts)
                 and name not in members and 0 <= item.size <= MAX_FILE,
                 "unsafe, repeated or oversized source member")
            need(len(members) < MAX_FILES, "source member count exceeds the bound")
            stream = archive.extractfile(item)
            need(stream is not None, "regular source member has no body")
            raw = stream.read(item.size + 1)
            need(len(raw) == item.size, "source member length differs")
            total += len(raw)
            need(total <= MAX_TOTAL, "source payload exceeds the total bound")
            members[name] = raw
    need(len(members) == EXPECTED_MEMBERS and total == EXPECTED_PAYLOAD_BYTES,
         "fixed source payload inventory differs")
    manifest_raw = members.get("package-manifest.json", b"")
    need(len(manifest_raw) == EXPECTED_MANIFEST["bytes"]
         and hashlib.sha256(manifest_raw).hexdigest() == EXPECTED_MANIFEST["sha256"],
         "frozen unsealed source manifest differs")
    manifest = json.loads(manifest_raw)
    need(manifest.get("schema") == "hepta-d1-c1-outer-preparation/v1"
         and manifest.get("revision") == "05" and manifest.get("sealed") is False
         and manifest.get("source_only") is True
         and manifest.get("actual_ordinary_result") is None
         and manifest.get("actual_measurement") is None
         and manifest.get("performance_acceptance_claim") is False,
         "only the exact unsealed source preparation may be installed")
    rows = manifest["files"]
    need(type(rows) is list and len(rows) == manifest["file_count"] == EXPECTED_MEMBERS - 1,
         "source manifest count differs")
    expected = {"package-manifest.json"}
    for row in rows:
        name = row["path"]
        need(name not in expected and name in members, "unknown or repeated declared source")
        need(len(members[name]) == row["bytes"]
             and hashlib.sha256(members[name]).hexdigest() == row["sha256"],
             "declared source bytes differ: " + name)
        expected.add(name)
    need(expected == set(members)
         and sum(row["bytes"] for row in rows) == manifest["payload_bytes"],
         "source manifest is incomplete")
    need(not os.path.lexists(DEST) and not os.path.lexists(RECEIPT),
         "source preparation or installation receipt already exists")
    # All source bodies and all destination guards are checked before mutation.
    # Partial failure leaves created originals intact; no cleanup or replay.
    os.umask(0o077)
    DEST.mkdir(mode=0o700)
    directory(DEST, private=True)
    sync_directory(ROOT)
    parents = set()
    for name in members:
        relative = Path(name).parent
        while relative != Path("."):
            parents.add(relative)
            relative = relative.parent
    created = [str(DEST)]
    for relative in sorted(parents, key=lambda path: (len(path.parts), path.as_posix())):
        path = DEST / relative
        path.mkdir(mode=0o700)
        directory(path, private=True)
        sync_directory(path.parent)
        created.append(str(path))
    installed = [write_new(DEST / name, raw) for name, raw in sorted(members.items())]
    need(regular(ARCHIVE) == archive_raw, "source archive changed during installation")
    receipt = {
        "schema": "hepta-d1-c1-source-preparation-install/v1",
        "archive": identity(ARCHIVE, archive_raw),
        "package_manifest": identity(DEST / "package-manifest.json", manifest_raw),
        "destination": str(DEST), "created_directories": created,
        "files": installed, "file_count": len(installed), "payload_bytes": total,
        "installed": True, "actual_source_seal_performed": False,
        "target_imports_or_executions": False, "compiler_or_workload_started": False,
        "ordinary_result_claimed": False, "host_requests": 0, "automatic_retries": 0,
        "existing_ordinary_or_runtime_source_modified": False,
        "partial_failure_policy": "Preserve original native logs and all created paths; do not replay or remove them.",
    }
    receipt_pin = write_new(RECEIPT, canonical(receipt))
    print(json.dumps({"receipt": receipt_pin, "file_count": len(installed),
                      "payload_bytes": total, "source_sealed": False,
                      "compiler_or_workload_started": False}, sort_keys=True), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True)
    install(parser.parse_args())


if __name__ == "__main__":
    main()
'''
    installer = (header + helpers + body).encode()
    parsed = ast.parse(installer)
    ilines = installer.decode().splitlines(True)
    now = {n.name: "".join(ilines[n.lineno - 1:n.end_lineno]) for n in parsed.body if isinstance(n, ast.FunctionDef)}
    assert all(now[name] == functions[name] for name in names)
    assert not any(isinstance(n, (ast.Import, ast.ImportFrom)) and any(a.name.startswith(("subprocess", "socket", "urllib", "requests")) for a in n.names) for n in ast.walk(parsed))
    OUT.mkdir(mode=0o700)
    write_new(OUT / "c1-parent-preparation-05.tar.gz", compressed)
    write_new(OUT / "c1-parent-preparation-05.tar.gz.b64", base64.b64encode(compressed))
    write_new(OUT / "install_c1_parent_preparation_05.py", installer)
    macroot = "/Users/qianqi/work/hepta-runtime-d1-launchers-01"
    macout = "/Users/qianqi/work/hepta-runtime-d1-c1-holder-01"
    report = {
        "schema": "hepta-d1-c1-source-preparation-transport/v1",
        "source_directory": str(SRC), "remote_root": str(REMOTE),
        "archive": {"local": str(OUT / "c1-parent-preparation-05.tar.gz"),
                    "remote": str(REMOTE / "c1-parent-preparation-05.tar.gz"), **ident(compressed)},
        "archive_base64": {"local": str(OUT / "c1-parent-preparation-05.tar.gz.b64"),
                           **ident(base64.b64encode(compressed)), "line_ending_added": False},
        "installer": {"local": str(OUT / "install_c1_parent_preparation_05.py"),
                      "remote": str(REMOTE / "install_c1_parent_preparation_05.py"), **ident(installer)},
        "source_manifest": ident(manifest_raw), "members": 43, "payload_bytes": 564059,
        "source_only_installation_argv": ["/usr/bin/python3", "-B", str(REMOTE / "install_c1_parent_preparation_05.py"),
                                          "--archive", str(REMOTE / "c1-parent-preparation-05.tar.gz")],
        "later_seal_argv": ["/usr/bin/python3", "-I", "-B", str(REMOTE / "c1-parent-preparation-05/seal_campaign.py"),
                            "--prerequisites", str(REMOTE / "c1-parent-preparation-05/actual-prerequisites-01.json"),
                            "--output", str(REMOTE / "c1-sealed-01")],
        "later_linux_install_argv": ["/usr/bin/python3", "-I", "-B", str(REMOTE / "c1-sealed-01/install_campaign.py"),
                                     "--sealed-dir", str(REMOTE / "c1-sealed-01"),
                                     "--manifest-sha256", "<actual seal-manifest SHA256>", "--target", "x230"],
        "later_mac_staging_directory": "/Users/qianqi/work/hepta-runtime-d1-c1-sealed-staging-01",
        "later_mac_install_argv": ["/usr/bin/python3", "-I", "-B", "/Users/qianqi/work/hepta-runtime-d1-c1-sealed-staging-01/install_campaign.py",
                                   "--sealed-dir", "/Users/qianqi/work/hepta-runtime-d1-c1-sealed-staging-01",
                                   "--manifest-sha256", "<same actual seal-manifest SHA256>", "--target", "mac"],
        "later_unique_holder_argv": ["/usr/bin/python3", "-B", macroot + "/held_agent_campaign_02.py",
                                    "--remote-script", macroot + "/d1_campaign.py", "--out", macout,
                                    "--timeout-seconds", "3600"],
        "later_seal_requires": "Actual ordinary02 five-stage original terminal/read plus successful original readonly verifier postflight02 and its native completion; all compiler work closed. Root retains the actual original receipts.",
        "c1_destination_foundation_must_remain_absent_until_install": str(REMOTE / "c1-prerequisites-01.json"),
        "original_helper_sources_byte_identical": list(names),
        "source_tar_memory_roundtrip_verified": True, "filesystem_extraction_performed": False,
        "installer_syntax_parsed": True, "installer_executed": False,
        "target_imports_or_functions_executed": 0, "host_requests": 0,
        "actual_ordinary_result": None, "actual_c1_result": None,
        "independent_source_review_git_blob": "11965cd600d8dbcfdc1dd3b2d497b3b766866ffa",
    }
    body = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode()
    write_new(OUT / "transport-manifest.json", body)
    print(json.dumps({"archive": ident(compressed), "base64": ident(base64.b64encode(compressed)),
                      "installer": ident(installer), "manifest": ident(body),
                      "members": 43, "payload_bytes": 564059, "installer_executed": False}, sort_keys=True))


if __name__ == "__main__":
    main()
