#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Independent byte-only readback of the successful actual sparse-layout capture."""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import signal
import stat
import sys
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

sys.dont_write_bytecode = True
REPO = "TrillionniumFoundation/hepta-runtime"
ARTIFACT = 14293854874
RUN = 44007184164
ZIP_PIN = dict(bytes=176502250, sha256="8c927f2eec0f14b2f004b5eeab4d88dcdb8ccba5a6e69a7b4454241275fbce18")
TAR_PIN = dict(bytes=172492519, sha256="1aa65ade235fdcb0dd728183ce7ba0ea705d2a3d89f6c2b3bd0a055e1588942a")
SOURCE_MANIFEST = "6bad80123817cf94d0f6e505d1ff1ad589499dd17fd4c77ae80d5aba0ebfb6ca"

def require(ok, message):
    if not ok:
        raise ValueError(message)

def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()

def decode(raw):
    def unique(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate JSON key")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique)

def pin(path):
    with path.open("rb") as stream:
        return dict(bytes=path.stat().st_size, sha256=hashlib.file_digest(stream, "sha256").hexdigest())

def safe(name):
    p = PurePosixPath(name)
    require(name and not p.is_absolute() and ".." not in p.parts and p.as_posix() == name, "unsafe evidence path")
    return p

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None

def download(destination):
    token = os.environ.pop("GH_TOKEN")
    request = urllib.request.Request("https://api.github.com/repos/" + REPO + "/actions/artifacts/" + str(ARTIFACT),
        headers={"Authorization": "Bearer " + token, "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"})
    with urllib.request.urlopen(request, timeout=60) as stream:
        metadata = decode(stream.read())
    require(metadata["id"] == ARTIFACT and metadata["workflow_run"]["id"] == RUN
        and metadata["size_in_bytes"] == ZIP_PIN["bytes"] and metadata["digest"] == "sha256:" + ZIP_PIN["sha256"]
        and metadata["expired"] is False, "original artifact metadata changed")
    request = urllib.request.Request(request.full_url + "/zip", headers=request.headers)
    try:
        with urllib.request.build_opener(NoRedirect).open(request, timeout=60) as stream:
            require(False, "artifact ZIP endpoint did not return a separate download location")
    except urllib.error.HTTPError as response:
        require(response.code == 302, "artifact redirect status changed")
        location = response.headers["Location"]
    require(urllib.parse.urlsplit(location).scheme == "https", "artifact redirect is not HTTPS")
    # This new request has no GitHub authorization headers.
    with urllib.request.urlopen(urllib.request.Request(location), timeout=60) as stream, destination.open("xb") as output:
        shutil.copyfileobj(stream, output, 1024 * 1024)
    require(pin(destination) == ZIP_PIN, "full artifact ZIP bytes differ")
    return metadata

def recover(archive, root):
    root.mkdir()
    wanted_zip = {"evidence.tar.gz", "FILES.json", "ARCHIVE.json", "readonly.stderr"}
    with zipfile.ZipFile(archive) as z:
        infos = z.infolist()
        require(len(infos) == len(wanted_zip) and {p.filename for p in infos} == wanted_zip, "complete ZIP member set changed")
        for item in infos:
            safe(item.filename)
            require(not item.is_dir() and not stat.S_ISLNK(item.external_attr >> 16), "ZIP member type changed")
            with z.open(item) as incoming, (root / item.filename).open("xb") as output:
                shutil.copyfileobj(incoming, output, 1024 * 1024)
    require(pin(root / "evidence.tar.gz") == TAR_PIN, "complete inner TAR bytes differ")
    require((root / "readonly.stderr").read_bytes() == b"", "original guarded reader stderr is nonempty")
    index = decode((root / "FILES.json").read_bytes())
    receipt = decode((root / "ARCHIVE.json").read_bytes())
    rows = {r["path"]: r for r in index["files"]}
    require(len(rows) == len(index["files"]) == 17196 and sum(r["bytes"] for r in rows.values()) == 550617133,
        "complete retained file count or byte total changed")
    require(receipt == dict(status="COMPLETE_ARCHIVE_BYTES_PASS", files=17196, logical_bytes=550617133, archive=TAR_PIN),
        "original full archive receipt differs")
    extracted = root / "extracted"
    extracted.mkdir()
    seen = set()
    with tarfile.open(root / "evidence.tar.gz", "r:gz") as t:
        for item in t:
            safe(item.name)
            require(item.isfile() and item.name in rows and item.name not in seen, "TAR member set/type changed")
            seen.add(item.name)
            row = rows[item.name]
            require(item.size == row["bytes"] and item.mode == row["mode"], "TAR member size/mode changed")
            target = extracted / item.name
            target.parent.mkdir(parents=True, exist_ok=True)
            with t.extractfile(item) as incoming, target.open("xb") as output:
                shutil.copyfileobj(incoming, output, 1024 * 1024)
            require(pin(target) == {k: row[k] for k in ("bytes", "sha256")}, "retained full member bytes changed")
            target.chmod(row["mode"])
            os.utime(target, ns=(row["original_mtime_ns"], row["original_mtime_ns"]))
    require(seen == set(rows), "archive omitted a complete retained member")
    actual = {}
    for path in extracted.rglob("*"):
        mode = path.lstat().st_mode
        require(stat.S_ISDIR(mode) or stat.S_ISREG(mode), "non-ordinary extracted entry")
        if stat.S_ISREG(mode):
            actual[path.relative_to(extracted).as_posix()] = dict(**pin(path), mode=stat.S_IMODE(mode))
    expected = {n: {k: r[k] for k in ("bytes", "sha256", "mode")} for n, r in rows.items()}
    require(actual == expected, "full extracted set/bytes/modes differ")
    return extracted, index, receipt

def source_check(root, original):
    for source in (root, original):
        require(hashlib.sha256((source / "MANIFEST.json").read_bytes()).hexdigest() == SOURCE_MANIFEST,
            "frozen sparse proof source manifest changed")
        rows = decode((source / "MANIFEST.json").read_bytes())["files"]
        require({p.name for p in source.iterdir()} == {r["path"] for r in rows} | {"MANIFEST.json"}, "source closure changed")
        for row in rows:
            raw = (source / row["path"]).read_bytes()
            require(len(raw) == row["bytes"] and hashlib.sha256(raw).hexdigest() == row["sha256"]
                and hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest() == row["git_blob"], "proof source byte identity differs")
            require(raw == (original / row["path"]).read_bytes(), "checkout and retained reader source differ")
    return rows

def save_proof(out, report, index, receipt, source):
    out.mkdir()
    (out / "READBACK.json").write_bytes(encoded(report))
    (out / "ORIGINAL_FILES.json").write_bytes(encoded(index))
    (out / "ORIGINAL_ARCHIVE.json").write_bytes(encoded(receipt))
    for name in ("readback.py", "SOURCE.json"):
        shutil.copyfile(Path(__file__).parent / name, out / name)
    for name in ("qualify.py", "readonly.py", "common.py", "MANIFEST.json"):
        shutil.copyfile(source / name, out / ("frozen-" + name))
    rows = []
    tar_path = out.parent / "readback-proof.tar.gz"
    with tarfile.open(tar_path, "w:gz", compresslevel=1, format=tarfile.PAX_FORMAT) as t:
        for path in sorted(out.iterdir()):
            row = dict(path=path.name, **pin(path), mode=path.stat().st_mode & 0o777)
            rows.append(row)
            info = tarfile.TarInfo(path.name)
            info.size, info.mode = row["bytes"], row["mode"]
            with path.open("rb") as stream:
                t.addfile(info, stream)
    expected = {r["path"]: r for r in rows}
    seen = set()
    with tarfile.open(tar_path, "r:gz") as t:
        for member in t:
            require(member.isfile() and member.name in expected and member.name not in seen, "proof export member set changed")
            seen.add(member.name)
            row = expected[member.name]
            require(member.size == row["bytes"] and member.mode == row["mode"], "proof export metadata changed")
            with t.extractfile(member) as stream:
                require(hashlib.file_digest(stream, "sha256").hexdigest() == row["sha256"], "proof export complete bytes differ")
    require(seen == set(expected), "proof export incomplete")
    result = dict(status="INDEPENDENT_HISTORICAL58_SPARSE111_READBACK_PASS",
        artifact=ARTIFACT, run=RUN, original_zip=ZIP_PIN, original_tar=TAR_PIN, files=17196, logical_bytes=550617133,
        readback=pin(out / "READBACK.json"), proof_archive=pin(tar_path), proof_files=rows,
        result=report["guarded"]["evidence"], guard_probes=len(report["guarded"]["probes"]),
        before_after_unchanged=report["guarded"]["before"] == report["guarded"]["after"],
        native_or_rust_executions=0)
    (out.parent / "READBACK_INDEX.json").write_bytes(encoded(result))
    print(json.dumps(result, sort_keys=True))

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    source = a.source.resolve(strict=True)
    output = a.output.absolute()
    require(not output.exists(), "independent readback output must be fresh")
    output.mkdir(parents=True)
    archive = output / "original-artifact.zip"
    metadata = download(archive)
    extracted, index, receipt = recover(archive, output / "retained")
    source_rows = source_check(source, extracted / "recipe-source")
    sys.path.insert(0, str(source))
    import qualify
    from readonly import guarded
    # Every import, including ctypes initialization and materializer modules,
    # happens before the frozen audit guard is active.
    for current in sorted((extracted / "capture/layouts").glob("*/current-source")):
        qualify.load_materializer(current)
    def expired(signum, frame):
        raise TimeoutError("independent frozen reader exceeded 180 seconds")
    signal.signal(signal.SIGALRM, expired)
    started = time.monotonic_ns()
    signal.alarm(180)
    try:
        proof = guarded(lambda: qualify.read(extracted / "capture"), roots=[output / "retained", source])
    finally:
        signal.alarm(0)
    elapsed = time.monotonic_ns() - started
    require(pin(archive) == ZIP_PIN and pin(output / "retained/evidence.tar.gz") == TAR_PIN, "source artifacts changed during reread")
    require(proof["evidence"]["status"] == "SPARSE_CURRENT111_HISTORICAL58_SOURCE_ONLY_PASS"
        and proof["evidence"]["production_files_unchanged"] == 390
        and proof["evidence"]["workflow_files"] == 4 and proof["evidence"]["sparse_checkouts"] == 7
        and len(proof["evidence"]["layouts"]) == 3 and proof["evidence"]["mutations"] == 4
        and proof["evidence"]["tree_files"] == 13257 and proof["evidence"]["historical_restore_unchanged"] == 119,
        "complete source-only proof scope changed")
    report = dict(schema="hepta.runtime.historical58-sparse111-independent-readback.v1",
        original_artifact_metadata=metadata, guarded=proof, source_rows=source_rows, elapsed_ns=elapsed,
        limit_seconds=180, native_executed=False, rust_executed=False, original_evidence_written=False)
    save_proof(output / "proof", report, index, receipt, source)

if __name__ == "__main__":
    main()
