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
"""Independent byte-only readback of current text publisher typed qualification."""
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
ARTIFACT = 14293983531
RUN = 44006321980
ZIP_PIN = dict(bytes=497017753, sha256="2546967c41da08b1b2d7efd139f6f33edca6919df51e44104dab162cf37592f8")
TAR_PIN = dict(bytes=492649161, sha256="f621756beb8e374600294edf8c4043c5336cb481296892712fd1fcbc33a0c28b")
SOURCE_MANIFEST = "a4ccc7009cc86f05885ca6e395a25603b465688c95954f87cd36e3f151e41f97"

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
    wanted_zip = {"evidence.tar.gz", "FILES.json", "ARCHIVE.json"}
    with zipfile.ZipFile(archive) as z:
        infos = z.infolist()
        require(len(infos) == len(wanted_zip) and {p.filename for p in infos} == wanted_zip, "complete ZIP member set changed")
        for item in infos:
            safe(item.filename)
            require(not item.is_dir() and not stat.S_ISLNK(item.external_attr >> 16), "ZIP member type changed")
            with z.open(item) as incoming, (root / item.filename).open("xb") as output:
                shutil.copyfileobj(incoming, output, 1024 * 1024)
    require(pin(root / "evidence.tar.gz") == TAR_PIN, "complete inner TAR bytes differ")
    index = decode((root / "FILES.json").read_bytes())
    receipt = decode((root / "ARCHIVE.json").read_bytes())
    rows = {r["path"]: r for r in index["files"]}
    require(len(rows) == len(index["files"]) == 16773 and sum(r["bytes"] for r in rows.values()) == 1635039123,
        "complete retained file count or byte total changed")
    require(receipt == dict(status="COMPLETE_ARCHIVE_BYTES_PASS", files=16773, logical_bytes=1635039123, archive=TAR_PIN),
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
        require(hashlib.sha256((source / "SOURCE_MANIFEST.json").read_bytes()).hexdigest() == SOURCE_MANIFEST,
            "frozen typed proof source manifest changed")
        rows = decode((source / "SOURCE_MANIFEST.json").read_bytes())["files"]
        actual = {p.relative_to(source).as_posix() for p in source.rglob("*") if p.is_file()}
        require(actual == {r["path"] for r in rows} | {"SOURCE_MANIFEST.json"}, "source closure changed")
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
    for name in ("scripts/run_ci.py", "scripts/readonly.py", "scripts/common.py", "scripts/read_params.py", "scripts/reader_controls.py", "scripts/registry_evidence.py", "SOURCE_MANIFEST.json"):
        shutil.copyfile(source / name, out / ("frozen-" + name.replace("/", "_")))
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
    result = dict(status="INDEPENDENT_CURRENT_TEXT_PUBLISHER_TYPED_READBACK_PASS",
        artifact=ARTIFACT, run=RUN, original_zip=ZIP_PIN, original_tar=TAR_PIN, files=16773, logical_bytes=1635039123,
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
    sys.path.insert(0, str(source / "scripts"))
    import run_ci
    import read_params
    import registry_evidence
    import params_cases
    import reader_controls
    from readonly import guarded
    capture = extracted / "capture"
    controls = extracted / "capture-reader-controls"
    def complete_read():
        result = run_ci.read_all(source, capture)
        result["physical_controls"] = reader_controls.verify(source, capture, controls)
        return result
    def expired(signum, frame):
        raise TimeoutError("independent frozen reader exceeded 180 seconds")
    signal.signal(signal.SIGALRM, expired)
    started = time.monotonic_ns()
    signal.alarm(180)
    try:
        proof = guarded(complete_read, roots=[output / "retained", source])
    finally:
        signal.alarm(0)
    elapsed = time.monotonic_ns() - started
    require(pin(archive) == ZIP_PIN and pin(output / "retained/evidence.tar.gz") == TAR_PIN, "source artifacts changed during reread")
    require(proof["evidence"]["status"] == "COMPLETE_TYPED_COMPARISON_PASS"
        and proof["evidence"]["native"]["cases"] == 259
        and len(proof["evidence"]["physical_controls"]["controls"]) == 6,
        "complete typed proof scope changed")
    report = dict(schema="hepta.runtime.text-publisher-typed-independent-readback.v1",
        original_artifact_metadata=metadata, guarded=proof, source_rows=source_rows, elapsed_ns=elapsed,
        limit_seconds=180, native_executed=False, rust_executed=False, original_evidence_written=False)
    save_proof(output / "proof", report, index, receipt, source)

if __name__ == "__main__":
    main()
