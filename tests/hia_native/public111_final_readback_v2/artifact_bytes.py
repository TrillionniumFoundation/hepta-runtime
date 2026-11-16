"""Download and fully verify frozen GitHub artifact ZIP and complete capture TAR."""
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


from pathlib import Path, PurePosixPath
import hashlib, json, os, shutil, stat, tarfile, urllib.error, urllib.parse, urllib.request, zipfile

REPOSITORY = "TrillionniumFoundation/hepta-runtime"
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None

def require(ok, message):
    if not ok:
        raise ValueError(message)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def pin(path):
    with Path(path).open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    return {"bytes": Path(path).stat().st_size, "sha256": digest}

def save(path, value):
    with Path(path).open("x", encoding="utf-8") as stream:
        json.dump(value, stream, sort_keys=True, indent=2, allow_nan=False)
        stream.write("\n")

def safe(name):
    require(type(name) is str and name, "empty archive path")
    path = PurePosixPath(name)
    require(not path.is_absolute() and path.as_posix() == name
            and all(part not in ("", ".", "..") for part in path.parts), "noncanonical archive path")
    return name

def download(spec, out):
    require(not out.exists(), "artifact destination already exists")
    out.mkdir(parents=True)
    url = f"https://api.github.com/repos/{REPOSITORY}/actions/artifacts/{spec['id']}"
    headers = {"Authorization": "Bearer " + os.environ["GH_TOKEN"],
               "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=60) as response:
        metadata = json.load(response)
    require(metadata["id"] == spec["id"] and metadata["name"] == spec["name"]
            and metadata["size_in_bytes"] == spec["bytes"]
            and metadata["digest"] == "sha256:" + spec["sha256"]
            and metadata["expired"] is False, "complete artifact API identity")
    require(metadata["workflow_run"]["id"] == spec["run_id"]
            and metadata["workflow_run"]["head_sha"] == spec["head"], "artifact producer identity")
    try:
        response = urllib.request.build_opener(NoRedirect).open(
            urllib.request.Request(url + "/zip", headers=headers), timeout=60)
    except urllib.error.HTTPError as error:
        require(error.code in (301, 302, 303, 307, 308), "artifact download response")
        location = error.headers["Location"]
        target = urllib.parse.urlsplit(location)
        require(target.scheme == "https" and target.hostname and target.username is None
                and target.password is None, "invalid artifact redirect")
        response = urllib.request.urlopen(urllib.request.Request(location), timeout=60)
    destination = out / "artifact.zip"
    with response, destination.open("xb") as stream:
        shutil.copyfileobj(response, stream, 1 << 20)
    require(pin(destination) == {key: spec[key] for key in ("bytes", "sha256")}, "whole ZIP identity")
    save(out / "API.json", metadata)
    return destination

def extract_capture(spec, out):
    archive = download(spec, out)
    with zipfile.ZipFile(archive) as zipped:
        require(len(zipped.infolist()) == 2 and set(zipped.namelist()) == {"archive.json", "capture.tar.gz"}
                and zipped.testzip() is None, "complete ZIP members and CRC")
        for name in zipped.namelist():
            with zipped.open(name) as source, (out / name).open("xb") as destination:
                shutil.copyfileobj(source, destination, 1 << 20)
    receipt = json.loads((out / "archive.json").read_bytes())
    require(receipt["schema"] == "hepta.runtime.complete-ci-archive-receipt.v1"
            and receipt["label"] == spec["label"] and receipt["git_head"] == spec["head"]
            and receipt["run_id"] == str(spec["run_id"]) and receipt["run_attempt"] == spec["attempt"]
            and receipt["source_manifest_sha256"] == spec["source_manifest_sha256"]
            and receipt["qualification_inferred_from_archive"] is False
            and receipt["captured_tree_modified_by_export"] is False, "archive producer declaration")
    require(pin(out / "capture.tar.gz") == receipt["archive"], "whole inner TAR identity")
    root = out / "capture"
    root.mkdir()
    seen, expected, manifest = set(), None, None
    with tarfile.open(out / "capture.tar.gz", "r:gz") as tar:
        for member in tar:
            require(member.name.startswith("capture/") and member.isfile()
                    and not member.islnk() and not member.issym(), "archive object type")
            name = safe(member.name.removeprefix("capture/"))
            require(name not in seen, "duplicate TAR member")
            source = tar.extractfile(member)
            require(source is not None, "missing member stream")
            if not seen:
                require(name == "artifact-manifest.json" and member.mode == 0o600, "first complete inventory")
                with source:
                    raw = source.read()
                require(member.size == len(raw)
                        and {"bytes": len(raw), "sha256": sha(raw)} == receipt["manifest"],
                        "complete inventory identity")
                manifest = json.loads(raw)
                require(manifest["schema"] == "hepta.runtime.complete-ci-archive.v2"
                        and manifest["label"] == spec["label"]
                        and manifest["source_manifest_sha256"] == spec["source_manifest_sha256"]
                        and manifest["qualification_inferred_from_archive"] is False, "inventory provenance")
                expected = dict(manifest["files"])
                for relative, row in expected.items():
                    safe(relative)
                    require(set(row) == {"bytes", "sha256", "mode"} and type(row["bytes"]) is int
                            and row["bytes"] >= 0 and type(row["mode"]) is int
                            and 0 <= row["mode"] <= 0o777, "inventory row")
                require(name not in expected, "inventory self-reference")
                expected[name] = {**receipt["manifest"], "mode": 0o600}
                with (root / name).open("xb") as destination:
                    destination.write(raw)
                os.chmod(root / name, 0o600)
            else:
                require(expected is not None and name in expected, "unclaimed member")
                row = expected[name]
                require(member.size == row["bytes"] and member.mode == row["mode"], "member mode and extent")
                destination = root / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                with source, destination.open("xb") as target:
                    shutil.copyfileobj(source, target, 1 << 20)
                require(pin(destination) == {key: row[key] for key in ("bytes", "sha256")}, "full member bytes")
                os.chmod(destination, row["mode"])
            seen.add(name)
    require(expected is not None and seen == set(expected), "complete TAR member set")
    require(receipt["readback"] == {"files": len(expected),
            "logical_bytes": sum(row["bytes"] for row in expected.values())}, "complete archive count")
    for name, mode in manifest["directories"].items():
        safe(name)
        require(type(mode) is int and 0 <= mode <= 0o777, "directory mode")
        (root / name).mkdir(parents=True, exist_ok=True)
    require({path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_dir()}
            == set(manifest["directories"]), "complete directory set")
    for name, mode in sorted(manifest["directories"].items(),
                             key=lambda row: len(Path(row[0]).parts), reverse=True):
        os.chmod(root / name, mode)
    declaration = json.loads((root / "CI_SOURCE_DECLARATION.json").read_bytes())
    require(declaration["manifest_sha256"] == spec["source_manifest_sha256"]
            and declaration["git_head"] == spec["head"] and declaration["run_id"] == str(spec["run_id"])
            and declaration["run_attempt"] == spec["attempt"] and declaration["label"] == spec["label"]
            and declaration["archive_is_qualification"] is False
            and declaration["captured_tree_modified_by_export"] is False, "complete source declaration")
    package = root / "ci-package"
    raw = (package / "PACKAGE.json").read_bytes()
    require(sha(raw) == spec["source_manifest_sha256"], "source package manifest")
    rows = json.loads(raw)["files"]
    require({path.relative_to(package).as_posix() for path in package.rglob("*") if path.is_file()}
            == set(rows) | {"PACKAGE.json"}, "complete source package file set")
    for name, row in rows.items():
        safe(name)
        content = (package / name).read_bytes()
        identity = {"bytes": len(content), "sha256": sha(content),
                    "git_blob": hashlib.sha1(b"blob " + str(len(content)).encode() + b"\0" + content).hexdigest(),
                    "mode": "100755" if (package / name).stat().st_mode & 0o111 else "100644"}
        require(identity == row, "source Git/SHA/mode identity: " + name)
    summary = {"artifact": spec, "archive": receipt["archive"], "manifest": receipt["manifest"],
               "members": len(expected), "logical_bytes": receipt["readback"]["logical_bytes"],
               "directories": len(manifest["directories"]), "source_files": len(rows) + 1,
               "complete_bytes_and_modes_read": True, "semantic_qualification_inferred": False}
    save(out / "EXTRACTION.json", summary)
    return root, summary
