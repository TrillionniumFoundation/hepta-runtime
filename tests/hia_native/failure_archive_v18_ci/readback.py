#!/usr/bin/env python3
"""Read every byte of fixed failed CI archives without executing retained code."""
from __future__ import annotations
import argparse, gzip, hashlib, json, os
from pathlib import Path, PurePosixPath
import tarfile, urllib.error, urllib.parse, urllib.request, zipfile

REPOSITORY = "TrillionniumFoundation/hepta-runtime"
RUN = 43807112557
HEAD = "915d199a04cd6260051dcccb8fdf36307a5a0fde"
INPUTS = {
    "bytes": {"id": 14202255509, "bytes": 1328078322,
              "sha256": "672c07da6d1c5e85d59c6d5bd72ed1c45807d864016c4ef0abce789067472f77"},
}
CHUNK = 1 << 20

def need(ok, message):
    if not ok: raise ValueError(message)

def encoded(value):
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2,
                       allow_nan=False) + "\n").encode()

def pin(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}

def saved(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream: stream.write(raw)

def safe(name):
    path = PurePosixPath(name)
    need(name and not path.is_absolute() and "\\" not in name and "\0" not in name
         and all(part not in ("..", "") for part in path.parts), "unsafe retained path")
    return path

class HashReader:
    def __init__(self, source):
        self.source, self.size, self.digest = source, 0, hashlib.sha256()
    def read(self, size=-1):
        raw = self.source.read(size)
        self.size += len(raw); self.digest.update(raw)
        return raw
    def record(self):
        return {"bytes": self.size, "sha256": self.digest.hexdigest()}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--kind", choices=tuple(INPUTS), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    expected = INPUTS[args.kind]
    output = args.output.absolute()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    token = os.environ.pop("GH_TOKEN")
    headers = {"Authorization": "Bearer " + token, "Accept": "application/vnd.github+json",
               "X-GitHub-Api-Version": "2022-11-28"}
    base = "https://api.github.com/repos/" + REPOSITORY + "/actions/artifacts/" + str(expected["id"])
    with urllib.request.urlopen(urllib.request.Request(base, headers=headers), timeout=60) as response:
        metadata_raw = response.read()
    metadata = json.loads(metadata_raw)
    need(metadata["id"] == expected["id"] and not metadata["expired"], "artifact identity differs")
    need(metadata["size_in_bytes"] == expected["bytes"]
         and metadata["digest"] == "sha256:" + expected["sha256"], "artifact transport identity differs")
    need(metadata["workflow_run"]["id"] == RUN and metadata["workflow_run"]["head_sha"] == HEAD,
         "artifact origin differs")
    saved(output / "artifact-api.json", metadata_raw)
    archive_path = output.parent / (args.kind + "-retained.zip")
    digest, size = hashlib.sha256(), 0
    class RedirectLocation(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, request, response, code, message, response_headers, new_url):
            return None
    try:
        urllib.request.build_opener(RedirectLocation).open(
            urllib.request.Request(base + "/zip", headers=headers), timeout=60)
    except urllib.error.HTTPError as redirect:
        need(redirect.code == 302, "expected artifact download redirect")
        download_url = redirect.headers["Location"]
        need(urllib.parse.urlsplit(download_url).scheme == "https", "artifact redirect must use HTTPS")
    else:
        raise ValueError("artifact API did not provide a download redirect")
    del headers, token
    with urllib.request.urlopen(download_url, timeout=60) as response, archive_path.open("xb") as writer:
        for raw in iter(lambda: response.read(CHUNK), b""):
            writer.write(raw); digest.update(raw); size += len(raw)
    need({"bytes": size, "sha256": digest.hexdigest()} == {k: expected[k] for k in ("bytes", "sha256")},
         "complete ZIP differs")
    with zipfile.ZipFile(archive_path) as archive:
        infos = archive.infolist()
        names = [row.filename for row in infos]
        need(len(names) == len(set(names)), "duplicate ZIP member")
        need("manifest.json" in names and "failure-evidence.tar" in names, "failure archive layout differs")
        outer = {}
        for row in infos:
            safe(row.filename)
            need(not row.is_dir(), "undeclared ZIP directory")
            if row.filename == "failure-evidence.tar": continue
            raw = archive.read(row)
            outer[row.filename] = pin(raw)
            saved(output / "outer" / row.filename, raw)
        manifest = json.loads((output / "outer/manifest.json").read_bytes())
        need(manifest["schema"] == "hepta.runtime.native-failure-evidence.v1"
             and manifest["status"] == "COMPLETE"
             and manifest["diagnostics_complete"] is True
             and manifest["original_failure_reclassified_as_pass"] is False, "failed evidence is incomplete or relabeled")
        for name, row in manifest["diagnostics"].items():
            need(row["complete"] is True and outer[row["destination"]] == row["copy"],
                 "complete diagnostic pin differs: " + name)
        receipt = json.loads((output / "outer/tar.process.json").read_bytes())
        need(receipt == manifest["archive"] and receipt["complete"] is True
             and receipt["exit_code"] == 0 and receipt["timed_out"] is False
             and receipt["source_links_dereferenced"] is False
             and receipt["fixture_permissions_changed"] is False, "archive custody differs")
        for channel in ("stdout", "stderr"):
            want = dict(receipt[channel]); name = want.pop("path")
            need(outer[name] == want, "tar stream differs")
        members, seen, nonregular, logical_bytes = [], set(), [], 0
        selected = {}
        with archive.open("failure-evidence.tar") as packed:
            stream = HashReader(packed)
            with tarfile.open(fileobj=stream, mode="r|") as retained:
                for member in retained:
                    name = member.name
                    safe(name)
                    normalized = str(PurePosixPath(name))
                    need(normalized not in seen, "duplicate tar member")
                    seen.add(normalized)
                    record = {"path": normalized, "size": member.size, "mode": member.mode,
                              "uid": member.uid, "gid": member.gid, "mtime": member.mtime,
                              "type": member.type.decode("ascii"), "linkname": member.linkname,
                              "pax_headers": member.pax_headers}
                    if member.isfile():
                        hashed, length = hashlib.sha256(), 0
                        capture = normalized in ("result.json", "rust-comparison-failure.txt")
                        pieces = [] if capture else None
                        with retained.extractfile(member) as reader:
                            for raw in iter(lambda: reader.read(CHUNK), b""):
                                hashed.update(raw); length += len(raw)
                                if capture: pieces.append(raw)
                        need(length == member.size, "truncated tar file: " + normalized)
                        record["sha256"] = hashed.hexdigest()
                        logical_bytes += length
                        if capture:
                            raw = b"".join(pieces)
                            saved(output / "selected" / normalized, raw)
                            selected[normalized] = pin(raw)
                    elif not member.isdir():
                        nonregular.append(record.copy())
                    members.append(record)
            for raw in iter(lambda: stream.read(CHUNK), b""): pass
            want = dict(receipt["archive"]); want.pop("path")
            need(stream.record() == want, "complete tar digest differs")
        need(len(members) == receipt["tar_members"], "tar member count differs")
        need(sum(row["type"] == "2" for row in members) == receipt["symlink_members"], "symlink count differs")
        need(sum(row["type"] == "6" for row in members) == receipt["fifo_members"], "FIFO count differs")
    saved(output / "complete-member-inventory.json.gz", gzip.compress(encoded(members), mtime=0))
    saved(output / "nonregular-members.json", encoded(nonregular))
    report = json.loads((output / "outer/diagnostics/result.json").read_bytes())
    need(report["status"] == "FAIL" and report["rust_comparison_status"] == "FAIL",
         "original failed report was relabeled")
    need(pin((output / "selected/result.json").read_bytes()) == outer["diagnostics/result.json"],
         "archived result differs from separately retained diagnostic")
    summary = {"schema": "hepta.runtime.failed-archive-full-readback.v1",
               "status": "READBACK_COMPLETE", "kind": args.kind, "original_status": "FAIL",
               "artifact": expected, "run": RUN, "head": HEAD,
               "archive": receipt["archive"], "members": len(members),
               "regular_files": sum(row["type"] in ("0", "\0", "7", "S") for row in members),
               "regular_bytes": logical_bytes, "nonregular_members": len(nonregular),
               "nonregular": nonregular, "outer_files": outer, "selected": selected,
               "error": report.get("error"), "completed_original_recipes": sorted(report.get("original_rust_comparisons", {})),
               "rust_recipe_processes": report.get("rust_recipe_processes", {}),
               "native_processes": 0, "rust_processes": 0,
               "original_failure_reclassified_as_pass": False,
               "production_activated": False, "whole_runtime_replaced": False,
               "old_stack_removal_qualified": False}
    saved(output / "readback.json", encoded(summary))
    print(json.dumps({key: value for key, value in summary.items()
                      if key not in ("outer_files", "nonregular", "rust_recipe_processes")}, sort_keys=True))
    print("HIA_RETAINED_SPECIAL " + json.dumps(nonregular, ensure_ascii=True, sort_keys=True))
    return 0
if __name__ == "__main__": raise SystemExit(main())

