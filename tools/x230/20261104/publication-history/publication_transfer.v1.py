#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Byte-exact publication indices and <=60000-character base64 transfer pieces.

This helper has no network client and never publishes to GitHub. Remote indexing
reads only named archive receipts and explicitly fingerprinted extra files.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import tempfile

from package_x230_evidence import directory_fd, source_file, parts, need, encoded, digest, identity

SCHEMA = "hepta-x230-publication-transfer/v1"


def hashes(path):
    path = Path(path).absolute()
    with source_file(str(path.parent), path.name) as (stream, before):
        sha, git = hashlib.sha256(), hashlib.sha1(f"blob {before['size']}\0".encode(), usedforsecurity=False)
        count = 0
        while block := stream.read(1024 * 1024):
            count += len(block)
            sha.update(block)
            git.update(block)
        need(count == before["size"] and before == identity(os.fstat(stream.fileno())), "indexed file changed")
    return {"bytes": count, "sha256": sha.hexdigest(), "git_blob_sha1": git.hexdigest()}


def write_new(path, raw):
    path = Path(path).absolute()
    with directory_fd(str(path.parent), create=True) as directory:
        fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=directory)
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())


def remote_index(receipts, extras, local_stage, output):
    entries = {}
    for name in receipts:
        receipt_path = Path(name).absolute()
        receipt = json.loads(receipt_path.read_bytes())
        need(receipt["verified"] is True, "unverified archive receipt")
        for filename in [receipt["archive"], receipt["manifest"], receipt_path.name]:
            parts(filename)
            need("/" not in filename, "receipt output must be a basename")
            path = receipt_path.parent / filename
            repo = receipt["repo_dir"] + "/" + filename
            parts(repo)
            values = hashes(path)
            if filename == receipt["archive"]:
                need(values["sha256"] == receipt["archive_sha256"] and values["bytes"] == receipt["archive_bytes"],
                     "archive receipt no longer matches")
            elif filename == receipt["manifest"]:
                need(values["sha256"] == receipt["manifest_sha256"], "manifest receipt no longer matches")
            entries[repo] = {"repo_path": repo, "absolute_remote_path": str(path),
                             "planned_local_path": str(Path(local_stage) / repo), **values}
    if extras:
        for item in json.loads(Path(extras).read_bytes())["files"]:
            repo = item["repo_path"]
            parts(repo)
            need(repo not in entries, "duplicate extra repo path")
            path = Path(item["absolute_remote_path"]).absolute()
            values = hashes(path)
            need(values["sha256"] == item["sha256"], "explicit extra file identity differs")
            entries[repo] = {"repo_path": repo, "absolute_remote_path": str(path),
                             "planned_local_path": str(Path(local_stage) / repo), **values}
    result = {"schema": SCHEMA, "files": [entries[k] for k in sorted(entries)],
              "local_files_verified": False, "network_requests": 0}
    write_new(output, encoded(result))
    return {"index": str(output), "files": len(entries), "sha256": digest(encoded(result)),
            "total_bytes": sum(e["bytes"] for e in entries.values())}


def chunks(index_path, pieces_dir, output):
    index_raw = Path(index_path).read_bytes()
    index = json.loads(index_raw)
    need(index["schema"] == SCHEMA, "transfer index schema differs")
    pieces = Path(pieces_dir).absolute()
    need(not pieces.exists() and not pieces.is_symlink(), "transfer-piece directory must be new")
    with directory_fd(str(pieces), create=True):
        pass
    result = {"schema": SCHEMA, "source_index_sha256": digest(index_raw), "files": [],
              "maximum_base64_characters": 60000, "raw_piece_bytes": 45000}
    for number, entry in enumerate(index["files"]):
        path = Path(entry["absolute_remote_path"])
        item = {**entry, "pieces": []}
        sha, git = hashlib.sha256(), hashlib.sha1(f"blob {entry['bytes']}\0".encode(), usedforsecurity=False)
        offset = 0
        with source_file(str(path.parent), path.name) as (stream, before):
            while block := stream.read(45000):
                text = base64.b64encode(block)
                need(len(text) <= 60000, "base64 piece exceeds transport bound")
                relative = f"file-{number:04d}/part-{len(item['pieces']):05d}.b64"
                target = pieces / relative
                write_new(target, text)  # No extra newline: exact maximum is 60000 characters.
                item["pieces"].append({"relative_path": relative, "absolute_remote_path": str(target),
                                      "offset": offset, "bytes": len(block), "sha256": digest(block),
                                      "base64_bytes": len(text), "base64_sha256": digest(text)})
                offset += len(block)
                sha.update(block)
                git.update(block)
            need(before == identity(os.fstat(stream.fileno())), "source changed while splitting")
        need(offset == entry["bytes"] and sha.hexdigest() == entry["sha256"]
             and git.hexdigest() == entry["git_blob_sha1"], "split source no longer matches transfer index")
        result["files"].append(item)
    write_new(output, encoded(result))
    return {"manifest": str(output), "sha256": digest(encoded(result)), "files": len(result["files"]),
            "pieces": sum(len(e["pieces"]) for e in result["files"])}


def assemble(manifest_path, pieces_dir, stage_root, output):
    manifest = json.loads(Path(manifest_path).read_bytes())
    need(manifest["schema"] == SCHEMA, "transfer schema differs")
    stage = Path(stage_root).absolute()
    result = {"schema": SCHEMA, "files": [], "local_files_verified": True}
    for entry in manifest["files"]:
        parts(entry["repo_path"])
        target = stage / entry["repo_path"]
        with directory_fd(str(target.parent), create=True):
            pass
        if target.exists() or target.is_symlink():
            need(hashes(target) == {k: entry[k] for k in ["bytes", "sha256", "git_blob_sha1"]},
                 "existing staged file differs; refusing overwrite")
        else:
            fd, temporary = tempfile.mkstemp(prefix=".transfer-", dir=target.parent)
            try:
                offset = 0
                with os.fdopen(fd, "wb") as stream:
                    for piece in entry["pieces"]:
                        parts(piece["relative_path"])
                        local = Path(pieces_dir).absolute() / piece["relative_path"]
                        with source_file(str(local.parent), local.name) as (encoded_stream, _):
                            text = encoded_stream.read(60001)
                        need(len(text) == piece["base64_bytes"] <= 60000
                             and digest(text) == piece["base64_sha256"], "base64 piece changed")
                        raw = base64.b64decode(text, validate=True)
                        need(offset == piece["offset"] and len(raw) == piece["bytes"]
                             and digest(raw) == piece["sha256"], "piece content/order differs")
                        stream.write(raw)
                        offset += len(raw)
                    stream.flush()
                    os.fsync(stream.fileno())
                need(hashes(temporary) == {k: entry[k] for k in ["bytes", "sha256", "git_blob_sha1"]},
                     "reassembled file identity differs")
                os.link(temporary, target, follow_symlinks=False)
            finally:
                Path(temporary).unlink(missing_ok=True)
        values = hashes(target)
        result["files"].append({"repo_path": entry["repo_path"], "absolute_local_path": str(target),
                                "absolute_remote_path": entry["absolute_remote_path"], **values})
    write_new(output, encoded(result))
    return {"manifest": str(output), "sha256": digest(encoded(result)), "files": len(result["files"])}


def local_index(remote_index_path, stage_root, add_files, add_dirs, output):
    remote = json.loads(Path(remote_index_path).read_bytes())
    stage = Path(stage_root).absolute()
    entries = {}
    for item in remote["files"]:
        repo = item["repo_path"]
        parts(repo)
        path = stage / repo
        actual = hashes(path)
        need(actual == {k: item[k] for k in ["bytes", "sha256", "git_blob_sha1"]}, "staged file differs from remote index")
        entries[repo] = {"repo_path": repo, "absolute_local_path": str(path),
                         "absolute_remote_path": item["absolute_remote_path"], **actual}
    additions = list(add_files)
    for directory in add_dirs:
        parts(directory)
        path = stage / directory
        with directory_fd(str(path)) as fd:
            for name in sorted(os.listdir(fd)):
                parts(name)
                need("/" not in name, "unsafe local evidence name")
                # Only this explicitly named directory's immediate regular files.
                additions.append(directory + "/" + name)
    for repo in additions:
        parts(repo)
        need(repo not in entries, "local addition duplicates a remote-index path")
        path = stage / repo
        entries[repo] = {"repo_path": repo, "absolute_local_path": str(path),
                         "absolute_remote_path": None, "origin": "local publication evidence; original paths retained in its own manifest",
                         **hashes(path)}
    result = {"schema": SCHEMA, "files": [entries[k] for k in sorted(entries)], "local_files_verified": True}
    write_new(output, encoded(result))
    return {"manifest": str(output), "sha256": digest(encoded(result)), "files": len(entries)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    index = sub.add_parser("remote-index")
    index.add_argument("--receipts", nargs="+", required=True)
    index.add_argument("--extras")
    index.add_argument("--local-stage", required=True)
    index.add_argument("--output", required=True)
    split = sub.add_parser("chunks")
    split.add_argument("--index", required=True)
    split.add_argument("--pieces-dir", required=True)
    split.add_argument("--output", required=True)
    restore = sub.add_parser("assemble")
    restore.add_argument("--manifest", required=True)
    restore.add_argument("--pieces-dir", required=True)
    restore.add_argument("--stage-root", required=True)
    restore.add_argument("--output", required=True)
    final = sub.add_parser("local-index")
    final.add_argument("--remote-index", required=True)
    final.add_argument("--stage-root", required=True)
    final.add_argument("--add-file", action="append", default=[])
    final.add_argument("--add-dir", action="append", default=[])
    final.add_argument("--output", required=True)
    args = parser.parse_args()
    if args.command == "remote-index":
        result = remote_index(args.receipts, args.extras, args.local_stage, args.output)
    elif args.command == "chunks":
        result = chunks(args.index, args.pieces_dir, args.output)
    elif args.command == "assemble":
        result = assemble(args.manifest, args.pieces_dir, args.stage_root, args.output)
    else:
        result = local_index(args.remote_index, args.stage_root, args.add_file, args.add_dir, args.output)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
