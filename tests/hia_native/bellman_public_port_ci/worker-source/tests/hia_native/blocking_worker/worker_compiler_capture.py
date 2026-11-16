"""Capture immutable compiler Git objects after the actual HIA build."""
from __future__ import annotations
import hashlib,subprocess
from worker_common import COMPILER_COMMIT,COMPILER_TREE,put,read,require,sha

def git(root, *arguments):
    return subprocess.run(["git", "-C", str(root), *arguments], check=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30).stdout

def tree_entries(raw):
    entries = {}
    offset = 0
    while offset < len(raw):
        space = raw.index(b" ", offset)
        zero = raw.index(b"\0", space)
        mode = raw[offset:space].decode()
        name = raw[space + 1:zero].decode()
        oid = raw[zero + 1:zero + 21].hex()
        require(len(oid) == 40 and name not in entries, "Git tree record")
        entries[name] = (mode, oid)
        offset = zero + 21
    require(offset == len(raw), "Git tree extent")
    return entries

def compiler_custody(hepta, identity, capture):
    objects = {}

    def get_object(kind, oid):
        key = kind + ":" + oid
        if key not in objects:
            raw = git(hepta, "cat-file", kind, oid)
            actual = hashlib.sha1(kind.encode() + b" " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
            require(actual == oid, "Git compiler object identity")
            put(capture / "compiler-git" / (oid + "." + kind), raw)
            objects[key] = raw
        return objects[key]

    commit = get_object("commit", COMPILER_COMMIT)
    require(commit.startswith(b"tree " + COMPILER_TREE.encode() + b"\n"), "compiler commit tree")
    rows = {}
    for relative, digest in identity["files"].items():
        parts = relative.split("/")
        current = COMPILER_TREE
        for name in parts[:-1]:
            mode, current = tree_entries(get_object("tree", current))[name]
            require(mode == "40000", "compiler directory mode")
        mode, oid = tree_entries(get_object("tree", current))[parts[-1]]
        require(mode in ("100644", "100755"), "compiler input mode")
        raw = read(hepta / relative)
        require(sha(raw) == digest, "compiler input changed after fresh build")
        require(hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest() == oid, "compiler input Git blob")
        path = capture / "compiler-source" / relative
        put(path, raw)
        path.chmod(0o755 if mode == "100755" else 0o644)
        rows[relative] = {"bytes": len(raw), "sha256": digest, "git_blob": oid, "git_mode": mode}
    put(capture / "compiler-source.json", {"commit": COMPILER_COMMIT, "tree": COMPILER_TREE,
        "files": rows, "git_objects": sorted(objects)})
