"""Complete compiler source and actual child receipt custody; read-only admission."""
from __future__ import annotations
import hashlib,json
from pathlib import Path
from worker_common import COMPILER_COMMIT,COMPILER_TREE,document,encoded,read,require,safe_relative,sha,tree_files

def git_tree(raw):
    result = {}
    at = 0
    while at < len(raw):
        space, zero = raw.index(b" ", at), raw.index(b"\0", at)
        require(space < zero and zero + 21 <= len(raw), "Git tree framing")
        name, mode = raw[space + 1:zero].decode(), raw[at:space].decode()
        require(name not in result and name not in (".", "..") and "/" not in name, "Git tree name")
        result[name] = (mode, raw[zero + 1:zero + 21].hex())
        at = zero + 21
    require(at == len(raw), "Git tree complete extent")
    return result

def compiler_sources(capture, dependency):
    proof = document(capture / "compiler-source.json")
    require(proof["commit"] == COMPILER_COMMIT and proof["tree"] == COMPILER_TREE, "compiler source identity")
    require(dependency == {"commit": COMPILER_COMMIT, "tree": COMPILER_TREE,
                           "files": {name: row["sha256"] for name, row in proof["files"].items()}}, "compiler source dependency closure")
    objects = {}

    def obj(kind, oid):
        key = kind + ":" + oid
        if key not in objects:
            raw = read(capture / "compiler-git" / (oid + "." + kind))
            require(hashlib.sha1(kind.encode() + b" " + str(len(raw)).encode() + b"\0" + raw).hexdigest() == oid,
                    "compiler immutable Git object changed")
            objects[key] = raw
        return objects[key]

    require(obj("commit", COMPILER_COMMIT).startswith(b"tree " + COMPILER_TREE.encode() + b"\n"), "compiler root tree differs")
    for name, row in proof["files"].items():
        parts = safe_relative(name).split("/")
        oid = COMPILER_TREE
        for component in parts[:-1]:
            mode, oid = git_tree(obj("tree", oid))[component]
            require(mode == "40000", "compiler ancestor is not a tree")
        mode, blob = git_tree(obj("tree", oid))[parts[-1]]
        require(mode == row["git_mode"] and blob == row["git_blob"] and mode in ("100644", "100755"), "compiler Git source binding")
        path = capture / "compiler-source" / name
        raw = read(path)
        require(len(raw) == row["bytes"] and sha(raw) == row["sha256"], "compiler complete source changed")
        require(hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest() == blob, "compiler original source blob changed")
        require(bool(path.stat().st_mode & 0o111) == (mode == "100755"), "compiler source executable mode changed")
    require(sorted(objects) == proof["git_objects"], "compiler Git source object coverage")
    require(set(tree_files(capture / "compiler-source")) == set(proof["files"]), "compiler source file set")
    contract = document(capture / "compiler-source/docs/HIA_SELFHOST_CORE_SUPPORT.json")
    for name, digest in contract["source_identity"]["files"].items():
        require(dependency["files"].get(name) == digest, "compiler cold source identity differs")
    return proof

def compile_receipt(capture, folder, label, compiler, source, output_name, image_format):
    directory = capture / folder
    record = document(directory / (label + ".receipt.json"))
    request = document(directory / (label + ".request.json"))
    input_raw = read(directory / (label + ".input.bin"))
    output = read(directory / (label + ".output.bin"))
    produced = read(directory / output_name)
    require(input_raw == source and request["source_sha256"] == sha(source), "compiler complete input differs")
    require(request["image_sha256"] == sha(compiler) and request["format"] == image_format, "compiler actual image binding")
    require(request["capacity"] == (1 << 20) and request["workspace_size"] == (1 << 20) and request["workspace_fill"] == 0,
            "compiler borrowed-buffer domain changed")
    require(Path(request["source"]).name == label + ".input.bin" and Path(request["output"]).name == label + ".output.bin", "compiler retained stream association")
    require(record["status"] == "returned" and type(record["abi_status"]) is int and record["abi_status"] == 0,
            "native compiler did not return successfully")
    require(type(record["core_u32"]) is int and record["core_u32"] == len(produced) and 0 < len(produced) <= (1 << 20), "compiled image extent")
    require(record["source_unchanged"] is True and record["forbidden_compiler_modules_loaded"] == [], "compiler source custody or fallback")
    require(record["input_sha256"] == sha(source) and record["input_bytes"] == len(source) and
            record["artifact_sha256"] == sha(compiler) and record["format"] == image_format, "compiler actual invocation source identity")
    require(record["produced_sha256"] == sha(produced) and record["produced_bytes"] == len(produced) and
            output[:len(produced)] == produced and record["output_sha256"] == sha(output) and len(output) == (1 << 20), "compiler complete output custody")
    require(record["result_u64"] == len(produced), "compiler full return value")
    runner = read(capture / "compiler-source/tools/hia_selfhost_child.py")
    require(record["runner_sha256"] == sha(runner), "compiler child source changed")
    actual = json.loads(read(directory / (label + ".stdout.log")))
    fields = {'abi_status','core_u32','forbidden_compiler_modules_loaded','image_sha256','limits','loader_operations',
              'native_elapsed_ns','output_sha256','output_unchanged','result_u64','return_encoding','source_sha256',
              'source_unchanged','status','workspace_header'}
    require(type(actual) is dict and set(actual) == fields and all(type(record.get(key)) is type(value) and
            record.get(key) == value for key, value in actual.items()), "compiler actual child stdout differs")
    require(read(directory / (label + ".stderr.log")) == b"", "compiler child emitted an unexpected error")
    return record
