#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Source-only actual Git sparse checkout and historical materialization proof."""
from __future__ import annotations
from pathlib import Path
import argparse
import ast
import hashlib
import importlib.util
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
BASE = "208ff61db1da78aadfeb8d7913af7ddf4b59d461"
HEAD = "c5cbd4d26f2b5ce074b78d77359d903a434139f1"
TREE = "8e2df796b3295673d2c6f58d4ae3c0402e19ea03"
PROFILE = "817652c6f11fed3035ea902fc54cedb16f931876"
MATERIALIZER = "c24d5798eedca8177cb3189ce7a7bd14e2b1e2b7"
FOLDER = Path("tests/hia_native/historical_public58")
CHANGED = {"hia-runtime-native.yml": 4, "hia-runtime-original-shard.yml": 1,
           "hia-local-text-body-native.yml": 1, "hia-runtime-shell.yml": 1}
FIXES = {"scripts/hia_native_shell_process_reference.py": "048ed71646399e92e4f8bcc465cf09043ccc53e3",
         "scripts/compare_hia_runtime_rust.py": "178b411e1fc15d21240d2588f62ebc61f1dfba99",
         "tests/hia_native/test_qualification_reporting.py": "64587aa4bac8cffd8e9fbe2119a9e8fcf2f925be"}


def require(value, message):
    if not value: raise ValueError(message)


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
                git_blob=hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest())


def inventory(root):
    result = {}
    for path in sorted(root.rglob("*")):
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode), "non-ordinary source")
        if stat.S_ISREG(info.st_mode):
            result[path.relative_to(root).as_posix()] = dict(**pin(path.read_bytes()), mode=stat.S_IMODE(info.st_mode))
    return result


def load_materializer(source):
    path = source / FOLDER / "materialize.py"
    require(pin(path.read_bytes())["git_blob"] == MATERIALIZER, "materializer changed")
    require(pin((source / FOLDER / "PROFILE.json").read_bytes())["git_blob"] == PROFILE, "profile changed")
    spec = importlib.util.spec_from_file_location("_materializer_" + hashlib.sha256(str(source).encode()).hexdigest()[:12], path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def process(root, label, argv, *, data=b"", expected=0):
    require(argv[0] == "git" or argv[:3] == [sys.executable, "-I", "-B"], "source-only process allowlist")
    folder = root / "processes"; folder.mkdir(exist_ok=True)
    start = time.monotonic_ns()
    result = subprocess.run(argv, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    for suffix, raw in (("stdin", data), ("stdout", result.stdout), ("stderr", result.stderr)):
        (folder / (label + "." + suffix)).write_bytes(raw)
    receipt = dict(argv=argv, returncode=result.returncode, limit_seconds=60,
                   elapsed_ns=time.monotonic_ns()-start,
                   streams={suffix: pin(raw) for suffix, raw in (("stdin", data), ("stdout", result.stdout), ("stderr", result.stderr))})
    (folder / (label + ".json")).write_bytes(encode(receipt))
    require(result.returncode == expected, "source-only process failed: " + label)
    return result.stdout


def tree_rows(raw):
    rows = {}
    for record in raw.split(b"\0"):
        if not record: continue
        metadata, name = record.split(b"\t", 1)
        mode, kind, oid = metadata.decode().split()
        require(kind == "blob" and name.decode() not in rows, "unsupported/duplicate Git tree leaf")
        rows[name.decode()] = dict(mode=mode, sha=oid)
    return rows


def tree_hash(rows):
    root = {}
    for name, row in rows.items():
        here = root; parts = name.split("/")
        for part in parts[:-1]: here = here.setdefault(part, {})
        here[parts[-1]] = (row["mode"], row["sha"])
    def digest(folder):
        items = []
        for name, item in folder.items():
            if isinstance(item, dict):
                mode, oid, key = "40000", digest(item), name.encode()+b"/"
            else:
                mode, oid = item; key = name.encode()
            items.append((key, mode.encode()+b" "+name.encode()+b"\0"+bytes.fromhex(oid)))
        payload = b"".join(value for _, value in sorted(items))
        return hashlib.sha1(b"tree "+str(len(payload)).encode()+b"\0"+payload).hexdigest()
    return digest(root)


def checkout_specs(raw):
    lines = raw.splitlines(); result = []
    for i, line in enumerate(lines):
        if line != "          path: runtime": continue
        block = []
        for later in lines[i+1:]:
            if later.startswith("      - "): break
            block.append(later)
        if "          sparse-checkout: |" not in block:
            result.append(None); continue
        index = block.index("          sparse-checkout: |") + 1
        paths = []
        for value in block[index:]:
            if value.startswith("            "): paths.append(value[12:])
            elif value.strip(): break
        require(paths and len(paths) == len(set(paths)), "invalid sparse list")
        result.append(paths)
    return result


def check_workflows(before, after):
    require(set(before) == set(after) and len(before) == 21, "complete workflow set changed")
    audit, variants = [], []
    for name in sorted(before):
        old, new = before[name], after[name]
        if name in CHANGED:
            require(old.count("            authoring\n") == CHANGED[name], "old checkout count changed")
            require(new == old.replace("            authoring\n", "            authoring\n            runtime_support\n"), "unrelated workflow edit")
        else:
            require(old == new, "unrelated workflow changed")
        if "historical_public58/materialize.py" not in new: continue
        a, b = checkout_specs(old), checkout_specs(new)
        require(len(a) == len(b), "runtime checkout count changed")
        for index, (old_paths, new_paths) in enumerate(zip(a, b)):
            if old_paths is None:
                require(new_paths is None, "full checkout changed")
                audit.append(dict(workflow=name, checkout=index, full_checkout=True)); continue
            require("runtime_support" in new_paths, "historical materializer sparse checkout still omits packed sources")
            record = dict(workflow=name, checkout=index, before=old_paths, after=new_paths, full_checkout=False)
            audit.append(record)
            if not any(v["after"] == new_paths for v in variants): variants.append(record)
    require(len([r for r in audit if not r["full_checkout"]]) == 7 and len(variants) == 3, "sparse domain changed")
    return audit, variants


def copy_selected(module, source, output):
    output.mkdir(parents=True)
    for name, path in module.selected(source).items():
        target = output / name; target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)


def read(root):
    proof = json.loads((root / "proof.json").read_bytes())
    before = json.loads((root / "base-tree.json").read_bytes()); after = json.loads((root / "candidate-tree.json").read_bytes())
    require(tree_hash(before) == "7d50c61f02704e3ce3afd82568c50db960b08a9a" and tree_hash(after) == TREE, "complete Git tree identity changed")
    require(set(before) == set(after) and len(after) == 13257, "full Git tree leaf set changed")
    delta = {name for name in before if before[name] != after[name]}
    require(delta == {".github/workflows/" + name for name in CHANGED}, "candidate changed production or unrelated files")
    workflows = {phase: {p.name: p.read_text() for p in (root / "workflows" / phase).glob("*.yml")} for phase in ("before", "after")}
    audit, variants = check_workflows(workflows["before"], workflows["after"])
    require(audit == proof["workflow_audit"] and proof["head"] == HEAD and proof["base"] == BASE, "workflow audit identity changed")
    for phase, rows in (("before", before), ("after", after)):
        for name, text in workflows[phase].items(): require(pin(text.encode())["git_blob"] == rows[".github/workflows/" + name]["sha"], "workflow source bytes differ from Git")
    cases = []
    for index, variant in enumerate(variants):
        folder = root / "layouts" / str(index); current = folder / "current-source"; historical = folder / "historical-source"
        module = load_materializer(current); profile, _ = module.check(current)
        require(inventory(current) == json.loads((folder / "CURRENT.json").read_bytes()), "full current sparse input changed")
        require(inventory(historical) == json.loads((folder / "HISTORICAL.json").read_bytes()), "full historical output changed")
        for name, identity in inventory(current).items():
            require(name in after and identity["git_blob"] == after[name]["sha"] and bool(identity["mode"] & 0o111) == (after[name]["mode"] == "100755"), "actual sparse file does not match candidate tree")
        for name, oid in FIXES.items(): require(pin((current / name).read_bytes())["git_blob"] == oid, "retained 7afd/08ce reader changed")
        receipt = json.loads((historical / "HISTORICAL_PUBLIC_SOURCE.json").read_bytes())
        selected = {name: pin(path.read_bytes()) for name, path in module.selected(historical).items()}
        require(receipt["files"] == selected and receipt["historical_public_images"] == 58 and receipt["current_default_images"] == 111, "materialized complete receipt differs")
        require(receipt["restored_paths"] == sorted(profile["restore"]) and receipt["excluded_current_only_paths"] == profile["remove_current_public_only"], "restore/exclude domain changed")
        for name, expected in profile["restore"].items(): require(pin((historical / name).read_bytes()) == expected, "historical exact source changed")
        for name in profile["remove_current_public_only"]: require(not (historical / name).exists(), "current-only source leaked into historical view")
        old = json.loads((root / "processes" / ("layout-"+str(index)+"-old.json")).read_bytes())
        require(old["returncode"] == 1 and b"runtime_support" in (root / "processes" / ("layout-"+str(index)+"-old.stderr")).read_bytes(), "original missing-input refusal omitted")
        cases.append(dict(layout=index, current_files=len(inventory(current)), historical_files=len(selected), current_bound=390, restored=119))
    controls = json.loads((root / "mutation-controls.json").read_bytes())
    require([r["kind"] for r in controls] == ["missing-packed", "changed-packed", "changed-current-owner", "changed-historical-owner"], "mutation domain changed")
    normal = root / "layouts/0/current-source"
    for control in controls:
        raw = (normal / control["path"]).read_bytes()
        require(pin(raw) == control["before"], "mutation preimage changed")
        if control["kind"] == "missing-packed": require(control["after"] is None, "missing mutation changed")
        else: require(control["after"] == pin(raw+b"\n"), "physical mutation bytes changed")
        actual_expected = inventory(normal)
        if control["after"] is None: del actual_expected[control["path"]]
        else: actual_expected[control["path"]] = dict(**control["after"], mode=actual_expected[control["path"]]["mode"])
        require(actual_expected == control["actual_source_inventory"], "actual physical control input closure changed")
        require(control["rejected"] is True and control["error_type"] in ("AssertionError", "FileNotFoundError"), "source mutation accepted")
    for path in (root / "processes").glob("*.json"):
        record = json.loads(path.read_bytes()); label = path.stem
        require(record["limit_seconds"] == 60 and record["elapsed_ns"] < 61_000_000_000, "source-only process limit changed")
        for suffix, expected in record["streams"].items(): require(pin((path.parent / (label+"."+suffix)).read_bytes()) == expected, "full source process stream changed")
        argv = record["argv"]
        require(argv[0] == "git" or argv[1:3] == ["-I", "-B"] and argv[3].endswith("/historical_public58/materialize.py"), "unexpected execution in source-only evidence")
    return dict(status="SPARSE_CURRENT111_HISTORICAL58_SOURCE_ONLY_PASS", workflow_files=4, sparse_checkouts=7,
                layouts=cases, mutations=len(controls), tree_files=len(after), production_files_unchanged=390,
                historical_restore_unchanged=119, native_executed=False, rust_executed=False)


def run(repository, output):
    require(not output.exists(), "proof output must be fresh"); output.mkdir(parents=True)
    head = process(output, "head", ["git", "-C", str(repository), "rev-parse", "HEAD"]).decode().strip(); require(head == HEAD, "wrong candidate checkout")
    parent = process(output, "parent", ["git", "-C", str(repository), "rev-parse", "HEAD^"]).decode().strip(); require(parent == BASE, "wrong exact parent")
    trees = {}
    for phase, ref in (("base", BASE), ("candidate", HEAD)):
        raw = process(output, phase+"-tree", ["git", "-C", str(repository), "ls-tree", "-rz", ref])
        trees[phase] = tree_rows(raw); (output / (phase+"-tree.json")).write_bytes(encode(trees[phase]))
    workflows = {"before": {}, "after": {}}
    for name in sorted(p.name for p in (repository / ".github/workflows").glob("*.yml")):
        for phase, ref in (("before", BASE), ("after", HEAD)):
            raw = process(output, "workflow-"+phase+"-"+name, ["git", "-C", str(repository), "show", ref+":.github/workflows/"+name])
            target = output / "workflows" / phase / name; target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(raw)
            workflows[phase][name] = raw.decode()
    audit, variants = check_workflows(workflows["before"], workflows["after"])
    for index, variant in enumerate(variants):
        label = "layout-"+str(index); checkout = output.parent / (output.name+"-"+label+"-checkout")
        require(not checkout.exists(), "actual sparse checkout must be fresh")
        process(output, label+"-clone", ["git", "clone", "--shared", "--no-checkout", str(repository), str(checkout)])
        process(output, label+"-init", ["git", "-C", str(checkout), "sparse-checkout", "init", "--cone"])
        process(output, label+"-old-set", ["git", "-C", str(checkout), "sparse-checkout", "set", "--stdin"], data=("\n".join(variant["before"])+"\n").encode())
        process(output, label+"-checkout", ["git", "-C", str(checkout), "checkout", "--detach", HEAD])
        process(output, label+"-old", [sys.executable, "-I", "-B", str(checkout / FOLDER / "materialize.py"), "--source", str(checkout), "--check-only"], expected=1)
        process(output, label+"-new-set", ["git", "-C", str(checkout), "sparse-checkout", "set", "--stdin"], data=("\n".join(variant["after"])+"\n").encode())
        module = load_materializer(checkout); module.check(checkout)
        folder = output / "layouts" / str(index); folder.mkdir(parents=True)
        current = folder / "current-source"; copy_selected(module, checkout, current)
        before = inventory(current)
        process(output, label+"-materialize", [sys.executable, "-I", "-B", str(current / FOLDER / "materialize.py"), "--source", str(current), "--output", str(folder / "historical-source")])
        require(before == inventory(current), "materialization changed current source")
        (folder / "CURRENT.json").write_bytes(encode(before)); (folder / "HISTORICAL.json").write_bytes(encode(inventory(folder / "historical-source")))
    normal = output / "layouts/0/current-source"; module = load_materializer(normal)
    controls = []
    variants = [("missing-packed", "runtime_support/bellman_port/BYTE_ACCESS_REBINDING.json"),
                ("changed-packed", "runtime_support/bellman_port/BYTE_ACCESS_REBINDING.json"),
                ("changed-current-owner", "native/runtime_mcp.hepta"),
                ("changed-historical-owner", (FOLDER/"source/native/runtime_mcp.hepta").as_posix())]
    original = inventory(normal)
    for kind, name in variants:
        path = normal / name; raw = path.read_bytes(); mode = path.stat().st_mode & 0o777
        if kind == "missing-packed": path.unlink(); after = None
        else: path.write_bytes(raw+b"\n"); after = pin(path.read_bytes())
        changed = inventory(normal)
        require({p for p in set(original)|set(changed) if original.get(p) != changed.get(p)} == {name}, "mutation changed another source")
        try: module.check(normal)
        except (AssertionError, FileNotFoundError) as error:
            controls.append(dict(kind=kind, path=name, before=pin(raw), after=after, rejected=True,
                                 error_type=type(error).__name__, error=str(error), actual_source_inventory=changed))
        else: raise ValueError("physical source mutation unexpectedly accepted")
        finally: path.write_bytes(raw); path.chmod(mode)
        require(inventory(normal) == original, "mutation did not restore owned source bytes")
    (output / "mutation-controls.json").write_bytes(encode(controls))
    (output / "proof.json").write_bytes(encode(dict(head=HEAD, base=BASE, tree=TREE, workflow_audit=audit,
        original_failure=dict(run=44000724037, job=133763797882, retained=True), native_executed=False, rust_executed=False)))
    result = read(output); (output / "RESULT.json").write_bytes(encode(result)); print(json.dumps(result, sort_keys=True))


def main():
    p = argparse.ArgumentParser(description=__doc__); p.add_argument("mode", choices=("run", "read")); p.add_argument("--repository", type=Path); p.add_argument("--output", required=True, type=Path)
    a = p.parse_args()
    if a.mode == "run": run(a.repository.resolve(strict=True), a.output.absolute())
    else:
        root = a.output.resolve(strict=True)
        # Load every source-only module before the reader guard starts.
        for path in (root/"layouts").glob("*/current-source"): load_materializer(path)
        from readonly import guarded
        print(json.dumps(guarded(lambda: read(root), roots=[root]), sort_keys=True))


if __name__ == "__main__": main()
