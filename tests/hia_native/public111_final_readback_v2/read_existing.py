"""Reopen one complete default111 role without executing HIA, Rust, or a build."""
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


from pathlib import Path
import argparse, hashlib, importlib, json, os, sys
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from artifact_bytes import extract_capture, pin, require, save, sha

def own_source():
    root = Path(__file__).resolve().parent
    doc = json.loads((root / "SOURCE.json").read_bytes())
    require({p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()}
            == set(doc["files"]) | {"SOURCE.json"}, "complete readback source set")
    for name, expected in doc["files"].items():
        require(pin(root / name) == expected, "readback source changed: " + name)
    return root, pin(root / "SOURCE.json")

def import_reader(package, name):
    sys.path.insert(0, str(package / "ci"))
    value = importlib.import_module(name)
    require(Path(value.__file__).resolve() == package / "ci" / (name + ".py"), "foreign reader: " + name)
    return value

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--role", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source, source_pin = own_source()
    plan = json.loads((source / "PLAN.json").read_bytes())
    require(os.environ.get("GITHUB_ACTIONS") == "true", "independent readback is CI-only")
    require(args.role in plan["roles"], "unlisted readback role")
    role = plan["roles"][args.role]
    out = args.output.absolute()
    require(not out.exists(), "readback output already exists")
    out.mkdir(parents=True)
    captures, inventories = {}, {}
    for name in [role["target"], *role["dependencies"]]:
        require(name not in captures, "duplicate role artifact")
        captures[name], inventories[name] = extract_capture(plan["artifacts"][name], out / name)
    run = captures[role["target"]]
    package = (run / "ci-package").resolve(strict=True)
    manifest_sha = plan["artifacts"][role["target"]]["source_manifest_sha256"]
    read_all = import_reader(package, "read_all")
    source_check = import_reader(package, "source_check")
    dependency_roots = {name: captures[name] for name in role["dependencies"]}
    if args.role in ("owner", "profiles", "authority", "connection"):
        reader = import_reader(package, "read_domains")
        prepared = reader.prepare(package, args.role)
        wire, guard = prepared["wire"], prepared["guard"]
        def operation():
            admitted = source_check.source(package, manifest_sha)
            physical = {name: read_all.inventory(root) for name, root in captures.items()}
            result = reader.verify(package, run, manifest_sha, args.role, dependency_roots, prepared)
            return {"status": result["status"], "qualification": result, "source": admitted,
                    "complete_archives": physical}
    elif args.role in ("batch", "batch-reference"):
        reader = import_reader(package, "read_batch")
        baseline = run / "baseline" if args.role == "batch-reference" else dependency_roots["batch-reference"] / "baseline"
        prepared = reader.prepare(package, baseline)
        wire, guard = prepared["wire"], prepared["guard"]
        def operation():
            admitted = source_check.source(package, manifest_sha)
            physical = {name: read_all.inventory(root) for name, root in captures.items()}
            result = reader.verify(package, run, manifest_sha, args.role, dependency_roots, prepared)
            return {"status": result["status"], "qualification": result, "source": admitted,
                    "complete_archives": physical}
    else:
        wire, guard = read_all.prepare(package)
        if args.role == "build":
            read_build = import_reader(package, "read_build")
            build_controls = import_reader(package, "build_controls")
            def operation():
                admitted = source_check.source(package, manifest_sha)
                physical = {name: read_all.inventory(root) for name, root in captures.items()}
                graph = read_build.verify_build(package, run, manifest_sha)
                controls = build_controls.verify_controls(package, run, manifest_sha)
                require(graph["runtime_hia_images"] == 111 and graph["fresh_direct_members"] == 103
                        and graph["packed_hia_members"] == 8 and controls["refusals"] == 4,
                        "complete fresh graph and physical controls")
                return {"status": "FRESH_PUMP_GRAPH_BUILD_READBACK_PASS", "graph": graph,
                        "controls": controls, "source": admitted, "complete_archives": physical}
        elif args.role == "original":
            original = guard["wire"].original_reader
            def operation():
                admitted = source_check.source(package, manifest_sha)
                physical = {name: read_all.inventory(root) for name, root in captures.items()}
                result = original.verify(package / "wire/reference", run)
                require(result["status"] == "COMPLETE_BELLMAN_PUBLIC_ORIGINAL_REFERENCE_PASS",
                        "complete actual original reference")
                return {"status": result["status"], "qualification": result, "source": admitted,
                        "complete_archives": physical}
        elif args.role == "native":
            def operation():
                admitted = source_check.source(package, manifest_sha)
                physical = {name: read_all.inventory(root) for name, root in captures.items()}
                result = read_all.verify(package, dependency_roots["build"], dependency_roots["original"],
                                         run, manifest_sha, wire, guard)
                return {"status": result["qualification"]["status"], "qualification": result,
                        "source": admitted, "complete_archives": physical}
        else:
            raise ValueError("unsupported complete role")
    roots = list(captures.values()) + [source]
    readonly = wire.guarded(operation, roots=roots, prepared=guard)
    require(readonly["before"] == readonly["after"] and len(readonly["probes"]) == 11
            and readonly["reader_writes"] == readonly["native_or_rust_executions"] == 0,
            "complete read-only custody")
    require(readonly["evidence"]["status"] == role["expected_status"], "complete role status differs")
    save(out / "READONLY.json", readonly)
    state_hash = lambda value: sha(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode())
    summary = {"schema": "hepta.public111.independent-role-readback.v1",
               "status": "COMPLETE_EXISTING_ROLE_ARCHIVES_AND_PURE_READER_PASS",
               "role": args.role, "qualification_status": readonly["evidence"]["status"],
               "producer_head": plan["producer_head"], "producer_run": plan["producer_run"],
               "source": source_pin, "artifact_inventories": inventories,
               "native_or_rust_reader_executions": 0, "reader_writes": 0,
               "physical_guard_probes": len(readonly["probes"]), "unchanged_entries": len(readonly["before"]),
               "before_sha256": state_hash(readonly["before"]), "after_sha256": state_hash(readonly["after"]),
               "readonly": pin(out / "READONLY.json"), "full_sdk_qualified": False,
               "full_async_qualified": False, "production_activated": False, "old_stack_removed": False}
    if args.role == "build":
        summary["entry_pins"] = {name: {kind: {key: row[kind][key] for key in ("bytes", "sha256")}
            for kind in ("elf", "manifest")} for name, row in readonly["evidence"]["graph"]["entries"].items()}
        summary["shape_source_proof"] = readonly["evidence"]["graph"]["shape_source_proof"]
    if args.role == "native":
        summary["public"] = readonly["evidence"]["qualification"]["qualification"]
    save(out / "READBACK.json", summary)
    print("READBACK_SUMMARY " + json.dumps(summary, sort_keys=True, allow_nan=False))

if __name__ == "__main__":
    main()
