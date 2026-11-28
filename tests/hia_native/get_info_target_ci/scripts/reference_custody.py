"""Authenticate retained reference bytes without writing or executing code.
Generation uses observe=False and never decodes original result streams.
"""
from pathlib import Path
import hashlib, json, stat, tarfile, zipfile
TARGET = "d3d75c30719db966b004756f610007a7c723729e"
TREE = "612e145513961556ac8844b5cc978f9b5175e4d4"
ZIP_BYTES = 95269620
ZIP_SHA = "32e325c73e8a47ee14683ff96dec87bf505c1e7ce2fff56af509aacc1b51e6a5"
RECIPE_SHA = "810c8a3d1fef5141830dc23271e345125e204d6771d8692fec6bbc782d324f20"
PROFILES = ["disabled", *map(str, range(8))]
PRIMARY = {
    "server.rs": "original-source/src/mcp/server.rs",
    "Cargo.lock": "original-source/Cargo.lock",
    "rmcp-model.rs": "registry-source/rmcp-3.9.0/src/model.rs",
    "rmcp-capabilities.rs": "registry-source/rmcp-3.9.0/src/model/capabilities.rs",
    "rmcp-Cargo.toml": "registry-source/rmcp-3.9.0/Cargo.toml",
}
FALSE_FLAGS = ("whole_runtime_replaced", "production_activated", "old_stack_removal_qualified")
def need(value, label):
    if not value: raise ValueError("retained get_info reference: " + label)
def sha(raw): return hashlib.sha256(raw).hexdigest()
def pin(raw): return dict(bytes=len(raw), sha256=sha(raw))
def parse(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, "duplicate JSON key")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")))
def file_pin(path):
    with Path(path).open("rb") as stream:
        return dict(bytes=Path(path).stat().st_size,
                    sha256=hashlib.file_digest(stream, "sha256").hexdigest())
def inspect_zip(path, *, observe=False):
    path = Path(path).absolute()
    need(path.resolve(strict=True) == path and stat.S_ISREG(path.lstat().st_mode), "regular reference ZIP")
    need(file_pin(path) == dict(bytes=ZIP_BYTES, sha256=ZIP_SHA), "exact reference artifact ZIP")
    names = ["rustc-version", "cargo-version", "cargo-build", "cargo-metadata",
             *("profile-" + profile for profile in PROFILES)]
    keep = set(PRIMARY.values()) | {
        "artifact-manifest.json", "result.json", "source.json", "registry.json",
        "target-tree.bin", "instrumented-server.rs", "recipe-source/source_manifest.json",
        "recipe-source/observer.rs", "recipe-source/main.rs", "processes/rustc-version.stdout",
        *("processes/" + name + ".process.json" for name in names),
    }
    streams = {"processes/profile-" + p + ".stdout": p for p in PROFILES}
    saved, actual, blobs, observed = {}, {}, {}, {}
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        need(len(entries) == 2 and {v.filename for v in entries} ==
             {"archive.json", "catalog-reference.tar.gz"}, "complete ZIP members")
        for entry in entries:
            need(not entry.is_dir() and not stat.S_ISLNK(entry.external_attr >> 16), "ordinary ZIP member")
        metadata = parse(archive.read("archive.json"))
        need(metadata["archive"] == "catalog-reference.tar.gz" and metadata["complete_archive"] is True
             and metadata["reference_status"] == "REFERENCE_EXECUTION_COMPLETE", "original exporter status")
        with archive.open("catalog-reference.tar.gz") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        need(digest == metadata["sha256"] and
             archive.getinfo("catalog-reference.tar.gz").file_size == metadata["bytes"], "complete tar bytes")
        with archive.open("catalog-reference.tar.gz") as stream:
            with tarfile.open(fileobj=stream, mode="r|gz") as tar:
                for member in tar:
                    relative = Path(member.name)
                    need(not relative.is_absolute() and ".." not in relative.parts
                         and relative.as_posix() == member.name, "ordinary tar path")
                    if member.isdir(): continue
                    need(member.isfile() and member.name not in actual, "unique regular tar file")
                    source = tar.extractfile(member)
                    digest = hashlib.sha256()
                    git = hashlib.sha1(b"blob " + str(member.size).encode() + b"\0")
                    collect = member.name in keep or observe and member.name in streams
                    chunks, count = [], 0
                    while True:
                        chunk = source.read(1 << 20)
                        if not chunk: break
                        count += len(chunk); digest.update(chunk)
                        if member.name.startswith("original-source/"): git.update(chunk)
                        if collect: chunks.append(chunk)
                    need(count == member.size, "complete tar member")
                    actual[member.name] = dict(bytes=count, sha256=digest.hexdigest())
                    if member.name.startswith("original-source/"): blobs[member.name] = git.hexdigest()
                    if collect:
                        raw = b"".join(chunks)
                        if member.name in keep: saved[member.name] = raw
                        if observe and member.name in streams:
                            profile = streams[member.name]
                            doc = parse(raw)
                            need(doc["schema"] == "hepta.runtime.current-catalog-observation.v1"
                                 and doc["target_commit"] == TARGET, "actual profile identity")
                            need(all(doc.get(flag) is False for flag in FALSE_FLAGS)
                                 and doc["tool_body_calls"] == 0 and doc["worker_readiness_qualified"] is False,
                                 "actual observation scope")
                            number = None if profile == "disabled" else int(profile)
                            flags = (number is not None, bool(number is not None and number & 1),
                                     bool(number is not None and number & 2), bool(number is not None and number & 4))
                            need(tuple(doc[key] for key in ("runtime_enabled", "hia_enabled", "rea_enabled", "weight_enabled"))
                                 == flags, "actual configuration reached target")
                            need(len(doc["raw_tool_wires"]) == 136 and len(doc["list_cases"]) == 24,
                                 "complete retained observation")
                            need(isinstance(doc["get_info_wire"], str), "complete get_info wire")
                            observed[profile] = dict(profile=profile, stdout=actual[member.name],
                                runtime_flags=list(flags), get_info_wire=doc["get_info_wire"])
    manifest = parse(saved["artifact-manifest.json"])
    need(manifest["schema"] == "hepta.runtime.current-catalog-artifact.v1"
         and manifest["only_excluded_directory"] == "cargo-target"
         and manifest["complete_process_streams_retained"] is True, "full original artifact manifest")
    need(manifest["files"] == {name: value for name, value in actual.items() if name != "artifact-manifest.json"},
         "every retained tar member matches its original full manifest")
    need(metadata["files"] == len(actual), "original tar file count")
    result, source = parse(saved["result.json"]), parse(saved["source.json"])
    need(result["status"] == "REFERENCE_EXECUTION_COMPLETE" and result["target_commit"] == TARGET
         and result["target_tree"] == TREE and source["target_commit"] == TARGET and source["target_tree"] == TREE,
         "exact complete current original reference")
    need(all(result.get(flag) is False for flag in FALSE_FLAGS)
         and result["public_transport_executed"] is False and result["tool_body_calls"] == 0,
         "original qualification boundary")
    need(result["original_get_info_calls"] == 9 and result["original_list_handler_calls"] == 216,
         "original observation counts")
    tree = {}
    for row in saved["target-tree.bin"].split(b"\0"):
        if row:
            descriptor, name = row.split(b"\t", 1)
            mode, kind, oid = descriptor.split()
            tree[name.decode()] = (mode, kind, oid.decode())
    for name, expected in source["originals"].items():
        relative = "original-source/" + name
        need(actual[relative] == expected and tree[name][1:] == (b"blob", blobs[relative]),
             "complete target Git source: " + name)
    need(saved["instrumented-server.rs"] ==
         saved["original-source/src/mcp/server.rs"] + b"\n" + saved["recipe-source/observer.rs"],
         "unaltered original method in append-only observer")
    need(source["original_functions_unchanged"] is True and result["original_functions_unchanged"] is True,
         "original functions retained")
    need(actual["reference.elf"] == result["original_binary"], "retained actual original executable")
    need(sha(saved["recipe-source/source_manifest.json"]) == RECIPE_SHA, "immutable original recipe")
    for name, expected in parse(saved["recipe-source/source_manifest.json"]).items():
        need(actual["recipe-source/" + name] == expected, "original recipe source " + name)
    registry = parse(saved["registry.json"])
    need(len(registry) == result["registry_packages"] and "rmcp-3.9.0" in registry, "complete registry inventory")
    for package, descriptor in registry.items():
        for name, expected in descriptor["files"].items():
            need(actual["registry-source/" + package + "/" + name] == expected, "retained registry source")
    need({name for name in actual if name.startswith("processes/") and name.endswith(".process.json")} ==
         {"processes/" + name + ".process.json" for name in names}, "actual process inventory")
    for name in names:
        process = parse(saved["processes/" + name + ".process.json"])
        need(process["name"] == name and process["exit_code"] == 0
             and process["start_error"] is None and process["timed_out"] is False, "actual process succeeded")
        deadline = 1800 if name == "cargo-build" else 180 if name == "cargo-metadata" else 120 if name.startswith("profile-") else 30
        need(process["timeout_seconds"] == deadline and 0 <= process["elapsed_seconds"] < deadline,
             "original process deadline retained")
        for field in ("stdout", "stderr"):
            item = process[field]
            need(item["path"] == name + "." + field and
                 actual["processes/" + item["path"]] == {key: item[key] for key in ("bytes", "sha256")},
                 "full original process stream")
        if name.startswith("profile-"): need(process["stderr"]["bytes"] == 0, "ordinary profile stderr")
    need(saved["processes/rustc-version.stdout"].startswith(b"rustc 1.95.0 "), "actual original Rust version")
    if observe:
        need(set(observed) == set(PROFILES), "all nine get_info calls decoded")
        need(len({row["get_info_wire"] for row in observed.values()}) == 1, "actual fixed get_info across configurations")
    primary = {name: saved[member] for name, member in PRIMARY.items()}
    proof = dict(schema="hepta.current-get-info.retained-reference-custody.v1",
        reference_commit="c5b484f9f7702794392bd01bebd4b87a6d0e3393",
        reference_run=43796801388, reference_artifact=14194828118,
        zip=dict(bytes=ZIP_BYTES, sha256=ZIP_SHA), tar=metadata,
        complete_members_verified=len(actual), complete_member_bytes=sum(v["bytes"] for v in actual.values()),
        target_commit=TARGET, target_tree=TREE,
        original_source_files=len(source["originals"]), registry_packages=len(registry),
        actual_original_processes=len(names), observation_outputs_decoded=observe,
        original_get_info_calls=9 if observe else 0, new_rust_executed=False,
        primary={name: {"member": PRIMARY[name], **pin(raw)} for name, raw in primary.items()})
    return proof, primary, [observed[p] for p in PROFILES] if observe else []
