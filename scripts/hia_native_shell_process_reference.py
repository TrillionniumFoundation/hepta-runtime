#!/usr/bin/env python3
"""Build/test a source-bound original shell/background Rust oracle.

The crate is test infrastructure. Original owner files and all original tests are
copied or included byte-for-byte; fixture transport never replaces owner bodies.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import contextlib
import io
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import signal
import subprocess
import sys
import tarfile
import time
import tomllib

ROOT = Path(__file__).resolve().parents[1]
ORACLE_REL = "tests/hia_native/shell_process_oracle"
SCHEMA = "hepta.runtime.shell-process-original-qualification.v1"
DRIVER_BYTES = Path(__file__).read_bytes()
DRIVER_REL = "scripts/hia_native_shell_process_reference.py"
TRANSPORT_SOURCES = (
    "Cargo.lock",
    "Cargo.toml",
    "README.md",
    "source_manifest.json",
    "src/background_render.rs",
    "src/fixture.rs",
    "src/main.rs",
    "src/outcome_render.rs",
    "src/mcp/fs/background_fixture.rs.in",
    "src/mcp/fs/background_module.rs.in",
    "src/mcp/fs/delta.rs",
    "src/mcp/fs/mod.rs",
    "src/mcp/fs/shell.rs",
    "src/mcp/fs/shell_fixture.rs",
    "src/mcp/fs/shell_outcome_fixture.rs.in",
    "src/mcp/mod.rs",
    "src/utils/mod.rs",
    "src/utils/truncation.rs",
)
TOOL_SIDECAR_PREFIX = ".hepta-"

def require(value, message):
    if not value:
        raise ValueError(message)

def pairs(rows):
    out = {}
    for key, value in rows:
        require(key not in out, "duplicate JSON key: " + key)
        out[key] = value
    return out

def decode(raw):
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda v: (_ for _ in ()).throw(ValueError("nonfinite JSON")))

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)

def exact(left, right, message):
    require(canonical(left) == canonical(right), message)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def pin(raw):
    return {"bytes": len(raw), "sha256": sha(raw)}

def owned(root, relative):
    require(type(relative) is str and relative, "path must be a string")
    path = PurePosixPath(relative)
    require(not path.is_absolute() and "\\" not in relative
            and all(p not in ("", ".", "..") for p in relative.split("/")), "unsafe source path")
    base = Path(root)
    for ancestor in (base, *base.parents):
        require(not ancestor.is_symlink(), "symlink in source base")
    for part in path.parts:
        base = base / part
        require(not base.is_symlink(), "symlink in source closure")
    require(base.is_file(), "missing source: " + str(base))
    return base

def read(root, relative):
    return owned(root, relative).read_bytes()

def normalize_lock_row(row, packages):
    """Only dependency-token spelling is normalized; every package/edge remains."""
    value = {key:item for key,item in row.items() if key != "dependencies"}
    if "dependencies" in row:
        dependencies = []
        for token in row["dependencies"]:
            fields = token.split()
            candidates = [p for p in packages if p["name"] == fields[0]
                          and (len(fields) == 1 or p["version"] == fields[1])]
            require(len(candidates) == 1, "ambiguous lock dependency token: " + token)
            package = candidates[0]
            dependencies.append({"name":package["name"],"version":package["version"],
                                 "source":package.get("source")})
        value["dependencies"] = sorted(dependencies,key=lambda p:(p["name"],p["version"],p["source"] or ""))
    return value

def ordinary_source_inventory(root: Path, expected) -> tuple[str, ...]:
    """Admit exact ordinary members; never stat/open reserved tool sidecars."""
    root=Path(root).absolute()
    require(root.resolve(strict=True)==root and root.is_dir(),
            "source inventory root is not an ordinary canonical directory")
    expected=set(expected)
    directories=set()
    for relative in expected:
        path=PurePosixPath(relative)
        require(type(relative) is str and relative and not path.is_absolute()
                and all(part not in ("", ".", "..") for part in relative.split("/"))
                and all(not part.startswith(TOOL_SIDECAR_PREFIX) for part in path.parts),
                "registered source path is unsafe")
        directories.update(parent.as_posix() for parent in path.parents if parent.as_posix()!=".")
    seen=set()
    def visit(directory):
        with os.scandir(directory) as iterator:
            entries=sorted(iterator,key=lambda entry:entry.name)
        for entry in entries:
            # This reserved namespace belongs to the filesystem tool. Skip the
            # name before any type/identity/content inspection or traversal.
            if entry.name.startswith(TOOL_SIDECAR_PREFIX):
                continue
            path=directory/entry.name
            relative=path.relative_to(root).as_posix()
            require(relative in expected or relative in directories,
                    "unregistered ordinary source member: "+relative)
            require(not entry.is_symlink(),"source inventory contains a symlink")
            if relative in directories:
                require(entry.is_dir(follow_symlinks=False),"registered source directory is missing")
                visit(path)
            else:
                require(entry.is_file(follow_symlinks=False)
                        and entry.stat(follow_symlinks=False).st_nlink==1,
                        "registered source is not an independent ordinary file")
                seen.add(relative)
    visit(root)
    exact(sorted(seen),sorted(expected),"registered ordinary source inventory is incomplete")
    return tuple(sorted(seen))

def original_sources(runtime: Path, oracle: Path | None = None):
    oracle = oracle or runtime / ORACLE_REL
    manifest = decode(read(oracle, "source_manifest.json"))
    require(manifest.get("schema") == "hepta.runtime.shell-process-original-source.v1",
            "original source manifest schema differs")
    require(read(runtime,DRIVER_REL) == DRIVER_BYTES, "executing reference driver differs from source tree")
    source = {}
    for relative, expected in manifest["files"].items():
        raw = read(runtime, relative)
        blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
        exact({**pin(raw), "git_blob_sha1": blob}, expected, "original source changed: " + relative)
        source[relative] = raw
    extracted = {}
    for relative, span in manifest["compiled_original_spans"].items():
        require(type(span["start"]) is int and type(span["end"]) is int
                and 0 <= span["start"] <= span["end"] <= len(source[span["source"]]),
                "original extraction offsets invalid")
        raw = source[span["source"]][span["start"]:span["end"]]
        exact(pin(raw), {"bytes": span["bytes"], "sha256": span["sha256"]},
              "original extraction differs: " + relative)
        extracted[relative] = raw
    fragments = {}
    for name, span in manifest["projection_spans"].items():
        require(type(span["start"]) is int and type(span["end"]) is int
                and 0 <= span["start"] <= span["end"] <= len(source[span["source"]]),
                "projection offsets invalid")
        raw = source[span["source"]][span["start"]:span["end"]]
        exact(pin(raw), {"bytes":span["bytes"],"sha256":span["sha256"]},
              "original projection statement bytes changed: " + name)
        fragments[name] = raw
    for relative, template in manifest["compiled_projection_sources"].items():
        require(relative not in extracted, "projection source collision")
        raw = read(oracle,template["template"])
        for marker,name in template["markers"].items():
            needle=marker.encode("ascii")
            require(raw.count(needle)==1, "projection marker is not unique")
            raw=raw.replace(needle,fragments[name])
        require(b"/* ORIGINAL_" not in raw, "unresolved original projection marker")
        extracted[relative]=raw
    for relative, suffix in manifest["compiled_source_appends"].items():
        require(relative in extracted, "append has no original prefix")
        extracted[relative]+=read(oracle,suffix)
    for file, expected_names in manifest["original_test_names"].items():
        names = [v.decode() for v in re.findall(
            rb"#\[(?:tokio::)?test\]\s*(?:async\s+)?fn\s+(\w+)\(", source[file])]
        exact(names, expected_names, "original test names changed")
    exact(sum(len(v) for v in manifest["original_test_names"].values()), 21, "original test set not complete")
    exact(manifest["original_test_count"], 21, "original test count differs")
    original_package = tomllib.loads(source["Cargo.toml"].decode())
    package = tomllib.loads(read(oracle, "Cargo.toml").decode())
    exact({"dependencies":package["dependencies"],"dev-dependencies":package["dev-dependencies"]},
          manifest["oracle_dependency_declarations"], "fixed original feature declarations changed")
    for name in ("anyhow","regex","serde","serde_json","tokio"):
        original = original_package["dependencies"][name]
        selected = package["dependencies"][name]
        version = original if type(original) is str else original["version"]
        exact(selected["version"],version,"production dependency version declaration changed")
        original_features = [] if type(original) is str else original.get("features",[])
        require(set(original_features) <= set(selected["features"]), "production features were removed")
    exact(package["dependencies"]["libc"]["version"],
          original_package["target"]["cfg(unix)"]["dependencies"]["libc"], "production libc declaration changed")
    exact(package["dev-dependencies"]["tempfile"],original_package["dev-dependencies"]["tempfile"],
          "original test dependency declaration changed")
    exact(package["profile"], original_package["profile"], "original build profiles changed")
    original_lock = tomllib.loads(source["Cargo.lock"].decode())
    oracle_lock = tomllib.loads(read(oracle, "Cargo.lock").decode())
    original_rows = {(v["name"],v["version"]):v for v in original_lock["package"]}
    dependencies = [v for v in oracle_lock["package"] if "source" in v]
    for row in dependencies:
        original = original_rows.get((row["name"],row["version"]))
        require(original is not None,"new dependency version/source introduced")
        exact(normalize_lock_row(row,oracle_lock["package"]),
              normalize_lock_row(original,original_lock["package"]),
              "locked dependency identity or edge differs: " + row["name"])
    exact(sorted(dependencies,key=lambda v:(v["name"],v["version"])),
          manifest["derived_registry_dependencies"], "complete derived locked dependency closure differs")
    exact(sorted([original_rows[(v["name"],v["version"])] for v in dependencies],key=lambda v:(v["name"],v["version"])),
          manifest["registry_dependencies"],"original locked dependency closure differs")
    transport = {relative:pin(read(oracle,relative))
                 for relative in ordinary_source_inventory(oracle,TRANSPORT_SOURCES)}
    provenance = {
        "schema":"hepta.runtime.shell-process-source-check.v1",
        "source_commit":manifest["source_commit"],"source_tree":manifest["source_tree"],
        "target":manifest["target"],"files":manifest["files"],
        "compiled_original_spans":manifest["compiled_original_spans"],
        "projection_spans":manifest["projection_spans"],
        "compiled_projection_sources":manifest["compiled_projection_sources"],
        "compiled_source_appends":manifest["compiled_source_appends"],
        "assembled_original_sources":{name:pin(raw) for name,raw in sorted(extracted.items())},
        "background_renderer_scope":manifest["background_renderer_scope"],
        "outcome_renderer_scope":manifest["outcome_renderer_scope"],
        "full_shell_owner_retained":True,"full_background_owner_retained":True,
        "full_request_context_retained":True,"original_function_bodies_changed":False,
        "original_test_names":manifest["original_test_names"],"original_test_count":21,
        "original_dependency_rows_equal":True,"registry_dependency_count":len(dependencies),
        "registry_dependencies":manifest["registry_dependencies"],
        "derived_registry_dependencies":manifest["derived_registry_dependencies"],
        "dependency_identity_normalization":manifest["dependency_identity_normalization"],
        "production_features":manifest["production_features"],
        "feature_unification_scope":manifest["feature_unification_scope"],
        "production_metadata_inputs":manifest["production_metadata_inputs"],
        "production_feature_reproduction":manifest["production_feature_reproduction"],
        "fixture_scope":manifest["fixture_scope"],
        "reference_driver_source":{"path":DRIVER_REL,**pin(DRIVER_BYTES)},
        "production_direct_dependency_declarations":manifest["production_direct_dependency_declarations"],
        "oracle_extra_tokio_feature":manifest["oracle_extra_tokio_feature"],
        "view_cache_scope":manifest["view_cache_scope"],
        "transport_source_admission":{"ordinary_files":list(TRANSPORT_SOURCES),
            "unknown_ordinary_members_rejected":True,
            "reserved_tool_sidecar_prefix":TOOL_SIDECAR_PREFIX,
            "tool_sidecars_inspected_or_copied":False},
        "test_transport_sources":transport,"whole_runtime_replaced":False,
        "production_shell_execution_qualified":False}
    return provenance, extracted

def materialize(runtime, output):
    oracle = runtime / ORACLE_REL
    provenance, extracted = original_sources(runtime,oracle)
    crate = output / "crate"
    crate.mkdir()
    for rel in provenance["test_transport_sources"]:
        if rel == "source_manifest.json" or rel.endswith(".md"):
            continue
        dest = crate / rel
        dest.parent.mkdir(parents=True,exist_ok=True)
        with dest.open("xb") as f:
            f.write(read(oracle,rel))
    for rel, raw in extracted.items():
        dest = crate / rel
        require(not dest.exists(), "original/transport path collision")
        dest.parent.mkdir(parents=True,exist_ok=True)
        with dest.open("xb") as f:
            f.write(raw)
    original = output / "original-source"
    for rel in provenance["files"]:
        path = original / rel
        path.parent.mkdir(parents=True,exist_ok=True)
        with path.open("xb") as stream:
            stream.write(read(runtime,rel))
    (crate/"source-receipt.json").write_text(json.dumps(provenance,sort_keys=True,indent=2)+"\n")
    return crate, provenance

def build_environment(rustc, target):
    env = os.environ.copy()
    removed=[]
    names={"RUSTFLAGS","RUSTDOCFLAGS","CARGO_ENCODED_RUSTFLAGS","CARGO_ENCODED_RUSTDOCFLAGS",
           "CARGO_BUILD_TARGET","RUSTC_WRAPPER","RUSTC_WORKSPACE_WRAPPER","RUSTC","RUSTDOC",
           "CARGO_TARGET_DIR","RUSTC_BOOTSTRAP","CARGO_BUILD_RUSTFLAGS",
           "CARGO_BUILD_RUSTC","CARGO_BUILD_RUSTC_WRAPPER","CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
           "CARGO_BUILD_TARGET_DIR"}
    for name in list(env):
        if name in names or name.startswith(("CARGO_TARGET_","CARGO_PROFILE_")):
            removed.append(name)
            del env[name]
    env["RUSTC"]=str(rustc)
    env["CARGO_TARGET_DIR"]=str(target)
    env["CARGO_TERM_COLOR"]="never"
    env["CARGO_ENCODED_RUSTFLAGS"]=""
    env["RUSTC_WRAPPER"]=""
    env["RUSTC_WORKSPACE_WRAPPER"]=""
    env["CARGO_INCREMENTAL"]="0"
    return env, sorted(removed)

def tool_identity(path):
    path = Path(path)
    require(path.is_absolute(), "explicit absolute Rust tool path required")
    resolved = path.resolve(strict=True)
    require(resolved.is_file() and os.access(resolved,os.X_OK), "Rust tool is not executable")
    return {"launch_path":str(path),"resolved_path":str(resolved),**pin(resolved.read_bytes())}

def process(output, label, command, cwd, env, timeout, input_relative=None):
    stdout=output/(label+".stdout")
    stderr=output/(label+".stderr")
    start=time.monotonic()
    started_unix_ns=time.time_ns()
    error=None
    exit_code=None
    timed_out=False
    pid=None
    with contextlib.ExitStack() as stack:
        so=stack.enter_context(stdout.open("xb"))
        se=stack.enter_context(stderr.open("xb"))
        stdin=(stack.enter_context(owned(output,input_relative).open("rb"))
               if input_relative is not None else subprocess.DEVNULL)
        try:
            child=subprocess.Popen(command,cwd=cwd,env=env,stdin=stdin,
                                   stdout=so,stderr=se,start_new_session=True)
            pid=child.pid
            try:
                exit_code=child.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out=True
                os.killpg(child.pid,signal.SIGKILL)
                exit_code=child.wait()
                error="deadline exceeded"
        except Exception as exc:
            error=f"{type(exc).__name__}: {exc}"
    receipt={"label":label,"command":list(command),"cwd":str(cwd),"timeout_seconds":timeout,
             "started_unix_ns":started_unix_ns,"finished_unix_ns":time.time_ns(),
             "duration_seconds":time.monotonic()-start,"pid":pid,"exit_code":exit_code,
             "timed_out":timed_out,"passed":type(exit_code) is int and exit_code==0 and error is None,
             "error":error,"stdout":{"path":stdout.name,**pin(stdout.read_bytes())},
             "stderr":{"path":stderr.name,**pin(stderr.read_bytes())}}
    if input_relative is not None:
        receipt["stdin"]={"path":input_relative,**pin(read(output,input_relative))}
    (output/(label+".execution.json")).write_text(json.dumps(receipt,sort_keys=True,indent=2)+"\n")
    return receipt

def package_identity(package):
    return {"name":package["name"],"version":package["version"],"source":package.get("source")}

def metadata_check(metadata, provenance, source_root, target, production=False):
    require(metadata.get("version") == 1, "Cargo metadata format changed")
    exact(metadata.get("workspace_root"),str(source_root),"Cargo metadata workspace path differs")
    exact(metadata.get("target_directory"),str(target),"Cargo metadata target directory differs")
    packages=metadata["packages"]
    byid={p["id"]:p for p in packages}
    require(len(byid)==len(packages),"duplicate metadata package identity")
    nodes=metadata["resolve"]["nodes"]
    node_by_id={v["id"]:v for v in nodes}
    require(len(node_by_id)==len(nodes),"duplicate Cargo resolve node")
    expected={(p["name"],p["version"],p["source"]):p for p in provenance["registry_dependencies"]}
    seen={}
    for package in packages:
        key=(package["name"],package["version"],package.get("source"))
        if key in expected:
            require(key not in seen,"duplicate selected package")
            node=node_by_id[package["id"]]
            features=node["features"]
            require(type(features) is list and all(type(v) is str for v in features)
                    and features==sorted(set(features)),"Cargo feature list is malformed")
            exact(features,provenance["production_features"][package["name"]+"@"+package["version"]],
                  "production feature union differs: "+package["name"])
            dependencies=[]
            for dependency in node["deps"]:
                child=byid.get(dependency["pkg"])
                require(child is not None,"unresolved metadata dependency")
                identity=package_identity(child)
                if identity not in dependencies:
                    dependencies.append(identity)
            dependencies.sort(key=lambda p:(p["name"],p["version"],p["source"] or ""))
            original_row=expected[key]
            original_packages=list(provenance["registry_dependencies"])
            # The normalized original closure is complete, including qualified
            # version tokens. It is sufficient to resolve each selected edge.
            wanted=normalize_lock_row(original_row,original_packages).get("dependencies",[])
            exact(dependencies,wanted,"Cargo actual dependency graph differs: "+package["name"])
            seen[key]={"features":features,"dependencies":dependencies,
                       "manifest_path":package["manifest_path"]}
    require(set(seen)==set(expected),"Cargo metadata omits a pinned original package")
    if not production:
        actual={(p["name"],p["version"],p.get("source")) for p in packages if p.get("source")}
        require(actual==set(expected),"oracle metadata contains a different dependency closure")
    root=byid.get(metadata["resolve"]["root"])
    require(root is not None,"Cargo resolve root missing")
    exact(root["name"],"hepta-runtime" if production else "hepta-shell-process-original-oracle",
          "Cargo metadata root package differs")
    return {name+"@"+version:details for (name,version,_),details in sorted(seen.items())}

def production_source(runtime, output, provenance, env, report):
    destination=output/"production-metadata-source"
    destination.mkdir()
    expected=provenance["production_metadata_inputs"]
    complete=all((runtime/rel).is_file() for rel in expected)
    material={}
    if complete:
        for rel in expected:
            material[rel]=read(runtime,rel)
        method="source-files"
    else:
        git=shutil.which("git",path=env.get("PATH"))
        require(git is not None,"Git required to recover missing pinned metadata-only inputs")
        git=Path(git).absolute()
        report["source_export_tool"]=tool_identity(git)
        command=[str(git),"-C",str(runtime),"archive",provenance["source_commit"],*sorted(expected)]
        record=process(output,"production-source-export",command,output,env,120)
        report["processes"].append(record)
        require(record["passed"],"pinned production metadata source export failed")
        archive=read(output,"production-source-export.stdout")
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
            exact(tar.pax_headers.get("comment"),provenance["source_commit"],"source archive commit differs")
            for member in tar.getmembers():
                require(not member.issym() and not member.islnk(),"source archive contains a link")
                if member.isdir():
                    continue
                require(member.isfile() and member.name in expected and member.name not in material,
                        "source archive member set differs")
                stream=tar.extractfile(member)
                require(stream is not None,"source archive file unavailable")
                material[member.name]=stream.read()
        method="fixed-commit-git-archive"
    exact(sorted(material),sorted(expected),"production metadata input closure differs")
    for rel,raw in material.items():
        blob=hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
        exact({**pin(raw),"git_blob_sha1":blob},expected[rel],"production metadata input differs: "+rel)
        path=destination/rel
        path.parent.mkdir(parents=True,exist_ok=True)
        with path.open("xb") as stream:
            stream.write(raw)
    receipt={"method":method,"source_commit":provenance["source_commit"],"files":expected,
             "production_crates_compiled":False}
    (destination/"source-receipt.json").write_text(json.dumps(receipt,sort_keys=True,indent=2)+"\n")
    report["production_source_materialization"]=receipt
    return destination

def registry_sources(metadata, provenance, output, retain=False):
    """Compare every compiled registry source byte to its original .crate hash."""
    expected={(p["name"],p["version"],p["source"]):p for p in provenance["registry_dependencies"]}
    packages=[]
    archives=output/"dependency-archives"
    if retain:
        archives.mkdir()
    for package in sorted(metadata["packages"],key=lambda p:(p["name"],p["version"])):
        key=(package["name"],package["version"],package.get("source"))
        if key not in expected:
            continue
        locked=expected[key]
        label=package["name"]+"-"+package["version"]
        manifest=Path(package["manifest_path"])
        source=manifest.parent
        require(manifest.name=="Cargo.toml" and source.name==label and source.parent.parent.name=="src",
                "unexpected Cargo registry source layout")
        registry=source.parent.parent.parent
        archive=registry/"cache"/source.parent.name/(label+".crate")
        archive_raw=owned(archive.parent,archive.name).read_bytes()
        exact(sha(archive_raw),locked["checksum"],"original locked crate archive checksum differs")
        retained=archives/(label+".crate")
        if retain:
            with retained.open("xb") as stream:
                stream.write(archive_raw)
        else:
            require(read(archives,label+".crate")==archive_raw,"retained original crate archive differs")
        files={}
        with tarfile.open(fileobj=io.BytesIO(archive_raw),mode="r:gz") as tar:
            for member in tar.getmembers():
                require(not member.issym() and not member.islnk(),"registry archive contains a link")
                if member.isdir():
                    continue
                prefix=label+"/"
                require(member.isfile() and member.name.startswith(prefix),"registry archive path differs")
                relative=member.name[len(prefix):]
                require(relative not in files,"duplicate registry archive member")
                stream=tar.extractfile(member)
                require(stream is not None,"registry archive member unreadable")
                raw=stream.read()
                require(read(source,relative)==raw,"actual cached crate source changed: "+label+"/"+relative)
                files[relative]=pin(raw)
        actual=set()
        for parent,dirs,names in os.walk(source,followlinks=False):
            require(all(not (Path(parent)/name).is_symlink() for name in dirs),
                    "registry source directory is a symlink")
            for name in names:
                actual.add((Path(parent)/name).relative_to(source).as_posix())
        allowed_generated={".cargo-ok",".cargo-checksum.json"}
        require(actual-set(files)<=allowed_generated,"unexpected extra source file in registry crate")
        generated={rel:pin(read(source,rel)) for rel in sorted(actual-set(files))}
        packages.append({
            "package":package_identity(package),"original_lock_checksum":locked["checksum"],
            "source_path":str(source),"archive_cache_path":str(archive),
            "retained_archive":{"path":str(retained.relative_to(output)),**pin(archive_raw)},
            "source_files":files,"cargo_generated_files":generated,
            "every_source_file_matches_original_archive":True})
    exact(len(packages),len(expected),"registry source archive closure incomplete")
    return {"schema":"hepta.runtime.shell-process-registry-source-check.v1",
            "packages":packages,"package_count":len(packages),
            "source_file_count":sum(len(p["source_files"]) for p in packages),
            "new_or_modified_registry_source_used":False}

def retained_registry_sources(metadata, provenance, output):
    """Read all captured original crate bytes without opening producer caches.

    The live producer still compares its expanded registry tree to these exact
    archives before and after the build. Its paths remain immutable provenance;
    a later reader obtains every original source byte from the retained .crate.
    The fixed Cargo 1.95 extraction marker is metadata, not compiled source.
    Any other unretained generated marker is refused, never silently ignored.
    """
    captured=decode(read(output,"registry-source-receipt.json"))
    require(type(captured) is dict and set(captured)=={
        "schema","packages","package_count","source_file_count","new_or_modified_registry_source_used"},
        "retained registry receipt fields differ")
    require(captured["schema"]=="hepta.runtime.shell-process-registry-source-check.v1"
            and captured["new_or_modified_registry_source_used"] is False,
            "retained registry receipt scope differs")
    expected={(p["name"],p["version"],p["source"]):p for p in provenance["registry_dependencies"]}
    selected=[]
    seen=set()
    for package in sorted(metadata["packages"],key=lambda p:(p["name"],p["version"])):
        key=(package["name"],package["version"],package.get("source"))
        if key not in expected:
            continue
        require(key not in seen,"duplicate selected registry package")
        seen.add(key)
        selected.append((package,expected[key]))
    require(seen==set(expected),"retained registry dependency closure incomplete")
    require(type(captured["packages"]) is list and len(captured["packages"])==len(selected),
            "retained registry package count differs")
    archives=output/"dependency-archives"
    ordinary_source_inventory(archives,[p["name"]+"-"+p["version"]+".crate" for p,_ in selected])
    packages=[]
    for (package,locked),claimed in zip(selected,captured["packages"]):
        require(type(claimed) is dict and set(claimed)=={
            "package","original_lock_checksum","source_path","archive_cache_path",
            "retained_archive","source_files","cargo_generated_files",
            "every_source_file_matches_original_archive"},"retained registry package fields differ")
        label=package["name"]+"-"+package["version"]
        manifest=Path(package["manifest_path"])
        source=manifest.parent
        require(manifest.is_absolute() and ".." not in manifest.parts
                and manifest.name=="Cargo.toml" and source.name==label
                and source.parent.parent.name=="src","unexpected captured Cargo registry source layout")
        archive=source.parent.parent.parent/"cache"/source.parent.name/(label+".crate")
        retained=archives/(label+".crate")
        archive_raw=read(archives,label+".crate")
        exact(sha(archive_raw),locked["checksum"],"retained original crate checksum differs")
        files={}
        members=set()
        with tarfile.open(fileobj=io.BytesIO(archive_raw),mode="r:gz") as tar:
            for member in tar:
                name=member.name.removesuffix("/") if member.isdir() else member.name
                parts=name.split("/")
                require(name and not name.startswith("/") and "\\" not in name
                        and all(part not in ("",".","..") for part in parts)
                        and parts[0]==label,"retained registry archive path differs")
                require(name not in members,"duplicate retained registry archive member")
                members.add(name)
                require(not member.issym() and not member.islnk(),"retained registry archive contains a link")
                if member.isdir():
                    continue
                require(member.isfile() and len(parts)>1,"retained registry archive member is not an ordinary source")
                relative="/".join(parts[1:])
                stream=tar.extractfile(member)
                require(stream is not None,"retained registry archive source unreadable")
                raw=stream.read()
                require(len(raw)==member.size,"retained registry archive source extent differs")
                files[relative]=pin(raw)
        require(files and "Cargo.toml" in files,"retained registry archive manifest missing")
        generated=claimed["cargo_generated_files"]
        require(type(generated) is dict and set(generated)== {".cargo-ok"},
                "unretained Cargo generated source is not admitted")
        generated={name:pin(b'{"v":1}') for name in generated}
        row={"package":package_identity(package),"original_lock_checksum":locked["checksum"],
             "source_path":str(source),"archive_cache_path":str(archive),
             "retained_archive":{"path":str(retained.relative_to(output)),**pin(archive_raw)},
             "source_files":files,"cargo_generated_files":generated,
             "every_source_file_matches_original_archive":True}
        exact(claimed,row,"retained original registry source record differs: "+label)
        packages.append(row)
    result={"schema":"hepta.runtime.shell-process-registry-source-check.v1",
            "packages":packages,"package_count":len(packages),
            "source_file_count":sum(len(p["source_files"]) for p in packages),
            "new_or_modified_registry_source_used":False}
    exact(captured,result,"retained registry summary differs")
    return result


def completed_process(output, label, row, command, cwd, timeout, input_relative=None):
    require(row.get("label")==label and row.get("passed") is True
            and type(row.get("exit_code")) is int and row["exit_code"]==0
            and row.get("timed_out") is False and row.get("error") is None,
            "original process failed or label changed: "+label)
    require(type(row.get("pid")) is int and row["pid"]>0,"original process PID invalid")
    if input_relative is None:
        require("stdin" not in row,"unexpected original process input")
    else:
        exact(row.get("stdin"),{"path":input_relative,**pin(read(output,input_relative))},
              "original process input bytes differ")
    exact(row.get("command"),command,"original process command changed: "+label)
    exact(row.get("cwd"),str(cwd),"original process cwd changed: "+label)
    exact(row.get("timeout_seconds"),timeout,"original process deadline changed: "+label)
    duration=row.get("duration_seconds")
    require(type(duration) in (int,float) and math.isfinite(duration) and 0<=duration<=timeout+3,
            "original process duration invalid")
    for name in ("started_unix_ns","finished_unix_ns"):
        require(type(row.get(name)) is int and row[name]>0,"original process timestamp invalid")
    require(row["finished_unix_ns"]>=row["started_unix_ns"],"original process time order invalid")
    exact(decode(read(output,label+".execution.json")),row,"separate process receipt differs")
    for suffix in ("stdout","stderr"):
        raw=read(output,label+"."+suffix)
        exact(row.get(suffix),{"path":label+"."+suffix,**pin(raw)},"actual process stream differs")
    return row

def read_evidence(runtime: Path, output: Path, rustc: Path | None = None, cargo: Path | None = None):
    """Strong captured-source reader; exact tools and invocation records remain required."""
    runtime=Path(runtime).absolute()
    output=Path(output).absolute()
    report=decode(read(output,"result.json"))
    require(report.get("schema")==SCHEMA and report.get("status")=="PASS" and report.get("error") is None,
            "original process reference is incomplete")
    for name in ("whole_runtime_replaced","production_shell_execution_qualified","old_stack_removal_qualified"):
        require(report.get(name) is False,"original reference overclaims production scope")
    provenance,extracted=original_sources(runtime,runtime/ORACLE_REL)
    exact(report.get("source_provenance"),provenance,"original source closure differs")
    crate=output/"crate"
    exact(decode(read(crate,"source-receipt.json")),provenance,"materialized source receipt differs")
    for rel in provenance["files"]:
        require(read(output/"original-source",rel)==read(runtime,rel),"retained complete original source changed")
    for rel,expected in provenance["test_transport_sources"].items():
        if rel=="source_manifest.json" or rel.endswith(".md"):
            continue
        exact(pin(read(crate,rel)),expected,"materialized fixture transport changed")
    for rel,raw in extracted.items():
        require(read(crate,rel)==raw,"complete original owner/test/extraction bytes changed")
    expected_crate={rel for rel in provenance["test_transport_sources"]
                    if rel!="source_manifest.json" and not rel.endswith(".md")}
    expected_crate.update(extracted)
    expected_crate.add("source-receipt.json")
    ordinary_source_inventory(crate,expected_crate)
    rustc=Path(rustc or report["build_tools"]["rustc"]["launch_path"])
    cargo=Path(cargo or report["build_tools"]["cargo"]["launch_path"])
    exact(report["build_tools"],{"rustc":tool_identity(rustc),"cargo":tool_identity(cargo)},
          "actual Rust build tools differ")
    removed=report.get("removed_build_environment_names")
    require(type(removed) is list and all(type(v) is str for v in removed) and removed==sorted(set(removed)),
            "build environment removal receipt malformed")
    exact(report.get("build_environment_overrides"),{
        "RUSTC":str(rustc),"CARGO_TARGET_DIR":str(output/"target"),"CARGO_TERM_COLOR":"never",
        "CARGO_ENCODED_RUSTFLAGS":"","RUSTC_WRAPPER":"","RUSTC_WORKSPACE_WRAPPER":"","CARGO_INCREMENTAL":"0"},
        "fixed reference build environment changed")
    require(type(report.get("offline")) is bool,"offline selection is not a boolean")
    prefix=[str(cargo)]+(["--offline"] if report["offline"] else [])
    source=output/"production-metadata-source"
    source_receipt=report["production_source_materialization"]
    require(source_receipt.get("method") in ("source-files","fixed-commit-git-archive"),
            "production metadata source method differs")
    exact(source_receipt,{"method":source_receipt["method"],"source_commit":provenance["source_commit"],
                          "files":provenance["production_metadata_inputs"],"production_crates_compiled":False},
          "production metadata source receipt changed")
    exact(decode(read(source,"source-receipt.json")),source_receipt,"separate metadata source receipt differs")
    for rel,expected in provenance["production_metadata_inputs"].items():
        raw=read(source,rel)
        blob=hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
        exact({**pin(raw),"git_blob_sha1":blob},expected,"production metadata source bytes differ")
    commands=[("rustc-version",[str(rustc),"--version","--verbose"],crate,30)]
    if source_receipt["method"]=="fixed-commit-git-archive":
        tool=report["source_export_tool"]
        git=Path(tool["launch_path"])
        exact(tool_identity(git),tool,"actual source export tool changed")
        commands.append(("production-source-export",[str(git),"-C",str(runtime),"archive",
                        provenance["source_commit"],*sorted(provenance["production_metadata_inputs"])],output,120))
    commands.extend([
        ("production-metadata",prefix+["metadata","--manifest-path",str(source/"Cargo.toml"),
                                      "--locked","--format-version","1"],source,180),
        ("metadata",prefix+["metadata","--manifest-path",str(crate/"Cargo.toml"),"--locked","--format-version","1"],crate,120),
        ("build",prefix+["build","--manifest-path",str(crate/"Cargo.toml"),"--locked","--release"],crate,240),
        ("original-tests",prefix+["test","--manifest-path",str(crate/"Cargo.toml"),"--locked","--release",
                                 "--","--nocapture","--test-threads=1"],crate,180)])
    require(type(report.get("processes")) is list and len(report["processes"])==len(commands),
            "original process recipe is incomplete")
    for row,(label,command,cwd,timeout) in zip(report["processes"],commands):
        completed_process(output,label,row,command,cwd,timeout)
    version=read(output,"rustc-version.stdout").decode()
    require(version.startswith("rustc 1.95.0 ") and "host: x86_64-unknown-linux-gnu\n" in version,
            "actual Rust version/host differs")
    exact(report["rustc_version"],version,"Rust version summary differs from actual stdout")
    production=decode(read(output,"production-metadata.stdout"))
    exact(report["production_metadata"],metadata_check(production,provenance,source,output/"target",True),
          "production metadata feature/edge summary differs")
    metadata=decode(read(output,"metadata.stdout"))
    exact(report["oracle_metadata"],metadata_check(metadata,provenance,crate,output/"target"),
          "oracle metadata feature/edge summary differs")
    registry=retained_registry_sources(metadata,provenance,output)
    exact(report["registry_source_verification"],registry,"actual original dependency source differs")
    exact(decode(read(output,"registry-source-receipt.json")),registry,"separate dependency source receipt differs")
    require(report.get("registry_sources_unchanged_after_build") is True,"post-build dependency source check absent")
    tests=read(output,"original-tests.stdout").decode()
    names=[]
    for file,values in provenance["original_test_names"].items():
        owner=Path(file).stem.removesuffix("_tests")
        names += ["mcp::fs::"+owner+"::"+owner+"_tests::"+name for name in values]
    exact(report.get("original_tests_executed"),names,"original test name set differs")
    exact(report.get("original_test_count"),21,"original test count differs")
    require(all("test "+name+" ... ok" in tests for name in names)
            and "21 passed; 0 failed; 0 ignored" in tests,"not every original test executed")
    executable=output/"target/release/hepta-shell-process-original-oracle"
    raw=owned(executable.parent,executable.name).read_bytes()
    require(raw[:7]==b"\x7fELF\x02\x01\x01","original oracle is not Linux ELF64")
    exact(report["executable"],{"path":str(executable),**pin(raw)},"actual oracle executable differs")
    return {"schema":"hepta.runtime.shell-process-original-evidence.v1","status":"PASS",
            "report_sha256":sha(read(output,"result.json")),"source_provenance":provenance,
            "actual_reference_processes":len(commands),"original_tests":21,
            "dependency_packages":len(registry["packages"]),
            "dependency_source_files":registry["source_file_count"],
            "registry_source_receipt_sha256":sha(read(output,"registry-source-receipt.json")),
            "production_metadata_sha256":sha(read(output,"production-metadata.stdout")),
            "oracle_metadata_sha256":sha(read(output,"metadata.stdout")),
            "executable":report["executable"],
            "fresh_original_rust_build_qualified":True,
            "native_process_comparison_performed":False,
            "whole_runtime_replaced":False,"production_shell_execution_qualified":False}

def run(runtime,output,rustc,cargo,offline=False):
    require(not output.exists(), "output must be a fresh directory")
    output.mkdir(parents=True)
    report={"schema":SCHEMA,"status":"FAIL","error":None,"processes":[],"offline":offline,
            "whole_runtime_replaced":False,"production_shell_execution_qualified":False,
            "old_stack_removal_qualified":False}
    start=time.monotonic()
    try:
        tools={"rustc":tool_identity(rustc),"cargo":tool_identity(cargo)}
        report["build_tools"]=tools
        crate,provenance=materialize(runtime,output)
        report["source_provenance"]=provenance
        env,removed=build_environment(rustc,output/"target")
        report["removed_build_environment_names"]=removed
        report["build_environment_overrides"]={name:env[name] for name in (
            "RUSTC","CARGO_TARGET_DIR","CARGO_TERM_COLOR","CARGO_ENCODED_RUSTFLAGS",
            "RUSTC_WRAPPER","RUSTC_WORKSPACE_WRAPPER","CARGO_INCREMENTAL")}
        prefix=[str(cargo)]+(["--offline"] if offline else [])
        def execute(label,command,cwd,timeout):
            row=process(output,label,command,cwd,env,timeout)
            report["processes"].append(row)
            require(row["passed"],"original "+label+" process failed; inspect retained stdout/stderr")
        execute("rustc-version",[str(rustc),"--version","--verbose"],crate,30)
        version=read(output,"rustc-version.stdout").decode()
        require(version.startswith("rustc 1.95.0 ") and "host: x86_64-unknown-linux-gnu\n" in version,
                "original reference requires Linux x86_64 Rust 1.95.0")
        report["rustc_version"]=version
        source=production_source(runtime,output,provenance,env,report)
        execute("production-metadata",prefix+["metadata","--manifest-path",str(source/"Cargo.toml"),
                                             "--locked","--format-version","1"],source,180)
        production=decode(read(output,"production-metadata.stdout"))
        report["production_metadata"]=metadata_check(production,provenance,source,output/"target",True)
        execute("metadata",prefix+["metadata","--manifest-path",str(crate/"Cargo.toml"),
                                  "--locked","--format-version","1"],crate,120)
        metadata=decode(read(output,"metadata.stdout"))
        report["oracle_metadata"]=metadata_check(metadata,provenance,crate,output/"target")
        registry=registry_sources(metadata,provenance,output,True)
        report["registry_source_verification"]=registry
        (output/"registry-source-receipt.json").write_text(json.dumps(registry,sort_keys=True,indent=2)+"\n")
        execute("build",prefix+["build","--manifest-path",str(crate/"Cargo.toml"),"--locked","--release"],crate,240)
        execute("original-tests",prefix+["test","--manifest-path",str(crate/"Cargo.toml"),"--locked","--release",
                                        "--","--nocapture","--test-threads=1"],crate,180)
        tests=read(output,"original-tests.stdout").decode()
        names=[]
        for file,values in provenance["original_test_names"].items():
            owner=Path(file).stem.removesuffix("_tests")
            names += ["mcp::fs::"+owner+"::"+owner+"_tests::"+name for name in values]
        require(all("test "+name+" ... ok" in tests for name in names)
                and "21 passed; 0 failed; 0 ignored" in tests,"not every original test executed")
        report["original_test_count"]=21
        report["original_tests_executed"]=names
        executable=output/"target/release/hepta-shell-process-original-oracle"
        require(executable.is_file(),"original oracle executable missing")
        report["executable"]={"path":str(executable),**pin(executable.read_bytes())}
        again,_=original_sources(runtime,runtime/ORACLE_REL)
        exact(again,provenance,"source/driver changed during qualification")
        exact(registry_sources(metadata,provenance,output,False),registry,"registry source changed during build")
        report["registry_sources_unchanged_after_build"]=True
        exact({"rustc":tool_identity(rustc),"cargo":tool_identity(cargo)},tools,"Rust tools changed during build")
        report["reference_runtime_libc"]=os.confstr("CS_GNU_LIBC_VERSION")
        report["status"]="PASS"
    except Exception as exc:
        report["error"]=f"{type(exc).__name__}: {exc}"
    report["duration_seconds"]=time.monotonic()-start
    result=output/"result.json"
    result.write_text(json.dumps(report,sort_keys=True,indent=2,allow_nan=False)+"\n")
    if report["status"]=="PASS":
        try:
            evidence=read_evidence(runtime,output,rustc,cargo)
            (output/"evidence.json").write_text(json.dumps(evidence,sort_keys=True,indent=2)+"\n")
        except Exception as exc:
            report["status"]="FAIL"
            report["error"]=f"post-build evidence reader: {type(exc).__name__}: {exc}"
            result.write_text(json.dumps(report,sort_keys=True,indent=2,allow_nan=False)+"\n")
    return report,result


BACKGROUND_SCHEMA="hepta.runtime.shell-background-original-comparison.v1"
BACKGROUND_DRIVER="tests/hia_native/shell_background_text.py"
BACKGROUND_ENVIRONMENT={"PATH":"/usr/bin:/bin","LANG":"C.UTF-8","LC_ALL":"C.UTF-8","TZ":"UTC"}

def background_native(runtime, native_corpus):
    """Load only the current pure reader; its native-execution branch is not used."""
    driver=owned(runtime,BACKGROUND_DRIVER)
    spec=importlib.util.spec_from_file_location("hia_shell_background_recorded_reader",driver)
    require(spec is not None and spec.loader is not None,"background reader cannot load")
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    raw_report=read(native_corpus,"report.json")
    report=decode(raw_report)
    require(type(report.get("files")) is dict,"native background member set missing")
    for relative,expected in report["files"].items():
        raw=read(native_corpus,relative)
        exact({"size":len(raw),"sha256":sha(raw)},expected,"native background artifact member differs")
    evidence=module.read_evidence(native_corpus)
    require(evidence.get("status")=="PASS","complete native background reader failed")
    cases=module.specifications()
    require(len(cases)==3456,"complete background semantic case set changed")
    requests=b"".join(len(wire).to_bytes(8,"little")+wire
                      for wire in (module.frame(**case["fields"]) for case in cases))
    require(read(native_corpus,"requests.bin")==requests,"full deterministic background input bytes differ")
    require(evidence["counts"]["semantic_cases"]==3456 and evidence["counts"]["controls"]==51,
            "background semantic/control partition differs")
    return module,cases,evidence

def background_comparison(cases, requests, native_responses, original_responses):
    """Compare complete independent Rust outputs, without calculating expected text."""
    input_at=native_at=original_at=0
    records=[]
    operations={"stable-full-log":0,"observed-tail-projection":0,"resource-uri":0,"job-id-from-uri":0}
    known_counts={"known":0,"unknown":0}
    names=set()
    def get_response(raw,at):
        require(at+16<=len(raw),"missing complete background response header")
        returned=int.from_bytes(raw[at:at+8],"little")
        extent=int.from_bytes(raw[at+8:at+16],"little")
        require(returned==extent and 48<=extent<0xfffffff0
                and at+16+extent<=len(raw),"background response extent/return invalid")
        body=raw[at+16:at+16+extent]
        require(body[:8]==b"HSHBGR01","background response magic differs")
        words=[int.from_bytes(body[i:i+8],"little") for i in (8,16,24,32,40)]
        require(words[0] in (0,1) and words[1] in (0,1)
                and 48+sum(words[2:])==len(body),"background typed response malformed")
        if words[0]==0:
            require(words==[0,0,0,0,0],"absent response carries values")
        return at+16+extent,body,returned
    for index,case in enumerate(cases):
        require(case["name"] not in names,"duplicate background semantic name")
        names.add(case["name"])
        require(input_at+8<=len(requests),"missing background request length")
        length=int.from_bytes(requests[input_at:input_at+8],"little")
        start=input_at+8
        require(length>=88 and start+length<=len(requests),"background request extent invalid")
        frame=requests[start:start+length]
        require(frame[:8]==b"HSHBGT01","background request magic differs")
        op=int.from_bytes(frame[8:16],"little")
        require(op in (1,2,3,4),"unknown background original operation")
        operations[("stable-full-log","observed-tail-projection","resource-uri","job-id-from-uri")[op-1]]+=1
        if op<=2:
            known_counts["known" if int.from_bytes(frame[16:24],"little") else "unknown"]+=1
        next_native,native,returned=get_response(native_responses,native_at)
        next_original,original,original_return=get_response(original_responses,original_at)
        if original!=native or returned!=original_return:
            mismatch=next((i for i,(a,b) in enumerate(zip(native,original)) if a!=b),
                          min(len(native),len(original)))
            raise ValueError("original/native background bytes differ: "+case["name"]
                             +" at body byte "+str(mismatch)
                             +"; native="+native[mismatch:mismatch+16].hex()
                             +"; original="+original[mismatch:mismatch+16].hex())
        records.append({"index":index,"name":case["name"],"operation":op,
                        "request_offset":input_at,"request":pin(frame),
                        "native_response_offset":native_at,"original_response_offset":original_at,
                        "return_u64":returned,"native_body":pin(native),"original_body":pin(original),
                        "complete_bytes_equal":True})
        input_at=start+length
        native_at=next_native
        original_at=next_original
    require(input_at==len(requests) and native_at==len(native_responses)
            and original_at==len(original_responses),"extra background stream bytes")
    return {"semantic_cases":len(records),"operation_counts":operations,"job_counts":known_counts,
            "cases":records,"request":pin(requests),"native_responses":pin(native_responses),
            "original_responses":pin(original_responses)}

def background_scope():
    return {"stable_file_original_reads_executed":True,
            "observed_tail_mode_is_pure_original_statement_projection":True,
            "observed_tail_filesystem_behavior_qualified":False,
            "native_filesystem_read_owner_qualified":False,
            "original_transport_control_cases":0,
            "production_shell_execution_qualified":False,"production_activated":False,
            "whole_runtime_replaced":False,"old_stack_removal_qualified":False}

def read_background_evidence(runtime, build_output, native_corpus, output, rustc=None, cargo=None):
    """Pure byte/receipt reader: no build, subprocess, native entry or live process read."""
    runtime=Path(runtime).absolute()
    build_output=Path(build_output).absolute()
    native_corpus=Path(native_corpus).absolute()
    output=Path(output).absolute()
    report=decode(read(output,"result.json"))
    require(report.get("schema")==BACKGROUND_SCHEMA and report.get("status")=="PASS"
            and report.get("error") is None,"background original comparison incomplete")
    exact(report.get("scope"),background_scope(),"background reference scope differs")
    build=read_evidence(runtime,build_output,rustc,cargo)
    exact(report.get("reference_build"),{"path":str(build_output),
          "report":pin(read(build_output,"result.json")),"evidence":build},
          "background reuse is not bound to the complete current fresh reference")
    module,cases,native=background_native(runtime,native_corpus)
    exact(report.get("native_corpus"),{"path":str(native_corpus),
          "report":pin(read(native_corpus,"report.json")),"evidence":native,
          "source":{"path":BACKGROUND_DRIVER,**pin(read(runtime,BACKGROUND_DRIVER))}},
          "native background evidence binding changed")
    require(read(output,"requests.bin")==read(native_corpus,"requests.bin"),
            "retained original stdin differs from the complete native corpus")
    require(read(output,"native-responses.bin")==read(native_corpus,"responses.bin"),
            "retained native response bytes differ")
    environment={**BACKGROUND_ENVIRONMENT,"TMPDIR":str(output/"temporary")}
    exact(report.get("execution_environment"),environment,"background process environment changed")
    require(type(report.get("processes")) is list and len(report["processes"])==1,
            "background original replay process missing")
    command=[build["executable"]["path"],"--background-render"]
    row=report["processes"][0]
    completed_process(output,"background-render",row,command,output,60,"requests.bin")
    require(row["started_unix_ns"]>=decode(read(build_output,"result.json"))["processes"][-1]["finished_unix_ns"],
            "background replay predates this fresh reference build")
    require(read(output,"background-render.stderr")==b"","original background replay emitted errors")
    comparison=background_comparison(cases,read(output,"requests.bin"),
                                    read(output,"native-responses.bin"),
                                    read(output,"background-render.stdout"))
    exact(report.get("comparison"),comparison,"complete original/native background comparison changed")
    return {"schema":"hepta.runtime.shell-background-original-evidence.v1","status":"PASS",
            "report_sha256":sha(read(output,"result.json")),
            "reference_report_sha256":build["report_sha256"],
            "executable":build["executable"],"fresh_original_rust_build_qualified":True,
            "original_tests":21,"actual_original_replay_processes":1,
            "semantic_cases":comparison["semantic_cases"],
            "operation_counts":comparison["operation_counts"],"job_counts":comparison["job_counts"],
            "native_transport_controls":native["counts"]["controls"],
            "complete_request":comparison["request"],
            "complete_original_responses":comparison["original_responses"],
            "complete_native_responses":comparison["native_responses"],
            "original_rust_compared":True,**background_scope()}

def run_background(runtime, build_output, native_corpus, output, rustc, cargo):
    require(not output.exists(),"background output must be a fresh directory")
    output.mkdir(parents=True)
    report={"schema":BACKGROUND_SCHEMA,"status":"FAIL","error":None,"processes":[],
            "scope":background_scope()}
    started=time.monotonic()
    try:
        build=read_evidence(runtime,build_output,rustc,cargo)
        report["reference_build"]={"path":str(build_output),
                                  "report":pin(read(build_output,"result.json")),"evidence":build}
        _,cases,native=background_native(runtime,native_corpus)
        report["native_corpus"]={"path":str(native_corpus),
            "report":pin(read(native_corpus,"report.json")),"evidence":native,
            "source":{"path":BACKGROUND_DRIVER,**pin(read(runtime,BACKGROUND_DRIVER))}}
        for source,dest in (("requests.bin","requests.bin"),("responses.bin","native-responses.bin")):
            with (output/dest).open("xb") as stream:
                stream.write(read(native_corpus,source))
        (output/"temporary").mkdir()
        environment={**BACKGROUND_ENVIRONMENT,"TMPDIR":str(output/"temporary")}
        report["execution_environment"]=environment
        row=process(output,"background-render",[build["executable"]["path"],"--background-render"],
                    output,environment,60,"requests.bin")
        report["processes"].append(row)
        require(row["passed"],"original background process failed; retained stdout/stderr contain diagnostics")
        require(read(output,"background-render.stderr")==b"","original background process emitted errors")
        report["comparison"]=background_comparison(cases,read(output,"requests.bin"),
            read(output,"native-responses.bin"),read(output,"background-render.stdout"))
        exact(read_evidence(runtime,build_output,rustc,cargo),build,
              "original reference source/build identity changed during background replay")
        exact(background_native(runtime,native_corpus)[2],native,
              "native background corpus changed during original replay")
        report["status"]="PASS"
    except Exception as error:
        report["error"]=type(error).__name__+": "+str(error)
    report["duration_seconds"]=time.monotonic()-started
    result=output/"result.json"
    result.write_text(json.dumps(report,sort_keys=True,indent=2,allow_nan=False)+"\n")
    if report["status"]=="PASS":
        try:
            evidence=read_background_evidence(runtime,build_output,native_corpus,output,rustc,cargo)
            (output/"evidence.json").write_text(json.dumps(evidence,sort_keys=True,indent=2)+"\n")
        except Exception as error:
            report["status"]="FAIL"
            report["error"]="post-replay evidence reader: "+type(error).__name__+": "+str(error)
            result.write_text(json.dumps(report,sort_keys=True,indent=2,allow_nan=False)+"\n")
    return report,result

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime",type=Path,default=ROOT)
    parser.add_argument("--output",type=Path,required=True)
    parser.add_argument("--rustc",type=Path,required=True)
    parser.add_argument("--cargo",type=Path,required=True)
    parser.add_argument("--offline",action="store_true")
    parser.add_argument("--reference-build",type=Path)
    parser.add_argument("--background-corpus",type=Path)
    args=parser.parse_args()
    if args.reference_build is not None or args.background_corpus is not None:
        if args.reference_build is None or args.background_corpus is None or args.offline:
            parser.error("background mode requires --reference-build and --background-corpus without --offline")
        report,path=run_background(args.runtime.absolute(),args.reference_build.absolute(),
            args.background_corpus.absolute(),args.output.absolute(),args.rustc,args.cargo)
    else:
        report,path=run(args.runtime.absolute(),args.output.absolute(),args.rustc,args.cargo,args.offline)
    print(canonical({"status":report["status"],"report":str(path),"processes":len(report["processes"]),
                     "original_test_count":report.get("original_test_count"),"error":report["error"],
                     "production_shell_execution_qualified":False,"whole_runtime_replaced":False}))
    return 0 if report["status"]=="PASS" else 1

if __name__=="__main__":
    raise SystemExit(main())
