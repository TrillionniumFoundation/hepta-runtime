"""Strong original source/lock/registry/process reader, extended to span v2."""
from pathlib import Path
import io
import json
import sys
import tarfile
import tomllib
from read_capture import SHA, PacketStream, file_pin, observation, parse, pin, read, require
from extract_reference import TARGET_COMMIT, TARGET_SHA, LOCK_SHA, extract, CARGO

ROOT = Path(__file__).resolve().parent
DOMAIN = parse(read(ROOT / "DOMAIN.json"))
EXPECTED = dict(cases=len(DOMAIN["cases"]), input_bytes=DOMAIN["input_bytes"], input_sha256=DOMAIN["input_sha256"])


def encoded(value):
    return (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+"\n").encode()


def opened(path):
    path=Path(path)
    require(path.is_file() and path.resolve()==path.absolute(),"nonordinary physical evidence copy")
    return path.open("rb")


def compare_original(native_directory, original_stdout):
    with PacketStream(Path(native_directory)/"observed.bin.gz") as native, PacketStream(original_stdout,compressed=False) as original:
        for _ in range(EXPECTED["cases"]):
            left,right = native.take(),original.take()
            require(left is not None and left == right,"complete unchanged original methods differ from HIA")
            observation(right)
        first,second = native.finish(),original.finish()
    require(first == second and first["count"] == EXPECTED["cases"],"complete original stream differs")
    return dict(status="PASS",**first,unchanged_original_methods=True,actual_target_constructor=True,actual_tracing_warning=True)


def process_evidence(process, folder, *, name, timeout, expected_pid=None):
    require(process["name"] == name and process["timeout_seconds"] == timeout, "process name/deadline differs")
    require(process["exit_code"] == 0 and process["timed_out"] is False and process["completed"] is True,
            "process did not complete successfully")
    require(type(process["pid"]) is int and process["pid"] > 0 and process["pgid"] == process["pid"], "owned process identity differs")
    if expected_pid is not None:
        require(process["pid"] == expected_pid, "native execution PID differs from its actual process")
    require(type(process["elapsed_seconds"]) in (int, float) and 0 <= process["elapsed_seconds"] < timeout,
            "process exceeded its declared deadline")
    require(type(process["parent_pid"]) is int and process["parent_pid"] > 0, "process parent identity differs")
    for stream in ("stdout", "stderr"):
        relative = process[stream]["file"]
        require(Path(relative).name == relative, "process stream path escapes custody")
        require(file_pin(folder/relative) == {k: process[stream][k] for k in ("bytes", "sha256")}, "process stream changed")
    return process



def original_evidence(directory,native_directory,*,source_root=ROOT):
    root=Path(source_root).resolve(strict=True)
    directory=Path(directory).resolve(strict=True)
    from extract_reference import TARGET_COMMIT,TARGET_SHA,LOCK_SHA,extract,CARGO
    reference=root/"reference"
    build=parse(read(directory/"build.json"))
    require(build["schema"]=="hepta.scope-annotation.actual-original-build.v1" and build["target_commit"]==TARGET_COMMIT
        and build["target_sha256"]==TARGET_SHA and build["target_lock_sha256"]==LOCK_SHA,"original target differs")
    require(build["actual_target_sdk_built"] is True and build["actual_target_sdk_executed"] is False
        and build["fresh_target_dir"] is True and build["production_activated"] is False and build["whole_runtime_replaced"] is False,
        "original build scope differs")
    generated,extracted=extract(read(reference/"target/src/mcp/runtime/caller_scope.rs"))
    require(read(directory/"reference-project/main.rs")==generated and read(directory/"reference-project/Cargo.toml")==CARGO,
        "compiled original source differs")
    require(build["source_sha256"]==SHA(generated) and build["cargo_sha256"]==SHA(CARGO)
        and build["extracted"]==extracted and build["profile"]=="exact target [profile.dev]","original extraction/profile differs")
    require(build["binary_file"]=="scope-annotation-original","original binary basename differs")
    require(file_pin(directory/build["binary_file"])==dict(bytes=build["binary_bytes"],sha256=build["binary_sha256"]),
        "executed original binary differs")
    require(build["rust_version"].splitlines()[0].startswith("rustc 1.95.0 ")
        and build["cargo_version"].splitlines()[0].startswith("cargo 1.95.0 "),"original toolchain differs")
    require(build["process_count"]==5,"fresh build process count differs")
    env=parse(read(directory/"reference-environment.json"))
    require(env==build["environment"] and env["cargo_encoded_rustflags_override"]=="","reference environment receipt differs")
    explicit=env["explicit_reference_environment"]
    for name in ("RUSTC_WRAPPER","RUSTC_WORKSPACE_WRAPPER","CARGO_BUILD_RUSTC_WRAPPER","CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
                 "CARGO_ENCODED_RUSTFLAGS","CARGO_ENCODED_RUSTDOCFLAGS","CARGO_BUILD_RUSTFLAGS"):
        require(explicit.get(name)=="","compiler wrapper/flags override survived")
    require(explicit["CARGO_BUILD_TARGET"]=="x86_64-unknown-linux-gnu","reference target differs")
    lock=read(directory/"reference-project/Cargo.lock")
    require(SHA(lock)==build["fixture_lock_sha256"],"compiled fixture lock differs")
    target_lock=read(reference/"target/Cargo.lock")
    originals={(p["name"],p["version"],p.get("source")):p.get("checksum")for p in tomllib.loads(target_lock.decode())["package"]if p.get("source")}
    wanted=[]
    for package in tomllib.loads(lock.decode())["package"]:
        if not package.get("source"):
            require(package["name"]=="scope-annotation-original","unbound local dependency")
            continue
        key=package["name"],package["version"],package["source"]
        require(originals.get(key)==package["checksum"],"registry dependency drifted from exact target lock")
        wanted.append({k:package[k]for k in ("name","version","source","checksum")})
    subset=parse(read(directory/"lock-subset.json"))
    require(subset["schema"]=="hepta.scope-annotation.target-lock-subset.v1" and subset["target_lock_sha256"]==LOCK_SHA
        and subset["fixture_lock_sha256"]==SHA(lock) and subset["retained_registry_packages"]==wanted,"registry subset differs")
    require(subset["all_retained_exactly_match_target"] is True and subset["actual_sdk_constructor_dependencies_match"] is True
        and subset["offline_resolution"] is True,"reference dependency custody not established")
    found,registry_artifacts=registry_evidence(directory,reference,subset,originals,wanted)
    return original_process_evidence(directory,native_directory,build,explicit,found,registry_artifacts,extracted)


def registry_evidence(directory,reference,subset,originals,wanted):
    found=set();artifacts={};sdk=False
    for package in subset["registry_source_verification"]:
        key=package["name"],package["version"],package["source"]
        require(key not in found and originals.get(key)==package["checksum"],"unbound/duplicate archived registry package")
        found.add(key)
        crate=package["name"]+"-"+package["version"]
        relative="registry/"+crate+".crate"
        require(package["archive_file"]==relative and Path(crate).name==crate,"crate path differs")
        raw=read(directory/relative,128<<20)
        require(SHA(raw)==package["checksum"]==package["archive_sha256"],"actual retained crate archive changed")
        artifacts[relative]=SHA(raw)
        files={}
        with tarfile.open(fileobj=io.BytesIO(raw),mode="r:gz")as archive:
            for member in archive.getmembers():
                parts=Path(member.name).parts
                require(parts and parts[0]==crate and not Path(member.name).is_absolute() and ".."not in parts,"crate member path escapes custody")
                if member.isdir():continue
                require(member.isfile(),"non-file crate member")
                name=str(Path(*parts[1:]));content=archive.extractfile(member).read()
                require(name not in files,"duplicate retained crate member")
                files[name]=SHA(content)
                if package["name"]=="rmcp"and name in ("src/model.rs","src/model/content.rs"):
                    require(content==read(reference/"sdk"/name),"actual constructor source differs from admitted dependency")
        require(files==package["source_files"] and len(files)==package["files_verified"],"complete registry source file inventory differs")
        if package["name"]=="rmcp":
            require(package["version"]=="3.9.0"and all(n in files for n in ("src/model.rs","src/model/content.rs")),"SDK source closure incomplete")
            sdk=True
    require(found=={(p["name"],p["version"],p["source"])for p in wanted}and sdk,"registry package set differs")
    return found,artifacts


def original_process_evidence(directory,native_directory,build,explicit,found,registry_artifacts,extracted):
    processes=parse(read(directory/"processes/processes.json"))
    expected=(("reference-target-head",30),("reference-rustc-version",60),("reference-cargo-version",60),
              ("reference-metadata",180),("reference-build",900),("original-replay",180))
    require([p["name"]for p in processes]==[n for n,_ in expected],"original process set differs")
    require(len({p["parent_pid"] for p in processes}) == 1, "fresh original process ownership differs")
    for process,(name,timeout)in zip(processes,expected,strict=True):
        process_evidence(process,directory/"processes",name=name,timeout=timeout)
    require(read(directory/"processes/reference-target-head.stdout").strip().decode()==build["target_commit"],"actual target checkout differs")
    require(read(directory/"processes/reference-rustc-version.stdout").decode()==build["rust_version"]
        and read(directory/"processes/reference-cargo-version.stdout").decode()==build["cargo_version"],"actual version output differs")
    require(processes[1]["argv"]==[explicit["RUSTC"],"--version","--verbose"],"actual rustc command differs")
    cargo=str(Path(explicit["RUSTC"]).parent/"cargo")
    require(processes[2]["argv"]==[cargo,"--version","--verbose"]
        and processes[3]["argv"]==[cargo,"metadata","--offline","--format-version","1"]
        and processes[4]["argv"]==[cargo,"build","--locked","--offline","--target","x86_64-unknown-linux-gnu","--bin","scope-annotation-original"],
        "actual locked original compile recipe differs")
    require(Path(processes[3]["cwd"]).name=="reference-project"and processes[3]["cwd"]==processes[4]["cwd"],"compile cwd differs")
    prior_root=Path(processes[3]["cwd"]).parent
    require(processes[5]["argv"]==[str(prior_root/"scope-annotation-original")],"actual replay binary differs")
    require(explicit["CARGO_TARGET_DIR"]==str(prior_root/"cargo-target"),"fresh Cargo target custody differs")
    metadata=parse(read(directory/"processes/reference-metadata.stdout"))
    actual_packages={(p["name"],p["version"],p["source"])for p in metadata["packages"]if p.get("source")}
    require(actual_packages==found,"actual Cargo metadata package set differs")
    require(metadata["target_directory"]==explicit["CARGO_TARGET_DIR"],"actual Cargo metadata target differs")
    replay=processes[-1]
    require(replay["stdin"]==dict(file="original-replay.stdin",bytes=EXPECTED["input_bytes"],sha256=EXPECTED["input_sha256"]),"complete replay stdin receipt differs")
    require(file_pin(directory/"processes/original-replay.stdin")==dict(bytes=EXPECTED["input_bytes"],sha256=EXPECTED["input_sha256"]),"complete actual replay stdin changed")
    require(replay["stderr"]["bytes"]==0,"original replay stderr is nonempty")
    comparison=compare_original(native_directory,directory/"processes/original-replay.stdout")
    return dict(schema="hepta.scope-annotation.original-evidence.v1",status="PASS",comparison=comparison,
        target_commit=build["target_commit"],target_file_sha256=build["target_sha256"],target_lock_sha256=build["target_lock_sha256"],
        binary_sha256=build["binary_sha256"],actual_processes=len(processes),retained_registry_packages=len(found),
        registry_artifact_sha256=registry_artifacts,source_extracted_annotate_sha256=extracted["annotate"]["sha256"],
        actual_target_constructor=True,exact_target_dev_profile=True,production_activated=False,whole_runtime_replaced=False)


