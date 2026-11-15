"""Strict typed Bellman commitment source, native, and unchanged Rust evidence."""
from __future__ import annotations
import contextlib, importlib.util, io, json, math, os, struct, subprocess, sys, tomllib
from pathlib import Path
from hia_native_bellman_qualification import (digest, identity, read, decode, exact,
    packet_counts, checked_process)

ROOT = Path(__file__).resolve().parents[1]
DRIVERS = "tests/hia_native/bellman/commitment"
REFERENCE = "tests/hia_native/bellman/reference"
CORE_CORPUS = "tests/hia_native/bellman/qualify_bellman.py"
FOLDER = "bellman-commitment-native"
ORIGINAL_FOLDER = "bellman-commitment-original"
TEST = "test_bellman_commitment.py"
MODULE = {"key":"bellman_commitment", "name":"bellman-commitment",
          "source":"native/bellman_commitment.hepta", "standalone":"filter",
          "buffer_profile":"serde-json.v1", "companion_sources":("native/serde_filter_packer.hepta",),
          "manifest_env":"HIA_BELLMAN_COMMITMENT_MANIFEST", "test":TEST}
SCOPE = {"whole_handler_replaced":False,"whole_runtime_replaced":False,
         "production_activated":False,"old_stack_removal_qualified":False,
         "installed_source_digest_bound":False,"native_cases_added_by_reference":0}
ORIGINAL_COMMIT = "737acf6f901e46c57b0b4374e323e0d1132e0d49"
ORACLE_SHA = "138fe1b97af574a84b3c0e912f9941dfa0fb7dcaffd8f85e96855472b1a09717"
RESOLVED_LOCK_SHA = "c7012ff277fa183c0aed8252522fa7741b71e49a5d49ebb83a5d1f8de0480215"
TARGET_PINS = {
    "src/mcp/weight_bellman.rs": "254de61b7a169ab0a01583feb9562051fa9d477d89d98683263c52ea5545a4a7",
    "Cargo.lock": "1509860cac0e7f26e6a845edfec1c87ae3bd92380ecaa357457e5263e861d631",
    "Cargo.toml": "bf00111f6ec88df9df4d0d1d14c125a64ce4f6bdc6724ba20e70498f56dcae7f",
}
CORPUS_PINS = {
    "inputs.bin": {"bytes":16766288,"sha256":"5fa31e258b9ad6a93655e4d54fc7db920620a13880cb5afaaf1401884e7b15f3"},
    "native.bin": {"bytes":22517995,"sha256":"af4829843bd3d88bd16035a8e8ad04675338345dfce58d60a182ab8d0dcd8201"},
}
FILES = (
    "native/bellman_commitment.hepta", "native/bellman_commitment_composition.json",
    "native/bellman_commitment_abi.md", "scripts/hia_native_bellman_commitment_qualification.py",
    "scripts/hia_native_bellman_commitment_build.py", "tests/hia_native/"+TEST,
    *(DRIVERS+"/"+name for name in ("author_commitment.py","commitment_source.py",
        "make_commitment_oracle.py","qualify_commitment.py","reference.Cargo.lock")),
    *(REFERENCE+"/"+Path(name).name for name in TARGET_PINS), CORE_CORPUS,
    "native/serde_json.hepta", "native/binary_codec.hepta", "native/serde_filter_packer.hepta",
)

def driver(name):
    sys.path.insert(0,str(ROOT/DRIVERS))
    spec=importlib.util.spec_from_file_location("hia_bellman_commitment_"+Path(name).stem,ROOT/DRIVERS/name)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module

def checked_registry(reference, resolved):
    expected={(p["name"],p["version"],p.get("source")):p
              for p in tomllib.loads(reference.decode())["package"]}
    actual=[]
    for package in tomllib.loads(resolved.decode())["package"]:
        if "source" not in package:
            if package["name"]!="hia-bellman-commitment-reference" or package["version"]!="0.1.0":
                raise ValueError("unexpected commitment reference workspace package")
            continue
        key=(package["name"],package["version"],package["source"])
        if key not in expected or package.get("checksum")!=expected[key].get("checksum"):
            raise ValueError("commitment reference registry version/checksum differs from current target")
        actual.append({key:package[key] for key in ("name","version","source","checksum")})
    if len(actual)!=27: raise ValueError("commitment registry closure differs")
    return actual

def source_evidence(root=ROOT):
    root=Path(root).resolve()
    raw=read(root/"native/bellman_commitment_component.json");component=decode(raw)
    actual={name:identity(read(root/name)) for name in FILES}
    exact(component.get("files"),actual,"commitment component source closure differs")
    from hia_native_build import HEPTA_COMMIT
    if component.get("original_commit")!=ORIGINAL_COMMIT or component.get("compiler_commit")!=HEPTA_COMMIT:
        raise ValueError("commitment original/compiler pin differs")
    exact({key:component.get(key) for key in SCOPE},SCOPE,"unqualified commitment scope claim")
    migration=decode(read(root/"native/migration.json"))
    target_raw=read(root/"native/migration_target.json");target=decode(target_raw)
    exact(migration.get("migration_target"),{"path":"native/migration_target.json","sha256":digest(target_raw)},
          "commitment migration target binding differs")
    if target.get("target_commit")!=ORIGINAL_COMMIT: raise ValueError("commitment target commit differs")
    bound={}
    import hashlib
    for name,pin in TARGET_PINS.items():
        original=read(root/REFERENCE/Path(name).name)
        if digest(original)!=pin: raise ValueError("commitment exact original reference differs: "+name)
        rows=[row for row in target["source_files"] if row["path"]==name]
        blob=hashlib.sha1(b"blob "+str(len(original)).encode()+b"\0"+original).hexdigest()
        expected={"path":name,"mode":"100644","git_blob":blob,"bytes":len(original)}
        exact(rows,[expected],"commitment original copy differs from current target Git blob")
        bound[name]={**expected,"sha256":pin}
    resolved=read(root/DRIVERS/"reference.Cargo.lock")
    if digest(resolved)!=RESOLVED_LOCK_SHA: raise ValueError("commitment resolved lock differs")
    packages=checked_registry(read(root/REFERENCE/"Cargo.lock"),resolved)
    exact(packages,component.get("reference_registry_packages"),"commitment registry source receipt differs")
    composition=decode(read(root/"native/bellman_commitment_composition.json"))
    if (composition.get("source_sha256")!=actual[MODULE["source"]]["sha256"]
            or composition.get("public_handler_qualified") is not False):
        raise ValueError("commitment composition scope/source differs")
    return {"component_sha256":digest(raw),"source_files":actual,"target_files":bound,
            "original_commit":ORIGINAL_COMMIT,"migration_target_sha256":digest(target_raw),
            "compiler_commit":component["compiler_commit"],"compiler_sha256":component["compiler_image_sha256"],
            "native_image_sha256":component["native_image_sha256"],"standalone_sha256":component["standalone_sha256"],
            "composition":composition,"reference_registry_packages":packages}

def module_evidence(output, report):
    output=Path(output).resolve();source=source_evidence()
    relative="build/modules/bellman-commitment/manifest.json"
    raw=read(output/relative);metadata=decode(raw)
    expected={"manifest":relative,"sha256":digest(raw),"source":MODULE["source"],"builder":"borrowed_bytes"}
    exact(report["modules"][MODULE["key"]],expected,"commitment registered module receipt differs")
    if (metadata.get("name")!=MODULE["name"] or metadata.get("buffer_profile")!="serde-json.v1"
            or metadata.get("source_sha256")!=source["source_files"][MODULE["source"]]["sha256"]
            or metadata.get("image_sha256")!=source["native_image_sha256"]
            or metadata.get("compiler_sha256")!=source["compiler_sha256"]
            or metadata.get("compiler_commit")!=source["compiler_commit"]
            or (metadata.get("input_capacity"),metadata.get("output_capacity"),metadata.get("workspace_capacity"))
                !=(16<<20,64<<20,256<<20)):
        raise ValueError("commitment native image/source/compiler/capacity profile differs")
    from hia_native_loader import NativeModule
    module=NativeModule(output/relative,manifest_sha256=digest(raw));module.close()
    standalone=metadata.get("standalone",{})
    if (standalone.get("path")!="bellman-commitment.elf" or standalone.get("transport")!="filter"
            or standalone.get("runtime_libc_required") is not False or standalone.get("runtime_python_required") is not False
            or standalone.get("sha256")!=source["standalone_sha256"]):
        raise ValueError("commitment standalone transport differs")
    elf=(output/relative).parent/standalone["path"]
    if digest(read(elf))!=source["standalone_sha256"]: raise ValueError("commitment ELF bytes differ")
    return {"manifest":relative,"manifest_sha256":digest(raw),"source_sha256":metadata["source_sha256"],
            "image_sha256":metadata["image_sha256"],"compiler_sha256":metadata["compiler_sha256"],
            "standalone":str(elf.relative_to(output)),"standalone_sha256":standalone["sha256"]}

def proof_evidence(output, hepta=None):
    folder=Path(output)/FOLDER/"source-proof"
    if hepta is not None:
        folder.mkdir()
        driver("author_commitment.py").generate(Path(hepta).resolve(),ROOT,folder/"bellman_commitment.hepta")
    if (read(folder/"bellman_commitment.hepta")!=read(ROOT/MODULE["source"])
            or read(folder/"bellman_commitment.composition.json")!=read(ROOT/"native/bellman_commitment_composition.json")):
        raise ValueError("commitment complete regenerated HIA or composition differs")
    component=decode(read(ROOT/"native/bellman_commitment_component.json"))
    if digest(read(folder/"bellman_commitment.names.json"))!=component.get("generated_names_sha256"):
        raise ValueError("commitment source graph names differ")
    return {name:identity(read(folder/name)) for name in
            ("bellman_commitment.hepta","bellman_commitment.composition.json","bellman_commitment.names.json")}

def corpus_evidence(output, manifest_sha):
    folder=Path(output)/FOLDER/"corpus";raw=read(folder/"report.json");report=decode(raw)
    actual={name:identity(read(folder/name)) for name in CORPUS_PINS}
    exact(actual,CORPUS_PINS,"commitment complete fixed native corpus differs")
    exact(report.get("files"),actual,"commitment captured corpus identities differ")
    if (report.get("status")!="NATIVE_TYPED_COMMITMENT_PASS_RUST_REPLAY_REQUIRED"
            or report.get("manifest_sha256")!=manifest_sha or type(report.get("native_cases")) is not int
            or report["native_cases"]!=1142 or report.get("same_session_refusal_recovery") is not True
            or report.get("public_handler_qualified") is not False or report.get("whole_runtime_replaced") is not False
            or report.get("source_sha256")!=digest(read(ROOT/MODULE["source"]))
            or report.get("core_fixture_sha256")!=digest(read(ROOT/CORE_CORPUS))):
        raise ValueError("commitment native corpus source, coverage or scope differs")
    inputs=read(folder/"inputs.bin");outputs=read(folder/"native.bin")
    if packet_counts(inputs,output=False)!=(1142,0) or packet_counts(outputs,output=True)!=(1142,1):
        raise ValueError("commitment input/output packet domain differs")
    probe=driver("qualify_commitment.py");core=probe.load_core(ROOT/CORE_CORPUS)
    names=[name for name,_,_,_ in probe.corpus(core)]
    rows=report.get("cases",[])
    if len(rows)!=1142 or [row["name"] for row in rows]!=names: raise ValueError("commitment case order differs")
    left=right=0
    for row in rows:
        size=struct.unpack_from("<Q",inputs,left)[0];left+=8+size
        kind,extent=struct.unpack_from("<QQ",outputs,right);payload=outputs[right+16:right+16+extent];right+=16+extent
        exact({key:row.get(key) for key in ("input_bytes","status","kind","output_bytes","output_sha256")},
              {"input_bytes":size,"status":0xffffff00 if kind else extent,"kind":kind,
               "output_bytes":extent,"output_sha256":digest(payload)},"commitment per-case retained bytes differ")
        elapsed=row.get("wall_seconds")
        if type(elapsed) not in (int,float) or not math.isfinite(elapsed) or elapsed<0:
            raise ValueError("commitment native case timing is not a completed observation")
    component=decode(read(ROOT/"native/bellman_commitment_component.json"))
    for key in ("refusal_controls","trusted_installation_digest_controls"):
        exact(report.get(key),component.get(key),"commitment control domain differs")
    progress=[decode(line) for line in read(Path(output)/FOLDER/"driver.stdout").splitlines()]
    summary={key:report[key] for key in ("status","native_cases","wall_seconds","files")}
    exact(progress,[*rows[-3:],summary],"commitment complete native driver stdout differs")
    return {"status":"PASS","cases":1142,"budget_refusals":1,"report_sha256":digest(raw),"files":actual,
            "refusal_controls":23,"trusted_installation_digest_controls":33,"same_session_refusal_recovery":True}

def static_cases():
    probe=driver("qualify_commitment.py");core=probe.load_core(ROOT/CORE_CORPUS)
    cases=[("empty",[],b'{"states":[]}'),
           ("signed-zero",[[core.terminal(-0.)]+[None]*5],
            b'{"states":[{"actions":[{"kind":"terminal","value":-0.0},null,null,null,null,null]}]}'),
           ("ordered-fields",[[core.continuation(core.branch(-0.,4294967295,1e-5,1e16))]+[None]*5],
            b'{"states":[{"actions":[{"kind":"continue","branches":[{"probability":-0.0,"successor":4294967295,"reward":0.00001,"fee":1e+16}]},null,null,null,null,null]}]}')]
    import hashlib
    for name,graph,canonical in cases:
        request=hashlib.sha256(canonical).digest()
        source=TARGET_PINS["src/mcp/weight_bellman.rs"]
        plan=hashlib.sha256(probe.DOMAIN+source.encode()+b"\0"+request.hex().encode()).digest()
        result=b"HBCMTRES"+struct.pack("<Q",len(canonical))+request+bytes.fromhex(source)+plan+bytes(16)+canonical
        yield name,probe.encode(graph,core),result

def static_evidence(output, module, *, execute=False):
    folder=Path(output)/FOLDER/"static"
    if execute: folder.mkdir()
    executable=Path(output)/module["standalone"]
    rows={}
    for name,wire,expected in static_cases():
        receipt={"command":[str(executable)],"timeout_seconds":30,"exit_code":0,
                 "environment":{"PATH":"","LC_ALL":"C"},"executable_sha256":module["standalone_sha256"],
                 "stdin":identity(wire),"stdout":identity(expected),"stderr":identity(b"")}
        if execute:
            process=subprocess.run([str(executable)],input=wire,stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE,timeout=30,env=receipt["environment"])
            (folder/(name+".input")).write_bytes(wire)
            (folder/(name+".stdout")).write_bytes(process.stdout)
            (folder/(name+".stderr")).write_bytes(process.stderr)
            actual=dict(receipt,exit_code=process.returncode,stdout=identity(process.stdout),stderr=identity(process.stderr))
            (folder/(name+".json")).write_text(json.dumps(actual,indent=2)+"\n")
        exact(decode(read(folder/(name+".json"))),receipt,"commitment actual standalone process differs")
        if (read(folder/(name+".input"))!=wire or read(folder/(name+".stdout"))!=expected
                or read(folder/(name+".stderr"))):
            raise ValueError("commitment complete standalone bytes differ")
        rows[name]=receipt
    return rows

def suite_summary(output, report):
    source=source_evidence();module=module_evidence(output,report)
    return {"schema":"hepta.runtime.hia-bellman-commitment-native-suite.v1","status":"PASS","suite":TEST,
            "source":source,"module":module,"source_proof":proof_evidence(output),
            "corpus":corpus_evidence(output,module["manifest_sha256"]),
            "static_executions":static_evidence(output,module),"original_rust_replay_required":True,**SCOPE}

def run_native():
    output=Path(os.environ["HIA_BELLMAN_COMMITMENT_QUALIFICATION_OUTPUT"]).resolve()
    manifest=Path(os.environ[MODULE["manifest_env"]]).resolve()
    report={"modules":{MODULE["key"]:{"manifest":str(manifest.relative_to(output)),
        "sha256":digest(read(manifest)),"source":MODULE["source"],"builder":"borrowed_bytes"}}}
    source_evidence();module=module_evidence(output,report)
    base=output/FOLDER;base.mkdir()
    proof_evidence(output,os.environ["HIA_HEPTA_DIR"])
    captured=io.StringIO()
    try:
        with contextlib.redirect_stdout(captured):
            driver("qualify_commitment.py").qualify(ROOT,manifest,base/"corpus",ROOT/CORE_CORPUS)
    finally:
        (base/"driver.stdout").write_text(captured.getvalue())
    static_evidence(output,module,execute=True)
    summary=suite_summary(output,report)
    (base/"suite.json").write_text(json.dumps(summary,indent=2)+"\n")
    print(json.dumps(summary))

def native_evidence(output, report):
    expected=suite_summary(output,report)
    command=[sys.executable,"-I","-B",str(ROOT/"tests/hia_native"/TEST)]
    process,stdout=checked_process(output,report,TEST,command,phase="native_components",timeout=180)
    exact(decode(read(Path(output)/FOLDER/"suite.json")),expected,"commitment retained native suite differs")
    exact(decode(stdout),expected,"commitment complete native process stdout differs")
    row=next(row for row in report["checks"] if row["name"]==TEST)
    exact(row.get("summary"),expected,"commitment native process summary differs")
    return {"status":"PASS","suite":expected,"process":process,**SCOPE}

BUILD_VARIABLES = ("RUSTFLAGS","CARGO_ENCODED_RUSTFLAGS","CARGO_BUILD_TARGET","RUSTC_WRAPPER",
                   "RUSTC_WORKSPACE_WRAPPER","CARGO_BUILD_RUSTC","CARGO_BUILD_RUSTC_WRAPPER",
                   "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER","CARGO_BUILD_RUSTFLAGS")

def build_override(key):
    return (key in BUILD_VARIABLES or key.startswith("CARGO_PROFILE_")
            or (key.startswith("CARGO_TARGET_") and key.endswith("_RUSTFLAGS")))

def environment_policy():
    return {"names":list(BUILD_VARIABLES),"prefix":"CARGO_PROFILE_",
            "cargo_target_rustflags":True,"encoded_rustflags":""}

def reference_environment(inherited, rustc):
    env=dict(inherited)
    removed=sorted(key for key in env if build_override(key))
    for key in removed: env.pop(key,None)
    env["RUSTC"]=str(rustc)
    # An explicit empty highest-precedence flags value also suppresses inherited
    # Cargo configuration files' lower-precedence build/target rustflags.
    env["CARGO_ENCODED_RUSTFLAGS"]=""
    return env,{"RUSTC":str(rustc),"CARGO_ENCODED_RUSTFLAGS":"","removed_inherited_variables":removed,
                "removal_policy":environment_policy()}

def original_commands(output, rustc):
    folder=Path(output)/ORIGINAL_FOLDER;cargo=Path(rustc).with_name("cargo")
    config=["--config","build.rustc="+json.dumps(str(rustc))]
    commands={
        "bellman-commitment-rust-version":([str(rustc),"--version","--verbose"],15),
        "bellman-commitment-cargo-version":([str(cargo),"--version"],15),
        "bellman-commitment-rust-extract":([sys.executable,"-I","-B",str(ROOT/DRIVERS/"make_commitment_oracle.py"),
            "--original",str(ROOT/REFERENCE/"weight_bellman.rs"),"--original-lock",str(ROOT/REFERENCE/"Cargo.lock"),
            "--original-manifest",str(ROOT/REFERENCE/"Cargo.toml"),"--resolved-lock",str(ROOT/DRIVERS/"reference.Cargo.lock"),
            "--output",str(folder)],180),
        "bellman-commitment-cargo-metadata":([str(cargo),*config,"metadata","--locked","--format-version=1",
            "--manifest-path",str(folder/"Cargo.toml")],180),
    }
    for label,flags in (("debug",[]),("release",["--release"])):
        commands["bellman-commitment-rust-build-"+label]=([str(cargo),*config,"build","--locked",*flags,
            "--manifest-path",str(folder/"Cargo.toml"),"--target-dir",str(folder/"target")],180)
        commands["bellman-commitment-rust-replay-"+label]=([str(folder/"target"/label/"hia-bellman-commitment-reference")],180)
    return commands

def compiler_identity(path):
    path=Path(path)
    return {"invocation_path":str(path),"resolved_path":str(path.resolve()),**identity(read(path.resolve()))}

def metadata_evidence(raw, component):
    metadata=decode(raw)
    packages={row["id"]:row for row in metadata["packages"]}
    registry={}
    roots=[]
    for node in metadata["resolve"]["nodes"]:
        package=packages[node["id"]]
        if package.get("source") is None:
            roots.append((package["name"],package["version"],node["features"]))
        else:
            registry[package["name"]+"@"+package["version"]]=node["features"]
    exact(roots,[["hia-bellman-commitment-reference","0.1.0",[]]],"commitment metadata workspace differs")
    exact(registry,component.get("reference_features"),"commitment actual Cargo feature closure differs")
    return registry

def compare_original(output, report, rustc):
    import qualify_hia_runtime_native as q
    output=Path(output).resolve();native_evidence(output,report)
    folder=output/ORIGINAL_FOLDER;folder.mkdir()
    wire=read(output/FOLDER/"corpus/inputs.bin");expected=read(output/FOLDER/"corpus/native.bin")
    (folder/"inputs.bin").write_bytes(wire);(folder/"expected-native.bin").write_bytes(expected)
    cargo=Path(rustc).with_name("cargo")
    before={"rustc":compiler_identity(rustc),"cargo":compiler_identity(cargo)}
    env,binding=reference_environment(q.qualification_env(),rustc)
    (folder/"build-environment.json").write_text(json.dumps(binding,indent=2)+"\n")
    component=decode(read(ROOT/"native/bellman_commitment_component.json"))
    for name,(command,timeout) in original_commands(output,rustc).items():
        replay="-replay-" in name
        result=q.record_check(output,report,name=name,command=command,timeout=timeout,env=env,
                              input_bytes=wire if replay else None)
        report["checks"][-1]["environment_binding"]=binding
        if replay: report["checks"][-1]["stdin"]=identity(wire)
        q.save_report(output/"result.json",report)
        if replay and (result.stdout!=expected or result.stderr):
            raise ValueError("commitment complete actual original replay differs: "+name)
        if name.endswith("rust-version") and not result.stdout.startswith(b"rustc 1.95.0 "):
            raise ValueError("commitment original requires Rust 1.95.0")
        if name.endswith("cargo-version") and not result.stdout.startswith(b"cargo 1.95.0 "):
            raise ValueError("commitment original requires Cargo 1.95.0")
        if name.endswith("cargo-metadata"):
            metadata_evidence(result.stdout,component)
            checked_registry(read(ROOT/REFERENCE/"Cargo.lock"),read(folder/"Cargo.lock"))
    exact(before,{"rustc":compiler_identity(rustc),"cargo":compiler_identity(cargo)},
          "commitment selected compiler bytes changed during reference build")
    return original_evidence(output,report,rustc)

def original_evidence(output, report, rustc):
    output=Path(output).resolve();native=native_evidence(output,report)
    folder=output/ORIGINAL_FOLDER;component=decode(read(ROOT/"native/bellman_commitment_component.json"))
    wire=read(output/FOLDER/"corpus/inputs.bin");expected=read(output/FOLDER/"corpus/native.bin")
    if read(folder/"inputs.bin")!=wire or read(folder/"expected-native.bin")!=expected:
        raise ValueError("commitment original replay corpus differs")
    program=read(folder/"oracle.rs");extraction=decode(read(folder/"extraction.json"))
    if (digest(program)!=ORACLE_SHA or extraction.get("oracle_sha256")!=ORACLE_SHA
            or extraction.get("original_commit")!=ORIGINAL_COMMIT
            or extraction.get("original_sha256")!=TARGET_PINS["src/mcp/weight_bellman.rs"]
            or extraction.get("original_lock_sha256")!=TARGET_PINS["Cargo.lock"]
            or extraction.get("original_manifest_sha256")!=TARGET_PINS["Cargo.toml"]
            or extraction.get("resolved_lock_sha256")!=RESOLVED_LOCK_SHA
            or read(folder/"weight_bellman.rs")!=read(ROOT/REFERENCE/"weight_bellman.rs")
            or read(folder/"target-Cargo.lock")!=read(ROOT/REFERENCE/"Cargo.lock")
            or digest(read(folder/"Cargo.lock"))!=RESOLVED_LOCK_SHA
            or digest(read(folder/"Cargo.toml"))!=component.get("oracle_manifest_sha256")):
        raise ValueError("commitment unchanged original extraction or locked manifest differs")
    exact(extraction.get("unchanged_extractions"),component.get("unchanged_extractions"),
          "commitment original serde/writer/identity pieces differ")
    profile=read(ROOT/REFERENCE/"Cargo.toml").decode().split("[profile.release]",1)[1].split("[dependencies]",1)[0]
    profile=("[profile.release]"+profile).encode()
    if (read(folder/"Cargo.toml").count(profile)!=1
            or extraction.get("unchanged_release_profile_sha256")!=digest(profile)):
        raise ValueError("commitment original release profile differs")
    binding=decode(read(folder/"build-environment.json"))
    removed=binding.get("removed_inherited_variables")
    if (type(removed) is not list or removed!=sorted(set(removed))
            or any(type(key) is not str or not build_override(key) for key in removed)):
        raise ValueError("commitment reference environment provenance differs")
    exact(binding,{"RUSTC":str(rustc),"CARGO_ENCODED_RUSTFLAGS":"","removed_inherited_variables":removed,
                   "removal_policy":environment_policy()},
          "commitment compiler/profile environment differs")
    processes={};features=None
    for name,(command,timeout) in original_commands(output,rustc).items():
        replay="-replay-" in name
        process,stdout=checked_process(output,report,name,command,phase="original_rust_comparison",timeout=timeout,
            stdin=wire if replay else None,empty_stderr="-build-" not in name and not name.endswith("cargo-metadata"))
        row=next(row for row in report["checks"] if row["name"]==name)
        exact(row.get("environment_binding"),binding,"commitment actual process environment binding differs")
        if replay and stdout!=expected: raise ValueError("commitment full captured Rust output differs")
        if name.endswith("rust-version") and not stdout.startswith(b"rustc 1.95.0 "):
            raise ValueError("commitment Rust version differs")
        if name.endswith("cargo-version") and not stdout.startswith(b"cargo 1.95.0 "):
            raise ValueError("commitment Cargo version differs")
        if name.endswith("rust-extract"):
            exact(decode(stdout),extraction,"commitment actual extraction process stdout differs")
        if name.endswith("cargo-metadata"): features=metadata_evidence(stdout,component)
        processes[name]=process
    return {"status":"PASS","reference_kind":"unchanged current-target typed serde and commitment owner",
            "source":native["suite"]["source"],"module":native["suite"]["module"],
            "cases":1142,"budget_refusals":1,"input_stream":identity(wire),"native_output_stream":identity(expected),
            "original_commit":ORIGINAL_COMMIT,"extraction":extraction,"features":features,
            "reference_registry_packages":checked_registry(read(ROOT/REFERENCE/"Cargo.lock"),read(folder/"Cargo.lock")),
            "compiler":{"rustc":compiler_identity(rustc),"cargo":compiler_identity(Path(rustc).with_name("cargo"))},
            "build_environment":binding,"processes":processes,
            "binaries":{label:identity(read(folder/"target"/label/"hia-bellman-commitment-reference"))
                        for label in ("debug","release")},**SCOPE}
