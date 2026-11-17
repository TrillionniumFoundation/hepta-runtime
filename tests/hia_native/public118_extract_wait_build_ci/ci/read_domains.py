"""Read the split Authority and connection domains against the actual default111 graph."""
from pathlib import Path
from functools import lru_cache
import argparse,importlib,json,sys
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import pin,require,files
from domain_support import doc,load,check_origin,record_process,graph_identity
import read_build,read_all
FLAGS=("full_sdk_qualified","full_async_runtime_qualified","production_activated","old_path_removed")
PREPARED={}
def prepare(package,role):
    package=Path(package).resolve(strict=True)
    key=(str(package),role)
    if key in PREPARED:return PREPARED[key]
    authority=package/"joint/authority";drivers=authority/"drivers"
    sys.path.insert(0,str(package/"joint/authority-runner"))
    aggregate=load("_public111_retained_authority_imports",package/"joint/authority-runner/verify_complete.py")
    value={"aggregate":aggregate}
    if role=="owner":
        with aggregate.isolated():
            owner=load("_public111_owner_qualifier",authority/"owner-reference/tests/hia_native/caller_owner_export/qualify.py")
            import controls
            owner.source_evidence(authority/"owner-reference")
            value["owner"]=owner
            value["owner_modules"]={n:sys.modules[n] for n in aggregate.ISOLATED if n in sys.modules}
    elif role=="profiles":
        retained=load("_public111_retained_profiles",drivers/"verify_authority_retained.py")
        retained.load_reader=lru_cache(maxsize=None)(retained.load_reader)
        with aggregate.isolated():retained.load_reader(authority/"authority-retained")
        with aggregate.isolated():retained.load_reader(authority/"authority-historical")
        value["retained"]=retained
        read_build.prepare(package)
    elif role in ("authority","connection"):
        read_build.prepare(package)
        sys.path.insert(0,str(package/"ci/authority"))
        if role=="authority":
            private=load("_public111_private_reader",package/"ci/authority/verify_private_binding.py")
            sys.modules["verify_private_binding"]=private
            value["private"]=private
            value["bridge"]=load("_public111_owner_observation",package/"ci/authority/public_owner_reference.py")
        else:
            value["public"]=load("_public111_public90",package/"ci/authority/verify_public.py")
            value["transport"]=load("_public111_transport",drivers/"verify_transport_reference.py")
            with aggregate.isolated():
                handshake=load("_public111_handshake",package/"ci/authority/verify_handshake.py")
                handshake.original_module=lru_cache(maxsize=None)(handshake.original_module)
                handshake.original_module(authority/"handshake-reference")
            value["handshake"]=handshake
            sys.path.insert(0,str(authority/"transport-reference/drivers"))
            import transport_cases
            value["baseline"]=aggregate.baseline
    else:raise ValueError("unknown complete role")
    sys.path.insert(0,str(package/"wire"))
    wire=importlib.import_module("read_wire_guarded")
    value.update(wire=wire,guard=wire.prepare(package/"port"))
    PREPARED[key]=value;return value

def graph_view(build,run):
    origin=doc(build/"BUILD_ORIGIN.json");producer=Path(origin["output"])
    expected={};mapping={}
    for label in ("production/build/public-task-batch","instances/task-pump"):
        md=doc(build/label/"manifest.json")
        for item in [*md["members"],md["link"],md["pack"]]:
            absolute=Path(item["manifest"]);relative=absolute.relative_to(producer)
            mapping[str(absolute)]=relative.as_posix()
            for p in (build/relative).parent.iterdir():
                if p.is_file():expected[p.relative_to(build).as_posix()]=pin(p)
        absolute=Path(md["packed_capabilities"]["57"]["build_root"])/"bellman-port-packed.elf"
        relative=absolute.relative_to(producer);mapping[str(absolute)]=relative.as_posix()
        expected[relative.as_posix()]=pin(build/relative)
    wanted={"schema":"hepta.public-authority.portable-module-map.v1","modules":mapping}
    require(doc(run/"graph-view/module-map.json")==wanted,"exact observer module relocation map")
    expected["module-map.json"]=pin(run/"graph-view/module-map.json")
    require(files(run/"graph-view")==expected,"complete unaliased observed module copies")
    require(doc(run/"module-map.json")=={"schema":wanted["schema"],
        "modules":{k:"graph-view/"+v for k,v in mapping.items()}},"capture module view association")

def verify(package,run,manifest_sha256,role,dependencies,prepared):
    origin=check_origin(package,run,manifest_sha256,role,dependencies)
    authority=package/"joint/authority";drivers=authority/"drivers";aggregate=prepared["aggregate"]
    # This verifies every unchanged historical input and its current nine-member
    # authority source binding. The actual 111 graph is admitted independently.
    closure=aggregate.check(authority)
    py=[origin["python"],"-I","-S","-B"]
    source=Path(origin["package"])/"joint/authority";out=Path(origin["output"])
    jobs=[]
    def process(label,script,args):
        row=record_process(run,label,py+[str(script),*map(str,args)]);jobs.append(row);return row
    graph=None
    if "build" in dependencies:
        build=dependencies["build"]
        graph=read_build.verify_build(package,build,manifest_sha256)
        require(graph["runtime_hia_images"]==111 and graph["fresh_direct_members"]==103
            and graph["actual_default_entry"] is True,"actual combined default graph")
    if role=="owner":
        with aggregate.selected(prepared["owner_modules"]):
            owner=prepared["owner"];oldsource=owner.source_evidence(authority/"owner-reference")
            actual=owner.qualification(run/"owner-v4",oldsource["pins_sha256"])
            require(owner.encoded(actual)==(run/"owner-v4/QUALIFICATION.json").read_bytes(),"complete existing owner report")
        require(actual["evidence"]["original"]["rows"]==243 and actual["reader_refusals"]==16,
            "full current owner original/control domain")
        process("owner-current243",source/"owner-reference/tests/hia_native/caller_owner_export/qualify.py",
            ["--phase","all","--source-root",source/"owner-reference","--hepta",origin["hepta"],"--output",out/"owner-v4"])
        result={"status":"FRESH_CURRENT_OWNER243_AND_16_CONTROLS_PASS","current_owner_v4":actual,"original_rows":243}
    elif role=="profiles":
        retained=prepared["retained"];build_origin=doc(dependencies["build"]/"BUILD_ORIGIN.json")
        for label,sub,runner,count in (
            ("current","authority-retained","run_authority_retained.py",23),
            ("historical","authority-historical","run_authority_historical.py",7)):
            with aggregate.isolated():
                value=retained.verify(authority/sub,run/(label+"-build"),run/label,historical=label=="historical")
            require(value["test_groups"]==count,"complete retained authority profile")
            process(label+"-build",source/"drivers/build_authority_retained.py",
                ["--source",source/sub,"--hepta",origin["hepta"],"--bootstrap",
                 Path(origin["dependencies"]["build"])/"production/build/bootstrap","--output",out/(label+"-build")])
            args=["--source",source/sub,"--manifests",out/(label+"-build/MANIFESTS.json"),"--output",out/label]
            if label=="current":args+=["--hepta",origin["hepta"]]
            process(label+"-groups",source/"drivers"/runner,args)
            if label=="current":current=value
            else:historical=value
        result={"status":"FULL_CURRENT23_HISTORICAL7_PROFILES_PASS","current":current,"historical":historical,
            "current_groups":23,"historical_groups":7,"historical_evidence_promoted":False}
    elif role=="authority":
        build=dependencies["build"];owner_run=dependencies["owner"]
        graph_view(build,run)
        manifest=build/"instances/task-pump/manifest.json";module_map=run/"module-map.json"
        private=prepared["private"].verify(package/"graph/source",manifest,run/"private-binding",module_map)
        oldguard=doc(run/"processes/private-readonly.stdout")
        require(oldguard["evidence"]==private and oldguard["before"]==oldguard["after"]
            and len(oldguard["probes"])==11 and oldguard["reader_writes"]==oldguard["native_or_rust_executions"]==0,
            "complete actual private current-call reader")
        owner_qualification=doc(owner_run/"QUALIFICATION.json")
        require(owner_qualification["status"]=="FRESH_CURRENT_OWNER243_AND_16_CONTROLS_PASS",
            "same-CI complete original owner dependency")
        bridge=prepared["bridge"].verify(owner_run/"owner-v4",private,run/"public-owner-reference")
        require(bridge==doc(run/"public-owner-reference/REFERENCE.json") and bridge["rows"]==16,
            "complete actual native OS observation/current-original replay")
        graph_origin=Path(origin["dependencies"]["build"])
        declared_manifest=graph_origin/"instances/task-pump/manifest.json"
        target=Path(origin["package"])/"graph/source";adapt=Path(origin["package"])/"ci/authority"
        process("native-private-binding",adapt/"capture_private_binding.py",
            ["--source",target,"--manifest",declared_manifest,"--output",out/"private-binding"])
        process("private-readonly",adapt/"verify_private_readonly.py",
            ["--source",target,"--manifest",declared_manifest,"--capture",out/"private-binding","--module-map",out/"module-map.json"])
        process("current-public-owner16",adapt/"public_owner_reference.py",
            ["--source",target,"--manifest",declared_manifest,"--capture",out/"private-binding",
             "--owner-output",Path(origin["dependencies"]["owner"])/"owner-v4",
             "--output",out/"public-owner-reference","--module-map",out/"module-map.json"])
        require(private["counts"]["input_frames"]==56 and private["counts"]["full_snapshots"]==28
            and private["counts"]["sessions"]==4,"complete retained private state domain")
        result={"status":"ACTUAL_PUBLIC111_PRIVATE_AUTHORITY_AND_CURRENT16_PASS","private":private,"original":bridge,
            "retained_owner_original_rows":243,"actual_new_graph_original_replay_rows":16,
            "peer_info_is_authority":False,"whole_owner243_repeated_as_public_input":False}
    else:
        build=dependencies["build"];target=package/"graph/source";aggregate=prepared["aggregate"]
        graph_view(build,run)
        module_map=run/"module-map.json"
        public=prepared["public"].verify(target,build/"production",run/"public-loop",module_map)
        with aggregate.isolated():
            handshake=prepared["handshake"].verify(authority/"handshake-reference",run/"handshake-reference",
                run/"native-handshake",build/"production")
        transport=prepared["transport"].verify(authority/"transport-reference",run/"transport-reference",
            run/"native-framing",run/"transport-inputs")
        baseline=prepared["baseline"](run/"retained-eight")
        require(handshake["sessions"]==54 and handshake["responses"]==324
            and public["counts"]["response_lines"]==90 and public["fresh_member_compiles"]==103
            and transport["serial_public_wire_cases"]==24 and transport["codec_eof_reference_only_cases"]==4,
            "complete actual retained current domains")
        require(public["elf_sha256"]==handshake["candidate_elf_sha256"]==transport["actual_native_elf_sha256"]
            ==graph["entries"]["production"]["elf"]["sha256"],"all domains executed the actual default ELF")
        declared_build=Path(origin["dependencies"]["build"])/"production"
        adapt=Path(origin["package"])/"ci/authority"
        process("retained62",source/"transport-reference/drivers/build_retained_eight.py",
            ["--sdk-source",origin["sdk_source"],"--hepta",origin["hepta"],"--output",out/"retained-eight"])
        process("normal-corpus",source/"drivers/transport_cases.py",["--output",out/"transport-inputs"])
        process("native-framing24",adapt/"capture_transport_native.py",
            ["--build",declared_build,"--cases",out/"transport-inputs","--output",out/"native-framing"])
        process("fresh-original28",source/"transport-reference/drivers/run_transport_reference.py",
            ["--source",source/"transport-reference","--cases",out/"transport-inputs",
             "--native",out/"native-framing","--rust-bin",origin["rust_bin"],"--output",out/"transport-reference"])
        process("fresh-original54",source/"handshake-reference/scripts/run_reference.py",
            ["--source",source/"handshake-reference","--rust-bin",origin["rust_bin"],"--output",out/"handshake-reference"])
        process("native-handshake54",source/"drivers/capture_handshake.py",
            ["--source",source/"handshake-reference","--build",declared_build,"--output",out/"native-handshake"])
        baseline_report=doc(run/"retained-eight/BUILD.json")
        process("public90",adapt/"qualify_public.py",
            ["--source",Path(origin["package"])/"graph/source","--manifest",
             declared_build/"build/public-task-batch/manifest.json","--baseline-elf",baseline_report["elf"],
             "--get-info-reference",origin["get_info_reference"],"--output",out/"public-loop"])
        result={"status":"ACTUAL_PUBLIC111_HANDSHAKE324_PUBLIC90_TRANSPORT24_PASS",
            "public":public,"handshake":handshake,"transport":transport,"retained_eight":baseline}
    result.update(source=closure,source_manifest_sha256=manifest_sha256,
        ci={k:origin[k] for k in ("git_head","run_id","run_attempt")},
        actual_graph=graph_identity(graph) if graph is not None else None,processes=jobs,**dict.fromkeys(FLAGS,False))
    if (run/"QUALIFICATION.json").is_file():
        require(doc(run/"QUALIFICATION.json")==result,"retained complete role qualification changed")
    return result
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--role",choices=("owner","profiles","authority","connection"),required=True)
    for name in ("package","run"):p.add_argument("--"+name,type=Path,required=True)
    for name in ("build","owner"):p.add_argument("--"+name,type=Path)
    p.add_argument("--manifest-sha256",required=True);a=p.parse_args()
    package=a.package.resolve(strict=True);run=a.run.resolve(strict=True)
    dependencies={n:getattr(a,n).resolve(strict=True) for n in ("build","owner") if getattr(a,n) is not None}
    prepared=prepare(package,a.role)
    roots=[package,run,*dependencies.values()]
    guarded=prepared["wire"].guarded(lambda:verify(package,run,a.manifest_sha256,a.role,dependencies,prepared),
        roots=roots,prepared=prepared["guard"])
    print(json.dumps({"status":guarded["evidence"]["status"],"qualification":guarded["evidence"],"read_only":guarded},
        sort_keys=True,allow_nan=False))
if __name__=="__main__":main()
