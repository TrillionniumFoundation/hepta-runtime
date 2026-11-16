"""Build and execute two additive SDK observers after the unchanged direct reference."""
from pathlib import Path
import argparse, os, shutil, struct, sys, time
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import common as c

def projection_inputs(original, output):
    index=[];sequence=0
    with (output/"projection.input.bin").open("xb") as stream:
        for profile in (None,*range(8)):
            name="profile-disabled" if profile is None else "profile-"+str(profile)
            observation=c.read_json(original/"processes"/(name+".stdout"))
            flags=0 if profile is None else 1|(profile<<1)
            for case in observation["list_cases"]:
                modern=int(case["protocol_version"] is not None and case["protocol_version"]>="2026-07-28")
                raw=case["result_wire"].encode()
                for installed in range(4):
                    for policy in (0,2 if modern else 1):
                        packet=b"HCATSP02"+struct.pack("<7Q",sequence,flags,modern,policy,len(raw),installed,0)+raw
                        c.need(stream.write(packet)==len(packet),"complete SDK input packet")
                        index.append({"sequence":sequence,"profile":profile,"flags":flags,
                            "protocol_version":case["protocol_version"],"cursor_case":case["cursor_case"],
                            "modern":modern,"policy":policy,"installed":installed,"input":c.pin(packet)})
                        sequence+=1
    c.need(sequence==1728,"complete original/mask/peer-policy matrix")
    c.put(output/"projection-index.json",index)
    return index

def run(package,target,original,output):
    c.need(os.environ.get("GITHUB_ACTIONS")=="true","fresh original build is CI-only")
    c.source_check(package)
    verifier=c.source_module("configured_original_catalog_verifier",
        package/"source/retained/pipeline/policy_base/reference/verify.py")
    old=verifier.verify(original)
    c.need(old["original_list_handler_calls"]==216,"complete unchanged direct reference")
    output.mkdir(parents=True,exist_ok=False)
    original_sources=c.read_json(original/"source.json")
    c.need(c.regular(target/"src/mcp/server.rs")==c.regular(original/"instrumented-server.rs"),
        "unchanged original server and append-only direct observer")
    for name in ("Cargo.toml","Cargo.lock"):
        c.need(c.pin(c.regular(target/name))==original_sources["originals"][name],"original locked build source")
    mapping={"hia_configured_public":"public_reference.rs","hia_configured_projection":"configured_projection.rs"}
    for example,source in mapping.items():
        c.put(target/"examples"/(example+".rs"),c.regular(package/"ci"/source))
    env=c.original_environment(original/"cargo-target")
    report={"schema":"hepta.runtime.configured-catalog-sdk-build.v1","status":"RUNNING",
        "target_commit":c.TARGET,"target_tree":c.TREE,"pid":os.getpid(),"parent_pid":os.getppid(),
        "pgid":os.getpgrp(),"roots":{"package":str(package),"target":str(target),"original":str(original),"output":str(output)},
        "package":c.pin(c.regular(package/"PACKAGE.json")),"same_ci_reference_target_reused":True,
        "original_functions_unchanged":True,"public_handler_requests":0,
        **{key:False for key in c.FALSE_FLAGS}}
    start=time.monotonic_ns()
    try:
        build=c.record_process(output/"processes","build-sdk-observers",
            ["cargo","build","--locked","--example","hia_configured_public","--example","hia_configured_projection"],
            target,180,env=env)
        binaries={}
        for name in mapping:
            path=original/"cargo-target/debug/examples"/name
            destination=output/(name+".elf")
            c.put(destination,c.regular(path));destination.chmod(0o500)
            binaries[name]={"origin":str(path),"saved":destination.name,"pin":c.pin(c.regular(destination))}
        index=projection_inputs(original,output)
        replay=c.record_process(output/"processes","sdk-projection",
            [str(output/"hia_configured_projection.elf")],target,60,env=env,stdin=output/"projection.input.bin")
        for name in ("Cargo.toml","Cargo.lock"):
            c.need(c.pin(c.regular(target/name))==original_sources["originals"][name],"original lock/source changed")
        c.need(c.regular(target/"src/mcp/server.rs")==c.regular(original/"instrumented-server.rs"),"original server changed")
        for name,source in mapping.items():
            c.need(c.regular(target/"examples"/(name+".rs"))==c.regular(package/"ci"/source),"observer source changed")
        report.update(status="FRESH_CURRENT_SDK_EXECUTION_COMPLETE",binaries=binaries,
            projection_records=len(index),build_process=build,replay_process=replay,
            observer_sources={name:c.pin(c.regular(package/"ci"/source)) for name,source in mapping.items()},
            elapsed_ns=time.monotonic_ns()-start)
    except BaseException as exc:
        report.update(status="FAIL",error=repr(exc),elapsed_ns=time.monotonic_ns()-start)
        raise
    finally:
        c.put(output/"result.json",report)
    print(c.encoded({key:value for key,value in report.items() if key not in ("build_process","replay_process")}).decode())
    return report

if __name__=="__main__":
    p=argparse.ArgumentParser()
    for name in ("package","target","original","output"):p.add_argument("--"+name,type=Path,required=True)
    a=p.parse_args()
    run(a.package.resolve(strict=True),a.target.resolve(strict=True),a.original.resolve(strict=True),a.output.absolute())
