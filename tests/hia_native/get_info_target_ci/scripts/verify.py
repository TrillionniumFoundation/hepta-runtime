"""Read all retained bytes and compare nine fixed get_info results; execute nothing."""
from pathlib import Path
import argparse, hashlib, json, os, stat, struct, sys
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from check_source import check
from derive_contract import derive
from reference_custody import inspect_zip, PROFILES, need, pin, parse
HEPTA="d3e2c90173cf733e42b299d0c4274df4b593a12f"
HEPTA_TREE="8d8b0fb8d015fb7edab302498bb9ed4c74ab6f49"
B3="bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0"
FALSE_FLAGS=("full_sdk_qualified","full_async_runtime_qualified","production_activated",
             "old_path_removed","public_frontend_registered","generic_initialize_result_serializer")
def sha(raw):return hashlib.sha256(raw).hexdigest()
def data(root,relative,expected=None):
    relative=Path(relative)
    need(not relative.is_absolute() and ".." not in relative.parts,"relative retained path")
    path=root/relative
    need(path.resolve(strict=True)==path and stat.S_ISREG(path.lstat().st_mode),"regular retained file")
    raw=path.read_bytes()
    if expected is not None:need(pin(raw)==expected,"complete bytes: "+relative.as_posix())
    return raw
def doc(root,relative):return parse(data(root,relative))
def verify(source,run,reference_zip,*,require_pass=False):
    source,run=Path(source).resolve(strict=True),Path(run).resolve(strict=True)
    package=check(source);recipe=doc(run,"RECIPE.json")
    need(recipe["status"] in (("PASS",) if require_pass else ("RUNNING","PASS")),"recipe phase")
    need(recipe["source_manifest"]==package["source_manifest"],"source closure")
    need(all(recipe.get(k) is False for k in FALSE_FLAGS) and recipe["new_rust_executed"] is False,"limited scope")
    labels=["primary-sources","generate-fixed-owner","fresh-hia-owner","capture-nine"]
    need([r["label"] for r in recipe["processes"]]==labels,"actual recipe sequence")
    for row in recipe["processes"]:
        need(row["exit_code"]==0 and row["outer_timeout_seconds"] is None,"recipe process completion")
        for stream in ("stdout","stderr"):data(run,"processes/"+row["label"]+"."+stream,row[stream])
    custody,primary,originals=inspect_zip(reference_zip,observe=True)
    need(doc(run,"primary/PRIMARY_CUSTODY.json")==
         dict(custody,observation_outputs_decoded=False,original_get_info_calls=0),"same authenticated reference")
    for name,raw in primary.items():need(data(run,"primary/"+name)==raw,"primary verbatim bytes")
    need(doc(run,"generated/derived-contract.json")==derive(run/"primary"),"source-derived fixed contract")
    audit=doc(run,"generated/AUTHOR_READS.json")
    need(audit["status"]=="PASS" and audit["denied"]==[] and audit["primary_only_derivation"] is True
         and audit["expected_reference_zip_or_profile_outputs_accessed"] is False
         and audit["child_or_native_execution"] is False,"actual author source isolation")
    need({r["path"] for r in audit["reads"] if r["root"]=="primary"}==set(primary),"five primary reads only")
    need(all(r["root"] in {"package","primary","hepta","stdlib","generated"} for r in audit["reads"]),"read roots")
    need(all(r["root"]=="generated" for r in audit["writes"]),"author write extent")
    composition=doc(run,"generated/native/current_get_info.composition.json")
    owner=data(run,"generated/native/current_get_info.hepta")
    need(pin(owner)==dict(bytes=composition["source_bytes"],sha256=composition["source_sha256"]),"generated owner")
    need(sha(owner)==audit["source_sha256"],"audited source")
    need(composition["author_sha256"]==sha(data(source,"scripts/author_get_info.py"))
         and composition["pseudo_sha256"]==sha(data(source,"scripts/current_get_info.pseudo")),"author identity")
    need(composition["derived_contract_sha256"]==sha(data(run,"generated/derived-contract.json")),"primary binding")
    need(composition["expected_output_or_process_stream_used_for_generation"] is False
         and composition["actual_target_comparison_complete"] is False,"generation-only status")
    need(all(composition.get(k) is False for k in FALSE_FLAGS),"generated owner limited scope")
    need(composition["helper_source_sha256"]==sha(data(source,"support/text_result_constructor.hepta")),"ABI helpers")
    plan=doc(run,"generated/literal-plan.json")
    need(plan["whole_expected_wire_read_or_embedded"] is False,"field writer scope")
    literals={r["name"]:r for r in plan["literals"]}
    for row in literals.values():need(pin(row["utf8"].encode())=={k:row[k] for k in ("bytes","sha256")},"field bytes")
    need(sum(literals[n]["bytes"] for n in plan["steps"])==plan["wire_bytes"]==composition["wire_bytes"],"wire extent")
    built=doc(run,"native/BUILD.json")
    need(built["status"]=="HIA_COMPILE_PASS" and built["fresh_native_compile"] is True
         and built["bootstrap_reused"] is False and built["independent_cold_qualified"] is False
         and built["original_rust_executed"] is False and built["public_frontend_registered"] is False,"fresh native build")
    raw=data(run,"native/"+built["manifest"])
    need(sha(raw)==built["manifest_sha256"],"module manifest")
    module=parse(raw);folder=Path("native")/Path(built["manifest"]).parent
    need(module["compiler_commit"]==HEPTA and module["compiler_sha256"]==B3,"pinned HIA compiler")
    need(module["standalone"] is None and module.get("buffer_profile","standard")=="standard","private owner profile")
    need(data(run,folder/module["source"])==owner,"actual compiled source")
    image=data(run,folder/module["image"])
    need(sha(image)==module["image_sha256"]==built["image_sha256"],"complete actual image")
    need(module["source_sha256"]==built["source_sha256"]==sha(owner),"source and image custody")
    bootstrap=doc(run,"native/build/bootstrap/bootstrap.json")
    need(bootstrap["dependency"]["commit"]==HEPTA and bootstrap["dependency"]["tree"]==HEPTA_TREE
         and bootstrap["generation_sha256"]==B3 and bootstrap["qualification"]=="development_fixed_point","bootstrap identity")
    for label in ("B1","B2","B3"):need(sha(data(run,"native/build/bootstrap/"+label+".image.bin"))==B3,"compiler generation")
    compile_record=doc(run,folder/"build.json")
    need(compile_record["compiler_dependency"]==bootstrap["dependency"]
         and compile_record["whole_runtime_replaced"] is False,"compiler source closure")
    summary=doc(run,"native-capture/SUMMARY.json")
    need(summary["status"]=="NATIVE_CAPTURE_COMPLETE" and summary["expected_cases"]==9
         and summary["completed_cases"]==9 and summary["native_calls"]==18 and len(summary["rows"])==9,"nine native captures")
    need(summary["expected_results_read"] is False and summary["actual_target_wire_compared"] is False,"independent capture")
    need(all(summary.get(k) is False for k in FALSE_FLAGS if k!="generic_initialize_result_serializer"),"capture scope")
    calls,comparisons=0,[]
    for index,(profile,row,original) in enumerate(zip(PROFILES,summary["rows"],originals)):
        folder=Path("native-capture")/("case-"+str(index))
        need(row["profile"]==profile==original["profile"] and row["folder"]==folder.name,"profile order")
        raw=data(run,folder/"CASE.json");need(sha(raw)==row["receipt_sha256"],"case receipt")
        case=parse(raw)
        need(case["status"]=="NATIVE_CAPTURE_COMPLETE" and case["index"]==index and case["profile"]==profile
             and case["expected_results_read"] is False and case["actual_target_wire_compared"] is False,"case status")
        process=doc(run,"native-capture/"+str(index)+".process.json")
        need(process["index"]==index and process["profile"]==profile and process["exit_code"]==0
             and process["native_deadline_seconds"]==60,"actual native process")
        for stream in ("stdout","stderr"):
            raw=data(run,"native-capture/"+str(index)+"."+stream,process[stream])
            need(raw==b"","ordinary native process streams")
        need(len(case["captures"])==2,"growth and completion")
        outputs=[]
        for attempt,capture in enumerate(case["captures"]):
            name="grow" if attempt==0 else "complete"
            need(capture["folder"]==name,"capture phase");child=folder/name
            need(doc(run,child/"CAPTURE.json")=={k:v for k,v in capture.items() if k!="folder"},"capture receipt")
            for field in ("input","output","workspace"):need(capture[field]["path"]==field+".bin","full capture file")
            request=data(run,child/"input.bin",{k:capture["input"][k] for k in ("bytes","sha256")})
            output=data(run,child/"output.bin",{k:capture["output"][k] for k in ("bytes","sha256")})
            workspace=data(run,child/"workspace.bin",{k:capture["workspace"][k] for k in ("bytes","sha256")})
            need(request==struct.pack("<8s3Q",b"HRTGIQ01",1,0,0),"fixed contract input")
            need(len(output)==capture["output_capacity"] and workspace==b"\x5a"*64
                 and capture["workspace_capacity"]==64 and capture["workspace_fill"]==0x5a
                 and capture["output_fill"]==0xa7,"complete mutable buffers")
            need(capture["deadline_seconds"]==60 and 0<=capture["elapsed_seconds"]<60,"native call deadline")
            need(capture["return_code"]==(0xffffffd0 if attempt==0 else 64),"actual return")
            outputs.append(output);calls+=1
        need(struct.unpack("<8s3Q",outputs[0])==(b"HGRWS002",2,len(outputs[1]),0),"real output growth")
        need(struct.unpack("<8s7Q",outputs[1][:64])==
             (b"HRTGIS01",0,1,0,64,len(outputs[1])-64,0,0),"complete native descriptor")
        need(len(outputs[1])==case["complete_extent"]==composition["complete_extent"],"complete extent")
        wire=data(run,folder/"wire.bin",{k:case["wire"][k] for k in ("bytes","sha256")})
        need(wire==outputs[1][64:] and row["wire"]==case["wire"],"wire custody")
        need(wire==original["get_info_wire"].encode(),"whole wire differs from actual get_info: "+profile)
        comparisons.append(dict(profile=profile,wire=pin(wire),original_stdout=original["stdout"],
                                runtime_flags=original["runtime_flags"]))
    need(calls==18 and len(comparisons)==9,"exact comparison counts")
    report=dict(schema="hepta.current-get-info.readonly-comparison.v1",status="GET_INFO_CURRENT_TARGET_PASS",
        source_manifest=package["source_manifest"],owner_source_sha256=sha(owner),owner_image_sha256=sha(image),
        fresh_native_modules=1,actual_native_calls=calls,actual_retained_original_get_info_calls=9,
        complete_wire_compared=True,comparisons=comparisons,reference_custody=custody,
        primary_only_authoring=True,readonly=True,new_native_or_original_execution=False,new_rust_executed=False,
        independent_cold_qualified=False,**{k:False for k in FALSE_FLAGS})
    if recipe["status"]=="PASS":
        need(doc(run,"READBACK.json")==report,"retained complete comparison report")
        need(recipe["actual_target_get_info_compared"] is True and recipe["native_calls"]==18
             and recipe["get_info_cases"]==9,"recipe completion facts")
    return report

def snapshot(root):
    rows={};root=Path(root).resolve(strict=True)
    for path in sorted(root.rglob("*")):
        if path.is_dir():continue
        need(path.resolve(strict=True)==path and stat.S_ISREG(path.lstat().st_mode),"readonly snapshot file")
        info=path.stat()
        with path.open("rb") as stream:digest=hashlib.file_digest(stream,"sha256").hexdigest()
        rows[path.relative_to(root).as_posix()]=(info.st_size,digest,info.st_mtime_ns,info.st_ctime_ns)
    return rows
def no_mutation(event,args):
    if event=="open":
        _,_,flags=args
        if flags & (os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND):
            raise PermissionError("read-only verifier forbids writable files")
    elif event in {"os.mkdir","os.remove","os.rmdir","os.rename","os.link","os.symlink",
                   "os.chmod","os.chown","os.utime","os.truncate","os.system","os.exec","os.posix_spawn","os.fork"}:
        raise PermissionError("read-only verifier forbids mutation or child execution")
    elif event.startswith(("subprocess.","ctypes.","mmap.")):
        raise PermissionError("read-only verifier cannot launch or map native code")
def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("source","run","reference-zip"):p.add_argument("--"+name,required=True,type=Path)
    p.add_argument("--require-pass",action="store_true");a=p.parse_args()
    sys.addaudithook(no_mutation)
    before=(snapshot(a.source),snapshot(a.run))
    z=a.reference_zip.resolve(strict=True);zinfo=z.stat()
    result=verify(a.source,a.run,z,require_pass=a.require_pass)
    after=(snapshot(a.source),snapshot(a.run))
    need(before==after,"reader changed source or capture bytes/mtime/ctime")
    zafter=z.stat()
    need((zinfo.st_size,zinfo.st_mtime_ns,zinfo.st_ctime_ns)==
         (zafter.st_size,zafter.st_mtime_ns,zafter.st_ctime_ns),"reader changed reference ZIP")
    print(json.dumps(result,sort_keys=True,separators=(",",":")))
if __name__=="__main__":main()
