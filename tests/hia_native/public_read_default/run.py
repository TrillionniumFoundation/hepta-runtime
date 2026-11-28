#!/usr/bin/env python3
"""Run complete controls against the default HIA read/catalog executable."""
from pathlib import Path
import argparse,json,os,subprocess,sys,time,traceback
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import load,pin,source_check
def save(path,value):path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def require(value,label):
    if not value:raise ValueError(label)
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--manifest",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    args=p.parse_args()
    require(sys.flags.isolated==1 and sys.flags.optimize==0,"use python3 -I -B")
    output=args.output.absolute();require(not output.exists(),"fresh output required")
    output.mkdir(parents=True)
    os.environ["HIA_PUBLIC_READ_OUTPUT"]=str(output)
    os.environ["HIA_PUBLIC_READ_MANIFEST"]=str(args.manifest.resolve(strict=True))
    _,root,_,build,elf,_=load("admission",create=False)
    here=Path(__file__).resolve().parent
    controls=sorted(p.name for p in here.glob("*.py"))
    require(controls==["catalog_component.py","catalog_wire.py","common.py","lifecycle.py","network.py","run.py"],"complete control source domain differs")
    source_before={name:pin(here/name)for name in controls}
    binding_before=source_check(root);elf_before=pin(elf)
    manifest=Path(build["manifest"]);manifest_before=pin(manifest)
    report={"schema":"hepta.runtime.public-read.default-qualification.v1","status":"RUNNING",
        "build":str(manifest),"build_pin":manifest_before,"elf":str(elf),"elf_pin":elf_before,
        "source_binding":binding_before["manifest_sha256"],"control_sources":source_before,
        "source_root":str(root),"source_registered_read_routes":["file_info","binary_read","read_multiple_files"],
        "configuration_flags_tested":[0,1],"complete_136_declaration_input":True,
        "full_136_handlers_qualified":False,"whole_runtime_replaced":False,
        "old_path_removed":False,"original_private_16_415_profile_rerun":False,
        "new_full_original_rust_runtime_rerun":False,"isolated":sys.flags.isolated,
        "optimize":sys.flags.optimize,"steps":[]}
    started=time.monotonic()
    try:
        env={"PATH":"/usr/bin:/bin","HOME":str(output),"LC_ALL":"C",
            "HIA_PUBLIC_READ_OUTPUT":str(output),"HIA_PUBLIC_READ_MANIFEST":str(manifest)}
        for label in("catalog_component","network","catalog_wire","lifecycle"):
            command=[sys.executable,"-I","-B",str(here/(label+".py"))]
            before=time.monotonic();row={"label":label,"command":command,"timeout_seconds":180}
            report["steps"].append(row);save(output/"result.json",report)
            with (output/(label+".stdout")).open("xb")as stdout,(output/(label+".stderr")).open("xb")as stderr:
                done=subprocess.run(command,cwd=root,env=env,stdin=subprocess.DEVNULL,
                    stdout=stdout,stderr=stderr,timeout=180,check=False)
            row.update(exit_code=done.returncode,seconds=time.monotonic()-before)
            require(done.returncode==0,"actual complete public control failed: "+label)
            result_path=output/label/"result.json";value=json.loads(result_path.read_bytes())
            require(value["status"]=="PASS"and value["isolated"]==1 and value["optimize"]==0,
                "isolated complete public result admission: "+label)
            if label=="catalog_component":
                require(value["tests_run"]==6 and all(value[k]==0 for k in
                    ("failures","errors","skipped","expected_failures","unexpected_successes")),
                    "complete six-method catalog suite admission")
                detail=value["details"]
                require(len(detail["rows"])==18 and detail["old_comparisons"]==187
                    and detail["malformed_queries"]==19 and detail["capacity_controls"]==12
                    and detail["owner_controls"]==12,"complete original catalog comparison count")
            elif label=="network":
                require(value["public_cases"]==21 and value["public_responses"]==23
                    and value["multi_cases"]==15 and value["read_info_cases"]==6
                    and value["actual_ssh_invocations"]==18 and len(value["actual_catalog_names"])==113
                    and value["returncode"]==0,"complete configured network route case count")
                require(all(c["status"]=="PASS"for c in value["cases"]+value["read_and_info_cases"]),
                    "all actual network business comparisons must complete")
            elif label=="catalog_wire":
                require(len(value["cases"])==18 and value["process_returncodes"]==[0]*6
                    and all(c["status"]=="PASS"for c in value["cases"]),
                    "complete default public catalog response domain")
            else:
                require([c["label"]for c in value["cases"]]==[
                    "concurrent-notification-retains-handler-and-discards-wire",
                    "EOF-reaps-owned-remote","original-30s-deadline-and-recover"],
                    "complete original lifecycle case domain")
                require(value["session_count"]==3 and all(c["status"]=="PASS"and c["returncode"]==0
                    and c["local"]["all_reaped"]and c["remote"]["all_reaped"]for c in value["cases"]),
                    "all owned lifecycle terminals must complete")
            row.update(status="PASS",result=str(result_path),result_pin=pin(result_path))
            save(output/"result.json",report)
            print("PUBLIC_READ_GATE",label,"PASS",flush=True)
        require(source_check(root)==binding_before and pin(elf)==elf_before
            and pin(manifest)==manifest_before
            and {name:pin(here/name)for name in controls}==source_before,
            "exact source/artifact/control closure changed during actual qualification")
        report.update(status="PASS",network_business_cases=21,network_responses=23,
            original_ssh_invocations=18,default_catalog_wire_cases=18,
            lifecycle_cases=3,full_catalog_methods=6,failures=0,errors=0,skipped=0,
            expected_failures=0,unexpected_successes=0)
    except BaseException as exc:
        report.update(status="FAIL",error=repr(exc));traceback.print_exc()
    finally:
        report["seconds"]=time.monotonic()-started;save(output/"result.json",report)
    print(json.dumps({k:v for k,v in report.items()if k not in("steps","control_sources")},sort_keys=True),flush=True)
    return 0 if report["status"]=="PASS"else 1
if __name__=="__main__":raise SystemExit(main())
