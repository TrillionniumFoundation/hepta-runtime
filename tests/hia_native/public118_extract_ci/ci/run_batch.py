"""Run fixed Batch domains using the actual installed111 entry and same-CI originals."""
from pathlib import Path
import argparse,json,os,sys,traceback
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import command,put,require,pin
from domain_support import begin,doc,selected,graph_identity
import read_build,read_batch
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--role",choices=("batch-reference","batch"),required=True)
    for n in ("package","output"):p.add_argument("--"+n,type=Path,required=True)
    for n in ("hepta","target","rust-bin","build","build-receipt","batch-reference","batch-reference-receipt"):
        p.add_argument("--"+n,type=Path)
    p.add_argument("--manifest-sha256",required=True);a=p.parse_args()
    dependencies={}
    for n in ("build","batch-reference"):
        key=n.replace("-","_");value=getattr(a,key)
        if value is not None:
            receipt=getattr(a,key+"_receipt");require(receipt is not None,"complete dependency receipt")
            dependencies[n]=(value,receipt)
    details={n:str(getattr(a,n).resolve(strict=True)) for n in ("hepta","target","rust_bin") if getattr(a,n) is not None}
    package,out,origin=begin(a.package,a.output,a.manifest_sha256,a.role,dependencies,details)
    py=[sys.executable,"-I","-S","-B"]
    try:
        if a.role=="batch-reference":
            require(all(getattr(a,n) is not None for n in ("hepta","target","rust_bin")),"fresh reference dependencies")
            command(out,"fresh-complete-batch-reference",py+[str(package/"joint/batch/run_recipe.py"),
                "--phase","all","--hepta",str(a.hepta),"--target",str(a.target),"--rust-bin",str(a.rust_bin),
                "--output",str(out/"baseline")])
        else:
            require(a.build is not None and a.batch_reference is not None,"same-CI reference and actual graph")
            build=a.build.resolve(strict=True);baseline=a.batch_reference.resolve(strict=True)/"baseline"
            read_build.prepare(package);graph=read_build.verify_build(package,build,a.manifest_sha256)
            require(graph["runtime_hia_images"]==111 and graph["fresh_direct_members"]==103,"actual default graph")
            report=doc(baseline/"result.json")
            producer=Path(report["producer_root"]);temp=Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
            require(producer.is_absolute() and producer.is_relative_to(temp)
                and not producer.is_relative_to(a.batch_reference.resolve(strict=True))
                and producer==temp/"public111-batch-reference/baseline","exact owned original fixture root")
            fixture_root=producer/"workspaces";fixture_root.mkdir(parents=True,exist_ok=True)
            batch,modules=read_batch.import_batch(package);source=package/"joint/batch"
            capture={"schema":"hepta.runtime.public111.batch-capture.v1","status":"RUNNING",
                "domains":read_batch.DOMAINS,"stdio":read_batch.STDIO,
                "source":pin(source/"source-profile.json"),"graph":graph_identity(graph),
                "binary":{k:{field:graph["entries"][k]["elf"][field] for field in ("bytes","sha256")} for k in ("production","instances")},
                "actual_new_native_processes":6,"fresh_original_reused_from_same_ci":True,
                "outer_lane_seconds":180,"exchange_seconds":60}
            put(out/"CAPTURE_START.json",capture)
            with selected(modules,read_batch.NAMES):
                old=pin(baseline/"original/bin/hepta-batch-sdk-current-original-oracle")
                for kind,domains in (("private",read_batch.DOMAINS),("stdio",read_batch.STDIO)):
                    binary=build/("instances/task-pump/filesystem-fixture.elf" if kind=="private" else
                        "production/build/public-task-batch/runtime-mcp.elf")
                    for domain in domains:
                        parent="public" if kind=="private" else "stdio"
                        folder=out/parent/domain/"native";original=baseline/parent/domain/"original"
                        fixture=fixture_root/(("private-" if kind=="private" else "stdio-")+domain)
                        require(not fixture.exists() and not fixture.is_symlink(),"new owned fixture already exists")
                        require(doc(original/"result.json")["fixture"]==str(fixture),"same absolute fixture as original")
                        batch.lane_guard.run(kind,"native",binary,fixture,folder,domain)
                        if kind=="private":batch.read_public.inspect(folder,source,expected_binary=pin(binary))
                        else:batch.read_stdio.inspect(folder,source,pin(binary))
                        batch.retire_fixture.retire(folder)
                        result=batch.read_public.compare(folder,original,source,native_binary=pin(binary),original_binary=old) \
                            if kind=="private" else batch.read_stdio.compare(folder,original,source,pin(binary),old)
                        put(out/parent/domain/"comparison.json",result)
            capture["status"]="PASS";put(out/"CAPTURE.json",capture)
        args=[]
        for n in ("build","batch-reference"):
            value=getattr(a,n.replace("-","_"))
            if value is not None:args+=["--"+n,str(value.resolve(strict=True))]
        command(out,"readonly-role",py+[str(package/"ci/read_batch.py"),"--role",a.role,"--package",str(package),
            "--run",str(out),"--manifest-sha256",a.manifest_sha256,*args])
        guarded=doc(out/"processes/readonly-role.stdout");guard=guarded["read_only"]
        require(guard["before"]==guard["after"] and len(guard["probes"])==11
            and guard["reader_writes"]==guard["native_or_rust_executions"]==0,"complete pure readback")
        put(out/"QUALIFICATION.json",guarded["qualification"])
        print(json.dumps(guarded["qualification"],sort_keys=True,allow_nan=False))
    except BaseException as e:
        put(out/"FAILURE.json",{"role":a.role,"status":"FAIL","error":repr(e),"traceback":traceback.format_exc(),
            "domain_reduced":False,"deadline_raised":False});raise
if __name__=="__main__":main()
