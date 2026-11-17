"""Independent complete-domain diagnostics only; never a qualification result."""
import argparse,sys,traceback
from pathlib import Path
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT))
from reader_common import read,loads,encoded,source
import qualify,legacy_build,read_pairs,read_trace,read_native,read_outer
def run(bundle,output):
    source();state=qualify.prepare(bundle);admission=legacy_build.verify(bundle/"retained",state["build"])
    m=loads(read(bundle/"run/CAPTURE.json"));d=loads(read(bundle/"source/DOMAIN.json"))
    records={r["name"]:r for r in loads(read(bundle/"run/processes/processes.json"))};results=[]
    for group in d["groups"]:
        item=dict(group=group);folder=bundle/"run"/("paired-"+group)
        cases=[c for c in d["cases"]if c["group"]==group]
        try:
            pair=read_pairs.verify(folder,m,records["paired-"+group],cases,dict(python_resolved="/usr/bin/python3.12"))
            item["pair"]=pair["summary"];traces=[]
            for name,role in zip(read_pairs.ROLES,pair["roles"]):traces.append(read_trace.verify(folder/"roles"/name,role,pair["commands"]))
            item["outer"]=[read_outer.verify(trace,pair["commands"],role)for trace,role in zip(traces,pair["roles"])]
            item["trace"]=read_trace.compare(traces,cases);item["native"]=[]
            for i,name in enumerate(read_pairs.ROLES[:2]):item["native"].append(read_native.verify(folder/"roles"/name/"capture",pair,i,m,admission,traces[i]))
        except BaseException as error:item.update(exception=repr(error),traceback=traceback.format_exc())
        results.append(item)
    result=dict(status="PURE_DIAGNOSTIC_ONLY",source_manifest_sha256=source(),groups=results,
        native_executions=0,rust_executions=0,application_executions=0,qualified=False)
    output.write_bytes(encoded(result));print(encoded(result).decode(),end="")
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--bundle",type=Path,required=True);p.add_argument("--output",type=Path,required=True)
    a=p.parse_args();run(a.bundle.resolve(strict=True),a.output.absolute())
