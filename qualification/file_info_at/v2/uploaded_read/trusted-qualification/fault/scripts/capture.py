#!/usr/bin/env python3
"""One bounded lane; every input gets its own process and complete EOF evidence."""
from pathlib import Path
import argparse,gzip,hashlib,os,platform,sys,traceback
sys.dont_write_bytecode=True
SOURCE=Path(__file__).resolve().parents[1];sys.path.insert(0,str(SOURCE/"scripts"))
from evidence_common import encoded,decode,pin,require,source_evidence
from buffer_store import Writer
from carrier import Carrier
from cases import group
from filesystem import Fixture
from run_case import run
from continuation import declaration,seed
def main():
    p=argparse.ArgumentParser();p.add_argument("--role",choices=["original","native"],required=True)
    p.add_argument("--group",required=True);p.add_argument("--output",type=Path,required=True);p.add_argument("--build",type=Path)
    p.add_argument("--retained",type=Path,required=True)
    a=p.parse_args();identity=source_evidence(SOURCE);queries=group(a.group)
    require(not a.output.exists(),"fresh actual capture");a.output.mkdir(parents=True)
    store=Writer(a.output/"buffers");(a.output/"carriers").mkdir();native=a.role=="native"
    if native:
        require(a.build is not None,"frozen actual build");binary=(a.build/"file-info-at-callable.elf").resolve(strict=True)
        require(pin(binary)==decode((SOURCE/"BUILD_REUSE.json").read_bytes())["elf"],"exact runtime bytes")
    else:
        require(sys.version_info[:3]==(3,12,3)and sys.getfilesystemencoding()=="utf-8"
            and sys.getfilesystemencodeerrors()=="surrogateescape"and sys.platform=="linux","exact original platform")
        binary=Path(sys.executable)
        require(pin(binary)==dict(bytes=8020928,sha256="e50d468e8b0adfb05733f5b87b3cff34829c4a8c1aea50c865aa8bdfe4bb150f"),"exact original interpreter")
    plan=declaration(SOURCE,a.group,a.role);pending_ids=set(plan["newly_executed_ids"])
    count=0;calls=0;pins=[];current=None;fixture=None;carrier=None
    raw=(a.output/"cases.jsonl.gz").open("xb");stream=gzip.GzipFile(filename="",fileobj=raw,mode="wb",compresslevel=1,mtime=0)
    digest=hashlib.sha256();length=0;processes=[]
    try:
        for data,row in seed(SOURCE,a.retained,a.group,a.role,a.output,store):
            stream.write(data);stream.flush();raw.flush();digest.update(data);length+=len(data)
            count+=1;calls+=len(row["actual"]["chain"]["invocations"])
            pins.append(dict(id=row["input"]["id"],bytes=len(data),sha256=hashlib.sha256(data).hexdigest()))
            processes.append(dict(id=row["input"]["id"],path=row["process_path"],
                receipt=pin(a.output/row["process_path"]/"carrier-process.json")))
        for q in queries:
            if q["id"]not in pending_ids:continue
            current=q;fixture=Fixture(q);folder=a.output/"carriers"/str(q["id"]);folder.mkdir()
            argv=None if native else[binary,"-I","-S","-B",SOURCE/"scripts/reference_worker.py",SOURCE]
            carrier=Carrier(binary,folder,store,argv);value=run(carrier,q,fixture,store,native)
            receipt=carrier.finish();require(not(Path("/proc")/str(carrier.pid)).exists(),"child survived complete EOF and reap")
            row=dict(input=q,setup=fixture.setup,fixture_root=str(fixture.root),initial_parent=str(fixture.parent_path),
                physical_name=fixture.physical_name,actual=value,process=receipt,process_path=folder.relative_to(a.output).as_posix(),
                whole_process_exited=True,after_exit=fixture.all())
            data=encoded(row);stream.write(data);stream.flush();raw.flush();digest.update(data);length+=len(data)
            count+=1;calls+=len(value["chain"]["invocations"]);pins.append(dict(id=q["id"],bytes=len(data),sha256=hashlib.sha256(data).hexdigest()))
            processes.append(dict(id=q["id"],path=row["process_path"],receipt=pin(folder/"carrier-process.json")))
            carrier.cleanup();carrier=None;fixture.cleanup();fixture=None
        require(count==len(queries)and calls==sum(q["attempts"]for q in queries),"complete inherited prefix and new suffix")
        stream.close();raw.close()
        report=dict(status="PASS",role=a.role,group=a.group,source=identity,cases=count,case_rows=pins,
            cases_file=pin(a.output/"cases.jsonl.gz"),cases_raw=dict(bytes=length,sha256=digest.hexdigest()),processes=processes,
            buffers=dict(images=store.images,logical_bytes=store.logical_bytes,blocks=len(store.known)),
            platform=dict(python=sys.version,machine=platform.machine(),kernel=platform.release(),uid=os.geteuid(),
                gid=os.getegid(),groups=os.getgroups(),filesystem_encoding=sys.getfilesystemencoding(),filesystem_errors=sys.getfilesystemencodeerrors()),
            entry_invocations=calls,continuation=plan,actual_inputs_only=True,expected_values_generated=False,whole_runtime_replaced=False)
        require(source_evidence(SOURCE)==identity,"source changed during capture")
        (a.output/"CAPTURE.json").write_bytes(encoded(report))
        print(encoded(dict(status="PASS",role=a.role,group=a.group,cases=count,entry_invocations=calls,
            full_buffers=report["buffers"],processes=processes)).decode(),end="")
    except BaseException as e:
        failure=dict(status="FAIL",role=a.role,group=a.group,completed_cases=count,current_input=current,
            error_type=type(e).__name__,message=str(e),traceback=traceback.format_exc())
        if fixture is not None:
            try:failure["retained_failure_filesystem"]=fixture.all()
            except BaseException as other:failure["filesystem_observation_error"]=str(other)
        (a.output/"FAILURE.json").write_bytes(encoded(failure));raise
    finally:
        if not stream.closed:stream.close()
        if not raw.closed:raw.close()
        if carrier is not None:carrier.cleanup()
        if fixture is not None:fixture.cleanup()
if __name__=="__main__":main()
