#!/usr/bin/env python3
"""One bounded process lane; fixed original or HIA execution and full custody."""
from pathlib import Path
import argparse,gzip,hashlib,json,os,platform,sys,traceback
sys.dont_write_bytecode=True
SOURCE=Path(__file__).resolve().parents[1];sys.path.insert(0,str(SOURCE/"scripts"))
from evidence_common import encoded,decode,pin,require,source_evidence
from buffer_store import Writer
from carrier import Carrier
from cases import group
from filesystem import Fixture
def main():
    p=argparse.ArgumentParser();p.add_argument("--role",choices=["original","native"],required=True)
    p.add_argument("--group",required=True);p.add_argument("--output",type=Path,required=True);p.add_argument("--build",type=Path)
    a=p.parse_args();identity=source_evidence(SOURCE);queries=group(a.group)
    require(not a.output.exists(),"fresh capture only");a.output.mkdir(parents=True)
    store=Writer(a.output/"buffers");(a.output/"carrier").mkdir()
    if a.role=="native":
        require(a.build is not None,"frozen actual build required");binary=(a.build/"file-metadata-callable.elf").resolve(strict=True)
        require(pin(binary)==decode((SOURCE/"BUILD_REUSE.json").read_bytes())["elf"],"qualified production executable bytes")
        carrier=Carrier(binary,a.output/"carrier",store)
        from native_driver import run
    else:
        require(sys.version_info[:3]==(3,12,3)and sys.getfilesystemencoding()=="utf-8"
            and sys.getfilesystemencodeerrors()=="surrogateescape"and sys.platform=="linux","exact original platform profile")
        binary=Path(sys.executable)
        require(pin(binary)==dict(bytes=8020928,sha256="e50d468e8b0adfb05733f5b87b3cff34829c4a8c1aea50c865aa8bdfe4bb150f"),"frozen actual original interpreter")
        carrier=Carrier(binary,a.output/"carrier",store,[binary,"-I","-S","-B",SOURCE/"scripts/reference_worker.py",SOURCE])
        from reference_driver import run
    count=0;function_calls=0;casepins=[];current=None;fixture=None
    raw=(a.output/"cases.jsonl.gz").open("xb");cases=gzip.GzipFile(filename="",fileobj=raw,mode="wb",compresslevel=1,mtime=0)
    digest=hashlib.sha256();length=0
    try:
        for query in queries:
            current=query;fixture=Fixture(query)
            value=run(carrier,query,fixture,store)
            row=dict(input=query,setup=fixture.setup,actual=value)
            data=encoded(row);cases.write(data);cases.flush();raw.flush();digest.update(data);length+=len(data);count+=1;function_calls+=len(value["chain"]["invocations"])
            casepins.append(dict(id=query["id"],bytes=len(data),sha256=hashlib.sha256(data).hexdigest()))
            fixture.cleanup();fixture=None
        process=carrier.finish();cases.close();raw.close()
        report=dict(status="PASS",role=a.role,group=a.group,source=identity,cases=count,case_rows=casepins,
            cases_file=pin(a.output/"cases.jsonl.gz"),cases_raw=dict(bytes=length,sha256=digest.hexdigest()),
            carrier=process,buffers=dict(images=store.images,logical_bytes=store.logical_bytes,blocks=len(store.known)),
            platform=dict(python=sys.version,machine=platform.machine(),kernel=platform.release(),uid=os.geteuid(),
                gid=os.getegid(),groups=os.getgroups(),filesystem_encoding=sys.getfilesystemencoding(),filesystem_errors=sys.getfilesystemencodeerrors()),
            function_calls=function_calls,
            actual_inputs_only=True,expected_values_generated=False,whole_runtime_replaced=False)
        require(source_evidence(SOURCE)==identity,"source changed during actual capture")
        (a.output/"CAPTURE.json").write_bytes(encoded(report))
        print(encoded(dict(status="PASS",role=a.role,group=a.group,cases=count,full_journal=process["journal"]["raw"],
            full_buffers=report["buffers"])).decode(),end="")
    except BaseException as e:
        failure=dict(status="FAIL",role=a.role,group=a.group,completed_cases=count,current_input=current,
            error_type=type(e).__name__,message=str(e),traceback=traceback.format_exc())
        if fixture is not None:
            try:failure["retained_failure_filesystem"]=fixture.all()
            except BaseException as other:failure["filesystem_observation_error"]=str(other)
        (a.output/"FAILURE.json").write_bytes(encoded(failure));raise
    finally:
        if not cases.closed:cases.close()
        if not raw.closed:raw.close()
        if fixture is not None:fixture.cleanup()
        carrier.cleanup()
if __name__=="__main__":main()
