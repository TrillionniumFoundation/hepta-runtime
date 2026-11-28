#!/usr/bin/env python3
"""Run two new input-only cases in one bounded role; preserve every target byte and kernel event."""
from pathlib import Path
import argparse,locale,os,sys,unicodedata
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import canonical,decode,owned,pin,source_evidence,require
from cases import group,wire,validate
from filesystem import snapshot
from buffer_store import Writer
from stdio_process import run
def main():
    p=argparse.ArgumentParser()
    for name in("source","setup","build","output"):p.add_argument("--"+name,type=Path,required=True)
    p.add_argument("--group",required=True);p.add_argument("--role",choices=("original","production","observed"),required=True)
    a=p.parse_args();source=a.source.resolve(strict=True);identity=source_evidence(source);validate()
    require(not a.output.exists(),"fresh actual helper capture");a.output.mkdir(parents=True)
    store=Writer(a.output/"buffers");rows=[];queries={q["id"]:q for q in decode(owned(a.setup,"inputs.json").read_bytes())}
    native=a.role!="original";observed=a.role=="observed"
    if native:
        variant="observed"if observed else"production";binary=owned(a.build,variant+"/binary-read-stdio.elf")
        require(pin(binary)==decode(owned(source,"BUILD_REUSE.json").read_bytes())["executables"][variant],"fixed executed complete image")
    else:binary=Path(sys.executable).resolve(strict=True)
    env=dict(python=sys.version,unicode_version=unicodedata.unidata_version,lc_messages=locale.setlocale(locale.LC_MESSAGES),
        platform=sys.platform,machine=os.uname().machine)
    reference=decode(owned(source,"native/reference_environment.json").read_bytes())
    require(env["unicode_version"]==reference["unicode_version"]=="15.0.0"and env["lc_messages"]=="C"
        and env["platform"]=="linux"and env["machine"]=="x86_64"and sys.version_info[:3]==(3,12,3),
        "fixed original diagnostic platform")
    for case in group(a.group):
        q=queries[case["id"]];folder=a.output/("case-"+str(case["id"]).zfill(3))
        row=dict(id=case["id"],name=case["name"],input=q,before=snapshot(q["fixture"],store))
        if native:argv=[str(binary)];raw=wire(q)
        else:
            argv=[str(binary),"-I","-S","-B"]
            if case["fault"]:argv.append(str(owned(source,"scripts/fault_original.py")))
            argv.append(str(owned(source,"target/binary_file.py")));raw=canonical(q["request"])
        process=run(folder,argv,raw,observed=observed,native=native,
            input_chunk=case["input_chunk_bytes"],output_chunk=case["output_chunk_bytes"],fault=case["fault"])
        row.update(process=process,after=snapshot(q["fixture"],store));rows.append(row)
        (a.output/"cases.json").write_bytes(canonical(rows))
    result=dict(status="ACTUAL_STDIO_READ67_CAPTURE_COMPLETE",source=identity,role=a.role,group=a.group,cases=len(rows),
        process_count=len(rows),environment=env,executed_binary=pin(binary),original_outputs_read=False,
        observer_enabled=observed,passive_kernel_trace=True,buffer_images=store.images,logical_buffer_bytes=store.logical_bytes,
        streams={n:sum(r["process"]["streams"][n]["raw"]["bytes"]for r in rows)
            for n in("stdin","stdout","stderr","body","formatter","ack")},
        kernel_calls=sum(r["process"]["kernel"]["calls"]for r in rows),
        kernel_bytes=sum(r["process"]["kernel"]["raw"]["bytes"]for r in rows),
        runtime_python_required=not native,runtime_libc_required=not native,pid=os.getpid())
    (a.output/"CAPTURE.json").write_bytes(canonical(result));require(source_evidence(source)==identity,"source changed")
    print(canonical(result).decode(),end="")
if __name__=="__main__":main()
