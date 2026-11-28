#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Run the exact reference script or one native ELF; retain every process stream."""
from pathlib import Path
import argparse,json,locale,os,sys,time,unicodedata
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import canonical,decode,owned,pin,source_evidence,require
from cases import domain,group,wire,control
from filesystem import snapshot
from buffer_store import Writer
from stdio_process import run
def main():
    p=argparse.ArgumentParser()
    for name in("source","setup","build","output"):p.add_argument("--"+name,type=Path,required=True)
    p.add_argument("--group",required=True);p.add_argument("--role",choices=("original","production","observed","controls"),required=True)
    a=p.parse_args();source=a.source.resolve(strict=True);identity=source_evidence(source)
    require(not a.output.exists(),"fresh actual helper capture");a.output.mkdir(parents=True)
    store=Writer(a.output/"buffers");rows=[];queries={q["id"]:q for q in decode(owned(a.setup,"inputs.json").read_bytes())}
    native=a.role!="original";observed=a.role=="observed";is_control=a.role=="controls"
    if native:
        variant="observed"if observed else"production";binary=owned(a.build,variant+"/binary-read-stdio.elf");argv=[str(binary)]
        binding=decode(owned(source,"BUILD_REUSE.json").read_bytes())
        require(pin(binary)==binding["executables"][variant],"fixed executed image differs")
    else:
        binary=Path(sys.executable);argv=[str(binary),"-I","-S","-B",str(owned(source,"target/binary_file.py"))]
    env=dict(python=sys.version,unicode_version=unicodedata.unidata_version,lc_messages=locale.setlocale(locale.LC_MESSAGES),
        platform=sys.platform,machine=os.uname().machine)
    reference=decode(owned(source,"native/reference_environment.json").read_bytes())
    require(env["unicode_version"]==reference["unicode_version"]=="15.0.0"and env["lc_messages"]=="C"
        and env["platform"]=="linux"and env["machine"]=="x86_64"and sys.version_info[:3]==(3,12,3),
        "frozen original diagnostic platform changed")
    selected=domain()["controls"]if is_control else group(a.group)
    for case in selected:
        folder=a.output/("case-"+str(case["id"]).zfill(3))
        row=dict(id=case["id"],name=case["name"])
        if is_control:
            raw=control(case);chunk=case["input_chunk_bytes"];outchunk=65536
        else:
            q=queries[case["id"]];row.update(input=q,before=snapshot(q["fixture"],store))
            raw=wire(q)if native else canonical(q["request"])
            chunk=case["input_chunk_bytes"];outchunk=case["output_chunk_bytes"]
        process=run(folder,argv,raw,observed=observed,native=native,input_chunk=chunk,output_chunk=outchunk,control=is_control)
        row["process"]=process
        if not is_control:row["after"]=snapshot(q["fixture"],store)
        rows.append(row);(a.output/"cases.json").write_bytes(canonical(rows))
    result=dict(status="ACTUAL_STDIO_HELPER_CAPTURE_COMPLETE",source=identity,role=a.role,group=a.group,cases=len(rows),
        process_count=len(rows),environment=env,executed_binary=pin(binary),original_outputs_read=False,
        observer_enabled=observed,buffer_images=store.images,logical_buffer_bytes=store.logical_bytes,
        streams={name:sum(r["process"]["streams"][name]["raw"]["bytes"]for r in rows)
            for name in("stdin","stdout","stderr","body","formatter")},
        runtime_python_required=not native,runtime_libc_required=not native,pid=os.getpid())
    (a.output/"CAPTURE.json").write_bytes(canonical(result))
    require(source_evidence(source)==identity,"source changed during actual process domain")
    print(json.dumps(result,sort_keys=True))
if __name__=="__main__":main()
