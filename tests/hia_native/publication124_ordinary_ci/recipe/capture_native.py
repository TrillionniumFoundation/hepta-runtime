#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Capture only the new native graph; retain the previously completed actual SDK role."""
from pathlib import Path
import argparse,importlib.util,json,os,shutil,struct,sys,time
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"recipe"));sys.path.insert(0,str(ROOT))
from common import canonical,decode,require,pin
from buffer_store import Writer
from body_filesystem import snapshot
from public_domain import PROFILES,ERAS,rows,stdio_rows,declaration
spec=importlib.util.spec_from_file_location("retained_publisher_process",ROOT/"retained/capture_gateway.py")
retained=importlib.util.module_from_spec(spec);spec.loader.exec_module(retained)
Q=lambda *v:struct.pack("<"+"Q"*len(v),*v)
U=lambda raw,at:struct.unpack_from("<Q",raw,at)[0]
class Process(retained.Process):
    def public_frame(self,deadline):
        head=self.take(96,deadline)
        require(head[:8]==b"HFSJPR03" and U(head,8) in (0,1) and U(head,16)<=4
            and U(head,24) in (0,1) and head[80:96]==bytes(16),"complete actual public carrier header")
        return head+(self.line(deadline) if U(head,16) in (1,2,3) else b"")
def original_command(row):
    cmd=dict(id=row["id"],kind=row["kind"],session=row["session"])
    if row["kind"] in ("wire","cache"):
        cmd["wire_hex"]=row["wire_hex"]
    if row["kind"]=="wire":cmd["response"]=row["response"]
    return canonical(cmd)
def native_command(row):
    raw=bytes.fromhex(row["wire_hex"])
    if row["kind"]=="wire":
        require(raw.endswith(b"\n"),"complete public input line")
        raw=raw[:-1];slot=34
    else:
        require(row["kind"]=="cache","only exact cache fixture input")
        slot=32
    out=b"HFSFXQ02"+Q(row["session"],slot,len(raw))+raw
    out+=b"".join(b"HFSFXQ02"+Q(sid,33,0) for sid in (0,1))
    out+=b"HFSFXQ02"+Q(0,41,0)
    return out
def execute(dependencies,output,profile,era,mode):
    require(os.environ.get("GITHUB_ACTIONS")=="true","HIA/Rust execution restricted to CI")
    require(profile in PROFILES and era in ERAS and mode in ("carrier","stdio"),"declared public domain")
    output=Path(output);require(not output.exists(),"fresh semantic capture required");output.mkdir(parents=True)
    deps=decode(Path(dependencies).read_bytes())
    (output/"DEPENDENCIES.json").write_bytes(canonical(deps))
    native=Path(deps["filesystem_binary"] if mode=="carrier" else deps["public_binary"])
    original=Path(deps["original_binary"])
    require(pin(native)==deps[mode+"_binary_pin"],"frozen actual native executable differs")
    root=output/"fixtures-root";retained.setup(root,profile)
    defined=rows(profile,root,era) if mode=="carrier" else stdio_rows(root,era)
    (output/"DOMAIN.json").write_bytes(canonical(declaration()))
    (output/"cases.jsonl").write_bytes(b"".join(canonical(r) for r in defined))
    config=output/"config.json";configured=profile!="absent"
    if configured:
        config.write_bytes(canonical(dict(state_dir=str(output/"controller-state"),
            controller_workspace_roots=[] if profile=="denied" else [str(root)],
            hosts={"fixture":dict(ssh_target="uncontacted-gateway-reference",remote_state_dir="/unused-runtime-state",
                allow_write=True,allowed_read_path_prefixes=["/allowed"],allowed_write_path_prefixes=["/allowed"],
                protected_path_prefixes=["/allowed/protected"])})))
        config.chmod(0o600)
    results=[]
    try:
        for role,binary in (("native",native),):
            if role=="original":retained.setup(root,profile)
            lane=output/role;lane.mkdir();buffers=Writer(lane/"buffers")
            command=[binary]
            if role=="original" and mode=="stdio":command.append("--stdio")
            if configured:command+=(["--runtime-config",config] if role=="native" else [config])
            proc=Process(command,root,lane,profile=="fence_required")
            ok=False;completed=0
            try:
                with (lane/"records.jsonl").open("xb") as records:
                    for index,row in enumerate(defined):
                        start=time.monotonic();deadline=start+60
                        observed=root/row["fixture"]
                        before=snapshot(observed,buffers)
                        if mode=="stdio":wire=bytes.fromhex(row["wire_hex"])
                        elif role=="native":wire=native_command(row)
                        else:wire=original_command(row)
                        proc.send(wire,deadline)
                        if mode=="stdio":response=proc.line(deadline) if row["response"] else b""
                        elif role=="original":response=proc.line(deadline)
                        else:
                            response=(proc.public_frame(deadline) if row["kind"]=="wire" else proc.frame(deadline))
                            response+=b"".join(proc.frame(deadline) for _ in range(3))
                        after=snapshot(observed,buffers)
                        record=dict(index=index,input=row,request=buffers.put(wire),response=buffers.put(response),
                            fixture=str(observed),before=before,after=after,
                            elapsed_ns=int((time.monotonic()-start)*1_000_000_000))
                        records.write(canonical(record));records.flush();completed+=1
                        require(time.monotonic()<deadline and time.monotonic()<proc.started+180,
                            "public capture exceeded frozen60/180 deadlines")
                ok=True
            finally:
                try:proc.finish(ok)
                finally:
                    report=dict(role=role,profile=profile,era=era,mode=mode,completed=completed,total=len(defined),
                        capture_completed=ok,source_dependencies=deps,native_binary=pin(native),original_binary=deps["original_binary_pin"],
                        complete_buffers=buffers.images,logical_buffer_bytes=buffers.logical_bytes,
                        per_exchange_seconds=60,per_process_seconds=180,public_comparison=False,full_async=False)
                    (lane/"CAPTURE.json").write_bytes(canonical(report));results.append(report)
            require(ok,"public capture incomplete")
        report=dict(status="COMPLETE_PUBLIC_PUBLISHER_CAPTURE_ONLY",profile=profile,era=era,mode=mode,
            cases=len(defined),roles=results,semantic_comparison=False)
        (output/"CAPTURE.json").write_bytes(canonical(report))
        print(json.dumps({k:report[k] for k in ("status","profile","era","mode","cases")},sort_keys=True))
    finally:
        if root.exists():
            require(root.parent==output and root.name=="fixtures-root","owned fixture retirement identity")
            retained_buffers=Writer(output/"retired-fixture-buffers")
            final=snapshot(root,retained_buffers)
            (output/"RETIRED_FIXTURE.json").write_bytes(canonical(dict(root=str(root),complete_snapshot=final,
                captured_before_retirement=True,case_buffers_preserved=True)))
            shutil.rmtree(root)
def main():
    p=argparse.ArgumentParser()
    p.add_argument("--dependencies",required=True,type=Path)
    p.add_argument("--output",required=True,type=Path)
    p.add_argument("--profile",required=True,choices=PROFILES)
    p.add_argument("--era",required=True,choices=ERAS)
    p.add_argument("--mode",required=True,choices=("carrier","stdio"))
    a=p.parse_args()
    execute(a.dependencies,a.output,a.profile,a.era,a.mode)
if __name__=="__main__":main()
