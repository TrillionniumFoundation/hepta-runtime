# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Actual two-context original/native capture. No expected result is consulted."""
from pathlib import Path
import argparse,json,os,struct,sys,time
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import canonical,decode,owned,pin,source_evidence,require
from cases import group,wire
from filesystem import snapshot
from buffer_store import Writer
from reference_carrier import Reference
from native_carrier import Carrier,WORD
from hooks import Hooks
from read_journal import result,I,stat_value
def process_view(pid,store):
    root=Path("/proc")/str(pid)
    return dict(fd={p.name:os.readlink(p)for p in sorted((root/"fd").iterdir(),key=lambda p:int(p.name))},
        maps=store.put((root/"maps").read_bytes()))
def main():
    p=argparse.ArgumentParser()
    for n in("source","setup","output"):p.add_argument("--"+n,type=Path,required=True)
    p.add_argument("--build",type=Path);p.add_argument("--group",required=True)
    p.add_argument("--native",action="store_true");p.add_argument("--unobserved",action="store_true");a=p.parse_args()
    source=a.source.resolve(strict=True);identity=source_evidence(source)
    require(not a.output.exists(),"fresh actual capture");a.output.mkdir(parents=True)
    inputs={r["id"]:r["roles"]for r in decode(owned(a.setup,"inputs.json").read_bytes())}
    store=Writer(a.output/"buffers");actor=None;rows=[];open_rows={};controls=[];tail=[]
    def save():
        (a.output/"cases.json").write_bytes(canonical(rows))
        (a.output/"hooks.json").write_bytes(canonical(dict(events=hooks.rows,mutations=hooks.mutations)))
        (a.output/"controls.json").write_bytes(canonical(controls))
        (a.output/"tail.json").write_bytes(canonical(tail))
    def observe(s):
        out={}
        for command,name in((4,"context"),(5,"workspace"),(6,"output"),(7,"input")):
            raw,n=actor.exchange(command,s);require(WORD(raw,8)==0,"native observation")
            out[name]=dict(exchange=n,bytes=store.put(raw[64:]))
        return out
    def refusal(s,name,command,payload,code):
        before=observe(s);raw,n=actor.exchange(command,s,payload);after=observe(s)
        require(WORD(raw,8)==code and all(before[k]["bytes"]==after[k]["bytes"]for k in before),"refusal mutated owned bytes: "+name)
        controls.append(dict(name=name,session=s,command=command,exchange=n,code=code,before=before,after=after))
    def stat(s):
        if a.native:
            raw,n=actor.exchange(11,s)
            value=dict(ok=True,metadata=stat_value(raw[64:]))if WORD(raw,8)==0 else dict(ok=False,errno=-I(WORD(raw,8)))
            return value,n
        return actor.exchange(dict(command="stat",session=s))
    def close_row(row):
        q=row["input"];s=q["session"];hooks.select(q)
        if a.native:
            raw,n=actor.exchange(10,s);require(WORD(raw,8)==64 and WORD(raw,24)==2 and WORD(raw,40)==0,"native close completion")
            value=result(raw[64:]);row["close_observation"]=observe(s)
            if q["id"]in(1,2)and not a.unobserved:
                refusal(s,"acquire-terminal",1,wire(q),0xfffffffd)
                refusal(s,"destroy-terminal",3,b"",0xfffffffd)
                refusal(s,"close-terminal",10,b"",0xfffffffd)
            dead,j=actor.exchange(12,s);require(I(WORD(dead,8))==-9 and WORD(dead,16)==0,"closed parent descriptor remains open")
            released,r=actor.exchange(2,s);require(WORD(released,8)==0 and WORD(released,24)==0,"native release")
            row["retired"]=dict(stat_exchange=j,release_exchange=r)
        else:
            value,n=actor.exchange(dict(command="close",session=s))
            dead,j=actor.exchange(dict(command="stat",session=s));require(dead==dict(ok=False,errno=9),"original closed descriptor remains open")
            row["retired"]=dict(stat_exchange=j)
        require(value==dict(ok=True),"actual close failed")
        row["close_result"]=value;row["close_exchange"]=n
        row["after_close_process"]=dict(process_view(actor.pid,store),at_exchange=actor.ordinal)
        open_rows.pop(s,None)
    try:
        actor=Carrier(a.build/"parent-directory-callable.elf",a.output,store)if a.native else Reference(source,a.output,store)
        hooks=Hooks(actor.pid,store);actor.hooks=hooks
        if a.native:
            for s in(0,1):
                raw,n=actor.exchange(9 if a.unobserved else 8,s);require(WORD(raw,8)==0,"native context creation")
                tail.append(dict(kind="create",session=s,exchange=n))
            if not a.unobserved:
                q=inputs[group(a.group)[0]["id"]];q=q.get("shared",q.get("native"));base=wire(q)
                variants=[("short-header",base[:95]),("wrong-magic",b"X"+base[1:])]
                for name,at,value in(("external-resume",8,2),("external-close",8,3),("sequence",16,1)):
                    b=bytearray(base);struct.pack_into("<Q",b,at,value);variants.append((name,bytes(b)))
                for name,b in variants:refusal(0,name,1,b,0xffffffff)
                refusal(0,"close-idle",10,b"",0xfffffffd)
        for case in group(a.group):
            role=inputs[case["id"]];q=role.get("shared",role.get("native"if a.native else"original"));s=q["session"]
            require(s not in open_rows,"same session still owns parent")
            hooks.select(q);begin_events=len(hooks.rows);start=time.monotonic_ns()
            row=dict(id=q["id"],input=q,before=snapshot(q["fixture"],store),hook_begin=begin_events)
            if a.native and open_rows:
                row["other_before"]={str(k):observe(k)for k in open_rows}
            hooks.limit_enter()
            try:
                if a.native:
                    raw,n=actor.exchange(1,s,wire(q));require(WORD(raw,8)==64,"native parent did not return a framed result")
                    value=result(raw[64:]);row["generation"]=WORD(raw,32);row["initial_observation"]=observe(s)
                else:
                    returned,n=actor.exchange(dict(command="acquire",session=s,query=q))
                    value=returned["result"];row["generation"]=returned["generation"];row["binding"]=returned["binding"]
            finally:hooks.limit_leave()
            row.update(acquire_exchange=n,result=value,descriptor_limit=hooks.limit)
            if a.native and open_rows:row["other_after"]={str(k):observe(k)for k in open_rows}
            if value["ok"]:
                row["before_mutation_stat"],row["before_mutation_stat_exchange"]=stat(s)
                require(row["before_mutation_stat"]["ok"],"acquired parent not valid")
                if q["mutation"]and q["mutation"].startswith("held_"):hooks.apply("held")
                row["held_stat"],row["held_stat_exchange"]=stat(s);require(row["held_stat"]["ok"],"held parent was lost")
                row["held_process"]=dict(process_view(actor.pid,store),at_exchange=actor.ordinal)
                open_rows[s]=row
                if a.native and q["id"]in(1,2)and not a.unobserved:
                    for name,cmd,payload in(("acquire-held",1,wire(q)),("release-held",2,b""),("destroy-held",3,b"")):
                        refusal(s,name,cmd,payload,0xffffffff if cmd==2 else 0xfffffffd)
                if q["close"]=="explicit":close_row(row)
            elif a.native:
                raw,j=actor.exchange(2,s);require(WORD(raw,8)==0,"error loan release")
                row["error_release_exchange"]=j
            row.update(hook_end=len(hooks.rows),after=snapshot(q["fixture"],store),elapsed_ns=time.monotonic_ns()-start,
                after_process=dict(process_view(actor.pid,store),at_exchange=actor.ordinal))
            rows.append(row);save()
        if open_rows and all(r["input"]["close"]=="deferred"for r in open_rows.values()):
            for s in sorted(open_rows,reverse=True):close_row(open_rows[s]);save()
        eof_ids=[open_rows[s]["id"]for s in sorted(open_rows)]
        require(not eof_ids or all(r["input"]["close"]=="eof"for r in open_rows.values()),"unexpected held parent at EOF")
        hooks.select(None)
        if a.native and not eof_ids:
            for s in(0,1):
                raw,n=actor.exchange(3,s);require(WORD(raw,8)==0,"native final context destroy")
                tail.append(dict(kind="destroy",session=s,exchange=n))
        before_eof=len(hooks.rows);receipt=actor.finish()
        save()
        require(not a.unobserved or receipt["journal"]["raw"]["bytes"]==0,"disabled observer emitted journal")
        result_doc=dict(status="ACTUAL_PARENT_DOMAIN_COMPLETE",role="native"if a.native else"original",
            group=a.group,cases=len(rows),source=identity,observer_enabled=not a.unobserved,
            process=receipt,exchanges=actor.ordinal,buffer_images=store.images,logical_buffer_bytes=store.logical_bytes,
            private_controls=len(controls),eof_case_ids=eof_ids,eof_hook_begin=before_eof,
            total_hooks=len(hooks.rows),mutations=len(hooks.mutations),actual_original_functions=not a.native,
            original_result_consulted_by_native=False)
        (a.output/"CAPTURE.json").write_bytes(canonical(result_doc));print(json.dumps(result_doc,sort_keys=True))
    finally:
        if actor:actor.cleanup()
if __name__=="__main__":main()
