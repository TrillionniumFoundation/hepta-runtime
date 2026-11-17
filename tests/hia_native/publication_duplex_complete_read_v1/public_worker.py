#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Join actual public inputs, retained CALL loans and every native worker event."""
from pathlib import Path
import gzip,hashlib,json,struct
from common import require,pin,sha,decode
from buffer_store import Reader
import retained_worker_journal
U=lambda b,n:struct.unpack_from("<Q",b,n)[0]
class GzipInput:
    def __init__(self,path):self.path=path;self.digest=hashlib.sha256();self.length=0
    def open(self,mode):
        require(mode=="rb" and self.length==0,"pure single complete journal read")
        self.stream=gzip.open(self.path,"rb");return self
    def __enter__(self):return self
    def read(self,n=-1):
        b=self.stream.read(n);self.digest.update(b);self.length+=len(b);return b
    def __exit__(self,*args):self.stream.close()
    def identity(self):return dict(bytes=self.length,sha256=self.digest.hexdigest())
def body_input(request):
    p=request["params"];require(p["name"]=="text_file_write","actual publication request")
    a=p["arguments"]
    require(set(a)=={"path","mode","content","expected_sha256"} and a["mode"]=="create"
        and a["expected_sha256"]=="absent","frozen lifecycle arguments")
    path=a["path"].encode();content=a["content"].encode();expected=a["expected_sha256"].encode()
    return b"HTPBQ001"+struct.pack("<7Q",1,0,1,len(path),len(content),len(expected),
        len(path)+len(content)+len(expected))+path+content+expected
def verify(root,original_root,case):
    root=Path(root);original_root=Path(original_root)
    process=decode((root/"process/PROCESS.json").read_bytes())
    controls=decode((root/"process/CONTROLS.json").read_bytes())
    store=Reader(root/"buffers")
    first=controls[0];pms=[store.get(x) for x in first["pms"]]
    engines=[U(x,240) for x in pms]
    require(len(set(engines))==2 and all(engines),"two actual admitted PM engines")
    sent={engine:[] for engine in engines}
    for step in case["steps"]:
        if step.get("kind")=="send":
            raw=bytes.fromhex(step["wire_hex"])
            require(raw.endswith(b"\n") and b"\r" not in raw and raw.count(b"\n")==1,"exact single ordinary frame")
            sent[engines[step["session"]]].append(raw[:-1])
    accepted={};accepted_order={engine:[] for engine in engines};retired=set();jobs={}
    job_nodes={};groups=[];boundary={};closed=set();seq={};times={}
    counts={};frames=0;logical=0;digest=hashlib.sha256();group=None
    frame_proofs=[];pending_events=[];loan_zero=[];send_results=[]
    def key(h):return U(h,56),U(h,48),U(h,32)
    def node_admit(raw,k):
        require(len(raw) in (512,4096) and raw[:8]==b"HRPRTN01"
            and (U(raw,392),U(raw,400))==(k[0],k[2]) and k in accepted,"actual admitted private node")
        old=accepted[k]
        require((U(raw,64),U(raw,72),U(raw,80))==old["input_identity"],"retained original input mapping/extent")
        g=U(raw,32)
        require(g==old["sdk_generation"] or old["sdk_generation"]==0,"one actual SDK generation per host request")
        if g:old["sdk_generation"]=g
        return old
    path=root/"process/host-trace.gz"
    require(pin(path)==process["files"]["host-trace"]["gzip"],"full actual compressed host trace")
    with gzip.open(path,"rb") as stream:
        def read_exact(n):
            nonlocal logical
            require(0<=n<=768<<20,"complete bounded owned trace extent")
            b=stream.read(n);require(len(b)==n,"full real trace frame")
            digest.update(b);logical+=len(b);return b
        while True:
            magic=stream.read(8)
            if not magic:break
            require(len(magic)==8,"complete actual trace magic");digest.update(magic);logical+=8
            frames+=1
            if magic==b"HRGTR002":
                require(group is None,"no interrupted publisher observation group")
                read_exact(216);counts["grow"]=counts.get("grow",0)+1;continue
            if magic==b"HRCNAK02":
                require(group is None,"no interrupted publisher observation group")
                read_exact(120);counts["canonical"]=counts.get("canonical",0)+1;continue
            require(magic==b"HPTREV01","exact fixed host trace event")
            h=magic+read_exact(120);event=U(h,24);engine=U(h,56)
            require(engine in engines and U(h,120)==0 and U(h,96) in range(5),"actual engine/phase/header")
            require(U(h,16)==seq.get(engine,0)+1 and U(h,64)>=times.get(engine,0),"all host trace sequence/time")
            seq[engine]=U(h,16);times[engine]=U(h,64)
            lengths=[U(h,n) for n in (72,80,88)]
            require(U(h,8)==128+sum(lengths),"whole actual event extent")
            a,b,c=[read_exact(n) for n in lengths]
            counts[str(event)]=counts.get(str(event),0)+1;k=key(h)
            if event==1:
                require(group is None and engine not in closed and len(b)==512 and not c
                    and U(h,40)==0 and k[1]>0 and k[2]>0 and k not in accepted,"unique actual request admission")
                at=len(accepted_order[engine])
                require(at<len(sent[engine]) and a==sent[engine][at],"actual transport accepted exact sent bytes in session order")
                require(b[:8]==b"HRPRTN01" and (U(b,392),U(b,400))==(engine,k[2])
                    and U(b,72)==len(a) and U(b,80)>=len(a) and U(b,64)>0,"full input/node loan")
                accepted[k]=dict(raw=a,request=decode(a),input_identity=(U(b,64),U(b,72),U(b,80)),
                    sdk_generation=0,first=U(h,16),last_boundary=None)
                accepted_order[engine].append(k)
            elif event in (3,4,7):
                require(group is None and len(a)==512 and len(b)==1408,"whole original frontend mapping prefixes")
                rec=node_admit(a,k);require(U(h,40)==U(a,32),"actual SDK identity in trace header")
                require(U(a,216)==(0 if event==4 else 3),"real descriptor detach/restore ownership")
                rec["last_boundary"]=event;boundary[k]=dict(event=event,sequence=U(h,16),node=a)
                if event==7:
                    require(k not in retired,"one actual retirement")
                    retired.add(k)
                # Complete frontend response bytes or genuine WAIT are copied,
                # never replaced by a length-only descriptor.
                require(len(c)==U(a,144) and len(c)<=U(a,128),"actual frontend result extent")
            elif event==19:
                require(group is None and len(a)==4096 and len(b)==4096 and not c,"complete publisher node/context")
                rec=node_admit(a,k);require(k in boundary and U(h,40)==U(a,32),"actual publisher boundary")
                require(b[:8]==b"HTPAWC01" and U(b,8)==4096 and U(b,16)==engine and U(b,64)==k[1]
                    and U(b,32)>0 and U(b,40)>0 and U(b,48)>0 and U(b,56) in (1,2,3),"real worker capability")
                require(U(a,1184) in (0,1) and U(a,480)==0
                    and (U(b,56)==1)==bool(U(a,1184)),"publisher/extract ownership exclusion")
                job=U(b,40);tag=U(b,48);pool=U(b,32)
                if job in job_nodes:require(job_nodes[job]==k,"worker job cannot move to another actual request")
                else:job_nodes[job]=k
                q=rec["request"];require(q.get("method")=="tools/call","worker came from a real public request")
                expected=body_input(q)
                if job in jobs:
                    require(jobs[job]["tag"]==tag and jobs[job]["input"]==expected,"stable actual job/tag/input")
                else:
                    jobs[job]=dict(tag=tag,input=expected)
                    rec["job"]=job
                group=dict(key=k,node=a,context=b,job=job,tag=tag,pool=pool,phase=U(b,56),
                    boundary=boundary[k]["event"],sequence=U(h,16),next=[20]+([17,18] if U(a,1184) else [])+[21,22,23,24,25],
                    rows=[],scope=None,engine=None)
            elif event in (20,17,18,21,22,23,24,25):
                require(group is not None and k==group["key"] and group["next"] and event==group["next"].pop(0),
                    "complete ordered publisher mapping observation")
                node=group["node"];ctx=group["context"]
                if event==20:
                    require(len(a)==4096 and len(b)==16384 and not c
                        and U(a,216)==group["pool"] and U(b,400)==U(ctx,24)
                        and U(b,8)==engine+8192,"real process pool/hub and entire engine")
                    group["engine"]=b
                elif event in (17,18):
                    require(len(a)==64 and len(b)==U(a,16) and len(c)==U(a,32)
                        and U(a,8)>0 and U(a,24)>0,"complete actual request-owned View mapping")
                    if U(node,3872)==3:
                        off=3744 if event==17 else 3808
                        require(a==node[off:off+64],"same retained Scope/context descriptor")
                    else:require(U(node,3872)==0,"valid Scope ownership")
                    if event==17:
                        require(b[:8]==b"HRSCST01" and U(b,24)==1 and U(b,64)>0,"actual suspended active Scope")
                        group["scope_token"]=U(b,64)
                    else:
                        require(b[:8]==b"HRCXST01" and U(b,40)>0 and U(b,32)+32<=len(b)
                            and U(b,U(b,32)+8)==group["scope_token"],"same actual Scope stack token")
                else:
                    slot=event+43
                    require(len(a)==64 and len(b)==U(a,16) and len(c)==U(a,40)
                        and (not b)==(U(a,8)==0) and (not c)==(U(a,32)==0),"complete real publisher descriptor and mappings")
                    if U(node,216)==3:
                        off=1216+(slot-64)*64;wanted=node[off:off+64]
                    else:
                        require(U(node,216)==0,"actual live or retained descriptor")
                        off=8192+slot*64;wanted=group["engine"][off:off+64]
                    require(a==wanted,"observed mapping is the exact selected descriptor")
                    group["rows"].append(dict(slot=slot,descriptor=a.hex(),workspace=dict(bytes=len(b),sha256=sha(b)),
                        output=dict(bytes=len(c),sha256=sha(c))))
                    if slot==66:
                        require(len(b)>=4096 and U(a,24)==group["tag"],"actual admitted caller generation")
                        start,extent=U(b,288),U(b,296)
                        require(start>=4096 and extent>=64 and start+extent<=len(b)
                            and b[start:start+extent]==jobs[group["job"]]["input"],"actual caller child2 whole input loan")
                        if group["phase"]==1:
                            require((U(b,8),U(b,48),U(b,440),U(b,416))==(3,2,0,1)
                                and U(b,16)==U(b,264)==group["tag"],"unfinished actual await state")
                    if slot==67:
                        require(b==ctx and U(a,8)>0,"body descriptor owns the exact saved capability")
                        if group["phase"]==2:
                            require(U(a,48)==64 and U(a,56)==len(c)>=64 and c[:8]==b"HTPBS001"
                                and len(c)==64+U(c,56),"complete real borrowed worker result")
                            old=jobs[group["job"]].get("observed_terminal")
                            require(old is None or old==c,"retained worker result loan changed")
                            jobs[group["job"]]["observed_terminal"]=c
                        else:require(not c and U(a,56)==0,"pending/dropped future has no fabricated result")
                    if slot==68 and group["boundary"]==7:
                        require(not any(a) and not b and not c,"retirement has already ended the non-owning Scope68 loan")
                        loan_zero.append(group["job"])
                if not group["next"]:
                    require(len(group["rows"])==5,"all five actual publisher mappings retained")
                    rec=accepted[group["key"]];rec.setdefault("publisher_groups",[]).append(len(groups))
                    if group["phase"]==1:pending_events.append(dict(job=group["job"],host_generation=k[2],sdk_generation=U(node,32),sequence=group["sequence"]))
                    groups.append(dict(engine=engine,node=k[1],host_generation=k[2],sdk_generation=U(node,32),
                        job=group["job"],tag=group["tag"],pool=group["pool"],stage=group["phase"],
                        boundary=group["boundary"],trace_sequence=group["sequence"],rows=group["rows"]))
                    group=None
            elif event==6:
                require(group is None and len(a)==512,"complete actual send node")
                rec=node_admit(a,k);require(U(a,456)==U(h,104),"actual writer result")
                send_results.append(dict(engine=engine,node=k[1],host_generation=k[2],sdk_generation=U(a,32),
                    write_kind=U(a,464),write_result=U(a,456),sequence=U(h,16),request_id=rec["request"].get("id")))
            elif event==8:
                require(group is None and k[1:]==(0,0) and engine not in closed,"one actual service closure per session")
                closed.add(engine)
            elif event==2:
                require(group is None and len(a)>=64 and len(b)==192 and len(c)>=256
                    and U(h,112)>=len(c),"complete actual registry call and committed state")
            elif event==5:
                require(group is None,"complete unrelated Bellman READY")
                raise ValueError("publication-only domain cannot contain a Bellman READY")
            else:raise ValueError("unexpected actual host event "+str(event))
    require(group is None and set(closed)==set(engines),"both full services close after complete mapping groups")
    require(dict(bytes=logical,sha256=digest.hexdigest())==process["files"]["host-trace"]["raw"],"every actual host trace byte parsed")
    for engine in engines:
        require(len(accepted_order[engine])==len(sent[engine]),"all public requests and notifications admitted")
    require(retired==set(accepted),"all actual request mappings retired")
    public_nodes={k for k,v in accepted.items() if v["request"].get("method")=="tools/call"}
    require(set(job_nodes.values())==public_nodes and len(job_nodes)==len(public_nodes)
        and len({g["pool"] for g in groups})==1,"each real handler has one job on the one shared process pool")
    require(set(loan_zero)==set(jobs),"every settled job ends its borrowed Scope68 alias before retirement")
    journal=root/"process/publication-journal.gz"
    require(pin(journal)==process["files"]["publication-journal"]["gzip"],"full actual native journal compressed identity")
    incoming=GzipInput(journal)
    proof=retained_worker_journal.verify(incoming,dict(name=case["name"],observer=True),[],jobs,process["pid"])
    require(proof["bytes"]==incoming.length and incoming.identity()==process["files"]["publication-journal"]["raw"],
        "every complete actual worker journal byte")
    require(proof["drop"]==[] and set(proof["take"])==set(jobs),"SDK cancellation/ordinary EOF did not destroy handler futures")
    for job,row in jobs.items():
        require(row["terminal"]==row.pop("observed_terminal"),"exact full result loan equals actual worker body terminal")
    original_commands=decode((original_root/"COMMANDS.json").read_bytes());old=Reader(original_root/"buffers")
    final=decode(old.get(original_commands[-1]["response"]))["state"]["events"]
    entered={e["number"]:e["path"] for e in final if e["event"]=="entered"}
    returned={e["number"]:e["path"] for e in final if e["event"]=="returned" and e["ok"] is True}
    require(len(entered)==len(returned)==len(jobs) and entered==returned,"actual original handlers also returned rather than dropping await")
    delivered=[];by_path={}
    for job,k in job_nodes.items():
        rec=accepted[k];p=rec["request"]["params"]["arguments"]["path"]
        require(p not in by_path,"one original path per job");by_path[p]=(job,k,rec["request"]["id"])
    for sid in (0,1):
        with gzip.open(root/"process"/("stdout-"+str(sid)+".gz"),"rb") as stream:wire=stream.read()
        for line in wire.splitlines(keepends=True):
            value=decode(line);content=value.get("result",{}).get("content")
            if not isinstance(content,list) or len(content)!=1 or content[0].get("type")!="text":continue
            raw=content[0]["text"].encode()
            try:body=decode(raw)
            except (ValueError,json.JSONDecodeError):continue
            if not isinstance(body,dict) or body.get("path") not in by_path:continue
            job,k,identifier=by_path[body["path"]]
            require(k[0]==engines[sid] and value["id"]==identifier and type(value["id"]) is type(identifier)
                and jobs[job]["terminal"][64:]==raw,"delivered SDK result uses exact actual worker output for this session/request")
            require(job not in delivered,"one actual response per job");delivered.append(job)
    for job in delivered:
        k=job_nodes[job]
        actual=[r for r in send_results if (r["engine"],r["node"],r["host_generation"])==k]
        require(actual and actual[-1]["write_kind"]==3 and actual[-1]["write_result"]==1
            and any(r["write_kind"]==1 and r["write_result"]==0 for r in actual),"complete actual publisher send then LF for each delivered response")
    if case["name"]=="close_transport_pending":
        require(any(r["write_kind"]==1 and r["write_result"]==74
            and (r["engine"],r["node"],r["host_generation"]) in public_nodes for r in send_results),
            "actual closed transport completes failed publication through existing cancel terminal")
    return dict(status="COMPLETE_PUBLIC_CALL_WORKER_BORROW_AND_OS_REAP_JOIN_PASS",
        actual_engines=engines,all_public_nodes=len(accepted),publisher_jobs=len(jobs),
        host_frames=frames,host_bytes=logical,host_sha256=digest.hexdigest(),host_counts=counts,
        actual_worker=proof,pending_events=pending_events,full_mapping_groups=groups,ended_scope_loans=loan_zero,
        delivered_jobs=delivered,actual_write_results=send_results,
        jobs={str(j):dict(tag=v["tag"],input=dict(bytes=len(v["input"]),sha256=sha(v["input"])),
            terminal=dict(bytes=len(v["terminal"]),sha256=sha(v["terminal"]))) for j,v in jobs.items()},
        native_executed=False,rust_executed=False,direct_drop_domain_included=False,full_sdk=False)
