#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Join real private direct futures, actual caller loans and every worker event."""
from pathlib import Path
import gzip,hashlib,json,struct
from common import require,pin,sha,decode
from buffer_store import Reader
import retained_worker_journal
from input_domain import startup
from direct_inputs import gateway
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
    for step in startup("legacy"):
        if step.get("kind")=="send":
            raw=bytes.fromhex(step["wire_hex"])
            require(raw.endswith(b"\n") and b"\r" not in raw and raw.count(b"\n")==1,"exact single ordinary frame")
            sent[engines[step["session"]]].append(raw[:-1])
    direct_commands=decode((root/"COMMANDS.json").read_bytes())
    expected_direct={};unpolled=[];direct_results={}
    for row in direct_commands:
        q=decode(store.get(row["request"]));first=controls[row["control_first"]]
        if q["kind"]=="direct_start":
            require(first["operation"]==6,"actual private start control")
            key=(engines[q["session"]],first["sequence"])
            require(key not in expected_direct,"one input per actual private host generation")
            expected_direct[key]=q
        elif q["kind"]=="direct_unpolled_drop":unpolled.append(q)
        elif q["kind"] in ("direct_drop","direct_join"):
            direct_results[q["session"],q["tag"]]=dict(kind=q["kind"],frame=bytes.fromhex(row["result"]["frame_hex"]),
                number=row["number"],control=row["control_first"],end=row["state_control"])
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
            elif event==26:
                require(group is None and len(b)==4096 and U(h,40)==0
                    and k[1]>0 and k[2]>0 and engine not in closed,"actual private direct boundary")
                q=expected_direct.get((engine,k[2]))
                require(q is not None and a==gateway(q) and U(b,288)==q["tag"],"complete real private input and control tag")
                require(b[:8]==b"HRPRTN01" and (U(b,392),U(b,400))==(engine,k[2])
                    and U(b,32)==0 and U(b,72)==len(a) and U(b,80)>=len(a) and U(b,64)>0,
                    "direct storage is not an invented SDK registry request")
                if k not in accepted:
                    accepted[k]=dict(raw=a,request=q,input_identity=(U(b,64),U(b,72),U(b,80)),
                        sdk_generation=0,first=U(h,16),last_boundary=None,direct=True)
                rec=node_admit(b,k)
                require(rec.get("direct") is True and U(b,216)==3 and U(b,280) in (1,2,3),
                    "real detached direct mappings")
                require(len(c)==U(b,144) and len(c)<=U(b,128),"whole direct gateway response extent")
                stage=U(b,280);raw=U(b,136)
                require(raw=={1:0xffffffdf,2:32,3:0xfffffff7}[stage]
                    and (stage==2 or not c),"actual pending/returned/CANCELLED return code")
                if stage==2:
                    require(c[:8]==b"HRCFGM01" and len(c)>=32 and U(c,16)==0
                        and U(c,24)==len(c)-32 and U(c,8) in (0,1),"whole real direct gateway result")
                    old=rec.get("result");require(old is None or old==c,"direct result loan changed")
                    rec["result"]=c
                rec["last_boundary"]=26
                boundary[k]=dict(event=26,sequence=U(h,16),node=b,stage=stage)
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
                q=rec["request"];require(rec.get("direct") is True and q["kind"]=="direct_start",
                    "worker came from actual fixed private gateway control")
                expected=body_input(dict(params=dict(name="text_file_write",arguments=q["parameters"])))
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
                        require(len(b)>=4096 and b[:8]==b"HTPCST01"
                            and U(b,16)==U(b,264)==U(a,24),"actual current caller/action generation")
                        start,extent=U(b,288),U(b,296)
                        require(start>=4096 and extent>=64 and start+extent<=len(b),"complete actual current caller loan")
                        if group["phase"]==1:
                            require(U(a,24)==group["tag"]
                                and (U(b,8),U(b,48),U(b,440),U(b,416))==(3,2,0,1)
                                and b[start:start+extent]==jobs[group["job"]]["input"],
                                "unfinished actual await and complete body child2 loan")
                            jobs[group["job"]]["pending_loan_seen"]=True
                        else:
                            # The successful HIA resumes the body action, then
                            # issues the actual forget and Scope-close actions.
                            # Its caller generation advances; the saved worker
                            # capability keeps the body-call generation.
                            require(group["phase"] in (2,3) and jobs[group["job"]].get("pending_loan_seen") is True,
                                "actual complete post-await/drop follows an admitted body loan")
                            if group["phase"]==2:
                                require(U(a,24)==group["tag"]+4
                                    and (U(b,8),U(b,48),U(b,440),U(b,416))==(0,0,3,0),
                                    "actual result forget then Scope close")
                            else:
                                require(U(a,24)==group["tag"]+1
                                    and (U(b,8),U(b,48),U(b,440),U(b,416))==(0,0,0,0)
                                    and U(b,200)==0 and U(b,216)==2,
                                    "actual future Drop issues one Scope-cancel action without post-await forget")
                            if group["phase"]==2:
                                close=b"HRSCQ001"+struct.pack("<7Q",7,U(b,112),U(b,120),0,0,0,0)
                            else:
                                close=b"HRSCQ001"+struct.pack("<7Q",8,U(b,112),0,2,0,0,0)
                            require(extent==64 and b[start:start+extent]==close,
                                "complete actual Scope close or Scope-cancel loan for this lifecycle")
                    if slot==67:
                        require(b==ctx and U(a,8)>0,"body descriptor owns the exact saved capability")
                        if group["phase"]==2:
                            require(U(a,48)==64 and U(a,56)==len(c)>=64 and c[:8]==b"HTPBS001"
                                and len(c)==64+U(c,56),"complete real borrowed worker result")
                            old=jobs[group["job"]].get("observed_terminal")
                            require(old is None or old==c,"retained worker result loan changed")
                            jobs[group["job"]]["observed_terminal"]=c
                        else:require(not c and U(a,56)==0,"pending/dropped future has no fabricated result")
                    if slot==68 and group["phase"] in (2,3) and not any(a):
                        require(not b and not c and group["phase"] in (2,3) and group["boundary"]==26,
                            "only a settled direct future can end its Scope68 loan")
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
    direct_nodes={k for k,v in accepted.items() if v.get("direct") is True}
    carrier_nodes=set(accepted)-direct_nodes
    require(retired==carrier_nodes,"all actual auxiliary public requests retired")
    require({(k[0],k[2]) for k in direct_nodes}==set(expected_direct)
        and set(job_nodes.values())==direct_nodes and len(job_nodes)==len(direct_nodes),
        "one actual worker per polled direct future, none for unpolled inputs")
    require(len({g["pool"] for g in groups})==(1 if jobs else 0),"one actual process publication pool")
    require(set(loan_zero)==set(jobs),"all settled direct futures end the real borrowed Scope68 alias")
    # The complete written reply has a retained direct mapping. The following
    # complete snapshot must observe that exact session mapping retired.
    for (sid,private_tag),record in direct_results.items():
        current=[k for k in direct_nodes if k[0]==engines[sid] and accepted[k]["request"]["tag"]==private_tag]
        require(len(current)==1,"one actual direct context per join/drop")
        k=current[0];rec=accepted[k]
        group_rows=[g for g in groups if (g["engine"],g["node"],g["host_generation"])==k]
        wanted=2 if record["kind"]=="direct_join" else 3
        require(group_rows and group_rows[-1]["stage"]==wanted and group_rows[-1]["job"] in loan_zero,
            "full terminal mappings and ended loan precede actual retirement")
        command=controls[record["control"]];snap=controls[record["end"]]
        pm=store.get(command["pms"][sid]);after=store.get(snap["pms"][sid])
        require(U(pm,1272)==k[1] and U(after,1272)==0,"real reply precedes direct storage retirement")
        if wanted==2:require(record["frame"]==rec.get("result"),"complete written join equals actual gateway result loan")
        else:require(record["frame"]==b"" and all(g["stage"]!=2 for g in group_rows),
            "actual destroyed future cannot return a fabricated result")
    last=controls[-1]
    require(all(U(store.get(x),1272)==0 for x in last["pms"]),"both direct future sets empty at process retirement")
    require(len(direct_results)==len(direct_nodes),"all polled futures explicitly joined or dropped")
    auxiliary=None
    aux_rows=decode((root/"AUXILIARY.json").read_bytes())
    for row in aux_rows:
        if row["kind"]!="real-queue-slot-occupied":continue
        require(auxiliary is None and case["mode"]=="queued","one real auxiliary queue body")
        co=store.get(controls[row["control_first"]]["coordinator"])
        job=U(co,2688);tag=0x100000000;payload=bytes.fromhex(row["input_hex"])
        require(job>0 and job not in jobs and U(co,2696)==1 and U(co,2728+32)==job,
            "actual auxiliary submit output and owned job identity")
        jobs[job]=dict(tag=tag,input=payload)
        final_co=store.get(last["coordinator"])
        require(U(final_co,2688)==job and U(final_co,2696)==2
            and U(final_co,3152+16)==job and U(final_co,3152+48)==tag,
            "actual auxiliary TAKE borrow and final release")
        auxiliary=job
    require((auxiliary is not None)==(case["mode"]=="queued"),"actual queue-capacity fixture inventory")
    journal=root/"process/publication-journal.gz"
    require(pin(journal)==process["files"]["publication-journal"]["gzip"],"whole actual worker journal")
    incoming=GzipInput(journal)
    if jobs:
        proof=retained_worker_journal.verify(incoming,dict(name=case["name"],observer=True),[],jobs,process["pid"])
        require(proof["bytes"]==incoming.length and incoming.identity()==process["files"]["publication-journal"]["raw"],
            "every actual worker HIA/OS/clone/reap byte")
    else:
        with incoming.open("rb") as stream:require(stream.read()==b"","unpolled future must never create worker journal events")
        require(incoming.identity()==process["files"]["publication-journal"]["raw"] and not groups and not job_nodes,
            "unpolled full empty worker evidence")
        proof=dict(bytes=0,drop=[],take=[],jobs=0,status="ACTUAL_UNPOLLED_NO_WORKER")
    expected_drop=set();expected_take=set()
    for job,k in job_nodes.items():
        rec=accepted[k];sid=engines.index(k[0]);out=direct_results[sid,rec["request"]["tag"]]
        if out["kind"]=="direct_drop":
            expected_drop.add(job);require("observed_terminal" not in jobs[job],"dropped handler never borrowed a result")
        else:
            expected_take.add(job)
            require(jobs[job]["terminal"]==jobs[job].pop("observed_terminal")
                and rec["result"][32:]==jobs[job]["terminal"][64:],"whole joined body equals actual worker terminal")
    if auxiliary is not None:expected_take.add(auxiliary)
    require(set(proof["drop"])==expected_drop and set(proof["take"])==expected_take,
        "only actual direct Future Drop destroys await; all other jobs taken/released")
    original_commands=decode((original_root/"COMMANDS.json").read_bytes());old=Reader(original_root/"buffers")
    final=decode(old.get(original_commands[-1]["response"]))["state"]["events"]
    entered={e["number"]:e["path"] for e in final if e["event"]=="entered"}
    returned={e["number"]:e["path"] for e in final if e["event"]=="returned" and e["ok"] is True}
    dropped={e["number"]:e["path"] for e in final if e["event"]=="dropped" and e["after_return"] is False}
    require(len(entered)==len(direct_nodes) and len(returned)==len(expected_take)-(1 if auxiliary else 0)
        and len(dropped)==len(expected_drop),"all original real future lifecycle counts")
    expected_paths={accepted[k]["request"]["parameters"]["path"] for k in direct_nodes}
    return_paths={accepted[job_nodes[j]]["request"]["parameters"]["path"] for j in expected_take if j!=auxiliary}
    drop_paths={accepted[job_nodes[j]]["request"]["parameters"]["path"] for j in expected_drop}
    require(set(entered.values())==expected_paths and set(returned.values())==return_paths
        and set(dropped.values())==drop_paths,"all actual original future paths and outcomes")
    return dict(status="COMPLETE_DIRECT_CALL_WORKER_DROP_BORROW_AND_OS_REAP_JOIN_PASS",
        actual_engines=engines,auxiliary_carrier_nodes=len(carrier_nodes),direct_futures=len(direct_nodes),
        unpolled_futures=len(unpolled),auxiliary_queue_job=auxiliary,publisher_jobs=len(job_nodes),
        host_frames=frames,host_bytes=logical,host_sha256=digest.hexdigest(),host_counts=counts,
        actual_worker=proof,pending_events=pending_events,full_mapping_groups=groups,ended_scope_loans=loan_zero,
        real_direct_drop_jobs=sorted(expected_drop),real_join_or_auxiliary_take_jobs=sorted(expected_take),
        jobs={str(j):dict(tag=v["tag"],input=dict(bytes=len(v["input"]),sha256=sha(v["input"])),
            terminal=dict(bytes=len(v["terminal"]),sha256=sha(v["terminal"]))) for j,v in jobs.items()},
        native_executed=False,rust_executed=False,full_sdk=False)
