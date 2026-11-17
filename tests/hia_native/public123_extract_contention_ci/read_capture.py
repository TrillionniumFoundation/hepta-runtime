"""Read full actual wire/state/files and compare the two actual executables."""
from pathlib import Path
import gzip,hashlib,json,struct
import wait_domain,wait_observations as obs
from wait_observations import need
from read_files import read_snapshot
from capture_common import structural_snapshots
from all_lines import AllLines
def pin(raw):return {"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()}
def doc(p):return json.loads(Path(p).read_bytes())
def raw_stream(folder,item):
    p=Path(folder)/Path(item["path"]).name
    need(pin(p.read_bytes())==item["compressed"],"complete compressed stream identity")
    with gzip.open(p,"rb") as stream:raw=stream.read()
    need(pin(raw)==item["uncompressed"],"complete raw stream identity")
    return raw
def control(folder,seq,side):
    prefix=Path(folder)/"controls"/("%04d"%seq)
    row=doc(prefix.with_suffix(".json"));request=prefix.with_suffix(".input.bin").read_bytes()
    need(row["sequence"]==seq and row["complete"] is True and row["failure"] is None and row["deadline_seconds"]==60 and 0<=row["elapsed_seconds"]<60,"actual successful bounded fixed exchange")
    need(pin(request)==row["input"] and row["accepted_input_bytes"]==len(request) and request[:8]==b"HXLTQ001","complete fixed input")
    sequence,op,slot,length,z0,z1,z2=struct.unpack_from("<7Q",request,8)
    need((sequence,op,slot)==(seq,row["operation"],row["slot"]) and 1<=op<=4 and slot<4 and length==len(request)-64 and z0==z1==z2==0,"source-owned control framing")
    response=raw_stream(prefix.parent,row["output"])
    need(row["actual_response_extent"]==len(response),"complete control reply extent")
    parsed=obs.frame(response,side);need(parsed==row["decoded"] and (parsed["sequence"],parsed["operation"],parsed["slot"],parsed["phase"])==(seq,op,slot,0),"complete decoded control identity")
    return row,request,parsed

def trace(folder,item,side):
    p=Path(folder)/Path(item["path"]).name
    need(pin(p.read_bytes())==item["compressed"],"complete compressed host trace")
    total=hashlib.sha256();size=0;at=0;sequence=0;counts={};final=[];pending=[];actual_lock_calls=[]
    fixed={b"HRGTR002":224,b"HRCNAK02":128,b"HWDIOAK2":160,b"HFSPCL02":80,b"HFSPAK02":192,b"HVRDACK1":128,b"HFLKEYFX":128}
    with gzip.open(p,"rb") as stream:
        def read(n):
            nonlocal size
            raw=stream.read(n);need(len(raw)==n,"full trace frame bytes");total.update(raw);size+=n;return raw
        while True:
            magic=stream.read(8)
            if not magic:break
            need(len(magic)==8,"complete trace magic");total.update(magic);size+=8
            if magic==b"HXLTR001":
                header=magic+read(56);words=struct.unpack_from("<7Q",header,8);length=words[4]+words[5]
                body=header+read(length);value=obs.frame(body,side)
                need(value["phase"]==value["operation"] in (90,91) and value["slot"]==0,"actual runtime Drop boundary")
                final.append(value)
            elif magic==b"HPTREV01":
                need(side=="native","original trace cannot contain native state")
                header=magic+read(120);values=struct.unpack_from("<15Q",header,8)
                extent,seq,event,hostgen,generation,node,engine,clock,an,bn,cn,phase,written,capacity,zero=values
                need(extent==128+an+bn+cn and seq==sequence+1 and 1<=event<=16 and phase<=4 and zero==0,"complete monotonic source-owned task trace")
                sequence=seq;payload=read(an+bn+cn);a=memoryview(payload)[:an];b=memoryview(payload)[an:an+bn];c=memoryview(payload)[an+bn:]
                counts[str(event)]=counts.get(str(event),0)+1
                if event==9:
                    need(an==bn==cn==4096,"complete retained node/caller/body contexts")
                    active=obs.q(a,480)[0]
                    need(active in (0,1),"actual pending-node flag")
                    if active:
                        need(obs.q(a,232)[0]==5 and obs.q(a,88+48)[0]==0xffffffdf and obs.q(a,88+56)[0]==0,"actual pending no-fabricated-output descriptor")
                        pending.append({"trace_sequence":seq,"node":node,"generation":generation,"host_generation":hostgen,"context":obs.q(a,1152)[0],"lease":obs.q(c,168)[0],"body_phase":obs.q(c,24)[0],"full_frame":pin(header+payload)})
                elif event in (10,11,12):
                    need(an==64,"complete descriptor observation")
                    if event==10:need(bn==obs.q(a,16)[0] and cn==obs.q(a,40)[0],"complete outer work/output buffers")
                    else:need(bn==obs.q(a,16)[0] and cn==obs.q(a,32)[0],"complete callable/shared work/output buffers")
                    if event==12 and b and b[:8]==b"HFLSTATE":obs.locks(b)
                elif event in (13,14):need(an==16 and cn==0 and bn==obs.q(a,8)[0],"complete owned region bytes")
                elif event==15:need((an,bn,cn)==(4096,16384,0),"complete shared hub and engine")
                elif event==16:
                    need(an>=64 and a[:8]==b"HRFLOCK1" and bn==64 and b[:8]==b"HRFLKR01" and cn==capacity and cn>=4096,"actual fixture HIA call full buffers")
                    operation=obs.q(a,8)[0];need(operation==obs.q(b,8)[0] and operation in (1,3,6) and obs.q(b,16)[0] in (0,1,2),"actual fixture lock transition")
                    obs.locks(c);actual_lock_calls.append({"trace_sequence":seq,"operation":operation,"status":obs.q(b,16)[0],"lease":obs.q(b,24)[0],"woken":obs.q(b,56)[0],"request":pin(a),"reply":pin(b),"workspace":pin(c)})
            else:
                need(side=="native" and magic in fixed,"entire source-owned trace inventory")
                read(fixed[magic]-8);counts[magic.decode()]=counts.get(magic.decode(),0)+1
            at=size
    need({"bytes":size,"sha256":total.hexdigest()}==item["uncompressed"],"entire decompressed host trace")
    need([x["phase"] for x in final]==[90,91],"both complete after-runtime Drop and after-fixture Drop observations")
    need(final[0]["sequence"]==final[1]["sequence"] and final[1]["private"]["fixture_holders"]==[False]*4,"actual fixture guard lifetime")
    if side=="native":need(pending and actual_lock_calls,"actual public WAIT and HIA lock calls were observed")
    return {"events":counts,"pending_nodes":pending,"fixture_hia_calls":actual_lock_calls,"final":final}

def process(folder,case,plan,side,binary,fixture):
    folder=Path(folder);p=doc(folder/"complete-process.json");base=doc(folder/"process.json")
    need(case["process"]==p and {k:p[k] for k in base}==base,"entire process receipts")
    need(p["schema"]=="hepta.runtime.complete-stdio-observer.v1","exact all-lines process schema")
    need(p["binary"]==binary and p["environment"]=={"PATH":"","LC_ALL":"C"} and p["cwd"]==str(fixture),"actual selected executable/environment/cwd")
    argv=p["native_argv"];config=str(fixture.parent/"config.json")
    need(argv[1:]==(["--stdio-wait-fixture",config] if side=="original" else ["--runtime-config",config]),"actual original/native public entry")
    command=p["command"];need(Path(command[0]).is_absolute() and command[1:4]==["-I","-S","-B"] and Path(command[4]).name=="fd_exec.py" and all(x.isdecimal() and int(x)>2 for x in command[5:8]) and command[8:]==argv,"fixed descriptor-only exec boundary")
    start=doc(folder/"started.json");need(all(start[k]==p[k] for k in ("command","native_argv","cwd","environment","pid","binary")) and start["fixed_capabilities"]==[3,4,5] and start["side"]==side,"complete actual start record")
    need(type(p["pid"]) is int and p["pid"]>0 and type(p["exit_code"]) is int and p["start_error"] is None,"terminal actual process identity")
    need(p["timed_out"] is p["wait_timed_out"] is p["kill_requested"] is p["failure_cleanup_requested"] is False and p["cleanup_error"] is None and p["pipe_eof"]=={"stdout":True,"stderr":True},"complete natural process exit")
    need(p["drain_deadline_seconds"]==60 and 0<=p["drain_elapsed_seconds"]<60 and p["wait_deadline_seconds"]==p["kill_cleanup_deadline_seconds"]==5 and p["response_count_assumed"] is None and p["nonzero_exit_is_observed_data"] is True,"unchanged process deadlines and all-line observation")
    streams={k:raw_stream(folder,v) for k,v in p["streams"].items()};need(set(streams)=={"attempted-stdin","stdin","stdout","stderr"},"all four public streams")
    lines=[];values=[];at=0
    while True:
        end=streams["stdout"].find(b"\n",at)
        if end<0:break
        raw=streams["stdout"][at:end+1];lines.append({"index":len(lines),"offset":at,**pin(raw)});values.append(raw);at=end+1
    need(doc(folder/"lines.json")==lines and pin((folder/"lines.json").read_bytes())==p["lines"] and len(lines)==p["complete_stdout_lines"],"all actual public lines")
    need(p["trailing_stdout"]=={"offset":at,**pin(streams["stdout"][at:])},"complete public tail")
    exchanges=doc(folder/"exchanges.json");journal=(folder/"exchanges.jsonl").read_bytes()
    need([json.loads(x) for x in journal.splitlines()]==exchanges and len(exchanges)==p["exchanges"]==p["exchange_journal"]["records"] and pin(journal)=={k:p["exchange_journal"][k] for k in ("bytes","sha256")} and p["exchange_journal"]["recording_error"] is None,"complete public exchange journal")
    seen_controls=[];input_at=0;exchange_index=0;timeline=[];milestones=[]
    need(len(case["steps"])==len(plan["steps"]),"every frozen step attempted")
    for i,(step,actual) in enumerate(zip(plan["steps"],case["steps"],strict=True)):
        need((actual["index"],actual["label"],actual["kind"])==(i,step["label"],step["kind"]),"exact ordered frozen input step")
        if step["kind"]=="wire":
            e=exchanges[exchange_index];need(actual["exchange"]==e and e["index"]==exchange_index and e["label"]==step["label"] and e["correlation_id"]==step["correlation_id"] and e["segments"]==[],"source-bound wire exchange")
            raw=bytes.fromhex(step["wire_hex"])
            need(e["attempted_input"]==e["accepted_input"]=={"offset":input_at,**pin(raw)} and streams["stdin"][input_at:input_at+len(raw)]==raw,"exact full public input accepted")
            need(e["deadline_seconds"]==60 and 0<=e["elapsed_seconds"]<60 and e["timed_out"] is False and e["error"] is None and e["response_count_assumed"] is None,"actual unchanged exchange budget")
            span=e["line_range"];match=step["correlation_id"] is not None and any(AllLines.matches(v,step["correlation_id"]) for v in values[span["first"]:span["first"]+span["count"]])
            need(e["matched_correlation"]==match and e["transport"]==("correlated" if match else "sent") and (step["correlation_id"] is None or match),"actual full-line barrier")
            timeline.append(e);input_at+=len(raw);exchange_index+=1
        elif step["kind"] in ("control","wait-lock"):
            sequences=[actual["observation"]["sequence"]] if step["kind"]=="control" else actual["readiness"]["observation_sequences"]
            need(sequences and sequences==list(range(len(seen_controls)+1,len(seen_controls)+len(sequences)+1)),"complete actual fixture command sequence")
            last=None
            for seq in sequences:
                c,raw,v=control(folder,seq,side)
                op,slot,payload=(step["operation"],step["slot"],bytes.fromhex(step["payload_hex"])) if step["kind"]=="control" else (3,0,b"")
                need((c["operation"],c["slot"],c["label"],raw[64:])==(op,slot,step["label"],payload),"frozen exact private command")
                if last is not None and step["kind"]=="wait-lock":need(last["state"]["locks"]["entries"].get(step["key_hex"])!=step["strong"],"readiness cannot skip an already satisfied observed state")
                seen_controls.append(seq);timeline.append(c);last=v
            if step["kind"]=="control":need(last==actual["observation"],"complete control state association")
            else:
                r=actual["readiness"];need(r["state"]==last and r["satisfied_by_actual_state"] is True and r["deadline_seconds"]==60 and 0<=r["elapsed_seconds"]<60 and last["state"]["locks"]["entries"].get(step["key_hex"])==step["strong"],"readiness from real full lock state")
            milestones.append({"step":i,"label":step["label"],"state":last["state"],"holders":last["private"]["fixture_holders"]})
        elif step["kind"]=="control-close":need(actual["control_closed"] is True,"actual control EOF")
        else:
            need(step["kind"]=="write" and actual["action"][0]["status"]=="EXECUTED" and actual["action"][0]["action"]=={"kind":"write","path_hex":step["path"].encode().hex(),"data_hex":step["bytes_hex"]},"only frozen owned fixture mutation")
    need(exchange_index==len(exchanges) and streams["stdin"]==streams["attempted-stdin"] and input_at==len(streams["stdin"]) and p["fixed_control_commands"]==len(seen_controls),"full public/private input coverage")
    need(len(list((folder/"controls").glob("*.json")))==len(seen_controls),"no hidden fixture command")
    out=err=line=0
    for row in timeline:
        need(row["stdout_range"]["offset"]==out and row["stderr_range"]["offset"]==err and row["line_range"]["first"]==line,"complete public-read event coverage")
        out+=row["stdout_range"]["bytes"];err+=row["stderr_range"]["bytes"];line+=row["line_range"]["count"]
        need(out<=len(streams["stdout"]) and err<=len(streams["stderr"]) and line<=len(lines),"bounded observed ranges")
    need(p["drain_line_range"]=={"first":line,"count":len(lines)-line},"complete actual EOF line drain")
    hosts=p["fixed_capabilities"];need(set(hosts)=={"worker-journal","host-trace"} and all(v["raw_retired_after_all_bytes_compared"] is True for v in hosts.values()),"complete fixed capability evidence")
    raw_stream(folder,hosts["worker-journal"])
    traces=trace(folder,hosts["host-trace"],side)
    need(traces["final"][-1]["sequence"]==len(seen_controls),"final actual controller sequence")
    return {"stdout":streams["stdout"],"stderr":streams["stderr"],"exit_code":p["exit_code"],"tail":p["trailing_stdout"],"milestones":milestones,"trace":traces}

def read(folder,side,binary):
    folder=Path(folder);report=doc(folder/"CAPTURE.json")
    need(report["status"]=="COMPLETE_ACTUAL_CONTENTION_DOMAIN_CAPTURED" and report["side"]==side and report["lane_seconds"]==180 and report["per_exchange_seconds"]==60 and 0<=report["elapsed_seconds"]<180 and report["original_old_domains_replayed"] is False,"complete actual lane")
    plan=wait_domain.domain(report["domain"],Path(report["fixture"]));need(doc(folder/"DOMAIN.json")==plan,"exact whole frozen input domain")
    selected=report["binary"];need({k:selected[k] for k in ("bytes","sha256")}==binary and pin((folder/selected["captured_file"]).read_bytes())==binary,"entire actual runtime binary")
    need(len(report["cases"])==len(plan["cases"])==4,"all four lane cases")
    result=[]
    for i,item in enumerate(plan["cases"]):
        case=folder/("%03d"%i);row=doc(case/"CASE.json")
        need(report["cases"][i]=={"index":i,"name":item["name"],"case":pin((case/"CASE.json").read_bytes())} and row["input"]==item and row["name"]==item["name"] and row["index"]==i and row["status"]=="ACTUAL_PROCESS_EOF_AND_RUNTIME_DROP_CAPTURED","complete case identity")
        used=set();snapshots=[row["initial"]]+[s["snapshot"] for s in row["steps"] if "snapshot" in s]+[row["final"]]
        views=[read_snapshot(case,s,Path(report["fixture"]),used) for s in snapshots]
        expected_files={x["path"].encode().hex():x for x in item["files"]}
        need({r["path_hex"] for r in views[0]["nodes"]}==set(expected_files),"exact frozen initial filesystem inventory")
        for initial in views[0]["nodes"]:
            original=expected_files[initial["path_hex"]]
            need(initial["kind"]=="file" and initial["mode"]==original["mode"] and (case/"blobs"/initial["content"]["path"]).read_bytes()==bytes.fromhex(original["bytes_hex"]),"exact frozen initial file bytes/mode")
        expected_setup=[]
        for initial in item["files"]:
            path=(Path(report["fixture"])/initial["path"]).as_posix().encode().hex()
            expected_setup.extend([{"kind":"write","path_hex":path,"data_hex":initial["bytes_hex"]},{"kind":"chmod","path_hex":path,"mode":initial["mode"]}])
        need([x["action"] for x in row["setup"]]==expected_setup and all(x["status"]=="EXECUTED" for x in row["setup"]),"complete actual frozen fixture setup")
        need(used=={p.name for p in (case/"blobs").iterdir()},"all complete filesystem blobs accounted")
        p=process(case/"process",row,item,side,binary,Path(report["fixture"]))
        p.update(name=item["name"],files=views,metadata=structural_snapshots([s["complete_metadata"] for s in snapshots]))
        result.append(p)
    return result
def compare(original,native):
    need(len(original)==len(native),"whole original/native lane cardinality")
    summaries=[]
    for a,b in zip(original,native,strict=True):
        need(a["name"]==b["name"],"same actual scenario")
        for field in ("stdout","stderr","exit_code","tail","files","metadata","milestones"):
            need(a[field]==b[field],"actual original/native "+field+" differs in "+a["name"])
        for x,y in zip(a["trace"]["final"],b["trace"]["final"],strict=True):
            need(x["state"]==y["state"] and x["private"]["fixture_holders"]==y["private"]["fixture_holders"],"actual runtime Drop/fixture Drop state differs in "+a["name"])
        summaries.append({"name":a["name"],"wire_bytes":len(a["stdout"]),"state_milestones":len(a["milestones"]),"filesystem_snapshots":len(a["files"]),"native_pending_context_observations":len(b["trace"]["pending_nodes"]),"native_fixture_hia_calls":len(b["trace"]["fixture_hia_calls"]),"both_actual_runtime_drop_boundaries":True})
    return {"status":"ACTUAL_PUBLIC_CONTENTION_COMPLETE_PAIR_PASS","cases":summaries,"expected_wire_generated":False,"application_semantics_replayed_by_reader":False}
