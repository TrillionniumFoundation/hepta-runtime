"""Strict pair reader with a proved native inode-allocation lifetime split."""
from pathlib import Path
import copy,hashlib,json,stat,struct
import atomic_frames,read_capture_fixed as base
from wait_observations import need
from capture_common import structural_snapshots
HERE=Path(__file__).resolve().parent
doc=base.doc
pin=base.pin
def source_contract():
    contract=doc(HERE/"SOURCE_CONTRACT.json")
    for row in contract["source_files"]:
        need(pin((HERE/row["path"]).read_bytes())=={k:row[k] for k in ("bytes","sha256")},"complete immutable rename/read source contract")
    return contract
def read(folder,side,binary):
    values=base.read(folder,side,binary)
    report=doc(Path(folder)/"CAPTURE.json")
    for i,value in enumerate(values):
        value["_case_folder"]=str(Path(folder)/("%03d"%i))
        value["_fixture"]=report["fixture"]
    return values
def snapshots(row):
    values=[("initial",row["initial"])]
    values.extend((s["label"],s["snapshot"]) for s in row["steps"] if "snapshot" in s)
    values.append(("final",row["final"]))
    return values
def q(raw,at):
    need(0<=at<=len(raw)-8,"complete lifetime scalar")
    return struct.unpack_from("<Q",raw,at)[0]
def atomic_success(frame,target,temporary):
    c=frame["context"];raw=bytes.fromhex(frame["workspace_first_512_hex"])
    out=bytes.fromhex(frame["output_first_256_hex"]);body=bytes.fromhex(c["full_body_context_hex"])
    need(len(raw)==512 and len(out)>=32 and frame["descriptor"][2]>=1024,"complete allocated actual atomic terminal")
    need(q(raw,0)==100 and q(raw,144)==6 and q(raw,256)==int.from_bytes(b"HIAATFX1","little"),"actual completed six-effect atomic owner")
    need(q(raw,264)==6 and q(raw,272)==8 and q(raw,280)==q(raw,64) and q(raw,288)==1024 and q(raw,296)==0,"actual last rename request and exact path arguments")
    need([q(raw,i) for i in (304,312,320,328,344)]==[0]*5 and q(raw,336)==1,"actual consumed successful rename acknowledgment")
    need(q(raw,128)==q(raw,136)==0 and q(raw,112)==q(raw,48)>0,"actual full write and closed HIA temporary token")
    need(out[:8]==b"HRAWR001" and out[8:32]==bytes(24),"actual atomic owner success result")
    need(c["retained_temp_fd"]==-1 and q(body,2384)==(1<<64)-1 and q(body,2048+72)==0,"both actual native temporary and read descriptors closed")
    need(frame["paths"]["target"]=={"offset":1024,"length":len(target),"bytes_hex":target.hex(),"terminator":0},"actual rename destination bytes")
    need(frame["paths"]["temporary"]=={"offset":q(raw,64),"length":len(temporary),"bytes_hex":temporary.hex(),"terminator":0},"actual rename source bytes")
    need(q(raw,64)==1024+len(target)+1 and q(raw,72)==len(temporary),"exact complete temporary path layout")
    return {"trace_sequence":frame["trace_sequence"],"context_sequence":c["trace_sequence"],"node":c["node"],"host_generation":c["host_generation"],
        "input":c["accepted"],"workspace":frame["workspace"],"output":frame["output"],"body":c["full_contexts"]["body"],
        "workspace_first_512_hex":frame["workspace_first_512_hex"],"read_fd_owned":0,"temporary_fd":-1,
        "rename_sequence":6,"rename_operation":8,"rename_errno":0,"rename_ack":1,"data_bytes":q(raw,48)}
def normalized_with_birth(sequence,target_hex,cut):
    identities={};answer=[]
    for i,trees in enumerate(sequence):
        current=[]
        for tree in trees:
            nodes=[]
            for node in tree["nodes"]:
                value=dict(node)
                if "inode" in value:
                    identity=(value.pop("device"),value.pop("inode"),int(node["relative_hex"]==target_hex and i>=cut))
                    value["identity"]=identities.setdefault(identity,len(identities))
                    value.pop("mtime");value.pop("ctime")
                    if stat.S_ISDIR(value["mode"]):value.pop("size")
                nodes.append(value)
            current.append({"root_hex":tree["root_hex"],"nodes":nodes})
        answer.append(current)
    return answer
def prove_reallocation(left,right):
    contract=source_contract()
    original=doc(Path(left["_case_folder"])/"CASE.json");native=doc(Path(right["_case_folder"])/"CASE.json")
    need(original["input"]==native["input"] and original["name"]==native["name"],"exact source-owned common identity scenario")
    plan=native["input"];fixture=Path(right["_fixture"]);target=(fixture/"target").as_posix().encode()
    temporary=(fixture/".octofs_tmp_target.tmp").as_posix().encode();target_hex=b"target".hex()
    need(all(s["kind"] in ("wire","control","wait-lock") for s in plan["steps"]),"no other mutating fixture actor in inode-lifetime interval")
    calls=[]
    for step in plan["steps"]:
        if step["kind"]!="wire":continue
        message=json.loads(bytes.fromhex(step["wire_hex"]))
        if message.get("method")=="tools/call":
            need(message["params"]["name"]=="extract_lines","no other filesystem public handler in identity scenario")
            args=message["params"]["arguments"]
            need(args["append_path"]=="target" and args["append_line"]==-1,"same actual locked destination")
            calls.append(bytes.fromhex(step["wire_hex"]).rstrip(b"\n"))
    need(len(calls)==2,"two distinct actual request arrivals in one replacement interval")
    commands=[s for s in plan["steps"] if s["kind"]=="control"]
    need(len([s for s in commands if s["operation"]==1])==len([s for s in commands if s["operation"]==2])==1,"one actual held/wake interval")
    held=next(s for s in commands if s["operation"]==1);released=next(s for s in commands if s["operation"]==2)
    need(held["payload_hex"]==target.hex() and held["slot"]==released["slot"],"held and released same real lock capability")
    need(all(s["operation"] in (1,2,3) for s in commands),"no additional cache/setup actor in lifetime interval")
    osnap=snapshots(original);nsnap=snapshots(native)
    need([x[0] for x in osnap]==[x[0] for x in nsnap],"all corresponding actual snapshot barriers")
    complete=[[x[1]["complete_metadata"] for x in side] for side in (osnap,nsnap)]
    def target_nodes(sequence):
        result=[]
        for trees in sequence:
            need(len(trees)==1 and trees[0]["root_hex"]==str(fixture).encode().hex(),"same complete owned root")
            bypath={n["relative_hex"]:n for n in trees[0]["nodes"]}
            need(target_hex in bypath and b".octofs_tmp_target.tmp".hex() not in bypath,"temporary path absent at every retained barrier")
            row=bypath[target_hex]
            need(stat.S_ISREG(row["mode"]) and row["links"]==1,"one regular target link throughout interval")
            need(all((v.get("device"),v.get("inode"))!=(row["device"],row["inode"]) for p,v in bypath.items() if p!=target_hex),"no simultaneous alias to the target allocation")
            result.append(row)
        return result
    ot,nt=[target_nodes(s) for s in complete]
    changes=[i for i in range(1,len(ot)) if (ot[i]["device"],ot[i]["inode"])!=(ot[i-1]["device"],ot[i-1]["inode"])]
    need(len(changes)==1,"reference demonstrates exactly one observed allocation transition")
    cut=changes[0]
    need(all(x==ot[0] for x in ot[:cut]) and all(x==ot[cut] for x in ot[cut:]),"complete stable reference object intervals")
    need(all(x==nt[0] for x in nt[:cut]) and all(x==nt[cut] for x in nt[cut:]),"complete stable native object intervals")
    need((nt[0]["device"],nt[0]["inode"])==(nt[cut]["device"],nt[cut]["inode"]),"actual numeric allocation was reused")
    need(nt[0]["ctime"]!=nt[cut]["ctime"] and nt[0]["mtime"]!=nt[cut]["mtime"] and nt[0]["content_hex"]!=nt[cut]["content_hex"],"observed distinct complete native object versions")
    label=nsnap[cut][0]
    wait_steps=[s for s in native["steps"] if s["label"]==label]
    need(len(wait_steps)==1 and wait_steps[0]["kind"]=="wait-lock","transition observed after actual settled lock barrier")
    readiness=wait_steps[0]["readiness"]
    need(readiness["satisfied_by_actual_state"] and readiness["state"]["state"]["locks"]["entries"].get(target.hex())==1,"both actual request lock owners have retired before post-replacement observation")
    for sequence in complete:
        stable={n["relative_hex"]:n for n in sequence[0][0]["nodes"] if n["relative_hex"] not in ("",target_hex)}
        for trees in sequence:
            now={n["relative_hex"]:n for n in trees[0]["nodes"] if n["relative_hex"] not in ("",target_hex)}
            need(now==stable,"every other file allocation, timestamp and byte remained unchanged")
            root=trees[0]["nodes"][0]
            first=sequence[0][0]["nodes"][0]
            need(root["relative_hex"]=="" and (root["device"],root["inode"])==(first["device"],first["inode"]),"held directory object remained unchanged")
    actual=atomic_frames.inspect(Path(right["_case_folder"])/"process")
    finals=[f for f in actual["atomic_frames"] if f["context"]["stage"]==7]
    need(len(finals)==2,"two complete actual retired atomic contexts")
    need(len({(f["context"]["node"],f["context"]["host_generation"]) for f in finals})==2,"distinct actual request lifetimes")
    proofs=[]
    for i,frame in enumerate(finals):
        c=frame["context"];key=(c["node"],c["host_generation"])
        own=[f for f in actual["atomic_frames"] if (f["context"]["node"],f["context"]["host_generation"])==key]
        need(bytes.fromhex(c["accepted"]["input_hex"])==calls[i],"exact complete accepted public request for atomic owner")
        pending=[f for f in own if f["context"]["stage"]==3 and f["descriptor"][2]==0]
        restored=[f for f in own if f["context"]["stage"]==4 and f["descriptor"][2]==0]
        completed=[f for f in own if f["context"]["stage"]==3 and f["descriptor"][2]!=0]
        need(len(pending)==len(restored)==len(completed)==1,"actual empty-before-write and complete-after-write lifetime")
        need(pending[0]["trace_sequence"]<restored[0]["trace_sequence"]<completed[0]["trace_sequence"]<frame["trace_sequence"],"actual WAIT/restore/write/retire order")
        if i:need(finals[i-1]["trace_sequence"]<restored[0]["trace_sequence"],"second temporary creation follows retirement of first replaced object")
        before=atomic_success(completed[0],target,temporary);after=atomic_success(frame,target,temporary)
        need(before["workspace"]==after["workspace"] and before["output"]==after["output"] and before["body"]==after["body"],"complete terminal bytes unchanged through retirement")
        proofs.append(after)
    need(proofs[0]["data_bytes"]<proofs[1]["data_bytes"]==nt[cut]["size"],"two complete actual replacements culminating in observed final object")
    normalized=normalized_with_birth(complete[1],target_hex,cut)
    need(normalized==left["metadata"],"entire object identity relation matches after proved numeric reuse split")
    return normalized,{"status":"ACTUAL_TWO_RENAME_INODE_REALLOCATION_PROVED","source_contract":pin((HERE/"SOURCE_CONTRACT.json").read_bytes()),
        "scenario":native["name"],"first_new_snapshot":cut,"barrier":label,"target_hex":target.hex(),"temporary_hex":temporary.hex(),
        "actual_numeric_identity":{"device":nt[0]["device"],"inode":nt[0]["inode"]},"complete_old_metadata":nt[0],"complete_new_metadata":nt[cut],
        "reference_old_metadata":ot[0],"reference_new_metadata":ot[cut],"actual_atomic_lifetimes":proofs,
        "full_trace":actual["complete_trace"],"no_identity_field_ignored":True,"no_implementation_output_generated":True,"application_executions":0}
def compare(original,native):
    need(len(original)==len(native),"whole source-owned lane")
    revised=[];proofs=[]
    for left,right in zip(original,native,strict=True):
        for field in ("stdout","stderr","exit_code","tail","files","milestones"):
            need(left[field]==right[field],"complete "+field+" differs before lifetime analysis")
        value=copy.copy(right)
        if left["metadata"]!=right["metadata"]:
            value["metadata"],proof=prove_reallocation(left,right);proofs.append(proof)
        revised.append(value)
    result=base.compare(original,revised)
    result["inode_reallocation_proofs"]=proofs
    result["original_numeric_identity_labels_preserved"]=True
    result["complete_unadjusted_metadata_preserved"]=True
    return result
