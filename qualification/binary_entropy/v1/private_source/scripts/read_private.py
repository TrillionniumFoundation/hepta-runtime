#!/usr/bin/env python3
"""Read complete private transport buffers; no native, original or compiler execution."""
from pathlib import Path
import argparse,struct,sys
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from evidence_common import decode,encoded,owned,pin,require,sha,source_evidence
from protocol import MASK,request,u
from entropy_model import Model
INVALID=4294967295
CAPACITY=4294967294
def source_check(source):
    identity=source_evidence(source);domain=decode(owned(source,"PRIVATE_DOMAIN.json").read_bytes())
    require(domain["schema"]=="hepta.runtime.binary-entropy.private-interface-domain.v1"
        and domain["native_build_commit"]=="a74ab0d0a4158c72f85921119dad76aca89d6a23"
        and domain["application_deadline_seconds"]==60 and domain["pure_deadline_seconds"]==180
        and domain["synthetic_syscall_responses_are_private_transport_inputs"]is True
        and domain["actual_kernel_entropy_applications"]==domain["original_applications"]==0,
        "frozen private protocol scope")
    require(len(domain["framing"])==domain["framing_calls"]==37 and len(domain["flows"])==29
        and sum(len(f["calls"])for f in domain["flows"])==domain["flow_calls"]==179
        and sum(bool(i["native_reject"])for i in domain["framing"])==domain["native_rejections"]==24,
        "complete frozen private domain counts")
    for rows in(domain["framing"],domain["flows"]):
        require(len({r["name"]for r in rows})==len(rows),"unique private labels")
    for flow in domain["flows"]:
        require(flow["workspace_capacity"]==4096 and flow["workspace_fill"]==0
            and flow["calls"][0]["kind"]=="start","cold complete persistent private workspace")
        for call in flow["calls"]:
            wire=bytes.fromhex(call["wire_hex"])
            require(wire.hex()==call["wire_hex"]and 64<=call["output_capacity"]<=256
                and call["kind"]in("start","resume","invalid","retry"),"exact private input")
            if call["kind"]=="start":require(wire==request(call["mode"]),"frozen start packet")
    return identity,domain
def growth(kind,size):
    return b"HENTR001"+struct.pack("<7Q",kind,0,0,size,0,0,0)
def verify(source,capture):
    source,capture=Path(source),Path(capture);identity,domain=source_check(source)
    summary=decode(owned(capture,"CAPTURE.json").read_bytes())
    binding=decode(owned(source,"BUILD_REUSE.json").read_bytes())
    build=decode(owned(capture,"BUILD.json").read_bytes())
    require(summary["status"]=="PRIVATE_INTERFACE_CAPTURE_COMPLETE"and summary["source"]==identity
        and summary["domain"]==pin(source/"PRIVATE_DOMAIN.json")and summary["executable"]==binding["elf"]
        and summary["build"]==pin(capture/"BUILD.json")and build["executable"]==binding["elf"]
        and build["image_order"]==["body"]and len(build["image_offsets"])==1,
        "exact qualified private executable and source")
    require(summary["private_hia_entry_calls"]==216 and summary["private_native_admission_calls"]==24
        and summary["actual_kernel_entropy_applications"]==summary["original_applications"]==0
        and summary["native_observer_events"]==dict(bytes=0,sha256=sha(b""),events=0)
        and owned(capture,"native-events.bin").read_bytes()==b"","complete private call scope")
    expected_files={"CAPTURE.json","BUILD.json","native-events.bin","hia/CALLS.json","native/CALLS.json"}
    rows=decode(owned(capture,"hia/CALLS.json").read_bytes());position=0;total_bytes=0
    require(len(rows)==216,"complete private HIA records")
    def read_bin(folder,value,name):
        nonlocal total_bytes
        require(value["path"]==name and set(value)=={"path","bytes","sha256"},"exact retained buffer name")
        key=folder+"/"+name;path=owned(capture,key);raw=path.read_bytes()
        require(dict(bytes=len(raw),sha256=sha(raw))=={k:value[k]for k in("bytes","sha256")},
            "complete private buffer bytes")
        expected_files.add(key);total_bytes+=len(raw);return raw
    def buffers(label,item,wcap):
        nonlocal position
        row=rows[position];prefix=str(position).zfill(4)
        require(row["index"]==position and row["label"]==label and row["input"]==item
            and row["workspace_capacity"]==wcap and set(row["before"])==set(row["after"])=={"input","output","work"},
            "fixed private HIA input order")
        before={n:read_bin("hia",row["before"][n],prefix+"-"+n+"-before.bin")for n in("input","output","work")}
        after={n:read_bin("hia",row["after"][n],prefix+"-"+n+"-after.bin")for n in("input","output","work")}
        wire=bytes.fromhex(item["wire_hex"]);cap=item["output_capacity"]
        require(before["input"]==after["input"]==wire+bytes([0xd3])*16
            and before["output"]==bytes([0xa5])*cap+bytes([0xe7])*16
            and len(after["output"])==cap+16 and after["output"][-16:]==bytes([0xe7])*16
            and len(before["work"])==len(after["work"])==wcap+16
            and before["work"][-16:]==after["work"][-16:]==bytes([0xa9])*16,
            "complete input, arena extents and all guard bytes")
        require(type(row["workspace_address"])is int and 0<row["workspace_address"]<(1<<63),
            "actual persistent workspace address")
        position+=1;return row,before,after
    for item in domain["framing"]:
        row,before,after=buffers("framing/"+item["name"],item,item["workspace_capacity"])
        require(row["return_value"]==item["expected_return"]
            and before["work"]==bytes([item["workspace_fill"]])*item["workspace_capacity"]+bytes([0xa9])*16
            and after["work"]==before["work"],"framing return and unchanged full workspace")
        expected=before["output"]if row["return_value"]in(INVALID,CAPACITY)else(
            growth(4,1024)+bytes([0xa5])*(item["output_capacity"]-64)+bytes([0xe7])*16)
        require(after["output"]==expected,"complete framing output and unused tail")
    reports=[]
    for flow in domain["flows"]:
        model=Model();previous=bytes(4096)+bytes([0xa9])*16;address=None;last_resume=None
        for index,item in enumerate(flow["calls"]):
            row,before,after=buffers("flow/"+flow["name"]+"/"+str(index),item,flow["workspace_capacity"])
            if address is None:address=row["workspace_address"]
            require(row["workspace_address"]==address and before["work"]==previous,
                "same persistent workspace and exact full before state")
            wire=bytes.fromhex(item["wire_hex"]);kind=item["kind"];cap=item["output_capacity"]
            if kind=="invalid":
                require(row["return_value"]==INVALID and before==after,"invalid resume changed bytes or return")
            else:
                if kind=="start":model.start(item["mode"]);last_resume=None
                elif kind=="resume":model.resume(wire);last_resume=wire
                else:require(kind=="retry"and wire==last_resume and model.pending is None,
                    "capacity retry must repeat the exact already accepted response")
                expected=model.response()
                if len(expected)>cap:
                    require(model.pending is None,"only completed payload may require output growth")
                    expected=growth(5,len(expected))
                require(row["return_value"]==64 and after["output"]==expected+bytes([0xa5])*(cap-len(expected))+bytes([0xe7])*16,
                    "complete private response, capacity header and unused output tail")
                require(after["work"]==model.workspace()+bytes([0xa9])*16,
                    "all persistent HIA workspace bytes differ from independent entropy policy")
            previous=after["work"]
        require(model.pending is None,"private fixed flow did not terminate")
        reports.append(dict(name=flow["name"],calls=len(flow["calls"]),generations=model.generation,
            orphans=model.orphans,result=sha(model.response()),workspace=sha(model.workspace())))
    require(position==len(rows),"unclaimed HIA calls")
    native=decode(owned(capture,"native/CALLS.json").read_bytes())
    bad=[i for i in domain["framing"]if i["native_reject"]]
    require(len(native)==len(bad)==24,"complete native admission rejection set")
    first=None
    for index,(row,item)in enumerate(zip(native,bad)):
        require(row["input"]==item and row["name"]==item["name"]and row["return_value"]==INVALID
            and set(row["buffers"])=={"before","after","input-before","input-after"},"exact rejected native input")
        data={name:read_bin("native",value,str(index).zfill(3)+"-"+name+".bin")for name,value in row["buffers"].items()}
        require(data["input-before"]==data["input-after"]==bytes.fromhex(item["wire_hex"])+bytes([0xd3])*16
            and data["before"]==data["after"]and len(data["before"])==24576,"native full no-mutation rejection")
        if first is None:first=data["before"]
        require(data["before"]==first,"rejected packets changed persistent native ownership")
        c=data["before"][:4096];expected=bytearray(4096);expected[:8]=b"HENTCI01"
        fields={8:4096,16:summary["mapping"]+256+build["exports"]["binary_entropy_body_call_displacement"]-1,
            376:summary["pool"],384:summary["process_pid"]}
        pointers=[summary["context"],summary["pool"]]
        for at in(64,88,104,120):
            fields[at]=u(c,at);fields[at+8]=4096;pointers.append(u(c,at))
        require(len(set(pointers))==6 and all(0<p<(1<<63)and p%4096==0 for p in pointers),
            "six distinct owned native mappings")
        for at in range(256,320,8):fields[at]=MASK
        for at,value in fields.items():struct.pack_into("<Q",expected,at,value)
        pool=b"HPORP001"+struct.pack("<QQ",4096,summary["process_pid"])+bytes(4096-24)
        require(data["before"]==bytes(expected)+bytes(16384)+pool,
            "all native arena, cache, callback, generation, HIA count and orphan-pool bytes")
    actual={p.relative_to(capture).as_posix()for p in capture.rglob("*")if p.is_file()}
    dirs={p.relative_to(capture).as_posix()for p in capture.rglob("*")if p.is_dir()}
    require(actual==expected_files and dirs=={"hia","native"},"complete private retained file/directory set")
    return dict(status="ENTROPY_PRIVATE_INTERFACE_PASS",source=identity,domain=pin(source/"PRIVATE_DOMAIN.json"),
        capture=pin(capture/"CAPTURE.json"),build=pin(capture/"BUILD.json"),files=len(expected_files),
        complete_buffer_bytes=total_bytes,framing_calls=37,flow_programs=29,flow_calls=179,
        private_hia_entry_calls=216,private_native_admission_calls=24,flows=reports,
        actual_kernel_entropy_applications=0,original_applications=0,reader_semantic_executions=0)
def main():
    p=argparse.ArgumentParser();p.add_argument("stage",choices=["source","capture"])
    p.add_argument("--source",type=Path,required=True);p.add_argument("--capture",type=Path)
    a=p.parse_args();source=a.source.resolve(strict=True)
    if a.stage=="source":
        identity,domain=source_check(source)
        result=dict(status="PRIVATE_SOURCE_DOMAIN_PASS",source=identity,domain=pin(source/"PRIVATE_DOMAIN.json"),
            private_hia_entry_calls=216,private_native_admission_calls=24,application_calls=0)
    else:
        from readonly import guarded
        capture=a.capture.resolve(strict=True)
        result=guarded(lambda:verify(source,capture),roots=[source,capture])
    print(encoded(result).decode(),end="")
if __name__=="__main__":main()
