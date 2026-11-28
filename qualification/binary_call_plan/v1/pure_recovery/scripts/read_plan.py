#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Read every retained native buffer and actual Rust typed response without execution."""
from __future__ import annotations
from pathlib import Path
import gzip
import hashlib
import re
import stat
import struct
from common import B3, HEPTA, canonical, decode, owned, pin, require, sha, source_evidence
import params_cases
import plan_cases

word = lambda raw, at: struct.unpack_from("<Q", raw, at)[0]


def build_evidence(source, output):
    source, output = Path(source), Path(output)
    bundle = decode(owned(output, "build/call-plan.json").read_bytes())
    require(bundle["schema"] == "hepta.runtime.binary-call-plan.build.v1", "build schema changed")
    require(set(bundle["members"]) == {"serde_json_span"} | {row["name"] + "_params" for row in params_cases.schemas()} | {"binary_call_plan"}, "build member set changed")
    require(bundle["compiler_commit"] == HEPTA and bundle["compiler_sha256"] == B3, "build compiler changed")
    bootstrap = decode(owned(output, "build/bootstrap/bootstrap.json").read_bytes())
    require(bootstrap["generation_sha256"] == B3 and bootstrap["qualification"] == "development_fixed_point", "bootstrap identity changed")
    dependency = bootstrap["dependency"]
    require(dependency["commit"] == HEPTA and dependency["tree"] == "8d8b0fb8d015fb7edab302498bb9ed4c74ab6f49", "compiler source commit/tree changed")
    for path, digest in dependency["files"].items():
        require(pin(owned(output, "compiler-source/" + path))["sha256"] == digest, "compiler dependency file changed: " + path)
    for generation in ("B1", "B2", "B3"):
        require(pin(owned(output, "build/bootstrap/" + generation + ".image.bin"))["sha256"] == B3, "bootstrap generation changed")
    artifacts = {"build/call-plan.json": pin(output / "build/call-plan.json")}
    for name, row in bundle["members"].items():
        path = owned(output, row["manifest"])
        require(pin(path)["sha256"] == row["manifest_sha256"], "member manifest changed")
        metadata = decode(path.read_bytes())
        require(metadata["source_sha256"] == row["source_sha256"] == pin(owned(source, "native/" + name + ".hepta"))["sha256"], "member source changed")
        require(metadata["image_sha256"] == row["image_sha256"], "member image declaration changed")
        require(metadata["compiler_commit"] == HEPTA and metadata["compiler_sha256"] == B3 and metadata["buffer_profile"] == "history.v1" and metadata["standalone"] is None, "member ABI changed")
        require([metadata[k] for k in ("input_capacity", "output_capacity", "workspace_capacity")] == [128 << 20, 128 << 20, 256 << 20], "member capacities changed")
        module_source = owned(path.parent, metadata["source"]).read_bytes()
        image = owned(path.parent, metadata["image"]).read_bytes()
        require(sha(module_source) == metadata["source_sha256"] and sha(image) == metadata["image_sha256"], "actual member bytes changed")
        request = decode(owned(path.parent, "module.request.json").read_bytes())
        receipt = decode(owned(path.parent, "module.receipt.json").read_bytes())
        raw_output = owned(path.parent, "module.output.bin").read_bytes()
        require(owned(path.parent, "module.input.bin").read_bytes() == module_source, "compiled input differs from published source")
        require(receipt["status"] == "returned" and type(receipt["abi_status"]) is int and receipt["abi_status"] == 0 and type(receipt["core_u32"]) is int, "compile did not return cleanly")
        require(receipt["core_u32"] == receipt["result_u64"] == receipt["produced_bytes"] == len(image) and image == raw_output[:len(image)], "compiled complete output/image differs")
        require(receipt["source_unchanged"] is True and receipt["forbidden_compiler_modules_loaded"] == [] and receipt["artifact_sha256"] == B3, "compile custody changed")
        require(receipt["input_bytes"] == len(module_source) and receipt["input_sha256"] == sha(module_source) and receipt["output_sha256"] == sha(raw_output) and receipt["produced_sha256"] == sha(image), "compile complete input/output hash differs")
        require(request["source_sha256"] == sha(module_source) and request["image_sha256"] == B3 and request["format"] == "flat-x86-64", "compile request changed")
        build = decode(owned(path.parent, "build.json").read_bytes())
        require(build["compile_receipt"] == receipt and build["compiler_dependency"] == dependency, "member build source closure changed")
        for artifact in (path, path.parent / metadata["source"], path.parent / metadata["image"]):
            artifacts[artifact.relative_to(output).as_posix()] = pin(artifact)
    return artifacts


def frame(owner, code, out):
    header = 32 if owner == 1 else 256
    require(code == header and out[:8] == (b"HJSVR002" if owner == 1 else b"HBPRR001"),
            "native response framing changed")
    status = word(out, 8)
    require(status in ((0, 1, 2, 3, 5) if owner == 1 else (0, 1, 2, 3)),
            "native response status changed")
    needed = word(out, 24 if owner == 1 else 80)
    if status in (2, 3):
        require(needed > 0, "growth omitted minimum")
        extent = header
    else:
        require(needed == 0, "completion requested growth")
        extent = header + (word(out, 16) if owner == 1 else
            sum(word(out, at) for at in range(88, 152, 8)) if status == 0 else word(out, 72))
    require(extent <= len(out) and out[extent:] == b"\xa5" * (len(out) - extent),
            "native complete output extent/tail changed")
    if owner > 1:
        kind = owner - 1
        require(kind in range(1, 6) and word(out, 16) == kind and out[152:256] == bytes(104),
                "typed kind/reserved words changed")
        if status:
            require(out[24:72] == bytes(48) and out[88:256] == bytes(168),
                    "typed refusal exposes success fields")
        else:
            require(word(out, 72) == 0, "typed success carries an error length")
            require(word(out, 24) in ((0,) if kind <= 3 else (1, 2, 3)), "typed action changed")
            flags = word(out, 40)
            require(flags & ~3 == 0 and (kind == 5 or flags == 0), "typed Boolean flags changed")
            allowed = {1:0, 2:(1<<9)|(1<<10)|(1<<4), 3:0,
                4:(1<<9)|(1<<3)|(1<<4)|(1<<11)|(1<<6),
                5:(1<<9)|(1<<4)|(1<<8)|(1<<3)}[kind]
            require(word(out, 32) & ~allowed == 0, "unknown optional presence bits")
            out[256:extent].decode()
    return status, needed, out[:extent]


def plan_frame(code,out):
    if code==0xffffffd0:
        require(len(out)>=64 and out[:8]==b"HGRWS002"and word(out,8)in(1,2)
            and word(out,16)>0 and word(out,24)==0 and out[32:]==b"\xa5"*(len(out)-32),
            "caller growth publication/tail differs")
        return ("growth",word(out,8),word(out,16)),out[:32]
    require(64<=code<0xffff0000 and code<=len(out)and out[:8]==b"HBPLR001"
        and word(out,56)==code-64 and out[code:]==b"\xa5"*(len(out)-code),
        "caller full publication/tail differs")
    status,kind,next_phase,op,audit,pool=tuple(word(out,n)for n in range(8,56,8))
    require(status in(1,2,3)and kind in range(1,6),"caller status/kind differs")
    if status==1:
        require(next_phase==op==audit==pool==0,"caller error publishes effect fields")
        out[64:code].decode()
    elif status==2:
        require(next_phase in(1,2)and op in(8,9)and audit in(0,1)and pool==0,"caller config effect metadata")
        payload=out[64:code]
        require(len(payload)>=64 and payload[:8]==b"HRCFGQ01"and word(payload,8)in(8,9)
            and word(payload,16)==len(payload)-24 and word(payload,24)==word(payload,32)==0
            and word(payload,8)==op and word(payload,40)==audit and word(payload,48)+word(payload,56)==len(payload)-64,
            "caller config request framing")
        require((next_phase==1)==(word(payload,8)==8)and(next_phase!=1 or kind==5),
            "caller phase/config operation mismatch")
    else:
        require(next_phase==0 and op in range(1,8)and audit==int(kind>=3)and pool in(0,1)
            and(kind<3 or pool==0),"caller ready effect metadata")
        require(type(decode(out[64:code]))is dict,"caller ready query is not a JSON object")
    return ("done",status,0),out[:code]

def typed_strings(raw):
    at=256;out=[]
    for n in range(88,152,8):
        size=word(raw,n);out.append(raw[at:at+size]);at+=size
    require(at==len(raw),"typed string extent")
    return out

def full_records(folder,index):
    offset=0
    with gzip.open(owned(folder,"calls.bin.gz"),"rb")as stream:
        for ordinal,row in enumerate(index,1):
            require(type(row["bytes"])is int and 64<=row["bytes"]<=128<<20,"private record extent")
            raw=stream.read(row["bytes"])
            require(len(raw)==row["bytes"]and sha(raw)==row["record_sha256"]
                and row["call"]==ordinal and row["offset"]==offset,"complete native record differs")
            fields=struct.unpack_from("<8Q",raw)
            require(fields==(ordinal,row["owner"],row["case_id"],row["return_code"],row["input_bytes"],
                row["output_capacity"],row["workspace_capacity"],0),"native record header differs")
            at=64;arrays=[]
            for size,label in((fields[4],"input"),(fields[6],"before"),(fields[5],"output_before"),
                (fields[5],"output"),(fields[6],"after")):
                part=raw[at:at+size];at+=size
                require(len(part)==size and sha(part)==row[label+"_sha256"],"full native buffer differs: "+label)
                arrays.append(part)
            require(at==len(raw)and fields[1]in range(1,8)and arrays[2]==b"\xa5"*fields[5],
                "native owner or unpublished output differs")
            yield ordinal,row,arrays
            offset+=len(raw)
        require(stream.read(1)==b"","unattributed native journal suffix")

def check_growth(chain,owner,wire,records,*,label,initial=None,capacity=None):
    before=bytes(16512 if owner==1 else 512 if owner==7 else 65536)if initial is None else initial
    capacity=(32 if owner==1 else 64 if owner==7 else 256)if capacity is None else capacity
    require(chain and len(chain)<=12,"native continuation count")
    final=None
    for position,call in enumerate(chain):
        row,arrays=records[call];actual,bw,old,out,after=arrays
        require(row["owner"]==owner and row["label"]==label and actual==wire
            and bw==before and len(out)==capacity,"actual continuation borrowed bytes changed")
        code=row["return_code"]
        if owner==7:
            status,published=plan_frame(code,out)
            growth=status[0]=="growth";which=status[1];needed=status[2]
        else:
            flag,needed,published=frame(owner,code,out)
            growth=flag in(2,3);which=1 if flag==2 else 2
        if growth:
            require(position+1<len(chain)and needed>(len(before)if which==1 else capacity),
                "actual growth omitted continuation or did not increase capacity")
            if which==1:before=after+bytes(needed-len(after))
            else:before,capacity=after,needed
        else:
            require(position+1==len(chain),"completed call replayed")
            final=published
    require(final is not None,"unterminated native continuation")
    return final

def read_native_group(source,output,group,artifacts):
    folder=output/"native"/group["name"];plan=folder/"plan"
    require(decode(owned(folder,"INPUT.json").read_bytes())==group,"native group domain changed")
    summary=decode(owned(plan,"capture-result.json").read_bytes())
    require(summary["status"]=="PASS"and summary["original_results_read"]is False
        and summary["public_route_replaced"]is False and summary["remote_body_executed"]is False,
        "native pipeline scope/status changed")
    require(summary["source_inputs"]==source_evidence(source)and summary["artifacts"]==artifacts,
        "actual pipeline source/build differs")
    require(decode(owned(folder,"RESULT.json").read_bytes())==summary,"native group summary differs")
    read=lambda name:[decode(line)for line in owned(plan,name).read_bytes().splitlines()]
    index,declared,results,controls=[read(name)for name in("calls.jsonl","native-cases.jsonl","native-results.jsonl","controls.jsonl")]
    require(len(group["cases"])==len(declared)==len(results)==summary["cases"]
        and len(index)==summary["native_calls"]and len(controls)==summary["controls"],
        "actual native domain/calls missing")
    require(len(controls)==(27 if group["name"]=="operator-00"else 0),"private control domain changed")
    root=folder/"root";exchanges=decode(owned(root,"exchanges.json").read_bytes())
    used=set();used_exchanges=set();records={};offset=0
    for ordinal,row,arrays in full_records(plan,index):
        records[ordinal]=(row,arrays);offset+=row["bytes"]
    require(offset==summary["full_record_bytes"],"complete pipeline record byte count differs")
    def claim(calls,cid):
        for call in calls:
            require(type(call)is int and call in records and call not in used,"call attribution duplicated/missing")
            require(records[call][0]["case_id"]==cid,"call belongs to another case")
            used.add(call)
    for case,row,result in zip(group["cases"],declared,results):
        identity=[case["case_id"],case["kind"],case["name"]]
        require([row[k]for k in("case_id","kind","name")]==[result[k]for k in("case_id","kind","name")]==identity,
            "native input/result ordering differs")
        cid,kind=case["case_id"],case["kind"];value=case["raw_json"].encode();out=result["result"]
        require(row["input_sha256"]==sha(value),"native original input changed")
        claim(row["value_calls"],cid);claim(row["params_calls"],cid)
        mapped=check_growth(row["value_calls"],1,b"HJSMS002"+struct.pack("<2Q",1,len(value))+value,records,label="semantic")
        require(word(mapped,8)==0 and row["value_admitted"]is True and mapped[32:].decode()==out["canonical"],
            "actual admitted Map result differs")
        typed=check_growth(row["params_calls"],kind+1,b"HBPRQ001"+struct.pack("<2Q",len(mapped)-32,kind)+mapped[32:],
            records,label="semantic")
        require(typed.hex()==out["typed_frame"]and(word(typed,8)==0)==out["typed_ok"]==row["typed_success"],
            "actual typed result differs")
        phase=0;feedback=b"";terminal=None
        require(len(row["stages"])<=3,"private caller has extra phases")
        for stage in row["stages"]:
            require(out["typed_ok"]and stage["phase"]==phase,"typed failure reached caller or phase reordered")
            wire=b"HBPLQ001"+struct.pack("<5Q",phase,int(case["pool"]),len(typed),len(feedback),0)+typed+feedback
            claim(stage["calls"],cid)
            plan_result=check_growth(stage["calls"],7,wire,records,label="plan")
            require(plan_result.hex()==stage["frame_hex"]and word(plan_result,16)==kind,
                "actual caller output differs")
            if word(plan_result,8)==2:
                nxt=word(plan_result,24);seq=stage["config_exchange"]
                require(type(seq)is int and 1<=seq<=len(exchanges)and seq not in used_exchanges,
                    "configuration reply ownership differs")
                require(nxt>phase and(nxt!=1 or phase==0 and kind==5),"caller configuration phase order differs")
                used_exchanges.add(seq);ex=exchanges[seq-1];payload=plan_result[64:]
                require(ex["sequence"]==seq and ex["case_id"]==cid and ex["phase"]==nxt
                    and bytes.fromhex(ex["request_hex"])==payload,"caller actual config request differs")
                strings=typed_strings(typed)
                require(payload[64:]==strings[0]+strings[1]and word(payload,48)==len(strings[0])
                    and word(payload,56)==len(strings[1])and word(payload,40)==(int(kind>=3)if nxt==2 else 0),
                    "caller config host/path/authority flags differ")
                feedback=bytes.fromhex(ex["response_hex"]);phase=nxt
            else:
                require(stage is row["stages"][-1]and stage["config_exchange"]is None,"caller terminal followed by another phase")
                terminal=plan_result
        require((terminal is not None)==out["typed_ok"],"caller completion missing or typed failure executed")
        require(out["plan_frame"]==(None if terminal is None else terminal.hex()),"terminal complete frame differs")
    if controls:check_controls(controls,records,used,declared,results)
    require(used==set(records)and used_exchanges==set(range(1,len(exchanges)+1)),
        "unattributed native call/config exchange")
    root_proof=read_config_process(output,group,exchanges)
    original=compare_original(source,output,group,results)
    return dict(status="PASS",cases=len(results),calls=len(index),controls=len(controls),
        full_record_bytes=offset,root=root_proof,original=original,
        results_sha256=pin(plan/"native-results.jsonl")["sha256"])

def check_controls(controls,records,used,declared,results):
    expected=["bound-reference"]+["short-output"]*4+["output-boundary"]*4+["workspace-growth"]*3+["invalid-frame"]*12+["dirty-workspace"]*3
    require([r["kind"]for r in controls]==expected,"caller physical control sequence differs")
    reference=controls[0];wire=bytes.fromhex(reference["wire_hex"]);full=bytes.fromhex(reference["frame_hex"])
    first=next(r for r in declared if r["stages"])["stages"][0]
    require(full.hex()==first["frame_hex"]and wire==records[first["calls"][0]][1][0],
        "control reference is not actual semantic input/output")
    dirty=b"\x7b"*512
    invalid=[b"",wire[:47],b"XXXXXXXX"+wire[8:]]
    for at,value in((8,3),(16,2),(24,0),(32,1),(40,1),(48,0),(56,1),(64,0),(200,1)):
        bad=bytearray(wire);struct.pack_into("<Q",bad,at,value);invalid.append(bytes(bad))
    for position,control in enumerate(controls[1:],1):
        call=control["call"];row,arrays=records[call];actual,before,old,out,after=arrays
        require(call not in used and row["owner"]==7 and row["label"]==control["kind"],"control call identity differs")
        used.add(call);code=row["return_code"];kind=control["kind"]
        if kind=="short-output":
            cap=(0,1,31,63)[position-1]
            require(actual==wire and len(out)==control["output_capacity"]==cap and before==b"\x7b"*512
                and(code,out,after)==(0xfffffffe,old,before),"short output control differs")
        elif kind=="invalid-frame":
            require(actual==invalid[position-12]and before==b"\x7b"*512 and len(out)==128
                and control["wire_hex"]==actual.hex()and(code,out,after)==(0xffffffff,old,before),
                "invalid caller frame control differs")
        elif kind=="output-boundary":
            cap=(64,max(64,len(full)-1),len(full),len(full)+17)[position-5]
            require(actual==wire and len(out)==control["output_capacity"]==cap and before==b"\x7b"*512,
                "output boundary setup differs")
            status,pub=plan_frame(code,out)
            require((status==("growth",2,len(full)))if cap<len(full)else(pub==full and code==len(full)),
                "output exact growth/result differs")
        elif kind=="workspace-growth":
            size=(0,1,511)[position-9]
            require(actual==wire and before==b"\x7b"*size and len(out)==len(full)+17
                and control["workspace_capacity"]==size and after==before,"workspace boundary setup differs")
            status,_=plan_frame(code,out);require(status==("growth",1,512),"workspace growth exact capacity differs")
            for following in control["resume_calls"]:
                require(following not in used and records[following][0]["case_id"]==900003,"control continuation reused")
                used.add(following)
            result=check_growth(control["resume_calls"],7,wire,records,label="growth-resume",
                initial=after+bytes(512-size),capacity=len(full))
            require(result==full,"growth continuation result differs")
        else:
            require(kind=="dirty-workspace"and actual==wire and before==dirty and len(out)==len(full)+7,
                "dirty-workspace setup differs")
            _,pub=plan_frame(code,out);require(pub==full,"dirty reuse result differs")
            dirty=after

def exact(stream,size):
    raw=bytearray()
    while len(raw)<size:
        part=stream.read(min(size-len(raw),1<<20));require(part,"incomplete full physical buffer")
        raw.extend(part)
    return bytes(raw)
def journal(path,summary):
    digest=hashlib.sha256();logical=0;ordinal=0
    with gzip.open(path,"rb")as stream:
        while True:
            header=stream.read(64)
            if not header:break
            require(len(header)==64 and header[:8]==b"HBRJQ001","native journal framing differs")
            a=struct.unpack("<8Q",header);ordinal+=1
            require(a[1]==ordinal and a[2]==a[3]==0 and a[7]==11,"native pre-call sequence differs")
            require(all(x<1<<32 for x in a[4:7]),"native buffer extent exceeds captured ABI")
            before=tuple(exact(stream,n)for n in a[4:7])
            for raw in(header,*before):digest.update(raw);logical+=len(raw)
            header=exact(stream,64);b=struct.unpack("<8Q",header)
            require(header[:8]==b"HBRJQ001"and b[1]==ordinal and b[2]==1 and b[4:]==a[4:]
                and 0<=b[3]<=0xffffffff,"native post-call sequence/capacity differs")
            after=tuple(exact(stream,n)for n in b[4:7])
            for raw in(header,*after):digest.update(raw);logical+=len(raw)
            require(before[0]==after[0],"actual native borrowed input changed")
            if len(before[2])>=65536:
                quantum=word(before[2],65000)or 1048576
                start=1048576+2*quantum;end=start+quantum
                if end<=len(before[2]):
                    require(before[2][start:end]==after[2][start:end],"installed config arena was mutated by root query")
            yield ordinal,b[3],before,after
        require(stream.read()==b"","trailing native journal bytes")
    summary.update(native_calls=ordinal,full_record_bytes=logical,full_record_sha256=digest.hexdigest(),journal=pin(path))

def trace_records(path):
    raw=path.read_bytes();at=0;counts={};calls=0
    sizes={b"HRCGRO02":80,b"HRGTR002":224,b"HRCNAK02":128,b"HWDIOAK2":160}
    while at<len(raw):
        tag=raw[at:at+8];require(tag in sizes and sizes[tag]<=len(raw)-at,"unbound native stderr bytes")
        size=sizes[tag];counts[tag.decode()]=counts.get(tag.decode(),0)+1
        if tag==b"HRGTR002"and word(raw,at+24)==1:calls+=1
        at+=size
    return dict(records=counts,query_native_calls=calls,bytes=len(raw),sha256=sha(raw))


def read_config_process(output,group,exchanges):
    folder=output/"native"/group["name"];root=folder/"root"
    process=decode(owned(root,"PROCESS.json").read_bytes())
    require(process["exit_code"]==0 and process["timed_out"]is False and process["timeout_seconds"]==45
        and 0<=process["elapsed_seconds"]<46 and process["original_outputs_read"]is False
        and process["inherited_owned_journal_descriptor"]==198 and process["start_new_session"]is False
        and process["journal_errors"]==[]and process["exchanges"]==len(exchanges),
        "actual configured process did not complete within frozen boundary")
    require(set(process["streams"])=={"stdin","stdout","stderr","calls.bin.gz"},"config process full streams omitted")
    for key,want in process["streams"].items():require(pin(owned(root,key))==want,"complete config process stream changed")
    origin=decode(owned(output,"ORIGIN.json").read_bytes());at=Path(origin["output"])
    old_folder=at/"native"/group["name"]
    capture=output/"root-reuse/original/restored/run/capture"
    from root_build_reader import original_location
    built=decode(owned(capture,"build/result.json").read_bytes())
    executable=original_location(capture,built["binary"]).relative_to(output)
    command=[str(at/executable)]
    if group["config"]is not None:command+=["--runtime-config",str(old_folder/"config.json")]
    require(process["executable_command"]==command and process["cwd"]==str(old_folder)
        and process["env"]=={"PATH":""},"config process command/source/identity differs")
    if group["config"]is not None:
        config=owned(folder,"config.json")
        require(decode(config.read_bytes())==group["config"]and stat.S_IMODE(config.stat().st_mode)==0o600,
            "actual native installed configuration changed")
    require(owned(root,"stdin").read_bytes()==b"".join(
        struct.pack("<2Q",11,len(bytes.fromhex(row["request_hex"])))+bytes.fromhex(row["request_hex"])
        for row in exchanges),"native config stdin differs from actual plans")
    summary={};calls=iter(journal(owned(root,"calls.bin.gz"),summary));previous=None;native_calls=0;growths=0
    stdout=owned(root,"stdout").read_bytes();cursor=0
    for ex in exchanges:
        header=stdout[cursor:cursor+96];cursor+=96
        require(len(header)==96 and header.hex()==ex["envelope_hex"]and header[:8]==b"HRGFR002"
            and word(header,8)==11,"actual config envelope differs")
        code,size,ncalls=word(header,16),word(header,24),word(header,32)
        payload=stdout[cursor:cursor+size];cursor+=size
        require(payload.hex()==ex["response_hex"]and code==size==len(payload)and len(payload)>=32
            and payload[:8]==b"HRCFGM01"and word(payload,8)in(0,1)and word(payload,16)==0
            and word(payload,24)==len(payload)-32 and ncalls>=1,"actual config complete result differs")
        payload[32:].decode()
        request=bytes.fromhex(ex["request_hex"]);final=None
        for position in range(ncalls):
            seq,ret,before,after=next(calls);native_calls+=1
            require(before[0]==request,"installed config native entry did not receive caller request")
            if previous is not None:
                oldout,oldwork=previous
                require(len(before[2])==len(oldwork),"borrowed query unexpectedly grew installed workspace")
                expected=bytearray(oldwork)
                if len(expected)>=256:struct.pack_into("<Q",expected,len(expected)-136,1)
                require(before[2]==expected,"unrecorded installed workspace transition")
                require(len(before[1])>=len(oldout)and before[1][:len(oldout)]==oldout
                    and not any(before[1][len(oldout):]),"unrecorded installed output transition")
            if ret==0xffffffd0:
                require(position<ncalls-1 and after[1][:8]==b"HGRWS002"and word(after[1],8)==2
                    and word(after[1],16)>len(after[1])and word(after[1],24)==0
                    and after[1][32:]==before[1][32:],"installed owner growth differs")
                growths+=1
            else:
                require(position==ncalls-1 and ret==len(payload)and after[1][:ret]==payload
                    and after[1][ret:]==before[1][ret:],"installed owner publication/tail differs")
            previous=(after[1],after[2]);final=(ret,after)
        require(final[0]==code and len(final[1][1])==word(header,88)
            and len(final[1][2])==word(header,80),"configured descriptor capacity differs")
    require(cursor==len(stdout)and next(calls,None)is None,"unattributed configured bytes/calls")
    require(native_calls==summary["native_calls"]and summary["full_record_bytes"]==process["full_native_buffer_record_bytes"]
        and summary["full_record_sha256"]==process["full_native_buffer_record_sha256"],"configured physical buffers differ")
    traces=trace_records(owned(root,"stderr"))
    require(traces["query_native_calls"]==native_calls,"actual config trace and physical calls differ")
    state=decode(owned(root,"STATE.json").read_bytes())
    from root_state import state_inventory
    actual_state=state_inventory(folder/"state")
    # Archive restoration changes link counts and ownership; saved actual process
    # values are retained, while every physical file byte and mode is rechecked.
    require(set(actual_state)==set(state),"installed state file/directory set differs")
    for name,row in state.items():
        got=actual_state[name]
        require(row["kind"]==got["kind"]and row["mode"]==got["mode"],"installed state kind/mode differs")
        if row["kind"]=="file":
            require({k:row[k]for k in("bytes","sha256")}=={k:got[k]for k in("bytes","sha256")},
                "installed state full file bytes differ")
    if group["config"]is None:require(state=={},"unconfigured pipeline created controller state")
    else:
        require(state["."]["mode"]==0o700,"installed controller state privacy differs")
        for name in("controller.owner.lock","controller.lock"):
            row=state[name]
            require(row["kind"]=="file"and row["mode"]==0o600 and row["nlink"]==1,
                "actual installed lock privacy differs")
    require(decode(owned(root,"RESULT.json").read_bytes())==dict(status="PASS",process=process,state=state),
        "installed process completion receipt differs")
    return dict(status="PASS",exchanges=len(exchanges),output_growths=growths,trace=traces,**summary)

def compare_original(source,output,group,native):
    path=owned(output,"processes/original-"+group["name"]+".stdout")
    original=decode(path.read_bytes())
    require(len(original)==len(native)==len(group["cases"]),"original complete case count differs")
    remote=b"\n".join(owned(source,"target/"+name).read_bytes()for name in
        ("file_metadata.py","inode_patch.py","binary_file.py")).decode()
    ready=0;typed_errors=0;body_errors=0
    operations={"info":1,"read":2,"write":3,"upload_chunk":4,"upload_commit":5,"upload_abort":6,"inode_patch":7}
    for case,a,b in zip(group["cases"],original,native):
        require([a[k]for k in("case_id","kind","name")]==[b[k]for k in("case_id","kind","name")]==
            [case[k]for k in("case_id","kind","name")],"actual original case order differs")
        x,y=a["result"],b["result"]
        require({k:x[k]for k in("canonical","typed_ok","typed_frame")}==
            {k:y[k]for k in("canonical","typed_ok","typed_frame")},
            "original complete canonical/typed result differs: "+group["name"]+"/"+case["name"])
        if not x["typed_ok"]:
            typed_errors+=1
            require(x["events"]==[]and y["plan_frame"]is None,"typed rejection crossed caller boundary")
            continue
        plan=bytes.fromhex(y["plan_frame"]);kind=case["kind"];body=x["body"];params=x["normalized"]
        if "error"in body:
            body_errors+=1
            require(word(plan,8)==1 and plan[64:].decode()==body["error"]and x["events"]==[],
                "original caller error/order differs: "+group["name"]+"/"+case["name"])
        else:
            ready+=1
            require(set(body)=={"ok"}and word(plan,8)==3 and plan[64:].decode()==body["ok"],
                "original exact JSON query differs: "+group["name"]+"/"+case["name"])
            query=decode(plan[64:]);pool=case["pool"]and kind<3
            require(word(plan,32)==operations[query["op"]]and word(plan,40)==int(kind>=3)
                and word(plan,48)==int(pool),"original caller effect plan differs")
            events=[]
            if kind>=3:
                events.append(dict(kind="audit",event="native_binary_write",host=params["host"],path=params["path"],
                    detail={"op":query["op"]}))
            if pool:
                events.append(dict(kind="observation",host=params["host"],query=query))
            else:
                host=group["config"]["hosts"][params["host"]]
                events.append(dict(kind="rpc",ssh_target=host["ssh_target"],source=remote,query=query,duration_seconds=30))
            require(x["events"]==events,"original post-admission event order/arguments differ")
    return dict(status="PASS",cases=len(original),typed_errors=typed_errors,body_errors=body_errors,
        ready_plans=ready,stdout=pin(path),actual_remote_bodies_executed=False)
