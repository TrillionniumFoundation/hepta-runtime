#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Complete byte-only original/native root proof. Never load a native image."""
from __future__ import annotations
from pathlib import Path
import gzip
import hashlib
import re
import struct
from common import B3,HEPTA,SCOPE,canonical,decode,owned,pin,require,sha,source_evidence
import root_cases
from native_capture import control_specs
PACK=root_cases.PACK
word=lambda raw,at:struct.unpack_from("<Q",raw,at)[0]
GROW=0xffffffd0
INVALID=0xffffffff
SHORT=0xfffffffe
def original_location(output,path):
    origin=decode(owned(output,"ORIGIN.json").read_bytes())
    p=Path(path);at=Path(origin["output"])
    require(p.is_relative_to(at),"retained process path escaped actual output")
    return owned(output,p.relative_to(at).as_posix())
def build_evidence(source,output):
    built=decode(owned(output,"build/result.json").read_bytes())
    require(built["schema"]=="hepta.runtime.config-span-build.v1"and built["status"]=="PASS"
        and built["installed_config_startup"]is True and len(built["members"])==19,"actual installed build missing")
    require(built["compiler_commit"]==HEPTA and built["compiler_sha256"]==B3,"actual compiler differs")
    bootstrap=decode(owned(output,"build/build/bootstrap/bootstrap.json").read_bytes())
    dep=bootstrap["dependency"]
    require(dep["commit"]==HEPTA and dep["tree"]=="8d8b0fb8d015fb7edab302498bb9ed4c74ab6f49"
        and len(dep["files"])==1080 and bootstrap["generation_sha256"]==B3
        and bootstrap["qualification"]=="development_fixed_point","complete compiler closure differs")
    for path,digest in dep["files"].items():
        require(pin(owned(output,"compiler-source/"+path))["sha256"]==digest,"complete compiler source changed")
    for generation in("B1","B2","B3"):
        require(pin(owned(output,"build/build/bootstrap/"+generation+".image.bin"))==dict(bytes=673413,sha256=B3),"actual generation differs")
    source_profile=decode(owned(source,"native/config_span_sources.json").read_bytes())
    require(source_profile==built["source_binding"],"actual build input profile changed")
    for path,want in source_profile["sources"].items():require(pin(owned(source,path))==want,"native closure source changed")
    origin=decode(owned(output,"ORIGIN.json").read_bytes())
    rows=[]
    for row in built["members"]:
        path=original_location(output,row["manifest"])
        require(pin(path)["sha256"]==row["manifest_sha256"],"native manifest changed")
        metadata=decode(path.read_bytes())
        native_source=original_location(output,row["source"])
        require(pin(native_source)["sha256"]==metadata["source_sha256"]==row["source_sha256"],"actual native source changed")
        require(metadata["image_sha256"]==row["image_sha256"]and metadata["compiler_commit"]==HEPTA
            and metadata["compiler_sha256"]==B3 and metadata["standalone"]is None
            and metadata["buffer_profile"]=="history.v1","actual member image/ABI changed")
        rows.append((path,metadata))
    link=built["link"];path=original_location(output,link["manifest"])
    require(pin(path)["sha256"]==link["manifest_sha256"],"actual native linker manifest changed")
    metadata=decode(path.read_bytes())
    require(metadata["source_sha256"]==pin(owned(output,"compiler-source/examples/hia_bootstrap/elf_static_linker.hepta"))["sha256"]
        and metadata["buffer_profile"]=="standard"and metadata["standalone"]is None,"native linker source/ABI changed")
    rows.append((path,metadata))
    for path,metadata in rows:
        module_source=owned(path.parent,metadata["source"]).read_bytes()
        image=owned(path.parent,metadata["image"]).read_bytes()
        require(sha(module_source)==metadata["source_sha256"]and sha(image)==metadata["image_sha256"],"complete native bytes differ")
        request=decode(owned(path.parent,"module.request.json").read_bytes())
        receipt=decode(owned(path.parent,"module.receipt.json").read_bytes())
        raw_output=owned(path.parent,"module.output.bin").read_bytes()
        require(owned(path.parent,"module.input.bin").read_bytes()==module_source,"compiled input source differs")
        require(receipt["status"]=="returned"and receipt["abi_status"]==0
            and receipt["core_u32"]==receipt["result_u64"]==receipt["produced_bytes"]==len(image)
            and image==raw_output[:len(image)],"actual complete native compile output differs")
        require(receipt["source_unchanged"]is True and receipt["forbidden_compiler_modules_loaded"]==[]
            and receipt["artifact_sha256"]==B3 and receipt["input_sha256"]==sha(module_source)
            and receipt["output_sha256"]==sha(raw_output)and receipt["produced_sha256"]==sha(image),"native compile custody differs")
        require(request["source_sha256"]==sha(module_source)and request["image_sha256"]==B3
            and request["format"]=="flat-x86-64","native compile request differs")
        build=decode(owned(path.parent,"build.json").read_bytes())
        require(build["compile_receipt"]==receipt and build["compiler_dependency"]==dep,"member build closure differs")
    binary=original_location(output,built["binary"])
    require(pin(binary)["sha256"]==built["binary_sha256"]==link["output_sha256"]
        and pin(binary)["bytes"]==link["output_bytes"],"actual ELF changed")
    headers=owned(output,"build/readelf.stdout").read_bytes()
    require(b"INTERP"not in headers and b"RWE"not in headers and b"GNU_STACK"in headers,"ELF memory permissions differ")
    frame=owned(output,"build/link.input.bin").read_bytes();obj=owned(output,"build/bridge.o").read_bytes()
    require(frame==b"HIALNK01"+PACK(1,6,0)+b"_start"+PACK(len(obj))+obj
        and sha(frame)==link["input_sha256"]and len(frame)==link["input_bytes"],"actual native link input changed")
    return dict(images=19,linker_images=1,compiler_source_files=1080,binary=pin(binary))
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
def expected(original):
    if "ok"in original:flag=0;payload=original["ok"].encode()
    else:
        require("error"in original,"original result shape missing")
        flag=1;payload=original["error"].encode()
    return b"HRCFGM01"+PACK(flag,0,len(payload))+payload
def trace_records(path):
    raw=path.read_bytes();at=0;counts={};calls=0
    sizes={b"HRCGRO02":80,b"HRGTR002":224,b"HRCNAK02":128,b"HWDIOAK2":160}
    while at<len(raw):
        tag=raw[at:at+8];require(tag in sizes and sizes[tag]<=len(raw)-at,"unbound native stderr bytes")
        size=sizes[tag];counts[tag.decode()]=counts.get(tag.decode(),0)+1
        if tag==b"HRGTR002"and word(raw,at+24)==1:calls+=1
        at+=size
    return dict(records=counts,query_native_calls=calls,bytes=len(raw),sha256=sha(raw))
def verify_original(source,group,rows):
    require(len(rows)==len(group["queries"]),"original cases missing")
    remote=b"\n".join(owned(source,"target/"+n).read_bytes()for n in("file_metadata.py","inode_patch.py","binary_file.py")).decode()
    for query,row in zip(group["queries"],rows):
        require(set(row)==({"ok","audit","transport"}if"ok"in row else{"error","audit","transport"}),"original result keys changed")
        if query["mode"]!="rpc"or"error"in row:
            require(row["audit"]==row["transport"]==[],"root rejection/observation performed post-admission effect")
        else:
            require(row["audit"]==([dict(event="native_binary_write",host=query["host"],path=query["path"],
                detail={"op":"root_probe"})]if query["write"]else[]),"original audit argument boundary changed")
            host=group["config"]["hosts"][query["host"]]
            require(row["transport"]==[dict(ssh_target=host["ssh_target"],source=remote,duration_seconds=30,
                query={"op":"root_probe","path":query["path"],"root":row["ok"]})],"original transport argument boundary changed")
def read_group(source,output,group,process):
    name=group["name"];folder=output/"native"/name
    require(decode(owned(folder,"INPUT.json").read_bytes())==group,"retained native input group changed")
    original=decode(owned(output,"processes/original-"+name+".stdout").read_bytes())
    require(owned(output,"processes/original-"+name+".stdin").read_bytes()==root_cases.encoded(group),"actual original input differs")
    verify_original(source,group,original)
    rows=[(query["name"],root_cases.frame(query),expected(row))for query,row in zip(group["queries"],original)]
    if name=="operator":rows += [(name,wire,None)for name,wire in root_cases.controls()]
    require(owned(folder,"stdin").read_bytes()==b"".join(PACK(11,len(wire))+wire for _,wire,_ in rows),"complete actual native input differs")
    require(process["exit_code"]==0 and process["timed_out"]is False and process["timeout_seconds"]==45
        and 0<=process["elapsed_seconds"]<46 and process["original_outputs_read"]is False
        and process["inherited_owned_journal_descriptor"]==198,"native process did not complete in frozen scope")
    for key,want in process["streams"].items():require(pin(owned(folder,key))==want,"native complete process stream changed")
    require(set(process["streams"])=={"stdin","stdout","stderr","kernel.trace","calls.bin.gz"},"native stream omitted")
    binary=decode(owned(output,"build/result.json").read_bytes())["binary"]
    origin=decode(owned(output,"ORIGIN.json").read_bytes())
    original_folder=Path(origin["output"])/"native"/name
    command=[binary]+([]if group["config"]is None else["--runtime-config",str(original_folder/"config.json")])
    require(process["executable_command"]==command and process["cwd"]==str(original_folder)and process["env"]=={"PATH":""},"native command/cwd/environment differs")
    if group["config"]is not None:require(decode(owned(folder,"config.json").read_bytes())==group["config"],"actual config file changed")
    out=owned(folder,"stdout").read_bytes();at=0;summary={};calls=iter(journal(owned(folder,"calls.bin.gz"),summary))
    previous=None;native_calls=0;growths=0
    for case,wire,want in rows:
        header=out[at:at+96];at+=96
        require(len(header)==96 and header[:8]==b"HRGFR002"and word(header,8)==11,"actual installed query envelope differs")
        code,size,ncalls=word(header,16),word(header,24),word(header,32)
        require(size<=len(out)-at,"query payload truncated")
        payload=out[at:at+size];at+=size
        if want is None:require(code==INVALID and size==0,"invalid private wire was accepted: "+case)
        else:require(code==size==len(want)and payload==want,"original/native root differs: "+name+"/"+case)
        final=None
        for position in range(ncalls):
            seq,ret,before,after=next(calls);native_calls+=1
            require(before[0]==wire,"native entry used a different query")
            if previous is not None:
                oldout,oldwork=previous
                require(len(before[2])==len(oldwork),"borrowed operation 8/9 unexpectedly grew installed workspace")
                expected_work=bytearray(oldwork)
                if len(expected_work)>=256:struct.pack_into("<Q",expected_work,len(expected_work)-136,1)
                require(before[2]==expected_work,"unrecorded owner workspace transition")
                require(len(before[1])>=len(oldout)and before[1][:len(oldout)]==oldout
                    and not any(before[1][len(oldout):]),"unrecorded output allocation transition")
            if ret==GROW:
                require(position<ncalls-1 and after[1][:8]==b"HGRWS002"and word(after[1],8)==2
                    and word(after[1],16)>len(after[1])and word(after[1],24)==0,"actual output growth invalid")
                require(after[1][32:]==before[1][32:],"growth changed unpublished output bytes");growths+=1
            elif ret<0xffff0000:
                require(position==ncalls-1 and ret==len(payload)and after[1][:ret]==payload
                    and after[1][ret:]==before[1][ret:],"actual complete publication/tail differs")
            else:
                require(position==ncalls-1 and ret==INVALID and want is None
                    and after[1]==before[1],"actual private refusal differs")
            previous=(after[1],after[2]);final=(ret,after)
        if ncalls:
            require(final[0]==code and len(final[1][1])==word(header,88)and len(final[1][2])==word(header,80),"actual descriptor differs from complete buffer record")
        else:require(want is None,"semantic query has no native execution")
    require(at==len(out),"unattributed native output")
    require(next(calls,None)is None,"unattributed native entry")
    require(native_calls==summary["native_calls"]and summary["full_record_bytes"]==process["full_native_buffer_record_bytes"]
        and summary["full_record_sha256"]==process["full_native_buffer_record_sha256"],"full native journal omitted or changed")
    traces=trace_records(owned(folder,"stderr"))
    require(traces["query_native_calls"]==native_calls,"native call trace and full buffer record disagree")
    state=decode(owned(folder,"STATE.json").read_bytes())
    require(decode(owned(folder,"RESULT.json").read_bytes())==dict(status="PASS",process=process,state=state),"retained native state result differs")
    if group["config"]is None:require(state=={},"absent configuration wrote controller state")
    else:
        require(state["."]["mode"]==0o700,"actual controller state privacy differs")
        kernel=owned(folder,"kernel.trace").read_bytes()
        locks=list(re.finditer(rb"flock\((\d+), LOCK_EX\|LOCK_NB\)\s+= 0",kernel))
        require(len(locks)>=2,"real controller lock acquisition absent")
        for name in("controller.owner.lock","controller.lock"):
            row=state[name];require(row["kind"]=="file"and row["mode"]==0o600 and row["nlink"]==1
                and {k:row[k]for k in("bytes","sha256")}==pin(owned(folder,"state/"+name)),"actual controller lock file differs")
        for lock in locks[-2:]:
            require(re.search(rb"close\("+lock[1]+rb"\)\s+= 0",kernel[lock.end():]),"actual controller lock release absent")
    return dict(status="PASS",cases=len(group["queries"]),wire_controls=len(rows)-len(group["queries"]),
        output_growths=growths,trace=traces,**summary)
def read_controls(source,output,reference):
    folder=output/"controls";state=owned(folder,"installed-owner.bin").read_bytes()
    seed=decode(owned(folder,"SEED.json").read_bytes());require(seed["snapshot"]==pin(folder/"installed-owner.bin")
        and seed["synthetic_installed_arena"]is False,"physical control installed state missing")
    probe={};stream=iter(journal(owned(output,"native/operator/calls.bin.gz"),probe))
    _,_,first,_=next(stream);require(first[2]==state,"physical controls were seeded by synthetic state")
    stream.close()
    declared=decode(owned(folder,"CONTROLS.json").read_bytes());summary={};records=iter(journal(owned(folder,"calls.bin.gz"),summary))
    require(len(declared)==14,"physical control omitted")
    want=expected(reference)
    for spec,row in zip(control_specs(),declared):
        seq,code,before,after=next(records)
        size=len(state)if spec["workspace"]is None else spec["workspace"]
        work=bytearray(state[:size])
        if size>=256:struct.pack_into("<Q",work,size-136,1)
        require(before==(spec["wire"],b"\xcc"*spec["output"],bytes(work)),"physical control input/capacity/state changed")
        require(row==dict(name=spec["name"],sequence=seq,code=code,input=sha(spec["wire"]),
            output_capacity=spec["output"],workspace_capacity=size,physical_guards=True),"physical control result declaration differs")
        name=spec["name"]
        if name in("work-zero","work-small"):
            require(code==GROW and after[1][:8]==b"HGRWS002"and word(after[1],8)==1
                and word(after[1],16)>size and word(after[1],24)==0 and after[1][32:]==before[1][32:],"workspace growth ABI changed")
        elif name in("out-zero","out-thirty-one"):
            require(code==SHORT and after[1]==before[1],"short output ABI changed")
        elif name.startswith("out-"):
            if len(before[1])<len(want):
                require(code==GROW and after[1][:8]==b"HGRWS002"and struct.unpack_from("<3Q",after[1],8)==(2,len(want),0)
                    and after[1][32:]==before[1][32:],"output boundary growth differs")
            else:
                require(code==len(want)and after[1][:code]==want and after[1][code:]==before[1][code:],"exact output publication differs")
        else:require(code==INVALID and after[1]==before[1],"invalid owner wire accepted")
    require(next(records,None)is None,"extra physical control native entry")
    result=decode(owned(folder,"RESULT.json").read_bytes())
    require(result["status"]=="PASS"and result["native_calls"]==summary["native_calls"]==14
        and result["complete_buffer_record_bytes"]==summary["full_record_bytes"]
        and result["journal"]==summary["journal"]and result["original_outputs_read"]is False,"physical control journal/result differs")
    return summary
