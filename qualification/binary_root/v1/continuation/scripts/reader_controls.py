#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Six physical refusals and two complete relocated pure admissions."""
from pathlib import Path
import gzip
import hashlib
import os
import shutil
import stat
import struct
from common import canonical,decode,owned,pin,require
from readonly import guarded
from read_root import original_location
from run_ci import read_all
NAMES=("source-byte","native-image","original-root","crate-archive","native-buffer","omitted-query")
EXPECTED={
    "source-byte":"source byte pin changed: README.md",
    "native-image":"complete native bytes differ",
    "original-root":"original/native root differs: absent/rpc",
    "crate-archive":"locked crate checksum differs",
    "native-buffer":"actual native borrowed input changed",
    "omitted-query":"actual installed query envelope differs",
}
def inventory(root):
    rows={}
    for path in [root,*sorted(root.rglob("*"))]:
        info=path.lstat();name="."if path==root else path.relative_to(root).as_posix()
        require(stat.S_ISREG(info.st_mode)or stat.S_ISDIR(info.st_mode),"physical clone entry kind differs")
        row=dict(mode=info.st_mode)
        if stat.S_ISREG(info.st_mode):row.update(pin(path))
        rows[name]=row
    return rows
def clone(source,target):
    target.mkdir(parents=True,mode=stat.S_IMODE(source.stat().st_mode))
    for path in sorted(source.rglob("*")):
        relative=path.relative_to(source);destination=target/relative;mode=path.lstat().st_mode
        if stat.S_ISDIR(mode):destination.mkdir(mode=stat.S_IMODE(mode));destination.chmod(stat.S_IMODE(mode))
        else:
            require(stat.S_ISREG(mode),"clone refuses non-ordinary input")
            os.link(path,destination)
    require(inventory(source)==inventory(target),"complete ordinary clone differs")
def replace(path,raw):
    tmp=path.with_name(path.name+".physical-replacement")
    require(not tmp.exists(),"mutation temporary file already exists")
    mode=stat.S_IMODE(path.stat().st_mode)
    tmp.write_bytes(raw);tmp.chmod(mode);os.replace(tmp,path)
def update_native_process(folder):
    process=decode((folder/"PROCESS.json").read_bytes())
    process["streams"]={name:pin(folder/name)for name in process["streams"]}
    replace(folder/"PROCESS.json",canonical(process))
    result=decode((folder/"RESULT.json").read_bytes());result["process"]=process
    replace(folder/"RESULT.json",canonical(result))
def mutate(root,name):
    if name=="source-byte":
        path=root/"source/README.md";replace(path,path.read_bytes()+b"\nphysical control\n")
    elif name=="native-image":
        built=decode((root/"build/result.json").read_bytes())
        owner=next(row for row in built["members"]if row["name"]=="config-owner")
        manifest=original_location(root,owner["manifest"]);metadata=decode(manifest.read_bytes())
        path=manifest.parent/metadata["image"];raw=bytearray(path.read_bytes());raw[0]^=1;replace(path,raw)
    elif name=="original-root":
        path=root/"processes/original-absent.stdout";rows=decode(path.read_bytes());rows[0]["error"]+="!"
        replace(path,canonical(rows))
        receipt=root/"processes/original-absent.json";value=decode(receipt.read_bytes())
        value["streams"]["stdout"]=pin(path);replace(receipt,canonical(value))
    elif name=="crate-archive":
        first=decode((root/"registry-evidence.json").read_bytes())["packages"][0]
        path=root/first["archive"];raw=bytearray(path.read_bytes());raw[-1]^=1;replace(path,raw)
    elif name=="native-buffer":
        folder=root/"native/absent";path=folder/"calls.bin.gz";tmp=path.with_name("mutated-call-stream.gz")
        digest=hashlib.sha256();at=0
        with gzip.open(path,"rb")as incoming,gzip.GzipFile(filename=str(tmp),mode="wb",compresslevel=1,mtime=0)as output:
            while True:
                part=incoming.read(1<<20)
                if not part:break
                raw=bytearray(part)
                if at<=64<at+len(raw):raw[64-at]^=1
                output.write(raw);digest.update(raw);at+=len(raw)
        tmp.chmod(stat.S_IMODE(path.stat().st_mode));os.replace(tmp,path)
        process=decode((folder/"PROCESS.json").read_bytes())
        require(process["full_native_buffer_record_bytes"]==at,"mutant must retain full physical size")
        process["full_native_buffer_record_sha256"]=digest.hexdigest();replace(folder/"PROCESS.json",canonical(process))
        update_native_process(folder)
    elif name=="omitted-query":
        folder=root/"native/absent";path=folder/"stdout";raw=path.read_bytes();at=0;starts=[]
        while at<len(raw):
            starts.append(at);require(len(raw)-at>=96,"original query envelope absent")
            size=struct.unpack_from("<Q",raw,at+24)[0];at+=96+size
        require(at==len(raw)and len(starts)==5,"absent group capture differs")
        replace(path,raw[:starts[-1]]);update_native_process(folder)
    else:raise ValueError("unknown physical mutation")
def produce(source,output):
    source,output=Path(source),Path(output);home=output.parent/"physical-controls"
    require(not home.exists(),"physical control output reused");home.mkdir(mode=0o700)
    before=inventory(output);cases=[]
    for name in NAMES:
        path=home/name/"complete";clone(output,path);cases.append((name,path,False))
    for name in("relocated-one","nested-relocated-two"):
        path=home/name/"nested ordinary runtime";clone(output,path);cases.append((name,path,True))
    for name,path,admit in cases:
        if not admit:mutate(path,name)
    require(inventory(output)==before,"physical setup changed original bytes, modes or file/directory set")
    setup=dict(schema="hepta.runtime.binary-root.physical-setup.v1",original=before,
        all_clones_prepared_before_all_readers=True,all_mutations_completed_before_all_readers=True,
        complete_ordinary_hardlink_clones=True,atomic_replacement_only=True,
        original_byte_mode_set_unchanged=True,link_counts_and_ctimes_change_only_during_declared_setup=True,
        cases=[dict(name=n,path=p.relative_to(home).as_posix(),admitted=a)for n,p,a in cases])
    (home/"SETUP.json").write_bytes(canonical(setup));proofs=home/"proofs";proofs.mkdir()
    records=[]
    for name,path,admit in cases:
        def operation():
            if admit:return read_all(source,path)
            try:read_all(source,path)
            except ValueError as error:
                require(EXPECTED[name]in str(error),"physical refusal reason changed: "+repr(error))
                return dict(status="EXPECTED_PHYSICAL_REFUSAL",mutation=name,error_type="ValueError",message=str(error))
            raise ValueError("physical mutant unexpectedly admitted")
        proof=guarded(operation,roots=[source,path])
        target=proofs/(name+".json");target.write_bytes(canonical(proof))
        records.append(dict(name=name,admitted=admit,path=path.relative_to(home).as_posix(),
            proof=target.relative_to(home).as_posix(),proof_pin=pin(target),
            guard_probes=len(proof["probes"]),unchanged_entries=proof["entries"],status=proof["evidence"]["status"]))
    require(inventory(output)==before,"physical readers changed original bytes/modes/set")
    result=dict(status="PHYSICAL_READER_CONTROLS_PASS",refusals=6,relocations=2,
        guard_probes=sum(x["guard_probes"]for x in records),records=records,setup=pin(home/"SETUP.json"),
        native_or_rust_executions=0,source_root=str(source),original_output=str(output))
    (home/"RESULT.json").write_bytes(canonical(result));return result
def verify(source,output):
    source,output=Path(source),Path(output);home=output.parent/"physical-controls"
    result=decode(owned(home,"RESULT.json").read_bytes())
    require(result["status"]=="PHYSICAL_READER_CONTROLS_PASS"and result["refusals"]==6 and result["relocations"]==2
        and result["guard_probes"]==88 and result["native_or_rust_executions"]==0,"physical control result differs")
    setup=decode(owned(home,"SETUP.json").read_bytes())
    require(pin(home/"SETUP.json")==result["setup"]and inventory(output)==setup["original"]
        and setup["all_clones_prepared_before_all_readers"]is True
        and setup["all_mutations_completed_before_all_readers"]is True
        and setup["original_byte_mode_set_unchanged"]is True,"original full capture changed after controls")
    require([r["name"]for r in result["records"]]==list(NAMES)+["relocated-one","nested-relocated-two"],"physical domain omitted")
    origin=decode(owned(output,"ORIGIN.json").read_bytes())
    old_source=Path(result["source_root"]);old_home=Path(result["original_output"]).parent/"physical-controls"
    expected_probes={"write","os-open-write","mkdir","rename","unlink","chmod","utime","subprocess","ctypes","mmap","foreign-read"}
    for row in result["records"]:
        path=owned(home,row["proof"]);require(pin(path)==row["proof_pin"],"saved full guard proof changed")
        proof=decode(path.read_bytes())
        require(proof["status"]=="READONLY_PASS"and proof["before"]==proof["after"]
            and len(proof["before"])==proof["entries"]==row["unchanged_entries"]
            and len(proof["probes"])==row["guard_probes"]==11
            and {p["name"]for p in proof["probes"]if p["rejected"]is True}==expected_probes
            and proof["native_executed"]is False and proof["rust_executed"]is False
            and proof["evidence_written"]is False,"complete immutable reader proof differs")
        mapped=[]
        for name in proof["roots"]:
            old=Path(name)
            if old==old_source:mapped.append(source)
            else:
                require(old.is_relative_to(old_home),"unbound proof root")
                mapped.append(home/old.relative_to(old_home))
        expected={}
        for item in proof["before"]:
            key=(item["root"],item["path"]);require(key not in expected,"duplicate saved snapshot entry")
            value=dict(mode=item["mode"])
            if stat.S_ISREG(item["mode"]):value.update(bytes=item["bytes"],sha256=item["sha256"])
            expected[key]=value
        actual={(number,name):value for number,root in enumerate(mapped)for name,value in inventory(root).items()}
        require(expected==actual,"complete saved proof file bytes/modes/set no longer match")
        if row["admitted"]:
            require(proof["evidence"]["status"]=="COMPLETE_BINARY_ROOT_COMPARISON_PASS"
                and proof["evidence"]["native"]["original_cases"]==135,"complete relocation admission missing")
        else:
            require(proof["evidence"]["status"]=="EXPECTED_PHYSICAL_REFUSAL"
                and EXPECTED[row["name"]]in proof["evidence"]["message"],"physical refusal evidence changed")
    admission=read_all(source,output)
    return dict(status="COMPLETE_BINARY_ROOT_CONTROLS_PASS",native=dict(**admission["native"],physical_refusals=6,relocations=2,
        retained_guard_probes=88,complete_control_proofs=8),admission=admission,native_or_rust_executions=0)
