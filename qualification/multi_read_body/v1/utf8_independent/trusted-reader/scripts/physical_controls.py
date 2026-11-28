#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Eight physical evidence refusals and two complete relocations, without app replay."""
from pathlib import Path
import argparse,gzip,hashlib,os,shutil,stat,struct,sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/"scripts"))
from evidence_common import source_evidence,encoded,decode,pin,require
import read_utf8
from readonly import guarded
def identity(p):return dict(**pin(p),mode=p.stat().st_mode&0o777)
def copy_tree(source,target):shutil.copytree(source,target,copy_function=os.link)
def replace(path,raw):
    mode=path.stat().st_mode&0o777;temporary=path.with_name(path.name+".new")
    temporary.write_bytes(raw);temporary.chmod(mode);os.replace(temporary,path)
def rewrite_cases(folder,change):
    path=folder/"cases.jsonl.gz"
    with gzip.open(path,"rb") as stream:values=[decode(row) for row in stream]
    change(values);lines=[encoded(v) for v in values];raw=b"".join(lines)
    replace(path,gzip.compress(raw,compresslevel=1,mtime=0))
    report=decode((folder/"CAPTURE.json").read_bytes())
    report["case_stream"]=dict(raw=dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest()),
        compressed=pin(path),line_sha256=[hashlib.sha256(line).hexdigest() for line in lines])
    replace(folder/"CAPTURE.json",encoded(report))
def alter_original(values):
    value=values[0]["result"]
    if value["kind"]=="valid":value["codepoints"]+=1
    else:value["message"]+=" altered";value["diagnostic"]="UnicodeDecodeError: "+value["message"]
def alter_native(values):values[0]["packet"]=values[1]["packet"]
def outcome(source,data,group):
    try:read_utf8.verify(source,data,group)
    except (ValueError,OSError,EOFError,KeyError,struct.error) as exc:
        return dict(status="REJECTED",error_type=type(exc).__name__,message=str(exc))
    raise ValueError("physically altered evidence unexpectedly passed")
def retire(copy,original):
    files={p.relative_to(copy).as_posix():p for p in copy.rglob("*") if p.is_file()}
    originals={p.relative_to(original).as_posix():p for p in original.rglob("*") if p.is_file()}
    dirs={p.relative_to(copy).as_posix():p.stat().st_mode&0o777 for p in [copy,*copy.rglob("*")] if p.is_dir()}
    before_dirs={p.relative_to(original).as_posix():p.stat().st_mode&0o777 for p in [original,*original.rglob("*")] if p.is_dir()}
    require(set(files)==set(originals) and dirs==before_dirs,"duplicate complete set before retirement")
    total=0
    for name,path in files.items():
        before=originals[name]
        require(not path.is_symlink() and identity(path)==identity(before) and path.read_bytes()==before.read_bytes(),
            "complete duplicate bytes/mode before retirement")
        total+=path.stat().st_size
    shutil.rmtree(copy)
    return dict(files=len(files),bytes=total,directories=len(dirs),all_bytes_and_modes_compared=True)
def main():
    p=argparse.ArgumentParser()
    for name in ("source","data","output","baseline"):p.add_argument("--"+name,type=Path,required=True)
    p.add_argument("--group",required=True);a=p.parse_args()
    source=a.source.resolve(strict=True);data=a.data.resolve(strict=True)
    before_source=source_evidence(source);baseline=decode(a.baseline.read_bytes())
    require(baseline["evidence"]["status"]=="COMPLETE_ORIGINAL_NATIVE_MULTI_UTF8_PASS","actual full baseline")
    require(not a.output.exists(),"fresh controls");a.output.mkdir(parents=True)
    names=("native-buffer","original-case","native-stdout","native-stdin","native-image",
        "source-manifest","honest-native-packet","honest-original-result")
    expected={"native-buffer":("complete block bytes changed",),
        "original-case":("complete case archive identity",),
        "native-stdout":("complete stdout compressed identity",),
        "native-stdin":("complete native stdin identity",),
        "native-image":("retained native ELF bytes",),
        "source-manifest":("Extra data",),
        "honest-native-packet":("actual native input-only packet",),
        "honest-original-result":("actual original decoded value","actual native complete diagnostic equals original")}
    results=[]
    for name in names:
        folder=a.output/name;folder.mkdir();working=folder/"working";working.mkdir()
        selected=working/"data";copy_tree(data,selected);selected_source=source
        if name=="source-manifest":selected_source=working/"source";copy_tree(source,selected_source)
        if name=="native-buffer":files=[sorted((selected/"native/buffers").glob("*.gz"))[0]]
        elif name=="original-case":files=[selected/"original/cases.jsonl.gz"]
        elif name=="native-stdout":files=[selected/"native/carrier.stdout.gz"]
        elif name=="native-stdin":files=[selected/"native/carrier.stdin"]
        elif name=="native-image":files=[selected/"production/multi-read-body-callable.elf"]
        elif name=="source-manifest":files=[selected_source/"SOURCE_MANIFEST.json"]
        else:
            base=selected/("native" if name=="honest-native-packet" else "original")
            files=[base/"cases.jsonl.gz",base/"CAPTURE.json"]
        changes=[]
        for number,path in enumerate(files):
            root_name="source" if path.is_relative_to(selected_source) and selected_source!=source else "data"
            relative=path.relative_to(selected_source if root_name=="source" else selected).as_posix()
            before=path.read_bytes();(folder/("change-"+str(number)+".before")).write_bytes(before)
            changes.append(dict(root=root_name,path=relative,before=identity(path),
                before_file="change-"+str(number)+".before",after_file="change-"+str(number)+".after"))
        file=files[0];before=file.read_bytes()
        if name=="native-buffer":
            raw=gzip.decompress(before);require(raw,"nonempty complete native block")
            replace(file,gzip.compress(bytes([raw[0]^1])+raw[1:],compresslevel=1,mtime=0))
        elif name=="source-manifest":replace(file,before+b"\nACTUAL_BAD_SOURCE\n")
        elif name=="honest-native-packet":rewrite_cases(file.parent,alter_native)
        elif name=="honest-original-result":rewrite_cases(file.parent,alter_original)
        else:require(before,"nonempty actual evidence file");replace(file,bytes([before[0]^1])+before[1:])
        for change,path in zip(changes,files):
            require(path.read_bytes()!=(folder/change["before_file"]).read_bytes(),"real changed bytes")
            (folder/change["after_file"]).write_bytes(path.read_bytes());change["after"]=identity(path)
        guard=guarded(lambda:outcome(selected_source,selected,a.group),roots=[selected_source,selected])
        require(guard["evidence"]["status"]=="REJECTED"
            and any(message in guard["evidence"]["message"] for message in expected[name]),
            "wrong physical rejection reason: "+name+" "+str(guard["evidence"]))
        (folder/"READONLY.json").write_bytes(encoded(guard))
        for change,path in zip(changes,files):replace(path,(folder/change["before_file"]).read_bytes())
        retired=dict(data=retire(selected,data))
        if selected_source!=source:retired["source"]=retire(selected_source,source)
        working.rmdir()
        row=dict(name=name,changes=changes,roots=dict(source=str(selected_source),data=str(selected)),
            guard=pin(folder/"READONLY.json"),evidence=guard["evidence"],guard_probes=len(guard["probes"]),
            retired=retired,honestly_resealed=name.startswith("honest-"))
        (folder/"CONTROL.json").write_bytes(encoded(row));results.append(row)
    relocations=[]
    for number in (1,2):
        folder=a.output/("relocation-"+str(number));folder.mkdir();working=folder/"working";working.mkdir()
        target_source=working/"source";target_data=working/"data";copy_tree(source,target_source);copy_tree(data,target_data)
        guard=guarded(lambda:read_utf8.verify(target_source,target_data,a.group),roots=[target_source,target_data])
        require(guard["evidence"]==baseline["evidence"],"complete relocated qualification")
        (folder/"READONLY.json").write_bytes(encoded(guard))
        retired=dict(source=retire(target_source,source),data=retire(target_data,data));working.rmdir()
        row=dict(name=folder.name,roots=dict(source=str(target_source),data=str(target_data)),
            guard=pin(folder/"READONLY.json"),evidence=guard["evidence"],guard_probes=len(guard["probes"]),retired=retired)
        (folder/"CONTROL.json").write_bytes(encoded(row));relocations.append(row)
    require(source_evidence(source)==before_source,"source changed during controls")
    result=dict(status="EIGHT_PHYSICAL_REFUSALS_TWO_FULL_RELOCATIONS_PASS",group=a.group,
        baseline=pin(a.baseline),physical=results,relocations=relocations,
        guard_probes=sum(r["guard_probes"] for r in results+relocations),application_executions=0)
    (a.output/"RESULT.json").write_bytes(encoded(result));print(encoded(result).decode(),end="")
if __name__=="__main__":main()
