#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Real physical evidence mutations and complete copies; no capability replay."""
from pathlib import Path
import gzip,shutil,struct
from common import canonical,decode,pin,require
from buffer_store import Reader,Writer
import read_native,readonly
U=lambda raw,at:struct.unpack_from("<Q",raw,at)[0]
def inventory(root):
    root=Path(root)
    return {p.relative_to(root).as_posix():dict(pin(p),mode=p.stat().st_mode&0o777)
        for p in sorted(root.rglob("*")) if p.is_file()}
def receipt(path,value):
    v=decode(Path(path).read_bytes())
    require(v["status"]=="READONLY_PASS" and v["before"]==v["after"] and len(v["probes"])==11
        and all(r["rejected"] is True for r in v["probes"])
        and v["native_executed"] is v["rust_executed"] is v["evidence_written"] is False
        and v["evidence"]==value,"complete prior readonly proof")
def source_case(capture):
    capture=Path(capture);plan=decode((capture/"PLAN.json").read_bytes())
    case=next(c for c in plan["cases"] if c["observer"] and c["name"]=="started_complete")
    return plan,case,capture/"cases"/("%03d"%case["case"]),capture/"fixtures"/Path(case["root"]).name
def resign(root):
    process=decode((root/"process/PROCESS.json").read_bytes())
    for key,path in (("stdin","stdin"),("stdout_gzip","stdout.gz"),("stderr","stderr"),("journal","journal.bin")):
        process[key]=pin(root/"process"/path)
    with gzip.open(root/"process/stdout.gz","rb") as incoming:raw=incoming.read()
    from common import sha
    process["full_stdout"]=dict(bytes=len(raw),sha256=sha(raw))
    (root/"process/PROCESS.json").write_bytes(canonical(process))
    result=decode((root/"RESULT.json").read_bytes());result["process"]=process
    result["files"]={name:pin(root/name) for name in ("COMMANDS.json","HOST.json","FILESYSTEM.json")}
    (root/"RESULT.json").write_bytes(canonical(result))
def mutate(root,kind):
    root=Path(root)
    if kind=="borrowed-result":
        commands=decode((root/"COMMANDS.json").read_bytes());store=Reader(root/"buffers")
        rows=[store.get(r["response"]) for r in commands]
        chosen=next(i for i,r in enumerate(commands) if r["command"]==4 and U(rows[i],8)==320 and U(rows[i],80)==0)
        old=rows[chosen];value=bytearray(old);require(len(value)>448+64,"complete actual borrowed text")
        offset=len(value)-1;value[offset]^=1;rows[chosen]=bytes(value)
        writer=Writer.__new__(Writer);writer.root=root/"buffers"
        writer.known={p.stem for p in writer.root.iterdir()};writer.images=0;writer.logical_bytes=0;writer.recent=[]
        commands[chosen]["response"]=writer.put(rows[chosen])
        (root/"COMMANDS.json").write_bytes(canonical(commands))
        with (root/"process/stdout.gz").open("wb") as out:
            with gzip.GzipFile(fileobj=out,mode="wb",compresslevel=1,mtime=0,filename="") as z:
                for raw in rows:z.write(raw)
        change=dict(command=chosen,offset=offset,before=old[offset],after=rows[chosen][offset])
    else:
        path=root/"process/journal.bin";raw=path.read_bytes();value=bytearray(raw);at=0;offset=None
        if kind=="truncated-final-record":
            require(len(value)>64,"actual journal");offset=len(value)-1;del value[-1:]
        else:
            while at<len(raw):
                require(raw[at:at+8]==b"HPTWJR01","actual journal frame");event=U(raw,at+8);length=U(raw,at+24)
                if kind=="complete-raw" and event==1 and length==64 and U(raw,at+72)==5:
                    offset=at+64+32;require(U(raw,offset)==64,"actual COMPLETE raw before mutation")
                    struct.pack_into("<Q",value,offset,65);break
                if kind=="wait4-status" and event==6 and length==32:
                    offset=at+64+24;require(U(raw,offset)==0,"actual successful wait4 before mutation")
                    struct.pack_into("<Q",value,offset,256);break
                at+=64+length
            require(offset is not None,"physical target frame not found")
        path.write_bytes(value);change=dict(offset=offset,before_extent=len(raw),after_extent=len(value))
    resign(root);return change
def refuse(root,case,fixture,plan):
    try:read_native.verify_case(root,case,fixture,plan["binary"],plan["binary_path"])
    except (ValueError,AssertionError,KeyError,IndexError,struct.error,UnicodeError) as error:
        return dict(rejected=True,type=type(error).__name__,message=str(error))
    raise ValueError("physical signed mutation unexpectedly accepted")
def create(source,capture,output):
    source,capture,output=map(Path,(source,capture,output));require(not output.exists(),"fresh controls");output.mkdir()
    plan,case,base,fixture=source_case(capture);before=inventory(base);fs_before=inventory(fixture)
    controls=[]
    for name in ("complete-raw","wait4-status","borrowed-result","truncated-final-record"):
        folder=output/name;folder.mkdir();shutil.copytree(base,folder/"case");shutil.copytree(fixture,folder/"fixture")
        change=mutate(folder/"case",name)
        proof=readonly.guarded(lambda:refuse(folder/"case",case,folder/"fixture",plan),roots=(source,folder))
        (folder/"READONLY.json").write_bytes(canonical(proof))
        controls.append(dict(name=name,change=change,rejection=proof["evidence"],files=inventory(folder/"case")))
    relocations=[]
    for number in (1,2):
        folder=output/("relocated-"+str(number));folder.mkdir();shutil.copytree(base,folder/"case");shutil.copytree(fixture,folder/"fixture")
        proof=readonly.guarded(lambda:read_native.verify_case(folder/"case",case,folder/"fixture",plan["binary"],plan["binary_path"]),roots=(source,folder))
        (folder/"READONLY.json").write_bytes(canonical(proof))
        relocations.append(dict(name=folder.name,evidence=proof["evidence"]))
    require(inventory(base)==before and inventory(fixture)==fs_before,"physical controls changed original capture")
    result=dict(status="NATIVE_WORKER_PHYSICAL_CONTROLS_PASS",case=case,plan=dict(binary=plan["binary"],binary_path=plan["binary_path"]),
        controls=controls,relocations=relocations,baseline=before,fixture=fs_before,native_executions=0,rust_executions=0)
    (output/"CONTROLS.json").write_bytes(canonical(result));return result
def read(source,capture,output):
    source,capture,output=map(Path,(source,capture,output));plan,case,base,fixture=source_case(capture)
    v=decode((output/"CONTROLS.json").read_bytes())
    require(v["status"]=="NATIVE_WORKER_PHYSICAL_CONTROLS_PASS" and v["case"]==case
        and v["plan"]==dict(binary=plan["binary"],binary_path=plan["binary_path"])
        and v["baseline"]==inventory(base) and v["fixture"]==inventory(fixture)
        and v["native_executions"]==v["rust_executions"]==0,"immutable controls and original binding")
    require([r["name"] for r in v["controls"]]==["complete-raw","wait4-status","borrowed-result","truncated-final-record"]
        and [r["name"] for r in v["relocations"]]==["relocated-1","relocated-2"],"whole physical control domain")
    for row in v["controls"]:
        folder=output/row["name"];require(inventory(folder/"case")==row["files"]==expected_mutation(base,row["name"]),
            "whole physical mutation bytes derived from original, including signed outer custody")
        value=refuse(folder/"case",case,folder/"fixture",plan)
        require(value==row["rejection"],"same actual physical rejection");receipt(folder/"READONLY.json",value)
    for row in v["relocations"]:
        folder=output/row["name"]
        require(inventory(folder/"case")==v["baseline"] and inventory(folder/"fixture")==v["fixture"],"full relocation bytes and modes")
        value=read_native.verify_case(folder/"case",case,folder/"fixture",plan["binary"],plan["binary_path"])
        require(value==row["evidence"],"same complete relocated evidence");receipt(folder/"READONLY.json",value)
    require(set(p.name for p in output.iterdir())=={"CONTROLS.json",*[r["name"] for r in v["controls"]],*[r["name"] for r in v["relocations"]]},"complete control directory set")
    return dict(status="COMPLETE_NATIVE_WORKER_CONTROLS_READ_PASS",physical_mutations=4,relocations=2,native_executed=False,rust_executed=False)

def expected_mutation(base,kind):
    import io
    from common import sha
    original={p.relative_to(base).as_posix():p.read_bytes() for p in base.rglob("*") if p.is_file()}
    data=dict(original)
    def compressed(raw):
        out=io.BytesIO()
        with gzip.GzipFile(fileobj=out,mode="wb",compresslevel=1,mtime=0,filename="") as z:z.write(raw)
        return out.getvalue()
    if kind=="borrowed-result":
        commands=decode(data["COMMANDS.json"]);store=Reader(base/"buffers")
        responses=[store.get(r["response"]) for r in commands]
        i=next(i for i,r in enumerate(commands) if r["command"]==4 and U(responses[i],8)==320 and U(responses[i],80)==0)
        value=bytearray(responses[i]);value[-1]^=1;responses[i]=bytes(value)
        blocks=[]
        for at in range(0,len(value),65536):
            block=bytes(value[at:at+65536]);key=sha(block);blocks.append(key)
            name="buffers/"+key+".gz"
            if name not in data:data[name]=compressed(block)
        commands[i]["response"]=dict(bytes=len(value),sha256=sha(value),blocks=blocks)
        data["COMMANDS.json"]=canonical(commands);data["process/stdout.gz"]=compressed(b"".join(responses))
    else:
        raw=data["process/journal.bin"];value=bytearray(raw)
        if kind=="truncated-final-record":del value[-1:]
        else:
            at=0;found=False
            while at<len(raw):
                event=U(raw,at+8);length=U(raw,at+24)
                if kind=="complete-raw" and event==1 and length==64 and U(raw,at+72)==5:
                    struct.pack_into("<Q",value,at+96,65);found=True;break
                if kind=="wait4-status" and event==6 and length==32:
                    struct.pack_into("<Q",value,at+88,256);found=True;break
                at+=64+length
            require(found,"exact retained physical mutation origin")
        data["process/journal.bin"]=bytes(value)
    process=decode(data["process/PROCESS.json"])
    for key,path in (("stdin","stdin"),("stdout_gzip","stdout.gz"),("stderr","stderr"),("journal","journal.bin")):
        raw=data["process/"+path];process[key]=dict(bytes=len(raw),sha256=sha(raw))
    raw=gzip.decompress(data["process/stdout.gz"]);process["full_stdout"]=dict(bytes=len(raw),sha256=sha(raw))
    data["process/PROCESS.json"]=canonical(process)
    result=decode(data["RESULT.json"]);result["process"]=process
    result["files"]={name:dict(bytes=len(data[name]),sha256=sha(data[name])) for name in ("COMMANDS.json","HOST.json","FILESYSTEM.json")}
    data["RESULT.json"]=canonical(result)
    return {name:dict(bytes=len(raw),sha256=sha(raw),mode=(base/name).stat().st_mode&0o777 if name in original else 0o644)
        for name,raw in sorted(data.items())}
