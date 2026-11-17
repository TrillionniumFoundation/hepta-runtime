"""Physical complete-evidence mutations with honestly resealed stream metadata."""
from pathlib import Path
import copy,gzip,io,shutil,stat,struct,sys
from common import canonical,decode,owned,pin,require,sha
from process import Recorder
from guard_refs import tree,saved_guard
from reuse import processes
import read_capture
CASES=[
("source-byte","frozen source bytes/mode differ"),
("image-self-sealed","runtime exact admitted bytes and modes"),
("original-message","complete actual literal class and unmodified Unicode message"),
("native-message","complete native diagnostic differs from actual original or output tail"),
("output-tail","complete native diagnostic differs from actual original or output tail"),
("workspace-tail","immutable formatter data/workspace tail differs"),
("input-frame","native all raw input/output/workspace bytes"),
("return-extent","native return differs from actual original"),
("relocation-a",None),("relocation-b",None)]
def rawpin(raw):return dict(bytes=len(raw),sha256=sha(raw))
def compressed(raw):
    out=io.BytesIO()
    with gzip.GzipFile(filename="",mode="wb",fileobj=out,compresslevel=1,mtime=0)as stream:stream.write(raw)
    return out.getvalue()
def changes(source,application,runtime,name):
    source,application,runtime=map(Path,(source,application,runtime));result={}
    if name.startswith("relocation-"):return result
    if name=="source-byte":
        path="trusted-build/native/literal_error.hepta";raw=bytearray(owned(source,path).read_bytes());raw[0]^=1
        return {"source/"+path:bytes(raw)}
    if name=="image-self-sealed":
        bundle=decode(owned(runtime,"build/formatter.json").read_bytes());member=bundle["member"]
        metadata=decode(owned(runtime,member["manifest"]).read_bytes())
        image=(Path(member["manifest"]).parent/metadata["image"]).as_posix()
        raw=bytearray(owned(runtime,image).read_bytes());raw[0]^=1;raw=bytes(raw)
        metadata["image_sha256"]=sha(raw);manifest=canonical(metadata)
        member["image_sha256"]=sha(raw);member["manifest_sha256"]=sha(manifest);bundle["image"]=rawpin(raw)
        return {"runtime/"+image:raw,"runtime/"+member["manifest"]:manifest,
            "runtime/build/formatter.json":canonical(bundle)}
    role="original"if name=="original-message"else"native";group="literal-basic-15"
    prefix=role+"/"+group;folder=application/prefix
    raw=bytearray(gzip.decompress(owned(folder,"records.bin.gz").read_bytes()))
    records=decode(owned(folder,"records.json").read_bytes());require(len(records)==9,"fixed sample group")
    record=records[8];at=record["offset"]
    if role=="original":
        cid,insize,outsize=struct.unpack_from("<3Q",raw,at);where=at+24+insize
        require(outsize==13 and bytes(raw[where:where+outsize])==b"Error: sample","fixed original mutation")
        raw[where+outsize-1]^=1
        record["response_sha256"]=sha(bytes(raw[where:where+outsize]))
    else:
        header=list(struct.unpack_from("<8Q",raw,at));cid,code,insize,oc,wc,_,_,_=header
        start=at+64;before=start+insize;old=before+wc;out=old+oc;after=out+oc
        require(code==13 and bytes(raw[out:out+13])==b"Error: sample","fixed native mutation")
        if name=="native-message":raw[out+7]^=1
        elif name=="output-tail":require(oc>code,"retained output tail");raw[out+oc-1]^=1
        elif name=="workspace-tail":require(wc>12288,"retained workspace tail");raw[after+wc-1]^=1
        elif name=="input-frame":raw[start+64]^=1
        elif name=="return-extent":
            header[1]+=1;raw[at:at+64]=struct.pack("<8Q",*header);record["return_code"]=header[1]
        else:raise ValueError("unfrozen physical mutation")
        for key,offset,size in(("input_sha256",start,insize),("before_sha256",before,wc),
            ("output_before_sha256",old,oc),("output_sha256",out,oc),("after_sha256",after,wc)):
            record[key]=sha(bytes(raw[offset:offset+size]))
    record["record_sha256"]=sha(bytes(raw[at:at+record["bytes"]]))
    packed=compressed(bytes(raw));rows=canonical(records);meta=decode(owned(folder,"CAPTURE.json").read_bytes())
    meta.update(raw=rawpin(bytes(raw)),compressed=rawpin(packed),records=rawpin(rows));meta_raw=canonical(meta)
    result.update({prefix+"/records.bin.gz":packed,prefix+"/records.json":rows,prefix+"/CAPTURE.json":meta_raw})
    process_rows=decode(owned(application,"processes/processes.json").read_bytes())
    process=next(r for r in process_rows if r["name"]==role+"-"+group)
    process["stdout"].update(rawpin(meta_raw));result["processes/"+process["stdout"]["file"]]=meta_raw
    result["processes/processes.json"]=canonical(process_rows)
    summary=decode(owned(application,"CAPTURE.json").read_bytes());summary["processes"]=process_rows
    finished=next(r for r in summary["completed"]if r["role"]==role and r["group"]==group)
    finished["capture"]=rawpin(meta_raw);result["CAPTURE.json"]=canonical(summary)
    return {"application/"+key:value for key,value in result.items()}
def full_copy_check(source,application,runtime,candidate,changed):
    count=0
    for label,base in(("source",source),("application",application),("runtime",runtime)):
        files,dirs=tree(base);actual,actualdirs=tree(candidate/label)
        require(set(files)==set(actual)and dirs==actualdirs,"physical complete file and directory set/mode")
        for name,(path,mode)in files.items():
            found,foundmode=actual[name];expected=rawpin(changed[label+"/"+name])if label+"/"+name in changed else pin(path)
            require(foundmode==mode and pin(found)==expected,"physical changed or unchanged full bytes/modes differ")
            count+=1
    require(set(changed)<=set(label+"/"+name for label,base in(("source",source),("application",application),("runtime",runtime))
        for name in tree(base)[0]),"physical mutation cannot create or remove entries")
    return count
def create(source,application,runtime,legacy,admission,output,baseline):
    source,application,runtime,legacy,admission=map(Path,(source,application,runtime,legacy,admission))
    output=Path(output);require(not output.exists(),"fresh complete physical control workspace");output.mkdir()
    origin=dict(source=str(source),application=str(application),runtime=str(runtime),legacy=str(legacy),
        admission=str(admission),controls=str(output),python=sys.executable)
    (output/"ORIGIN.json").write_bytes(canonical(origin));rec=Recorder(source,output/"processes");rows=[]
    for name,reason in CASES:
        candidate=output/name;candidate.mkdir()
        for label,base in(("source",source),("application",application),("runtime",runtime)):
            shutil.copytree(base,candidate/label,copy_function=shutil.copy2)
        changed=changes(source,application,runtime,name)
        for path,raw in changed.items():
            target=owned(candidate,path);mode=stat.S_IMODE(target.stat().st_mode)
            target.chmod(mode|0o200);target.write_bytes(raw);target.chmod(mode)
        files=full_copy_check(source,application,runtime,candidate,changed)
        command=[sys.executable,"-I","-S","-B",candidate/"source/scripts/read_main.py",
            "--source",candidate/"source","--application",candidate/"application","--runtime",candidate/"runtime",
            "--legacy",legacy,"--admission",admission]
        if reason is not None:command+=["--expected-error",reason]
        raw,process=rec.run(name,command,timeout=180);value=decode(raw)
        expected=baseline if reason is None else dict(status="EXPECTED_PHYSICAL_REFUSAL",reason=reason,new_application_calls=0)
        require(value["evidence"]==expected,"complete physical control result")
        rows.append(dict(name=name,reason=reason,files=files,changed={p:rawpin(v)for p,v in changed.items()},
            result=expected,process=process["name"],guard_probes=len(value["probes"])))
        (output/"CONTROLS.json").write_bytes(canonical(dict(status="PENDING",cases=rows,processes=rec.records)))
    result=dict(status="COMPLETE_PHYSICAL_LITERAL_CONTROLS_PASS",cases=rows,processes=rec.records,
        refusals=8,relocations=2,guard_probes=110,new_application_calls=0)
    (output/"CONTROLS.json").write_bytes(canonical(result));return result
def verify(source,application,runtime,legacy,admission,output,baseline):
    origin=decode(owned(output,"ORIGIN.json").read_bytes());saved=decode(owned(output,"CONTROLS.json").read_bytes())
    require(saved["status"]=="COMPLETE_PHYSICAL_LITERAL_CONTROLS_PASS"and saved["refusals"]==8
        and saved["relocations"]==2 and saved["guard_probes"]==110 and saved["new_application_calls"]==0
        and len(saved["cases"])==10,"complete physical control declaration")
    values=processes(output/"processes",saved["processes"],[(name,180)for name,_ in CASES])
    accepted=decode(admission.read_bytes());references=0;file_refs=0
    for (name,reason),row,process in zip(CASES,saved["cases"],saved["processes"]):
        candidate=output/name;changed=changes(source,application,runtime,name)
        files=full_copy_check(source,application,runtime,candidate,changed);file_refs+=files
        old=Path(origin["controls"])/name
        command=[origin["python"],"-I","-S","-B",str(old/"source/scripts/read_main.py"),
            "--source",str(old/"source"),"--application",str(old/"application"),"--runtime",str(old/"runtime"),
            "--legacy",origin["legacy"],"--admission",origin["admission"]]
        if reason is not None:command+=["--expected-error",reason]
        require(process["argv"]==command and process["cwd"]==origin["source"],"exact physical reader command")
        try:
            actual=read_capture.verify(candidate/"source",candidate/"application",candidate/"runtime",legacy,
                accepted["legacy_identity"],accepted["runtime"])
        except ValueError as error:
            require(reason is not None and str(error)==reason,"independent physical refusal reason")
            actual=dict(status="EXPECTED_PHYSICAL_REFUSAL",reason=reason,new_application_calls=0)
        else:require(reason is None and actual==baseline,"independent full relocation result")
        require(row==dict(name=name,reason=reason,files=files,changed={p:rawpin(v)for p,v in changed.items()},
            result=actual,process=name,guard_probes=11)and values[name]["evidence"]==actual,"complete physical saved result")
        roots={str(old/"source"):tree(candidate/"source"),str(old/"application"):tree(candidate/"application"),
            str(old/"runtime"):tree(candidate/"runtime"),str(Path(origin["admission"]).parent):tree(admission.parent),
            str(Path(origin["legacy"])/"original"):tree(legacy/"original"),
            str(Path(origin["legacy"])/"processes"):tree(legacy/"processes")}
        references+=saved_guard(values[name],roots)
    return dict(status="ALL_PHYSICAL_LITERAL_EVIDENCE_PASS",refusals=8,relocations=2,guard_probes=110,
        complete_physical_file_references=file_refs,saved_guard_full_file_references=references,new_application_calls=0)
