"""Physically reseal complete evidence variants; no application invocations."""
from pathlib import Path
import gzip,io,shutil,stat,struct,sys
from common import canonical,decode,owned,pin,require,sha
from process import Recorder
from guard_refs import tree,saved_guard
from reuse import processes
import read_capture
CASES=[
("source-byte","frozen source bytes/mode differ"),
("image-self-sealed","runtime exact admitted bytes and modes"),
("original-message","native full response or output tail differs from actual original"),
("native-message","native full response or output tail differs from actual original"),
("output-tail","native full response or output tail differs from actual original"),
("workspace-tail","native workspace tail or guard changed"),
("input-guard","native actual input or input guard changed"),
("return-extent","native return differs from retained actual original"),
("relocation-a",None),("relocation-b",None)]
def rawpin(raw):return dict(bytes=len(raw),sha256=sha(raw))
def compressed(raw):
    out=io.BytesIO()
    with gzip.GzipFile(filename="",mode="wb",fileobj=out,compresslevel=1,mtime=0)as stream:stream.write(raw)
    return out.getvalue()
def changes(source,application,runtime,name):
    if name.startswith("relocation-"):return {}
    if name=="source-byte":
        path="trusted-build/native/python_json_items.hepta";raw=bytearray(owned(source,path).read_bytes());raw[0]^=1
        return {"source/"+path:bytes(raw)}
    if name=="image-self-sealed":
        bundle=decode(owned(runtime,"build/module.json").read_bytes());member=bundle["member"]
        metadata=decode(owned(runtime,member["manifest"]).read_bytes())
        image=(Path(member["manifest"]).parent/metadata["image"]).as_posix()
        raw=bytearray(owned(runtime,image).read_bytes());raw[0]^=1;raw=bytes(raw)
        metadata["image_sha256"]=sha(raw);manifest=canonical(metadata)
        member["image_sha256"]=sha(raw);member["manifest_sha256"]=sha(manifest);bundle["image"]=rawpin(raw)
        return {"runtime/"+image:raw,"runtime/"+member["manifest"]:manifest,"runtime/build/module.json":canonical(bundle)}
    role="original"if name=="original-message"else"native";group="0";prefix=role+"/"+group;folder=application/prefix
    raw=bytearray(gzip.decompress(owned(folder,"records.bin.gz").read_bytes()))
    records=decode(owned(folder,"records.json").read_bytes())
    record=next(r for r in records if r["case_id"]==1);at=record["offset"]
    if role=="original":
        cid,insize,paysize,metasize,ordinal,bl,br,al,ar,zero=struct.unpack_from("<10Q",raw,at)
        where=at+80+insize;require(insize==100 and paysize==56,"whole original dictionary item sample")
        raw[where+paysize-1]^=1;record["payload_sha256"]=sha(bytes(raw[where:where+paysize]))
    else:
        header=list(struct.unpack_from("<10Q",raw,at));cid,code,insize,ic,oc,wc,ordinal,z0,z1,z2=header
        start=at+80;after_input=start+ic;before_out=after_input+ic;after_out=before_out+oc+16
        before_work=after_out+oc+16;after_work=before_work+wc+16
        require(insize==100 and code==180 and oc==728 and wc==16840,"complete native dictionary item sample")
        if name=="native-message":raw[after_out+code-1]^=1
        elif name=="output-tail":raw[after_out+oc-1]^=1
        elif name=="workspace-tail":raw[after_work+wc+15]^=1
        elif name=="input-guard":raw[after_input+ic-1]^=1
        elif name=="return-extent":
            header[1]+=1;raw[at:at+80]=struct.pack("<10Q",*header);record["return_code"]=header[1]
        else:raise ValueError("undeclared physical variant")
        record["before"]=[sha(bytes(raw[p:p+n]))for p,n in((start,ic),(before_out,oc+16),(before_work,wc+16))]
        record["after"]=[sha(bytes(raw[p:p+n]))for p,n in((after_input,ic),(after_out,oc+16),(after_work,wc+16))]
    record["record_sha256"]=sha(bytes(raw[at:at+record["bytes"]]))
    packed=compressed(bytes(raw));rows=canonical(records);meta=decode(owned(folder,"CAPTURE.json").read_bytes())
    meta.update(raw=rawpin(bytes(raw)),compressed=rawpin(packed),records=rawpin(rows));meta_raw=canonical(meta)
    result={prefix+"/records.bin.gz":packed,prefix+"/records.json":rows,prefix+"/CAPTURE.json":meta_raw}
    process_rows=decode(owned(application,"processes/processes.json").read_bytes())
    process=next(r for r in process_rows if r["name"]==role+"-"+group)
    process["stdout"].update(rawpin(meta_raw));result["processes/"+process["stdout"]["file"]]=meta_raw
    result["processes/processes.json"]=canonical(process_rows)
    summary=decode(owned(application,"CAPTURE.json").read_bytes());summary["processes"]=process_rows
    next(r for r in summary["completed"]if r["role"]==role and r["group"]==group)["capture"]=rawpin(meta_raw)
    result["CAPTURE.json"]=canonical(summary)
    return {"application/"+key:value for key,value in result.items()}
def full_copy_check(source,application,runtime,candidate,changed):
    count=0;names=set()
    for label,base in(("source",source),("application",application),("runtime",runtime)):
        files,dirs=tree(base);actual,actualdirs=tree(candidate/label)
        require(set(files)==set(actual)and dirs==actualdirs,"physical full file and directory set/mode")
        for name,(path,mode)in files.items():
            found,foundmode=actual[name];key=label+"/"+name;names.add(key)
            expected=rawpin(changed[key])if key in changed else pin(path)
            require(foundmode==mode and pin(found)==expected,"physical complete changed and unchanged bytes")
            count+=1
    require(set(changed)<=names,"physical variant cannot add entries");return count
def create(source,application,runtime,original_runtime,admission,output,baseline):
    require(not output.exists(),"fresh physical decoder control workspace");output.mkdir()
    origin=dict(source=str(source),application=str(application),runtime=str(runtime),original_runtime=str(original_runtime),
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
            "--original-runtime",original_runtime,"--admission",admission]
        if reason is not None:command+=["--expected-error",reason]
        raw,process=rec.run(name,command,timeout=180);value=decode(raw)
        expected=baseline if reason is None else dict(status="EXPECTED_PHYSICAL_REFUSAL",reason=reason,new_application_calls=0)
        require(value["evidence"]==expected,"complete physical decoder control result")
        rows.append(dict(name=name,reason=reason,files=files,changed={p:rawpin(v)for p,v in changed.items()},
            result=expected,process=process["name"],guard_probes=len(value["probes"])))
        (output/"CONTROLS.json").write_bytes(canonical(dict(status="PENDING",cases=rows,processes=rec.records)))
    value=dict(status="COMPLETE_PHYSICAL_JSON_BYTES_CONTROLS_PASS",cases=rows,processes=rec.records,
        refusals=8,relocations=2,guard_probes=110,new_application_calls=0)
    (output/"CONTROLS.json").write_bytes(canonical(value));return value
def verify(source,application,runtime,original_runtime,admission,output,baseline):
    origin=decode(owned(output,"ORIGIN.json").read_bytes());saved=decode(owned(output,"CONTROLS.json").read_bytes())
    require(saved["status"]=="COMPLETE_PHYSICAL_JSON_BYTES_CONTROLS_PASS"and saved["refusals"]==8
        and saved["relocations"]==2 and saved["guard_probes"]==110 and saved["new_application_calls"]==0
        and len(saved["cases"])==10,"complete physical decoder control declaration")
    values=processes(output/"processes",saved["processes"],[(name,180)for name,_ in CASES])
    references=0;file_refs=0
    for (name,reason),row,process in zip(CASES,saved["cases"],saved["processes"]):
        candidate=output/name;changed=changes(source,application,runtime,name)
        files=full_copy_check(source,application,runtime,candidate,changed);file_refs+=files
        old=Path(origin["controls"])/name
        command=[origin["python"],"-I","-S","-B",str(old/"source/scripts/read_main.py"),
            "--source",str(old/"source"),"--application",str(old/"application"),"--runtime",str(old/"runtime"),
            "--original-runtime",origin["original_runtime"],"--admission",origin["admission"]]
        if reason is not None:command+=["--expected-error",reason]
        require(process["argv"]==command and process["cwd"]==origin["source"],"exact retained physical reader command")
        expected=baseline if reason is None else dict(status="EXPECTED_PHYSICAL_REFUSAL",reason=reason,new_application_calls=0)
        require(row==dict(name=name,reason=reason,files=files,changed={p:rawpin(v)for p,v in changed.items()},
            result=expected,process=name,guard_probes=11)and values[name]["evidence"]==expected,"complete retained physical result")
        roots={str(old/"source"):tree(candidate/"source"),str(old/"application"):tree(candidate/"application"),
            str(old/"runtime"):tree(candidate/"runtime"),origin["original_runtime"]:tree(original_runtime),
            str(Path(origin["admission"]).parent):tree(admission.parent)}
        references+=saved_guard(values[name],roots)
    return dict(status="ALL_RETAINED_PHYSICAL_JSON_BYTES_EVIDENCE_PASS",refusals=8,relocations=2,guard_probes=110,
        complete_physical_file_references=file_refs,saved_guard_full_file_references=references,new_application_calls=0,
        physical_controls_reexecuted=False)
