"""Compare complete retained actual byte-decoder records; zero application calls."""
from pathlib import Path
import gzip,hashlib,struct
from common import canonical,decode,owned,pin,require,sha,source_evidence
from reuse import processes
import cases,read_runtime
MAGIC=int.from_bytes(b"HPYDER01","little")
ENCODING={"utf-8":1,"utf-8-sig":1,"utf-16-le":2,"utf-16-be":3,"utf-32-le":4,"utf-32-be":5}
REASONS={"invalid start byte":1,"invalid continuation byte":2,"unexpected end of data":3,
    "truncated data":4,"code point not in range(0x110000)":5}
def take(stream,size):
    require(type(size)is int and size>=0,"invalid retained span extent")
    raw=stream.read(size);require(len(raw)==size,"short complete actual byte record");return raw
def rawpin(raw):return dict(bytes=len(raw),sha256=sha(raw))
def runtime_files(runtime):
    bundle=decode(owned(runtime,"build/module.json").read_bytes());row=bundle["member"]
    path=owned(runtime,row["manifest"]);metadata=decode(path.read_bytes())
    require(pin(path)["sha256"]==row["manifest_sha256"]and bundle["image"]["sha256"]==metadata["image_sha256"],
        "fixed runtime manifest and image declaration")
    artifacts={row["manifest"]:pin(path)}
    for name in("source","image"):
        member=owned(path.parent,metadata[name]);artifacts[member.relative_to(runtime).as_posix()]=pin(member)
        require(pin(member)["sha256"]==metadata[name+"_sha256"],"runtime complete source and image")
    return artifacts,bundle
def expected_response(wire,meta,payload,obj):
    detected=meta["detected"];skip=0
    if detected=="utf-16":
        require(wire[:2]in(b"\xff\xfe",b"\xfe\xff"),"actual BOM UTF-16 detection")
        encoding=2 if wire[:2]==b"\xff\xfe"else 3;skip=2
    elif detected=="utf-32":
        require(wire[:4]in(b"\xff\xfe\0\0",b"\0\0\xfe\xff"),"actual BOM UTF-32 detection")
        encoding=4 if wire[:4]==b"\xff\xfe\0\0"else 5;skip=4
    else:
        require(detected in ENCODING,"actual explicit detected encoding");encoding=ENCODING[detected]
        if detected=="utf-8-sig":skip=3
    if meta["kind"]==0:
        require(obj==b""and len(payload)==4*meta["codepoints"],"complete actual Unicode payload extent")
        header=(MAGIC,0,encoding,meta["codepoints"],skip,0,0,len(payload))
    else:
        require(meta["kind"]==1 and meta["encoding"]in ENCODING and ENCODING[meta["encoding"]]==encoding
            and meta["reason"]in REASONS and 0<=meta["start"]<meta["end"]<=len(obj),
            "actual UnicodeDecodeError fields")
        require(obj==(wire[3:]if detected=="utf-8-sig"else wire)
            and payload.startswith(b"UnicodeDecodeError: "),"whole actual decoder error object and class")
        header=(MAGIC,1,encoding,meta["start"],meta["end"],REASONS[meta["reason"]],obj[meta["start"]],len(payload))
    return struct.pack("<8Q",*header)+payload
def capture_meta(source,application,role,group,process_map):
    folder=application/role/group;meta=decode(owned(folder,"CAPTURE.json").read_bytes())
    require(meta["schema"]=="hepta.runtime.python-json-bytes."+role+".v1"and meta["status"]=="PASS"
        and meta["source"]==source_evidence(source)and meta["group"]==group and meta["application_replay"]is False,
        "complete capture identity")
    require(meta["compressed"]==pin(owned(folder,"records.bin.gz"))and meta["records"]==pin(owned(folder,"records.json")),
        "complete capture retained stream bytes")
    process=process_map[role+"-"+group]
    require(decode(owned(application,"processes/"+process["stdout"]["file"]).read_bytes())==meta
        and meta["pid"]==process["pid"],"actual worker stdout and PID custody")
    return folder,meta,decode(owned(folder,"records.json").read_bytes())
def original_group(source,application,group,process_map,runtime_value,control_oracles):
    folder,meta,records=capture_meta(source,application,"original",group,process_map)
    require(meta["runtime"]==runtime_value,"original actual interpreter/module identity")
    values=cases.cases(int(group));whole=hashlib.sha256();offset=0;results={};count=0
    desired={v["wire"]for v in cases.controls()if len(v["wire"])<=16}
    with gzip.open(owned(folder,"records.bin.gz"),"rb")as stream:
        for number,value in enumerate(values,1):
            require(number<=len(records),"missing original record");record=records[number-1]
            header=take(stream,64);cid,insize,paysize,objsize,metasize,ordinal,z0,z1=struct.unpack("<8Q",header)
            require((cid,insize,ordinal,z0,z1)==(value["case_id"],len(value["wire"]),number,0,0)
                and paysize==record["payload_bytes"]and objsize==record["object_bytes"]and metasize<=2048,
                "original complete record header")
            wire=take(stream,insize);payload=take(stream,paysize);obj=take(stream,objsize);metadata=take(stream,metasize)
            actual=decode(metadata);require(metadata==canonical(actual)and actual["native_byteorder"]=="little",
                "original complete canonical metadata")
            digest=hashlib.sha256();size=0
            for span in(header,wire,payload,obj,metadata):digest.update(span);whole.update(span);size+=len(span)
            expected=dict(case_id=cid,label=value["label"],offset=offset,bytes=size,input_bytes=len(wire),input_sha256=sha(wire),
                payload_bytes=len(payload),payload_sha256=sha(payload),object_bytes=len(obj),object_sha256=sha(obj),
                metadata=actual,record_sha256=digest.hexdigest())
            require(wire==value["wire"]and record==expected,"original complete actual input/output bytes")
            response=expected_response(wire,actual,payload,obj);results[cid]=response
            if wire in desired:
                if wire in control_oracles:require(control_oracles[wire]==response,"same retained original control input")
                control_oracles[wire]=response
            offset+=size;count=number
        require(stream.read()==b""and count==len(records)==meta["cases"],"original complete record set")
    require(meta["raw"]==dict(bytes=offset,sha256=whole.hexdigest()),"whole original raw byte custody")
    return results,offset
def native_group(source,application,group,original,process_map,artifacts,image,control_oracles):
    folder,meta,records=capture_meta(source,application,"native",group,process_map)
    require(meta["artifacts"]==artifacts and meta["code_mapping_before_after"]==image["sha256"]
        and meta["actual_guard_bytes_retained"]is True and meta["original_results_read"]is False,
        "native complete admitted actual code mapping")
    control=group=="controls";values=cases.controls()if control else cases.cases(int(group))
    whole=hashlib.sha256();offset=0;count=0;success=0;invalid=0;workspace=0;capacity=0
    with gzip.open(owned(folder,"records.bin.gz"),"rb")as stream:
        for number,value in enumerate(values,1):
            require(number<=len(records),"missing native record");record=records[number-1]
            wire=value["wire"];oc=value["output_capacity"];wc=value["workspace_capacity"];ic=max(1,len(wire))+16
            header=take(stream,80);cid,code,insize,extent,outcap,workcap,ordinal,z0,z1,z2=struct.unpack("<10Q",header)
            require((cid,insize,extent,outcap,workcap,ordinal,z0,z1,z2)==
                (value["case_id"],len(wire),ic,oc,wc,number,0,0,0),"native complete record header")
            before_input=take(stream,ic);after_input=take(stream,ic);before_out=take(stream,oc+16);after_out=take(stream,oc+16)
            before_work=take(stream,wc+16);after_work=take(stream,wc+16);digest=hashlib.sha256();size=0
            for span in(header,before_input,after_input,before_out,after_out,before_work,after_work):
                digest.update(span);whole.update(span);size+=len(span)
            expected=dict(case_id=cid,label=value["label"],offset=offset,bytes=size,return_code=code,input_bytes=len(wire),
                input_sha256=sha(wire),output_capacity=oc,workspace_capacity=wc,record_sha256=digest.hexdigest(),
                before=[sha(before_input),sha(before_out),sha(before_work)],after=[sha(after_input),sha(after_out),sha(after_work)])
            require(record==expected,"native full retained record metadata")
            require(before_input==(wire or b"\0")+b"\xb6"*16 and after_input==before_input,
                "native actual input or input guard changed")
            require(before_out==bytes([value["output_fill"]])*oc+b"\xa5"*16
                and before_work==bytes([value["workspace_fill"]])*wc+b"\x5a"*16,"actual native buffer initialization")
            if len(wire)>cases.LIMIT:expected_code=0xffffffff
            elif wc<1024:expected_code=0xfffffffd
            else:
                response=control_oracles[wire]if control else original[cid]
                expected_code=0xfffffffe if oc<len(response)else len(response)
            require(code==expected_code,"native return differs from retained actual original")
            if code in(0xffffffff,0xfffffffd,0xfffffffe):
                require(after_out==before_out,"private refusal changed output or output guard")
                if code==0xffffffff:invalid+=1
                elif code==0xfffffffd:workspace+=1
                else:capacity+=1
            else:
                require(after_out==response+bytes([value["output_fill"]])*(oc-code)+b"\xa5"*16,
                    "native full response or output tail differs from actual original")
                success+=1
            if code in(0xffffffff,0xfffffffd):
                require(after_work==before_work,"unadmitted input or workspace changed complete workspace")
            else:
                require(after_work[1024:]==before_work[1024:],"native workspace tail or guard changed")
            offset+=size;count=number
        require(stream.read()==b""and count==len(records)==meta["cases"],"native complete record set")
    require(meta["raw"]==dict(bytes=offset,sha256=whole.hexdigest()),"whole native raw byte custody")
    return dict(calls=count,raw_bytes=offset,successes=success,input_refusals=invalid,workspace_refusals=workspace,capacity_refusals=capacity)
def verify(source,application,runtime,original_runtime,admission):
    source,application,runtime,original_runtime,admission=map(Path,(source,application,runtime,original_runtime,admission))
    identity=source_evidence(source);summary=decode(owned(application,"CAPTURE.json").read_bytes())
    origin=decode(owned(application,"ORIGIN.json").read_bytes());accepted=decode(admission.read_bytes())
    shard=summary["domain"]["shard"];domain=cases.shard_domain(shard);plan=cases.plan(shard)
    require(summary["status"]=="PASS"and summary["source"]==identity and summary["domain"]==domain
        and summary["new_original_calls"]==summary["native_semantic_calls"]==domain["semantic_cases"]
        and summary["private_native_calls"]==domain["private_native_calls"]and summary["application_replays"]==0
        and summary["current"]is None and summary["error"]is None and summary["completed_or_unknown_never_replayed"]is True,
        "complete never-replayed actual capture")
    rows=summary["processes"];returns=processes(application/"processes",rows,[(role+"-"+group,60)for role,group in plan])
    require(summary["planned_groups"]==len(plan)==len(summary["completed"])==len(rows),"every frozen actual process")
    for (role,group),row,finished in zip(plan,rows,summary["completed"]):
        command=[origin["python"],"-I","-S","-B",str(Path(origin["source"])/"scripts"/(role+"_capture.py")),
            "--group",group,"--output",str(Path(origin["capture"])/role/group)]
        command+=["--capture",origin["runtime"]]if role=="native"else["--runtime",origin["original_runtime"]]
        require(row["argv"]==command and row["cwd"]==origin["source"]and finished==dict(role=role,group=group,
            cases=returns[role+"-"+group]["cases"],process=role+"-"+group,capture=pin(application/role/group/"CAPTURE.json")),
            "exact bounded actual command and full result")
    artifacts,bundle=runtime_files(runtime);actual_runtime={p:dict(**pin(owned(runtime,p)),mode=owned(runtime,p).stat().st_mode&0o777)
        for p in set(artifacts)|{"build/module.json"}}
    require(actual_runtime==accepted["runtime"]and {p.relative_to(runtime).as_posix()for p in runtime.rglob("*")if p.is_file()}
        ==set(actual_runtime),"runtime exact admitted bytes and modes")
    require(bundle["image"]==decode(owned(source,"BUILD_INPUT.json").read_bytes())["image"],"single fixed decoder image")
    runtime_value=read_runtime.verify(source,original_runtime)
    require(accepted["source"]==identity and accepted["original_runtime"]==pin(owned(original_runtime,"RUNTIME.json")),
        "original runtime complete admission")
    process_map={r["name"]:r for r in rows};control_oracles={};original_bytes=0;native=[]
    for group in domain["groups"]:
        original,count=original_group(source,application,str(group["id"]),process_map,runtime_value,control_oracles)
        require(len(original)==group["cases"],"frozen original group case count");original_bytes+=count
        result=native_group(source,application,str(group["id"]),original,process_map,artifacts,bundle["image"],control_oracles)
        require(result["successes"]==group["cases"]and result["input_refusals"]==result["workspace_refusals"]
            ==result["capacity_refusals"]==0,"every semantic input returns full actual result")
        native.append(result)
    private=None
    if domain["private_native_calls"]:
        private=native_group(source,application,"controls",{},process_map,artifacts,bundle["image"],control_oracles)
        require(private["calls"]==domain["private_native_calls"],"all private capacity controls")
    files={"ORIGIN.json","CAPTURE.json","processes/processes.json"}
    for row in rows:files.update("processes/"+row[k]["file"]for k in("stdout","stderr"))
    for role,group in plan:files.update(role+"/"+group+"/"+name for name in("CAPTURE.json","records.json","records.bin.gz"))
    require({p.relative_to(application).as_posix()for p in application.rglob("*")if p.is_file()}==files,
        "complete actual capture file set")
    return dict(status="PYTHON_JSON_BYTES_ACTUAL_COMPLETE_PASS",source=identity,domain=domain,image=bundle["image"],
        original_calls=domain["semantic_cases"],native_semantic_calls=domain["semantic_cases"],private_native_calls=domain["private_native_calls"],
        actual_processes=len(rows),original_full_bytes=original_bytes,
        native_full_buffer_bytes=sum(r["raw_bytes"]for r in native)+(private["raw_bytes"]if private else 0),
        controls=private,application_replays=0,whole_runtime_replaced=False)
