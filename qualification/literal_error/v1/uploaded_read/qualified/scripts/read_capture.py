"""Full original/native formatter frames and tails; no application or compiler execution."""
from pathlib import Path
import gzip,hashlib,struct
from common import canonical,decode,owned,pin,require,sha,source_evidence
import cases
from reuse import processes
def take(stream,size):
    raw=stream.read(size);require(len(raw)==size,"short full-buffer record");return raw
def capture_meta(source,capture,side,group,processes,expected_source=None):
    folder=capture/side/group;meta=decode(owned(folder,"CAPTURE.json").read_bytes())
    require(meta["status"]=="PASS"and meta["group"]==group and meta["source"]==(expected_source or source_evidence(source)),
        "capture identity differs: "+side+"/"+group)
    require(meta["compressed"]==pin(owned(folder,"records.bin.gz"))and
        meta["records"]==pin(owned(folder,"records.json")),"capture full retained stream differs")
    pname=side+"-"+group
    require(decode(owned(capture,"processes/"+pname+".stdout").read_bytes())==meta
        and meta["pid"]==processes[pname]["pid"],"capture does not match actual process stdout")
    if side=="original":
        require(meta["hia_executed"]is False and meta["native_result_read"]is False
            and meta["environment"]["unicode_version"]=="15.0.0"and meta["environment"]["lc_messages"]=="C"
            and meta["environment"]["platform"]=="linux","original environment or provenance differs")
    else:
        require(meta["original_result_read"]is False and meta["semantic_replay"]is False,"native provenance changed")
    return folder,meta,decode(owned(folder,"records.json").read_bytes())
def original_group(source,capture,group,processes,expected_source=None):
    folder,meta,records=capture_meta(source,capture,"original",group,processes,expected_source)
    values=list(cases.cases(group));require(len(records)==meta["cases"]==len(values),"original case count")
    digest=hashlib.sha256();offset=0;results={}
    with gzip.open(owned(folder,"records.bin.gz"),"rb")as stream:
        for value,record in zip(values,records):
            wire=cases.frame(value);header=take(stream,24);cid,in_size,out_size=struct.unpack("<3Q",header)
            require(cid==value["case_id"]and in_size==len(wire)and out_size==record["response_bytes"],
                "original complete frame header")
            actual_input=take(stream,in_size);response=take(stream,out_size);block=header+actual_input+response
            require(actual_input==wire and record["offset"]==offset and record["bytes"]==len(block)
                and record["record_sha256"]==sha(block)and record["response_sha256"]==sha(response),
                "original exact request/result bytes")
            require({k:record[k]for k in cases.public_row(value)}==cases.public_row(value),"original frozen case identity")
            require(response.startswith(record["actual_exception_class"].encode()+b": "),"original actual exception class")
            response.decode("utf-8")
            if value["kind"]in(15,16,17)and value["errno"]==0 and value.get("protocol")is None:
                require(record["actual_exception_class"]==cases.CLASSES[value["kind"]-1]
                    and response==cases.CLASSES[value["kind"]-1].encode()+b": "+value["payload"],
                    "complete actual literal class and unmodified Unicode message")
            results[cid]=response;digest.update(block);offset+=len(block)
        require(stream.read()==b"","trailing original bytes")
    require(meta["raw"]==dict(bytes=offset,sha256=digest.hexdigest()),"complete original raw custody")
    return results,offset
def native_group(source,capture,group,original,processes,artifacts,data):
    folder,meta,records=capture_meta(source,capture,"native",group,processes)
    require(meta["artifacts"]==artifacts,"actual admitted native image/source differs")
    control=group=="controls";values=cases.controls()if control else list(cases.cases(group))
    require(len(records)==meta["cases"]==len(values),"native case count")
    digest=hashlib.sha256();offset=0;previous=None;success=0;invalid=0;capacity=0
    with gzip.open(owned(folder,"records.bin.gz"),"rb")as stream:
        for index,(value,record)in enumerate(zip(values,records),1):
            wire=value["wire"]if control else cases.frame(value)
            outcap=value["output_capacity"]if control else cases.capacity(value)
            workcap=value["workspace_capacity"]if control else cases.WORK+31
            before=previous if control and value.get("reuse")else b"\x7b"*workcap
            old=b"\xa5"*outcap
            header=take(stream,64);cid,code,insize,oc,wc,number,z0,z1=struct.unpack("<8Q",header)
            require((cid,insize,oc,wc,number,z0,z1)==(value["case_id"],len(wire),outcap,workcap,index,0,0),
                "native complete frame header")
            actual_input=take(stream,insize);actual_before=take(stream,wc);actual_old=take(stream,oc)
            output=take(stream,oc);after=take(stream,wc)
            spans=(header,actual_input,actual_before,actual_old,output,after)
            record_hash=hashlib.sha256();size=0
            for raw in spans:record_hash.update(raw);digest.update(raw);size+=len(raw)
            expected=dict(case_id=cid,label=value["label"],offset=offset,bytes=size,return_code=code,
                input_bytes=len(wire),input_sha256=sha(wire),output_capacity=outcap,workspace_capacity=workcap,
                before_sha256=sha(before),output_before_sha256=sha(old),output_sha256=sha(output),
                after_sha256=sha(after),record_sha256=record_hash.hexdigest())
            require(record==expected and actual_input==wire and actual_before==before and actual_old==old,
                "native all raw input/output/workspace bytes")
            if control:
                require(code==value["expected"],"native frozen boundary result: "+value["label"])
                installed=value["mutation"]=="installed"
                if code not in(cases.INVALID,cases.CAPACITY):
                    expected_output=(original[value["reference_case_id"]]if "reference_case_id"in value else
                        cases.CLASSES[value["reference_class"]-1].encode()+b": "+bytes.fromhex(value["message_hex"]))
                    require(code==len(expected_output)==value["required"],"literal boundary extent")
            else:
                expected_output=original[cid];require(code==len(expected_output),"native return differs from actual original")
                installed=True
            if code in(cases.INVALID,cases.CAPACITY):
                require(output==old,"rejected input/capacity changed complete output")
                if code==cases.INVALID:invalid+=1
                else:capacity+=1
            else:
                require(0<=code<=outcap and output==expected_output+b"\xa5"*(outcap-code),
                    "complete native diagnostic differs from actual original or output tail")
                success+=1
            if installed:
                size_data=data["data_bytes"]
                require(len(after)>=data["workspace_required"]and sha(after[:size_data])==data["data_sha256"]
                    and after[size_data:]==before[size_data:],"immutable formatter data/workspace tail differs")
            else:require(after==before,"rejected input/capacity changed complete workspace")
            previous=after;offset+=size
        require(stream.read()==b"","trailing native full-buffer bytes")
    require(meta["raw"]==dict(bytes=offset,sha256=digest.hexdigest()),"complete native raw custody")
    return dict(calls=len(values),raw_bytes=offset,successes=success,invalid=invalid,capacity=capacity)

def runtime_files(runtime):
    bundle=decode(owned(runtime,"build/formatter.json").read_bytes());row=bundle["member"]
    path=owned(runtime,row["manifest"]);metadata=decode(path.read_bytes())
    require(pin(path)["sha256"]==row["manifest_sha256"]and bundle["image"]["sha256"]==metadata["image_sha256"],
        "fixed runtime manifest and image declaration")
    artifacts={row["manifest"]:pin(path)}
    for name in("source","image"):
        member=owned(path.parent,metadata[name]);artifacts[member.relative_to(runtime).as_posix()]=pin(member)
        require(pin(member)["sha256"]==metadata[name+"_sha256"],"runtime complete source and image")
    return artifacts,bundle
def verify(source,application,runtime,legacy_capture,legacy_identity,admitted_runtime):
    source,application,runtime,legacy_capture=map(Path,(source,application,runtime,legacy_capture))
    identity=source_evidence(source);domain=cases.validate();origin=decode(owned(application,"ORIGIN.json").read_bytes())
    summary=decode(owned(application,"CAPTURE.json").read_bytes())
    require(summary["status"]=="PASS"and summary["source"]==identity and summary["domain"]==domain
        and summary["new_original_calls"]==435 and summary["native_semantic_calls"]==22336
        and summary["private_native_calls"]==1255 and summary["legacy_original_applications"]==0
        and summary["application_replays"]==0 and summary["current"]is None and summary["error"]is None
        and summary["completed_or_unknown_never_replayed"]is True,"complete never-replayed candidate capture")
    plan=[("original",g["name"])for g in cases.domain()["new_groups"]]
    plan+=[("native",g["name"])for g in cases.groups()]+[("native","controls")]
    rows=summary["processes"];returns=processes(application/"processes",rows,[(r+"-"+g,60)for r,g in plan])
    require(summary["planned_groups"]==len(plan)==len(summary["completed"])==len(rows)==285,
        "every declared actual process is present")
    for (role,group),row,finished in zip(plan,rows,summary["completed"]):
        expected=[origin["python"],"-I","-S","-B",str(Path(origin["source"])/"scripts"/(role+"_capture.py")),
            "--group",group,"--output",str(Path(origin["capture"])/role/group)]
        if role=="native":expected+=["--capture",origin["runtime"]]
        require(row["argv"]==expected and row["cwd"]==origin["source"]and finished==dict(role=role,group=group,
            cases=returns[role+"-"+group]["cases"],process=role+"-"+group,capture=pin(application/role/group/"CAPTURE.json")),
            "exact one bounded actual command and complete output binding")
    process_map={r["name"]:r for r in rows}
    old_processes=decode(owned(legacy_capture,"processes/processes.json").read_bytes())
    old_map={r["name"]:r for r in old_processes}
    artifacts,bundle=runtime_files(runtime)
    require(admitted_runtime=={p:dict(**pin(owned(runtime,p)),mode=owned(runtime,p).stat().st_mode&0o777)
        for p in admitted_runtime},"runtime exact admitted bytes and modes")
    require({p.relative_to(runtime).as_posix()for p in runtime.rglob("*")if p.is_file()}==set(admitted_runtime)
        and set(admitted_runtime)==set(artifacts)|{"build/formatter.json"},"complete sole runtime file set")
    require(bundle["image"]==dict(bytes=312298,sha256="531c65b74394565a9c2a8ba70f9daa0d466f9c0cb2567525d4397593b6c80943"),
        "single fixed qualified new formatter image")
    data=decode(owned(source,"trusted-build/native/platform_data.json").read_bytes())
    all_original={};native=[];old_bytes=0;new_bytes=0
    for group in cases.domain()["new_groups"]+cases.legacy.domain()["groups"]:
        name=group["name"];fresh=name in cases.new_names()
        results,count=original_group(source,application if fresh else legacy_capture,name,
            process_map if fresh else old_map,None if fresh else legacy_identity)
        if fresh:new_bytes+=count
        else:old_bytes+=count
        require(not(set(all_original)&set(results)),"unique complete original case IDs")
        all_original.update(results)
        result=native_group(source,application,name,results,process_map,artifacts,data)
        require(result["invalid"]==result["capacity"]==0,"accepted semantic input was rejected")
        native.append(result)
    controls=native_group(source,application,"controls",all_original,process_map,artifacts,data)
    require(len(all_original)==22336 and controls["calls"]==1255
        and {k:controls[k]for k in("invalid","capacity")}=={k:domain["control_counts"][k]for k in("invalid","capacity")}
        and controls["successes"]==domain["control_counts"]["success"],"complete semantic and private control totals")
    expected_files={"ORIGIN.json","CAPTURE.json","processes/processes.json"}
    for row in rows:
        expected_files.update("processes/"+row[s]["file"]for s in("stdout","stderr"))
    for role,group in plan:
        expected_files.update(role+"/"+group+"/"+name for name in("CAPTURE.json","records.json","records.bin.gz"))
    require({p.relative_to(application).as_posix()for p in application.rglob("*")if p.is_file()}==expected_files,
        "complete actual capture file set")
    return dict(status="LITERAL_ERROR_ACTUAL_COMPLETE_PASS",source=identity,domain=domain,
        reused_original_cases=21901,new_original_cases=435,new_native_cases=22336,private_native_calls=1255,
        total_new_native_calls=23591,controls=controls,actual_processes=285,
        native_full_buffer_bytes=sum(r["raw_bytes"]for r in native)+controls["raw_bytes"],
        reused_original_full_bytes=old_bytes,new_original_full_bytes=new_bytes,
        image=bundle["image"],whole_runtime_replaced=False,application_replays=0)
