"""Compare whole original values/errors with complete actual native buffers."""
from pathlib import Path
import gzip,hashlib,struct
from common import canonical,decode,owned,pin,require,sha,source_evidence
from reuse import processes
import cases,read_runtime,read_graph
MAGIC=int.from_bytes(b"HPYJSR01","little")
JSON_ERRORS={1:"Expecting value",2:"Expecting property name enclosed in double quotes",3:"Expecting ':' delimiter",
    4:"Expecting ',' delimiter",5:"Unterminated string starting at",6:"Invalid control character at",
    7:"Invalid "+chr(92)+"escape",8:"Invalid "+chr(92)+"uXXXX escape",9:"Extra data"}
RECURSION={11:" while decoding a JSON array from a unicode string",12:" while decoding a JSON object from a unicode string",
    17:" while encoding a JSON object",19:" in comparison",20:" while calling a Python object",21:""}
def take(stream,size):
    require(type(size)is int and size>=0,"invalid retained span extent")
    raw=stream.read(size);require(len(raw)==size,"short complete actual value record");return raw
def expected_response(case,meta,payload,after_left):
    command=case["command"]
    if meta["status"]=="RAISED":
        kind=meta["exception_class"];message=meta["message"]
        require(payload==(kind+": "+message).encode("utf-8"),"complete original exception text")
        if kind=="JSONDecodeError":
            matches=[k for k,v in JSON_ERRORS.items()if message.startswith(v+": line ")]
            require(len(matches)==1,"actual JSON decoder error family");tag=matches[0]
        elif kind=="RecursionError":
            matches=[k for k,v in RECURSION.items()if message=="maximum recursion depth exceeded"+v]
            require(len(matches)==1,"actual recursion exception family");tag=matches[0]
        elif kind=="ValueError":
            require(message.startswith("Exceeds the limit (4300 digits)"),"actual integer digit limit");tag=10
        elif kind=="KeyError":require(command==2,"actual strict subscript error");tag=13
        elif kind=="TypeError":require(command==2,"actual non-dict subscript error");tag=14
        else:
            require(kind=="AttributeError"and command==1,"actual method attribute error");tag=22
        return struct.pack("<8Q",MAGIC,3,tag,0,0,0,2,len(payload))+payload
    require(meta["status"]=="RETURNED"and meta["exception_class"]is meta["message"]is None,
        "actual returned object items")
    require(meta["tag"]==7 and type(case["item_spans"])is list and meta["count"]==len(case["item_spans"])
        and meta["truth"]==bool(meta["count"]),"actual complete dictionary cardinality")
    at=0;parts=[]
    for key,raw_value in case["item_spans"]:
        require(at+48<=len(payload),"complete original item scalar header")
        cp,tag,truth,count,size,zero=struct.unpack_from("<6Q",payload,at);at+=48
        require(zero==0 and truth in(0,1)and tag<=7 and cp==len(key),"actual original item identity")
        require(at+cp*4+size<=len(payload),"complete original key and scalar extent")
        key_raw=payload[at:at+cp*4];at+=cp*4;value=payload[at:at+size];at+=size
        require(key_raw==key.encode("utf-32-le","surrogatepass"),"actual original key order and decoded bytes")
        bits=0;encoding=0;units=0;raw=raw_value.encode("utf-32-le","surrogatepass")
        if tag==3:
            require(count==len(value)and value and all(x in b"-0123456789"for x in value),"complete actual integer")
            units=len(value);encoding=2
        elif tag==4:
            require(count==8 and len(value)==8,"complete actual binary64")
            bits=struct.unpack("<Q",value)[0];value=b""
        elif tag==5:
            require(len(value)==count*4,"complete actual Unicode value");units=count;encoding=1
        elif tag in(6,7):
            require(value==b""and raw_value[0]in"[{","complete actual container original span")
            value=raw;units=len(raw_value);encoding=1
        else:require(value==b""and count==0,"actual singleton item")
        record=struct.pack("<8Q",MAGIC,0,tag,truth,bits,units,encoding,len(value))+value
        parts.extend((struct.pack("<4Q",cp,len(record),len(raw_value),0),key_raw,record,raw))
    require(at==len(payload),"complete original item set without trailing bytes")
    body=b"".join(parts)
    return struct.pack("<8Q",int.from_bytes(b"HPYJIR01","little"),0,7,int(meta["truth"]),0,meta["count"],0,len(body))+body

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
def capture_meta(source,application,role,group,process_map):
    folder=application/role/group;meta=decode(owned(folder,"CAPTURE.json").read_bytes())
    require(meta["schema"]=="hepta.runtime.python-json-items."+role+".v2"and meta["status"]=="PASS"
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
    require(meta["runtime"]==runtime_value and meta["complete_actual_operands"]is True,"actual original runtime and whole operands")
    whole=hashlib.sha256();offset=0;results={};count=0
    with gzip.open(owned(folder,"records.bin.gz"),"rb")as stream:
        for number,case in enumerate(cases.cases(int(group)),1):
            require(number<=len(records),"missing original record");row=records[number-1]
            header=take(stream,80);cid,wi,pa,me,ordinal,bl,br,al,ar,zero=struct.unpack("<10Q",header)
            require((cid,wi,ordinal,zero)==(case["case_id"],len(case["wire"]),number,0)and me<=8192,"whole original value frame")
            wire,payload,metadata,before_left,before_right,after_left,after_right=[take(stream,n)for n in(wi,pa,me,bl,br,al,ar)]
            actual=decode(metadata);require(metadata==canonical(actual),"canonical full original metadata")
            digest=hashlib.sha256();size=0
            for part in(header,wire,payload,metadata,before_left,before_right,after_left,after_right):
                digest.update(part);whole.update(part);size+=len(part)
            expected=dict(case_id=cid,label=case["label"],offset=offset,bytes=size,input_bytes=len(wire),input_sha256=sha(wire),
                payload_bytes=len(payload),payload_sha256=sha(payload),metadata=actual,
                observed_before=[sha(before_left),sha(before_right)],observed_after=[sha(after_left),sha(after_right)],
                record_sha256=digest.hexdigest())
            require(row==expected and wire==case["wire"],"all actual original input/value/error/tree bytes")
            command=case["command"]
            if before_left and command!=4:require(before_left==after_left,"original immutable primary value")
            require(before_right==after_right,"original immutable auxiliary value")
            counts=dict(loads=1,items=int(bool(before_left)))
            require(actual["operations"]==counts,"exact original command operation custody")
            response=expected_response(case,actual,payload,after_left)
            results[cid]=dict(response=response,after_left=after_left,after_right=after_right,metadata=actual,payload=payload)
            if cid==0:control_oracles[0]=results[cid]
            offset+=size;count=number
        require(stream.read()==b""and count==len(records)==meta["cases"],"entire original record set")
    require(meta["raw"]==dict(bytes=offset,sha256=whole.hexdigest()),"whole original uncompressed stream")
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
            oracle=control_oracles.get(value.get("oracle"))if control else original[cid]
            response=oracle["response"]if oracle else None
            expected_code=value["expected_code"]if control else len(response)
            require(code==expected_code,"native return differs from retained actual original")
            if code in(0xffffffff,0xfffffffd,0xfffffffe):
                require(after_out==before_out,"private refusal changed output or output guard")
                if code==0xffffffff:invalid+=1
                elif code==0xfffffffd:workspace+=1
                else:capacity+=1
            else:
                require(response is not None and after_out==response+bytes([value["output_fill"]])*(oc-code)+b"\xa5"*16,
                    "native full response or output tail differs from actual original")
                success+=1
            require(after_work[wc:]==before_work[wc:],"native workspace tail or guard changed")
            if control and value["workspace_unchanged"]:
                require(after_work==before_work,"unadmitted input or workspace changed complete workspace")
            if not control:
                work=after_work[:wc]
                if oracle["after_left"]:
                    require(read_graph.observe(wire,work,16384)==oracle["after_left"],"native complete primary tree differs from actual original")
                if oracle["after_right"]and value["command"]==5:
                    root=read_graph.auxiliary_root(wire,work,value["primary"],value["auxiliary"])
                    require(read_graph.observe(wire,work,root)==oracle["after_right"],"native complete auxiliary tree differs from actual original")
                meta_result=oracle["metadata"]
                if meta_result["status"]=="RETURNED"and value["command"]in(2,6)and meta_result["tag"]in(6,7):
                    root=read_graph.selected_root(work,16384,value["auxiliary"])
                    require(root is not None and read_graph.observe(wire,work,root)==oracle["payload"],
                        "native selected complete tree differs from actual original")
            offset+=size;count=number
        require(stream.read()==b""and count==len(records)==meta["cases"],"native complete record set")
    require(meta["raw"]==dict(bytes=offset,sha256=whole.hexdigest()),"whole native raw byte custody")
    return dict(calls=count,raw_bytes=offset,successes=success,input_refusals=invalid,workspace_refusals=workspace,capacity_refusals=capacity)
def verify(source,application,runtime,original_runtime,admission):
    source,application,runtime,original_runtime,admission=map(Path,(source,application,runtime,original_runtime,admission))
    identity=source_evidence(source);summary=decode(owned(application,"CAPTURE.json").read_bytes())
    origin=decode(owned(application,"ORIGIN.json").read_bytes());accepted=decode(admission.read_bytes())
    shard=summary["domain"]["shard"];domain=cases.shard_domain(shard);plan=cases.plan(shard)
    require(shard==0 and summary["status"]=="FAIL"and summary["source"]==identity and summary["domain"]==domain
        and summary["current"]==dict(role="native",group="controls")and summary["error"]["type"]=="ValueError"
        and summary["error"]["message"]=="complete frozen actual group"and summary["error"]["unknown_group"]is None
        and summary["application_replays"]==0 and summary["completed_or_unknown_never_replayed"]is True,
        "retained failed control-count orchestration without replay")
    original_driver=owned(source,"scripts/capture.py").read_bytes()
    require(b'count=30 if group=="controls"'in original_driver and domain["private_native_calls"]==25,
        "exact retained count mismatch cause")
    rows=summary["processes"];returns=processes(application/"processes",rows,[(role+"-"+group,60)for role,group in plan])
    require(summary["planned_groups"]==len(plan)==len(rows)==3 and len(summary["completed"])==2,
        "all three actual workers finished before obsolete control count rejection")
    for index,((role,group),row)in enumerate(zip(plan,rows)):
        command=[origin["python"],"-I","-S","-B",str(Path(origin["source"])/"scripts"/(role+"_capture.py")),
            "--group",group,"--output",str(Path(origin["capture"])/role/group)]
        command+=["--capture",origin["runtime"]]if role=="native"else["--runtime",origin["original_runtime"]]
        finished=dict(role=role,group=group,cases=returns[role+"-"+group]["cases"],process=role+"-"+group,
            capture=pin(application/role/group/"CAPTURE.json"))
        require(row["argv"]==command and row["cwd"]==origin["source"],"exact bounded actual command and full result")
        if index<2:require(summary["completed"][index]==finished,"both recorded semantic completions")
        else:require((role,group)==("native","controls")and finished["cases"]==25,
            "complete actual 25 controls are not the stale expected30")
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
    return dict(status="PYTHON_JSON_ITEMS_ACTUAL_COMPLETE_PASS",source=identity,domain=domain,image=bundle["image"],
        original_calls=domain["semantic_cases"],native_semantic_calls=domain["semantic_cases"],private_native_calls=domain["private_native_calls"],
        actual_processes=len(rows),original_full_bytes=original_bytes,
        native_full_buffer_bytes=sum(r["raw_bytes"]for r in native)+(private["raw_bytes"]if private else 0),
        controls=private,application_replays=0,whole_runtime_replaced=False)
