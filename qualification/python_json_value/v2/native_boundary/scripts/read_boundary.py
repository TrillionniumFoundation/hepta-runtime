"""Compare C-boundary HIA outputs and full decoded trees with retained actual originals."""
from pathlib import Path
import gzip,hashlib,struct
from common import canonical,decode,owned,pin,require,sha,source_evidence
import cases,read_graph,original_input
from reuse import processes
from guard_refs import tree,saved_guard
MAGIC=int.from_bytes(b"HPYJSR01","little")
RECURSION={11:" while decoding a JSON array from a unicode string",12:" while decoding a JSON object from a unicode string",
    17:" while encoding a JSON object",19:" in comparison",20:" while calling a Python object",21:""}
JSON_ERRORS={1:"Expecting value",2:"Expecting property name enclosed in double quotes",3:"Expecting ':' delimiter",
    4:"Expecting ',' delimiter",5:"Unterminated string starting at",6:"Invalid control character at",
    7:"Invalid "+chr(92)+"escape",8:"Invalid "+chr(92)+"uXXXX escape",9:"Extra data"}
def take(stream,n):
    require(type(n)is int and n>=0,"ordinary complete profile span")
    raw=stream.read(n);require(len(raw)==n,"short boundary capture");return raw
def chain_observation(s,w,root):
    shape=bytearray();at=root
    while True:
        tag=read_graph.node(w,at)
        if tag not in(6,7)or read_graph.word(w,at+48)==0:break
        rows=read_graph.children(w,at);require(len(rows)==1,"complete original profile one-child shape")
        if tag==7:require(read_graph.string(w,read_graph.word(w,rows[0]+32))[0]==b"x\0\0\0","complete original profile key")
        shape.append(1 if tag==6 else 2);at=rows[0]
    tag=read_graph.node(w,at)
    if tag==0:kind,data="NoneType",None
    elif tag in(1,2):kind,data="bool","true"if tag==2 else"false"
    elif tag==3:kind,data="int",read_graph.integer(s,w,at).decode("ascii")
    elif tag==4:kind,data="float",read_graph.span(w,at+40,8).hex()
    elif tag==5:kind,data="str",read_graph.string(w,at)[0].hex()
    else:
        require(tag in(6,7)and read_graph.word(w,at+48)==0,"complete terminal empty native container")
        kind,data=("list"if tag==6 else"dict"),[]
    return struct.pack("<Q",len(shape))+shape+canonical(dict(type=kind,data=data))
def expected(case,meta,payload):
    if meta["status"]=="RAISED":
        message=meta["message"];kind=meta["exception_class"]
        require(payload==(kind+": "+message).encode(),"complete retained original error")
        if kind=="RecursionError":matches=[k for k,v in RECURSION.items()if message=="maximum recursion depth exceeded"+v]
        elif kind=="JSONDecodeError":matches=[k for k,v in JSON_ERRORS.items()if message.startswith(v+": line ")]
        else:require(kind=="ValueError"and message.startswith("Exceeds the limit (4300 digits)"),"actual original error family");matches=[10]
        require(len(matches)==1,"one actual original diagnostic kind")
        return struct.pack("<8Q",MAGIC,3,matches[0],0,0,0,2,len(payload))+payload
    mode=case["original"]["mode"];root_tag=7 if case["original"]["shape"]=="object"else 6
    require(meta["status"]=="RETURNED"and meta["exception_class"]is meta["message"]is None,"actual successful boundary result")
    if mode=="parse":
        require(meta["type"]==("dict"if root_tag==7 else"list")and meta["truth"]is True,"actual original root kind")
        raw=case["primary"].encode("utf-32-le","surrogatepass")
        return struct.pack("<8Q",MAGIC,0,root_tag,1,0,len(case["primary"]),1,len(raw))+raw
    if mode=="equal":
        require(meta["type"]=="bool"and payload==b"1"and meta["truth"]is True,"actual completed equality")
        return struct.pack("<8Q",MAGIC,2,2,1,0,0,0,0)
    require(meta["type"]=="str"and len(payload)==4*meta["length"],"complete actual encoded profile text")
    values=[cp[0]for cp in struct.iter_unpack("<I",payload)];require(all(cp<128 for cp in values),"complete ASCII encoder text")
    raw=bytes(values);return struct.pack("<8Q",MAGIC,1,root_tag,1,0,len(raw),2,len(raw))+raw
def retained_cases(source,profile_work,group):
    selected={r["original_id"]:r for r in cases.cases(group)}
    folder=profile_work/"original/restored/run/capture";rows=decode(owned(folder,"records.json").read_bytes())
    results={}
    with gzip.open(owned(folder,"records.bin.gz"),"rb")as stream:
        for row in rows:
            head=take(stream,80);cid,wi,pa,me,ordinal,bl,br,al,ar,zero=struct.unpack("<10Q",head)
            wire,payload,metadata,before_left,before_right,after_left,after_right=[take(stream,n)for n in(wi,pa,me,bl,br,al,ar)]
            if cid not in selected:continue
            case=selected[cid];meta=decode(metadata)
            require(wire==case["primary"].encode("utf-32-le","surrogatepass")and meta==row["metadata"],
                "selected input is the same completed original operation")
            require(before_left==after_left and before_right==after_right,"whole original operand stability")
            results[case["case_id"]]=dict(response=expected(case,meta,payload),metadata=meta,payload=payload,
                before_left=before_left,before_right=before_right,original_record=row)
        require(stream.read()==b""and len(results)==len(selected),"entire selected retained original set")
    return results
def runtime_files(runtime):
    bundle=decode(owned(runtime,"build/module.json").read_bytes());row=bundle["member"];path=owned(runtime,row["manifest"])
    metadata=decode(path.read_bytes());require(pin(path)["sha256"]==row["manifest_sha256"]
        and bundle["image"]["sha256"]==metadata["image_sha256"],"native boundary admitted image declaration")
    files={row["manifest"]:pin(path)}
    for name in("source","image"):
        member=owned(path.parent,metadata[name]);files[member.relative_to(runtime).as_posix()]=pin(member)
        require(pin(member)["sha256"]==metadata[name+"_sha256"],"native boundary complete source and image")
    return files,bundle
def verify(source,work,group):
    identity=source_evidence(source);domain=cases.domain(group)
    origin=decode(owned(work/"admission","ORIGIN.json").read_bytes());admission=decode(owned(work,"admission/ADMISSION.json").read_bytes())
    profile=original_input.verify(source,work/"profile-input",group);original=retained_cases(source,work/"profile-input",group)
    profile_guard=decode(owned(work/"admission","PROFILE_ADMISSION.json").read_bytes())
    require(profile_guard["evidence"]==profile,"complete original profile pure admission")
    references=saved_guard(profile_guard,{origin["source"]:tree(source),str(Path(origin["work"])/"profile-input"):tree(work/"profile-input")})
    runtime=work/"runtime";files,bundle=runtime_files(runtime)
    observed={p:dict(**pin(owned(runtime,p)),mode=owned(runtime,p).stat().st_mode&0o777)for p in set(files)|{"build/module.json"}}
    require(observed==admission["runtime"]and {p.relative_to(runtime).as_posix()for p in runtime.rglob("*")if p.is_file()}==set(observed)
        and bundle["image"]==decode(owned(source,"BUILD_INPUT.json").read_bytes())["image"],"complete admitted native runtime")
    require(admission["source"]==identity and admission["domain"]==domain
        and admission["profile_proof"]==pin(work/"admission/PROFILE_ADMISSION.json")
        and admission["build_proof"]==pin(work/"admission/BUILD_ADMISSION.json"),"whole boundary admission")
    process_rows=decode(owned(work/"admission","processes/processes.json").read_bytes())
    values=processes(work/"admission/processes",process_rows,[
        ("source-check",60),("build-fetch",60),("build-unpack",180),("build-read-build",180),
        ("profile-fetch",60),("profile-unpack",180),("profile-read",180),("native",60)])
    folder=work/"native";meta=decode(owned(folder,"CAPTURE.json").read_bytes());rows=decode(owned(folder,"records.json").read_bytes())
    require(meta["schema"]=="hepta.runtime.python-json-value.boundary-native.v1"and meta["status"]=="PASS"
        and meta["group"]==group and meta["source"]==identity and meta["artifacts"]==files
        and meta["code_mapping_before_after"]==bundle["image"]["sha256"]and meta["original_results_read"]is False
        and meta["actual_guard_bytes_retained"]is True and meta["application_replay"]is False
        and meta==values["native"]and meta["pid"]==process_rows[-1]["pid"],"one original-independent native worker")
    require(meta["compressed"]==pin(owned(folder,"records.bin.gz"))and meta["records"]==pin(owned(folder,"records.json")),
        "whole native boundary capture")
    command=[origin["python"],"-I","-S","-B",str(Path(origin["source"])/"scripts/native_capture.py"),"--group",group,
        "--capture",str(Path(origin["work"])/"runtime"),"--output",str(Path(origin["work"])/"native")]
    require(process_rows[-1]["argv"]==command and process_rows[-1]["cwd"]==origin["source"],"exact one actual native boundary command")
    require(values["profile-read"]==profile_guard,"actual complete profile admission stdout")
    offset=0;whole=hashlib.sha256();count=0;returned=raised=0
    with gzip.open(owned(folder,"records.bin.gz"),"rb")as stream:
        for number,case in enumerate(cases.cases(group),1):
            require(number<=len(rows),"missing boundary native row");row=rows[number-1]
            wire=case["wire"];oc=case["output_capacity"];wc=case["workspace_capacity"];ic=len(wire)+16
            head=take(stream,80);cid,code,insize,extent,outcap,workcap,ordinal,z0,z1,z2=struct.unpack("<10Q",head)
            require((cid,insize,extent,outcap,workcap,ordinal,z0,z1,z2)==(case["case_id"],len(wire),ic,oc,wc,number,0,0,0),
                "complete actual native boundary frame")
            bi,ai,bo,ao,bw,aw=[take(stream,n)for n in(ic,ic,oc+16,oc+16,wc+16,wc+16)]
            digest=hashlib.sha256();size=0
            for part in(head,bi,ai,bo,ao,bw,aw):digest.update(part);whole.update(part);size+=len(part)
            expected_row=dict(case_id=cid,label=case["label"],offset=offset,bytes=size,return_code=code,input_bytes=len(wire),
                input_sha256=sha(wire),output_capacity=oc,workspace_capacity=wc,record_sha256=digest.hexdigest(),
                before=[sha(bi),sha(bo),sha(bw)],after=[sha(ai),sha(ao),sha(aw)])
            require(row==expected_row and bi==wire+b"\xb6"*16 and ai==bi,"all boundary actual input and guard bytes")
            require(bo==bytes([case["output_fill"]])*oc+b"\xa5"*16 and bw==bytes([case["workspace_fill"]])*wc+b"\x5a"*16,
                "complete original native boundary buffer initialization")
            oracle=original[cid];response=oracle["response"]
            require(code==len(response)and ao==response+bo[code:]and aw[wc:]==bw[wc:],"exact original/native boundary result and guards")
            mode=case["original"]["mode"];meta_original=oracle["metadata"];w=aw[:wc]
            if mode=="parse"and meta_original["status"]=="RETURNED":
                require(chain_observation(wire,w,16384)==oracle["payload"],"all native decoded tree bytes equal actual original")
            if mode in("dump","equal"):
                require(chain_observation(wire,w,16384)==oracle["before_left"],"complete native primary operand")
                if mode=="equal":
                    root=read_graph.auxiliary_root(wire,w,case["primary"],case["auxiliary"])
                    require(chain_observation(wire,w,root)==oracle["before_right"],"complete native auxiliary operand")
            if meta_original["status"]=="RETURNED":returned+=1
            else:raised+=1
            offset+=size;count=number
        require(stream.read()==b""and count==len(rows)==meta["cases"]==domain["native_calls"],"complete frozen native boundary call set")
    require(meta["raw"]==dict(bytes=offset,sha256=whole.hexdigest()),"whole native C-depth raw stream")
    return dict(status="COMPLETE_PYTHON_JSON_VALUE_C_BOUNDARY_PASS",group=group,source=identity,domain=domain,image=bundle["image"],
        retained_original_profile=profile,original_records_read=profile["profile"]["profile"]["actual_calls"],
        native_calls=count,returned=returned,raised=raised,full_native_buffer_bytes=offset,
        saved_profile_guard_file_references=references,new_original_calls=0,application_replays=0)
