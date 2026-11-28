"""Full retained producer/process/guard/control verification, without any application replay."""
from pathlib import Path
import gzip,hashlib
from evidence_common import decode,encoded,owned,pin,require
from read_build_evidence import tree,saved_guard
import read_build_evidence,read_utf8
NAMES=("native-buffer","original-case","native-stdout","native-stdin","native-image",
    "source-manifest","honest-native-packet","honest-original-result")
def argument(row,name):
    return row["argv"][row["argv"].index("--"+name)+1]
def copied_tree(value):
    return (dict(value[0]),dict(value[1]))
def rawpin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def retired(row,trees):
    require(set(row)==set(trees),"all retired duplicate roots")
    for name,value in row.items():
        files,dirs=trees[name]
        require(value==dict(files=len(files),bytes=sum(p.stat().st_size for p,_ in files.values()),
            directories=len(dirs),all_bytes_and_modes_compared=True),"full verified retirement extent")
def changed_bytes(name,changes,before):
    if name.startswith("honest-"):
        require(len(changes)==2 and changes[0]["path"].endswith("/cases.jsonl.gz")
            and changes[1]["path"].endswith("/CAPTURE.json"),"both honestly resealed files")
        values=[decode(row) for row in gzip.decompress(before[0]).splitlines()]
        if name=="honest-native-packet":values[0]["packet"]=values[1]["packet"]
        elif values[0]["result"]["kind"]=="valid":values[0]["result"]["codepoints"]+=1
        else:
            value=values[0]["result"];value["message"]+=" altered"
            value["diagnostic"]="UnicodeDecodeError: "+value["message"]
        lines=[encoded(v) for v in values];raw=b"".join(lines)
        compressed=gzip.compress(raw,compresslevel=1,mtime=0)
        report=decode(before[1]);report["case_stream"]=dict(raw=rawpin(raw),compressed=rawpin(compressed),
            line_sha256=[hashlib.sha256(line).hexdigest() for line in lines])
        return [compressed,encoded(report)]
    require(len(changes)==1,"one actual physical file mutation")
    raw=before[0]
    if name=="native-buffer":
        value=gzip.decompress(raw);require(value,"nonempty native mutation buffer")
        return [gzip.compress(bytes([value[0]^1])+value[1:],compresslevel=1,mtime=0)]
    if name=="source-manifest":return [raw+b"\nACTUAL_BAD_SOURCE\n"]
    require(raw,"nonempty actual physical mutation");return [bytes([raw[0]^1])+raw[1:]]
def controls(source,data,capture,baseline):
    root=capture/"controls";result=decode(owned(root,"RESULT.json").read_bytes())
    require(result["status"]=="EIGHT_PHYSICAL_REFUSALS_TWO_FULL_RELOCATIONS_PASS"
        and result["group"]==baseline["group"] and result["application_executions"]==0
        and result["guard_probes"]==110 and [r["name"] for r in result["physical"]]==list(NAMES)
        and [r["name"] for r in result["relocations"]]==["relocation-1","relocation-2"]
        and result["baseline"]==pin(capture/"READONLY.json"),"all exact physical controls")
    source_tree=tree(source);data_tree=tree(data);bound=0;expected_files={"RESULT.json"}
    failure_messages={"native-buffer":("complete block bytes changed",),"original-case":("complete case archive identity",),
        "native-stdout":("complete stdout compressed identity",),"native-stdin":("complete native stdin identity",),
        "native-image":("retained native ELF bytes",),"source-manifest":("Extra data",),
        "honest-native-packet":("actual native input-only packet",),
        "honest-original-result":("actual original decoded value","actual native complete diagnostic equals original")}
    expected_paths={
        "native-buffer":"native/buffers/"+sorted((data/"native/buffers").iterdir())[0].name,
        "original-case":"original/cases.jsonl.gz","native-stdout":"native/carrier.stdout.gz",
        "native-stdin":"native/carrier.stdin","native-image":"production/multi-read-body-callable.elf",
        "source-manifest":"SOURCE_MANIFEST.json","honest-native-packet":"native/cases.jsonl.gz",
        "honest-original-result":"original/cases.jsonl.gz"}
    for row in result["physical"]:
        name=row["name"];folder=root/name;changes=row["changes"]
        require(decode(owned(folder,"CONTROL.json").read_bytes())==row
            and pin(owned(folder,"READONLY.json"))==row["guard"] and row["guard_probes"]==11
            and row["honestly_resealed"]==name.startswith("honest-"),"saved physical control record")
        require(changes[0]["path"]==expected_paths[name]
            and all(c["root"]==("source" if name=="source-manifest" else "data") for c in changes),
            "exact targeted physical file")
        st=copied_tree(source_tree);dt=copied_tree(data_tree);before=[];after=[]
        for index,change in enumerate(changes):
            require(change["before_file"]=="change-"+str(index)+".before"
                and change["after_file"]=="change-"+str(index)+".after","complete mutation file identities")
            original=(source if change["root"]=="source" else data)/change["path"]
            previous=owned(folder,change["before_file"]);mutated=owned(folder,change["after_file"])
            a,b=previous.read_bytes(),mutated.read_bytes();before.append(a);after.append(b)
            require(a==original.read_bytes() and a!=b and pin(previous)=={k:change["before"][k] for k in ("bytes","sha256")}
                and pin(mutated)=={k:change["after"][k] for k in ("bytes","sha256")}
                and change["before"]["mode"]==change["after"]["mode"]==original.stat().st_mode&0o777,
                "all real before/after mutation bytes and modes")
            (st if change["root"]=="source" else dt)[0][change["path"]]=(mutated,change["after"]["mode"])
            expected_files|={name+"/"+change["before_file"],name+"/"+change["after_file"]}
        require(after==changed_bytes(name,changes,before),"exact honestly resealed physical mutations")
        guard=decode((folder/"READONLY.json").read_bytes())
        require(row["evidence"]==guard["evidence"] and row["evidence"]["status"]=="REJECTED"
            and any(t in row["evidence"]["message"] for t in failure_messages[name]),"actual targeted physical refusal")
        require(set(row["roots"])=={"source","data"},"exact physical guard roots")
        mapping={row["roots"]["source"]:st,row["roots"]["data"]:dt}
        bound+=saved_guard(guard,mapping)
        retired(row["retired"],{"data":data_tree,**({"source":source_tree} if name=="source-manifest" else {})})
        expected_files|={name+"/CONTROL.json",name+"/READONLY.json"}
    for row in result["relocations"]:
        folder=root/row["name"]
        require(decode(owned(folder,"CONTROL.json").read_bytes())==row
            and pin(owned(folder,"READONLY.json"))==row["guard"] and row["guard_probes"]==11
            and row["evidence"]==baseline and set(row["roots"])=={"source","data"},"actual full relocation record")
        guard=decode((folder/"READONLY.json").read_bytes())
        require(guard["evidence"]==baseline,"actual complete relocated evidence")
        bound+=saved_guard(guard,{row["roots"]["source"]:source_tree,row["roots"]["data"]:data_tree})
        retired(row["retired"],dict(source=source_tree,data=data_tree))
        expected_files|={row["name"]+"/CONTROL.json",row["name"]+"/READONLY.json"}
    require({p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()}==expected_files,
        "complete retained physical-control file set")
    return result,bound
def verify(source,capture,reuse):
    source,capture,reuse=Path(source),Path(capture),Path(reuse)
    gate=decode(owned(capture,"GATE.json").read_bytes());group=gate["group"]
    require(gate["status"]=="PASS" and gate["compiled_build_reused"] is True
        and gate["compiler_or_rust_executions"]==0 and gate["whole_runtime_replaced"] is False
        and gate["upstream_archive_excluded_from_duplicate_semantic_archive"] is True,
        "actual captured qualification gate")
    rows=decode(owned(capture,"processes/processes.json").read_bytes())
    require(rows==gate["processes"] and [r["name"] for r in rows]==
        ["source-check","build-fetch","build-unpack","build-admission","capture-original","capture-native","full-read","physical-controls"],
        "all actual producer processes")
    returned={};expected_process_files={"processes.json"}
    for row,limit in zip(rows,(60,60,180,180,180,180,180,180)):
        require(row["pid"]==row["pgid"] and row["pid"]>0 and row["parent_pid"]>0 and row["exit_code"]==0
            and row["timed_out"] is False and row["completed"] is True and row["timeout_seconds"]==limit
            and 0<=row["elapsed_seconds"]<limit and row["stdin"] is None,"actual natural bounded producer")
        for suffix in ("stdout","stderr"):
            part=row[suffix];name=row["name"]+"."+suffix
            require(part["file"]==name and pin(owned(capture,"processes/"+name))=={k:part[k] for k in ("bytes","sha256")},
                "full producer process streams")
            expected_process_files.add(name)
        require(row["stderr"]["bytes"]==0,"no hidden actual producer stderr")
        returned[row["name"]]=decode((capture/"processes"/row["stdout"]["file"]).read_bytes())
    require({p.name for p in (capture/"processes").iterdir()}==expected_process_files,"complete producer stream set")
    data=capture/"application";actual=read_utf8.verify(source,data,group)
    require(gate["original_native"]==actual and gate["source"]==actual["source"],"complete original/native current pure read")
    domain=decode(owned(capture,"INPUT_DOMAIN.json").read_bytes())
    require(returned["source-check"]==domain and domain["status"]=="MULTI_UTF8_SOURCE_AND_INPUT_ONLY_PASS"
        and domain["source"]==actual["source"] and domain["original_inputs"]==76414 and domain["native_inputs"]==76662
        and domain["private_controls"]==248 and domain["original_decode_calls"]==domain["native_or_rust_calls"]==0,
        "frozen input-only source admission")
    for role in ("original","native"):
        report=decode(owned(data,role+"/CAPTURE.json").read_bytes())
        expected=dict(status="PASS",role=role,group=group,cases=report["cases"],original_decode_calls=report["original_decode_calls"],
            native_utf8_calls=report["native_utf8_calls"],body_or_parent_application_calls=0)
        require(returned["capture-"+role]==expected,"exact actual capture returned counters")
    completed=decode(owned(capture,"COMPLETED.json").read_bytes())
    require(completed==[dict(role=role,report=returned["capture-"+role]) for role in ("original","native")],"completed roles retained")
    primary=decode(owned(capture,"READONLY.json").read_bytes())
    require(primary==returned["full-read"] and primary["evidence"]==actual,"original primary reader full evidence")
    row=rows[6];bound=saved_guard(primary,{argument(row,"source"):tree(source),argument(row,"data"):tree(data)})
    physical,physical_files=controls(source,data,capture,actual);bound+=physical_files
    require(physical==gate["controls"]==returned["physical-controls"],"all actual returned physical controls")
    # Complete original build admission and seven saved upstream guards.
    built=read_build_evidence.verify(source,reuse)
    admission=decode(owned(capture,"BUILD_ADMISSION.json").read_bytes())
    require(admission==returned["build-admission"] and admission["evidence"]==built,"retained exact full build admission")
    original_work=Path(argument(rows[3],"work"));original_source=argument(rows[3],"source")
    bound+=saved_guard(admission,{original_source:tree(source),
        str(original_work/"original"):tree(reuse/"original"),str(original_work/"download"):tree(reuse/"download")})
    require(returned["build-fetch"]["status"]==returned["build-unpack"]["status"]=="PASS"
        and gate["complete_upstream_build"]==decode((source/"BUILD_REUSE.json").read_bytes()),"complete upstream provenance")
    rootfiles={p.name for p in capture.iterdir() if p.is_file()}
    require(rootfiles=={"ENVIRONMENT.json","INPUT_DOMAIN.json","BUILD_ADMISSION.json","COMPLETED.json","READONLY.json","GATE.json"}
        and {p.name for p in capture.iterdir() if p.is_dir()}=={"application","processes","controls"},
        "complete actual capture root set")
    decode(owned(capture,"ENVIRONMENT.json").read_bytes())
    return dict(status="COMPLETE_UPLOADED_MULTI_UTF8_PRODUCER_AND_CONTROLS_PASS",group=group,actual=actual,
        producer_processes=8,retained_guard_invocations=12,retained_guard_probes=132,
        retained_guard_file_references=bound,upstream_build=built,physical_refusals=8,full_relocations=2,
        new_original_or_native_applications=0,body_or_public_qualified=False)
