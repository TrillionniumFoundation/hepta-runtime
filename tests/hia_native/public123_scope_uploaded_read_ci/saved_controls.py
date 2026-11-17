"""Read full saved controls and their actual changed buffers."""
from pathlib import Path
import copy,gzip,hashlib,json,os,shutil,stat,struct
from archive_input import require,doc,pin,put,files,saved_guard
PHYSICAL=(("public-wire","native/000/process/stdout.bin.gz"),("accepted-input","native/000/process/stdin.bin.gz"),("private-state","native/000/process/controls/0001.output.bin.gz"),("host-trace","native/000/process/host-trace.bin.gz"),("binary","native/tool-runtime.bin"),("case-file","native/000/CASE.json"),("original-wire","original/000/process/stdout.bin.gz"),("domain","native/DOMAIN.json"),("relocated-a",None),("relocated-b",None))
SEMANTIC=(("rename-ack-not-consumed",11,"b",336,1,0,"actual consumed successful rename acknowledgment"),("rename-returned-errno",11,"b",320,0,5,"actual consumed successful rename acknowledgment"),("different-final-effect",11,"b",272,8,9,"actual last rename request"),("temporary-fd-still-open",9,"c",2384,(1<<64)-1,0,"both actual native temporary and read descriptors closed"),("read-fd-still-owned",9,"c",2120,0,1,"both actual native temporary and read descriptors closed"))
def prepare_semantic(capture,controls,dest):
    result={}
    dest.mkdir()
    for name,*_ in SEMANTIC:
        item=dest/name;shutil.copytree(capture,item,copy_function=os.link)
        mutation=doc(controls/name/"MUTATION.json")
        for rel,row in mutation["changed"].items():
            path=item/rel;path.unlink();path.write_bytes((controls/name/row["after"]).read_bytes());os.chmod(path,row["mode"])
        result[name]=item
    return result
def trace_change(before,after,mutation,old_value,fixed):
    hashes=[hashlib.sha256(),hashlib.sha256()];sizes=[0,0];found=0
    with gzip.open(before,"rb") as left,gzip.open(after,"rb") as right:
        streams=(left,right)
        def read(index,n):
            raw=streams[index].read(n);require(len(raw)==n,"full changed trace span")
            hashes[index].update(raw);sizes[index]+=len(raw);return raw
        while True:
            magic=left.read(8);other=right.read(8);require(magic==other,"same complete trace framing")
            if not magic:break
            require(len(magic)==8,"complete changed trace magic")
            for i in range(2):hashes[i].update(magic);sizes[i]+=8
            if magic==b"HPTREV01":
                headers=[read(i,120) for i in range(2)];require(headers[0]==headers[1],"exact unchanged trace header")
                w=struct.unpack("<15Q",headers[0]);an,bn,cn=w[8:11];extent=an+bn+cn
                changed=w[1]==mutation["sequence"]
                if changed:
                    require(w[2]==mutation["event"],"exact controlled actual event")
                    begin={"a":0,"b":an,"c":an+bn}[mutation["span"]]+mutation["offset"];end=begin+8
                    require(end<=extent,"controlled word bound")
                    found+=1
                at=0
                while at<extent:
                    size=min(1<<20,extent-at)
                    raws=[read(i,size) for i in range(2)]
                    if changed and at<end and at+size>begin:
                        low=max(at,begin);high=min(at+size,end)
                        start=low-at;stop=high-at
                        require(raws[0][:start]==raws[1][:start] and raws[0][stop:]==raws[1][stop:],"all other actual trace bytes")
                        require(raws[0][start:stop]==struct.pack("<Q",old_value)[low-begin:high-begin] and raws[1][start:stop]==struct.pack("<Q",mutation["value"])[low-begin:high-begin],"only exact claimed actual word changed")
                    else:require(raws[0]==raws[1],"entire unmodified actual trace spans")
                    at+=size
            elif magic==b"HXLTR001":
                headers=[read(i,56) for i in range(2)];require(headers[0]==headers[1],"exact Drop frame header")
                w=struct.unpack("<7Q",headers[0]);length=w[4]+w[5];require(read(0,length)==read(1,length),"full unchanged Drop bytes")
            else:
                require(magic in fixed,"all original fixed trace kinds")
                require(read(0,fixed[magic]-8)==read(1,fixed[magic]-8),"complete fixed native frame")
    require(found==1,"exactly one controlled actual event")
    return [{"bytes":sizes[i],"sha256":hashes[i].hexdigest()} for i in range(2)]
def controls(capture,root,recipe,source,process,qualification,reader,prepared,role):
    saved=doc(root/"CONTROLS.json");actual=files(capture);base=[actual,files(recipe),files(source)]
    inventory=[]
    if role=="complete":
        require(saved["status"]=="EIGHT_PHYSICAL_CONTROLS_TWO_RELOCATIONS_PASS" and saved["application_executions"]==0 and len(saved["cases"])==10,"complete physical control set")
        for index,(name,target) in enumerate(PHYSICAL):
            path=root/name;mutation=doc(path/"MUTATION.json");proof=doc(path/"READ.json");retired=doc(path/"RETIREMENT.json")
            roots=[dict(actual),base[1],base[2]]
            if target is not None:
                require(mutation["path"]==target and mutation["mode"]==actual[target].stat().st_mode&0o777,"exact physical target mode")
                before=(path/"before.bin").read_bytes();after=(path/"after.bin").read_bytes()
                require(before==actual[target].read_bytes() and after==bytes([before[0]^1])+before[1:],"all before/after physical bytes")
                require(pin(path/"before.bin")==mutation["before"] and pin(path/"after.bin")==mutation["after"],"complete physical mutation pins")
                roots[0][target]=(path/"after.bin",mutation["mode"])
                require(proof["evidence"]["status"]=="PHYSICAL_EVIDENCE_REJECTED" and proof["evidence"]["type"] in ("ValueError","AssertionError","KeyError","UnicodeDecodeError"),"actual physical rejection")
                names={"before.bin","after.bin","MUTATION.json","READ.json","RETIREMENT.json"}
            else:
                require(mutation is None and proof["evidence"]==qualification,"exact complete relocated evidence")
                names={"MUTATION.json","READ.json","RETIREMENT.json"}
            require(set(files(path))==names,"entire physical control artifact")
            checked=saved_guard(proof,roots,process["pid"])
            require(retired=={"all_files":len(actual),"complete_bytes_compared":True,"all_unchanged_modes_compared":True,"mutation_mode_retained":mutation["mode"] if mutation else None},"complete source-owned retirement")
            row={"name":name,"status":proof["evidence"]["status"],"guard_probes":11,"target":target,"complete_files":len(actual)}
            require(saved["cases"][index]==row,"exact physical receipt")
            inventory.append({"name":name,"guarded_files":checked,"actual_control_replayed":False})
        require(set(p.name for p in root.iterdir())=={n for n,_ in PHYSICAL}|{"CONTROLS.json"},"whole physical evidence directory")
        return inventory
    require(saved["status"]=="FIVE_RESEALED_PHYSICAL_LIFETIME_CONTROLS_PASS" and saved["application_executions"]==0 and len(saved["cases"])==5,"all five resealed controls")
    require(len(qualification["inode_reallocation_proofs"])==1,"actual one-scenario lifetime proof")
    life=qualification["inode_reallocation_proofs"][0];final=life["actual_atomic_lifetimes"][-1]
    report=doc(capture/"native/CAPTURE.json");number=next(i for i,r in enumerate(report["cases"]) if r["name"]==life["scenario"])
    case_dir="%03d"%number;process_rel="native/"+case_dir+"/process/"
    original_process=doc(capture/process_rel/"complete-process.json")
    trace_rel=process_rel+Path(original_process["fixed_capabilities"]["host-trace"]["path"]).name
    inputs=doc(capture/"INPUTS_READY.json")
    original=reader.read_selected(capture/"original","original",{k:inputs["original"][k] for k in ("bytes","sha256")},number)
    import atomic_frames
    for index,(name,event,span,offset,old_value,new_value,message) in enumerate(SEMANTIC):
        path=root/name;mutation=doc(path/"MUTATION.json");proof=doc(path/"READ.json")
        expected_sequence=final["trace_sequence"] if event==11 else final["context_sequence"]
        require({k:mutation[k] for k in ("sequence","event","span","offset","value")}=={"sequence":expected_sequence,"event":event,"span":span,"offset":offset,"value":new_value},"exact actual controlled field")
        require(mutation["outer_receipts_recomputed_from_actual_changed_bytes"] is True,"honestly recomputed outer receipts")
        changed=mutation["changed"];roots=[dict(actual),base[1],base[2]]
        known={trace_rel,process_rel+"complete-process.json","native/"+case_dir+"/CASE.json","native/CAPTURE.json"}
        if "fixed_capabilities" in doc(capture/process_rel/"process.json"):known.add(process_rel+"process.json")
        require(set(changed)==known,"only actual trace and dependent complete receipts changed")
        expected_files={"MUTATION.json","READ.json","RETIREMENT.json"}
        for rel,row in changed.items():
            before=path/row["before"];after=path/row["after"];expected_files.update((row["before"],row["after"]))
            require(before.read_bytes()==actual[rel].read_bytes() and pin(before)==row["before_pin"] and pin(after)==row["after_pin"] and row["mode"]==actual[rel].stat().st_mode&0o777,"complete saved mutation bytes and permissions")
            roots[0][rel]=(after,row["mode"])
        require(set(files(path))==expected_files,"all complete resealed control files")
        t=changed[trace_rel];raw_pins=trace_change(path/t["before"],path/t["after"],mutation,old_value,atomic_frames.FIXED)
        require(raw_pins[0]==original_process["fixed_capabilities"]["host-trace"]["uncompressed"],"entire original actual trace")
        expected_process=copy.deepcopy(original_process)
        expected_process["fixed_capabilities"]["host-trace"].update(compressed=pin(path/t["after"]),uncompressed=raw_pins[1])
        def serial(value):return (json.dumps(value,sort_keys=True,indent=2)+"\n").encode()
        def changed_bytes(rel):return (path/changed[rel]["after"]).read_bytes()
        require(changed_bytes(process_rel+"complete-process.json")==serial(expected_process),"actual complete process resealed from changed trace")
        if process_rel+"process.json" in changed:
            v=doc(capture/process_rel/"process.json");v["fixed_capabilities"]["host-trace"].update(compressed=pin(path/t["after"]),uncompressed=raw_pins[1])
            require(changed_bytes(process_rel+"process.json")==serial(v),"actual base process reseal")
        case=doc(capture/"native"/case_dir/"CASE.json");case["process"]=expected_process
        require(changed_bytes("native/"+case_dir+"/CASE.json")==serial(case),"entire case resealed from actual process")
        report_new=copy.deepcopy(report);report_new["cases"][number]["case"]=pin(path/changed["native/"+case_dir+"/CASE.json"]["after"])
        require(changed_bytes("native/CAPTURE.json")==serial(report_new),"entire capture resealed from actual case")
        checked=saved_guard(proof,roots,process["pid"])
        require(proof["evidence"]["status"]=="RESEALED_LIFETIME_PRECONDITION_REJECTED" and proof["evidence"]["changed_case_complete_readers_passed"] is True and message in proof["evidence"]["error"],"actual specific semantic refusal")
        require(doc(path/"RETIREMENT.json")=={"all_files":len(actual),"complete_bytes_and_modes_compared":True},"complete control retirement")
        row={"name":name,"status":proof["evidence"]["status"],"guard_probes":11,"changed_files":len(changed),"complete_files":len(actual)}
        require(saved["cases"][index]==row,"complete saved semantic receipt")
        # Read the entire resealed native case again in this independent guard.
        native=reader.read_selected(prepared[name]/"native","native",{k:inputs["native"][k] for k in ("bytes","sha256")},number)
        try:reader.compare(original,native)
        except ValueError as error:require(message in str(error),"independent identical lifetime precondition refusal")
        else:raise AssertionError("independent reader accepted corrupted physical lifetime")
        inventory.append({"name":name,"guarded_files":checked,"changed_trace_uncompressed":raw_pins,"actual_control_replayed":False,"independent_full_changed_case_read":True})
    require(set(p.name for p in root.iterdir())=={r[0] for r in SEMANTIC}|{"CONTROLS.json"},"whole semantic evidence directory")
    return inventory
def retire(prepared,capture,controls):
    result=[]
    for name,root in prepared.items():
        mutation=doc(controls/name/"MUTATION.json");changed=mutation["changed"];count=0
        for rel,path in files(root).items():
            expected=controls/name/changed[rel]["after"] if rel in changed else capture/rel
            mode=changed[rel]["mode"] if rel in changed else expected.stat().st_mode&0o777
            require(path.read_bytes()==expected.read_bytes() and path.stat().st_mode&0o777==mode,"all independent prepared bytes and modes before retirement");count+=1
        shutil.rmtree(root);result.append({"name":name,"complete_files":count,"full_bytes_and_modes":True})
    return result
