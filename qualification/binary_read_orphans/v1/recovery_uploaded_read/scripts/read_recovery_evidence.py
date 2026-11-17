"""Entire source/process/guard/control recovery proof admission; zero application replay."""
from pathlib import Path
import copy,gzip,hashlib
from evidence_common import decode,encoded,pin,require,source_evidence
from read_build_evidence import tree,saved_guard
import read_retained
def identities(root):
    files,dirs=tree(root)
    return {p:dict(**pin(v[0]),mode=v[1])for p,v in files.items()},dirs
def verify(recovery_source,capture,name,upstream):
    recovery_source,capture,upstream=Path(recovery_source),Path(capture),Path(upstream)
    binding=source_evidence(recovery_source);gate=decode((capture/"GATE.json").read_bytes())
    require(gate["status"]=="PASS"and gate["source"]==binding and gate["group"]==name
        and gate["original_application_executions"]==gate["native_application_executions"]==gate["compiler_executions"]==gate["rust_executions"]==0
        and gate["original_archive_included_in_full"]is True and gate["whole_runtime_replaced"]is False,"exact pure recovery gate")
    processes=decode((capture/"processes/processes.json").read_bytes())
    expected=[("source-check",60),("original-fetch",60),("original-unpack",180),("original-admit",180),
        ("upstream-fetch",60),("upstream-unpack",180),("retained-full-read",180),("physical-controls",180)]
    require(processes==gate["processes"]and[(p["name"],p["timeout_seconds"])for p in processes]==expected,
        "exact no-replay process set")
    returns={}
    for p in processes:
        require(p["pid"]==p["pgid"]and p["exit_code"]==0 and p["completed"]is True and p["timed_out"]is False
            and 0<=p["elapsed_seconds"]<p["timeout_seconds"]and p["stdin"]is None,"natural bounded recovery custody")
        for suffix in("stdout","stderr"):
            item=p[suffix];require(item["file"]==p["name"]+"."+suffix and
                pin(capture/"processes"/item["file"])=={k:item[k]for k in("bytes","sha256")},"full recovery process streams")
        require(p["stderr"]["bytes"]==0,"unread recovery stderr")
        returns[p["name"]]=decode((capture/"processes"/p["stdout"]["file"]).read_bytes())
    require(returns["source-check"]==decode((capture/"SOURCE_CHECK.json").read_bytes())
        and returns["source-check"]["source"]==binding and returns["source-check"]["status"]=="READ_ORPHANS_SOURCE_AND_INPUT_ONLY_PASS",
        "exact recovery source/AST/input-only admission")
    semantic=capture/"semantic";value=read_retained.verify(recovery_source,semantic,name,upstream)
    primary=decode((capture/"READONLY.json").read_bytes())
    require(primary==returns["retained-full-read"]and primary["evidence"]==value==gate["read"],"whole recomputed original read and recovery guard")
    require(returns["original-admit"]==value["archive"],"whole archive admission output")
    unpacked=decode((semantic/"original/UNPACK.json").read_bytes())
    require(returns["original-unpack"]==unpacked and returns["original-fetch"]["zip"]==value["archive"]["zip"],
        "original full transfer/restoration custody")
    for stage in("fetch","unpack"):
        require(returns["upstream-"+stage]["status"]=="PASS","qualified build transfer/restoration return")
    recovery_origin=processes[0]["cwd"]
    semantic_origin=processes[1]["argv"][processes[1]["argv"].index("--work")+1]
    upstream_origin=processes[4]["argv"][processes[4]["argv"].index("--work")+1]
    guarded_files=saved_guard(primary,{recovery_origin:tree(recovery_source),semantic_origin:tree(semantic),upstream_origin:tree(upstream)})
    actual=value["actual"]
    source=semantic/"original/restored/source";data=semantic/"original/restored/run/application"
    original_source=processes[7]["argv"][processes[7]["argv"].index("--source")+1]
    controls=decode((capture/"controls/RESULT.json").read_bytes())
    require(controls==returns["physical-controls"]==gate["controls"]
        and controls["status"]=="EIGHT_PHYSICAL_REFUSALS_TWO_FULL_RELOCATIONS_PASS"
        and controls["guard_probes"]==110 and controls["application_executions"]==0,"whole ten guarded controls")
    names=["native-buffer","original-stdout","native-journal","original-case","native-image","source-manifest","honest-native-result","honest-original-result"]
    require([c["name"]for c in controls["physical"]]==names and len(controls["relocations"])==2,"physical domain fixed")
    base_files,base_dirs=identities(data);source_files,source_dirs=identities(source)
    controls_origin=processes[7]["argv"][processes[7]["argv"].index("--output")+1]
    for c in controls["physical"]:
        root=capture/"controls"/c["name"];copied=root/"data";selected_source=root/"source"if c["name"]=="source-manifest"else source
        mutation=decode((root/"MUTATION.json").read_bytes());require(mutation==c["mutation"],"full mutation record")
        prefix=controls_origin+"/"+c["name"]+("/source"if c["name"]=="source-manifest"else"/data")
        relative=Path(mutation["file"]).relative_to(prefix).as_posix()
        changed=(selected_source if c["name"]=="source-manifest"else copied)/relative
        original=(source if c["name"]=="source-manifest"else data)/relative
        before=(root/"changed-before.bin").read_bytes();after=(root/"changed-after.bin").read_bytes()
        require(before==original.read_bytes()and after==changed.read_bytes()and before!=after
            and mutation["before"]==dict(**pin(original),mode=original.stat().st_mode&0o777)
            and mutation["after"]==dict(**pin(changed),mode=changed.stat().st_mode&0o777)
            and mutation["before_bytes"]==pin(root/"changed-before.bin")and mutation["after_bytes"]==pin(root/"changed-after.bin"),
            "real physical full before/after bytes")
        copied_files,copied_dirs=identities(copied);require(copied_dirs==base_dirs and set(copied_files)==set(base_files),"complete physical copy set")
        changes={p for p in base_files if base_files[p]!=copied_files[p]}
        if c["name"]=="source-manifest":
            require(not changes and after==before+b"\nACTUAL_BAD_SOURCE\n","source-only physical change")
            sf,sd=identities(selected_source);require(sd==source_dirs and set(sf)==set(source_files)
                and {p for p in sf if sf[p]!=source_files[p]}=={"SOURCE_MANIFEST.json"},"only one physical source mutation")
        elif c["name"].startswith("honest-"):
            require(changes=={relative,str(Path(relative).with_name("CAPTURE.json"))}and mutation["honestly_resealed"],"honest control changed only full case and own seal")
            left=[decode(x)for x in gzip.decompress(before).splitlines()]
            right=[decode(x)for x in gzip.decompress(after).splitlines()]
            altered=copy.deepcopy(right);a=left[0]["actual"]["chain"]["invocations"][0]["result"]
            b=altered[0]["actual"]["chain"]["invocations"][0]["result"]
            if a["ok"]:
                require("__physically_resealed_bad_field__"not in a["value"]and b["value"].pop("__physically_resealed_bad_field__")is True,"physical success alteration")
            else:
                require(b["error"]["message"]==a["error"]["message"]+" physically altered","physical literal alteration");b["error"]["message"]=a["error"]["message"]
            require(altered==left,"no additional honest control mutation")
            folder=changed.parent;report=decode((folder/"CAPTURE.json").read_bytes())
            raw=gzip.decompress(after);rows=raw.splitlines(keepends=True)
            require(report["cases_file"]==pin(changed)and report["cases_raw"]==dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
                and report["case_rows"]==[dict(id=v["input"]["id"],bytes=len(r),sha256=hashlib.sha256(r).hexdigest())for v,r in zip(right,rows)],"honest complete reseal")
            base_report=decode((original.parent/"CAPTURE.json").read_bytes())
            require({k:v for k,v in report.items()if k not in("cases_file","cases_raw","case_rows")}
                =={k:v for k,v in base_report.items()if k not in("cases_file","cases_raw","case_rows")},"honest seal changed no other producer record")
        else:
            require(changes=={relative}and not mutation["honestly_resealed"],"one physical byte-bearing file change")
            if c["name"]=="native-buffer":
                a,b=gzip.decompress(before),gzip.decompress(after);require(b==bytes([a[0]^1])+a[1:],"real complete buffer alteration")
            else:require(after==bytes([before[0]^1])+before[1:],"real byte alteration")
        guard=decode((root/"READONLY.json").read_bytes())
        selected_origin=controls_origin+"/"+c["name"]+"/source"if c["name"]=="source-manifest"else original_source
        data_origin=controls_origin+"/"+c["name"]+"/data"
        guarded_files+=saved_guard(guard,{recovery_origin:tree(recovery_source),selected_origin:tree(selected_source),data_origin:tree(copied)})
        require(guard["evidence"]==c["evidence"]and guard["evidence"]["status"]=="REJECTED"and c["guard_probes"]==11,
            "physical original guarded rejection")
    for index,c in enumerate(controls["relocations"],1):
        require(c["name"]=="relocated-"+str(index),"fixed complete relocation")
        root=capture/"controls"/c["name"];sf,sd=identities(root/"source");df,dd=identities(root/"data")
        require((sf,sd)==(source_files,source_dirs)and(df,dd)==(base_files,base_dirs),"all complete relocated source/data bytes and modes")
        guard=decode((root/"READONLY.json").read_bytes())
        base=controls_origin+"/"+c["name"]
        guarded_files+=saved_guard(guard,{recovery_origin:tree(recovery_source),base+"/source":tree(root/"source"),base+"/data":tree(root/"data")})
        require(guard["evidence"]==actual==c["evidence"]and c["guard_probes"]==11 and c["entries"]==guard["entries"],"complete retained relocation result")
    return dict(status="COMPLETE_UPLOADED_READ_ORPHANS_RECOVERY_QUALIFICATION_PASS",group=name,actual=actual,
        retained=value,producer_processes=len(processes),retained_recovery_guards=11,retained_recovery_guard_probes=121,
        retained_recovery_guard_full_file_references=guarded_files,physical_refusals=8,complete_relocations=2,
        new_application_executions=0,whole_runtime_replaced=False)
