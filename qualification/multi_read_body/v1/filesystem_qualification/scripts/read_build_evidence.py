"""Complete source-owned verification of retained build processes and all six guards."""
from pathlib import Path
import stat
from evidence_common import decode,pin,require,owned
import build_reuse
PROBES=["write","os-open-write","mkdir","rename","unlink","chmod","utime","subprocess","ctypes","mmap","foreign-read"]
def tree(root):
    root=Path(root);files={};dirs={}
    for p in [root,*sorted(root.rglob("*"))]:
        name="."if p==root else p.relative_to(root).as_posix()
        require(not p.is_symlink(),"guard tree symlink")
        if p.is_dir():dirs[name]=p.stat().st_mode&0o777
        else:
            require(p.is_file(),"guard ordinary file")
            files[name]=(p,p.stat().st_mode&0o777)
    return files,dirs
def saved_guard(value,roots):
    require(value["status"]=="READONLY_PASS" and value["before"]==value["after"]
        and value["native_executed"]is value["rust_executed"]is value["evidence_written"]is False,
        "saved guard complete nonmutating result")
    require(value["roots"]==sorted(roots) and value["probes"]==[dict(name=n,rejected=True)for n in PROBES],
        "all eleven exact saved guard denials")
    require(value["entries"]==len(value["before"]),"guard entry count")
    bound=0
    for number,name in enumerate(value["roots"]):
        files,dirs=roots[name];rows={r["path"]:r for r in value["before"]if r["root"]==number}
        require(len(rows)==sum(r["root"]==number for r in value["before"]) and set(rows)==set(files)|set(dirs),
            "complete saved guard entry set")
        for path,(physical,mode)in files.items():
            r=rows[path];actual=pin(physical)
            require(stat.S_ISREG(r["mode"]) and r["mode"]&0o777==mode
                and r["bytes"]==actual["bytes"] and r["sha256"]==actual["sha256"],
                "all saved guarded file bytes and modes")
            bound+=1
        for path,mode in dirs.items():
            r=rows[path];require(stat.S_ISDIR(r["mode"]) and r["mode"]&0o777==mode and "sha256"not in r,
                "all saved guard directory modes")
    require(all(type(r["root"])is int and 0<=r["root"]<len(roots)for r in value["before"]),
        "no foreign saved guard root")
    return bound
def processes(run,gate):
    rows=decode(owned(run,"processes/processes.json").read_bytes())
    require(rows==gate["processes"] and [r["name"]for r in rows]==
        ["source-check","native-build","read-build","physical-controls"],"exact bounded build process set")
    limits=[60,900,180,180];values={}
    for r,limit in zip(rows,limits):
        require(r["pid"]==r["pgid"] and type(r["parent_pid"])is int and r["parent_pid"]>0
            and r["exit_code"]==0 and r["timed_out"]is False and r["completed"]is True
            and r["timeout_seconds"]==limit and 0<=r["elapsed_seconds"]<limit and r["stdin"]is None,
            "actual natural bounded build process")
        for suffix in("stdout","stderr"):
            item=r[suffix];require(item["file"]==r["name"]+"."+suffix
                and pin(owned(run,"processes/"+item["file"]))=={k:item[k]for k in("bytes","sha256")},
                "whole actual build process streams")
        require(r["stderr"]["bytes"]==0,"no hidden build process error")
        values[r["name"]]=decode(owned(run,"processes/"+r["stdout"]["file"]).read_bytes())
    require(values["source-check"]["status"]=="SOURCE_ONLY_PASS"
        and values["native-build"]==gate["build"]
        and values["read-build"]==decode(owned(run,"READONLY.json").read_bytes())
        and values["physical-controls"]==gate["controls"]
        ==decode(owned(run,"controls/CONTROLS.json").read_bytes()),"full retained process returned values")
    return rows,values
def verify(source,work):
    result=build_reuse.verify(source,work)
    base=Path(work)/"original/restored";old=base/"source";run=base/"run";build=run/"build"
    gate=decode(owned(run,"GATE.json").read_bytes());rows,values=processes(run,gate)
    require(gate["build"]==decode(owned(build,"BUILD.json").read_bytes()),"complete actual build producer record")
    source_origin=rows[0]["argv"][rows[0]["argv"].index("--source")+1]
    build_origin=rows[1]["argv"][rows[1]["argv"].index("--output")+1]
    source_tree=tree(old);build_tree=tree(build)
    primary=values["read-build"]
    count=saved_guard(primary,{source_origin:source_tree,build_origin:build_tree})
    require(primary["evidence"]==gate["build_read"]==result["build"],"complete source-owned build reader result")
    controls=gate["controls"];cases=controls["cases"]
    require(controls["status"]=="FOUR_PHYSICAL_REFUSALS_TWO_COMPLETE_RELOCATIONS_PASS"
        and controls["guarded_process_calls"]==6 and controls["guard_probes"]==66
        and controls["new_native_application_calls"]==controls["new_rust_calls"]==0
        and [c["name"]for c in cases]==["source-native","compiled-owner","packed-output","copied-B3","relocation-a","relocation-b"],
        "complete original six physical and relocation controls")
    expected=[("source","asm/multi_read_body_callable.S","source bytes/mode differ"),
        ("build",None,"actual member bytes differ"),("build","pack.output.bin","full build artifact bytes differ"),
        ("build","build/bootstrap/B3.image.bin","bootstrap generation differs"),(None,None,None),(None,None,None)]
    bm=gate["build"]["members"]["body"];bm_path=Path(bm["manifest"])
    expected[1]=("build",(bm_path.parent/decode(owned(build,bm["manifest"]).read_bytes())["source"]).as_posix(),
        "actual member bytes differ")
    totalfiles=count
    for c,(which,path,message)in zip(cases,expected):
        folder=run/"controls"/c["name"];guard_path=owned(folder,"READONLY.json")
        require(pin(guard_path)==c["guard"],"complete saved control guard bytes")
        checked=decode(guard_path.read_bytes())
        st=(dict(source_tree[0]),dict(source_tree[1]));bt=(dict(build_tree[0]),dict(build_tree[1]))
        if which is not None:
            physical=c["physical"];original=(old if which=="source"else build)/path
            before=owned(folder,"before.bin");after=owned(folder,"after.bin")
            a,b=before.read_bytes(),after.read_bytes()
            require(physical==dict(root=which,path=path,before=pin(before),after=pin(after),
                mode=original.stat().st_mode&0o777,changed_offset=0)
                and a==original.read_bytes() and b==bytes([a[0]^1])+a[1:],"actual single physical mutation")
            (st if which=="source"else bt)[0][path]=(after,physical["mode"])
            require(c["result"]["status"]=="TARGETED_PHYSICAL_REFUSAL" and message in c["result"]["message"],
                "exact targeted original control refusal")
        else:
            require(c["physical"]is None and c["result"]==dict(status="COMPLETE_RELOCATED_BUILD_PASS",qualification=result["build"]),
                "complete original relocated qualification")
        labels=checked["roots"]
        require(len(labels)==2 and all(Path(x).parent.name=="working" for x in labels)
            and {Path(x).name for x in labels}=={"source","build"}
            and all(Path(x).parent.parent.name==c["name"] for x in labels),"exact historical control roots")
        mapping={x:st if Path(x).name=="source"else bt for x in labels}
        totalfiles+=saved_guard(checked,mapping)
        require(checked["evidence"]==c["result"] and c["retired_complete_duplicate_files"]==len(st[0])+len(bt[0]),
            "retained control result and complete retirement extent")
    return dict(status="COMPLETE_UPLOADED_MULTI_READ_BUILD_AND_SEVEN_GUARDS_PASS",
        qualified_build=result,retained_guard_invocations=7,retained_guard_probes=77,
        retained_guard_full_file_references=totalfiles,physical_refusals=4,complete_relocations=2,
        new_hia_or_rust_applications=0,multi_read_body_application_qualified=False)
