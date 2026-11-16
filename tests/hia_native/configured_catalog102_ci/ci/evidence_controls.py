"""Twelve physical, retained evidence mutations; no HIA or Rust is executed."""
from pathlib import Path
import argparse, copy, gzip, os, stat, sys, time
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import catalog_ci_support as c
import read_all,read_reference,read_graph,registry_evidence
NAMES=("source-byte","native-input","native-output-tail","native-workspace-tail","native-missing-case",
       "public-input","public-output","pack-workspace-tail","compiler-stdout","sdk-output-rehashed",
       "original-missing-case-rehashed","locked-registry-archive-rehashed")
KINDS=("source","native","native","native","native","public","public","graph","graph","sdk","original","sdk")

def files(root):
    root=Path(root)
    result={}
    for folder,dirs,names in os.walk(root,followlinks=False):
        for name in dirs:
            path=Path(folder)/name;c.need(stat.S_ISDIR(path.lstat().st_mode),"owned regular directory")
        for name in names:
            path=Path(folder)/name;raw=c.regular(path)
            result[path.relative_to(root).as_posix()]={"mode":stat.S_IMODE(path.lstat().st_mode),**c.pin(raw)}
    return result

def copy_owned(source,destination):
    inventory=files(source)
    destination.mkdir(mode=stat.S_IMODE(source.stat().st_mode))
    for path in sorted(source.rglob("*"),key=lambda p:(len(p.parts),p.as_posix())):
        relative=path.relative_to(source);dest=destination/relative;info=path.lstat()
        if stat.S_ISDIR(info.st_mode):
            dest.mkdir();dest.chmod(stat.S_IMODE(info.st_mode))
        else:
            c.need(relative.as_posix() in inventory,"copy only admitted regular files")
            c.put(dest,c.regular(path));dest.chmod(stat.S_IMODE(info.st_mode))
    c.need(files(destination)==inventory,"complete independent physical copy")
    return inventory

def flip(raw,at=-1):
    c.need(bool(raw),"nonempty mutation target")
    result=bytearray(raw);result[at]^=1;return bytes(result)

def changes(name,root):
    result={}
    if name=="source-byte":
        path="graph/native/runtime_mcp_catalog_ninth.hepta";result[path]=flip(c.regular(root/path),0)
    elif name.startswith("native-"):
        report=c.read_json(root/"result.json")
        if name=="native-missing-case":report["records"].pop()
        else:
            field={"native-input":"input","native-output-tail":"output","native-workspace-tail":"workspace"}[name]
            call=report["records"][0]["calls"][0];path=call["prefix"]+"."+field+".gz"
            raw=flip(gzip.decompress(c.regular(root/path)))
            result[path]=gzip.compress(raw,compresslevel=1,mtime=0);call[field+"_sha256"]=c.sha(raw)
        result["result.json"]=c.encoded(report)
    elif name in ("public-input","public-output"):
        path="profile-0/"+("request-000.bin" if name=="public-input" else "response-000.bin")
        result[path]=flip(c.regular(root/path),-2)
    elif name=="pack-workspace-tail":
        path="build/public-authority-batch/pack.workspace.bin";result[path]=flip(c.regular(root/path))
    elif name=="compiler-stdout":
        m=c.read_json(root/"build/public-authority-batch/manifest.json")
        old=Path(m["build_root"]).parent;path=Path(m["members"][0]["manifest"]).relative_to(old).parent/"module.stdout.log"
        row=c.read_json(root/path);row["result_u64"]+=1;result[path.as_posix()]=c.encoded(row)
    elif name=="sdk-output-rehashed":
        path="processes/sdk-projection.stdout";raw=flip(c.regular(root/path),64);result[path]=raw
        row=c.read_json(root/"processes/sdk-projection.process.json");row["stdout"]=c.pin(raw)
        result["processes/sdk-projection.process.json"]=c.encoded(row)
        report=c.read_json(root/"result.json");report["replay_process"]=row;result["result.json"]=c.encoded(report)
    elif name=="original-missing-case-rehashed":
        path="processes/profile-disabled.stdout";row=c.read_json(root/path);row["list_cases"].pop()
        raw=c.encoded(row);result[path]=raw
        proc=c.read_json(root/"processes/profile-disabled.process.json")
        proc["stdout"].update(c.pin(raw));result["processes/profile-disabled.process.json"]=c.encoded(proc)
    elif name=="locked-registry-archive-rehashed":
        report=c.read_json(root/"registry-archives.json");key=sorted(report["packages"])[0]
        row=report["packages"][key];path=row["path"];raw=flip(c.regular(root/path),0)
        row["archive"]=c.pin(raw);result[path]=raw;result["registry-archives.json"]=c.encoded(report)
    else:raise ValueError(name)
    return result

def dispatch(name,kind,package,capture,clone,gate,processes):
    component,domain,public,configured,old,guard=read_all.prepare(package)
    if kind=="source":return c.source_check(clone)
    if kind=="native":return configured.verify(package/"source",capture/"b",clone)
    if kind=="public":return public.verify(package/"public",package/"source",package/"graph",
        capture/"g/build/public-authority-batch/manifest.json",clone)
    if kind=="graph":return read_graph.verify(package,clone,expected_origin=gate["origins"]["graph"],
        expected_source=gate["origins"]["source"]+"/graph",expected_manifest=gate["graph_manifest"])
    if kind=="original":return old.verify(clone)
    if name=="locked-registry-archive-rehashed":return registry_evidence.verify(capture/"r",clone)
    roots={"package":gate["origins"]["source"],"target":gate["target_checkout"],
        "original":gate["origins"]["original"],"output":gate["origins"]["sdk"]}
    return read_reference.verify_build(package,capture/"r",clone,expected_roots=roots,
        expected_parent=processes["sdk-observers"])

def run(package,capture,output):
    read_all.prepare(package)
    gate,processes,streams,reader=read_all.execution_gate(package,capture)
    output.mkdir(parents=True,exist_ok=False)
    roots={"source":package,"native":capture/"n","public":capture/"pn","graph":capture/"g",
        "sdk":capture/"k","original":capture/"r"}
    start=time.monotonic_ns();rows=[]
    for ordinal,(name,kind) in enumerate(zip(NAMES,KINDS,strict=True)):
        source=roots[kind];clone=output/f"{ordinal:02d}-{name}"
        baseline=copy_owned(source,clone);delta=changes(name,source)
        for path,raw in delta.items():
            p=clone/path;c.need(p.is_file(),"existing admitted mutation path");p.write_bytes(raw)
        physical=files(clone)
        try:dispatch(name,kind,package,capture,clone,gate,processes)
        except (ValueError,AssertionError,KeyError,UnicodeError) as error:
            refusal={"type":type(error).__name__,"message":str(error)}
        else:raise ValueError("reader accepted physical mutation: "+name)
        rows.append({"name":name,"kind":kind,"directory":clone.name,"baseline":baseline,
            "changed":{path:{"before":c.pin(c.regular(source/path)),"after":c.pin(raw)} for path,raw in delta.items()},
            "physical_files":physical,"refusal":refusal})
    elapsed=time.monotonic_ns()-start
    c.need(elapsed<=180_000_000_000,"original complete control budget")
    report={"schema":"hepta.runtime.configured-catalog-evidence-controls.v1","status":"PASS",
        "package":c.pin(c.regular(package/"PACKAGE.json")),"execution":c.pin(c.regular(capture/"EXECUTION.json")),
        "pid":os.getpid(),"parent_pid":os.getppid(),"pgid":os.getpgrp(),"elapsed_ns":elapsed,
        "deadline_seconds":180,"controls":rows,"native_executions":0,"rust_executions":0}
    c.put(output/"result.json",report)
    print(c.encoded({key:value for key,value in report.items() if key!="controls"}|{"refusals":len(rows)}).decode())
    return report

def verify(package,capture,output):
    read_all.prepare(package)
    gate,processes,streams,reader=read_all.execution_gate(package,capture)
    report=c.read_json(output/"result.json")
    c.need(report["schema"]=="hepta.runtime.configured-catalog-evidence-controls.v1" and report["status"]=="PASS"
        and report["package"]==c.pin(c.regular(package/"PACKAGE.json"))
        and report["execution"]==c.pin(c.regular(capture/"EXECUTION.json")),"actual control source/capture binding")
    for key in ("pid","parent_pid","pgid"):c.need(type(report[key])is int and report[key]>0,"control PID")
    c.need(report["pid"]==report["pgid"] and report["parent_pid"]==gate["pid"],"actual control process ownership")
    c.need(type(report["elapsed_ns"])is int and 0<report["elapsed_ns"]<=180_000_000_000
        and type(report["deadline_seconds"])is int and report["deadline_seconds"]==180
        and type(report["native_executions"])is int and type(report["rust_executions"])is int
        and report["native_executions"]==report["rust_executions"]==0,"unchanged control budget/zero semantic execution")
    roots={"source":package,"native":capture/"n","public":capture/"pn","graph":capture/"g",
        "sdk":capture/"k","original":capture/"r"}
    c.need(len(report["controls"])==len(NAMES),"complete rejection domain")
    actual_dirs={p.name for p in output.iterdir() if p.is_dir()};expected_dirs=set()
    for ordinal,(row,name,kind) in enumerate(zip(report["controls"],NAMES,KINDS,strict=True)):
        c.need(row["name"]==name and row["kind"]==kind and row["directory"]==f"{ordinal:02d}-{name}","fixed control association")
        expected_dirs.add(row["directory"]);source=roots[kind];clone=output/row["directory"]
        baseline=files(source);delta=changes(name,source);physical=files(clone)
        c.need(row["baseline"]==baseline and set(physical)==set(baseline),"full original and mutated file domains")
        c.need(row["changed"]=={path:{"before":c.pin(c.regular(source/path)),"after":c.pin(raw)}
            for path,raw in delta.items()},"exact independently recomputed mutation")
        expected=dict(baseline)
        for path,raw in delta.items():expected[path]={"mode":baseline[path]["mode"],**c.pin(raw)}
        c.need(physical==expected==row["physical_files"],"entire physical clone byte identity")
        try:dispatch(name,kind,package,capture,clone,gate,processes)
        except (ValueError,AssertionError,KeyError,UnicodeError) as error:
            c.need(row["refusal"]=={"type":type(error).__name__,"message":str(error)},"same actual rejection after relocation")
        else:raise ValueError("reader accepted retained mutant: "+name)
    c.need(actual_dirs==expected_dirs and {p.name for p in output.iterdir() if p.is_file()}=={"result.json"},
        "exact complete retained control tree")
    return {"status":"COMPLETE_PHYSICAL_CONFIGURED_CATALOG_REFUSALS_READONLY_PASS","refusals":len(NAMES),
        "control_names":list(NAMES),"report":c.pin(c.regular(output/"result.json")),"process_launches":0,
        "native_execution":False,"rust_execution":False}

if __name__=="__main__":
    p=argparse.ArgumentParser()
    for name in ("package","capture","output"):p.add_argument("--"+name,type=Path,required=True)
    a=p.parse_args()
    run(a.package.resolve(strict=True),a.capture.resolve(strict=True),a.output.absolute())
