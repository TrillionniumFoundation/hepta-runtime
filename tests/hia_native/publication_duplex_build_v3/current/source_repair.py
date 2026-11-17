#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Execute the source-only author once; independently reread its exact inverse."""
from pathlib import Path
import json,os,shutil,stat,subprocess,sys,time
from async_build_common import require,pin,raw,doc,files,put,blob,source_files
PREFIX="authoring/publication_borrow_end_v1"
BASE="f8857cbd18b3dedb38718f68822c072053b03233"
CHANGED=frozenset(("scripts/runtime_mcp_publication_async.py",
    "scripts/runtime_mcp_task_publication.S","scripts/runtime_mcp_task_storage.S"))
BINDING="native/runtime_mcp_sources.json"
def fullpin(value):
    import hashlib
    return dict(bytes=len(value),sha256=hashlib.sha256(value).hexdigest(),git_blob=blob(value))
def canonical(value):return (json.dumps(value,sort_keys=True,indent=2)+"\n").encode()
def produce(base,candidate,output):
    base=Path(base).resolve(strict=True);candidate=Path(candidate).resolve(strict=True)
    output=Path(output).resolve(strict=True)
    source_files(candidate,complete=False)
    root=output/"source-repair";root.mkdir()
    before=doc(candidate/PREFIX/"BASE_SOURCE_ROWS.json")
    require(before["commit"]==BASE and len(before["rows"])==530,"exact source author base")
    rows={r["path"]:r for r in before["rows"]}
    for path in sorted(CHANGED|{BINDING}):
        source=base/path;value=raw(source)
        require(fullpin(value)=={k:rows[path][k] for k in ("bytes","sha256","git_blob")},"retained changed predecessor")
        target=root/"before"/path;target.parent.mkdir(parents=True,exist_ok=True)
        target.write_bytes(value);target.chmod(0o644)
    script=candidate/PREFIX/"author.py";python=str(Path(sys.executable).resolve(strict=True))
    argv=[python,"-I","-S","-B",str(script),"--source",str(base),"--output",str(output/"source")]
    record=dict(schema="hepta.publication.borrow-end.source-author.v1",base=str(base),
        candidate=str(candidate),output=str(output),base_commit=BASE,python=python,
        argv=argv,cwd=str(candidate),timeout_seconds=60,author=pin(script),
        process_exit=None,timed_out=False,elapsed_seconds=None,hia_executed=False,rust_executed=False)
    start=time.monotonic()
    try:
        with (root/"author.stdout").open("wb") as stdout,(root/"author.stderr").open("wb") as stderr:
            result=subprocess.run(argv,cwd=candidate,stdout=stdout,stderr=stderr,timeout=60,check=False)
            record["process_exit"]=result.returncode
    except subprocess.TimeoutExpired:
        record["timed_out"]=True
        raise
    finally:
        record["elapsed_seconds"]=time.monotonic()-start
        for name in ("stdout","stderr"):
            path=root/("author."+name)
            if path.exists():record[name]=pin(path)
        put(root/"PROCESS.json",record)
    require(record["process_exit"]==0 and not record["timed_out"] and raw(root/"author.stderr")==b"","actual source author completion")
    source_files(output/"source")
    return verify(output)
def verify(output):
    output=Path(output).resolve(strict=True);graph=output/"source";root=output/"source-repair"
    rows=source_files(graph)
    before=doc(graph/PREFIX/"BASE_SOURCE_ROWS.json");change=doc(graph/PREFIX/"CHANGES.json")
    own=doc(graph/PREFIX/"SOURCE_MANIFEST.json")
    require(before["commit"]==change["base"]==BASE and len(before["rows"])==530,"entire exact predecessor identity")
    require(set(change["edits"])==CHANGED,"exact three repaired mechanical sources")
    wanted={"before/"+p for p in CHANGED|{BINDING}}|{"PROCESS.json","author.stdout","author.stderr"}
    require({p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()}==wanted,"complete source author receipt and retained before files")
    for p in root.rglob("*"):
        require(not p.is_symlink(),"source author capture contains no symlinks")
        require(p.is_file() or p.is_dir(),"source author capture contains no special files")
        if p.is_file():require(stat.S_IMODE(p.stat().st_mode)==0o644,"source author capture regular file mode")
    previous={}
    for row in before["rows"]:
        path=row["path"];p=root/"before"/path if path in CHANGED|{BINDING} else graph/path
        value=raw(p);require(fullpin(value)=={k:row[k] for k in ("bytes","sha256","git_blob")},"complete predecessor reconstructed: "+path)
        previous[path]=value
    require(fullpin(previous[BINDING])==change["base_binding"],"entire predecessor binding")
    for path,rule in change["edits"].items():
        original=previous[path];require(fullpin(original)==rule["before"],"exact edit preimage")
        text=original.decode()
        for edit in rule["edits"]:
            require(text.count(edit["before"])==1,"unique source forward splice")
            text=text.replace(edit["before"],edit["after"],1)
        require(text.encode()==raw(graph/path) and fullpin(text.encode())==rule["after"],"whole repaired source")
        for edit in reversed(rule["edits"]):
            require(text.count(edit["after"])==1,"unique source inverse splice")
            text=text.replace(edit["after"],edit["before"],1)
        require(text.encode()==original,"whole inverse source")
    for row in own["files"]:
        require(fullpin(raw(graph/PREFIX/row["path"]))=={k:row[k] for k in ("bytes","sha256","git_blob")},"complete source author package")
    paths=[row["path"] for row in own["files"]]+["SOURCE_MANIFEST.json"]
    require(set(rows)==set(previous)|{PREFIX+"/"+p for p in paths},"exact successor addition set")
    binding=json.loads(previous[BINDING])
    for path in [*change["edits"],*(PREFIX+"/"+p for p in paths)]:
        binding["sources"][path]=pin(graph/path)
    binding["publication_borrow_end_extension"]={
        "base_commit":change["base"],"base_binding_sha256":change["base_binding"]["sha256"],
        "changes":PREFIX+"/CHANGES.json","cancel_and_drop_are_alternative_terminal_operations":True,
        "completed_scope_alias_released_after_full_detach_observation":True,
        "slot68_owns_no_mapping":True,"unchanged_hia":True,"public_async_qualified":False,"full_sdk":False}
    require(canonical(binding)==raw(graph/BINDING),"exact integer-preserving source binding derivation")
    hia=[]
    for path,value in previous.items():
        if path.endswith(".hepta"):
            require(value==raw(graph/path),"every actual HIA byte retained");hia.append(path)
    receipt=doc(root/"PROCESS.json")
    require(receipt["schema"]=="hepta.publication.borrow-end.source-author.v1" and receipt["base_commit"]==BASE,"actual source author receipt identity")
    origin=Path(receipt["output"]);candidate=Path(receipt["candidate"]);base=Path(receipt["base"])
    argv=[receipt["python"],"-I","-S","-B",str(candidate/PREFIX/"author.py"),
        "--source",str(base),"--output",str(origin/"source")]
    require(origin.is_absolute() and candidate.is_absolute() and base.is_absolute()
        and Path(receipt["python"]).is_absolute() and receipt["argv"]==argv
        and receipt["cwd"]==str(candidate) and receipt["timeout_seconds"]==60,"exact actual source author command")
    require(receipt["author"]==pin(graph/PREFIX/"author.py") and receipt["process_exit"]==0
        and receipt["timed_out"] is False and type(receipt["elapsed_seconds"]) in (int,float)
        and 0<=receipt["elapsed_seconds"]<=60,"source author succeeded under original limit")
    require(receipt["hia_executed"] is False and receipt["rust_executed"] is False
        and receipt["stdout"]==pin(root/"author.stdout") and receipt["stderr"]==pin(root/"author.stderr")
        and raw(root/"author.stderr")==b"","complete source-only process streams")
    lines=raw(root/"author.stdout").decode().splitlines()
    require(len(lines)==2 and lines[0].startswith("BORROW_END_SOURCE_EXPORT ")
        and lines[1].startswith("BORROW_END_BINDING_EXPORT "),"complete author stdout")
    exported=json.loads(lines[0].split(" ",1)[1]);exported_binding=json.loads(lines[1].split(" ",1)[1])
    expected_rows=[dict(path=path,mode="100644",**fullpin(raw(graph/path))) for path in sorted(rows,key=Path)]
    require(exported==dict(status="EXACT_THREE_MECHANICAL_EDITS_AND_ALL_HIA_UNCHANGED",
        rows=expected_rows,hia_executed=False,rust_executed=False,public_async_qualified=False),"author full source export")
    require(exported_binding==dict(path=BINDING,utf8=raw(graph/BINDING).decode(),**fullpin(raw(graph/BINDING))),"author full exact binding export")
    return dict(status="COMPLETE_THREE_SOURCE_EDITS_INVERSE_AND_ACTUAL_AUTHOR_PASS",
        predecessor_files=530,current_files=len(rows),unchanged_hia_files=len(hia),
        repaired=sorted(CHANGED),all_before_bytes_bound=True,author_receipt=pin(root/"PROCESS.json"),
        native_or_rust_executed=False,public_async_qualified=False)
