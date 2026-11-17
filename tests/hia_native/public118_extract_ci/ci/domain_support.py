"""Path-independent admission and process custody for the split fixed-budget jobs."""
from pathlib import Path
from contextlib import contextmanager
from functools import lru_cache
import hashlib,importlib.util,json,os,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from common import command,pin,put,require
from source_check import source
from read_all import inventory,recorded_command
KEYS=("git_head","run_id","run_attempt")
def doc(path):return json.loads(Path(path).read_bytes())
def check_dependency(package,root,receipt,manifest_sha256,identity,expected_label):
    root=Path(root).resolve(strict=True)
    value=doc(receipt) if isinstance(receipt,(str,Path)) else receipt
    require(value["label"]==expected_label and value["source_manifest_sha256"]==manifest_sha256
        and value["qualification_inferred_from_archive"] is False
        and value["captured_tree_modified_by_export"] is False,"dependency source/scope")
    require(all(type(value[k]) is str and value[k] and value[k]==identity[k] for k in KEYS),
        "dependency belongs to a different CI attempt")
    archive=inventory(root,value["manifest"])
    require(source(root/"ci-package",manifest_sha256)==source(package,manifest_sha256),
        "complete dependency source differs")
    declaration=doc(root/"CI_SOURCE_DECLARATION.json")
    require(declaration["label"]==expected_label and declaration["manifest_sha256"]==manifest_sha256
        and all(declaration[k]==identity[k] for k in KEYS),"complete dependency declaration")
    return {"receipt":value,"archive":archive}
def begin(package,output,manifest_sha256,label,dependencies,details=None):
    package=Path(package).resolve(strict=True);out=Path(output).absolute()
    require(os.environ.get("GITHUB_ACTIONS")=="true","fresh original/native work is CI-only")
    require(not out.exists(),"new job output already exists")
    admitted=source(package,manifest_sha256,syntax=True)
    out.mkdir(parents=True)
    origin={"schema":"hepta.runtime.public111.split-job.v1","label":label,
        "package":str(package),"output":str(out),"manifest_sha256":manifest_sha256,
        "python":sys.executable,"pid":os.getpid(),"source_admission":admitted,
        "git_head":os.environ.get("GITHUB_SHA"),"run_id":os.environ.get("GITHUB_RUN_ID"),
        "run_attempt":os.environ.get("GITHUB_RUN_ATTEMPT"),"workflow_job_limit_minutes":15,
        "new_outer_timeout":False,"full_sdk_qualified":False,"full_async_qualified":False}
    details=details or {}
    require(not set(details)&set(origin),"job details cannot replace fixed origin")
    origin.update(details)
    origin["dependencies"]={name:str(Path(pair[0]).resolve(strict=True)) for name,pair in dependencies.items()}
    dep={}
    for name,(root,receipt) in dependencies.items():
        dep[name]={"root":str(Path(root).resolve(strict=True)),
            **check_dependency(package,root,receipt,manifest_sha256,origin,name)}
    put(out/"ORIGIN.json",origin);put(out/"DEPENDENCIES.json",dep)
    return package,out,origin
def check_origin(package,run,manifest_sha256,label,dependencies):
    origin=doc(run/"ORIGIN.json")
    require(origin["schema"]=="hepta.runtime.public111.split-job.v1" and origin["label"]==label
        and origin["manifest_sha256"]==manifest_sha256
        and origin["source_admission"]==source(package,manifest_sha256)
        and origin["workflow_job_limit_minutes"]==15 and origin["new_outer_timeout"] is False
        and origin["full_sdk_qualified"] is False and origin["full_async_qualified"] is False,
        "complete fixed-budget job origin")
    declared=doc(run/"DEPENDENCIES.json")
    require(set(declared)==set(dependencies),"job dependency inventory")
    for name,root in dependencies.items():
        current=check_dependency(package,root,declared[name]["receipt"],manifest_sha256,origin,name)
        require(current=={k:declared[name][k] for k in ("receipt","archive")},"dependency declaration changed")
    return origin
def record_process(run,label,command):
    origin=doc(run/"ORIGIN.json")
    return recorded_command(run,label,command,origin["output"])
@lru_cache(maxsize=None)
def load(name,path):
    path=Path(path).resolve(strict=True)
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
@contextmanager
def isolated(names):
    saved={n:sys.modules.pop(n,None) for n in names};paths=list(sys.path)
    try:yield
    finally:
        sys.path[:]=paths
        for name,value in saved.items():
            sys.modules.pop(name,None)
            if value is not None:sys.modules[name]=value
@contextmanager
def selected(modules,names):
    with isolated(names):
        sys.modules.update(modules)
        yield
def finish(package,run,manifest_sha256,role,arguments):
    py=[sys.executable,"-I","-S","-B"]
    command(run,"readonly-role",py+[str(package/"ci/read_domains.py"),"--role",role,
        "--package",str(package),"--run",str(run),"--manifest-sha256",manifest_sha256,*map(str,arguments)])
    guarded=doc(run/"processes/readonly-role.stdout")
    require(guarded["read_only"]["before"]==guarded["read_only"]["after"]
        and len(guarded["read_only"]["probes"])==11
        and guarded["read_only"]["reader_writes"]==guarded["read_only"]["native_or_rust_executions"]==0,
        "complete role reader was not read-only")
    put(run/"QUALIFICATION.json",guarded["qualification"])
    print(json.dumps(guarded["qualification"],sort_keys=True,allow_nan=False))

def graph_identity(proof):
    """Retain portable identities after the full raw graph reader succeeds."""
    require(proof["runtime_hia_images"]==111 and proof["fresh_direct_members"]==103
        and proof["packed_hia_members"]==8 and proof["physical_containers"]==104
        and proof["actual_default_entry"] is True,"complete default graph identity")
    entries={}
    for name,row in proof["entries"].items():
        entries[name]={k:v for k,v in row.items() if k not in ("elf","manifest")}
        for kind in ("elf","manifest"):
            entries[name][kind]={k:row[kind][k] for k in ("bytes","sha256")}
    require(set(entries)=={"production","journal","trace","instances"},"all four actual carriers")
    return {"source":proof["source"],"runtime_hia_images":111,"fresh_direct_members":103,
        "packed_hia_members":8,"physical_containers":104,"actual_default_entry":True,
        "installed_source_before_after_equal":proof["installed_source_before_after_equal"],
        "shape_admission_controls":proof["shape_admission_controls"],
        "shape_source_proof":proof["shape_source_proof"],"entries":entries,
        "complete_raw_graph_reader_ran":True,"native_or_rust_executed":False}
