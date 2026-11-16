#!/usr/bin/env python3
"""Re-admit unchanged 08ce evidence with the single reviewed prefix correction.

Actual Git metadata is captured before and rechecked after the guarded reader.
Inside it, only those complete responses and existing-directory mkdir no-ops
are replayed. The report, source pins, native images and all process evidence
remain byte-identical. This does not relabel the original failed workflow.
"""
from __future__ import annotations
import argparse,ast,base64,bz2,copy,ctypes,decimal,fcntl,fnmatch,gzip,hashlib,importlib,importlib.util
import io,json,lzma,math,mmap,os,pickle,platform,re,resource,shutil,stat,struct,subprocess
import sys,sysconfig,tarfile,tempfile,time,traceback,unittest,unittest.mock,zipfile,zlib
from pathlib import Path
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
import read_only_guard as guard

ORIGINAL_SHA="2ec6aca31ade229cdf853bf8c1bf57486f0fc87d443f490b8ae01fafc4ddae8e"
FIX_SHA="aa988767938f4fb1613fabe5defd1ea705a1381213add91476b98554ad40c493"
REPORT_SHA="6159169d8c0763d2418c8f625e5cd67099a06179f69927f7a1e62972a1eafa41"
SOURCE=Path("/home/runner/work/_temp/hia-historical-public58")
CAPTURE=Path("/home/runner/work/_temp/hia-runtime-native")
COMPILER=Path("/home/runner/work/hepta-runtime/hepta-runtime/compiler")
PYTHON=Path("/home/runner/work/_temp/hia-native-python/bin/python3")
CONTROLS=("result-values-evidence-controls","public-registry-evidence-controls","result-storage-evidence-controls")
NAME="public_registry_control_evidence"

def need(value,label):
    if not value:raise ValueError(label)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def encoded(value):return (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+"\n").encode()
def put(path,value):
    with path.open("xb") as f:f.write(encoded(value))
def pin(path):
    raw=path.read_bytes();return {"bytes":len(raw),"sha256":sha(raw)}
def plain(value):
    if isinstance(value,bytes):return {"encoding":"base64","bytes":len(value),"sha256":sha(value),"data":base64.b64encode(value).decode()}
    return value

class MechanicalReads:
    def __init__(self,source,compiler):
        self.source=source;self.compiler=compiler;self.real_run=subprocess.run
        self.cache={};self.records=[];self.replays=[];self.noop_mkdir=[];self.violations=[]
        self.phase="capture"
    def key(self,args,kwargs):
        need(len(args)==1 and isinstance(args[0],(list,tuple)),"one explicit argv")
        argv=list(args[0]);need(all(type(x)is str for x in argv),"string argv")
        allowed=[["git","-C",str(self.source),"rev-parse","--show-toplevel"],
                 ["git","-C",str(self.source),"rev-parse","HEAD"],
                 ["git","-C",str(self.compiler),"rev-parse","HEAD"],
                 ["git","-C",str(self.compiler),"rev-parse","HEAD^{tree}"]]
        contract=self.compiler/"docs/HIA_SELFHOST_CORE_SUPPORT.json"
        cold=json.loads(contract.read_bytes())["source_identity"]["files"]
        allowed.append(["git","-C",str(self.compiler),"ls-tree","-rz","HEAD","--","hepta","tools",
                        "examples/hia_bootstrap",contract.relative_to(self.compiler).as_posix(),
                        *[":(literal)"+name for name in cold]])
        need(argv in allowed,"undeclared metadata process")
        need(set(kwargs)<= {"capture_output","text","timeout","check","stdout","stderr"},"metadata kwargs")
        if argv[2]==str(self.source):
            need(kwargs=={"capture_output":True,"text":True,"timeout":15},"source Git metadata contract")
        else:
            need(kwargs=={"check":True,"stdout":subprocess.PIPE,"stderr":subprocess.PIPE,"timeout":30},
                 "compiler Git metadata contract")
        return json.dumps([argv,kwargs],sort_keys=True)
    def run(self,*args,**kwargs):
        try:key=self.key(args,kwargs)
        except BaseException:
            self.violations.append("undeclared-process");raise
        if self.phase=="capture":
            begin=time.monotonic_ns();result=self.real_run(*args,**kwargs);elapsed=time.monotonic_ns()-begin
            need(elapsed<=kwargs["timeout"]*1000000000,"metadata process deadline")
            record={"argv":list(args[0]),"kwargs":kwargs,"returncode":result.returncode,
                    "stdout":plain(result.stdout),"stderr":plain(result.stderr),"elapsed_ns":elapsed}
            if key in self.cache:
                old=self.cache[key];need((old.returncode,old.stdout,old.stderr)==
                    (result.returncode,result.stdout,result.stderr),"metadata response changed")
            else:self.cache[key]=result
            self.records.append(record);return result
        if key not in self.cache:
            self.violations.append("uncaptured-metadata");raise PermissionError("unretained metadata request")
        self.replays.append(key);v=self.cache[key]
        return subprocess.CompletedProcess(copy.deepcopy(v.args),v.returncode,v.stdout,v.stderr)
    def mkdir(self,path,mode=0o777,parents=False,exist_ok=False):
        target=Path(path).absolute()
        try:
            need(exist_ok is True,"create-only directory request in reader")
            need(target.is_relative_to(CAPTURE) and target.resolve(strict=True)==target
                 and stat.S_ISDIR(target.lstat().st_mode),"only existing owned directory")
        except BaseException:
            self.violations.append("directory-create");raise
        self.noop_mkdir.append({"path":str(target),"mode":mode,"parents":parents,"exist_ok":exist_ok})
        return None

def source_function(old,new):
    need(sha(old)==ORIGINAL_SHA and sha(new)==FIX_SHA,"exact old/repaired whole comparator")
    a=ast.parse(old);b=ast.parse(new)
    ax=[x for x in a.body if isinstance(x,ast.FunctionDef) and x.name==NAME]
    bx=[x for x in b.body if isinstance(x,ast.FunctionDef) and x.name==NAME]
    need(len(ax)==len(bx)==1,"unique reviewed helper")
    a.body.remove(ax[0]);b.body.remove(bx[0])
    need(ast.dump(a,include_attributes=False)==ast.dump(b,include_attributes=False),"unreviewed code difference")
    return ax[0],bx[0]

def external_paths(fix):
    roots={Path(sysconfig.get_path("stdlib")).resolve(),Path(sysconfig.get_path("purelib")).resolve()}
    files={fix.absolute(),Path(__file__).absolute(),Path(guard.__file__).absolute(),PYTHON,PYTHON.resolve()}
    for root in roots:
        for folder,dirs,names in os.walk(root,followlinks=False):
            dirs[:]=[n for n in dirs if not (Path(folder)/n).is_symlink()]
            for name in names:
                path=Path(folder)/name
                try:regular=path.resolve(strict=True).is_file()
                except (OSError,RuntimeError):regular=False
                if regular:
                    files.add(path.absolute());files.add(path.resolve())
                    if path.suffix==".py":
                        files.add(Path(importlib.util.cache_from_source(str(path))).absolute())
    # Importlib may probe absent cache files even with bytecode writes disabled.
    # Admit only each exact cache path of a retained Python source and bind its
    # absence (or complete bytes) before and after the read-only operation.
    for root in (SOURCE,COMPILER):
        for path in root.rglob("*.py"):
            if path.is_file() and not path.is_symlink():
                files.add(Path(importlib.util.cache_from_source(str(path))).absolute())
    for name in ("git","as","ld","objcopy","strace","tar","rustc","cargo","rustup"):
        value=shutil.which(name)
        if value:files.add(Path(value).absolute());files.add(Path(value).resolve())
    rustbin=Path("/home/runner/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin")
    need(rustbin.is_dir(),"exact retained compiler bytes must be present")
    for path in rustbin.iterdir():
        if path.resolve().is_file():files.add(path.absolute());files.add(path.resolve())
    return sorted(files,key=str)

def main():
    p=argparse.ArgumentParser();p.add_argument("--fix",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True);a=p.parse_args()
    destination=a.output.absolute();destination.mkdir(mode=0o700,parents=True,exist_ok=False)
    started=time.monotonic_ns()
    need(Path(sys.executable)==PYTHON,"restore the exact recorded Python invocation path")
    report_bytes=(CAPTURE/"result.json").read_bytes();need(sha(report_bytes)==REPORT_SHA,"original failed report bytes")
    report=json.loads(report_bytes);need(report["status"]=="FAIL" and report["phase"]=="original_collect"
        and report["error"]=={"type":"ValueError","message":"public evidence controls did not observe the complete prior process set"},
        "retain the original final reader failure")
    need(len(report["checks"])==405 and len(report["original_rust_comparisons"])==81
         and [x["name"] for x in report["checks"][-3:]]==list(CONTROLS),"complete actual process/recipe set")
    need(all(x["exit_code"]==0 and x["timed_out"] is False and x["timeout_seconds"]==180
         for x in report["checks"][-3:]),"all three actual controls retain original limits")
    original=(SOURCE/"scripts/compare_hia_runtime_rust.py").read_bytes();fix=a.fix.resolve(strict=True)
    old_node,new_node=source_function(original,fix.read_bytes())
    sys.path.insert(0,str(SOURCE/"scripts"))
    import compare_hia_runtime_rust as r
    import qualify_hia_runtime_native as q
    import hia_native_build as build
    need(r.ROOT==q.ROOT==SOURCE and q.sources()==report["source_sha256"],"complete original source closure")
    need(report["compiler_checkout"]==str(COMPILER),"original compiler checkout path")
    bootstrap=CAPTURE/"build/bootstrap/bootstrap.json"
    need(bootstrap.is_file() and not bootstrap.is_symlink(),"cached bootstrap receipt required before reader setup")
    for label in ("B1","B2","B3"):
        need(pin(bootstrap.with_name(label+".image.bin"))["sha256"]==report["compiler_image_sha256"],
             "all three retained compiler images required")
    adapters=MechanicalReads(SOURCE,COMPILER)
    real_run=subprocess.run;real_mkdir=Path.mkdir
    subprocess.run=adapters.run
    Path.mkdir=lambda path,mode=0o777,parents=False,exist_ok=False:adapters.mkdir(path,mode,parents,exist_ok)
    proof=None
    try:
        actual_head=q.git_head();need(actual_head is None and report["checkout_head"] is None,"materialized source is not a Git checkout")
        builder=build.NativeBuild(COMPILER,CAPTURE/"build");compiler_path=builder.bootstrap()
        need(pin(compiler_path)["sha256"]==report["compiler_image_sha256"],"retained B3 identity")
        dependency=copy.deepcopy(builder.identity)
        adapters.phase="replay"
        old=r.public_registry_control_evidence
        namespace=dict(r.__dict__)
        module=ast.Module(body=[new_node],type_ignores=[]);ast.fix_missing_locations(module)
        exec(compile(module,str(fix),"exec"),namespace)
        replacement=namespace[NAME]
        need(replacement.__name__==NAME,"one fixed helper binding")
        r.public_registry_control_evidence=replacement
        def operation():
            try:old(CAPTURE,report)
            except ValueError as error:
                need(str(error)=="public evidence controls did not observe the complete prior process set",
                     "the retained old failure must be the known prefix bug")
            else:raise ValueError("old comparator unexpectedly admitted the retained later-control tail")
            r.check_input_pins(CAPTURE,report)
            need(sha((CAPTURE/"result.json").read_bytes())==REPORT_SHA,"failed report was modified")
            need(not adapters.violations,"mechanical reader adapter had an undeclared operation")
            return {"status":"COMPLETE_RETAINED_AGGREGATE_READBACK_PASS","original_status":"FAIL",
                "original_report_sha256":REPORT_SHA,"actual_checks":405,"recipes":81,
                "preserved_controls":list(CONTROLS),"old_prefix_refusal_reproduced":True,
                "changed_function":NAME,"original_comparator_sha256":ORIGINAL_SHA,"fixed_comparator_sha256":FIX_SHA,
                "all_other_comparator_ast_identical":True,"source_pins_rebound":False,
                "original_failure_reclassified_as_pass":False,"native_or_rust_executions":0}
        proof=guard.guarded(operation,roots=[CAPTURE,SOURCE,COMPILER],
            foreign_path=Path("/etc/hostname"),external_files=external_paths(fix))
        need(not adapters.violations,"no adapter violation")
        adapters.phase="capture"
        need(q.git_head()==actual_head and build.check_dependency(COMPILER)==dependency,"real metadata changed after full reader")
    finally:
        subprocess.run=real_run
        Path.mkdir=real_mkdir
        if "old" in locals():r.public_registry_control_evidence=old
        put(destination/"MECHANICAL_READS.json",{"records":adapters.records,"replayed_metadata":adapters.replays,
            "existing_directory_noops":adapters.noop_mkdir,"violations":adapters.violations,
            "native_or_rust_executions":0,"actual_git_metadata_only":True})
    need(proof is not None,"guarded reader did not complete")
    need(q.sources()==report["source_sha256"],"complete source closure changed after guard")
    for key in ("before","after","external_before","external_after"):
        with gzip.open(destination/(key+".json.gz"),"xb",compresslevel=1) as f:f.write(encoded(proof[key]))
    small={k:v for k,v in proof.items() if k not in ("before","after","external_before","external_after")}
    small.update(elapsed_ns=time.monotonic_ns()-started,full_snapshot_entries=len(proof["before"]),
        external_snapshot_entries=len(proof["external_before"]),
        original_report=pin(CAPTURE/"result.json"),original_source=pin(SOURCE/"scripts/compare_hia_runtime_rust.py"),
        fixed_reader=pin(fix),metadata_actual_calls=len(adapters.records),metadata_replayed_calls=len(adapters.replays),
        existing_directory_noops=len(adapters.noop_mkdir),source_after=q.sources(),
        whole_runtime_replaced=False,production_activated=False,old_stack_removal_qualified=False)
    put(destination/"READBACK.json",small)
    print(json.dumps({k:small[k] for k in ("schema","elapsed_ns","full_snapshot_entries","external_snapshot_entries",
        "metadata_actual_calls","metadata_replayed_calls","existing_directory_noops","evidence")},sort_keys=True))
if __name__=="__main__":main()
