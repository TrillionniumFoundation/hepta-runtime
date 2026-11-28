#!/usr/bin/env python3
"""Fixed-source POSIX path-guard acceleration for unchanged evidence controls.

The retained control source is never overwritten. Only its nested relocation
path guard is replaced in memory after whole-source and all-other-AST checks.
Every original mutation, reader call, refusal, relocation and byte comparison
is retained. The optional outer-call journal changes no reader arguments/results.
"""
from __future__ import annotations
import ast,copy,functools,hashlib,importlib.machinery,json,os,stat,textwrap,time
from pathlib import Path

CONTROL_SHA="aec910dc9f700e94d1f5e61910c9bd0afce35ba659ba02e2afe70adc2ca9493b"
QUALIFIER_SHA="2ffe915c28f5759444f473fe146b24743cb154600b8cbcdb7575d963b565d5e1"
TIMED=("native_evidence","original_evidence","retained_original",
       "retire_fixtures","retirement","private_state","build_controls")
FAST_GUARD=r'''def guard(fn,*,metadata=False):
    allowed_text=tuple(str(home) for home in allowed)
    blocked_text=tuple(str(home) for home in blocked_now)
    def within(value,home):
        # normpath preserves exactly two leading POSIX slashes as a distinct
        # anchor, just as pathlib.PosixPath does. Root "/" must not admit "//".
        if value.startswith("//") != home.startswith("//"):
            return False
        return value==home or value.startswith(home if home.endswith("/") else home+"/")
    def call(path,*pos,**kw):
        if isinstance(path,(str,bytes,os.PathLike)):
            current=os.path.abspath(os.fsdecode(path))
            current_copy=any(within(current,home) for home in allowed_text)
            traversal=metadata and any(within(home,current) for home in allowed_text)
            forbidden=any(within(current,home) for home in blocked_text)
            q.need(not forbidden or current_copy or traversal,
                   'relocated reader touched a producer path: '+current)
        return fn(path,*pos,**kw)
    return call
'''
def need(value,message):
    if not value:raise ValueError("fixed filesystem control guard: "+message)
def digest(raw):return hashlib.sha256(raw).hexdigest()
def encoded(value):return (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+"\n").encode()
def pin(path):
    raw=path.read_bytes();return {"bytes":len(raw),"sha256":digest(raw)}
def put(path,value):
    with path.open("xb") as stream:stream.write(encoded(value))
def transformed(source):
    raw=source.read_bytes()
    need(len(raw)==13411 and digest(raw)==CONTROL_SHA,"exact whole original control")
    old=ast.parse(raw);nodes=[x for x in ast.walk(old) if isinstance(x,ast.FunctionDef) and x.name=="guard"]
    need(len(nodes)==1,"one nested original relocation guard")
    node=nodes[0];lines=raw.decode().splitlines(keepends=True)
    before="".join(lines[node.lineno-1:node.end_lineno])
    need(before.startswith("        def guard("),"fixed nested guard indentation")
    replacement=textwrap.indent(FAST_GUARD,"        ")
    changed="".join(lines[:node.lineno-1])+replacement+"".join(lines[node.end_lineno:])
    new=ast.parse(changed)
    old_copy=copy.deepcopy(old);new_copy=copy.deepcopy(new)
    for tree in (old_copy,new_copy):
        guards=[x for x in ast.walk(tree) if isinstance(x,ast.FunctionDef) and x.name=="guard"]
        need(len(guards)==1,"unique replacement guard")
        guards[0].body=[ast.Pass()]
    need(ast.dump(old_copy,include_attributes=False)==ast.dump(new_copy,include_attributes=False),
         "every original control AST outside the mechanical guard is identical")
    # The source-defined loop fixes allowed/blocked_now before installing each
    # guard and restores all five APIs before changing those roots.
    loop=[x for x in ast.walk(old) if isinstance(x,ast.For)
          and isinstance(x.target,ast.Tuple) and [getattr(y,"id",None) for y in x.target.elts]==["root","output"]
          and isinstance(x.iter,ast.Name) and x.iter.id=="moved"]
    need(len(loop)==1,"fixed two-copy relocation loop")
    names={x.id for x in ast.walk(loop[0]) if isinstance(x,ast.Name) and isinstance(x.ctx,ast.Store)}
    need({"allowed","blocked_now"}<=names,"fixed roots belong to each relocation turn")
    proof={"schema":"hepta.history.filesystem-guard-transformation.v1",
           "original_source":pin(source),"executed_source":{"bytes":len(changed.encode()),"sha256":digest(changed.encode())},
           "old_guard":{"bytes":len(before.encode()),"sha256":digest(before.encode())},
           "new_guard":{"bytes":len(replacement.encode()),"sha256":digest(replacement.encode())},
           "all_other_ast_identical":True,"physical_original_source_modified":False,
           "original_control_labels":11,"original_physical_relocations":2,"original_foreign_path_refusals":12,
           "reader_results_cached":False,"file_bytes_skipped":False,"native_or_rust_executions":0}
    return changed,proof,node
def equivalence(source):
    _,proof,node=transformed(source)
    lifted=copy.deepcopy(node);ast.fix_missing_locations(lifted)
    oldcode=compile(ast.fix_missing_locations(ast.Module(body=[lifted],type_ignores=[])),"<original-guard>","exec")
    newcode=compile(FAST_GUARD,"<fixed-source-fast-guard>","exec")
    class Need:
        @staticmethod
        def need(value,message):
            if not value:raise ValueError(message)
    class Fspath:
        def __init__(self,value):self.value=value
        def __fspath__(self):return self.value
    homes=("/tmp/origin/source","/tmp/origin/output","/tmp/copies/one/source","/tmp/copies/one/output",
           "/tmp/copies/two/source","/tmp/copies/two/output","/dev/shm/original","//tmp/origin",
           "/","//","/tmp/other","/tmp/origin-old")
    spellings={"","/","//","///",".","..","a","../a","/tmp","/tmp/","/tmp/../tmp",
               "/tmp/originx","//tmp/origin","/dev/shm/original","/etc/hostname"}
    suffixes=("","/","/file","/nested/file","/../peer","/./file","//file","/\x00","/é","/\udcff")
    for home in homes:
        for suffix in suffixes:spellings.add(home+suffix)
    rows=[];counts={"accepted":0,"rejected":0,"cases":0};elapsed=[]
    root_sets=[
        ((homes[2],homes[3]),(homes[0],homes[1],homes[4],homes[5],homes[6])),
        ((homes[4],homes[5]),(homes[0],homes[1],homes[2],homes[3],homes[6])),
        (("//tmp/one/source","//tmp/one/output"),("//tmp/origin","/tmp/origin")),
        (("/","/tmp/output"),("//","/tmp/origin")),
        (("//","//tmp/output"),("/","//tmp/origin")),
    ]
    for roots,blocked in root_sets:
        for metadata in (False,True):
            spaces=[]
            for code in (oldcode,newcode):
                namespace={"os":os,"Path":Path,"q":Need,
                           "allowed":tuple(map(Path,roots)),"blocked_now":tuple(map(Path,blocked))}
                exec(code,namespace);spaces.append(namespace)
            for text in sorted(spellings):
                variants=(text,os.fsencode(text),Path(text),Fspath(text),Fspath(os.fsencode(text)))
                for variant_index,value in enumerate(variants):
                    outcomes=[]
                    for namespace in spaces:
                        calls=[]
                        def actual(path,*args,**kwargs):
                            calls.append((path,args,kwargs));return ("delegated",)
                        fn=namespace["guard"](actual,metadata=metadata)
                        t=time.monotonic_ns()
                        try:result=fn(value,7,follow_symlinks=False);outcome=("return",result)
                        except BaseException as error:outcome=("error",type(error).__name__,str(error))
                        elapsed.append(time.monotonic_ns()-t)
                        outcomes.append((outcome,len(calls),calls[0][1:] if calls else None))
                    need(outcomes[0]==outcomes[1],"complete original/new guard decision and delegate arguments")
                    counts["cases"]+=1;counts["accepted" if outcomes[0][0][0]=="return" else "rejected"]+=1
                    rows.append({"roots":list(roots),"blocked":list(blocked),"metadata":metadata,
                                 "path":text,"representation":variant_index,"outcome":outcomes[0][0],
                                 "delegate_count":outcomes[0][1]})
            for value in (0,1,-1,True,False,None,1.5):
                actual=lambda *args,**kwargs:("delegated",type(args[0]).__name__,repr(args[0]),args[1:],kwargs)
                a=spaces[0]["guard"](actual,metadata=metadata)(value,9,follow_symlinks=False)
                b=spaces[1]["guard"](actual,metadata=metadata)(value,9,follow_symlinks=False)
                need(a==b,"non-path input delegation unchanged")
                counts["cases"]+=1;counts["accepted"]+=1
                rows.append({"roots":list(roots),"blocked":list(blocked),"metadata":metadata,
                             "non_path_type":type(value).__name__,"value":repr(value),"outcome":a})
    return {"schema":"hepta.history.filesystem-guard-equivalence.v1","status":"PASS",
            **counts,"source":proof,"complete_rows":rows,"native_or_rust_executions":0,
            "old_guard_ns":sum(elapsed[0::2]),"new_guard_ns":sum(elapsed[1::2])}
def run_original(source,destination):
    changed,proof,_=transformed(source)
    adapted=destination/"filesystem-control-adapted.py"
    with adapted.open("xb") as stream:stream.write(changed.encode())
    put(destination/"FILESYSTEM_GUARD_BINDING.json",proof)
    journal=destination/"filesystem-reader-calls.jsonl"
    real=importlib.machinery.SourceFileLoader.exec_module
    sequence=[0];stack=[]
    with journal.open("xb",buffering=0) as stream:
        def emit(value):
            raw=(json.dumps(value,sort_keys=True,allow_nan=False)+"\n").encode()
            view=memoryview(raw)
            while view:
                n=stream.write(view);need(type(n)is int and n>0,"complete observer journal write");view=view[n:]
        def loader(self,module):
            real(self,module)
            filename=getattr(module,"__file__",None)
            if not filename or Path(filename).name!="hia_native_filesystem_parity_qualification.py":
                return
            need(pin(Path(filename))["sha256"]==QUALIFIER_SHA,"exact qualifier before timing wrapper")
            for name in TIMED:
                fn=getattr(module,name)
                def wrap(original,label):
                    @functools.wraps(original)
                    def call(*args,**kwargs):
                        sequence[0]+=1;seq=sequence[0];start=time.monotonic_ns()
                        parent=stack[-1] if stack else None
                        roots=[str(v) for v in args[:2] if isinstance(v,(str,os.PathLike))]
                        emit({"event":"begin","sequence":seq,"parent_sequence":parent,"name":label,
                              "module":filename,"module_sha256":QUALIFIER_SHA,"roots":roots,
                              "pid":os.getpid(),"time_ns":start})
                        stack.append(seq);error=None
                        try:return original(*args,**kwargs)
                        except BaseException as exc:
                            error={"type":type(exc).__name__,"message":str(exc)};raise
                        finally:
                            need(stack.pop()==seq,"observer nesting")
                            emit({"event":"end","sequence":seq,"parent_sequence":parent,"name":label,
                                  "pid":os.getpid(),"elapsed_ns":time.monotonic_ns()-start,"error":error})
                    return call
                setattr(module,name,wrap(fn,name))
        importlib.machinery.SourceFileLoader.exec_module=loader
        try:
            namespace={"__name__":"__main__","__file__":str(source),"__package__":None,"__spec__":None}
            exec(compile(changed,str(source),"exec"),namespace)
        finally:
            importlib.machinery.SourceFileLoader.exec_module=real
    need(not stack,"all observer calls completed")
    return {**proof,"journal":pin(journal),"actual_reader_calls":sequence[0],
            "coarse_call_observer_only":True,"qualifier_source_sha256":QUALIFIER_SHA}
