"""Exact original verifier, with only its outer row iterator partitioned before guarding."""
from pathlib import Path
import ast,copy,hashlib,math,os,sys,time
import recovery_common as rc

def frozen_source(root,expected):
    raw=rc.read(root/"SOURCE.json");rc.check(rc.pin(raw)==expected,"complete retained physical source manifest")
    source=rc.loads(raw)
    rc.check(set(rc.files(root))==set(source["files"])|{"SOURCE.json"},"whole retained reader source set")
    for n,r in source["files"].items():
        b=rc.read(root/n)
        rc.check(rc.pin(b)=={k:r[k] for k in ("bytes","sha256")} and
                 hashlib.sha1(b"blob "+str(len(b)).encode()+b"\0"+b).hexdigest()==r["git_blob"],"every retained reader Git byte")
    return rc.pin(raw)["sha256"]

def prepare(complete):
    identity=rc.source();binding=rc.loads(rc.read(rc.ROOT/"PINS.json"))
    frozen=complete/"source";old_identity=frozen_source(frozen,binding["source_manifests"]["source/SOURCE.json"])
    sys.path.insert(0,str(frozen))
    import physical_common as pc,bundle,physical_controls,physical_parallel,mutations,entry
    rc.check(pc.ROOT==frozen,"exact already admitted physical reader root")
    old=bundle.prepare(complete/"retained/restored/prior/source")
    rc.check(old["identity"]==old_identity==binding["source_sha256"],"entire unchanged retained reader and controls")
    raw=rc.read(frozen/"physical_controls.py")
    rc.check(rc.pin(raw)==dict(bytes=7319,sha256="6d1143360069fee14bc27c0b8054b99b28cdb1b1a6ca5e6576cfc577d6efda62"),
             "exact original complete physical verifier")
    module=ast.parse(raw);original=next(n for n in module.body if isinstance(n,ast.FunctionDef) and n.name=="verify")
    transformed=copy.deepcopy(original);loops=[n for n in transformed.body if isinstance(n,ast.For)]
    rc.check(len(loops)==1,"one exact original outer row iteration")
    loop=loops[0];prior=copy.deepcopy(loop.iter)
    expected=ast.parse("zip((*ADMISSIONS,*mutations.NAMES),report['rows'],strict=True)",mode="eval").body
    rc.check(ast.dump(prior,include_attributes=False)==ast.dump(expected,include_attributes=False),"exact source-bound outer iterator")
    loop.iter=ast.Call(func=ast.Name(id="_selected_pairs",ctx=ast.Load()),args=[ast.Name(id="report",ctx=ast.Load())],keywords=[])
    restored=copy.deepcopy(transformed)
    next(n for n in restored.body if isinstance(n,ast.For)).iter=prior
    rc.check(ast.dump(restored,include_attributes=False)==ast.dump(original,include_attributes=False),
             "every verifier statement including complete per-row body remains identical")
    compiled=compile(ast.fix_missing_locations(ast.Module(body=[transformed],type_ignores=[])),
                     str(rc.ROOT/"read_adapter.py")+"::source_bound_outer_iterator","exec")
    all_names=(*physical_controls.ADMISSIONS,*mutations.NAMES)
    partitions=physical_parallel.parts(physical_controls.ADMISSIONS,mutations.NAMES)
    functions=[]
    for names in partitions:
        indices=tuple(all_names.index(n) for n in names)
        def selected(report,indices=indices,names=names):
            rc.check(len(report["rows"])==len(all_names),"full retained row domain before selection")
            return zip(names,(report["rows"][i] for i in indices),strict=True)
        namespace=dict(vars(physical_controls));namespace["_selected_pairs"]=selected
        exec(compiled,namespace);functions.append(namespace["verify"])
    transform=dict(before_ast=rc.pin(ast.dump(original,include_attributes=False).encode()),
                   after_ast=rc.pin(ast.dump(transformed,include_attributes=False).encode()),
                   inverse_ast_exact=True,only_replaced_node="one outer row iterator",
                   whole_per_row_body_exact=True,all_other_statements_exact=True)
    return dict(identity=identity,binding=binding,complete=complete,old=old,pc=pc,entry=entry,physical=physical_controls,
                old_identity=old_identity,all_names=all_names,partitions=partitions,functions=functions,transform=transform)

def failed_verification(output,physical_process,pc):
    rows=pc.loads(pc.read(output/"processes/verify/processes.json"))
    rc.check(len(rows)==1,"one preserved failed serial reader")
    row=rows[0];old=pc.loads(pc.read(output/"physical/CONTROLS.json"))
    rc.check(row["name"]=="publisher-verify" and row["argv"]==[physical_process["argv"][0],"-I","-B",old["source_root"]+"/entry.py",
        "--retained",old["retained_root"],"--output",old["output_root"].rsplit("/",1)[0],"--phase","verify"] and
        row["cwd"]==old["source_root"] and row["stdin"] is None and type(row["exit_code"]) is int and row["exit_code"]==-9 and
        row["completed"] is False and row["timed_out"] is True and type(row["timeout_seconds"]) is int and row["timeout_seconds"]==180 and
        type(row["elapsed_seconds"]) in (int,float) and math.isfinite(row["elapsed_seconds"]) and row["elapsed_seconds"]>=180,
        "original serial 180-second timeout remains FAIL")
    rc.check(all(type(row[k]) is int and row[k]>1 for k in ("pid","parent_pid","pgid")) and
             row["pid"]==row["pgid"]!=row["parent_pid"],"preserved actual failed reader PID chain")
    for kind in ("stdout","stderr"):
        name="publisher-verify."+kind;raw=pc.read(output/"processes/verify"/name)
        rc.check(row[kind]==dict(file=name,**rc.pin(raw)) and raw==b"","complete preserved failed reader streams")
    rc.check(set(pc.files(output/"processes/verify"))=={"processes.json","publisher-verify.stdout","publisher-verify.stderr"} and
             not (output/"GATE.json").exists() and not (output/"READBACK.json").exists(),"no retrospective PASS report")
    return row

def verify_partition(prepared,part,parent_file):
    complete=prepared["complete"];pc=prepared["pc"];parent_raw=rc.read(parent_file);parent=rc.loads(parent_raw)
    rc.check(type(part) is int and part in (0,1),"fixed pure-reader partition")
    def operation():
        rc.check(rc.source()==prepared["identity"],"all current source bytes inside strict reader guard")
        rc.check(rc.pin(rc.read(parent_file))==rc.pin(parent_raw) and
                 parent["source_root"]==str(rc.ROOT) and parent["complete_root"]==str(complete) and
                 parent["source_manifest_sha256"]==prepared["identity"] and parent["pid"]==os.getppid() and
                 parent["pgid"]==os.getpgrp(),"actual private parent input binding inside guard")
        retained=complete/"retained";output=complete/"run"
        process=prepared["entry"].custody(output)
        full_scope=prepared["functions"][part](retained,output/"physical",prepared["old"])
        failed=failed_verification(output,process,pc)
        return dict(status="PUBLISHER_PHYSICAL_PART_READ_PASS",part=part,checked_names=list(prepared["partitions"][part]),
                    full_retained_scope=full_scope,physical_process=process,failed_verification=failed,
                    source_manifest_sha256=prepared["identity"],retained_source_sha256=prepared["old_identity"],
                    source_transform=prepared["transform"],parent_evidence=rc.pin(parent_raw),
                    native_or_rust_executions=0,reader_writes=0)
    return prepared["old"]["guard"].guarded(operation,roots=[complete,rc.ROOT,parent_file.parent],
                 foreign_path="/original-producer-not-admitted/CAPTURE.json")
