"""Only physical retained reads; no native mapping, syscall, or Rust execution."""
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT))
import physical_common as pc

def prepare(original):
    identity=pc.source();sys.path.insert(0,str(ROOT/"controls"))
    import execute
    control_identity,owner,transport,transport_reader=execute.prepare(original)
    pc.check(control_identity=="febe3ccf961a1449536b73c51dddace7adaff69a55ed69c4fbb3639bb077f47b","entire immutable passed control source")
    import read_capture,read_callable,read_only_guard,verify_controls
    import gzip,math,re,struct,hashlib,copy
    return dict(identity=identity,original=original,control_identity=control_identity,owner=owner,transport=transport_reader,
                semantic=read_capture,callable=read_callable,guard=read_only_guard,custody=verify_controls.process_custody)

def files(root,exclude=()):
    return {n:r for n,r in pc.files(root).items() if n not in exclude}

def copy_files(source,target):
    admitted=pc.files(source);target.mkdir(parents=True,exist_ok=False)
    for name,row in admitted.items():
        raw=pc.read(source/name);pc.check(pc.pin(raw)=={k:row[k] for k in ("bytes","sha256")},"entire admitted copy input")
        dest=target/name;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(raw);dest.chmod(row["mode"])
        a=(source/name).stat();b=dest.stat();pc.check((a.st_dev,a.st_ino)!=(b.st_dev,b.st_ino),"independent physical inode")
    pc.check(pc.files(target)==admitted,"complete independently copied bytes and modes")
    return admitted

def make_bundle(retained,target):
    target.mkdir(parents=True,exist_ok=False)
    copy_files(retained/"restored/prior/run/semantic",target/"semantic")
    for n in ("owner-controls","transport-controls"):copy_files(retained/"control-run"/n,target/n)
    for n in ("owner","transport"):copy_files(retained/"control-run/processes"/n,target/"processes"/n)
    meta=dict(schema="hepta.audit-anchor-publish.retained-bundle.v1",
              original_source_sha256="5108ee26b26723f601207fe15fa849f6b4f07b80aa0b752574792062c49010a9",
              control_source_sha256="febe3ccf961a1449536b73c51dddace7adaff69a55ed69c4fbb3639bb077f47b",
              ordinary_replay=False,files=pc.files(target))
    (target/"BUNDLE.json").write_bytes(pc.enc(meta))
    return meta

def verify(target,prepared):
    pc.check(pc.source()==prepared["identity"],"every frozen physical-reader source inside guard")
    m=pc.loads(pc.read(target/"BUNDLE.json"))
    pc.check(m["schema"]=="hepta.audit-anchor-publish.retained-bundle.v1" and
             m["original_source_sha256"]=="5108ee26b26723f601207fe15fa849f6b4f07b80aa0b752574792062c49010a9" and
             m["control_source_sha256"]==prepared["control_identity"] and m["ordinary_replay"] is False and
             files(target,("BUNDLE.json",))==m["files"],"entire source-bound retained evidence bundle")
    capture=target/"semantic"
    processes=prepared["custody"](target)
    semantic=prepared["semantic"].verify(capture)
    observed=prepared["callable"].verify(capture/"native-observed-normal",semantic["fresh_build"]["image"],observed=True,group="normal")
    owner=prepared["owner"].verify(target/"owner-controls",capture,capture/"build/modules/audit-anchor-publish/manifest.json")
    transport=prepared["transport"].verify(target/"transport-controls",semantic["fresh_build"]["image"],observed)
    # Reports are JSON values: the unchanged reader returns effect_kinds as tuples in memory.
    # Round-trip only this already verified report, never source, requests, buffers, or evidence.
    return pc.loads(pc.enc(dict(status="PUBLISHER_SEMANTIC_AND_ABI_CONTROLS_PASS",semantic=semantic,owner_controls=owner,transport_controls=transport,
                control_processes=processes,control_source_sha256=prepared["control_identity"],native_or_rust_executions=0,reader_writes=0)))

def roots(target,prepared):
    return [target,prepared["original"],ROOT]

def custody(retained,baseline):
    """Read the passed control verification process, all proof bytes, and original archive immutability."""
    import math
    control=retained/"control-run";proof=pc.loads(pc.read(control/"READBACK.json"));gate=pc.loads(pc.read(control/"GATE.json"))
    rows=pc.loads(pc.read(control/"processes/verify/processes.json"))
    pc.check(len(rows)==1 and set(pc.files(control/"processes/verify"))==
             {"processes.json","publisher-verify.stdout","publisher-verify.stderr"},"one complete retained pure verification process")
    row=rows[0];old_source=baseline["control_processes"]["owner"]["cwd"]
    old_prior=baseline["control_processes"]["owner"]["argv"][5];old_out=baseline["control_processes"]["owner"]["argv"][7].rsplit("/",1)[0]
    pc.check(row["argv"]==[baseline["control_processes"]["owner"]["argv"][0],"-I","-B",old_source+"/verify_controls.py",
             "--prior",old_prior,"--output",old_out,"--receipt",old_out+"/READBACK.json"] and row["name"]=="publisher-verify" and
             row["cwd"]==old_source and row["stdin"] is None and type(row["timeout_seconds"]) is int and row["timeout_seconds"]==180 and
             type(row["exit_code"]) is int and row["exit_code"]==0 and row["timed_out"] is False and row["completed"] is True and
             type(row["elapsed_seconds"]) in (int,float) and math.isfinite(row["elapsed_seconds"]) and 0<row["elapsed_seconds"]<=180,
             "exact retained pure verification command, status and deadline")
    pc.check(all(type(row[k]) is int and row[k]>1 for k in ("pid","parent_pid","pgid")) and row["pid"]==row["pgid"]!=row["parent_pid"] and
             proof["pid"]==row["pid"] and proof["ppid"]==row["parent_pid"] and proof["pgid"]==row["pgid"],"actual prior reader PID chain")
    for kind in ("stdout","stderr"):
        name="publisher-verify."+kind;raw=pc.read(control/"processes/verify"/name)
        pc.check(row[kind]==dict(file=name,**pc.pin(raw)) and raw==(pc.enc({k:v for k,v in proof.items() if k not in ("before","after")}) if kind=="stdout" else b""),
                 "every retained pure verification stream")
    pc.check(proof["before"]==proof["after"] and len(proof["probes"])==12 and proof["reader_writes"]==proof["native_or_rust_executions"]==0 and
             proof["evidence"]==baseline,"complete existing proof equals fresh read of same evidence")
    pc.check(gate["status"]==baseline["status"] and gate["readback"]==pc.pin(pc.read(control/"READBACK.json")) and
             gate["owner"]==baseline["owner_controls"] and gate["transport"]==baseline["transport_controls"] and
             gate["ordinary_native_replayed"] is False and gate["rust_replayed"] is False and gate["physical_reader_controls_pending"] is True,
             "original partial gate remains unchanged")
    pc.check(pc.files(retained/"control-source")==pc.files(ROOT/"controls"),"every passed control source byte and mode unchanged")
    return dict(process=row,proof=pc.pin(pc.read(control/"READBACK.json")),original_gate_preserved=True)
