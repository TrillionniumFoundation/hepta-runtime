#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Pure source and actual assembler proof; never execute the graph."""
from pathlib import Path
import argparse,hashlib,json,re,stat,subprocess,sys,time
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE))
from compose import compose,require,pin
ENC=lambda v:(json.dumps(v,sort_keys=True,indent=2)+"\n").encode()
def main():
    p=argparse.ArgumentParser();p.add_argument("--source",type=Path,required=True);p.add_argument("--output",type=Path,required=True);a=p.parse_args()
    require(not a.output.exists(),"fresh author output");a.output.mkdir(parents=True)
    package=HERE.parent;manifest=json.loads((package/"SOURCE_MANIFEST.json").read_bytes())
    require({p.relative_to(package).as_posix() for p in package.rglob("*") if p.is_file()}=={r["path"] for r in manifest["files"]}|{"SOURCE_MANIFEST.json"},"exact package")
    for r in manifest["files"]:
        q=package/r["path"];v=q.read_bytes();require(pin(v)=={k:r[k] for k in ("bytes","sha256")},"exact fixture author")
        require(hashlib.sha1(b"blob "+str(len(v)).encode()+b"\0"+v).hexdigest()==r["git_blob"],"fixture blob")
        if q.suffix==".py":compile(v,str(q),"exec")
    index=json.loads((HERE/"PRODUCTION_ROWS.json").read_bytes());require(len(index["rows"])==530,"full graph")
    for row in index["rows"]:
        q=a.source/row["path"];v=q.read_bytes()
        require(not q.is_symlink() and stat.S_IMODE(q.stat().st_mode)==0o644,"source type/mode")
        require(pin(v)=={k:row[k] for k in ("bytes","sha256")},"exact source "+row["path"])
        require(hashlib.sha1(b"blob "+str(len(v)).encode()+b"\0"+v).hexdigest()==row["git_blob"],"git input")
    proof=json.loads((HERE/"FRAMING.json").read_bytes())
    transport=(a.source/"scripts/runtime_mcp_transport.S").read_text()
    before=transport[transport.index("public_span_next:"):transport.index("public_span_finish:")]
    require(before==proof["before"],"whole retained framing source")
    after=before.replace("public_span_","df_span_").replace("df_span_fail","public_span_fail").replace("call df_span_grow_input","call public_span_grow_input")
    after=after.replace("df_span_wait_input:\n    call pump_wait\n    jmp df_span_scan","df_span_wait_input:\n    jmp df_service_return")
    after=after.replace("    add [r12], rax\n    jc public_span_fail\n","    add [r12+DF_READ],rax\n    jc public_span_fail\n    add [r12], rax\n    jc public_span_fail\n")
    require(after==proof["after"] and (HERE/"duplex_fixture.S").read_text().count(after)==1,"only declared framing edits")
    sys.path.insert(0,str(a.source/"scripts"));import public_nine_build as build
    build.source_check(a.source)
    before=build.adapter_source(a.source,private_fixture=False,private_pump_fixture=True,private_pump_trace=True,private_publication_trace=True)
    combined=compose(before);(a.output/"combined.S").write_text(combined)
    actual=[]
    for name,argv in (
        ("assemble",["as","--64","-o",str(a.output/"bridge.o"),str(a.output/"combined.S")]),
        ("nm",["nm","-u",str(a.output/"bridge.o")]),
        ("relocations",["readelf","-r",str(a.output/"bridge.o")]),
        ("objdump",["objdump","-drw","-Mintel",str(a.output/"bridge.o")])):
        start=time.monotonic();r=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
        (a.output/(name+".stdout")).write_bytes(r.stdout);(a.output/(name+".stderr")).write_bytes(r.stderr)
        row=dict(argv=argv,exit_code=r.returncode,stdout=pin(r.stdout),stderr=pin(r.stderr),elapsed_seconds=time.monotonic()-start,timeout_seconds=30)
        (a.output/(name+".json")).write_bytes(ENC(row));actual.append(row)
        require(r.returncode==0 and not r.stderr,"actual assembler "+name)
        if name=="nm":require(not r.stdout,"no undefined symbols")
        if name=="relocations":require(b"There are no relocations" in r.stdout,"no unresolved relative calls")
        if name=="objdump":
            text=r.stdout.decode()
            for name in ("public_span_start","duplex_fixture_preflight","duplex_service_current","duplex_observe_future","duplex_destroy",
                "pump_initialize_shared","pump_finish_service","pump_finish_runtime","pump_finish_storage"):
                require("<"+name+">:" in text,"actual native symbol "+name)
    report=dict(status="TWO_SESSION_NATIVE_FIXTURE_SOURCE_PASS",production=index["commit"],production_files=530,
        production_binding=pin((a.source/"native/runtime_mcp_sources.json").read_bytes()),ordinary_prefix=pin(before.encode()),
        actual_fixture_prefix=pin(combined.encode()),actual_processes=actual,public_sessions=2,shared_runtime=True,
        actual_graph_executions=0,rust_executions=0,full_async=False,production_installed=False)
    (a.output/"CHECK.json").write_bytes(ENC(report));print(json.dumps(report,sort_keys=True))
if __name__=="__main__":main()
