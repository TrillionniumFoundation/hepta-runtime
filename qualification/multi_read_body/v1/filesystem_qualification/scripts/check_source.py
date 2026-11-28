#!/usr/bin/env python3
"""Compile all frozen Python sources and admit only the already frozen input domain."""
from pathlib import Path
import argparse,ast,json,struct,sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/"scripts"))
from evidence_common import decode,encoded,pin,require,source_evidence
from cases import domain,groups,actual_query
from protocol import wire,U
import read_capture,read_compare,read_body,read_trace,read_qualification,physical_controls
def main():
    before=source_evidence(ROOT);compiled=0
    for path in sorted(ROOT.rglob("*.py")):
        raw=path.read_bytes();tree=ast.parse(raw,filename=str(path));compile(tree,str(path),"exec");compiled+=1
        if path.parent==ROOT/"scripts":
            names=[n.name for n in tree.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef))]
            require(len(names)==len(set(names)),"duplicate source-level definition: "+path.name)
    trusted=source_evidence(ROOT/"trusted-build");native=decode((ROOT/"BUILD_REUSE.json").read_bytes())
    require(trusted["manifest"]["sha256"]==native["manifest_sha256"]and trusted["files"]==72,"exact successful corrected body build")
    original=source_evidence(ROOT/"retained-input-source")
    require(original["manifest"]["sha256"]=="86df7415d1356cdf02576367229df863146b69de826b27c9b61d73db8a62cbc3","original frozen input author")
    frozen=decode((ROOT/"DOMAIN.json").read_bytes())
    require(frozen["schema"]=="hepta.runtime.multi-read-body.actual-inputs.v1"and frozen["cases"]==domain()
        and frozen["groups"]==groups()and frozen["application_executions"]==0 and frozen["expected_outputs"]is False,
        "exact input-only domain")
    require((ROOT/"DOMAIN.json").read_bytes()==(ROOT/"retained-input-author/generated/DOMAIN.json").read_bytes(),"actual author materialized same whole inputs")
    author=decode((ROOT/"retained-input-author/generated/INPUT_AUTHOR.json").read_bytes())
    require(author["status"]=="INPUT_AUTHOR_ONLY_PASS"and author["source"]==original and author["inputs"]==84
        and author["groups"]==27 and author["requested_native_calls"]==author["requested_original_calls"]==89
        and author["native_applications"]==author["original_applications"]==author["rust_applications"]==0,"input-author zero-application receipt")
    rows=decode((ROOT/"retained-input-author/processes/processes.json").read_bytes());require(len(rows)==1,"single input-author process")
    r=rows[0];require(r["name"]=="input-author"and r["completed"]is True and r["exit_code"]==0 and r["timed_out"]is False
        and r["timeout_seconds"]==60 and r["elapsed_seconds"]<60 and r["pid"]==r["pgid"]and r["stdin"]is None,"actual source-only bounded author")
    for suffix in("stdout","stderr"):
        part=r[suffix];require(pin(ROOT/"retained-input-author/processes"/part["file"])=={k:part[k]for k in("bytes","sha256")},"complete original author streams")
    require(r["stderr"]["bytes"]==0 and decode((ROOT/"retained-input-author/processes/input-author.stdout").read_bytes())==author,"source-only author exact result")
    for q in domain():
        packet=wire(actual_query(q,Path("/tmp/frozen-input-only")));require(packet[:8]==b"HMRDQ001"
            and len(packet)==96+U(packet,88)and U(packet,8)==1 and U(packet,16)==0,"complete concrete input framing")
    require(source_evidence(ROOT)==before,"source check mutated frozen input")
    print(encoded(dict(status="MULTI_FILESYSTEM_SOURCE_AND_INPUT_ONLY_PASS",source=before,compiled_python_sources=compiled,
        inputs=84,groups=27,requested_original_calls=89,requested_native_calls=89,
        original_applications=0,native_applications=0,rust_applications=0)).decode(),end="")
if __name__=="__main__":main()
