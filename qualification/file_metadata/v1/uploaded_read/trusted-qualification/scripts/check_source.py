#!/usr/bin/env python3
"""Source and input-only check; no fixture effects or application entry calls."""
from pathlib import Path
import argparse,ast,hashlib,json,os,struct,sys
sys.dont_write_bytecode=True
SOURCE=Path(__file__).resolve().parents[1];sys.path.insert(0,str(SOURCE/"scripts"))
from evidence_common import source_evidence,require,encoded,pin
from cases import cases,wire,snapshot,original_snapshot
from protocol import snapshot_decode,original_snapshot as encode_original
def main():
    identity=source_evidence(SOURCE)
    files=[]
    for path in sorted(SOURCE.rglob("*.py")):
        raw=path.read_bytes();ast.parse(raw,filename=str(path));compile(raw,str(path),"exec")
        files.append(dict(path=path.relative_to(SOURCE).as_posix(),**pin(path)))
    raw=(SOURCE/"target/file_metadata.py").read_bytes()
    require(hashlib.sha256(raw).hexdigest()=="24b9df89816536db16dd35a74d6460b1a215981a00798393a00853da6077f5d3","original complete target")
    queries=cases();require(len(queries)==82 and [q["id"]for q in queries]==list(range(1,83)),"frozen input extent")
    groups={}
    for q in queries:
        require(q["expected_result"]is None and(q["observer"]or not q["actions"]),"input-only/no unobserved actor")
        groups.setdefault(q["group"],[]).append(dict(id=q["id"],name=q["name"],input_sha256=hashlib.sha256(encoded(q)).hexdigest()))
        if q["mode"]=="summary":
            data=snapshot(q["snapshot"]);value=snapshot_decode(data)
            require(value==encode_original(original_snapshot(q["snapshot"])),"declared owned snapshot encoding")
        else:data=b""
        body=wire(q["mode"],data);require(body[:8]==b"HMDTQ001"and len(body)==96+len(data),"fixed input ABI")
    require(len(groups)==16 and len(groups["observer-off"])==12,"frozen lane count")
    report=dict(status="METADATA_SOURCE_AND_INPUT_ONLY_PASS",source=identity,python_sources=files,groups=groups,
        observed_inputs=70,observer_off_inputs=12,metadata_function_calls=0,hia_calls=0,rust_calls=0,fixture_effects=0)
    print(encoded(report).decode(),end="")
if __name__=="__main__":main()
