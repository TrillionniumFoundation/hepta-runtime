"""Pure source checks for the new anchor owner; never execute HIA or Rust."""
import ast, json, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True
sys.path.insert(0,str(ROOT))
from common import source,read,pin,require,encoded
def check(*,compile_sources=False):
    digest=source()
    if compile_sources:
        for path in ROOT.rglob("*.py"):compile(read(path),str(path),"exec")
        ast.parse(read(ROOT/"authoring/audit_anchor_publish.pseudo"))
    original=read(ROOT/"imports/audit_pinned_anchor_callable.S").decode()
    delta=json.loads(read(ROOT/"authoring/ADAPTER_DELTA.json"))
    require(pin(original.encode())=={k:delta["preimage"][k] for k in ("bytes","sha256")},"exact qualified preimage")
    for row in delta["changes"]:
        require(original.count(row["before"])==row["count"],"exact adapter source occurrence")
        original=original.replace(row["before"],row["after"])
    require(original.encode()==read(ROOT/"authoring/audit_anchor_publish_callable.S.in"),"entire narrow adapter replay")
    spans=json.loads(read(ROOT/"reference/ORIGINAL_SPANS.json"))
    for row in spans["spans"]:
        body=read(ROOT/row["source"])[row["start_byte"]:row["end_byte"]]
        require(body==read(ROOT/row["extraction"]),"exact unchanged original span")
        require(pin(body)=={k:row[k] for k in ("bytes","sha256")},"original function source identity")
    proof=json.loads(read(ROOT/"native/audit_anchor_publish.composition.json"))
    callable_proof=json.loads(read(ROOT/"native/audit_anchor_publish_callable.composition.json"))
    for path,expected in (("imports/audit_anchor_publish.hepta",proof["source"]),
                          ("imports/audit_json.hepta",proof["json_child"]),
                          ("imports/audit_record_io.hepta",proof["imports"]["source"]),
                          ("authoring/audit_anchor_publish.pseudo",proof["pseudo"]),
                          ("authoring/author_owner.py",proof["author"]),
                          ("reference/ORIGINAL_SPANS.json",proof["original_spans"]),
                          ("authoring/audit_anchor_publish_callable.S",callable_proof["adapter_source"]),
                          ("native/audit_anchor_publish_callable.hepta",callable_proof["packer_source"])):
        require(pin(read(ROOT/path))=={k:expected[k] for k in ("bytes","sha256")},"complete exact owner/author/codec source")
    domain=json.loads(read(ROOT/"DOMAIN.json"))
    require(domain["case_count"]==99 and domain["operation_count"]==137 and domain["expected_outputs_embedded"] is False,"unchanged complete new domain")
    return dict(status="SOURCE_ONLY_PASS",source_sha256=digest,source_files=len(json.loads(read(ROOT/"SOURCE.json"))["files"]),
        original_spans=len(spans["spans"]),adapter_deltas=len(delta["changes"]),native_or_rust_semantic_executions=0)
if __name__=="__main__":print(encoded(check(compile_sources=True)).decode(),end="")
