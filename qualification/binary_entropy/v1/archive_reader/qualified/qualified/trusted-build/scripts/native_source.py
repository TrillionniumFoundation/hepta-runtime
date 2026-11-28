"""Admit every frozen native byte and unchanged process-pool source."""
from callable_common import decode,owned,require,pin
def verify(root):
    value=decode(owned(root,"NATIVE_PROVENANCE.json").read_bytes())
    require(value["production_native_executed"]is False and value["application_executions"]==0,"source-only provenance")
    require(value["author_process"]["status"]=="PASS"and value["author_process"]["native_execution"]is False,"HIA source author")
    for name,row in value["native_sources"].items():
        require(pin(owned(root,name))==row,"complete native source bytes")
    require(value["native_sources"]["asm/process_orphans.S"]["sha256"]==
        "f1d4e92b9d2ce68c68dcbc730950eaddaf3aa1093f143d34924c3eafc302e050","unchanged shared process pool")
    for name,row in value["author_complete"]["members"].items():
        path="native/"+name.removeprefix("generated/")if name.startswith("generated/")else"author-evidence/"+name
        require(pin(owned(root,path))=={k:row[k]for k in("bytes","sha256")},"complete authored HIA and process streams")
    return dict(status="ALL_NATIVE_SOURCE_BYTES_BOUND",native_sources=value["native_sources"],
        complete_author_bytes=True,native_application_calls=0)
