"""Exact source derivation, shared primitive and unchanged read functions."""
from pathlib import Path
from callable_common import decode,owned,require,pin,sha
def verify(root):
    root=Path(root);provenance=decode(owned(root,"NATIVE_PROVENANCE.json").read_bytes())
    for name,row in provenance["exact_dependencies"].items():
        require(pin(owned(root,name))==row,"exact shared dependency differs: "+name)
    derivation=decode(owned(root,"authoring/native_derivation.json").read_bytes())
    for key in("bridge","fixture"):
        item=derivation[key];original=owned(root,item["source"]).read_text();current=original
        for row in item["edits"]:
            count=row.get("count",1);require(current.count(row["before"])==count,"native complete preimage: "+row["label"])
            current=current.replace(row["before"],row["after"])
        require(current==owned(root,item["target"]).read_text(),"exact native source derivation: "+key)
        for row in reversed(item["edits"]):
            count=row.get("count",1);require(current.count(row["after"])==count,"native inverse preimage: "+row["label"])
            current=current.replace(row["after"],row["before"])
        require(current==original,"reversible complete native derivation")
    for row in derivation["shared_fixture_fragments"]:
        before=owned(root,row["source"]).read_text()
        fragment=before[before.index(row["from"]):before.index(row["to"])]
        fragment=fragment.replace(".Liff_",".Lbrf_").replace(".Lifa_",".Lbrd_")
        fragment=fragment.replace("I_ENTER","B_ENTER").replace("I_LEAVE","B_LEAVE").replace("I_INVALID","B_INVALID")
        require(owned(root,"asm/binary_read_body_fixture.S").read_text().count(fragment)==1,"exact shared fixture fragment")
    before=owned(root,"reference/binary_read_body_fixture.S").read_text()
    io=before[before.index(".Lbrf_read_exact:"):before.index("/* Immutable observer binding:")]
    require(owned(root,"asm/binary_read_body_fixture.S").read_text().count(io)==1,"unchanged whole carrier read/write helpers")
    before=owned(root,"baseline/binary_read_body_callable.S").read_text()
    allocator=before[:before.index("/* Trusted rdi callback")]
    require(owned(root,"asm/binary_read_body_callable.S").read_text().startswith(allocator),"unchanged complete arena prefix")
    receipt=decode(owned(root,"native/binary_read_body_composition.json").read_bytes())
    require(receipt["source_sha256"]==pin(root/"native/binary_read_body.hepta")["sha256"]
        and receipt["functions"]==67 and receipt["instructions"]==4063 and receipt["retained_functions"]==66
        and receipt["changed_function"]=="f20","complete HIA author binding")
    require(all(v==receipt["baseline_function_sha256"][k]for k,v in receipt["function_sha256"].items()if k!="f20"),
        "all66 unchanged function identities")
    return dict(status="EXACT_SHARED_ORPHAN_PRIMITIVE_AND_READ_SOURCE_PASS",
        exact_dependencies=len(provenance["exact_dependencies"]),unchanged_functions=66,
        unchanged_arena_prefix_bytes=len(allocator.encode()),unchanged_io_helper_bytes=len(io.encode()),
        new_native_application_calls=0)
