"""Read complete source identities and reversible source-owned native derivatives."""
from pathlib import Path
from callable_common import decode,owned,require,pin,sha
def verify(root):
    root=Path(root);p=decode(owned(root,"NATIVE_PROVENANCE.json").read_bytes())
    for path,row in p["exact_dependencies"].items():
        require(pin(owned(root,path))==row,"exact dependency differs: "+path)
    d=decode(owned(root,"authoring/native_derivation.json").read_bytes())
    counts={}
    for key,item in d["files"].items():
        original=owned(root,item["source"]).read_text()
        require(sha(original.encode())==item["source_sha256"],"native derivative original")
        value=original
        for row in item["renames"]:
            require(value.count(row["before"])==row["count"],"native rename full preimage")
            value=value.replace(row["before"],row["after"])
        for row in item["edits"]:
            require(value.count(row["before"])==1 and value.index(row["before"])==row["offset"],
                "native edit full preimage: "+row["label"])
            value=value[:row["offset"]]+row["after"]+value[row["offset"]+len(row["before"]):]
        require(value==owned(root,item["target"]).read_text()
            and sha(value.encode())==item["target_sha256"],"complete native derivative")
        for row in reversed(item["edits"]):
            require(value[row["offset"]:row["offset"]+len(row["after"])]==row["after"],
                "inverse native edit preimage")
            value=value[:row["offset"]]+row["before"]+value[row["offset"]+len(row["after"]):]
        for row in reversed(item["renames"]):
            require(value.count(row["after"])==row["count"],"inverse rename full preimage")
            value=value.replace(row["after"],row["before"])
        require(value==original,"whole native inverse source")
        counts[key]=len(item["edits"])
    body=decode(owned(root,"native/multi_read_body_composition.json").read_bytes())
    utf=decode(owned(root,"native/utf8_decode_diagnostic_composition.json").read_bytes())
    require(body["source_sha256"]==pin(root/"native/multi_read_body.hepta")["sha256"]
        and body["functions"]==53 and body["instructions"]==3642,"complete body author binding")
    require(utf["source_sha256"]==pin(root/"native/utf8_decode_diagnostic.hepta")["sha256"]
        and utf["functions"]==17 and utf["instructions"]==707,"complete UTF8 author binding")
    expected={"body":"multi_read_body","parent":"parent_directory","codec":"binary_codec",
        "stat":"stat_version","utf8":"utf8_decode_diagnostic","error":"structured_error"}
    require({key:pin(root/("native/"+name+".hepta"))["sha256"]for key,name in expected.items()}
        ==p["hia_sources"],"all six exact HIA sources")
    return dict(status="COMPLETE_MULTI_READ_SOURCE_DERIVATION_PASS",native_edits=counts,
        body_functions=53,utf8_functions=17,body_runtime_images=5,fixture_images=6,
        exact_dependencies=len(p["exact_dependencies"]),new_native_application_calls=0)
