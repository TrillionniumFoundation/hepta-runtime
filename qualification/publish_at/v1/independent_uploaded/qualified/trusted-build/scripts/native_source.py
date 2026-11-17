"""Exact fixed dependencies and fully reversible source-owned native edits."""
from pathlib import Path
from callable_common import decode,owned,require,pin,sha
def derive(root,original,edits,final):
    before=owned(root,original).read_text();value=before
    rows=decode(owned(root,edits).read_bytes())
    for row in rows:
        require(sha(value.encode())==row["before_sha256"],"native edit preceding source")
        positions=[];at=0
        while True:
            pos=value.find(row["before"],at)
            if pos<0:break
            positions.append(pos);at=pos+len(row["before"])
            if not row["all"]:break
        require(positions==row["positions"] and len(positions)==row["count"],"native edit exact occurrences")
        expected=[p+i*(len(row["after"])-len(row["before"]))for i,p in enumerate(positions)]
        require(expected==row["after_positions"],"native edit inverse positions")
        value=value.replace(row["before"],row["after"],-1 if row["all"] else 1)
        require(sha(value.encode())==row["after_sha256"],"native edit resulting source")
    require(value==owned(root,final).read_text(),"complete derived native source differs")
    reverse=value
    for row in reversed(rows):
        require(sha(reverse.encode())==row["after_sha256"],"native inverse stage")
        for at in reversed(row["after_positions"]):
            require(reverse[at:at+len(row["after"])]==row["after"],"native inverse span")
            reverse=reverse[:at]+row["before"]+reverse[at+len(row["after"]):]
        require(sha(reverse.encode())==row["before_sha256"],"native inverse complete stage")
    require(reverse==before,"complete native source inverse differs")
    return dict(edits=len(rows),baseline=pin(root/original),derived=pin(root/final),complete_inverse=True)
def verify(root):
    root=Path(root);provenance=decode(owned(root,"NATIVE_PROVENANCE.json").read_bytes())
    for name,row in provenance["exact_dependencies"].items():
        require(pin(owned(root,name))==row,"exact shared dependency differs: "+name)
    native=derive(root,"reference/file_info_at_callable_before.S","authoring/callable_native_edits.json","asm/publish_at_callable.S")
    fixture=derive(root,"reference/file_info_at_fixture_before.S","authoring/fixture_native_edits.json","asm/publish_at_fixture.S")
    receipt=decode(owned(root,"native/publish_at_composition.json").read_bytes())
    require(receipt["source_sha256"]==pin(root/"native/publish_at.hepta")["sha256"]
        and receipt["functions"]==35 and receipt["instructions"]==3015 and receipt["blocks"]==568,"actual HIA author binding")
    return dict(status="EXACT_SHARED_PRIMITIVES_AND_PUBLICATION_SOURCE_PASS",
        exact_dependencies=len(provenance["exact_dependencies"]),native=native,fixture=fixture,new_native_application_calls=0)
