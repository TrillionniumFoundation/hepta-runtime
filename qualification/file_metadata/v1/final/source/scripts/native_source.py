"""Exact forward and inverse bytes for the fixed metadata capability author."""
from pathlib import Path
from callable_common import decode,owned,require,pin
def derive(root,label):
    plan=decode(owned(root,"authoring/"+label+"_native_edits.json").read_bytes())
    original=owned(root,"reference/"+label+"_before.S").read_text()
    require(len(original.encode())==plan["baseline"]["bytes"] and pin(root/("reference/"+label+"_before.S"))["sha256"]==plan["baseline"]["sha256"],"native exact before bytes")
    value=original
    for before,after in plan["renames"]:
        require(before in value,"native rename preimage");value=value.replace(before,after)
    for patch in plan["patches"]:
        at=patch["offset"];before=patch["before"];after=patch["after"]
        require(value[at:at+len(before)]==before,"native exact patch preimage")
        value=value[:at]+after+value[at+len(before):]
    observed=owned(root,"asm/file_metadata_"+label+".S").read_text()
    require(value==observed,"complete derived native source")
    for patch in reversed(plan["patches"]):
        at=patch["offset"];before=patch["before"];after=patch["after"]
        require(value[at:at+len(after)]==after,"native inverse exact offset")
        value=value[:at]+before+value[at+len(after):]
    for before,after in reversed(plan["renames"]):value=value.replace(after,before)
    require(value==original,"complete inverse original native bytes")
    return dict(before=pin(root/("reference/"+label+"_before.S")),
        after=pin(root/("asm/file_metadata_"+label+".S")),patches=len(plan["patches"]))
def verify(root):
    root=Path(root)
    return {label:derive(root,label) for label in("callable","fixture")}
