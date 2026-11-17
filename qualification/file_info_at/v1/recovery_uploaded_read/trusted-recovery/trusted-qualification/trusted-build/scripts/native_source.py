"""Source-owned native capability graph and exact retained primitives."""
from pathlib import Path
from callable_common import decode,owned,require,pin,sha
def verify(root):
    root=Path(root);provenance=decode(owned(root,"NATIVE_PROVENANCE.json").read_bytes())
    for name,row in provenance["exact_dependencies"].items():
        require(pin(owned(root,name))==row,"exact shared native/HIA dependency differs: "+name)
    for name in("binary_read_body","file_metadata","binary_codec","stat_version"):
        require(owned(root,"native/"+name+".hepta").read_bytes()
            ==owned(root,"baseline/"+name+".hepta").read_bytes(),"qualified HIA owner changed")
    before=owned(root,"reference/metadata_callable_before.S").read_text()
    prefix=before[:before.index("/* Trusted rdi callback")]
    prefix=prefix.replace("M_","I_").replace(".Lmdt_",".Lifa_")
    prefix=prefix.replace("0x3130494354444d48 /* HMDTCI01 */","0x31304943464e4948 /* HINFCI01 */")
    prefix=prefix.replace(".equ I_REPLY_CAP, 69632",".equ I_REPLY_CAP, 4096")
    prefix=prefix.replace("Fixed borrowed-file metadata capability. All metadata policy is HIA.",
        "Fixed borrowed-parent info capability. All original info policy is HIA.")
    require(owned(root,"asm/file_info_at_callable.S").read_text().startswith(prefix),
        "complete qualified arena allocator/grow prefix changed")
    before=owned(root,"reference/metadata_fixture_before.S").read_text()
    io=before[before.index(".Lmtf_read_exact:"):before.index("/* Immutable observer binding:")].replace(".Lmtf_",".Liff_")
    require(owned(root,"asm/file_info_at_fixture.S").read_text().count(io)==1,
        "complete fixed read/write carrier helpers changed")
    hia=decode(owned(root,"native/file_info_at_composition.json").read_bytes())
    require(hia["source_sha256"]==pin(root/"native/file_info_at.hepta")["sha256"]
        and hia["functions"]==40 and hia["instructions"]==2605,"actual info author binding")
    return dict(status="EXACT_SHARED_PRIMITIVES_AND_INFO_SOURCE_PASS",
        exact_dependencies=len(provenance["exact_dependencies"]),unchanged_arena_prefix_bytes=len(prefix.encode()),
        unchanged_io_helper_bytes=len(io.encode()),new_native_application_calls=0)
