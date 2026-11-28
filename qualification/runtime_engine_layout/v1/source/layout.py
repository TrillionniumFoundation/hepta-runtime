"""Fixed graph storage layout; build-time constants only, never public input."""
import re

def layout(slots):
    if type(slots) is not int or slots<59:
        raise ValueError("engine graph needs its existing fixed 59 descriptors")
    continuation_end=512+64*slots
    descriptor_base=max(8192,(continuation_end+4095)&~4095)
    descriptor_end=descriptor_base+64*slots
    high_bytes=max(0,((slots+63)//64)-1)*8
    work_high=descriptor_end
    output_high=work_high+high_bytes
    high_end=output_high+high_bytes
    engine_bytes=max(16384,(high_end+4095)&~4095)
    if engine_bytes+4096>0x7fffffff:
        raise ValueError("fixed native displacement/extent is not representable")
    assert 512<=continuation_end<=descriptor_base<=descriptor_end<=work_high<=output_high<=high_end<=engine_bytes
    return dict(slots=slots,header_bytes=512,continuation_base=512,continuation_end=continuation_end,
        descriptor_base=descriptor_base,descriptor_end=descriptor_end,descriptor_bytes=64,
        low_work_bits=64,low_output_bits=72,high_bytes=high_bytes,work_high=work_high,
        output_high=output_high,engine_bytes=engine_bytes,guard_bytes=4096)

def rebind(source,slots):
    values=layout(slots)
    names={"RG_SLOTS":"slots","RG_ENGINE":"engine_bytes","RG_TABLE":"descriptor_base",
           "RG_WORK_HIGH":"work_high","RG_OUTPUT_HIGH":"output_high","RG_HIGH_BYTES":"high_bytes"}
    for name,key in names.items():
        pattern=r"(?m)^\.equ "+name+r", [0-9]+$"
        source,count=re.subn(pattern,".equ "+name+", "+str(values[key]),source)
        if count!=1:raise ValueError("fixed layout constant missing or repeated: "+name)
    return source

def upgrade(original):
    """Exact six variable-index operations; low fixed-slot users stay byte exact."""
    source=original
    marker=".equ RG_SLOTS, 59\n.equ RG_ENGINE, 16384\n"
    if source.count(marker)!=1:raise ValueError("old engine constant anchor")
    fixed=layout(59)
    source=source.replace(marker,marker+
        ".equ RG_TABLE, "+str(fixed["descriptor_base"])+"\n"+
        ".equ RG_WORK_HIGH, "+str(fixed["work_high"])+"\n"+
        ".equ RG_OUTPUT_HIGH, "+str(fixed["output_high"])+"\n"+
        ".equ RG_HIGH_BYTES, "+str(fixed["high_bytes"])+"\n",1)
    before="    lea rdx, [rbx + 8192]\n"
    if source.count(before)!=1:raise ValueError("old table anchor")
    source=source.replace(before,"    lea rdx, [rbx + RG_TABLE]\n",1)
    for offset,name in ((64,"RG_WORK_HIGH"),(72,"RG_OUTPUT_HIGH")):
        for op in ("bt","btr","bts"):
            before="    "+op+" qword ptr [r15 + "+str(offset)+"], rbp\n"
            if source.count(before)!=1:raise ValueError("old ownership anchor: "+before)
            after=("    lea rax, [r15 + "+str(offset)+"]\n"+
                "    lea rdx, [r15 + "+name+" - 8]\n"+
                "    cmp rbp, 64\n"+
                "    cmovae rax, rdx\n"+
                "    "+op+" qword ptr [rax], rbp\n")
            source=source.replace(before,after,1)
    return source

def undo(candidate):
    source=candidate
    for offset,name in ((64,"RG_WORK_HIGH"),(72,"RG_OUTPUT_HIGH")):
        for op in ("bt","btr","bts"):
            after=("    lea rax, [r15 + "+str(offset)+"]\n"+
                "    lea rdx, [r15 + "+name+" - 8]\n"+
                "    cmp rbp, 64\n"+
                "    cmovae rax, rdx\n"+
                "    "+op+" qword ptr [rax], rbp\n")
            if source.count(after)!=1:raise ValueError("new ownership anchor")
            source=source.replace(after,"    "+op+" qword ptr [r15 + "+str(offset)+"], rbp\n",1)
    source=source.replace("    lea rdx, [rbx + RG_TABLE]\n","    lea rdx, [rbx + 8192]\n",1)
    for name in ("RG_TABLE","RG_WORK_HIGH","RG_OUTPUT_HIGH","RG_HIGH_BYTES"):
        source,count=re.subn(r"(?m)^\.equ "+name+r", [0-9]+\n","",source)
        if count!=1:raise ValueError("new layout constant anchor")
    return source
