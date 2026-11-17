"""Frozen source-only legacy and new literal domains; never reads execution results."""
from pathlib import Path
import importlib.util,struct
from common import canonical,decode,require,sha
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("qualified_path_error_cases",ROOT/"trusted-legacy/scripts/cases.py")
legacy=importlib.util.module_from_spec(spec);spec.loader.exec_module(legacy)
WORK=legacy.WORK;MAX=(1<<64)-1;INVALID=0xffffffff;CAPACITY=0xfffffffe
CLASSES=legacy.CLASSES+("Error","NotImplementedError","RuntimeError")
frame=legacy.frame;public_row=legacy.public_row;capacity=legacy.capacity
def domain():return decode((ROOT/"DOMAIN.json").read_bytes())
def groups():return legacy.domain()["groups"]+domain()["new_groups"]
def new_names():return {r["name"]for r in domain()["new_groups"]}
def extra(cls,bucket,index,label,raw):
    return legacy.row(1000000+(cls-15)*100000+bucket*10000+index,label,cls,0,raw)
def runtime_literals():
    rows=["Only base64 data is allowed","Excess data after padding","Leading padding not allowed",
        "Discontinuous padding not allowed","Incorrect padding"]
    rows+=["Invalid base64-encoded string: number of data characters ("+number+
        ") cannot be 1 more than a multiple of 4"for number in domain()["base64_character_counts_decimal"]]
    rows+=["/dev/urandom (or equivalent) not found"]
    rows+=["Failed to read "+str(number)+" bytes from /dev/urandom"for number in range(1,17)]
    require(len(rows)==86,"complete runtime literal shapes")
    return rows
def cases(group):
    selected=next((r for r in domain()["new_groups"]if r["name"]==group),None)
    if selected is None:yield from legacy.cases(group);return
    cls=selected["class_id"];kind=selected["kind"]
    if kind=="literal_basic":
        for i,message in enumerate((*legacy.LITERALS,"sample")):
            yield extra(cls,0,i,group+"-"+str(i),message.encode())
    elif kind=="literal_lengths":
        for i,size in enumerate(domain()["lengths"]):
            yield extra(cls,1,i,group+"-"+str(size),b"x"*size)
    elif kind=="literal_runtime":
        for i,message in enumerate(runtime_literals()):
            yield extra(cls,2,i,group+"-"+str(i),message.encode())
    elif kind=="literal_scalar":
        plane=selected["plane"];raw="".join(chr(cp)for cp in range(plane<<16,(plane+1)<<16)if not 0xd800<=cp<=0xdfff).encode()
        yield extra(cls,3,plane,group,raw)
    else:raise ValueError("unfrozen literal group")
def controls():
    result=legacy.controls();changed=[]
    for row in result:
        if row["label"]in("class-15","class-16"):
            cls=int(row["label"].split("-")[1]);wire=legacy.packet(cls,0,b"sample",sequence=MAX)
            require(row["wire"]==wire and row["expected"]==INVALID and row["mutation"]=="unchanged",
                "exact previously invalid newly admitted literal")
            needed=len(CLASSES[cls-1])+2+6
            row.update(expected=needed,mutation="installed",required=needed,
                reference_case_id=1000000+(cls-15)*100000+8)
            changed.append(row["label"])
    require(changed==domain()["explicitly_extended_legacy_boundaries"],"only declared old boundaries extend")
    def add(label,wire,out,work,expected,**extra):
        result.append(dict(case_id=3000000+len(result),label=label,wire=wire,
            output_capacity=out,workspace_capacity=work,expected=expected,**extra))
    def change(raw,at,value):return raw[:at]+struct.pack("<Q",value)+raw[at+8:]
    message="capacity\0\u6c49\u5b57'\"\\".encode()
    invalid_utf8=(b"\x80",b"\xbf",b"\xc0\x80",b"\xc1\xbf",b"\xc2",b"\xc2A",
        b"\xe0\x80\x80",b"\xed\xa0\x80",b"\xed\xbf\xbf",b"\xe1\x80",b"\xe1A\x80",
        b"\xf0\x80\x80\x80",b"\xf4\x90\x80\x80",b"\xf5\x80\x80\x80",b"\xff",
        b"\xf1\x80\x80",b"\xf1\x80A\x80",b"valid\xf1\x80\x80\x80\x80")
    for cls in(15,16,17):
        wire=legacy.packet(cls,0,message,sequence=MAX-cls);needed=len(CLASSES[cls-1])+2+len(message)
        for cap in(0,1,needed-1,needed,needed+17):
            add("new-output-"+str(cls)+"-"+str(cap),wire,cap,WORK+31,CAPACITY if cap<needed else needed,
                mutation="installed",required=needed,reference_class=cls,message_hex=message.hex())
        for size in(0,1,WORK-1):
            add("new-workspace-"+str(cls)+"-"+str(size),wire,needed+17,size,CAPACITY,mutation="unchanged")
        for repeat in range(3):
            add("new-reuse-"+str(cls)+"-"+str(repeat),wire,needed+17,WORK+31,needed,
                mutation="installed",reuse=repeat>0,required=needed,reference_class=cls,message_hex=message.hex())
        good=legacy.packet(cls,0,b"sample",sequence=MAX)
        for i,raw in enumerate(invalid_utf8):
            add("new-utf8-"+str(cls)+"-"+str(i),legacy.packet(cls,0,raw),512,WORK+31,INVALID,mutation="unchanged")
        for at,values in((8,(0,1,2,4,MAX)),(32,(1,4095,4096,MAX)),(48,(1,2,3,MAX)),
                (40,(5,7,MAX)),(56,(5,7,MAX))):
            for value in values:
                add("new-field-"+str(cls)+"-"+str(at)+"-"+str(value),change(good,at,value),512,WORK+31,INVALID,mutation="unchanged")
        for size in(0,1,7,8,23,24,31,32,63):
            add("new-short-"+str(cls)+"-"+str(size),good[:size],512,WORK+31,INVALID,mutation="unchanged")
        for magic in(b"HMDSR001",b"HOSER001"):
            add("new-old-protocol-"+str(cls)+"-"+magic.decode(),magic+good[8:],512,WORK+31,INVALID,mutation="unchanged")
    for cls in(0,18,19,MAX):
        add("new-class-"+str(cls),legacy.packet(cls,0,b"sample"),512,WORK+31,INVALID,mutation="unchanged")
    return result
def validate():
    old=legacy.validate();d=domain();new=[r for group in d["new_groups"]for r in cases(group["name"])]
    require(old["groups"]==164 and old["semantic_cases"]==21901 and len(d["new_groups"])==60
        and len(new)==d["new_semantic_cases"]==435 and len({r["case_id"]for r in new})==len(new),
        "complete old and new literal domain")
    require(len(groups())==224 and d["total_native_semantic_cases"]==21901+435
        and len(d["lengths"])==33 and len(d["base64_character_counts_decimal"])==64,"literal counts and sizes")
    for cls in(15,16,17):
        require(sum(len(r["payload"].decode())for r in new if r["kind"]==cls and r["label"].startswith("literal-scalar-"))
            ==1112064,"every Unicode scalar for each new class")
    boundary=controls();counts=dict(invalid=sum(r["expected"]==INVALID for r in boundary),
        capacity=sum(r["expected"]==CAPACITY for r in boundary),success=sum(r["expected"]not in(INVALID,CAPACITY)for r in boundary))
    require(len(boundary)==d["private_controls"]==1255 and counts==d["control_counts"]
        ==dict(invalid=516,capacity=402,success=337),"all explicit extension and boundary counts")
    require(len({r["case_id"]for r in boundary})==len(boundary),"unique boundary input identities")
    return dict(groups=224,legacy_groups=164,new_groups=60,native_semantic_cases=22336,new_original_applications=435,
        reused_original_cases=21901,controls=1255,control_counts=counts,unicode_scalars_per_new_class=1112064,
        legacy_domain=old,domain_sha256=sha(canonical(d)))
