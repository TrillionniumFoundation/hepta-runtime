#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Freeze complete Linux errno and Unicode printable data into a pure HIA diagnostic leaf."""
import argparse,ast,copy,hashlib,json,locale,os,re,struct,sys,unicodedata
from pathlib import Path
sys.dont_write_bytecode=True
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
CANON=lambda value:json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
CLASSES=["ValueError","PermissionError","OSError","FileNotFoundError","NotADirectoryError",
    "IsADirectoryError","FileExistsError","InterruptedError","BlockingIOError","BrokenPipeError",
    "TimeoutError","ConnectionResetError","ConnectionAbortedError","ConnectionRefusedError","ProcessLookupError","ChildProcessError"]
def main():
    p=argparse.ArgumentParser()
    for n in("source","hepta","output"):p.add_argument("--"+n,type=Path,required=True)
    a=p.parse_args();source=a.source.resolve(strict=True);out=a.output.absolute();assert not out.exists()
    sys.path.insert(0,str(a.hepta.resolve(strict=True)))
    from tools.generate_hia_selfhost import Builder,compact_authoring_cfg,total_scalar_functions
    from hepta.hia_agent_assembly import assemble_program,render_assembly
    raw_baseline=(source/"baseline/binary_read_body.hepta").read_bytes()
    raw_composition=(source/"baseline/binary_read_body_composition.json").read_bytes()
    assert SHA(raw_baseline)=="3dbf1f5f46e9bc7e8a139714db1ff9588a95d1d9cc7d1dab1a8da03470a7fbd3"
    assert SHA(raw_composition)=="737f9b2985f6a70965ae5dd3c323074b46d11080c484c7ce8f0b9ffc2f352f35"
    composition=json.loads(raw_composition);old_utf8=composition["aliases"]["utf8"]
    original=next(f for f in assemble_program(raw_baseline).as_dict()["functions"]if f["name"]==old_utf8)
    assert SHA(CANON(original))==composition["function_sha256"][old_utf8]
    assert not any(op["op"]=="call"for b in original["blocks"]for op in b["ops"])
    assert [p["type"]for p in original["params"]]==["readbuf","u64","u64"]
    # These are source-generation inputs, never runtime requests or host fallbacks.
    ranges=[];first=None
    for cp in range(0x110000):
        keep=chr(cp).isprintable()
        if not keep and first is None:first=cp
        if keep and first is not None:ranges.append((first,cp-1));first=None
    if first is not None:ranges.append((first,0x10ffff))
    errors={};classes={}
    for number in range(1,4096):
        message=os.strerror(number)
        if message!="Unknown error "+str(number):errors[number]=message
        classes[number]=CLASSES.index(type(OSError(number,message)).__name__)+1
    # Linux x86_64 platform contract. Unexpected errno maps are rejected at authoring.
    expected_classes={}
    for number in range(1,4096):
        expected_classes[number]={1:2,13:2,2:4,20:5,21:6,17:7,4:8,11:9,114:9,115:9,
            32:10,108:10,110:11,104:12,103:13,111:14,3:15,10:16}.get(number,3)
    assert classes==expected_classes
    errno_count=max(errors)+1
    assert errno_count==134 and unicodedata.unidata_version=="15.0.0",(errno_count,unicodedata.unidata_version)
    errno_table=len(CLASSES)*8;ranges_at=errno_table+errno_count*8
    pool=bytearray(ranges_at+len(ranges)*8)
    for n,(first,last)in enumerate(ranges):struct.pack_into("<II",pool,ranges_at+n*8,first,last)
    literals={}
    def append(raw):
        if raw in literals:return literals[raw]
        offset=len(pool);pool.extend(raw);literals[raw]=(offset,len(raw));return offset,len(raw)
    for n,name in enumerate(CLASSES):
        offset,size=append(name.encode());struct.pack_into("<II",pool,n*8,offset,size)
    for number,message in sorted(errors.items()):
        offset,size=append(message.encode());struct.pack_into("<II",pool,errno_table+number*8,offset,size)
    unknown_at,unknown_size=append(b"Unknown error ");prefix_at,prefix_size=append(b"[Errno ")
    assert prefix_size==7
    pool.extend(bytes(-len(pool)%8));work_size=(len(pool)+4095)&~4095
    assert work_size<=32768
    constants=dict(RESPONSE=int.from_bytes(b"HBRDS001","little"),LIMIT=0xffff0000,INVALID=0xffffffff,
        CAPACITY=0xfffffffe,WORK_SIZE=work_size,ERRNO_COUNT=errno_count,ERRNO_TABLE=errno_table,
        RANGE_COUNT=len(ranges),RANGES_AT=ranges_at,UNKNOWN_AT=unknown_at,UNKNOWN_SIZE=unknown_size,ERR_PREFIX=prefix_at)
    pseudo=(source/"authoring/binary_error.pseudo").read_text()
    pseudo+="\ndef install_data(w:mutbuf) -> u64:\n"
    for at in range(0,len(pool),8):pseudo+=f"    put(w,{at},{int.from_bytes(pool[at:at+8],'little')})\n"
    pseudo+="    return 0\n"
    pseudo=re.sub(r"\b("+"|".join(constants)+r")\b",lambda m:str(constants[m[0]]),pseudo)
    nodes=ast.parse(pseudo).body;assert all(isinstance(n,ast.FunctionDef)for n in nodes)and nodes[0].name=="entry"
    names={n.name:"f"+str(i)for i,n in enumerate(nodes)};names["utf8"]="f"+str(len(nodes))
    signatures={n.name:([p.annotation.id for p in n.args.args],n.returns.id)for n in nodes}
    signatures["utf8"]=(["readbuf","u64","u64"],"u64")
    total=total_scalar_functions(nodes);functions=[]
    for node in nodes:
        b=Builder(node,names,signatures,total);b.statements(node.body)
        functions.append(dict(name=names[node.name],params=[b.param(p)for p in b.params],
            returns=[b.returns],effects=["read","write","trap"],entry="b0",blocks=b.blocks))
    retained=copy.deepcopy(original);retained["name"]=names["utf8"];functions.append(retained)
    document=dict(schema="hepta.hia.program.v8",module="binary_error",functions=functions)
    compacted=compact_authoring_cfg(document);compacted["functions"][-1]=retained
    raw=render_assembly(compacted).encode();actual=assemble_program(raw).as_dict()
    assert actual["functions"][-1]==retained and render_assembly(actual).encode()==raw
    operations=sum(len(b["ops"])for f in actual["functions"]for b in f["blocks"])
    assert operations<=8192,operations
    for f in actual["functions"]:
        assert len(f["blocks"])<=256 and max(len(b["params"])for b in f["blocks"])<=16,f["name"]
    data=dict(schema="hepta.runtime.binary-error.frozen-platform-data.v1",unicode_version=unicodedata.unidata_version,
        nonprintable_ranges=ranges,known_errno_messages=errors,errno_class_ids=classes,classes=CLASSES,
        data_bytes=len(pool),data_sha256=SHA(bytes(pool)),workspace_required=work_size,
        unknown_errno_form="Unknown error "+str(4095),source_only=True)
    receipt=dict(schema="hepta.runtime.binary-error.author.v1",source_sha256=SHA(raw),source_bytes=len(raw),
        functions=len(functions),instructions=operations,aliases=names,constants=constants,
        data_sha256=SHA(CANON(data)),function_sha256={f["name"]:SHA(CANON(f))for f in actual["functions"]},
        retained_utf8=dict(original_function=old_utf8,original_function_sha256=composition["function_sha256"][old_utf8],
            baseline_sha256=SHA(raw_baseline),new_function=names["utf8"]),
        native_compiled=False,native_executed=False,original_compared=False,public_route=False)
    out.mkdir(parents=True)
    (out/"binary_error.hepta").write_bytes(raw)
    (out/"binary_error_composition.json").write_text(json.dumps(receipt,sort_keys=True,indent=2)+"\n")
    (out/"binary_error.pseudo").write_text(pseudo)
    (out/"platform_data.json").write_text(json.dumps(data,sort_keys=True,ensure_ascii=False,indent=2)+"\n")
    (out/"reference_environment.json").write_text(json.dumps(dict(python=sys.version,executable=sys.executable,
        unicode_version=unicodedata.unidata_version,lc_messages=locale.setlocale(locale.LC_MESSAGES),
        platform=sys.platform,uname=list(os.uname())),sort_keys=True,indent=2)+"\n")
    print(json.dumps({k:receipt[k]for k in("schema","source_sha256","source_bytes","functions","instructions")},sort_keys=True))
if __name__=="__main__":main()
