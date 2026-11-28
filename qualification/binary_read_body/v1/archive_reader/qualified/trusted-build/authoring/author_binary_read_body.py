#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Author descriptor-bound binary reading and fingerprinting in HIA."""
from __future__ import annotations
import argparse,ast,copy,hashlib,json,re,sys
from pathlib import Path
sys.dont_write_bytecode=True
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
CANON=lambda value:json.dumps(value,sort_keys=True,separators=(",",":")).encode()
ERRORS={
    1:"absolute non-traversing file path required",
    2:"file outside configured root",
    3:"capability root and runtime sidecars are not file targets",
    4:"embedded null byte",
    5:"invalid regular file or private sidecar",
    6:"source version changed",
    7:"read cursor outside file",
    8:"file changed while reading",
    9:"file changed while hashing",
    10:"private file changed or exceeded limit"}
LITERALS={
    "wire_private_data":b'{"data_base64":',
    "wire_private_verified":b',"private_file_verified":true}',
    "wire_mode":b'{"mode":',
    "wire_sha":b',"sha256":',
    "wire_chunk_sha":b'{"chunk_sha256":',
    "wire_data":b',"data_base64":',
    "wire_eof":b',"eof":',
    "wire_true":b'true',
    "wire_false":b'false',
    "wire_next":b',"next_offset":',
    "wire_offset":b',"offset":',
    "wire_path":b',"path":',
    "wire_size":b',"size":',
    "wire_version":b',"version":'}
def literal(name,raw):
    text="\ndef "+name+"(w:mutbuf,at:u64) -> u64:\n"
    end=len(raw)//8*8
    for at in range(0,end,8):text+=f"    put(w,at+{at},{int.from_bytes(raw[at:at+8],'little')})\n"
    for at in range(end,len(raw)):text+=f"    store(w,at+{at},{raw[at]})\n"
    return text+f"    return at+{len(raw)}\n"
def main():
    p=argparse.ArgumentParser()
    for name in("hepta","source","output"):p.add_argument("--"+name,required=True,type=Path)
    a=p.parse_args();source=a.source.resolve(strict=True);out=a.output.absolute()
    assert not out.exists()
    sys.path.insert(0,str(a.hepta.resolve(strict=True)))
    from tools.generate_hia_selfhost import Builder,compact_authoring_cfg,total_scalar_functions
    from hepta.hia_agent_assembly import assemble_program,render_assembly
    class NativeBuilder(Builder):
        def expr(self,node):
            if isinstance(node,ast.Call)and isinstance(node.func,ast.Name)and node.func.id=="copy_within":
                values=[self.expr(v)for v in node.args]
                assert len(values)==4 and values[0][1]=="mutbuf"
                return self.op("buffer.move_within",[values[0],*(self.cast(v,"usize")for v in values[1:])])
            return super().expr(node)
    baseline=(source/"baseline/config_directory_owner_span.hepta").read_bytes()
    assert SHA(baseline)=="6a0e7817013c32bd7189864c91dc768764ae44988cabe4391446ceafea9b5d81"
    original=copy.deepcopy(next(f for f in assemble_program(baseline).as_dict()["functions"]if f["name"]=="f44"))
    assert original["returns"]==["u64"]and[p["type"]for p in original["params"]]==["readbuf","u64","u64"]
    assert not any(op["op"]=="call"for b in original["blocks"]for op in b["ops"])
    target=(source/"target/binary_file.py").read_bytes()
    assert SHA(target)=="c15e8900b0ab867b221ff08d5a10401c8b656c87676f57b478b9a21219f7fe12"
    for code,message in ERRORS.items():
        if code!=4:assert repr(message).encode() in target
    constants={k:int.from_bytes(v,"little")for k,v in{
        "REQUEST":b"HBRDQ001","RESPONSE":b"HBRDS001","WORK_MAGIC":b"HBRDW001",
        "CODEC_TAG":b"HRCODEC1","STAT_TAG":b"HSTVER01"}.items()}
    constants.update(INVALID=0xffffffff,CAPACITY=0xfffffffe,NEXT=0xfffffffd,LIMIT=0xffff0000,
        MAXIMUM=(1<<64)-1,ROOT_RAW=4096,OLD_STAT=1024,LAST_STAT=1200,VERSION=1408,DIGEST=1536,
        HASH_STATE=1664,DECIMAL=3072,PATH_RAW="get(w,304)",EXPECT="get(w,312)",
        ROOT_NORMAL="get(w,320)",PATH_NORMAL="get(w,328)",COMPONENT="get(w,336)",DATA="get(w,344)",
        ENCODED="get(w,352)",RESULT="get(w,360)",ERROR_NAME="get(w,368)",CODEC_DATA="get(w,376)",REPLY="get(w,392)")
    pseudo=(source/"authoring/binary_read_body.pseudo").read_text()
    for code,message in ERRORS.items():pseudo+=literal("error_"+str(code),message.encode())
    pseudo+="\ndef error_literal(w:mutbuf,at:u64,code:u64) -> u64:\n"
    for code in ERRORS:pseudo+=f"    if code=={code}:\n        return error_{code}(w,at)\n"
    pseudo+="    return at\n"
    for name,raw in LITERALS.items():pseudo+=literal(name,raw)
    pseudo=re.sub(r"\b("+"|".join(constants)+r")\b",lambda m:str(constants[m[0]]),pseudo)
    nodes=ast.parse(pseudo).body
    assert all(isinstance(n,ast.FunctionDef)for n in nodes)and nodes[0].name=="entry"
    names={n.name:"f"+str(i)for i,n in enumerate(nodes)};names["utf8"]="f"+str(len(nodes))
    signatures={n.name:([p.annotation.id for p in n.args.args],n.returns.id)for n in nodes}
    signatures["utf8"]=(["readbuf","u64","u64"],"u64")
    total=total_scalar_functions(nodes);functions=[]
    for node in nodes:
        b=NativeBuilder(node,names,signatures,total);b.statements(node.body)
        functions.append(dict(name=names[node.name],params=[b.param(p)for p in b.params],
            returns=[b.returns],effects=["read","write","trap"],entry="b0",blocks=b.blocks))
    retained=copy.deepcopy(original);retained["name"]=names["utf8"];functions.append(retained)
    document=dict(schema="hepta.hia.program.v8",module="binary_read_body",functions=functions)
    compacted=compact_authoring_cfg(document)
    compacted["functions"][-1]=retained
    raw=render_assembly(compacted).encode();actual=assemble_program(raw).as_dict()
    assert actual["functions"][-1]==retained and render_assembly(actual).encode()==raw
    ops=sum(len(b["ops"])for f in actual["functions"]for b in f["blocks"])
    assert ops<=8192,ops
    for f in actual["functions"]:
        assert len(f["blocks"])<=256 and max(len(b["params"])for b in f["blocks"])<=16,f["name"]
    receipt=dict(schema="hepta.runtime.binary-read-body.author.v1",
        target_commit="d3d75c30719db966b004756f610007a7c723729e",target_source_sha256=SHA(target),
        source_sha256=SHA(raw),source_bytes=len(raw),functions=len(functions),instructions=ops,
        aliases=names,constants=constants,function_sha256={f["name"]:SHA(CANON(f))for f in actual["functions"]},
        exact_retained_utf8=dict(baseline_sha256=SHA(baseline),original_function="f44",function=names["utf8"],
            original_function_sha256=SHA(CANON(original))),
        modes=["binary_read","fingerprint","private_read"],python_path_anchor_and_precondition_order=True,
        syscall_and_codec_policy_in_hia=True,version_via_stat_version_hia=True,hash_base64_via_binary_codec_hia=True,
        error_envelope="structured exception class, errno and raw filename; outer diagnostic formatting separate",
        native_compiled=False,native_executed=False,original_compared=False,
        public_route_registered=False,whole_runtime_qualified=False)
    out.mkdir(parents=True)
    (out/"binary_read_body.hepta").write_bytes(raw)
    (out/"binary_read_body_composition.json").write_text(json.dumps(receipt,sort_keys=True,indent=2)+"\n")
    (out/"binary_read_body.pseudo").write_text(pseudo)
    print(json.dumps({k:receipt[k]for k in("schema","source_sha256","source_bytes","functions","instructions")},sort_keys=True))
if __name__=="__main__":main()
