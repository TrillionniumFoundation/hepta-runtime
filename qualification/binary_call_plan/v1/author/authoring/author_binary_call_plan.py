#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Author exact five-handler preconditions and request construction in HIA."""
from __future__ import annotations
import argparse,ast,copy,hashlib,json,re,sys
from pathlib import Path
sys.dont_write_bytecode=True
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
CANON=lambda value:json.dumps(value,sort_keys=True,separators=(",",":")).encode()
LITERALS={
    1:b"binary payload exceeds 1 MiB decoded bound",
    2:b"invalid upload identity",
    3:b"chunk requires expected version and bounded base64 data",
    4:b"commit requires total size and SHA256",
    5:b"in-place patch requires explicit non-atomic acknowledgement",
    6:b"apply requires source version, SHA256 and bounded 64 KiB patch",
    100:b"null",101:b"false",102:b"true",
    110:b'"op":',111:b'"expected_version":',112:b',"limit":',113:b',"offset":',114:b',"op":',
    115:b'"data_base64":',116:b',"expected_version":',117:b'"acknowledge_non_atomic":',
    118:b',"action":',119:b',"data_base64":',120:b',"expected_sha256":',121:b',"host":',
    122:b',"path":',123:b',"preserve_special_bits":',124:b',"root":',125:b',"sha256":',
    126:b',"size":',127:b',"upload_id":',128:b',"transaction_id":',
    201:b'"info"',202:b'"read"',203:b'"write"',204:b'"upload_chunk"',205:b'"upload_commit"',
    206:b'"upload_abort"',207:b'"inode_patch"',211:b'"apply"',212:b'"status"',213:b'"recover"'}
def literals():
    text="\ndef literal(o:mutbuf,w:mutbuf,code:u64) -> u64:\n"
    for code,raw in sorted(LITERALS.items()):
        text+=f"    if code=={code}:\n"
        end=len(raw)//8*8
        for at in range(0,end,8):text+=f"        emit_word(w,o,{int.from_bytes(raw[at:at+8],'little')})\n"
        for at in range(end,len(raw)):text+=f"        emit(w,o,{raw[at]})\n"
        text+="        return 0\n"
    text+="    return 0\n\ndef decimal_power(index:u64) -> u64:\n"
    for index in range(20):text+=f"    if index=={index}:\n        return {10**(19-index)}\n"
    return text+"    return 1\n"
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
            if isinstance(node,ast.Call)and isinstance(node.func,ast.Name)and node.func.id=="copy_span":
                values=[self.expr(v)for v in node.args]
                assert len(values)==5 and values[0][1]=="mutbuf"and values[1][1]=="readbuf"
                return self.op("buffer.copy_range",[values[0],values[1],*(self.cast(v,"usize")for v in values[2:])])
            return super().expr(node)
    baseline=(source/"baseline/config_directory_owner_span.hepta").read_bytes()
    assert SHA(baseline)=="6a0e7817013c32bd7189864c91dc768764ae44988cabe4391446ceafea9b5d81"
    original=copy.deepcopy(next(f for f in assemble_program(baseline).as_dict()["functions"]if f["name"]=="f44"))
    assert original["returns"]==["u64"]and[p["type"]for p in original["params"]]==["readbuf","u64","u64"]
    assert not any(op["op"]=="call"for b in original["blocks"]for op in b["ops"])
    constants={k:int.from_bytes(v,"little")for k,v in{
        "REQUEST":b"HBPLQ001","RESPONSE":b"HBPLR001","TYPED":b"HBPRR001",
        "CONFIG_REQUEST":b"HRCFGQ01","CONFIG_RESULT":b"HRCFGM01","GROW_TAG":b"HGRWS002"}.items()}
    constants.update(INVALID=0xffffffff,SHORT=0xfffffffe,GROW=0xffffffd0,LIMIT=0xffff0000)
    pseudo=(source/"authoring/binary_call_plan.pseudo").read_text()+literals()
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
    document=dict(schema="hepta.hia.program.v8",module="binary_call_plan",functions=functions)
    compacted=compact_authoring_cfg(document)
    compacted["functions"][-1]=retained
    raw=render_assembly(compacted).encode();actual=assemble_program(raw).as_dict()
    assert actual["functions"][-1]==retained
    assert render_assembly(actual).encode()==raw
    ops=sum(len(b["ops"])for f in actual["functions"]for b in f["blocks"])
    assert ops<=8192
    for f in actual["functions"]:
        assert len(f["blocks"])<=256 and max(len(b["params"])for b in f["blocks"])<=16,f["name"]
    receipt=dict(schema="hepta.runtime.binary-call-plan.author.v1",
        target_commit="d3d75c30719db966b004756f610007a7c723729e",
        source_sha256=SHA(raw),source_bytes=len(raw),functions=len(functions),instructions=ops,
        aliases=names,constants=constants,function_sha256={f["name"]:SHA(CANON(f))for f in actual["functions"]},
        exact_retained_utf8=dict(baseline_sha256=SHA(baseline),original_function="f44",function=names["utf8"],
            original_function_sha256=SHA(CANON(original))),typed_owner_final="0666613d8c3cad74f6eb192c287069988e813827",
        root_owner_final="19d586be0db6a13d18a6f7e1356ce6c8dc55abce",
        precondition_order_retained=True,optional_none_and_zero_preserved=True,full_u64_decimal_emission=True,
        original_remote_body_executed=False,native_compiled=False,native_executed=False,original_compared=False,
        public_route_registered=False,whole_runtime_qualified=False)
    out.mkdir(parents=True)
    (out/"binary_call_plan.hepta").write_bytes(raw)
    (out/"binary_call_plan_composition.json").write_text(json.dumps(receipt,sort_keys=True,indent=2)+"\n")
    (out/"binary_call_plan.pseudo").write_text(pseudo)
    print(json.dumps({k:receipt[k]for k in("schema","source_sha256","source_bytes","functions","instructions")},sort_keys=True))
if __name__=="__main__":main()
