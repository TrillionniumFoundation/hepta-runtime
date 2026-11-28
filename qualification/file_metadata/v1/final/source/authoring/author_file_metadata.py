#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Author Linux descriptor-bound capture, summary and preservation in HIA."""
from __future__ import annotations
import argparse,ast,hashlib,json,re,sys
from pathlib import Path
sys.dont_write_bytecode=True
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
CANON=lambda value:json.dumps(value,sort_keys=True,separators=(",",":")).encode()
ERRORS={
    1:"metadata requires regular file descriptor",
    2:"metadata budget exceeded",
    3:"source metadata changed during capture",
    4:"atomic replacement would split hard links; original remains unchanged",
    5:"special execution/immutable flags require a separately qualified operation",
    6:"preserving executable capabilities across content edits requires explicit qualification",
    7:"metadata verification failed: uid",
    8:"metadata verification failed: gid",
    9:"metadata verification failed: mode",
    10:"metadata verification failed: xattrs",
    11:"metadata verification failed: acl",
    12:"source metadata changed before publication"}
LITERALS={
    "wire_uid":b'{"uid":',
    "wire_gid":b',"gid":',
    "wire_mode":b',"mode":',
    "wire_links":b',"link_count":',
    "wire_names":b',"xattr_names":[',
    "wire_hashes":b'],"xattr_sha256":{',
    "wire_acl_hash":b'},"acl_sha256":',
    "wire_platform":b',"metadata_platform":"linux"}',
    "literal_capability":b"security.capability",
    "literal_acl":b"system.posix_acl_access"}
def literal(name,raw):
    text="\ndef "+name+"(w:mutbuf,at:u64) -> u64:\n"
    end=len(raw)//8*8
    for at in range(0,end,8):text+=f"    put(w,at+{at},{int.from_bytes(raw[at:at+8],'little')})\n"
    for at in range(end,len(raw)):text+=f"    store(w,at+{at},{raw[at]})\n"
    return text+f"    return at+{len(raw)}\n"
def main():
    p=argparse.ArgumentParser()
    for name in ("hepta","source","output"):p.add_argument("--"+name,required=True,type=Path)
    a=p.parse_args();source=a.source.resolve(strict=True);out=a.output.absolute()
    assert not out.exists()
    sys.path.insert(0,str(a.hepta.resolve(strict=True)))
    from tools.generate_hia_selfhost import Builder,compact_authoring_cfg,total_scalar_functions
    from hepta.hia_agent_assembly import assemble_program,render_assembly
    class NativeBuilder(Builder):
        def expr(self,node):
            if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id=="copy_within":
                values=[self.expr(v) for v in node.args]
                assert len(values)==4 and values[0][1]=="mutbuf"
                return self.op("buffer.move_within",[values[0],*(self.cast(v,"usize") for v in values[1:])])
            return super().expr(node)
    target=(source/"target/file_metadata.py").read_bytes()
    expected=json.loads((source/"PROVENANCE.json").read_bytes())
    assert SHA(target)==expected["target"]["sha256"]
    for code,message in ERRORS.items():
        if 7<=code<=11:
            assert b"'metadata verification failed: ' + key" in target
            assert ("'"+message.rsplit(": ",1)[1]+"'").encode() in target
        else:assert repr(message).encode() in target
    codec=(source/"baseline/binary_codec.hepta").read_bytes()
    assert SHA(codec)==expected["codec"]["sha256"]
    constants={k:int.from_bytes(v,"little") for k,v in {
        "REQUEST":b"HMDTQ001","RESPONSE":b"HMDSR001","WORK_MAGIC":b"HMDTW001",
        "SNAP_MAGIC":b"HMTSS001","CODEC_TAG":b"HRCODEC1"}.items()}
    cap=73856+4194304
    constants.update(INVALID=0xffffffff,CAPACITY=0xfffffffe,NEXT=0xfffffffd,LIMIT=0xffff0000,
        MAXIMUM=(1<<64)-1,SNAP_CAP=cap,NAME_START=8320,VALUE_START=73856,
        SNAPSHOT0=8192,SNAPSHOT1=8192+cap,SNAPSHOT2=8192+2*cap,
        OLD_STAT=1024,ACL_DIGEST=1536,DECIMAL=3072,
        REPLY="get(w,304)",LIST="get(w,312)",NAME="get(w,320)",CODEC="get(w,328)",
        HASHES="get(w,336)",ORDER="get(w,344)",RESULT="get(w,352)")
    pseudo=(source/"authoring/file_metadata.pseudo").read_text()
    for code,message in ERRORS.items():pseudo+=literal("error_"+str(code),message.encode())
    pseudo+="\ndef error_literal(w:mutbuf,at:u64,code:u64) -> u64:\n"
    for code in ERRORS:pseudo+=f"    if code=={code}:\n        return error_{code}(w,at)\n"
    pseudo+="    return at\n"
    for name,raw in LITERALS.items():pseudo+=literal(name,raw)
    pseudo=re.sub(r"\b("+"|".join(constants)+r")\b",lambda m:str(constants[m[0]]),pseudo)
    nodes=ast.parse(pseudo).body
    assert all(isinstance(n,ast.FunctionDef) for n in nodes) and nodes[0].name=="entry"
    names={n.name:"f"+str(i) for i,n in enumerate(nodes)}
    assert len(names)==len(nodes)
    signatures={n.name:([p.annotation.id for p in n.args.args],n.returns.id) for n in nodes}
    total=total_scalar_functions(nodes);functions=[]
    for node in nodes:
        b=NativeBuilder(node,names,signatures,total);b.statements(node.body)
        functions.append(dict(name=names[node.name],params=[b.param(p) for p in b.params],
            returns=[b.returns],effects=["read","write","trap"],entry="b0",blocks=b.blocks))
    document=dict(schema="hepta.hia.program.v8",module="file_metadata",functions=functions)
    compacted=compact_authoring_cfg(document)
    raw=render_assembly(compacted).encode();actual=assemble_program(raw).as_dict()
    assert render_assembly(actual).encode()==raw
    ops=sum(len(b["ops"]) for f in actual["functions"] for b in f["blocks"])
    assert ops<=8192,ops
    for f in actual["functions"]:
        assert len(f["blocks"])<=256 and max(len(b["params"]) for b in f["blocks"])<=16,f["name"]
    receipt=dict(schema="hepta.runtime.file-metadata.author.v1",
        target_commit=expected["target"]["commit"],target_source_sha256=SHA(target),
        source_sha256=SHA(raw),source_bytes=len(raw),functions=len(functions),instructions=ops,
        aliases=names,constants=constants,function_sha256={f["name"]:SHA(CANON(f)) for f in actual["functions"]},
        modes=["metadata_capture","metadata_summary_of_owned_linux_snapshot","metadata_preserve"],
        platform="linux-x86_64",filesystem_encoding="utf-8 with surrogateescape",
        snapshot_semantics="uid,gid,mode,nlink,flags,xattrs,acl; xattrs compare without insertion-order dependence",
        fixed_syscall_order_in_hia=True,no_borrowed_descriptor_dup_or_close=True,
        stable_acl_last_order_in_hia=True,hash_via_binary_codec_hia=True,
        cpysource_reference_version="v3.12.3; actual reference interpreter must be captured and qualified separately",
        error_envelope="exception class, errno, literal ValueError, optional integer-fd filename",
        summary_representation="compact ASCII JSON carrying the original metadata_summary Python value; public serialization separate",
        native_compiled=False,native_executed=False,original_compared=False,
        public_route_registered=False,whole_runtime_qualified=False)
    out.mkdir(parents=True)
    (out/"file_metadata.hepta").write_bytes(raw)
    (out/"file_metadata_composition.json").write_text(json.dumps(receipt,sort_keys=True,indent=2)+"\n")
    (out/"file_metadata.pseudo").write_text(pseudo)
    print(json.dumps({k:receipt[k] for k in ("schema","source_sha256","source_bytes","functions","instructions")},sort_keys=True))
if __name__=="__main__":main()
