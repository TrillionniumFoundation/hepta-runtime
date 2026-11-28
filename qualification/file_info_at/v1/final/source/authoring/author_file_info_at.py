#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Author the original info branch as a separate borrowed-parent HIA controller."""
from __future__ import annotations
import argparse,ast,copy,hashlib,json,re,sys
from pathlib import Path
sys.dont_write_bytecode=True
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
CANON=lambda value:json.dumps(value,sort_keys=True,separators=(",",":")).encode()
HELPERS=("negative","equal","load","get","put","u32_at","copy_in","copy_out","hex_digit","quoted")
LITERALS={
 "literal_regular":b"invalid regular file or private sidecar",
 "literal_changed":b"file changed during metadata inspection",
 "wire_path":b'{"path":',
 "wire_metadata":b',"metadata":'
}
MATCHES={
 "match_mode":b'{"mode":',
 "match_sha":b',"sha256":"',
 "match_size":b'","size":',
 "match_version":b',"version":"'
}
def literal(name,raw):
    text="\ndef "+name+"(w:mutbuf,at:u64) -> u64:\n"
    end=len(raw)//8*8
    for at in range(0,end,8):text+=f"    put(w,at+{at},{int.from_bytes(raw[at:at+8],'little')})\n"
    for at in range(end,len(raw)):text+=f"    store(w,at+{at},{raw[at]})\n"
    return text+f"    return at+{len(raw)}\n"
def match(name,raw):
    text="\ndef "+name+"(w:mutbuf,at:u64,end:u64) -> u64:\n"
    text+=f"    if at>end or end-at<{len(raw)}:\n        return MAXIMUM\n"
    for index,value in enumerate(raw):
        text+=f"    if byte(w,at+{index})!={value}:\n        return MAXIMUM\n"
    return text+f"    return at+{len(raw)}\n"
def main():
    p=argparse.ArgumentParser()
    for key in ("source","hepta","output"):p.add_argument("--"+key,required=True,type=Path)
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
    provenance=json.loads((source/"PROVENANCE.json").read_bytes())
    for key,row in provenance["files"].items():
        raw=(source/row["path"]).read_bytes()
        assert len(raw)==row["bytes"] and SHA(raw)==row["sha256"],key
    target=(source/"target/binary_file.py").read_bytes()
    target_tree=ast.parse(target)
    info=[]
    for node in ast.walk(target_tree):
        if isinstance(node,ast.If) and ast.dump(node.test,include_attributes=False)==ast.dump(ast.parse("op == 'info'",mode="eval").body,include_attributes=False):
            info.append(node)
    assert len(info)==1
    info_source=ast.get_source_segment(target.decode(),info[0])
    assert "result = fingerprint(fd, name)" in info_source
    assert "f = regular(fd, name)" in info_source
    assert "version(os.fstat(f)) != result['version']" in info_source
    assert "metadata_summary(metadata_capture(f))" in info_source
    assert "finally: os.close(f)" in info_source
    assert "'path': q['path']" in info_source
    regular=next(node for node in target_tree.body if isinstance(node,ast.FunctionDef) and node.name=="regular")
    assert not any(isinstance(node,ast.Try) for node in ast.walk(regular))
    assert isinstance(regular.body[0],ast.Assign) and isinstance(regular.body[1],ast.Assign)
    for message in list(LITERALS.values())[:2]:assert repr(message.decode()).encode() in target
    baseline_pseudo=(source/"baseline/binary_read_body.pseudo").read_text()
    original_helpers={node.name:node for node in ast.parse(baseline_pseudo).body if isinstance(node,ast.FunctionDef)}
    pseudo=(source/"authoring/file_info_at.pseudo").read_text()
    own_helpers={node.name:node for node in ast.parse(pseudo).body if isinstance(node,ast.FunctionDef)}
    helper_proof={}
    for name in HELPERS:
        old=ast.dump(original_helpers[name],include_attributes=False);new=ast.dump(own_helpers[name],include_attributes=False)
        assert old==new,name
        helper_proof[name]=SHA(old.encode())
    base_raw=(source/"baseline/binary_read_body.hepta").read_bytes()
    baseline=assemble_program(base_raw).as_dict()
    original_utf8=next(f for f in baseline["functions"] if f["name"]=="f62")
    assert not any(op["op"]=="call" for b in original_utf8["blocks"] for op in b["ops"])
    constants={k:int.from_bytes(v,"little") for k,v in {
       "REQUEST":b"HINFQ001","RESPONSE":b"HINFR001","WORK_MAGIC":b"HINFW001",
       "FP_REQUEST":b"HBRDFD01","FP_RESPONSE":b"HBRDS001",
       "METADATA_REQUEST":b"HMDTQ001","METADATA_RESPONSE":b"HMDSR001",
       "SNAP_MAGIC":b"HMTSS001","STAT_TAG":b"HSTVER01"}.items()}
    constants.update(INVALID=0xffffffff,CAPACITY=0xfffffffe,NEXT=0xfffffffd,LIMIT=0xffff0000,
       MAXIMUM=(1<<64)-1,SNAP_CAP=4268160,FP_JSON=1024,VERSION=1536,STAT_DATA=1792,
       PACKET="get(w,304)",REPLY="get(w,312)",ERROR="get(w,320)",
       RESULT="get(w,328)",NAME="get(w,336)",PATH="get(w,344)")
    for name,raw in LITERALS.items():pseudo+=literal(name,raw)
    for name,raw in MATCHES.items():pseudo+=match(name,raw)
    pseudo=re.sub(r"\b("+"|".join(constants)+r")\b",lambda m:str(constants[m[0]]),pseudo)
    nodes=ast.parse(pseudo).body
    assert all(isinstance(n,ast.FunctionDef) for n in nodes) and nodes[0].name=="entry"
    names={node.name:"f"+str(i) for i,node in enumerate(nodes)}
    assert len(names)==len(nodes) and "utf8" not in names
    names["utf8"]="f"+str(len(nodes))
    signatures={node.name:([p.annotation.id for p in node.args.args],node.returns.id) for node in nodes}
    signatures["utf8"]=(["readbuf","u64","u64"],"u64")
    total=total_scalar_functions(nodes);functions=[]
    for node in nodes:
        builder=NativeBuilder(node,names,signatures,total);builder.statements(node.body)
        functions.append(dict(name=names[node.name],params=[builder.param(p) for p in builder.params],
             returns=[builder.returns],effects=["read","write","trap"],entry="b0",blocks=builder.blocks))
    unicode=copy.deepcopy(original_utf8);unicode["name"]=names["utf8"];functions.append(unicode)
    document=dict(schema="hepta.hia.program.v8",module="file_info_at",functions=functions)
    compacted=compact_authoring_cfg(document)
    raw=render_assembly(compacted).encode();actual=assemble_program(raw).as_dict()
    assert render_assembly(actual).encode()==raw
    generated_utf8=next(f for f in actual["functions"] if f["name"]==names["utf8"])
    restored=copy.deepcopy(generated_utf8);restored["name"]="f62"
    assert CANON(restored)==CANON(original_utf8),"copied UTF8 helper IR"
    ops=sum(len(b["ops"]) for f in actual["functions"] for b in f["blocks"])
    assert ops<=8192,ops
    for f in actual["functions"]:
        assert len(f["blocks"])<=256 and max(len(b["params"]) for b in f["blocks"])<=16,f["name"]
    receipt=dict(schema="hepta.runtime.file-info-at.author.v1",
       target_commit=provenance["target_commit"],target_sha256=SHA(target),
       target_info_ast_sha256=SHA(ast.dump(info[0],include_attributes=False).encode()),
       target_regular_ast_sha256=SHA(ast.dump(regular,include_attributes=False).encode()),
       source_bytes=len(raw),source_sha256=SHA(raw),functions=len(functions),instructions=ops,
       aliases=names,constants=constants,
       function_sha256={f["name"]:SHA(CANON(f)) for f in actual["functions"]},
       unchanged_helper_ast_sha256=helper_proof,unchanged_utf8_ir_sha256=SHA(CANON(original_utf8)),
       borrowed_parent_fd=True,no_parent_dup_or_close=True,
       unchanged_fingerprint_child=True,unchanged_metadata_child=True,unchanged_stat_version_child=True,
       separate_regular_fstat_and_version_fstat_and_metadata_first_fstat=True,
       no_new_comparison_between_version_fstat_and_metadata_capture=True,
       regular_initial_fstat_failure_orphans_open_descriptor_until_process_exit=True,
       metadata_snapshot_is_passed_to_summary_without_recapture=True,
       complete_error_child_frames_retained=True,
       native_compiled=False,native_executed=False,original_compared=False,
       public_route_registered=False,remote_transport_qualified=False,whole_runtime_qualified=False)
    out.mkdir(parents=True)
    (out/"file_info_at.hepta").write_bytes(raw)
    (out/"file_info_at.pseudo").write_text(pseudo)
    (out/"file_info_at_composition.json").write_text(json.dumps(receipt,sort_keys=True,indent=2)+"\n")
    (out/"target_info_branch.py").write_text(info_source+"\n")
    print(json.dumps({key:receipt[key] for key in ("schema","source_bytes","source_sha256","functions","instructions")},sort_keys=True))
if __name__=="__main__":main()
