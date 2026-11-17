#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Author the original bounded multi-file body with two independent parent owners."""
from pathlib import Path
import argparse,ast,copy,hashlib,json,re,sys
sys.dont_write_bytecode=True
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
CANON=lambda value:json.dumps(value,sort_keys=True,separators=(",",":")).encode()
HELPERS=("negative","equal","load","get","put","u32_at","copy_in","copy_out","hex_digit","decimal","quoted","same_identity")
ERRORS={
 1:"invalid bounded multi-file request",
 2:"bounded absolute non-aliased path required",
 3:"batch paths must be distinct",
 4:"hardlinked files are outside this read capability",
 5:"file exceeds full-read byte ceiling; use binary_read",
 6:"file changed during full read",
 7:"source path identity changed during read",
 8:"multi-file response exceeds serialized MCP result byte budget",
 9:"invalid regular file or private sidecar"}
LITERALS={
 "wire_prefix":b'{"atomic_snapshot":false,"encoding":"utf-8","files":[',
 "wire_file":b'{"eof":true,"path":',
 "wire_sha":b',"sha256":',
 "wire_size":b',"size":',
 "wire_text":b',"text":',
 "wire_version":b',"version":',
 "wire_suffix":b'],"snapshot_scope":"independent_file","truncated":false}'}
OUTER_PREFIX=b'{"content":[{"type":"text","text":'
OUTER_SUFFIX=b'}],"isError":false}'
def literal(name,raw):
    lines=["","def "+name+"(w:mutbuf,at:u64) -> u64:"]
    end=len(raw)//8*8
    for i in range(0,end,8):lines.append("    put(w,at+"+str(i)+","+str(int.from_bytes(raw[i:i+8],"little"))+")")
    for i in range(end,len(raw)):lines.append("    store(w,at+"+str(i)+","+str(raw[i])+")")
    lines.append("    return at+"+str(len(raw)))
    return "\n".join(lines)+"\n"
def functions(raw):
    return {n.name:n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)}
def main():
    p=argparse.ArgumentParser()
    for key in("source","hepta","output"):p.add_argument("--"+key,required=True,type=Path)
    a=p.parse_args();source=a.source.resolve(strict=True);out=a.output.absolute();assert not out.exists()
    provenance=json.loads((source/"PROVENANCE.json").read_bytes())
    for path,row in provenance["files"].items():
        raw=(source/path).read_bytes();assert len(raw)==row["bytes"]and SHA(raw)==row["sha256"],path
    target=(source/"target/multi_read_host.py").read_bytes()
    binary=(source/"target/binary_file.py").read_bytes()
    assert SHA(target)=="6f83b3e1031642e9981310916181858941dec51bb1696a79087beeb60a6e3eb5"
    assert SHA(binary)=="c15e8900b0ab867b221ff08d5a10401c8b656c87676f57b478b9a21219f7fe12"
    target_functions=functions(target);original=target_functions["multi_read"];regular=functions(binary)["regular"]
    assert not any(isinstance(n,ast.Try)for n in ast.walk(regular))
    for code,message in ERRORS.items():assert repr(message).encode()in(target if code!=9 else binary)
    calls=[n for n in ast.walk(original)if isinstance(n,ast.Call)]
    assert sum(isinstance(n.func,ast.Name)and n.func.id=="parent"for n in calls)==2
    assert sum(isinstance(n.func,ast.Name)and n.func.id=="regular"for n in calls)==2
    assert sum(isinstance(n.func,ast.Attribute)and n.func.attr=="fstat"for n in calls)==3
    assert sum(isinstance(n.func,ast.Attribute)and n.func.attr=="read"for n in calls)==1
    assert "remaining = file_limit + 1" in target.decode()
    assert "data.decode('utf-8', errors='strict')" in target.decode()
    assert "version(after) != ver or after.st_nlink != 1 or len(data) != before.st_size" in target.decode()
    assert "version(checked) != ver or checked.st_nlink != 1" in target.decode()
    before=functions((source/"baseline/binary_read_body.pseudo").read_text())
    previous=functions((source/"baseline/file_info_at.pseudo").read_text())
    pseudo=(source/"authoring/multi_read_body.pseudo").read_text();own=functions(pseudo);helper_proof={}
    for name in HELPERS:
        old=ast.dump(before[name],include_attributes=False);new=ast.dump(own[name],include_attributes=False)
        assert old==new,name;helper_proof[name]=SHA(old.encode())
    old=ast.dump(previous["error_class"],include_attributes=False)
    assert old==ast.dump(own["error_class"],include_attributes=False)
    helper_proof["error_class"]=SHA(old.encode())
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
    baseline=assemble_program((source/"baseline/binary_read_body.hepta").read_bytes()).as_dict()
    original_utf8=next(fn for fn in baseline["functions"]if fn["name"]=="f62")
    assert not any(op["op"]=="call"for block in original_utf8["blocks"]for op in block["ops"])
    constants={k:int.from_bytes(v,"little")for k,v in{
      "REQUEST":b"HMRDQ001","RESPONSE":b"HMRDS001","WORK_MAGIC":b"HMRDW001",
      "PARENT_REQUEST":b"HPRDQ001","ERROR_RESPONSE":b"HBRDS001",
      "UTF8_REQUEST":b"HUTFQ001","UTF8_RESPONSE":b"HUTFD001",
      "CODEC_TAG":b"HRCODEC1","STAT_TAG":b"HSTVER01"}.items()}
    constants.update(INVALID=0xffffffff,CAPACITY=0xfffffffe,NEXT=0xfffffffd,
      MAXIMUM=(1<<64)-1,DECIMAL=3072,OUTER_BYTES=len(OUTER_PREFIX)+len(OUTER_SUFFIX))
    regions={"DATA":(0,65537),"VERSION":(65544,128),"STAT1":(65680,144),
      "DIGEST":(65968,64),"PACKET":(66048,65632),"REPLY":(131712,65616),
      "ERROR":(197376,8192),"NAME":(205632,4097),"NAME2":(209792,4097),
      "RESULT":(214016,704512)}
    previous_end=0
    for name,(offset,capacity)in regions.items():
        assert offset>=previous_end
        previous_end=offset+capacity
        constants[name]="(get(w,304)+"+str(offset)+")"
    assert previous_end<=1048576
    # A retained prior file prefix cannot exceed its accepted complete MCP wire.
    # The next file's JSON string escaping is at most six output bytes per byte.
    next_file_bound=6*4096+6*65536+122+64+1024
    assert 262144+next_file_bound<regions["RESULT"][1]
    assert 96+8192+64==8352 and 24+65536<=regions["PACKET"][1]
    for name,raw in LITERALS.items():pseudo+=literal(name,raw)
    for code,message in ERRORS.items():pseudo+=literal("error_"+str(code),message.encode())
    pseudo+="\ndef error_literal(w:mutbuf,at:u64,code:u64) -> u64:\n"
    for code in ERRORS:pseudo+="    if code=="+str(code)+":\n        return error_"+str(code)+"(w,at)\n"
    pseudo+="    return at\n"
    generated=re.sub(r"\b("+"|".join(constants)+r")\b",lambda m:str(constants[m[0]]),pseudo)
    nodes=ast.parse(generated).body
    assert all(isinstance(n,ast.FunctionDef)for n in nodes)and nodes[0].name=="entry"
    names={n.name:"f"+str(i)for i,n in enumerate(nodes)}
    assert len(names)==len(nodes)and"utf8"not in names
    names["utf8"]="f"+str(len(nodes))
    signatures={n.name:([v.annotation.id for v in n.args.args],n.returns.id)for n in nodes}
    signatures["utf8"]=(["readbuf","u64","u64"],"u64")
    total=total_scalar_functions(nodes);compiled=[]
    for node in nodes:
        b=NativeBuilder(node,names,signatures,total);b.statements(node.body)
        compiled.append(dict(name=names[node.name],params=[b.param(v)for v in b.params],
            returns=[b.returns],effects=["read","write","trap"],entry="b0",blocks=b.blocks))
    retained=copy.deepcopy(original_utf8);retained["name"]=names["utf8"];compiled.append(retained)
    document=compact_authoring_cfg(dict(schema="hepta.hia.program.v8",module="multi_read_body",functions=compiled))
    raw=render_assembly(document).encode();actual=assemble_program(raw).as_dict()
    assert render_assembly(actual).encode()==raw
    prior=assemble_program((source/"reference/previous_body.hepta").read_bytes()).as_dict()
    assert len(prior["functions"])==len(actual["functions"])==53
    changed=[new["name"] for old,new in zip(prior["functions"],actual["functions"]) if CANON(old)!=CANON(new)]
    assert changed==[names["result_flow"]],changed
    codec_source=(source/"reference/binary_codec.hepta").read_bytes()
    assert SHA(codec_source)=="f58ab824ecb47545f19cd1d0daded9e41fca5457110693677d84e393e3098f23"
    restored=copy.deepcopy(actual["functions"][-1]);restored["name"]="f62"
    assert CANON(restored)==CANON(original_utf8)
    ops=sum(len(b["ops"])for fn in actual["functions"]for b in fn["blocks"])
    assert ops<=8192,ops
    for fn in actual["functions"]:
        assert len(fn["blocks"])<=256 and max(len(b["params"])for b in fn["blocks"])<=16,fn["name"]
    receipt=dict(schema="hepta.runtime.multi-read-body.author.v1",target_commit=provenance["target_commit"],
      target_sha256=SHA(target),target_ast_sha256={k:SHA(ast.dump(target_functions[k],include_attributes=False).encode())
          for k in("_batch_path","_wire_size","multi_read","run_multi_read")},
      target_regular_ast_sha256=SHA(ast.dump(regular,include_attributes=False).encode()),
      source_bytes=len(raw),source_sha256=SHA(raw),functions=len(compiled),instructions=ops,
      aliases=names,constants=constants,regions=regions,output_next_file_upper_bound=next_file_bound,
      function_sha256={fn["name"]:SHA(CANON(fn))for fn in actual["functions"]},
      unchanged_helper_ast_sha256=helper_proof,retained_utf8_ir_sha256=SHA(CANON(original_utf8)),
      all_paths_validated_before_any_open=True,raw_read_bounded_loop=True,
      independent_confirmation_parent_rewalk=True,two_unchanged_parent_callable_contexts=True,
      first_regular_fstat_error_orphans_in_shared_process_pool=True,
      complete_finally_error_override_order=True,compact_result_and_full_nested_mcp_wire_budget_in_hia=True,
      child_images=["parent_directory","binary_codec","stat_version","utf8_decode_diagnostic"],
      native_compiled=False,native_executed=False,original_compared=False,
      public_route=False,ssh_transport=False,whole_runtime_replaced=False)
    receipt["codec_reserved_header_correction"]=dict(previous_body_sha256=SHA((source/"reference/previous_body.hepta").read_bytes()),
        fixed_codec_sha256=SHA(codec_source),reserved_word_offset=16,reserved_word_value=0,
        only_changed_ir_functions=changed,unchanged_ir_functions=52,body_applications_before_correction=0)
    out.mkdir(parents=True)
    (out/"multi_read_body.hepta").write_bytes(raw)
    (out/"multi_read_body.pseudo").write_text(generated)
    (out/"multi_read_body_composition.json").write_text(json.dumps(receipt,sort_keys=True,indent=2)+"\n")
    print(json.dumps(dict(status="SOURCE_AUTHOR_ONLY_PASS",source_bytes=len(raw),source_sha256=SHA(raw),
        functions=len(compiled),instructions=ops,application_calls=0),sort_keys=True))
if __name__=="__main__":main()
