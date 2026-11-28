#!/usr/bin/env python3
"""Change only read67's regular-first-fstat failure, preserving every other IR function."""
from pathlib import Path
import argparse,ast,copy,hashlib,json,re,sys
sys.dont_write_bytecode=True
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
CANON=lambda value:json.dumps(value,sort_keys=True,separators=(",",":")).encode()
def main():
    p=argparse.ArgumentParser()
    for name in("source","hepta","output"):p.add_argument("--"+name,type=Path,required=True)
    a=p.parse_args();root=a.source.resolve(strict=True);out=a.output.absolute();assert not out.exists()
    sys.path.insert(0,str(a.hepta.resolve(strict=True)))
    from tools.generate_hia_selfhost import Builder,compact_authoring_cfg,total_scalar_functions
    from hepta.hia_agent_assembly import assemble_program,render_assembly
    class NativeBuilder(Builder):
        def expr(self,node):
            if isinstance(node,ast.Call)and isinstance(node.func,ast.Name)and node.func.id=="copy_within":
                values=[self.expr(v)for v in node.args];assert len(values)==4 and values[0][1]=="mutbuf"
                return self.op("buffer.move_within",[values[0],*(self.cast(v,"usize")for v in values[1:])])
            return super().expr(node)
    raw=(root/"baseline/binary_read_body.hepta").read_bytes()
    assert SHA(raw)=="75719ec36492fd265fefc61f8a66cc6550657306e0b7cc91072df94681b5808d"
    old=assemble_program(raw).as_dict();funcs=old["functions"]
    assert len(funcs)==67 and [v["name"]for v in funcs]==["f"+str(i)for i in range(67)]
    composed=(root/"baseline/binary_read_body_composition.json").read_bytes()
    assert SHA(composed)=="9feb305803088a7f96efead6c5632763432b737c66bf8c0891bec5521c6ef884"
    composition=json.loads(composed);assert composition["source_sha256"]==SHA(raw)
    for fn in funcs:assert SHA(CANON(fn))==composition["function_sha256"][fn["name"]]
    names=dict(composition["aliases"]);assert names["open_source"]=="f20"
    byname={fn["name"]:fn for fn in funcs}
    signatures={name:([p["type"]for p in byname[fn]["params"]],byname[fn]["returns"][0])for name,fn in names.items()}
    constants=composition["constants"]
    assert constants["MAXIMUM"]==(1<<64)-1 and constants["REQUEST"]==int.from_bytes(b"HBRDQ001","little")
    assert constants["AT_REQUEST"]==int.from_bytes(b"HBRDFD01","little")
    target=(root/"target/binary_file.py").read_bytes()
    assert SHA(target)=="c15e8900b0ab867b221ff08d5a10401c8b656c87676f57b478b9a21219f7fe12"
    target_ast=ast.parse(target)
    regular=next(n for n in target_ast.body if isinstance(n,ast.FunctionDef)and n.name=="regular")
    assert not any(isinstance(n,ast.Try)for n in ast.walk(regular))
    assert [ast.dump(n.value,include_attributes=False)for n in regular.body[:2]if isinstance(n,ast.Assign)]==[
        ast.dump(ast.parse("os.open(name, flags | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, mode, dir_fd=fd)",mode="eval").body,include_attributes=False),
        ast.dump(ast.parse("os.fstat(f)",mode="eval").body,include_attributes=False)]
    original_author=(root/"baseline/author_binary_read_body.py").read_bytes()
    namespace={"__name__":"retained_binary_author","__file__":str(root/"baseline/author_binary_read_body.py")}
    exec(compile(original_author,str(root/"baseline/author_binary_read_body.py"),"exec"),namespace)
    full=(root/"baseline/binary_read_body.pseudo").read_text()
    assert SHA(full.encode())=="ee9ef7c11e17eaa3bf1cb28f64e523fe405a3f06b51fd249d06b95519354b451"
    original_node=next(n for n in ast.parse(full).body if isinstance(n,ast.FunctionDef)and n.name=="open_source")
    before=(root/"authoring/open_source_before.pseudo").read_text()
    after=(root/"authoring/open_source.pseudo").read_text()
    assert ast.dump(ast.parse(before).body[0],include_attributes=False)==ast.dump(original_node,include_attributes=False)
    branch="    if phase==25:\n        if result==MAXIMUM-3:\n            put(w,8,24)\n            return NEXT\n        if negative(result)!=0:\n            return os_fail(w,0-result,0)\n"
    changed="    if phase==25:\n        if result==MAXIMUM-3:\n            put(w,8,24)\n            return NEXT\n        if negative(result)!=0:\n            os_fail(w,0-result,0)\n            put(w,8,34)\n            return NEXT\n"
    tail="    if phase==34:\n        return request(w,o,35,1,4,get(w,96),0,0,0,0)\n    if phase==35:\n        if result!=0 or get(w,48)!=0:\n            return INVALID\n        put(w,96,MAXIMUM)\n        put(w,8,90)\n        return NEXT\n"
    assert before.count(branch)==1 and before.endswith("    return INVALID\n")
    expected=before.replace(branch,changed)
    expected=expected[:-len("    return INVALID\n")]+tail+"    return INVALID\n"
    assert after==expected,"narrow semantic source change"
    for code,message in namespace["ERRORS"].items():full+=namespace["literal"]("error_"+str(code),message.encode())
    full+="\ndef error_literal(w:mutbuf,at:u64,code:u64) -> u64:\n"
    for code in namespace["ERRORS"]:full+=f"    if code=={code}:\n        return error_{code}(w,at)\n"
    full+="    return at\n"
    for name,value in namespace["LITERALS"].items():full+=namespace["literal"](name,value)
    substitute=lambda text:re.sub(r"\b("+"|".join(constants)+r")\b",lambda m:str(constants[m[0]]),text)
    all_nodes=ast.parse(substitute(full)).body
    total=total_scalar_functions(all_nodes)
    def author_one(pseudo):
        node=ast.parse(substitute(pseudo)).body[0];assert node.name=="open_source"
        builder=NativeBuilder(node,names,signatures,total);builder.statements(node.body)
        candidate=dict(name="f20",params=[builder.param(p)for p in builder.params],returns=[builder.returns],
            effects=["read","write","trap"],entry="b0",blocks=builder.blocks)
        document=copy.deepcopy(old);document["functions"][20]=candidate
        compacted=compact_authoring_cfg(document)
        return compacted["functions"][20]
    regenerated=author_one(before)
    assert CANON(regenerated)==CANON(funcs[20]),"exact old f20 author/IR preimage"
    fresh=author_one(after)
    assert CANON(fresh)!=CANON(funcs[20])
    document=copy.deepcopy(old);document["functions"][20]=fresh
    emitted=render_assembly(document).encode();actual=assemble_program(emitted).as_dict()
    assert render_assembly(actual).encode()==emitted and len(actual["functions"])==67
    assert all(CANON(fn)==CANON(funcs[i])for i,fn in enumerate(actual["functions"])if i!=20),"all other66 functions"
    operations=sum(len(b["ops"])for fn in actual["functions"]for b in fn["blocks"])
    assert operations<=8192
    for fn in actual["functions"]:assert len(fn["blocks"])<=256 and max(len(b["params"])for b in fn["blocks"])<=16
    receipt=dict(schema="hepta.runtime.binary-read-orphans.author.v1",source_bytes=len(emitted),source_sha256=SHA(emitted),
        functions=67,instructions=operations,aliases=names,constants=constants,
        baseline_source_sha256=SHA(raw),baseline_composition_sha256=SHA(composed),baseline_function_sha256=composition["function_sha256"],
        function_sha256={fn["name"]:SHA(CANON(fn))for fn in actual["functions"]},
        changed_function="f20",retained_functions=66,before_function_sha256=SHA(CANON(regenerated)),
        after_function_sha256=SHA(CANON(fresh)),target_regular_ast_sha256=SHA(ast.dump(regular,include_attributes=False).encode()),
        native_orphan_operation=4,orphan_request_kind=1,request_phase=34,ack_phase=35,
        context_owns_parent=False,first_regular_fstat_non_eintr_preserved_until_process_exit=True,
        native_compiled=False,native_executed=False,original_compared=False,public_route=False,whole_runtime_replaced=False)
    out.mkdir(parents=True)
    (out/"binary_read_body.hepta").write_bytes(emitted)
    (out/"binary_read_body_composition.json").write_text(json.dumps(receipt,sort_keys=True,indent=2)+"\n")
    (out/"open_source.pseudo").write_text(substitute(after))
    (out/"open_source_before.pseudo").write_text(substitute(before))
    print(json.dumps({k:receipt[k]for k in("schema","source_bytes","source_sha256","functions","instructions","retained_functions")},sort_keys=True))
if __name__=="__main__":main()
